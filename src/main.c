// pico-wg-dongle: a USB WireGuard adapter.
//
// The Pico 2 W joins an upstream Wi-Fi network as a station, runs a WireGuard
// tunnel on-device, and presents a CDC-NCM network interface to the USB host.
// The host's DHCP lease IS a tunnel address: the WireGuard peer's AllowedIPs
// covers a tiny subnet holding the Pico (gateway) and the host, so no NAT is
// needed. The host's only route is through the Pico, the Pico forwards host
// traffic only into the tunnel (route hook in wg.c), and DNS is the
// tunnel-side resolver handed out over DHCP -- the host can reach the
// WireGuard LAN and nothing else. Provisioning and status are on the CDC-ACM
// serial console (serial_console.c).
//
// Derived from pico-usb-wifi (MIT, baiyibai): the USB descriptors, console,
// config store, and main-loop robustness scaffolding carry over; the L2
// bridge it was built around does not.

#include <malloc.h>
#include <stdio.h>
#include <string.h>

#include <hardware/watchdog.h>
#include <lwip/netif.h>
#include <pico/cyw43_arch.h>
#include <pico/stdlib.h>

#include <lwip/apps/mdns.h>

#include "ap.h"
#include "config.h"
#include "config_proto.h"
#include "debug_console.h"
#include "dhcp_server.h"
#include "eth_csum.h"
#include "http_portal.h"
#include "serial_bridge.h"
#include "serial_console.h"
#include "usb_net.h"
#include "wg.h"
#include "wifi_conn.h"
#include "wireguardif.h" // WIREGUARDIF_MTU for the DHCP option

// Bring-up island addressing, used while the WireGuard config is incomplete:
// the host is leased on-link reachability to the portal and nothing more (no
// router/routes/DNS -- see dhcp_server.h). An address pair at the top of
// 172.16/12 to make collision with a real LAN unlikely; once provisioned, the
// link is re-addressed with the tunnel pair and this subnet disappears.
#define BRINGUP_DEV_ADDR PP_HTONL(0xAC1FFF01u)  // 172.31.255.1
#define BRINGUP_HOST_ADDR PP_HTONL(0xAC1FFF02u) // 172.31.255.2
#define BRINGUP_PREFIX 30

// The mDNS hostname: the portal is http://pico-wg.local in every device state.
#define MDNS_HOSTNAME "pico-wg"

// Watchdog timeout. If the main loop stops feeding the watchdog for this long,
// the chip resets and USB re-enumerates instead of needing a physical replug.
#define WDT_TIMEOUT_MS 4000u

// Crash telemetry that survives a watchdog reboot (see pico-usb-wifi). The C
// runtime does not clear .uninitialized_data, so on a warm reset these fields
// retain the values last written before the firmware hung.
#define CRASHLOG_MAGIC 0x50574731u // "PWG1"
typedef struct {
  uint32_t magic;
  uint32_t from_host, to_host, txdrop, poolfail, ring_max;
  uint32_t boots;
  uint32_t hangs;
  uint32_t faults;
  uint32_t fault_pc;
  uint32_t fault_lr;
  uint32_t fault_pending;
} crashlog_t;
static crashlog_t crashlog __attribute__((section(".uninitialized_data.crashlog")));

// Hard-fault handler: record the faulting PC/LR into the crashlog (which
// survives the reset) and reboot immediately. Overrides the pico-sdk weak
// isr_hardfault.
void __attribute__((used)) fault_capture(uint32_t pc, uint32_t lr) {
  crashlog.magic = CRASHLOG_MAGIC;
  crashlog.fault_pc = pc;
  crashlog.fault_lr = lr;
  crashlog.fault_pending = 1;
  watchdog_reboot(0, 0, 0);
  while (1) tight_loop_contents();
}

void __attribute__((naked, used)) isr_hardfault(void) {
  __asm volatile(
      "movs r0, #4         \n" // select the stack the fault frame is on
      "mov  r1, lr         \n" // (EXC_RETURN bit 2: 0 = MSP, 1 = PSP)
      "tst  r0, r1         \n"
      "beq  1f             \n"
      "mrs  r0, psp        \n"
      "b    2f             \n"
      "1:  mrs r0, msp     \n"
      "2:  ldr r1, [r0, #20] \n" // stacked LR  -> r1 (arg1)
      "    ldr r0, [r0, #24] \n" // stacked PC  -> r0 (arg0)
      "    ldr r2, =fault_capture \n"
      "    bx  r2          \n"
      "    .ltorg          \n");
}

// Apply WireGuard/addressing config immediately: re-address the USB link,
// restart the DHCP server, and re-create the tunnel. An incomplete WireGuard
// config gets the bring-up island instead, so the portal is reachable at a
// known v4 address out of the box. Either way the v6 link-local address (and
// with it http://pico-wg.local) is untouched -- the portal never moves.
static void apply_wg(const config_t *cfg) {
  if (config_wg_complete(cfg)) {
    usb_net_set_addr(cfg->wg.addr, cfg->wg.prefix);
    dhcp_server_start(&dhcp_usb, usb_net_netif(), cfg->wg.host_addr, cfg->wg.prefix,
                      cfg->wg.dns, cfg->wg.host_mtu ? cfg->wg.host_mtu : WIREGUARDIF_MTU,
                      cfg->wg.routes, cfg->wg.route_count, false);
    // MSS clamp = configured path MTU minus IP+TCP headers, so TCP fits even
    // when the host ignores/rejects the DHCP MTU (macOS floors at 1280).
    usb_net_set_mss_clamp(cfg->wg.host_mtu ? (uint16_t)(cfg->wg.host_mtu - 40) : 0);
  } else {
    usb_net_set_addr(BRINGUP_DEV_ADDR, BRINGUP_PREFIX);
    dhcp_server_start(&dhcp_usb, usb_net_netif(), BRINGUP_HOST_ADDR, BRINGUP_PREFIX, 0,
                      1500, NULL, 0, true);
    usb_net_set_mss_clamp(0);
  }
  wg_apply(cfg, &cyw43_state.netif[CYW43_ITF_STA]);
  // The AP hands out the tunnel-side DNS/MTU, so it follows WireGuard changes
  // too (ap_apply is a no-op when nothing it uses changed).
  ap_apply(cfg);
  // Re-announce so hosts' mDNS caches follow the v4 re-addressing.
  cyw43_arch_lwip_begin();
  mdns_resp_announce(usb_net_netif());
  cyw43_arch_lwip_end();

  // If the USB-link subnet itself changed (island <-> tunnel pair), schedule a
  // logical replug so the host re-DHCPs onto it without a manual reboot. Not
  // on the boot-time apply -- the host is still enumerating the device then.
  // While a bounce is pending, every further apply re-arms it: a provisioning
  // burst (each `set` lands here) pushes the replug past its own last command,
  // so the console it is talking over isn't yanked mid-conversation.
  uint32_t now_addr = config_wg_complete(cfg) ? cfg->wg.addr : BRINGUP_DEV_ADDR;
  static uint32_t applied_addr;
  static bool applied_once;
  if (applied_once && (now_addr != applied_addr || usb_net_bounce_pending())) {
    usb_net_schedule_bounce();
  }
  applied_once = true;
  applied_addr = now_addr;
}

// Free RAM: heap region minus what malloc holds out (debug console gauge).
static uint32_t free_ram(void) {
  extern char __StackLimit, __bss_end__;
  struct mallinfo mi = mallinfo();
  return (uint32_t)(&__StackLimit - &__bss_end__) - (uint32_t)mi.uordblks;
}

// Human-readable cyw43 station link status for the debug console.
static const char *link_reason(int s) {
  switch (s) {
    case CYW43_LINK_DOWN: return "down";
    case CYW43_LINK_JOIN: return "join";
    case CYW43_LINK_NOIP: return "noip";
    case CYW43_LINK_UP: return "up";
    case CYW43_LINK_FAIL: return "fail";
    case CYW43_LINK_NONET: return "nonet";
    case CYW43_LINK_BADAUTH: return "badauth";
    default: return "?";
  }
}

int main(void) {
  stdio_uart_init();

  config_t cfg;
  config_load(&cfg);

  bool warm = watchdog_caused_reboot() && crashlog.magic == CRASHLOG_MAGIC;
  crashlog_t pre = crashlog;
  bool fault_recovered = warm && pre.fault_pending;
  bool hang_recovered = warm && !pre.fault_pending;
  if (crashlog.magic != CRASHLOG_MAGIC) {
    memset(&crashlog, 0, sizeof(crashlog));
    crashlog.magic = CRASHLOG_MAGIC;
  }
  crashlog.boots++;
  if (fault_recovered) crashlog.faults++;
  if (hang_recovered) crashlog.hangs++;
  crashlog.fault_pending = 0;

  // Bump the boot counter behind TAI64N before any handshake can happen.
  wg_time_init();

  // cyw43_arch_init also initialises lwIP; the station netif gets a DHCP
  // client from the cyw43 glue and stays the default netif until the tunnel
  // is up. The route hook (wg.c) keeps forwarded traffic off it regardless.
  if (cyw43_arch_init_with_country(cfg.country)) {
    printf("cyw43_arch_init failed\n");
    return -1;
  }
  cyw43_arch_enable_sta_mode();
  struct netif *sta = &cyw43_state.netif[CYW43_ITF_STA];

  // Locally-originated packets leave the stack with L4 checksum 0 (checksum
  // generation is compiled out so lwIP's forward path stops zeroing transit
  // traffic -- see lwipopts.h); restore them at the radio egress. The USB and
  // tunnel egress hops have their own restorers.
  eth_csum_wrap(sta);

  // The cyw43 glue gives the station netif a v6 link-local address and enables
  // SLAAC. Strip both: v6 belongs to the USB link only -- the Wi-Fi side must
  // never acquire an address the tunnel doesn't cover (see lwipopts.h).
  netif_set_ip6_autoconfig_enabled(sta, 0);
  netif_ip6_addr_set_state(sta, 0, IP6_ADDR_INVALID);

  // USB side: CDC-NCM netif; addressing (tunnel pair or bring-up island) is
  // applied by apply_wg below. v6 link-local comes up inside usb_net_init.
  if (!usb_net_init(cfg.wg.addr, cfg.wg.prefix)) {
    printf("failed to start usb network\n");
    return -1;
  }

  // pico-wg.local -> the portal, in every provisioning state, plus a
  // _http._tcp service record so it shows up in Bonjour browsing.
  cyw43_arch_lwip_begin();
  mdns_resp_init();
  mdns_resp_add_netif(usb_net_netif(), MDNS_HOSTNAME);
  mdns_resp_add_service(usb_net_netif(), "pico-wg portal", "_http", DNSSD_PROTO_TCP, 80,
                        NULL, NULL);
  cyw43_arch_lwip_end();

  http_portal_init(&cfg);
  serial_bridge_init();
  serial_console_init(&cfg);
  config_proto_set_apply(wifi_conn_apply);
  config_proto_set_apply_wg(apply_wg);
  config_proto_set_apply_ap(ap_apply);

  // The connection manager owns station association from here on: it joins
  // the active profile now, and falls back to scan-and-pick across all saved
  // profiles whenever that (or any later association) fails.
  wifi_conn_init(&cfg);

  apply_wg(&cfg);
  printf("setup complete\n");

  watchdog_enable(WDT_TIMEOUT_MS, true);

  int key = 0;
  uint32_t last_led = 0;
  uint32_t last_dbg = 0;
  uint32_t last_wg_poll = 0;
  bool was_wg_up = false;
  bool led_on = false;
  bool hang_reported = false;
  while ((key != 's') && (key != 'S')) {
    watchdog_update();
    usb_net_update();      // USB datapath pump
    serial_console_task(); // CDC-ACM management console
    debug_console_task();  // CDC-ACM debug console (drain input)
    serial_bridge_task();  // CDC <-> UART1 <-> TCP party line

    uint32_t now = to_ms_since_boot(get_absolute_time());
    wifi_conn_task(now); // station association state machine (rate-limited)

    if (now - last_wg_poll >= 1000u) {
      last_wg_poll = now;
      wg_poll(); // endpoint resolution, handshake kicks, session monitoring
      if (wg_session_up() != was_wg_up) {
        was_wg_up = wg_session_up();
        if (cfg.debug_enabled) {
          debug_printf(was_wg_up ? "wireguard session up\n" : "wireguard session down\n");
        }
      }
    }

    if ((fault_recovered || hang_recovered) && !hang_reported && usb_net_is_up()) {
      hang_reported = true;
      if (fault_recovered) {
        debug_printf("RECOVERED from HARD FAULT pc=0x%08lx lr=0x%08lx (fault #%lu, boot #%lu)\n",
                     (unsigned long)pre.fault_pc, (unsigned long)pre.fault_lr,
                     (unsigned long)crashlog.faults, (unsigned long)crashlog.boots);
        printf("RECOVERED from HARD FAULT pc=0x%08lx lr=0x%08lx\n",
               (unsigned long)pre.fault_pc, (unsigned long)pre.fault_lr);
      } else {
        debug_printf("RECOVERED from hang (watchdog timeout, no fault; hang #%lu, boot #%lu)\n",
                     (unsigned long)crashlog.hangs, (unsigned long)crashlog.boots);
        printf("RECOVERED from hang via watchdog (hang #%lu)\n", (unsigned long)crashlog.hangs);
      }
    }

    // Periodic stats on the debug console, only when enabled.
    if (cfg.debug_enabled && (now - last_dbg >= 2000u)) {
      last_dbg = now;
      usb_net_stats_t s;
      usb_net_get_stats(&s);
      const char *link = netif_is_link_up(sta)
                             ? "up"
                             : link_reason(cyw43_wifi_link_status(&cyw43_state, CYW43_ITF_STA));
      char sta_ip[16];
      ip4addr_ntoa_r(netif_ip4_addr(sta), sta_ip, sizeof(sta_ip));
      debug_printf("stats: h>%lu >h%lu txdrop=%lu poolfail=%lu ringpk=%lu wifi=%s(%s) "
                   "wg=%s lease=%s hangs=%lu faults=%lu freeram=%lu\n",
                   (unsigned long)s.from_host, (unsigned long)s.to_host,
                   (unsigned long)s.txdrop, (unsigned long)s.poolfail,
                   (unsigned long)usb_net_ring_recent_reset(), link, sta_ip, wg_state_str(),
                   dhcp_server_leased(&dhcp_usb) ? "yes" : "no", (unsigned long)crashlog.hangs,
                   (unsigned long)crashlog.faults, (unsigned long)free_ram());
    }

    // LED:
    //   solid              = tunnel up (session established)
    //   slow blink (1 Hz)  = associating / handshaking
    //   fast blink (5 Hz)  = unprovisioned (Wi-Fi or WireGuard config missing)
    //   double-flash       = live (continuous) scan
    //   off                = USB not ready
    if (config_proto_contscan_active()) {
      uint32_t t = now % 2000u;
      bool on = usb_net_is_up() && ((t < 70u) || (t >= 220u && t < 290u));
      if (on != led_on) {
        cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, on);
        led_on = on;
      }
    } else if (now - last_led >= 50u) {
      last_led = now;

      usb_net_stats_t cs;
      usb_net_get_stats(&cs);
      crashlog.from_host = cs.from_host;
      crashlog.to_host = cs.to_host;
      crashlog.txdrop = cs.txdrop;
      crashlog.poolfail = cs.poolfail;
      crashlog.ring_max = cs.ring_max;

      bool usb_ok = usb_net_is_up();
      // With multi-profile auto-join, "Wi-Fi provisioned" means any saved
      // network at all -- the manager finds whichever one is in range.
      bool provisioned = cfg.profile_count > 0 && config_wg_complete(&cfg);
      bool on;
      if (!usb_ok) {
        on = false;
      } else if (wg_session_up()) {
        on = true;
      } else if (!provisioned) {
        on = (now % 200u) < 100u;
      } else {
        on = (now % 1000u) < 500u;
      }
      cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, on);
      led_on = on;
    }

    key = getchar_timeout_us(0);
  }

  printf("shutting down\n");
  usb_net_deinit();
  cyw43_arch_deinit();
  return 0;
}
