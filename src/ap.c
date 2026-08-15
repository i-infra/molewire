// Quarantine access point. See ap.h.

#include <stdio.h>
#include <string.h>

#include <lwip/netif.h>
#include <pico/cyw43_arch.h>

#include "ap.h"
#include "dhcp_server.h"
#include "eth_csum.h"
#include "pcap.h"
#include "wg.h"
#include "wireguardif.h" // WIREGUARDIF_MTU for the DHCP option

static bool ap_up;

// What the AP was last brought up with; a re-apply that changes none of it is
// a no-op so unrelated config changes never bounce the wireless client.
static ap_config_t applied;
static uint32_t applied_dns;
static uint16_t applied_mtu;

static struct netif *ap_nif(void) { return &cyw43_state.netif[CYW43_ITF_AP]; }

struct netif *ap_active_netif(void) { return ap_up ? ap_nif() : NULL; }

// --- pcap taps -------------------------------------------------------------------
//
// The quarantine's instrumentation: both directions of the AP link feed the
// same capture ring as the USB link, so the .pcap shows exactly what the
// contained device does. Installed by swapping the netif's input/linkoutput
// pointers for wrappers (the cyw43 lwIP glue owns the netif, so there is no
// hook to register; re-enabling the AP re-adds the netif and resets the
// pointers, hence the idempotent re-wrap in ap_apply).

static netif_input_fn orig_input;
static err_t (*orig_linkoutput)(struct netif *n, struct pbuf *p);

static void tap_frame(const struct pbuf *p) {
  if (p->len == p->tot_len) {
    pcap_capture((const uint8_t *)p->payload, p->tot_len);
    return;
  }
  // Chained pbuf: flatten what the snaplen can keep; the record still carries
  // the original length. (pcap_capture copies at most 256 bytes -- exactly
  // what was flattened here.)
  uint8_t snap[256];
  uint16_t n = (uint16_t)LWIP_MIN(p->tot_len, sizeof(snap));
  pbuf_copy_partial((struct pbuf *)p, snap, n, 0);
  pcap_capture(snap, (uint16_t)p->tot_len);
}

static err_t ap_input_tap(struct pbuf *p, struct netif *inp) {
  tap_frame(p);
  return orig_input(p, inp);
}

static err_t ap_linkoutput_tap(struct netif *n, struct pbuf *p) {
  // Device-originated frames (DHCP offers, ICMP/TCP replies to the client)
  // carry zero L4 checksums until an egress hop restores them (lwipopts.h);
  // do it before the tap so the capture shows what actually hits the air.
  eth_csum_restore(p);
  tap_frame(p);
  return orig_linkoutput(n, p);
}

// --- radio-level single client -----------------------------------------------------

// Cap associations at one via the "maxassoc" iovar on the AP interface
// (WLC_SET_VAR = 263; cyw43_ioctl wants cmd << 1 | set). The DHCP scope's
// single lease and the tiny subnet already bound the design; this makes the
// radio refuse a second association outright. Best-effort: an unsupported
// iovar just logs.
static void ap_limit_to_one_sta(void) {
  uint8_t buf[13];
  memcpy(buf, "maxassoc", 9); // 8 chars + NUL
  buf[9] = 1;
  buf[10] = buf[11] = buf[12] = 0;
  int r = cyw43_ioctl(&cyw43_state, (263u << 1) | 1u, sizeof(buf), buf, CYW43_ITF_AP);
  if (r != 0) {
    printf("ap: maxassoc=1 not accepted (%d); relying on the single DHCP lease\n", r);
  }
}

int ap_client_count(void) {
  if (!ap_up) {
    return 0;
  }
  int num = 4; // buffer capacity in stations; maxassoc clamps the real answer
  uint8_t macs[4 * 6];
  cyw43_wifi_ap_get_stas(&cyw43_state, &num, macs);
  return num;
}

// --- lifecycle -------------------------------------------------------------------

static void ap_teardown(void) {
  cyw43_arch_disable_ap_mode();
  struct netif *n = ap_nif();
  cyw43_arch_lwip_begin();
  // The driver only drops the radio-side BSS; the netif stays in lwIP's list.
  // Take it down and clear its address so it can't match any route or
  // is-own-address check while disabled.
  netif_set_link_down(n);
  netif_set_down(n);
  netif_set_addr(n, IP4_ADDR_ANY4, IP4_ADDR_ANY4, IP4_ADDR_ANY4);
  cyw43_arch_lwip_end();
  dhcp_server_start(&dhcp_ap, n, 0, 0, 0, 0, NULL, 0, false);
  ap_up = false;
}

void ap_apply(const config_t *cfg) {
  bool want = cfg->ap.enabled && config_ap_complete(cfg);
  uint32_t dns = cfg->wg.dns;
  uint16_t mtu = cfg->wg.host_mtu ? cfg->wg.host_mtu : WIREGUARDIF_MTU;

  if (ap_up && want && memcmp(&applied, &cfg->ap, sizeof(applied)) == 0 &&
      applied_dns == dns && applied_mtu == mtu) {
    return; // nothing relevant changed
  }
  if (ap_up) {
    ap_teardown(); // parameters changed (or disabling): start from scratch
  }
  if (!want) {
    return;
  }

  // WPA2-PSK only -- config_ap_complete refused empty/short passwords, so an
  // open AP can't happen. The radio forces the AP onto the station's channel
  // whenever the station is associated (one radio); the channel the driver
  // sets here is only used until then.
  cyw43_arch_enable_ap_mode(cfg->ap.ssid, cfg->ap.password, CYW43_AUTH_WPA2_AES_PSK);
  ap_limit_to_one_sta();

  struct netif *n = ap_nif();
  cyw43_arch_lwip_begin();
  // The cyw43 glue just gave the netif 192.168.4.1/24 and made it the DEFAULT
  // netif. Both are wrong here: re-address with the configured AP pair and
  // give the default back to the tunnel (or the station while it's down) --
  // otherwise the device's own traffic would route out the AP.
  ip4_addr_t a, m, g;
  ip4_addr_set_u32(&a, cfg->ap.addr);
  ip4_addr_set_u32(&m, lwip_htonl(0xFFFFFFFFu << (32 - cfg->ap.prefix)));
  ip4_addr_set_any(&g);
  netif_set_addr(n, &a, &m, &g);
  struct netif *wg = wg_session_up() ? wg_active_netif() : NULL;
  netif_set_default(wg ? wg : &cyw43_state.netif[CYW43_ITF_STA]);
  if (n->input != ap_input_tap) {
    orig_input = n->input;
    n->input = ap_input_tap;
  }
  if (n->linkoutput != ap_linkoutput_tap) {
    orig_linkoutput = n->linkoutput;
    n->linkoutput = ap_linkoutput_tap;
  }
  cyw43_arch_lwip_end();

  // Gateway mode always: the AP client's only link is us, so split routing is
  // meaningless there. DNS and MTU are the tunnel-side values, same story as
  // the USB host's lease.
  dhcp_server_start(&dhcp_ap, n, cfg->ap.client_addr, cfg->ap.prefix, dns, mtu, NULL, 0,
                    false);

  applied = cfg->ap;
  applied_dns = dns;
  applied_mtu = mtu;
  ap_up = true;
}
