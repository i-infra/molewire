// WireGuard tunnel management and platform layer. See wg.h.

#include <stdio.h>
#include <string.h>

#include <hardware/flash.h>
#include <lwip/dns.h>
#include <lwip/ip4_addr.h>
#include <lwip/netif.h>
#include <lwip/sys.h>
#include <pico/cyw43_arch.h>
#include <pico/flash.h>
#include <pico/rand.h>
#include <pico/stdlib.h>

#include "ap.h"     // AP netif for the route hook's client isolation
#include "crypto.h" // wireguard_x25519 for on-device keypair generation
#include "usb_net.h"
#include "wg.h"
#include "wireguard-platform.h"
#include "wireguard.h" // wireguard_base64_decode for the PSK
#include "wireguardif.h"

// --- state ----------------------------------------------------------------------

static struct netif wg_netif;
static bool wg_netif_added;
static uint8_t wg_peer_idx = WIREGUARDIF_INVALID_INDEX;
static struct netif *sta_netif;

// The live config the tunnel was applied with (wireguardif keeps pointers into
// its init data only during init; the peer public key pointer must stay valid,
// so keep our own stable copy).
static wg_config_t wgc;
static bool wg_configured;

static enum { WG_UNCONFIGURED, WG_RESOLVING, WG_HANDSHAKING, WG_UP } wg_state;
static ip_addr_t endpoint_addr;
static bool endpoint_resolved;
static uint32_t last_kick_ms;
static uint32_t last_resolve_ms;

// Blackhole for forwarded packets that may not be routed yet (tunnel interface
// absent). Never netif_add()ed -- returned only from the route hook, so normal
// routing can never select it. Output "succeeds" and the packet evaporates.
static err_t blackhole_output(struct netif *n, struct pbuf *p, const ip4_addr_t *a) {
  (void)n;
  (void)p;
  (void)a;
  return ERR_OK;
}

static struct netif blackhole_netif = {
    .output = blackhole_output,
    .mtu = 1500,
    .flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP,
    .name = {'b', 'h'},
};

// --- platform layer (wireguard-platform.h) ---------------------------------------

uint32_t wireguard_sys_now(void) { return to_ms_since_boot(get_absolute_time()); }

// pico_rand: on RP2350 seeded from the hardware TRNG.
void wireguard_random_bytes(void *bytes, size_t size) {
  uint8_t *p = (uint8_t *)bytes;
  while (size >= 8) {
    uint64_t r = get_rand_64();
    memcpy(p, &r, 8);
    p += 8;
    size -= 8;
  }
  if (size) {
    uint64_t r = get_rand_64();
    memcpy(p, &r, size);
  }
}

bool wireguard_is_under_load(void) {
  return false; // single peer, we initiate; the cookie-reply path is moot
}

// --- on-device keypair -----------------------------------------------------------

// The X25519 generator, as in the WireGuard reference implementation.
static const uint8_t curve_basepoint[32] = {9};

bool wg_keypair_generate(uint8_t pub[32], uint8_t priv[32]) {
  wireguard_random_bytes(priv, 32); // hardware TRNG via pico_rand
  priv[0] &= 248;                   // curve25519 clamp
  priv[31] = (uint8_t)((priv[31] & 127) | 64);
  return wireguard_x25519(pub, priv, curve_basepoint) == 0;
}

bool wg_public_from_private(uint8_t pub[32], const uint8_t priv[32]) {
  return wireguard_x25519(pub, priv, curve_basepoint) == 0;
}

struct netif *wg_active_netif(void) { return wg_netif_added ? &wg_netif : NULL; }

// TAI64N without NTP. WireGuard's handshake timestamp only has to be strictly
// increasing as seen by the server, not a real time. A flash-backed boot
// counter provides the increase across reboots; uptime provides it within one
// boot. Each boot gets a 2^25-second (~1 year) window, so the value from boot
// N+1 always exceeds anything boot N could have produced.
// Second-to-last sector: the last one is erased by the bootrom on every UF2
// download (RP2350-E10) -- see the flash layout note in config.c.
#define BOOTCOUNT_MAGIC 0x43424757u // "WGBC"
#define BOOTCOUNT_FLASH_OFFSET (PICO_FLASH_SIZE_BYTES - 2 * FLASH_SECTOR_SIZE)

static uint32_t boot_count;

static void bootcount_flash_write(void *param) {
  (void)param;
  static uint32_t rec[2];
  rec[0] = BOOTCOUNT_MAGIC;
  rec[1] = boot_count;
  flash_range_erase(BOOTCOUNT_FLASH_OFFSET, FLASH_SECTOR_SIZE);
  flash_range_program(BOOTCOUNT_FLASH_OFFSET, (const uint8_t *)rec, sizeof(rec));
}

void wg_time_init(void) {
  const uint32_t *rec = (const uint32_t *)(XIP_BASE + BOOTCOUNT_FLASH_OFFSET);
  boot_count = (rec[0] == BOOTCOUNT_MAGIC) ? rec[1] + 1 : 1;
  if (flash_safe_execute(bootcount_flash_write, NULL, 1000) != PICO_OK) {
    printf("wg: boot counter write failed\n");
  }
}

void wireguard_tai64n_now(uint8_t *output) {
  // TAI64 label for the epoch, as used by the reference implementations.
  uint64_t millis = wireguard_sys_now();
  uint64_t seconds = 0x400000000000000aULL + ((uint64_t)boot_count << 25) + millis / 1000u;
  uint32_t nanos = (uint32_t)(millis % 1000u) * 1000000u;
  for (int i = 0; i < 8; i++) {
    output[i] = (uint8_t)(seconds >> (56 - 8 * i));
  }
  for (int i = 0; i < 4; i++) {
    output[8 + i] = (uint8_t)(nanos >> (24 - 8 * i));
  }
}

// --- route hook (host isolation) --------------------------------------------------

// True when a is inside the USB-link subnet (valid only while provisioned).
static bool in_usb_subnet(const ip4_addr_t *a) {
  struct netif *usb = usb_net_netif();
  if (ip4_addr_isany_val(*netif_ip4_addr(usb))) {
    return false;
  }
  return ip4_addr_net_eq(a, netif_ip4_addr(usb), netif_ip4_netmask(usb));
}

// True when a is inside the AP-link subnet (only while the AP is up).
static bool in_ap_subnet(const ip4_addr_t *a) {
  struct netif *ap = ap_active_netif();
  if (!ap || ip4_addr_isany_val(*netif_ip4_addr(ap))) {
    return false;
  }
  return ip4_addr_net_eq(a, netif_ip4_addr(ap), netif_ip4_netmask(ap));
}

static bool is_own_addr(const ip4_addr_t *a) {
  struct netif *n;
  NETIF_FOREACH(n) {
    if (!ip4_addr_isany_val(*netif_ip4_addr(n)) && ip4_addr_eq(a, netif_ip4_addr(n))) {
      return true;
    }
  }
  return false;
}

// LWIP_HOOK_IP4_ROUTE_SRC. Called for every routing decision that knows a
// source address -- most importantly ip4_forward(), where src is the forwarded
// packet's source. Locally-originated traffic (src unset or one of our own
// addresses) returns NULL and routes normally: the station netif stays usable
// for DHCP, endpoint DNS, and the tunnel's outer UDP (which is pinned to the
// station PCB anyway). Everything else is forwarded traffic and is confined to
// its client link and the tunnel; with no tunnel interface it is blackholed.
// This is the property "a client can only ever reach the WireGuard LAN" --
// and the USB host and AP client cannot reach each other: each client's
// packets may exit only via the tunnel, never the other client's link.
struct netif *wg_ip4_route_hook(const struct ip4_addr *src, const struct ip4_addr *dest) {
  if (src == NULL || ip4_addr_isany(src) || is_own_addr(src)) {
    return NULL; // our own traffic: normal routing
  }
  if (in_usb_subnet(dest)) {
    // Delivery toward the USB host -- unless it came from the AP client.
    return in_ap_subnet(src) ? &blackhole_netif : usb_net_netif();
  }
  if (in_ap_subnet(dest)) {
    // Delivery toward the AP client -- unless it came from the USB host.
    return in_usb_subnet(src) ? &blackhole_netif : ap_active_netif();
  }
  if (wg_netif_added) {
    return &wg_netif; // into the tunnel (drops until the session is up)
  }
  return &blackhole_netif;
}

// --- tunnel lifecycle --------------------------------------------------------------

static void wg_teardown(void) {
  cyw43_arch_lwip_begin();
  if (wg_netif_added) {
    if (netif_default == &wg_netif) {
      netif_set_default(sta_netif);
    }
    if (wg_peer_idx != WIREGUARDIF_INVALID_INDEX) {
      wireguardif_disconnect(&wg_netif, wg_peer_idx);
      wireguardif_remove_peer(&wg_netif, wg_peer_idx);
      wg_peer_idx = WIREGUARDIF_INVALID_INDEX;
    }
    wireguardif_shutdown(&wg_netif);
    netif_remove(&wg_netif);
    wg_netif_added = false;
  }
  cyw43_arch_lwip_end();
  wg_state = WG_UNCONFIGURED;
  endpoint_resolved = false;
}

// Add the peer once the endpoint address is known, and start handshaking.
static void wg_add_peer_and_connect(void) {
  struct wireguardif_peer peer;
  wireguardif_peer_init(&peer);
  peer.public_key = wgc.peer_public;
  static uint8_t psk[32];
  if (wgc.psk[0]) {
    size_t psk_len = sizeof(psk);
    if (wireguard_base64_decode(wgc.psk, psk, &psk_len) && psk_len == 32) {
      peer.preshared_key = psk;
    }
  }
  // AllowedIPs 0.0.0.0/0: the tunnel claims everything the route hook and the
  // default route send it.
  ip4_addr_set_any(ip_2_ip4(&peer.allowed_ip));
  ip4_addr_set_any(ip_2_ip4(&peer.allowed_mask));
  peer.endpoint_ip = endpoint_addr;
  peer.endport_port = wgc.endpoint_port;
  if (wgc.keepalive) {
    peer.keep_alive = wgc.keepalive;
  }

  cyw43_arch_lwip_begin();
  err_t err = wireguardif_add_peer(&wg_netif, &peer, &wg_peer_idx);
  if (err == ERR_OK && wg_peer_idx != WIREGUARDIF_INVALID_INDEX) {
    wireguardif_connect(&wg_netif, wg_peer_idx);
    wg_state = WG_HANDSHAKING;
  } else {
    printf("wg: add_peer failed (%d)\n", (int)err);
    wg_state = WG_UNCONFIGURED;
  }
  cyw43_arch_lwip_end();
  last_kick_ms = wireguard_sys_now();
}

static void dns_resolved_cb(const char *name, const ip_addr_t *ipaddr, void *arg) {
  (void)name;
  (void)arg;
  if (ipaddr) {
    endpoint_addr = *ipaddr;
    endpoint_resolved = true;
  }
  // On failure leave endpoint_resolved false; wg_poll retries.
}

void wg_apply(const config_t *cfg, struct netif *sta) {
  sta_netif = sta;
  wg_teardown();

  wg_configured = config_wg_complete(cfg);
  if (!wg_configured) {
    return;
  }
  wgc = cfg->wg;

  // Endpoint: literal IPv4, or a hostname resolved once Wi-Fi is up.
  ip4_addr_t lit;
  if (ip4addr_aton(wgc.endpoint, &lit)) {
    ip_addr_copy_from_ip4(endpoint_addr, lit);
    endpoint_resolved = true;
  }

  static struct wireguardif_init_data init_data;
  init_data.private_key = wgc.private_key;
  init_data.listen_port = WIREGUARDIF_DEFAULT_PORT;
  init_data.bind_netif = sta; // pin the outer UDP to Wi-Fi: never up our own tunnel

  ip4_addr_t addr, mask, gw;
  ip4_addr_set_u32(&addr, wgc.addr);
  // /32: route lookups for the USB-link subnet must keep matching the USB
  // netif; the tunnel gets everything else via default route + route hook.
  ip4_addr_set_u32(&mask, 0xFFFFFFFFu);
  ip4_addr_set_any(&gw);

  cyw43_arch_lwip_begin();
  if (netif_add(&wg_netif, &addr, &mask, &gw, &init_data, wireguardif_init, ip_input)) {
    wg_netif_added = true;
    // Advertise the measured/configured path MTU on the tunnel netif so
    // oversized forwards get fragmented or answered with ICMP frag-needed
    // instead of black-holing beyond a re-encapsulating server.
    if (wgc.host_mtu && wgc.host_mtu < wg_netif.mtu) {
      wg_netif.mtu = wgc.host_mtu;
    }
    netif_set_up(&wg_netif);
    wg_state = WG_RESOLVING; // waiting for endpoint and/or Wi-Fi
  } else {
    printf("wg: netif_add failed (bad private key?)\n");
  }
  cyw43_arch_lwip_end();
}

void wg_poll(void) {
  if (!wg_configured || !wg_netif_added) {
    return;
  }
  uint32_t now = wireguard_sys_now();

  // Nothing to do until the station is associated (outer packets need Wi-Fi).
  if (!sta_netif || !netif_is_link_up(sta_netif)) {
    return;
  }

  if (wg_state == WG_RESOLVING) {
    if (!endpoint_resolved) {
      if (now - last_resolve_ms >= 15000u || last_resolve_ms == 0) {
        last_resolve_ms = now;
        cyw43_arch_lwip_begin();
        ip_addr_t out;
        err_t err = dns_gethostbyname(wgc.endpoint, &out, dns_resolved_cb, NULL);
        cyw43_arch_lwip_end();
        if (err == ERR_OK) { // cached
          endpoint_addr = out;
          endpoint_resolved = true;
        }
      }
    }
    if (endpoint_resolved) {
      wg_add_peer_and_connect();
    }
    return;
  }

  // Session monitoring. wireguardif re-handshakes on traffic; a periodic kick
  // covers the quiet case so the tunnel comes back without host traffic.
  cyw43_arch_lwip_begin();
  bool up = (wg_peer_idx != WIREGUARDIF_INVALID_INDEX) &&
            (wireguardif_peer_is_up(&wg_netif, wg_peer_idx, NULL, NULL) == ERR_OK);
  cyw43_arch_lwip_end();

  if (up && wg_state != WG_UP) {
    wg_state = WG_UP;
    cyw43_arch_lwip_begin();
    netif_set_default(&wg_netif); // Pico-originated traffic now prefers the tunnel
    cyw43_arch_lwip_end();
  } else if (!up && wg_state == WG_UP) {
    wg_state = WG_HANDSHAKING;
    cyw43_arch_lwip_begin();
    netif_set_default(sta_netif); // so a DNS re-resolve can still work
    wireguardif_connect(&wg_netif, wg_peer_idx);
    cyw43_arch_lwip_end();
    last_kick_ms = now;
  } else if (!up && now - last_kick_ms >= 10000u) {
    last_kick_ms = now;
    cyw43_arch_lwip_begin();
    wireguardif_connect(&wg_netif, wg_peer_idx);
    cyw43_arch_lwip_end();
  }
}

bool wg_session_up(void) { return wg_state == WG_UP; }

const char *wg_state_str(void) {
  switch (wg_state) {
    case WG_RESOLVING: return endpoint_resolved ? "starting" : "resolving";
    case WG_HANDSHAKING: return "handshaking";
    case WG_UP: return "up";
    default: return "unconfigured";
  }
}
