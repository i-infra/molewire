// USB CDC-NCM network interface as a routed lwIP netif. See usb_net.h.
//
// Derived from pico-usb-wifi's usb_network.c (MIT, Peter Lawrence / Matthew
// Bennett, influenced by lrndis); reworked from a transparent L2 bridge into a
// proper lwIP interface so packets can be routed through the WireGuard netif.

#include <string.h>

#include <hardware/sync.h>
#include <lwip/etharp.h>
#include <lwip/ethip6.h>
#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <netif/ethernet.h>
#include <pico/cyw43_arch.h>
#include <pico/stdlib.h>
#include <pico/unique_id.h>
#include <tusb.h>

#include "debug_console.h"
#include "pcap.h"
#include "usb_net.h"

// The MAC TinyUSB reports in the NCM iMACAddress string descriptor -- the
// address the HOST's interface adopts. Derived from the flash unique ID; the
// Pico-side netif uses the same bytes with a different low bit so the two ends
// of the USB link have distinct addresses.
uint8_t tud_network_mac_address[6];

static struct netif usb_netif;

// A single host->device frame staged by tud_network_recv_cb() for the main loop.
static struct pbuf *received_frame;

// Set when tud_network_recv_cb() had to drop a datagram (pbuf pool exhausted).
// The main loop must still call tud_network_recv_renew() to re-arm the NCM OUT
// endpoint; otherwise the host->device direction wedges (see pico-usb-wifi).
static bool recv_stalled;

static volatile uint32_t cnt_from_host;
static volatile uint32_t cnt_to_host;
static volatile uint32_t cnt_txdrop;
static volatile uint32_t cnt_poolfail;
static volatile uint32_t cnt_ring_max;
static volatile uint32_t cnt_ring_recent;

// Deferred to-host queue. The netif's linkoutput runs wherever lwIP routes a
// packet from -- including the cyw43 background context (a WireGuard-decrypted
// packet being forwarded to the host) -- but TinyUSB must only be touched from
// the main loop, so linkoutput pushes here and usb_tx_drain() transmits.
#define USB_TX_QUEUE_LEN 32
static struct pbuf *usb_tx_queue[USB_TX_QUEUE_LEN];
static volatile uint8_t usb_tx_head;
static volatile uint8_t usb_tx_tail;

static bool usb_tx_push(struct pbuf *q) {
  uint32_t save = save_and_disable_interrupts();
  uint8_t next = (uint8_t)((usb_tx_head + 1) % USB_TX_QUEUE_LEN);
  bool ok = (next != usb_tx_tail);
  if (ok) {
    usb_tx_queue[usb_tx_head] = q;
    usb_tx_head = next;
    uint8_t depth = (uint8_t)((usb_tx_head + USB_TX_QUEUE_LEN - usb_tx_tail) % USB_TX_QUEUE_LEN);
    if (depth > cnt_ring_max) cnt_ring_max = depth;
    if (depth > cnt_ring_recent) cnt_ring_recent = depth;
  }
  restore_interrupts(save);
  return ok;
}

// Drain queued frames to the host over USB -- MAIN LOOP ONLY.
static void usb_tx_drain(void) {
  while (usb_tx_tail != usb_tx_head) {
    struct pbuf *q = usb_tx_queue[usb_tx_tail];
    if (!tud_ready() || !tud_network_can_xmit(q->tot_len)) {
      break; // USB busy; try again next iteration
    }
    tud_network_xmit(q, 0);
    cnt_to_host++;
    uint32_t save = save_and_disable_interrupts();
    usb_tx_tail = (uint8_t)((usb_tx_tail + 1) % USB_TX_QUEUE_LEN);
    restore_interrupts(save);
    cyw43_arch_lwip_begin(); // pbuf pool is shared with the background Wi-Fi context
    pbuf_free(q);
    cyw43_arch_lwip_end();
  }
}

// lwIP linkoutput: queue the frame for the main loop. Always called with the
// lwIP lock held (lwIP only runs under it), so pbuf_ref/free need no extra lock.
static err_t usb_linkoutput(struct netif *n, struct pbuf *p) {
  (void)n;
  if (!tud_ready()) {
    cnt_txdrop++;
    return ERR_IF;
  }
  pbuf_ref(p); // the ring holds a reference until drained
  if (!usb_tx_push(p)) {
    pbuf_free(p);
    cnt_txdrop++;
    return ERR_MEM;
  }
  return ERR_OK;
}

static err_t usb_netif_init_cb(struct netif *n) {
  n->name[0] = 'u';
  n->name[1] = 's';
  n->mtu = 1500; // the host is clamped to the tunnel MTU via DHCP option 26
  n->hwaddr_len = 6;
  memcpy(n->hwaddr, tud_network_mac_address, 6);
  n->hwaddr[5] ^= 0x01; // distinct from the host's MAC on the same link
  // IGMP flag so ip4_input accepts joined multicast (mDNS); no mac filter
  // function is installed since the host's NCM frames all reach us anyway.
  n->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET |
             NETIF_FLAG_IGMP;
  n->output = etharp_output;
  n->linkoutput = usb_linkoutput;
#if LWIP_IPV6
  // v6 link-local rides the USB link so the portal has an address that never
  // changes across v4 re-provisioning. No MAC filter: the host's NCM frames
  // all reach us anyway, so multicast (ND, MLD, mDNS) needs no opt-in.
  n->output_ip6 = ethip6_output;
  n->flags |= NETIF_FLAG_MLD6;
#endif
  return ERR_OK;
}

// --- host TX checksum offload (defensive) ----------------------------------------
//
// If a host driver ever does TX checksum offload over NCM (hands us frames
// with zeroed checksums, expecting "the NIC" to fill them), repair them here
// before lwIP sees the packet. Empirically macOS and Linux both send valid
// checksums over NCM, so today this is a cheap no-op -- it exists so an
// offloading host can't silently poison forwarded traffic. (The zeroed
// checksums we actually chased in the field came from lwIP's own ip4_forward;
// that fix lives in wireguardif.c.)

static uint32_t csum_add(uint32_t sum, const uint8_t *d, uint16_t n) {
  while (n > 1) {
    sum += ((uint32_t)d[0] << 8) | d[1];
    d += 2;
    n = (uint16_t)(n - 2);
  }
  if (n) {
    sum += (uint32_t)d[0] << 8;
  }
  return sum;
}

static uint16_t csum_finish(uint32_t s) {
  while (s >> 16) {
    s = (s & 0xFFFF) + (s >> 16);
  }
  return (uint16_t)~s;
}

// TCP MSS clamp for forwarded connections, applied to SYNs in both directions.
// The end-to-end path MTU through a re-encapsulating server (e.g. a Tailscale
// bridge) can be well below anything the host will let us configure on its
// interface (macOS refuses MTU < 1280), so the router rewrites the MSS option
// like any commercial gateway would. 0 disables.
static uint16_t g_mss_clamp;

void usb_net_set_mss_clamp(uint16_t mss) { g_mss_clamp = mss; }

// Returns true if it rewrote the option (checksum must then be regenerated).
static bool clamp_tcp_mss(uint8_t *l4, uint16_t l4len) {
  if (!g_mss_clamp || l4len < 20 || !(l4[13] & 0x02)) {
    return false; // no clamp configured, or not a SYN
  }
  uint8_t doff = (uint8_t)((l4[12] >> 4) * 4);
  if (doff < 24 || doff > l4len) {
    return false; // no options present (or malformed)
  }
  uint16_t off = 20;
  while (off + 1 < doff) {
    uint8_t kind = l4[off];
    if (kind == 0) break; // end of options
    if (kind == 1) {      // NOP
      off++;
      continue;
    }
    uint8_t olen = l4[off + 1];
    if (olen < 2 || off + olen > doff) break;
    if (kind == 2 && olen == 4) { // MSS
      uint16_t mss = (uint16_t)(((uint16_t)l4[off + 2] << 8) | l4[off + 3]);
      if (mss > g_mss_clamp) {
        l4[off + 2] = (uint8_t)(g_mss_clamp >> 8);
        l4[off + 3] = (uint8_t)g_mss_clamp;
        return true;
      }
      return false;
    }
    off = (uint16_t)(off + olen);
  }
  return false;
}

static void fix_host_checksums(uint8_t *f, uint16_t flen) {
  if (flen < 34 || f[12] != 0x08 || f[13] != 0x00) {
    return; // not IPv4
  }
  uint8_t *ip = f + 14;
  uint8_t ihl = (uint8_t)((ip[0] & 0x0F) * 4);
  uint16_t tot = (uint16_t)(((uint16_t)ip[2] << 8) | ip[3]);
  if ((ip[0] >> 4) != 4 || ihl < 20 || tot < ihl || (uint16_t)(14 + tot) > flen) {
    return;
  }
  if (ip[10] == 0 && ip[11] == 0) { // header checksum 0 = offloaded
    uint16_t c = csum_finish(csum_add(0, ip, ihl));
    ip[10] = (uint8_t)(c >> 8);
    ip[11] = (uint8_t)c;
  }
  if ((ip[6] & 0x3F) || ip[7]) {
    return; // fragment with nonzero offset: no L4 header here
  }
  uint8_t proto = ip[9];
  uint8_t *l4 = ip + ihl;
  uint16_t l4len = (uint16_t)(tot - ihl);
  if (proto == 1 && l4len >= 8 && l4[2] == 0 && l4[3] == 0) { // ICMP
    uint16_t c = csum_finish(csum_add(0, l4, l4len));
    l4[2] = (uint8_t)(c >> 8);
    l4[3] = (uint8_t)c;
  } else if (proto == 6 && l4len >= 20) { // TCP
    if (clamp_tcp_mss(l4, l4len)) {
      l4[16] = 0; // force checksum regeneration below
      l4[17] = 0;
    }
    if (l4[16] == 0 && l4[17] == 0) {
      uint32_t s = csum_add(0, ip + 12, 8); // pseudo header: src+dst
      s += (uint32_t)proto + l4len;         // ... zero, proto, tcp length
      uint16_t c = csum_finish(csum_add(s, l4, l4len));
      l4[16] = (uint8_t)(c >> 8);
      l4[17] = (uint8_t)c;
    }
  }
  // UDP checksum 0 is legal over IPv4 (RFC 768) -- leave it alone.
}

// --- TinyUSB network callbacks -------------------------------------------------

void tud_network_init_cb(void) {
  if (received_frame) {
    cyw43_arch_lwip_begin();
    pbuf_free(received_frame);
    cyw43_arch_lwip_end();
    received_frame = NULL;
  }
}

bool tud_network_recv_cb(const uint8_t *src, uint16_t size) {
  if (received_frame) {
    return false; // previous frame not yet consumed; TinyUSB holds off
  }
  if (size) {
    cyw43_arch_lwip_begin(); // pbuf pool is shared with the background Wi-Fi context
    struct pbuf *p = pbuf_alloc(PBUF_RAW, size, PBUF_POOL);
    cyw43_arch_lwip_end();
    if (p) {
      memcpy(p->payload, src, size);
      received_frame = p; // fed to lwIP by usb_net_update()
    } else {
      recv_stalled = true; // pool exhausted: drop, but still re-arm RX below
      cnt_poolfail++;
    }
  }
  return true;
}

uint16_t tud_network_xmit_cb(uint8_t *dst, void *ref, uint16_t arg) {
  struct pbuf *p = (struct pbuf *)ref;
  (void)arg;
  uint16_t n = pbuf_copy_partial(p, dst, p->tot_len, 0);
  // Mirror of the wireguardif.c egress patch: lwIP's ip4_forward zeroes the
  // checksums of tunnel->host packets too, and the host's stack silently
  // drops zero-checksum datagrams. The frame is a contiguous copy here, so
  // regenerate any zeroed checksums before it goes over USB.
  fix_host_checksums(dst, n);
  pcap_capture(dst, n); // record exactly what the host receives
  return n;
}

// --- public api ------------------------------------------------------------------

static void derive_macs(void) {
  pico_unique_board_id_t id;
  pico_get_unique_board_id(&id);
  // Globally-administered bit (0x02) deliberately clear: Android's kernel
  // renames a locally-administered CDC interface to usb0 and leaves it out of
  // the default routing/connectivity path, while a globally-unique-looking MAC
  // comes up as eth0 and is picked up automatically. Body from the flash
  // unique ID, so the address is still per-device.
  tud_network_mac_address[0] = 0x00;
  tud_network_mac_address[1] = 0x1A;
  tud_network_mac_address[2] = 0x11;
  for (int i = 0; i < 3; i++) {
    tud_network_mac_address[3 + i] =
        id.id[i] ^ id.id[(i + 5) % PICO_UNIQUE_BOARD_ID_SIZE_BYTES];
  }
  tud_network_mac_address[5] &= 0xFE; // keep the ^0x01 device MAC distinct
}

static void netmask_from_prefix(ip4_addr_t *m, uint8_t prefix) {
  ip4_addr_set_u32(m, prefix ? lwip_htonl(0xFFFFFFFFu << (32 - prefix)) : 0);
}

bool usb_net_init(uint32_t addr_be, uint8_t prefix) {
  derive_macs();

  if (!tud_init(PICO_TUD_RHPORT)) {
    printf("usb_net: tud_init fail\n");
    return false;
  }

  ip4_addr_t ip, mask, gw;
  ip4_addr_set_u32(&ip, addr_be);
  netmask_from_prefix(&mask, addr_be ? prefix : 0);
  ip4_addr_set_any(&gw);

  cyw43_arch_lwip_begin();
  netif_add(&usb_netif, &ip, &mask, &gw, NULL, usb_netif_init_cb, ethernet_input);
  netif_set_up(&usb_netif);
  netif_set_link_up(&usb_netif);
#if LWIP_IPV6
  // fe80::... from the MAC (EUI-48 form). Stable for the life of the device.
  netif_create_ip6_linklocal_address(&usb_netif, 1);
#endif
  cyw43_arch_lwip_end();
  return true;
}

void usb_net_set_addr(uint32_t addr_be, uint8_t prefix) {
  ip4_addr_t ip, mask;
  ip4_addr_set_u32(&ip, addr_be);
  netmask_from_prefix(&mask, addr_be ? prefix : 0);
  cyw43_arch_lwip_begin();
  netif_set_addr(&usb_netif, &ip, &mask, IP4_ADDR_ANY4);
  cyw43_arch_lwip_end();
}

struct netif *usb_net_netif(void) { return &usb_netif; }

// Deferred logical replug (see usb_net.h). This TinyUSB has no runtime NCM
// link-state control, so the whole device detaches and re-attaches -- which
// is also the only signal that reliably makes every host re-run DHCP.
//
// The delay is generous, and each call re-arms it: the replug yanks the CDC
// consoles along with the network, and a provisioning burst (script or
// portal) keeps issuing commands for several seconds after the re-address
// that scheduled the bounce. Firing mid-burst cost a user a manual DHCP kick
// once -- so the bounce waits until the config traffic has been quiet.
#define BOUNCE_DELAY_MS 5000u
static uint32_t bounce_at_ms;    // 0 = idle
static uint32_t reconnect_at_ms; // 0 = idle

void usb_net_schedule_bounce(void) {
  bounce_at_ms = to_ms_since_boot(get_absolute_time()) + BOUNCE_DELAY_MS;
}

bool usb_net_bounce_pending(void) { return bounce_at_ms != 0; }

void usb_net_update(void) {
  uint32_t now = to_ms_since_boot(get_absolute_time());
  if (bounce_at_ms && now >= bounce_at_ms) {
    bounce_at_ms = 0;
    tud_disconnect();
    reconnect_at_ms = now + 300u;
  }
  if (reconnect_at_ms && now >= reconnect_at_ms) {
    reconnect_at_ms = 0;
    tud_connect();
  }

  tud_task();
  usb_tx_drain();

  bool renew = false;
  if (received_frame) {
    struct pbuf *p = received_frame;
    received_frame = NULL; // consume before input(): the callback may re-stage
    cnt_from_host++;
    // The staged frame is a single contiguous pbuf (tud_network_recv_cb
    // allocates it frame-sized); fill in any host-offloaded checksums before
    // lwIP sees it.
    if (p->next == NULL) {
      fix_host_checksums((uint8_t *)p->payload, p->len);
      pcap_capture((const uint8_t *)p->payload, p->len);
    }
    cyw43_arch_lwip_begin();
    if (usb_netif.input(p, &usb_netif) != ERR_OK) {
      pbuf_free(p);
    }
    cyw43_arch_lwip_end();
    renew = true;
  }
  if (recv_stalled) {
    recv_stalled = false;
    renew = true;
  }
  // Re-arm the NCM OUT endpoint after every consumed or dropped datagram, or
  // the host->device direction wedges (NETDEV WATCHDOG on the host).
  if (renew) tud_network_recv_renew();
}

void usb_net_get_stats(usb_net_stats_t *s) {
  s->from_host = cnt_from_host;
  s->to_host = cnt_to_host;
  s->txdrop = cnt_txdrop;
  s->poolfail = cnt_poolfail;
  s->ring_max = cnt_ring_max;
}

uint32_t usb_net_ring_recent_reset(void) {
  uint32_t save = save_and_disable_interrupts();
  uint32_t v = cnt_ring_recent;
  cnt_ring_recent = 0;
  restore_interrupts(save);
  return v;
}

bool usb_net_is_up(void) { return tud_ready(); }

void usb_net_deinit(void) { tud_deinit(PICO_TUD_RHPORT); }
