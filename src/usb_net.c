// USB CDC-NCM network interface as a routed lwIP netif. See usb_net.h.
//
// Derived from pico-usb-wifi's usb_network.c (MIT, Peter Lawrence / Matthew
// Bennett, influenced by lrndis); reworked from a transparent L2 bridge into a
// proper lwIP interface so packets can be routed through the WireGuard netif.

#include <string.h>

#include <hardware/sync.h>
#include <lwip/etharp.h>
#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <netif/ethernet.h>
#include <pico/cyw43_arch.h>
#include <pico/stdlib.h>
#include <pico/unique_id.h>
#include <tusb.h>

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
  n->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET;
  n->output = etharp_output;
  n->linkoutput = usb_linkoutput;
  return ERR_OK;
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
  return pbuf_copy_partial(p, dst, p->tot_len, 0);
}

// --- public api ------------------------------------------------------------------

static void derive_macs(void) {
  pico_unique_board_id_t id;
  pico_get_unique_board_id(&id);
  // Locally administered, unicast; body from the flash unique ID.
  tud_network_mac_address[0] = 0x02;
  for (int i = 0; i < 5; i++) {
    tud_network_mac_address[1 + i] =
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

void usb_net_update(void) {
  tud_task();
  usb_tx_drain();

  bool renew = false;
  if (received_frame) {
    struct pbuf *p = received_frame;
    received_frame = NULL; // consume before input(): the callback may re-stage
    cnt_from_host++;
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
