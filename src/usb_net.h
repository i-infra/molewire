// USB CDC-NCM network interface, as a routed lwIP netif.
//
// Unlike pico-usb-wifi (which this project derives from), the USB side is not a
// layer-2 bridge: it is a real lwIP interface with its own MAC and IP address.
// The host sits on a tiny USB-link subnet whose addresses are tunnel addresses
// (covered by the WireGuard peer's AllowedIPs), the Pico is its gateway, and
// every host packet is routed -- through the WireGuard netif and nowhere else
// (see wg.c for the route hook that enforces this).

#ifndef USB_NET_H
#define USB_NET_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

struct netif;

// Bring up TinyUSB and add the USB lwIP netif with the given IPv4 address and
// prefix length (both from the WireGuard config; addr 0 = not yet provisioned,
// the netif comes up address-less and is re-addressed by usb_net_set_addr).
bool usb_net_init(uint32_t addr_be, uint8_t prefix);

// Re-address the USB netif (config change applied live).
void usb_net_set_addr(uint32_t addr_be, uint8_t prefix);

// The USB-side lwIP netif (valid after usb_net_init).
struct netif *usb_net_netif(void);

// Pump USB: service TinyUSB, drain queued netif output to the host, and feed
// any received frame into lwIP. Main loop only.
void usb_net_update(void);

bool usb_net_is_up(void);
void usb_net_deinit(void);

typedef struct {
  uint32_t from_host; // frames received from the host and fed to lwIP
  uint32_t to_host;   // frames transmitted to the host
  uint32_t txdrop;    // to-host frames dropped (USB down or ring full)
  uint32_t poolfail;  // from-host frames dropped (pbuf pool exhausted)
  uint32_t ring_max;  // all-time high-water mark of the to-host ring
} usb_net_stats_t;
void usb_net_get_stats(usb_net_stats_t *s);

// Peak to-host ring depth since the previous call, then reset (a live gauge for
// the debug console; ring_max latches at the ceiling).
uint32_t usb_net_ring_recent_reset(void);

#ifdef __cplusplus
}
#endif

#endif // USB_NET_H
