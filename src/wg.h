// WireGuard tunnel management: netif lifecycle, peer/session state machine,
// the RP2350 platform layer (TRNG randomness, flash-backed TAI64N counter),
// and the source-routing hook that enforces host isolation.
//
// Routing model: the USB host's packets (and WireGuard-decrypted packets
// heading back to it) are FORWARDED traffic, and the route hook confines them
// to the USB netif and the WireGuard netif -- they can never exit via Wi-Fi.
// Before the tunnel interface exists they fall into a blackhole netif (fail
// closed). The Pico's own traffic (DHCP client, DNS lookup of the endpoint,
// and the tunnel's outer UDP, which is pinned to the station netif) routes
// normally.

#ifndef WG_H
#define WG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

#include "config.h"

struct netif;
struct ip4_addr;

// Read and bump the boot counter that makes TAI64N handshake timestamps
// monotonic across reboots without NTP. Call once, early in main().
void wg_time_init(void);

// Tear down any existing tunnel and, if the config is complete, bring up the
// WireGuard netif and start connecting. Safe to call repeatedly (live apply).
// sta is the Wi-Fi station netif the outer UDP is bound to.
void wg_apply(const config_t *cfg, struct netif *sta);

// Drive the state machine: endpoint DNS resolution, handshake kick, session
// monitoring, default-route management. Call about once a second.
void wg_poll(void);

// True while the peer has a valid session (handshake complete, not expired).
bool wg_session_up(void);

// One-word tunnel state for status displays: "unconfigured", "resolving",
// "handshaking", "up".
const char *wg_state_str(void);

// Generate a fresh X25519 keypair from the hardware TRNG (clamped private
// key). The private key is meant to be stored in the config and never shown;
// only the public key is for display. Returns false on the (astronomically
// unlikely) degenerate key.
bool wg_keypair_generate(uint8_t pub[32], uint8_t priv[32]);

// Derive the public key of an existing private key (for status displays).
bool wg_public_from_private(uint8_t pub[32], const uint8_t priv[32]);

// The WireGuard netif while the tunnel interface exists, else NULL (e.g. for
// which-netif-did-this-arrive-on checks).
struct netif *wg_active_netif(void);

// lwIP LWIP_HOOK_IP4_ROUTE_SRC hook (referenced from lwip_hooks.h).
struct netif *wg_ip4_route_hook(const struct ip4_addr *src, const struct ip4_addr *dest);

#ifdef __cplusplus
}
#endif

#endif // WG_H
