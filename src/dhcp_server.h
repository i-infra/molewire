// Minimal single-lease DHCPv4 server, instanced per link.
//
// Two scopes exist, one per client-facing link: the USB host and the AP
// client. Each scope serves exactly one client, which is offered the one
// configured address -- a tunnel address -- with the device as router, the
// tunnel-side resolver as DNS (option 6), and the WireGuard MTU as the
// interface MTU (option 26), which keeps the client's packets small enough to
// avoid black-holing inside the tunnel. One shared UDP pcb receives on port
// 67; requests are dispatched to the scope whose netif they arrived on, so
// nothing is ever served on the Wi-Fi station link.

#ifndef DHCP_SERVER_H
#define DHCP_SERVER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

#include "config.h" // wg_route_t

struct netif;

// One lease scope. Treat as opaque; use the functions below.
typedef struct {
  struct netif *nif;   // the link this scope serves
  uint32_t lease_addr; // client address, network order (0 = scope disabled)
  uint32_t lease_mask; // network order
  uint32_t lease_dns;  // network order (0 = omit option 6)
  uint16_t lease_mtu;
  wg_route_t lease_routes[CONFIG_ROUTES_MAX];
  uint8_t lease_route_count; // 0 = full-gateway mode
  bool lease_link_only;      // bring-up island: no router, no routes
  volatile bool leased;
} dhcp_server_t;

// The device's two scopes (defined in dhcp_server.c).
extern dhcp_server_t dhcp_usb; // the USB host's lease
extern dhcp_server_t dhcp_ap;  // the AP client's lease

// Start (or re-start) scope s on the given netif. host_addr/dns are IPv4 in
// network byte order; prefix is the link's subnet prefix length; mtu is the
// value for option 26 (the WireGuard MTU). host_addr 0 disables the scope.
//
// route_count 0: full-gateway mode -- the device is offered as default router
// (option 3). route_count > 0: split mode -- no router option; the given
// subnets are pushed as classless static routes via the device (option 121),
// so the client keeps its own default route and only tunnel subnets ride the
// link. dns 0 omits option 6 entirely.
//
// link_only true: bring-up island for the unprovisioned device -- the lease
// carries no router, no routes, and no DNS, giving the USB host on-link
// reachability to the config portal and influence over nothing else.
void dhcp_server_start(dhcp_server_t *s, struct netif *nif, uint32_t host_addr,
                       uint8_t prefix, uint32_t dns, uint16_t mtu,
                       const wg_route_t *routes, uint8_t route_count, bool link_only);

// True once the scope's client has ACKed its lease (for status display / LED).
bool dhcp_server_leased(const dhcp_server_t *s);

#ifdef __cplusplus
}
#endif

#endif // DHCP_SERVER_H
