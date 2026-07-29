// Minimal single-lease DHCPv4 server for the USB link.
//
// Exactly one client (the USB host) is ever served: it is offered the one
// configured address -- the host's tunnel address -- with the Pico as router,
// the tunnel-side resolver as DNS (option 6), and the WireGuard MTU as the
// interface MTU (option 26), which keeps the host's packets small enough to
// avoid black-holing inside the tunnel. Bound to the USB netif only.

#ifndef DHCP_SERVER_H
#define DHCP_SERVER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

#include "config.h" // wg_route_t

struct netif;

// Start (or re-start) the server on the given netif. host_addr/dns are IPv4 in
// network byte order; prefix is the USB-link subnet prefix length; mtu is the
// value for option 26 (the WireGuard MTU). host_addr 0 stops the server.
//
// route_count 0: full-gateway mode -- the Pico is offered as default router
// (option 3). route_count > 0: split mode -- no router option; the given
// subnets are pushed as classless static routes via the Pico (option 121), so
// the host keeps its own default route and only tunnel subnets ride the USB
// link. dns 0 omits option 6 entirely.
//
// link_only true: bring-up island for the unprovisioned device -- the lease
// carries no router, no routes, and no DNS, giving the host on-link
// reachability to the config portal and influence over nothing else.
void dhcp_server_start(struct netif *nif, uint32_t host_addr, uint8_t prefix,
                       uint32_t dns, uint16_t mtu, const wg_route_t *routes,
                       uint8_t route_count, bool link_only);

// True once the host has ACKed its lease (for status display / LED).
bool dhcp_server_leased(void);

#ifdef __cplusplus
}
#endif

#endif // DHCP_SERVER_H
