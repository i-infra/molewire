// Quarantine access point: the CYW43 runs an AP alongside the station uplink,
// and ONE wireless client is routed through the WireGuard tunnel exactly like
// the USB host -- and nowhere else. The point is isolation, not throughput:
// an SSID for bringing up untrusted devices that structurally cannot reach
// the LAN (the route only exists toward the tunnel; there is no filter to
// misconfigure), with the pcap ring capturing what they do.
//
// Single-client by construction, three layers deep: the radio firmware caps
// associations at one (maxassoc), the DHCP scope holds one lease, and the AP
// block is a tiny subnet -- so no NAT exists anywhere in the device. The AP
// pair must be covered by the server peer's AllowedIPs, same rule as the USB
// pair.
//
// CYW43439 constraint: AP and station share one radio, so the AP always
// beacons on the station's channel and every forwarded packet pays airtime
// (and the gSPI bus) twice. Expect roughly half the station-only throughput.

#ifndef AP_H
#define AP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

#include "config.h"

struct netif;

// Bring the AP up/down to match the config (live apply; safe to call
// repeatedly -- a call that changes nothing does nothing, so unrelated config
// applies do not bounce the wireless client). Enabling requires
// cfg->ap.enabled AND config_ap_complete().
void ap_apply(const config_t *cfg);

// The AP lwIP netif while the AP is up, else NULL (for route-hook and
// which-netif-did-this-arrive-on checks).
struct netif *ap_active_netif(void);

// Associated stations right now (0 or 1; radio-level, before DHCP). Costs a
// couple of SPI ioctls -- status paths only.
int ap_client_count(void);

#ifdef __cplusplus
}
#endif

#endif // AP_H
