#ifndef __LWIPOPTS_H__
#define __LWIPOPTS_H__

// lwIP configuration for the routed WireGuard dongle. Unlike pico-usb-wifi
// (which bypassed lwIP entirely), lwIP here IS the datapath: four netifs
// (USB, WireGuard, Wi-Fi station, and the optional quarantine AP) with IP
// forwarding between the client links and the tunnel, gated by the
// source-routing hook in lwip_hooks.h.

#ifndef NO_SYS
#define NO_SYS 1
#endif
#ifndef LWIP_SOCKET
#define LWIP_SOCKET 0
#endif
#if PICO_CYW43_ARCH_POLL
#define MEM_LIBC_MALLOC 1
#else
#define MEM_LIBC_MALLOC 0
#endif
#define MEM_ALIGNMENT 4

// Heap: wireguardif allocates its device struct and one contiguous PBUF_RAM
// per encrypted packet from here, and the portal's TCP segments join them;
// sized generously (RP2350 has 520 KB).
#define MEM_SIZE 24000
#define PBUF_POOL_SIZE 48 // cyw43 RX + USB staging + the 32-deep to-host ring

// TCP serves exactly one thing: the HTTP config/status portal on the USB link.
// Forwarded (host<->tunnel) TCP never terminates here. Buffers are sized for a
// small embedded page + JSON, not throughput.
#define LWIP_TCP 1
#define TCP_MSS 1460
#define TCP_WND (4 * TCP_MSS)
#define TCP_SND_BUF (4 * TCP_MSS)
#define MEMP_NUM_TCP_PCB 6
// Listeners: portal :80 + bridge :2323 raw + bridge :3323 rfc2217, headroom.
#define MEMP_NUM_TCP_PCB_LISTEN 4
#define MEMP_NUM_TCP_SEG 24
// Per-pcb keepalive tuning (the serial bridge reaps dead tunnel clients).
#define LWIP_TCP_KEEPALIVE 1

#define LWIP_IPV4 1
// IPv6 exists ONLY as link-local on the USB netif: an addressing plane for the
// config portal that survives every v4 re-addressing (unprovisioned -> tunnel
// /30) and is unreachable beyond the USB link by construction (link-local
// scope + IPV6_FORWARD 0). main.c strips the address the cyw43 glue would
// put on the Wi-Fi station netif, so the tunnel bypass surface stays v4-only.
#define LWIP_IPV6 1
#define LWIP_IPV6_MLD 1
#define LWIP_IPV6_DHCP6 0
#define LWIP_IPV6_FORWARD 0
#define MEMP_NUM_MLD6_GROUP 6 // allnodes + solicited-node + mdns, per v6 netif
// The endpoint must resolve to IPv4: the outer tunnel socket is v4-on-Wi-Fi.
#define LWIP_DNS_ADDRTYPE_DEFAULT LWIP_DNS_ADDRTYPE_IPV4
#define LWIP_ARP 1
#define LWIP_ETHERNET 1
#define LWIP_ICMP 1
#define LWIP_RAW 0
#define LWIP_UDP 1  // WireGuard outer, DHCP (both roles), DNS, mDNS
#define LWIP_DNS 1  // endpoint hostname resolution (via the upstream resolver)
#define LWIP_DHCP 1 // client on the Wi-Fi station netif
#define LWIP_IGMP 1 // mDNS joins 224.0.0.251 on the USB netif

// mDNS responder on the USB netif only: pico-wg.local resolves to the portal
// (A + AAAA) with zero host-side configuration -- .local queries are multicast
// on-link by the host resolver, never touching its DNS servers or routes.
#define LWIP_MDNS_RESPONDER 1
#define MDNS_MAX_SERVICES 1 // _http._tcp so the portal is discoverable
#define LWIP_NUM_NETIF_CLIENT_DATA 1
#define DHCP_DOES_ARP_CHECK 0
#define LWIP_DHCP_DOES_ACD_CHECK 0

// The whole point: forward between the USB netif and the WireGuard netif. The
// route hook makes any other forwarding path impossible.
//
// The hook must be defined HERE, not via LWIP_HOOK_FILENAME: ip4.h keys
// LWIP_IPV4_SRC_ROUTING off whether LWIP_HOOK_IP4_ROUTE_SRC is defined when it
// is preprocessed, and the hook file is included after ip4.h in ip4.c.
// wg_ip4_route_hook (wg.c) confines forwarded traffic -- the USB host's
// packets -- to the USB link and the tunnel; see wg.h.
#define IP_FORWARD 1
struct ip4_addr;
struct netif;
struct netif *wg_ip4_route_hook(const struct ip4_addr *src, const struct ip4_addr *dest);
#define LWIP_HOOK_IP4_ROUTE_SRC(src, dest) wg_ip4_route_hook((src), (dest))

// A tunnel MTU of 1420 with a 1500-byte USB link means occasional oversize
// forwards: fragment DF=0, ICMP frag-needed for DF=1 (the DHCP-advertised host
// MTU makes both rare).
#define IP_FRAG 1
#define IP_REASSEMBLY 1

// PCBs: WireGuard outer + DHCP server + DHCP client + DNS + mDNS, headroom.
#define MEMP_NUM_UDP_PCB 8
// Timers: cyw43 + DHCP + DNS + ARP + IP-reass + the wireguardif 400 ms timer,
// plus mDNS probe/announce timeouts and ND6/MLD6.
#define MEMP_NUM_SYS_TIMEOUT (LWIP_NUM_SYS_TIMEOUT_INTERNAL + 10)

#define MEMP_NUM_ARP_QUEUE 10
#define LWIP_NETIF_STATUS_CALLBACK 1
#define LWIP_NETIF_LINK_CALLBACK 1
#define LWIP_NETIF_HOSTNAME 1
#define LWIP_NETCONN 0
#define LWIP_STATS 0
#define MEM_STATS 0
#define SYS_STATS 0
#define MEMP_STATS 0
#define LINK_STATS 0
#define LWIP_CHKSUM_ALGORITHM 3
#define LWIP_NETIF_TX_SINGLE_PBUF 1 // cyw43 driver requirement

#ifndef NDEBUG
#define LWIP_DEBUG 1
#endif

#define ETHARP_DEBUG LWIP_DBG_OFF
#define NETIF_DEBUG LWIP_DBG_OFF
#define PBUF_DEBUG LWIP_DBG_OFF
#define API_LIB_DEBUG LWIP_DBG_OFF
#define API_MSG_DEBUG LWIP_DBG_OFF
#define SOCKETS_DEBUG LWIP_DBG_OFF
#define ICMP_DEBUG LWIP_DBG_OFF
#define INET_DEBUG LWIP_DBG_OFF
#define IP_DEBUG LWIP_DBG_OFF
#define IP_REASS_DEBUG LWIP_DBG_OFF
#define RAW_DEBUG LWIP_DBG_OFF
#define MEM_DEBUG LWIP_DBG_OFF
#define MEMP_DEBUG LWIP_DBG_OFF
#define SYS_DEBUG LWIP_DBG_OFF
#define TCP_DEBUG LWIP_DBG_OFF
#define UDP_DEBUG LWIP_DBG_OFF
#define TCPIP_DEBUG LWIP_DBG_OFF
#define PPP_DEBUG LWIP_DBG_OFF
#define SLIP_DEBUG LWIP_DBG_OFF
#define DHCP_DEBUG LWIP_DBG_OFF
#define DNS_DEBUG LWIP_DBG_OFF

#endif /* __LWIPOPTS_H__ */
