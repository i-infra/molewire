// Egress checksum restoration for radio-side links (Wi-Fi station and
// quarantine AP).
//
// With CHECKSUM_GEN_{TCP,UDP,ICMP} = 0 (see lwipopts.h -- disabled so lwIP's
// forward path stops zeroing transit packets' checksums), packets the device
// itself originates leave the stack with L4 checksum 0. The USB and tunnel
// egress hops already restore those; this module is the same restoration for
// frames leaving over the radio: the WireGuard outer UDP, DNS/DHCP-client
// traffic, and ICMP/TCP replies to on-link peers.
//
// Fragments are left alone by design: an L4 checksum spans the whole
// datagram, so it cannot be computed from one fragment -- and with the GEN
// flags off, fragmented transit traffic arrives here with its original valid
// checksums and needs nothing.

#ifndef ETH_CSUM_H
#define ETH_CSUM_H

struct netif;
struct pbuf;

// Restore any zero IPv4 header/L4 checksums in an outgoing ethernet frame,
// in place. Non-IPv4 frames, fragments (for L4), nonzero (already valid)
// checksums, and chained pbufs are passed through untouched.
void eth_csum_restore(struct pbuf *p);

// Idempotently wrap netif->linkoutput so every egress frame goes through
// eth_csum_restore. One netif only (the Wi-Fi station); the AP link calls
// eth_csum_restore from its own existing linkoutput wrapper (ap.c).
void eth_csum_wrap(struct netif *n);

#endif // ETH_CSUM_H
