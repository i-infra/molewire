// Station-edge NAT for exit mode.
//
// Exit mode is the one place the device does NAT. Overlay clients' decrypted
// packets leave the Wi-Fi station interface masqueraded to the station's own
// address, because the local router has no route back to tunnel space; return
// traffic is matched by NAT port at input and rewritten back before it is
// forwarded into the tunnel. Everything else in the device stays NAT-free.
//
// The table maps (proto, inner ip:port) to a NAT port in a fixed private
// range (NAPT_PORT_BASE..+NAPT_MAX-1, chosen not to collide with the
// WireGuard listen port). Mappings are endpoint-independent: one inner
// ip:port keeps one NAT port for all destinations. TCP, UDP, and ICMP echo
// are translated; other protocols and IP fragments are not (an untranslatable
// outbound packet is dropped, an unmatched inbound one is left alone).
//
// Checksums are adjusted incrementally (RFC 1624) and only when nonzero: with
// CHECKSUM_GEN_* off, a zero checksum here means a later egress hop restores
// it over the final bytes (see lwipopts.h), so touching it would be wrong.
//
// Pure C over a flat byte buffer, no lwIP types: the core is exercised by the
// host-side tests. Callers pass the first-pbuf span; all rewrites live in the
// IP and transport headers, which always fit there.

#ifndef NAPT_H
#define NAPT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

#define NAPT_MAX 512        // concurrent mappings (16 bytes of state each)
#define NAPT_PORT_BASE 60000u // NAT ports 60000..60511; clear of WG's 51820

// The external (station) address, network byte order. 0 disables translation.
void napt_set_ext_ip(uint32_t ip_be);

// Clamp the TCP MSS option on translated SYNs to this value (0 = off).
// Set to tunnel MTU - 40 so exit flows fit the tunnel without fragmentation.
void napt_set_mss_clamp(uint16_t mss);

// Drop all mappings (config change / tunnel restart).
void napt_reset(void);

// Translate an outbound packet in place: src ip:port becomes ext_ip:nat_port.
// pkt points at the IPv4 header; avail is how many bytes of it are present
// (the first pbuf's length). Returns false when the packet cannot be
// translated (no free slot, unsupported protocol, a fragment, or truncated
// headers) -- the caller must drop it, never send it untranslated.
bool napt_outbound(uint8_t *pkt, uint16_t avail, uint32_t now_ms);

// Match an inbound packet against the table and, on a hit, rewrite dst
// ip:port back to the inner host in place. Returns true on a hit (the caller
// lets the stack forward it); false leaves the packet untouched for normal
// local delivery.
bool napt_inbound(uint8_t *pkt, uint16_t avail, uint32_t now_ms);

// Live mapping count and cumulative outbound drops, for status displays.
void napt_stats(uint16_t *entries, uint32_t *drops);

#ifdef __cplusplus
}
#endif

#endif // NAPT_H
