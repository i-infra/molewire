// Plaintext packet capture on the client links, downloadable as a .pcap file.
//
// A RAM ring holds the most recent traffic crossing the USB netif (both
// directions, after checksum repair) and the quarantine AP netif, so it
// records exactly what the clients and the forwarding path see (the
// pre-encrypt / post-decrypt side of the tunnel). Frames are stored as native pcap records (LINKTYPE_ETHERNET,
// snaplen 256; original lengths preserved) so the download is a straight
// dump of the ring. Timestamps are seconds-since-boot -- Wireshark shows
// them relative to 1970, deltas are what matter.
//
// Capture is off by default (console/portal: `pcap on|off|clear`); the ring
// overwrites oldest records when full. All calls are main-loop only.

#ifndef PCAP_H
#define PCAP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

// Append one frame to the ring (no-op unless capturing and not paused).
void pcap_capture(const uint8_t *frame, uint16_t len);

void pcap_set_enabled(bool on);
bool pcap_enabled(void);
void pcap_clear(void);
void pcap_stats(uint32_t *packets, uint32_t *bytes_used);

// Download support: freeze the ring and get the record stream as up to two
// contiguous spans (oldest first; either may be empty). The spans point into
// the live ring, so capture stays paused until pcap_resume().
void pcap_freeze(const uint8_t **a, uint32_t *a_len, const uint8_t **b, uint32_t *b_len);
void pcap_resume(void);

// The 24-byte pcap global header to prepend to the record stream.
void pcap_global_header(uint8_t out[24]);
#define PCAP_GLOBAL_HDR_LEN 24u

#ifdef __cplusplus
}
#endif

#endif // PCAP_H
