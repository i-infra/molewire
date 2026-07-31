// Plaintext packet-capture ring. See pcap.h.
//
// Layout: records are written contiguously into ring[]; a record that would
// straddle the physical end wraps to offset 0 instead, and `high` remembers
// where the valid bytes at the top end. `tail` is the oldest surviving
// record; writing over it advances it record-by-record (records self-
// describe their length), preserving a parseable stream at all times.

#include <string.h>

#include <pico/stdlib.h>

#include "pcap.h"

#define RING_SIZE (64u * 1024u)
#define SNAPLEN 256u
#define REC_HDR 16u // pcap record header: ts_sec, ts_usec, incl_len, orig_len

static uint8_t ring[RING_SIZE];
static uint32_t head;    // next write offset
static uint32_t tail;    // oldest record offset
static uint32_t high;    // valid bytes end at `high` when wrapped
static bool wrapped;     // head has lapped at least once
static bool enabled;
static bool paused;      // a download is holding the ring still
static uint32_t n_packets;

static uint32_t rec_len_at(uint32_t off) {
  uint32_t incl;
  memcpy(&incl, ring + off + 8, 4);
  return REC_HDR + incl;
}

// Advance tail past any record whose storage intersects [from, from+need).
static void evict(uint32_t from, uint32_t need) {
  while (wrapped) {
    if (tail >= from + need || tail + rec_len_at(tail) <= from) {
      break; // oldest record is clear of the region
    }
    tail += rec_len_at(tail);
    if (tail >= high) {
      tail = 0;
      // Everything at the top is consumed; the valid region now ends at head.
      high = head;
      wrapped = false; // tail is now behind head in a linear stream
      break;
    }
  }
}

void pcap_capture(const uint8_t *frame, uint16_t len) {
  if (!enabled || paused || len == 0) {
    return;
  }
  uint32_t incl = (len > SNAPLEN) ? SNAPLEN : len;
  uint32_t need = REC_HDR + incl;

  if (head + need > RING_SIZE) { // record would straddle the end: wrap
    if (wrapped) {
      // Records between head and the top are the oldest; they die with the
      // truncated region.
      if (tail >= head) {
        tail = 0;
      }
    }
    high = head;
    head = 0;
    wrapped = true;
  }
  if (wrapped) {
    evict(head, need);
  }

  uint64_t us = to_us_since_boot(get_absolute_time());
  uint32_t hdr[4] = {(uint32_t)(us / 1000000u), (uint32_t)(us % 1000000u), incl, len};
  memcpy(ring + head, hdr, REC_HDR);
  memcpy(ring + head + REC_HDR, frame, incl);
  head += need;
  if (head > high && !wrapped) {
    high = head;
  }
  n_packets++;
}

void pcap_set_enabled(bool on) { enabled = on; }
bool pcap_enabled(void) { return enabled; }

void pcap_clear(void) {
  head = tail = high = 0;
  wrapped = false;
  n_packets = 0;
}

void pcap_stats(uint32_t *packets, uint32_t *bytes_used) {
  if (packets) *packets = n_packets;
  if (bytes_used) *bytes_used = wrapped ? (high - tail) + head : head - tail;
}

void pcap_freeze(const uint8_t **a, uint32_t *a_len, const uint8_t **b, uint32_t *b_len) {
  paused = true;
  if (wrapped) {
    *a = ring + tail;
    *a_len = high - tail;
    *b = ring;
    *b_len = head;
  } else {
    *a = ring + tail;
    *a_len = head - tail;
    *b = NULL;
    *b_len = 0;
  }
}

void pcap_resume(void) { paused = false; }

void pcap_global_header(uint8_t out[24]) {
  // magic (usec), version 2.4, thiszone 0, sigfigs 0, snaplen, LINKTYPE_ETHERNET
  const uint32_t hdr[6] = {0xA1B2C3D4u, 0x00040002u, 0, 0, SNAPLEN, 1u};
  memcpy(out, hdr, 24);
}
