// Station-edge NAT for exit mode. See napt.h.

#include <string.h>

#include "napt.h"

// One mapping: NAT port = NAPT_PORT_BASE + table index, so inbound lookup is
// a direct index and no port allocator exists. proto 0 marks a free slot.
typedef struct {
  uint8_t inner_ip[4]; // network byte order, as on the wire
  uint8_t inner_port[2];
  uint32_t last_ms;
  uint8_t proto; // 6/17/1, or 0 = free
  uint8_t state; // TCP only: NAPT_ST_*
} napt_entry_t;

enum { NAPT_ST_NEW, NAPT_ST_ESTABLISHED, NAPT_ST_CLOSING };

static napt_entry_t table[NAPT_MAX];
static uint8_t g_ext[4]; // external address bytes; all-zero = disabled
static uint16_t g_mss;
static uint32_t g_drops;

void napt_set_ext_ip(uint32_t ip_be) { memcpy(g_ext, &ip_be, 4); }
void napt_set_mss_clamp(uint16_t mss) { g_mss = mss; }
void napt_reset(void) { memset(table, 0, sizeof(table)); }

// Per-entry idle timeout. TCP holds established flows for hours (RFC 5382),
// half-open and closing ones briefly; datagram flows expire on short idle.
static uint32_t timeout_ms(const napt_entry_t *e) {
  if (e->proto == 6) {
    if (e->state == NAPT_ST_ESTABLISHED) return 7200000u; // 2 h
    if (e->state == NAPT_ST_CLOSING) return 30000u;
    return 240000u; // half-open
  }
  return e->proto == 17 ? 120000u : 60000u; // UDP : ICMP
}

static bool entry_live(const napt_entry_t *e, uint32_t now) {
  return e->proto != 0 && (uint32_t)(now - e->last_ms) < timeout_ms(e);
}

// Incremental checksum update for changing the n bytes (n even) at oldp to
// the bytes at newp -- RFC 1624 eqn. 3, big-endian 16-bit words in place.
static void csum_adjust(uint8_t *csum, const uint8_t *oldp, const uint8_t *newp, int n) {
  uint32_t sum = (uint32_t)(~(((uint16_t)csum[0] << 8) | csum[1]) & 0xFFFFu);
  for (int i = 0; i < n; i += 2) {
    sum += (uint16_t)~(((uint16_t)oldp[i] << 8) | oldp[i + 1]) & 0xFFFFu;
    sum += (uint16_t)(((uint16_t)newp[i] << 8) | newp[i + 1]);
  }
  while (sum >> 16) {
    sum = (sum & 0xFFFFu) + (sum >> 16);
  }
  sum = ~sum & 0xFFFFu;
  csum[0] = (uint8_t)(sum >> 8);
  csum[1] = (uint8_t)sum;
}

// Adjust only a checksum that is present: zero means "an egress hop restores
// this over the final bytes" (see lwipopts.h) or, for UDP, "no checksum".
static void csum_adjust_nz(uint8_t *csum, const uint8_t *oldp, const uint8_t *newp, int n) {
  if (csum[0] | csum[1]) {
    csum_adjust(csum, oldp, newp, n);
  }
}

// UDP variant: an adjustment landing on 0x0000 would read as "no checksum",
// so RFC 768 wants the alternate all-ones form instead.
static void csum_adjust_udp(uint8_t *csum, const uint8_t *oldp, const uint8_t *newp, int n) {
  if (csum[0] | csum[1]) {
    csum_adjust(csum, oldp, newp, n);
    if (!(csum[0] | csum[1])) {
      csum[0] = csum[1] = 0xFF;
    }
  }
}

typedef struct {
  uint8_t *ip;
  uint8_t *l4;
  uint16_t l4avail;
  uint8_t ihl;
  uint8_t proto;
} pkt_view_t;

// Validate the flat span as a non-fragment IPv4 packet with its transport
// header present. Fragments are refused whole: past the first there is no
// port to translate, so translating only the head would corrupt the datagram.
static bool parse(uint8_t *pkt, uint16_t avail, pkt_view_t *v) {
  if (pkt == NULL || avail < 20 || (pkt[0] >> 4) != 4) {
    return false;
  }
  uint8_t ihl = (uint8_t)((pkt[0] & 0x0F) * 4);
  if (ihl < 20 || avail < ihl) {
    return false;
  }
  if ((pkt[6] & 0x3F) || pkt[7]) { // MF or a nonzero offset
    return false;
  }
  v->ip = pkt;
  v->ihl = ihl;
  v->proto = pkt[9];
  v->l4 = pkt + ihl;
  v->l4avail = (uint16_t)(avail - ihl);
  uint16_t need = v->proto == 6 ? 20 : 8; // TCP: through flags+csum; UDP/ICMP: 8
  return (v->proto == 6 || v->proto == 17 || v->proto == 1) && v->l4avail >= need;
}

// Clamp the MSS option on a SYN so exit flows fit the tunnel MTU end to end.
static void clamp_mss(uint8_t *l4, uint16_t l4avail, uint8_t *csum) {
  if (!g_mss || !(l4[13] & 0x02)) { // SYN only
    return;
  }
  uint8_t off = (uint8_t)((l4[12] >> 4) * 4);
  if (off <= 20 || off > l4avail) {
    return;
  }
  for (uint16_t i = 20; i + 1 < off;) {
    uint8_t kind = l4[i];
    if (kind == 0) {
      break;
    }
    if (kind == 1) {
      i++;
      continue;
    }
    uint8_t olen = l4[i + 1];
    if (olen < 2 || i + olen > off) {
      break;
    }
    if (kind == 2 && olen == 4) {
      uint16_t mss = (uint16_t)(((uint16_t)l4[i + 2] << 8) | l4[i + 3]);
      if (mss > g_mss) {
        uint8_t oldb[2] = {l4[i + 2], l4[i + 3]};
        l4[i + 2] = (uint8_t)(g_mss >> 8);
        l4[i + 3] = (uint8_t)g_mss;
        csum_adjust_nz(csum, oldb, l4 + i + 2, 2);
      }
      break;
    }
    i = (uint16_t)(i + olen);
  }
}

static void tcp_track(napt_entry_t *e, const uint8_t *l4) {
  uint8_t flags = l4[13];
  if (flags & 0x05) { // FIN or RST: either side is done
    e->state = NAPT_ST_CLOSING;
  } else if ((flags & 0x12) == 0x10 && e->state == NAPT_ST_NEW) { // ACK, no SYN
    e->state = NAPT_ST_ESTABLISHED;
  }
}

// The two-byte field the mapping is keyed on: ports, or the ICMP echo id.
static uint8_t *keyfield(const pkt_view_t *v, bool src_side) {
  if (v->proto == 1) {
    return v->l4 + 4;
  }
  return src_side ? v->l4 : v->l4 + 2;
}

bool napt_outbound(uint8_t *pkt, uint16_t avail, uint32_t now_ms) {
  pkt_view_t v;
  if (!(g_ext[0] | g_ext[1] | g_ext[2] | g_ext[3]) || !parse(pkt, avail, &v)) {
    g_drops++;
    return false;
  }
  if (v.proto == 1 && v.l4[0] != 8) { // ICMP: echo request only
    g_drops++;
    return false;
  }
  uint8_t *sport = keyfield(&v, true);

  // Existing mapping, or the first reusable slot.
  napt_entry_t *e = NULL;
  int freeslot = -1;
  for (int i = 0; i < NAPT_MAX; i++) {
    napt_entry_t *t = &table[i];
    if (entry_live(t, now_ms)) {
      if (t->proto == v.proto && memcmp(t->inner_ip, v.ip + 12, 4) == 0 &&
          memcmp(t->inner_port, sport, 2) == 0) {
        e = t;
        break;
      }
    } else if (freeslot < 0) {
      freeslot = i;
    }
  }
  if (e == NULL) {
    if (freeslot < 0) {
      g_drops++;
      return false; // table full: drop rather than leak an untranslated packet
    }
    e = &table[freeslot];
    memcpy(e->inner_ip, v.ip + 12, 4);
    memcpy(e->inner_port, sport, 2);
    e->proto = v.proto;
    e->state = NAPT_ST_NEW;
  }
  uint16_t nat = (uint16_t)(NAPT_PORT_BASE + (e - table));
  uint8_t natb[2] = {(uint8_t)(nat >> 8), (uint8_t)nat};

  // Source address: IP header checksum plus the TCP/UDP pseudo header.
  csum_adjust_nz(v.ip + 10, v.ip + 12, g_ext, 4);
  if (v.proto == 6) {
    csum_adjust_nz(v.l4 + 16, v.ip + 12, g_ext, 4);
  } else if (v.proto == 17) {
    csum_adjust_udp(v.l4 + 6, v.ip + 12, g_ext, 4);
  }
  memcpy(v.ip + 12, g_ext, 4);

  // Source port / echo id.
  if (v.proto == 6) {
    csum_adjust_nz(v.l4 + 16, sport, natb, 2);
    tcp_track(e, v.l4);
    clamp_mss(v.l4, v.l4avail, v.l4 + 16);
  } else if (v.proto == 17) {
    csum_adjust_udp(v.l4 + 6, sport, natb, 2);
  } else {
    csum_adjust_nz(v.l4 + 2, sport, natb, 2); // ICMP csum covers the id
  }
  memcpy(sport, natb, 2);

  e->last_ms = now_ms;
  return true;
}

bool napt_inbound(uint8_t *pkt, uint16_t avail, uint32_t now_ms) {
  pkt_view_t v;
  if (!parse(pkt, avail, &v) || memcmp(pkt + 16, g_ext, 4) != 0) {
    return false;
  }
  if (v.proto == 1 && v.l4[0] != 0) { // ICMP: echo reply only
    return false;
  }
  uint8_t *dport = keyfield(&v, false);
  uint16_t port = (uint16_t)(((uint16_t)dport[0] << 8) | dport[1]);
  if (port < NAPT_PORT_BASE || port >= NAPT_PORT_BASE + NAPT_MAX) {
    return false;
  }
  napt_entry_t *e = &table[port - NAPT_PORT_BASE];
  if (!entry_live(e, now_ms) || e->proto != v.proto) {
    return false;
  }

  // Destination address: IP header checksum plus the TCP/UDP pseudo header.
  csum_adjust_nz(v.ip + 10, v.ip + 16, e->inner_ip, 4);
  if (v.proto == 6) {
    csum_adjust_nz(v.l4 + 16, v.ip + 16, e->inner_ip, 4);
  } else if (v.proto == 17) {
    csum_adjust_udp(v.l4 + 6, v.ip + 16, e->inner_ip, 4);
  }
  memcpy(v.ip + 16, e->inner_ip, 4);

  // Destination port / echo id.
  if (v.proto == 6) {
    csum_adjust_nz(v.l4 + 16, dport, e->inner_port, 2);
    tcp_track(e, v.l4);
    clamp_mss(v.l4, v.l4avail, v.l4 + 16); // SYN-ACK carries an MSS too
  } else if (v.proto == 17) {
    csum_adjust_udp(v.l4 + 6, dport, e->inner_port, 2);
  } else {
    csum_adjust_nz(v.l4 + 2, dport, e->inner_port, 2);
  }
  memcpy(dport, e->inner_port, 2);

  e->last_ms = now_ms;
  return true;
}

void napt_stats(uint16_t *entries, uint32_t *drops) {
  uint16_t n = 0;
  for (int i = 0; i < NAPT_MAX; i++) {
    if (table[i].proto != 0) {
      n++;
    }
  }
  if (entries) {
    *entries = n;
  }
  if (drops) {
    *drops = g_drops;
  }
}
