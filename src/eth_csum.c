// Egress checksum restoration for radio-side links. See eth_csum.h.

#include <lwip/netif.h>
#include <lwip/pbuf.h>

#include "eth_csum.h"

static uint32_t csum_add(uint32_t sum, const uint8_t *d, uint16_t n) {
  while (n > 1) {
    sum += ((uint32_t)d[0] << 8) | d[1];
    d += 2;
    n = (uint16_t)(n - 2);
  }
  if (n) {
    sum += (uint32_t)d[0] << 8;
  }
  return sum;
}

static uint16_t csum_finish(uint32_t s) {
  while (s >> 16) {
    s = (s & 0xFFFF) + (s >> 16);
  }
  return (uint16_t)~s;
}

void eth_csum_restore(struct pbuf *p) {
  if (p == NULL || p->next != NULL) {
    // Chained pbuf: the parse below wants one flat buffer. Locally-originated
    // frames here (WG outer, DNS, DHCP, ICMP replies, TCP control) are built
    // in single pbufs; anything chained is passed through -- worst case a
    // zero UDP checksum, which is legal over IPv4.
    return;
  }
  uint8_t *f = (uint8_t *)p->payload;
  uint16_t flen = p->len;
  if (flen < 34 || f[12] != 0x08 || f[13] != 0x00) {
    return; // not IPv4
  }
  uint8_t *ip = f + 14;
  uint8_t ihl = (uint8_t)((ip[0] & 0x0F) * 4);
  uint16_t tot = (uint16_t)(((uint16_t)ip[2] << 8) | ip[3]);
  if ((ip[0] >> 4) != 4 || ihl < 20 || tot < ihl || (uint16_t)(14 + tot) > flen) {
    return;
  }
  if (ip[10] == 0 && ip[11] == 0) {
    uint16_t c = csum_finish(csum_add(0, ip, ihl));
    ip[10] = (uint8_t)(c >> 8);
    ip[11] = (uint8_t)c;
  }
  if ((ip[6] & 0x3F) || ip[7]) {
    return; // any fragment: the L4 checksum spans the whole datagram
  }
  uint8_t proto = ip[9];
  uint8_t *l4 = ip + ihl;
  uint16_t l4len = (uint16_t)(tot - ihl);
  if (proto == 1 && l4len >= 8 && l4[2] == 0 && l4[3] == 0) { // ICMP
    uint16_t c = csum_finish(csum_add(0, l4, l4len));
    l4[2] = (uint8_t)(c >> 8);
    l4[3] = (uint8_t)c;
  } else if (proto == 6 && l4len >= 20 && l4[16] == 0 && l4[17] == 0) { // TCP
    uint32_t s = csum_add(0, ip + 12, 8); // pseudo header: src + dst
    s += (uint32_t)proto + l4len;
    uint16_t c = csum_finish(csum_add(s, l4, l4len));
    l4[16] = (uint8_t)(c >> 8);
    l4[17] = (uint8_t)c;
  } else if (proto == 17 && l4len >= 8 && l4[6] == 0 && l4[7] == 0) { // UDP
    // Zero would be legal ("no checksum"), but the WireGuard outer rides
    // here -- give it a real checksum so middleboxes have nothing to hate.
    uint32_t s = csum_add(0, ip + 12, 8);
    s += (uint32_t)proto + l4len;
    uint16_t c = csum_finish(csum_add(s, l4, l4len));
    if (c == 0) {
      c = 0xFFFF; // RFC 768: transmitted 0 means "none"; use the alternate form
    }
    l4[6] = (uint8_t)(c >> 8);
    l4[7] = (uint8_t)c;
  }
}

static err_t (*orig_linkoutput)(struct netif *n, struct pbuf *p);

static err_t csum_linkoutput(struct netif *n, struct pbuf *p) {
  eth_csum_restore(p);
  return orig_linkoutput(n, p);
}

void eth_csum_wrap(struct netif *n) {
  if (n->linkoutput != csum_linkoutput) {
    orig_linkoutput = n->linkoutput;
    n->linkoutput = csum_linkoutput;
  }
}
