// Minimal single-lease DHCPv4 server, instanced per link. See dhcp_server.h.

#include <string.h>

#include <lwip/ip.h> // ip_current_input_netif() for scope dispatch
#include <lwip/ip_addr.h>
#include <lwip/netif.h>
#include <lwip/udp.h>

#include "dhcp_server.h"

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

#define BOOTREQUEST 1
#define BOOTREPLY 2

#define DHCPDISCOVER 1
#define DHCPOFFER 2
#define DHCPREQUEST 3
#define DHCPACK 5
#define DHCPNAK 6

#define OPT_PAD 0
#define OPT_SUBNET_MASK 1
#define OPT_ROUTER 3
#define OPT_DNS 6
#define OPT_MTU 26
#define OPT_REQUESTED_IP 50
#define OPT_LEASE_TIME 51
#define OPT_MSG_TYPE 53
#define OPT_SERVER_ID 54
#define OPT_CLASSLESS_ROUTES 121
#define OPT_END 255

#define LEASE_TIME_S 86400u

// Fixed-header part of a BOOTP/DHCP message, through the options magic cookie.
typedef struct __attribute__((packed)) {
  uint8_t op, htype, hlen, hops;
  uint32_t xid;
  uint16_t secs, flags;
  uint32_t ciaddr, yiaddr, siaddr, giaddr;
  uint8_t chaddr[16];
  uint8_t sname[64];
  uint8_t file[128];
  uint32_t magic;
} dhcp_msg_t;

#define DHCP_MAGIC 0x63825363u // network order after lwip_htonl
#define REPLY_OPTS_MAX 128     // fixed options + up to 4 option-121 routes

dhcp_server_t dhcp_usb;
dhcp_server_t dhcp_ap;

// One pcb for both scopes: two pcbs cannot both bind ANY:67, and binding each
// to its netif's address would go stale across re-addressing. Dispatch by the
// netif the request arrived on instead; an unknown arrival netif (the Wi-Fi
// station link) is dropped, which is the not-served-on-Wi-Fi guarantee.
static struct udp_pcb *pcb;

static dhcp_server_t *scope_for(struct netif *in) {
  if (in && in == dhcp_usb.nif) {
    return &dhcp_usb;
  }
  if (in && in == dhcp_ap.nif) {
    return &dhcp_ap;
  }
  return NULL;
}

// Find option `code` in the options block; returns pointer to its length byte
// or NULL. Bounds-checked.
static const uint8_t *find_opt(const uint8_t *opts, uint16_t len, uint8_t code) {
  uint16_t i = 0;
  while (i + 1 < len) {
    uint8_t c = opts[i];
    if (c == OPT_END) break;
    if (c == OPT_PAD) {
      i++;
      continue;
    }
    uint8_t olen = opts[i + 1];
    if (i + 2 + olen > len) break;
    if (c == code) return &opts[i + 1];
    i = (uint16_t)(i + 2 + olen);
  }
  return NULL;
}

static uint8_t *put_opt(uint8_t *p, uint8_t code, const void *val, uint8_t len) {
  *p++ = code;
  *p++ = len;
  memcpy(p, val, len);
  return p + len;
}

static void dhcp_recv(void *arg, struct udp_pcb *upcb, struct pbuf *p,
                      const ip_addr_t *addr, u16_t port) {
  (void)arg;
  (void)addr;
  (void)port;
  dhcp_server_t *s = scope_for(ip_current_input_netif());
  if (!s || s->lease_addr == 0 || p->tot_len < sizeof(dhcp_msg_t) + 3) {
    pbuf_free(p);
    return;
  }

  // Flatten the request (NCM frames arrive in single pbufs, but don't assume).
  static uint8_t req[600];
  uint16_t rlen = (uint16_t)LWIP_MIN(p->tot_len, sizeof(req));
  pbuf_copy_partial(p, req, rlen, 0);
  pbuf_free(p);

  const dhcp_msg_t *m = (const dhcp_msg_t *)req;
  if (m->op != BOOTREQUEST || m->htype != 1 || m->hlen != 6 ||
      m->magic != lwip_htonl(DHCP_MAGIC)) {
    return;
  }
  const uint8_t *opts = req + sizeof(dhcp_msg_t);
  uint16_t optlen = (uint16_t)(rlen - sizeof(dhcp_msg_t));
  const uint8_t *mt = find_opt(opts, optlen, OPT_MSG_TYPE);
  if (!mt || mt[0] != 1) {
    return;
  }
  uint8_t msg_type = mt[1];
  uint8_t reply_type;
  if (msg_type == DHCPDISCOVER) {
    reply_type = DHCPOFFER;
  } else if (msg_type == DHCPREQUEST) {
    // NAK a request for anything but our one lease so the client restarts
    // cleanly at DISCOVER (e.g. it remembered a lease from another network).
    const uint8_t *rip = find_opt(opts, optlen, OPT_REQUESTED_IP);
    uint32_t want = m->ciaddr;
    if (rip && rip[0] == 4) memcpy(&want, rip + 1, 4);
    reply_type = (want == 0 || want == s->lease_addr) ? DHCPACK : DHCPNAK;
  } else {
    return; // DECLINE/RELEASE/INFORM: single static lease, nothing to do
  }

  struct pbuf *rp = pbuf_alloc(PBUF_TRANSPORT, sizeof(dhcp_msg_t) + REPLY_OPTS_MAX, PBUF_RAM);
  if (!rp) {
    return;
  }
  dhcp_msg_t *r = (dhcp_msg_t *)rp->payload;
  memset(r, 0, sizeof(*r));
  r->op = BOOTREPLY;
  r->htype = 1;
  r->hlen = 6;
  r->xid = m->xid;
  r->flags = m->flags; // preserve the broadcast bit
  r->yiaddr = (reply_type == DHCPNAK) ? 0 : s->lease_addr;
  memcpy(r->chaddr, m->chaddr, 16);
  r->magic = lwip_htonl(DHCP_MAGIC);

  uint8_t *o = (uint8_t *)rp->payload + sizeof(dhcp_msg_t);
  o = put_opt(o, OPT_MSG_TYPE, &reply_type, 1);
  uint32_t sid = ip4_addr_get_u32(netif_ip4_addr(s->nif));
  o = put_opt(o, OPT_SERVER_ID, &sid, 4);
  if (reply_type != DHCPNAK) {
    uint32_t lease_be = lwip_htonl(LEASE_TIME_S);
    o = put_opt(o, OPT_LEASE_TIME, &lease_be, 4);
    o = put_opt(o, OPT_SUBNET_MASK, &s->lease_mask, 4);
    if (s->lease_link_only) {
      // Bring-up island: the host gets on-link reachability to the device (the
      // config portal) from the subnet mask alone -- no router, no static
      // routes, no DNS. Its own default route and resolver are untouched.
    } else if (s->lease_route_count == 0) {
      // Full-gateway mode: the device is the client's default router.
      o = put_opt(o, OPT_ROUTER, &sid, 4);
    } else {
      // Split mode: no default route. Push each subnet as a classless static
      // route via the device (RFC 3442: prefix length, the significant octets
      // of the destination, then the gateway). Clients that support option
      // 121 ignore option 3 by spec, but we omit it anyway.
      uint8_t buf[CONFIG_ROUTES_MAX * 9];
      uint8_t n = 0;
      for (uint8_t i = 0; i < s->lease_route_count; i++) {
        uint8_t plen = s->lease_routes[i].prefix;
        uint8_t octets = (uint8_t)((plen + 7) / 8);
        buf[n++] = plen;
        memcpy(buf + n, &s->lease_routes[i].net, octets);
        n = (uint8_t)(n + octets);
        memcpy(buf + n, &sid, 4);
        n = (uint8_t)(n + 4);
      }
      o = put_opt(o, OPT_CLASSLESS_ROUTES, buf, n);
    }
    if (s->lease_dns) {
      o = put_opt(o, OPT_DNS, &s->lease_dns, 4);
    }
    uint16_t mtu_be = lwip_htons(s->lease_mtu);
    o = put_opt(o, OPT_MTU, &mtu_be, 2);
  }
  *o++ = OPT_END;
  pbuf_realloc(rp, (u16_t)((uint8_t *)o - (uint8_t *)rp->payload));

  // Reply as broadcast on the scope's link: pre-lease the client has no
  // unicast address to receive on, and post-lease broadcast still reaches it.
  udp_sendto_if(upcb, rp, IP_ADDR_BROADCAST, DHCP_CLIENT_PORT, s->nif);
  pbuf_free(rp);

  if (reply_type == DHCPACK) {
    s->leased = true;
  }
}

void dhcp_server_start(dhcp_server_t *s, struct netif *nif, uint32_t host_addr,
                       uint8_t prefix, uint32_t dns, uint16_t mtu,
                       const wg_route_t *routes, uint8_t route_count, bool link_only) {
  s->nif = nif;
  s->lease_addr = host_addr;
  s->lease_mask = prefix ? lwip_htonl(0xFFFFFFFFu << (32 - prefix)) : 0;
  s->lease_link_only = link_only;
  s->lease_dns = link_only ? 0 : dns;
  s->lease_mtu = mtu;
  s->lease_route_count = (uint8_t)(route_count > CONFIG_ROUTES_MAX ? CONFIG_ROUTES_MAX : route_count);
  if (routes && s->lease_route_count) {
    memcpy(s->lease_routes, routes, s->lease_route_count * sizeof(wg_route_t));
  }
  s->leased = false;

  if (!pcb) {
    pcb = udp_new();
    if (!pcb) {
      return;
    }
#if IP_SOF_BROADCAST
    ip_set_option(pcb, SOF_BROADCAST);
#endif
    udp_bind(pcb, IP_ADDR_ANY, DHCP_SERVER_PORT);
    udp_recv(pcb, dhcp_recv, NULL);
  }
}

bool dhcp_server_leased(const dhcp_server_t *s) { return s->leased; }
