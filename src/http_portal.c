// HTTP configuration/status portal. See http_portal.h.
//
// Raw-TCP (NO_SYS) server. All callbacks for USB-link connections run in the
// main loop under the lwIP lock (usb_net_update pumps input there), so calling
// into config_proto here is exactly equivalent to the serial console path.

#include <stdio.h>
#include <stdlib.h> // strtoul (Content-Length)
#include <string.h>
#include <strings.h> // strncasecmp

#include <lwip/ip.h> // ip_current_netif() for the accept-side netif check
#include <lwip/tcp.h>
#include <pico/cyw43_arch.h>

#include "config.h"
#include "config_proto.h"
#include "dhcp_server.h"
#include "http_portal.h"
#include "usb_net.h"
#include "web_page.h" // generated: web_index_gz[] / WEB_INDEX_GZ_LEN
#include "wg.h"

#ifndef FW_VERSION
#define FW_VERSION "0.0.0-dev"
#endif

#define HTTP_CONNS 2
#define REQ_MAX 1024
#define RESP_MAX 2304 // headers + JSON status or captured console output
#define IDLE_POLLS 10 // ~10 s at the 1 s poll interval before an idle abort

typedef struct {
  struct tcp_pcb *pcb;
  uint16_t req_len;
  uint8_t idle;
  bool responded;
  // Response = one dynamic segment (headers + any generated body, in resp[])
  // then an optional flash segment (the gzipped SPA). Sent with NOCOPY --
  // both stay stable until the connection is done.
  const uint8_t *seg[2];
  uint32_t seg_len[2];
  uint8_t seg_ix;
  uint16_t resp_len;
  char req[REQ_MAX];
  char resp[RESP_MAX];
} conn_t;

static conn_t conns[HTTP_CONNS];
static config_t *g_cfg;

// --- console-output capture (the cfg_io_t sink for /api/cmd) --------------------

typedef struct {
  char *buf;
  uint16_t len, cap;
} capture_t;

static void capture_write(void *ctx, const char *s) {
  capture_t *c = (capture_t *)ctx;
  uint16_t n = (uint16_t)strlen(s);
  if (n > (uint16_t)(c->cap - c->len)) {
    n = (uint16_t)(c->cap - c->len); // truncate; the SPA shows what fits
  }
  memcpy(c->buf + c->len, s, n);
  c->len = (uint16_t)(c->len + n);
}

// --- tiny JSON helpers ----------------------------------------------------------

// Append an escaped JSON string (quotes included). Bounded; truncates cleanly.
static int json_str(char *o, size_t cap, const char *s) {
  size_t w = 0;
  if (w < cap) o[w++] = '"';
  for (; *s && w + 8 < cap; s++) {
    unsigned char ch = (unsigned char)*s;
    if (ch == '"' || ch == '\\') {
      o[w++] = '\\';
      o[w++] = (char)ch;
    } else if (ch < 0x20) {
      w += (size_t)snprintf(o + w, cap - w, "\\u%04x", ch);
    } else {
      o[w++] = (char)ch;
    }
  }
  if (w < cap) o[w++] = '"';
  return (int)w;
}

// Bounded accumulate-append: snprintf returns the would-be length on
// truncation, so clamp n to the buffer to keep `cap - n` from underflowing.
#define JADD(o, n, cap, ...)                                                    \
  do {                                                                          \
    (n) += (uint16_t)snprintf((o) + (n), (size_t)((cap) - (n)), __VA_ARGS__);   \
    if ((n) >= (cap)) (n) = (uint16_t)((cap) - 1);                              \
  } while (0)

static void fmt_ip4_or_empty(char *o, size_t n, uint32_t addr_be) {
  if (!addr_be) {
    o[0] = '\0';
    return;
  }
  ip4_addr_t a;
  ip4_addr_set_u32(&a, addr_be);
  ip4addr_ntoa_r(&a, o, (int)n);
}

// Build the /api/status JSON body. Returns its length.
static uint16_t status_json(char *o, uint16_t cap) {
  const wg_config_t *w = &g_cfg->wg;
  char pub[48], ip[20], hostip[20], dns[20];
  bool have_pub = config_proto_pubkey(g_cfg, pub, sizeof(pub));
  struct netif *sta = &cyw43_state.netif[CYW43_ITF_STA];
  char sta_ip[20];
  ip4addr_ntoa_r(netif_ip4_addr(sta), sta_ip, sizeof(sta_ip));
  fmt_ip4_or_empty(ip, sizeof(ip), w->addr);
  fmt_ip4_or_empty(hostip, sizeof(hostip), w->host_addr);
  fmt_ip4_or_empty(dns, sizeof(dns), w->dns);
  usb_net_stats_t s;
  usb_net_get_stats(&s);

  uint16_t n = 0;
  JADD(o, n, cap, "{\"version\":\"" FW_VERSION "\",\"uptime_s\":%lu,",
       (unsigned long)(to_ms_since_boot(get_absolute_time()) / 1000u));
  JADD(o, n, cap, "\"provisioned\":%s,\"leased\":%s,",
       config_wg_complete(g_cfg) ? "true" : "false", dhcp_server_leased() ? "true" : "false");
  JADD(o, n, cap, "\"wifi\":{\"ssid\":");
  n += (uint16_t)json_str(o + n, cap - n, config_active_ssid(g_cfg)); // bounded by cap
  JADD(o, n, cap, ",\"link\":%s,\"ip\":\"%s\"},", netif_is_link_up(sta) ? "true" : "false",
       sta_ip);
  JADD(o, n, cap, "\"wg\":{\"state\":\"%s\",\"pubkey\":\"%s\",", wg_state_str(),
       have_pub ? pub : "");
  JADD(o, n, cap, "\"peer_set\":%s,\"psk_set\":%s,\"endpoint\":",
       w->peer_public[0] ? "true" : "false", w->psk[0] ? "true" : "false");
  n += (uint16_t)json_str(o + n, cap - n, w->endpoint); // bounded by cap
  JADD(o, n, cap,
       ",\"port\":%u,\"addr\":\"%s\",\"prefix\":%u,\"hostip\":\"%s\","
       "\"dns\":\"%s\",\"mtu\":%u,\"keepalive\":%u,\"routes\":[",
       w->endpoint_port, ip, w->prefix, hostip, dns, w->host_mtu, w->keepalive);
  for (uint8_t i = 0; i < w->route_count; i++) {
    char net[20];
    fmt_ip4_or_empty(net, sizeof(net), w->routes[i].net);
    JADD(o, n, cap, "%s\"%s/%u\"", i ? "," : "", net, w->routes[i].prefix);
  }
  JADD(o, n, cap, "]},");
  JADD(o, n, cap,
       "\"usb\":{\"from_host\":%lu,\"to_host\":%lu,\"txdrop\":%lu,\"poolfail\":%lu}}",
       (unsigned long)s.from_host, (unsigned long)s.to_host, (unsigned long)s.txdrop,
       (unsigned long)s.poolfail);
  return n;
}

// --- connection lifecycle -------------------------------------------------------

static void conn_free(conn_t *c) {
  if (c->pcb) {
    tcp_arg(c->pcb, NULL);
    tcp_recv(c->pcb, NULL);
    tcp_sent(c->pcb, NULL);
    tcp_err(c->pcb, NULL);
    tcp_poll(c->pcb, NULL, 0);
  }
  memset(c, 0, sizeof(*c));
}

// Push queued response segments as send-buffer space allows; close when done.
static void conn_send_more(conn_t *c) {
  while (c->seg_ix < 2) {
    if (c->seg_len[c->seg_ix] == 0) {
      c->seg_ix++;
      continue;
    }
    uint16_t room = tcp_sndbuf(c->pcb);
    if (room == 0) {
      return; // wait for tcp_sent
    }
    uint16_t chunk = (uint16_t)LWIP_MIN(c->seg_len[c->seg_ix], room);
    // Both segments are stable (static conn buffer / XIP flash): NOCOPY.
    if (tcp_write(c->pcb, c->seg[c->seg_ix], chunk, 0) != ERR_OK) {
      return; // retry from tcp_sent
    }
    c->seg[c->seg_ix] += chunk;
    c->seg_len[c->seg_ix] -= chunk;
  }
  tcp_output(c->pcb);
  // Everything queued: FIN after the queued data drains.
  struct tcp_pcb *pcb = c->pcb;
  conn_free(c);
  if (tcp_close(pcb) != ERR_OK) {
    tcp_abort(pcb);
  }
}

// Queue a full response. A body pointing at the flash page is sent in place
// (NOCOPY, stable); any other body is generated scratch and is copied into the
// connection's resp[] buffer behind the headers.
static void conn_respond(conn_t *c, const char *status, const char *ctype,
                         const char *extra_hdr, const uint8_t *body, uint32_t body_len) {
  int h = snprintf(c->resp, sizeof(c->resp),
                   "HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %lu\r\n"
                   "Cache-Control: no-store\r\n%sConnection: close\r\n\r\n",
                   status, ctype, (unsigned long)body_len, extra_hdr ? extra_hdr : "");
  c->resp_len = (uint16_t)h;
  c->seg[0] = (const uint8_t *)c->resp;
  c->seg_ix = 0;
  if (body && body_len && body != (const uint8_t *)web_index_gz) {
    // Generated body: append into resp[] (bounded by RESP_MAX).
    uint32_t room = (uint32_t)(sizeof(c->resp) - (uint16_t)h);
    if (body_len > room) body_len = room;
    memmove(c->resp + h, body, body_len);
    c->resp_len = (uint16_t)(h + body_len);
    c->seg_len[0] = c->resp_len;
    c->seg[1] = NULL;
    c->seg_len[1] = 0;
  } else {
    c->seg_len[0] = (uint32_t)h;
    c->seg[1] = body;
    c->seg_len[1] = body ? body_len : 0;
  }
  c->responded = true;
  conn_send_more(c);
}

// Scratch for generated bodies (single-threaded: main loop under lwIP lock).
static char body_buf[RESP_MAX - 256];

static void handle_request(conn_t *c) {
  c->req[c->req_len] = '\0';
  char *hdr_end = strstr(c->req, "\r\n\r\n");
  if (!hdr_end) {
    return; // incomplete; keep receiving
  }

  bool is_get = strncmp(c->req, "GET ", 4) == 0;
  bool is_post = strncmp(c->req, "POST ", 5) == 0;
  char *path = c->req + (is_get ? 4 : 5);
  char *path_end = strchr(path, ' ');
  if ((!is_get && !is_post) || !path_end) {
    conn_respond(c, "400 Bad Request", "text/plain", NULL, (const uint8_t *)"bad request", 11);
    return;
  }
  *path_end = '\0';

  if (is_get && (strcmp(path, "/") == 0 || strcmp(path, "/index.html") == 0)) {
    conn_respond(c, "200 OK", "text/html; charset=utf-8", "Content-Encoding: gzip\r\n",
                 web_index_gz, WEB_INDEX_GZ_LEN);
    return;
  }
  if (is_get && strcmp(path, "/api/status") == 0) {
    uint16_t n = status_json(body_buf, sizeof(body_buf));
    conn_respond(c, "200 OK", "application/json", NULL, (const uint8_t *)body_buf, n);
    return;
  }
  if (is_post && strcmp(path, "/api/cmd") == 0) {
    // Body: one console-protocol line. Find Content-Length (case-insensitive;
    // it lives beyond the NUL we put at path_end, so scan from there).
    uint32_t content_len = 0;
    for (char *l = path_end + 1; l < hdr_end; l++) {
      if ((*l == '\n') && strncasecmp(l + 1, "Content-Length:", 15) == 0) {
        content_len = (uint32_t)strtoul(l + 16, NULL, 10);
        break;
      }
    }
    char *body = hdr_end + 4;
    uint32_t have = (uint32_t)(c->req_len - (uint16_t)(body - c->req));
    if (content_len > 256) {
      conn_respond(c, "413 Payload Too Large", "text/plain", NULL,
                   (const uint8_t *)"too large", 9);
      return;
    }
    if (have < content_len) {
      *path_end = ' '; // un-split: we re-parse when the rest arrives
      return;
    }
    char line[257];
    memcpy(line, body, content_len);
    line[content_len] = '\0';
    char *nl = strpbrk(line, "\r\n");
    if (nl) *nl = '\0';

    capture_t cap = {.buf = body_buf, .len = 0, .cap = sizeof(body_buf) - 1};
    cfg_io_t io = {.write = capture_write, .ctx = &cap};
    config_proto_handle_line(&io, line, g_cfg);
    conn_respond(c, "200 OK", "text/plain; charset=utf-8", NULL, (const uint8_t *)body_buf,
                 cap.len);
    return;
  }
  conn_respond(c, "404 Not Found", "text/plain", NULL, (const uint8_t *)"not found", 9);
}

// --- lwIP callbacks -------------------------------------------------------------

static err_t http_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
  conn_t *c = (conn_t *)arg;
  if (!p) { // peer closed
    if (c) conn_free(c);
    tcp_close(pcb);
    return ERR_OK;
  }
  if (!c || err != ERR_OK) {
    pbuf_free(p);
    return ERR_OK;
  }
  uint16_t room = (uint16_t)(REQ_MAX - 1 - c->req_len);
  uint16_t n = (uint16_t)LWIP_MIN(p->tot_len, room);
  pbuf_copy_partial(p, c->req + c->req_len, n, 0);
  c->req_len = (uint16_t)(c->req_len + n);
  tcp_recved(pcb, p->tot_len);
  pbuf_free(p);
  c->idle = 0;
  if (!c->responded) {
    if (n == 0) { // request overflow with no end-of-headers in sight
      tcp_abort(pcb);
      conn_free(c);
      return ERR_ABRT;
    }
    handle_request(c);
  }
  return ERR_OK;
}

static err_t http_sent(void *arg, struct tcp_pcb *pcb, u16_t len) {
  (void)pcb;
  (void)len;
  conn_t *c = (conn_t *)arg;
  if (c && c->responded) {
    c->idle = 0;
    conn_send_more(c);
  }
  return ERR_OK;
}

static err_t http_poll(void *arg, struct tcp_pcb *pcb) {
  conn_t *c = (conn_t *)arg;
  if (!c) {
    tcp_abort(pcb);
    return ERR_ABRT;
  }
  if (++c->idle > IDLE_POLLS) {
    conn_free(c);
    tcp_abort(pcb);
    return ERR_ABRT;
  }
  if (c->responded) {
    conn_send_more(c); // nudge a stalled send along
  }
  return ERR_OK;
}

static void http_err(void *arg, err_t err) {
  (void)err;
  conn_t *c = (conn_t *)arg;
  if (c) {
    c->pcb = NULL; // already freed by lwIP
    conn_free(c);
  }
}

static err_t http_accept(void *arg, struct tcp_pcb *newpcb, err_t err) {
  (void)arg;
  if (err != ERR_OK || !newpcb) {
    return ERR_VAL;
  }
  // The portal is a USB-link service, full stop: a connection that arrived on
  // any other netif (e.g. from the tunnel side to our tunnel address) is
  // refused. Same trust boundary as the serial console.
  if (ip_current_netif() != usb_net_netif()) {
    tcp_abort(newpcb);
    return ERR_ABRT;
  }
  conn_t *c = NULL;
  for (int i = 0; i < HTTP_CONNS; i++) {
    if (!conns[i].pcb) {
      c = &conns[i];
      break;
    }
  }
  if (!c) {
    tcp_abort(newpcb);
    return ERR_ABRT;
  }
  memset(c, 0, sizeof(*c));
  c->pcb = newpcb;
  tcp_arg(newpcb, c);
  tcp_recv(newpcb, http_recv);
  tcp_sent(newpcb, http_sent);
  tcp_err(newpcb, http_err);
  tcp_poll(newpcb, http_poll, 2); // every ~1 s
  return ERR_OK;
}

void http_portal_init(config_t *cfg) {
  g_cfg = cfg;
  cyw43_arch_lwip_begin();
  struct tcp_pcb *l = tcp_new_ip_type(IPADDR_TYPE_ANY); // v4 + v6 on one pcb
  if (l && tcp_bind(l, IP_ANY_TYPE, 80) == ERR_OK) {
    l = tcp_listen_with_backlog(l, 2);
    tcp_accept(l, http_accept);
  } else if (l) {
    tcp_abort(l);
    printf("http_portal: bind failed\n");
  }
  cyw43_arch_lwip_end();
}
