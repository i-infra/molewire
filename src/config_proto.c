// Runtime configuration control protocol, transport-agnostic. See config_proto.h.

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h> // strtol
#include <string.h>
#include <strings.h>

#include <hardware/watchdog.h> // watchdog_reboot for the REBOOT command
#include <lwip/ip4_addr.h>
#include <lwip/netif.h>
#include <pico/bootrom.h>    // reset_usb_boot for the BOOTSEL command
#include <pico/cyw43_arch.h> // CYW43_COUNTRY(...) / cyw43_state
#include <tusb.h>            // tud_task to drain the goodbye message

#include "ap.h" // AP client status for the dump
#include "config.h"
#include "config_proto.h"
#include "dhcp_server.h"
#include "pcap.h"          // capture toggle + status for the dump
#include "serial_bridge.h" // bridge status for the dump
#include "wg.h"
#include "wifi_conn.h" // per-profile status/RSSI annotations, creds-unsaved flag
#include "wifi_scan.h"
#include "wireguard.h" // base64 validation of keys

#ifndef FW_VERSION
#define FW_VERSION "0.0.0-dev" // overridden at build time from the git tag
#endif

static inline void out(const cfg_io_t *io, const char *s) { io->write(io->ctx, s); }

static config_apply_fn g_apply;    // re-applies Wi-Fi config live (registered by main)
static config_apply_fn g_apply_wg; // re-applies WireGuard/addressing config live
static config_apply_fn g_apply_ap; // re-applies the quarantine AP config live

void config_proto_set_apply(config_apply_fn cb) { g_apply = cb; }
void config_proto_set_apply_wg(config_apply_fn cb) { g_apply_wg = cb; }
void config_proto_set_apply_ap(config_apply_fn cb) { g_apply_ap = cb; }

// Which menu the console is in. MODE_SCAN is entered by the SCAN command and
// left by BACK or a successful JOIN. MODE_CONTSCAN is the live (continuous) scan,
// entered by LIVE and left by any keypress.
static enum { MODE_MAIN, MODE_SCAN, MODE_CONTSCAN } g_mode;

// A single `scan` unions several passive passes -- one pass catches only a subset
// of the beacons present -- accumulating into the results before the list shows.
#define SCAN_PASSES 4
static uint8_t scan_rounds; // passes remaining in a single-scan session, 0 = idle

void config_proto_reset(void) {
  // Only stop a scan this console started: a manager (wifi_conn) scan may be
  // in flight, and clearing its latch here would eat its completion.
  if (scan_rounds > 0 || g_mode == MODE_CONTSCAN) {
    wifi_scan_stop(); // drop the scan latch so association can resume
  }
  g_mode = MODE_MAIN;
  scan_rounds = 0;
}

// --- helpers ------------------------------------------------------------------

static uint32_t parse_country(const char *v) {
  if (strcasecmp(v, "WORLDWIDE") == 0) {
    return CYW43_COUNTRY_WORLDWIDE;
  }
  if (strlen(v) >= 2) {
    return CYW43_COUNTRY(toupper((unsigned char)v[0]), toupper((unsigned char)v[1]), 0);
  }
  return CYW43_COUNTRY_WORLDWIDE;
}

// Format the regulatory country, guarding against the unset/zero case whose
// bytes would be NUL (which truncates the output string).
static void fmt_country(char *o, size_t n, uint32_t country) {
  char a = (char)(country & 0xff), b = (char)((country >> 8) & 0xff);
  if (a >= 0x20 && a < 0x7f && b >= 0x20 && b < 0x7f) {
    snprintf(o, n, "%c%c", a, b);
  } else {
    snprintf(o, n, "(unset)");
  }
}

// Copy an SSID for display, replacing non-printable bytes with '?', so a name
// with control bytes or an exotic encoding cannot corrupt the terminal. The
// numbered lists exist precisely so such networks are still selectable.
static void fmt_ssid(char *o, size_t n, const char *ssid) {
  size_t i = 0;
  for (; ssid[i] && i + 1 < n; i++) {
    unsigned char c = (unsigned char)ssid[i];
    o[i] = (c >= 0x20 && c < 0x7f) ? (char)c : '?';
  }
  o[i] = '\0';
}

// Parse a 1-based list index argument into a 0-based index in [0,count), or -1.
static int parse_index(const char *s, int count) {
  char *end;
  long v = strtol(s, &end, 10);
  if (end == s || *end != '\0' || v < 1 || v > count) {
    return -1;
  }
  return (int)v - 1;
}

// A WireGuard key: base64 that decodes to exactly 32 bytes.
static bool valid_wg_key(const char *s) {
  uint8_t buf[64];
  size_t len = sizeof(buf);
  return wireguard_base64_decode(s, buf, &len) && len == 32;
}

// Derive the public key of the stored private key, base64-encoded into out
// (needs >= 45 bytes). False if no key is set or it does not decode.
bool config_proto_pubkey(const config_t *cfg, char *pub_b64, size_t n) {
  uint8_t priv[64], pub[32];
  size_t len = sizeof(priv);
  bool ok = cfg->wg.private_key[0] &&
            wireguard_base64_decode(cfg->wg.private_key, priv, &len) && len == 32 &&
            wg_public_from_private(pub, priv);
  memset(priv, 0, sizeof(priv)); // don't leave the private key on the stack
  if (!ok) {
    return false;
  }
  size_t olen = n;
  return wireguard_base64_encode(pub, sizeof(pub), pub_b64, &olen);
}

// Parse "a.b.c.d" into a network-order u32; 0 on failure (0.0.0.0 is not a
// meaningful value for any of these settings, so it doubles as the error).
static uint32_t parse_ip4(const char *s) {
  ip4_addr_t a;
  if (!ip4addr_aton(s, &a)) {
    return 0;
  }
  return ip4_addr_get_u32(&a);
}

static void fmt_ip4(char *o, size_t n, uint32_t addr_be) {
  ip4_addr_t a;
  ip4_addr_set_u32(&a, addr_be);
  ip4addr_ntoa_r(&a, o, (int)n);
}

// --- state dump (printed after every main-menu command) -----------------------

void config_proto_dump(const cfg_io_t *io, const config_t *cfg) {
  bool assoc = netif_is_link_up(&cyw43_state.netif[CYW43_ITF_STA]);
  char line[80], cc[8], ssid[CONFIG_SSID_MAX];

  out(io, "\n-- molewire " FW_VERSION " --\n");
  if (cfg->active < cfg->profile_count) {
    snprintf(line, sizeof(line), "    profiles:   %u saved (active: %u)\n",
             cfg->profile_count, (unsigned)(cfg->active + 1));
  } else {
    snprintf(line, sizeof(line), "    profiles:   %u saved (active: none)\n", cfg->profile_count);
  }
  out(io, line);

  const char *as = config_active_ssid(cfg);
  fmt_ssid(ssid, sizeof(ssid), as);
  snprintf(line, sizeof(line), "    ssid:       %s\n", as[0] ? ssid : "(unset)");
  out(io, line);
  out(io, config_active_pass(cfg)[0] ? "    pass:       set\n" : "    pass:       unset\n");
  fmt_country(cc, sizeof(cc), cfg->country);
  snprintf(line, sizeof(line), "    country:    %s\n", cc);
  out(io, line);
  out(io, cfg->debug_enabled ? "    debug:      on\n" : "    debug:      off\n");
  snprintf(line, sizeof(line), "    wifi:       %s\n",
           assoc ? "associated" : wifi_conn_state_str());
  out(io, line);

  const wg_config_t *w = &cfg->wg;
  char a[16], b[16], pub[48];
  if (config_proto_pubkey(cfg, pub, sizeof(pub))) {
    snprintf(line, sizeof(line), "    wg pubkey:  %s\n", pub);
    out(io, line);
  } else {
    out(io, w->private_key[0] ? "    wg key:     set (pubkey underivable?)\n"
                              : "    wg key:     unset -- genkey, or set key <b64>\n");
  }
  out(io, w->peer_public[0] ? "    wg peer:    set\n" : "    wg peer:    unset\n");
  out(io, w->psk[0] ? "    wg psk:     set\n" : "    wg psk:     off\n");
  if (w->endpoint[0]) {
    snprintf(line, sizeof(line), "    endpoint:   %s:%u\n", w->endpoint, w->endpoint_port);
  } else {
    snprintf(line, sizeof(line), "    endpoint:   (unset)\n");
  }
  out(io, line);
  if (w->addr && w->host_addr) {
    fmt_ip4(a, sizeof(a), w->addr);
    fmt_ip4(b, sizeof(b), w->host_addr);
    snprintf(line, sizeof(line), "    tunnel:     %s/%u (this device), %s (host)\n", a,
             w->prefix, b);
  } else {
    snprintf(line, sizeof(line), "    tunnel:     (unset -- set addr and hostip)\n");
  }
  out(io, line);
  if (w->dns) {
    fmt_ip4(a, sizeof(a), w->dns);
    snprintf(line, sizeof(line), "    dns:        %s\n", a);
    out(io, line);
  } else {
    out(io, "    dns:        (unset -- host gets no resolver)\n");
  }
  if (w->keepalive) {
    snprintf(line, sizeof(line), "    keepalive:  %us\n", w->keepalive);
    out(io, line);
  }
  if (w->host_mtu) {
    snprintf(line, sizeof(line), "    host mtu:   %u\n", w->host_mtu);
    out(io, line);
  }
  if (w->route_count) {
    out(io, "    mode:       split -- host keeps its own default route; routed here:\n");
    for (uint8_t i = 0; i < w->route_count; i++) {
      fmt_ip4(a, sizeof(a), w->routes[i].net);
      snprintf(line, sizeof(line), "                  %s/%u\n", a, w->routes[i].prefix);
      out(io, line);
    }
  } else {
    out(io, "    mode:       gateway -- host default-routes through the tunnel\n");
  }
  const ap_config_t *ap = &cfg->ap;
  if (ap->ssid[0] || ap->enabled) {
    char ssid_disp[CONFIG_SSID_MAX];
    fmt_ssid(ssid_disp, sizeof(ssid_disp), ap->ssid);
    fmt_ip4(a, sizeof(a), ap->addr);
    fmt_ip4(b, sizeof(b), ap->client_addr);
    snprintf(line, sizeof(line), "    ap:         %s \"%s\" %s/%u -> %s\n",
             ap->enabled ? "on" : "off", ssid_disp, ap->addr ? a : "?", ap->prefix,
             ap->client_addr ? b : "?");
    out(io, line);
    if (ap->enabled) {
      int stas = ap_client_count();
      snprintf(line, sizeof(line), "    ap client:  %s%s\n",
               stas ? "associated" : "none",
               dhcp_server_leased(&dhcp_ap) ? ", leased" : "");
      out(io, line);
    }
  }
  snprintf(line, sizeof(line), "    bridge:     uart1@%lu tcp :2323 raw :3323 rfc2217 (%s)\n",
           (unsigned long)serial_bridge_baud(),
           serial_bridge_client_connected() ? "client" : "no client");
  out(io, line);
  if (pcap_enabled()) {
    uint32_t pkts, bytes;
    pcap_stats(&pkts, &bytes);
    snprintf(line, sizeof(line), "    pcap:       capturing (%lu pkts, %lu KB in ring)\n",
             (unsigned long)pkts, (unsigned long)(bytes / 1024u));
    out(io, line);
  }
  snprintf(line, sizeof(line), "    tunnel state: %s; host lease: %s\n", wg_state_str(),
           dhcp_server_leased(&dhcp_usb) ? "yes" : "no");
  out(io, line);
  if (!config_wg_complete(cfg)) {
    out(io, "    (wireguard not fully configured -- host traffic is blocked)\n");
  }
}

// --- list views ---------------------------------------------------------------

// One profile's runtime annotation: connection/attempt state, or how the
// latest scan saw it. Empty until anything is known.
static void prof_note(char *o, size_t n, uint8_t i) {
  wifi_prof_status_t st = wifi_conn_prof_status(i);
  int16_t rssi = wifi_conn_prof_rssi(i);
  if (st == WIFI_PROF_CONNECTED) {
    snprintf(o, n, rssi != WIFI_RSSI_UNSEEN ? "connected, %d dBm" : "connected", rssi);
  } else if (st == WIFI_PROF_BADPASS) {
    snprintf(o, n, "bad password?");
  } else if (rssi != WIFI_RSSI_UNSEEN) {
    snprintf(o, n, st == WIFI_PROF_NOJOIN ? "%d dBm, couldn't join" : "%d dBm", rssi);
  } else if (wifi_conn_scan_age_ms() != UINT32_MAX) {
    snprintf(o, n, st == WIFI_PROF_NOJOIN ? "not seen, couldn't join" : "not seen");
  } else {
    o[0] = '\0';
  }
}

static void list_profiles(const cfg_io_t *io, const config_t *cfg) {
  char line[112], ssid[CONFIG_SSID_MAX], note[32];
  if (cfg->profile_count == 0) {
    out(io, "    (no saved profiles -- scan, or set ssid/pass to add one)\n");
    return;
  }
  snprintf(line, sizeof(line), "    profiles (%u/%u, most recent first):\n",
           cfg->profile_count, CONFIG_PROFILE_MAX);
  out(io, line);
  for (uint8_t i = 0; i < cfg->profile_count; i++) {
    fmt_ssid(ssid, sizeof(ssid), cfg->profiles[i].ssid);
    prof_note(note, sizeof(note), i);
    snprintf(line, sizeof(line), "      %u%c %-20s%s%s%s%s\n", i + 1,
             i == cfg->active ? '*' : ' ', ssid,
             cfg->profiles[i].password[0] ? "" : "  (open)",
             note[0] ? "  (" : "", note, note[0] ? ")" : "");
    out(io, line);
  }
  out(io, "    (* = active)\n");
}

static void list_scan(const cfg_io_t *io, const config_t *cfg) {
  char line[112], ssid[CONFIG_SSID_MAX];
  bool assoc = netif_is_link_up(&cyw43_state.netif[CYW43_ITF_STA]);
  uint8_t n = wifi_scan_count();
  if (n == 0) {
    out(io, "    (no networks found -- scan to try again)\n");
  } else {
    snprintf(line, sizeof(line), "    networks (%u):\n", n);
    out(io, line);
    for (uint8_t i = 0; i < n; i++) {
      const wifi_scan_entry_t *e = wifi_scan_get(i);
      fmt_ssid(ssid, sizeof(ssid), e->ssid);
      int p = config_find_profile(cfg, e->ssid);
      const char *mark = "";
      if (p >= 0) {
        if ((uint8_t)p == cfg->active && assoc) {
          mark = "  [connected]";
        } else if (wifi_conn_prof_status((uint8_t)p) == WIFI_PROF_BADPASS) {
          mark = "  [saved, bad password?]";
        } else {
          mark = "  [saved]";
        }
      } else if (e->auth == 0) {
        mark = "  [open]";
      }
      snprintf(line, sizeof(line),
               "      %2u  %-20s  %4d dBm  %02x:%02x:%02x:%02x:%02x:%02x%s\n", i + 1,
               ssid, e->rssi, e->bssid[0], e->bssid[1], e->bssid[2], e->bssid[3],
               e->bssid[4], e->bssid[5], mark);
      out(io, line);
    }
  }
}

// Continuous-scan line: signal, channel, and BSSID (MAC) alongside the SSID --
// enough to identify each access point as the stream scrolls. No index; the
// numbered list for joining is reprinted when the stream stops.
static void stream_scan(const cfg_io_t *io) {
  char line[96], ssid[CONFIG_SSID_MAX];
  for (uint8_t i = 0; i < wifi_scan_count(); i++) {
    const wifi_scan_entry_t *e = wifi_scan_get(i);
    fmt_ssid(ssid, sizeof(ssid), e->ssid);
    snprintf(line, sizeof(line),
             "  %-20s  %4d dBm  ch %2u  %02x:%02x:%02x:%02x:%02x:%02x\n", ssid,
             e->rssi, e->channel, e->bssid[0], e->bssid[1], e->bssid[2],
             e->bssid[3], e->bssid[4], e->bssid[5]);
    out(io, line);
  }
}

static void start_scan(const cfg_io_t *io) {
  if (wifi_scan_start()) {
    g_mode = MODE_SCAN;
    scan_rounds = SCAN_PASSES;
    out(io, "[*] scanning"); // a dot is appended as each pass completes
  } else {
    out(io, "[!] scan failed to start\n");
  }
}

// Select-or-create the profile for `ssid` and join it now if the credentials
// suffice: a stored password, or the latest scan saw the network as open.
// Otherwise the profile is staged and the caller is told to set the password
// (which applies on its own). open_hint: 1 = open, 0 = secured, -1 = look it
// up in the scan results.
static void join_ssid(const cfg_io_t *io, config_t *cfg, const char *ssid, int open_hint) {
  int p = config_find_profile(cfg, ssid);
  if (p < 0) {
    p = config_add_profile(cfg, ssid); // a full list evicts its LRU tail
    if (p < 0) {
      out(io, "ERR could not add a profile\n");
      return;
    }
    // New credentials: once a join with them succeeds, persist automatically.
    wifi_conn_mark_creds_unsaved();
  }
  cfg->active = (uint8_t)p;
  if (open_hint < 0) {
    open_hint = 0; // unknown networks are assumed secured (hidden SSIDs etc.)
    for (uint8_t i = 0; i < wifi_scan_count(); i++) {
      const wifi_scan_entry_t *e = wifi_scan_get(i);
      if (strncmp(e->ssid, ssid, CONFIG_SSID_MAX) == 0) {
        open_hint = e->auth == 0;
        break;
      }
    }
  }
  if (cfg->profiles[p].password[0] || open_hint == 1) {
    out(io, cfg->profiles[p].password[0] ? "[*] joining with the saved password\n"
                                         : "[*] joining (open network)\n");
    if (g_apply) {
      g_apply(cfg);
    }
  } else {
    out(io, "[*] staged -- set pass <password> to join (saved automatically once it works)\n");
  }
}

// --- SET ----------------------------------------------------------------------

enum { SET_ERR, SET_WIFI, SET_OTHER, SET_WG, SET_AP }; // error / Wi-Fi / other / WireGuard / AP

// set key/peer/psk: store a validated base64 WireGuard key.
static int set_wg_key(const cfg_io_t *io, char *field, size_t cap, const char *val,
                      bool allow_off) {
  if (allow_off && strcasecmp(val, "off") == 0) {
    field[0] = '\0';
    return SET_WG;
  }
  if (!valid_wg_key(val)) {
    out(io, "ERR not a WireGuard key (base64, 32 bytes)\n");
    return SET_ERR;
  }
  strncpy(field, val, cap - 1);
  field[cap - 1] = '\0';
  return SET_WG;
}

static int cmd_set(const cfg_io_t *io, char *args, config_t *cfg) {
  char *val = strchr(args, ' ');
  if (val == NULL) {
    out(io, "ERR usage: set <key> <value> (see help)\n");
    return SET_ERR;
  }
  *val++ = '\0'; // args is now the key, val the remainder of the line

  if (strcasecmp(args, "ssid") == 0) {
    // Edit the active profile's SSID, or create the first profile if none.
    // (To ADD a network rather than rename the active one, use `join <ssid>`.)
    if (cfg->active < cfg->profile_count) {
      strncpy(cfg->profiles[cfg->active].ssid, val, CONFIG_SSID_MAX - 1);
      cfg->profiles[cfg->active].ssid[CONFIG_SSID_MAX - 1] = '\0';
    } else {
      int i = config_add_profile(cfg, val);
      if (i < 0) {
        out(io, "ERR could not add a profile\n");
        return SET_ERR;
      }
      cfg->active = (uint8_t)i;
    }
    wifi_conn_mark_creds_unsaved(); // persist once a join with these works
    return SET_WIFI;
  } else if (strcasecmp(args, "pass") == 0) {
    if (cfg->active >= cfg->profile_count) {
      out(io, "ERR no active profile -- set ssid (or join <ssid>) first\n");
      return SET_ERR;
    }
    strncpy(cfg->profiles[cfg->active].password, val, CONFIG_PASS_MAX - 1);
    cfg->profiles[cfg->active].password[CONFIG_PASS_MAX - 1] = '\0';
    wifi_conn_mark_creds_unsaved(); // persist once a join with these works
    return SET_WIFI;
  } else if (strcasecmp(args, "country") == 0) {
    cfg->country = parse_country(val);
    return SET_WIFI;
  } else if (strcasecmp(args, "debug") == 0) {
    if (strcasecmp(val, "on") == 0) {
      cfg->debug_enabled = 1;
      return SET_OTHER;
    } else if (strcasecmp(val, "off") == 0) {
      cfg->debug_enabled = 0;
      return SET_OTHER;
    }
    out(io, "ERR usage: set debug <on|off>\n");
    return SET_ERR;
  } else if (strcasecmp(args, "key") == 0) {
    return set_wg_key(io, cfg->wg.private_key, CONFIG_WGKEY_MAX, val, false);
  } else if (strcasecmp(args, "peer") == 0) {
    return set_wg_key(io, cfg->wg.peer_public, CONFIG_WGKEY_MAX, val, false);
  } else if (strcasecmp(args, "psk") == 0) {
    return set_wg_key(io, cfg->wg.psk, CONFIG_WGKEY_MAX, val, true);
  } else if (strcasecmp(args, "endpoint") == 0) {
    // "set endpoint <host|ip> <port>"
    char *port = strchr(val, ' ');
    if (port == NULL) {
      out(io, "ERR usage: set endpoint <host|ip> <port>\n");
      return SET_ERR;
    }
    *port++ = '\0';
    long p = strtol(port, NULL, 10);
    if (p < 1 || p > 65535 || strlen(val) >= CONFIG_ENDPOINT_MAX) {
      out(io, "ERR bad endpoint (name too long or port not 1-65535)\n");
      return SET_ERR;
    }
    strncpy(cfg->wg.endpoint, val, CONFIG_ENDPOINT_MAX - 1);
    cfg->wg.endpoint[CONFIG_ENDPOINT_MAX - 1] = '\0';
    cfg->wg.endpoint_port = (uint16_t)p;
    return SET_WG;
  } else if (strcasecmp(args, "addr") == 0) {
    // "set addr <a.b.c.d/nn>" -- device tunnel address + USB-link prefix
    char *slash = strchr(val, '/');
    if (slash == NULL) {
      out(io, "ERR usage: set addr <a.b.c.d/nn> (e.g. 10.66.0.249/30)\n");
      return SET_ERR;
    }
    *slash++ = '\0';
    uint32_t a = parse_ip4(val);
    long pfx = strtol(slash, NULL, 10);
    if (!a || pfx < 8 || pfx > 30) {
      out(io, "ERR bad address or prefix (prefix 8-30)\n");
      return SET_ERR;
    }
    cfg->wg.addr = a;
    cfg->wg.prefix = (uint8_t)pfx;
    return SET_WG;
  } else if (strcasecmp(args, "hostip") == 0) {
    uint32_t a = parse_ip4(val);
    if (!a) {
      out(io, "ERR usage: set hostip <a.b.c.d>\n");
      return SET_ERR;
    }
    cfg->wg.host_addr = a;
    return SET_WG;
  } else if (strcasecmp(args, "dns") == 0) {
    if (strcasecmp(val, "off") == 0) {
      cfg->wg.dns = 0; // offer no resolver; the host keeps its own
      return SET_WG;
    }
    uint32_t a = parse_ip4(val);
    if (!a) {
      out(io, "ERR usage: set dns <a.b.c.d|off>\n");
      return SET_ERR;
    }
    cfg->wg.dns = a;
    return SET_WG;
  } else if (strcasecmp(args, "routes") == 0) {
    // "set routes off" -> full-gateway mode (Pico becomes the host's default
    // route). "set routes <cidr>[,<cidr>...]" -> split mode: only these
    // subnets are routed to the Pico (DHCP option 121); the host keeps its
    // own default route and DNS path.
    if (strcasecmp(val, "off") == 0) {
      cfg->wg.route_count = 0;
      return SET_WG;
    }
    wg_route_t parsed[CONFIG_ROUTES_MAX];
    uint8_t n = 0;
    char *tok = val;
    while (tok && *tok) {
      char *comma = strchr(tok, ',');
      if (comma) *comma++ = '\0';
      char *slash = strchr(tok, '/');
      if (!slash) {
        out(io, "ERR routes are <a.b.c.d/nn>, comma-separated\n");
        return SET_ERR;
      }
      *slash++ = '\0';
      uint32_t net = parse_ip4(tok);
      long plen = strtol(slash, NULL, 10);
      if ((!net && strcmp(tok, "0.0.0.0") != 0) || plen < 1 || plen > 32) {
        out(io, "ERR bad route (prefix 1-32)\n");
        return SET_ERR;
      }
      if (n >= CONFIG_ROUTES_MAX) {
        out(io, "ERR too many routes (max 4)\n");
        return SET_ERR;
      }
      parsed[n].net = net;
      parsed[n].prefix = (uint8_t)plen;
      n++;
      tok = comma;
    }
    if (n == 0) {
      out(io, "ERR usage: set routes <a.b.c.d/nn>[,...] | off\n");
      return SET_ERR;
    }
    memcpy(cfg->wg.routes, parsed, sizeof(parsed));
    cfg->wg.route_count = n;
    return SET_WG;
  } else if (strcasecmp(args, "keepalive") == 0) {
    long k = strtol(val, NULL, 10);
    if (k < 0 || k > 65000) {
      out(io, "ERR usage: set keepalive <seconds> (0 = off)\n");
      return SET_ERR;
    }
    cfg->wg.keepalive = (uint16_t)k;
    return SET_WG;
  } else if (strcasecmp(args, "mtu") == 0) {
    // MTU handed to the host over DHCP. Lower it below the WireGuard 1420 when
    // the far end re-encapsulates (e.g. a Tailscale bridge: set mtu 1280).
    long m = strtol(val, NULL, 10);
    if (m != 0 && (m < 576 || m > 1420)) { // ceiling = WIREGUARDIF_MTU
      out(io, "ERR usage: set mtu <576-1420> (0 = default 1420)\n");
      return SET_ERR;
    }
    cfg->wg.host_mtu = (uint16_t)m;
    return SET_WG;
  } else if (strcasecmp(args, "apssid") == 0) {
    strncpy(cfg->ap.ssid, val, CONFIG_SSID_MAX - 1);
    cfg->ap.ssid[CONFIG_SSID_MAX - 1] = '\0';
    return SET_AP;
  } else if (strcasecmp(args, "appass") == 0) {
    size_t n = strlen(val);
    if (n < 8 || n > 63) { // WPA2-PSK bounds; an open quarantine AP would hand
      out(io, "ERR AP password must be 8-63 chars (an open AP is not allowed)\n");
      return SET_ERR; //     the tunnel to anyone in radio range
    }
    strncpy(cfg->ap.password, val, CONFIG_PASS_MAX - 1);
    cfg->ap.password[CONFIG_PASS_MAX - 1] = '\0';
    return SET_AP;
  } else if (strcasecmp(args, "apaddr") == 0) {
    // "set apaddr <a.b.c.d/nn>" -- device's AP-link address + prefix
    char *slash = strchr(val, '/');
    if (slash == NULL) {
      out(io, "ERR usage: set apaddr <a.b.c.d/nn> (e.g. 10.66.0.253/30)\n");
      return SET_ERR;
    }
    *slash++ = '\0';
    uint32_t a = parse_ip4(val);
    long pfx = strtol(slash, NULL, 10);
    if (!a || pfx < 8 || pfx > 30) {
      out(io, "ERR bad address or prefix (prefix 8-30)\n");
      return SET_ERR;
    }
    cfg->ap.addr = a;
    cfg->ap.prefix = (uint8_t)pfx;
    return SET_AP;
  } else if (strcasecmp(args, "apclient") == 0) {
    uint32_t a = parse_ip4(val);
    if (!a) {
      out(io, "ERR usage: set apclient <a.b.c.d>\n");
      return SET_ERR;
    }
    cfg->ap.client_addr = a;
    return SET_AP;
  } else if (strcasecmp(args, "ap") == 0) {
    if (strcasecmp(val, "off") == 0) {
      cfg->ap.enabled = 0;
      return SET_AP;
    }
    if (strcasecmp(val, "on") != 0) {
      out(io, "ERR usage: set ap <on|off>\n");
      return SET_ERR;
    }
    if (!config_ap_complete(cfg)) {
      out(io, "ERR AP config incomplete -- need apssid, appass (8-63 chars), and an\n"
              "    apaddr/apclient pair inside one subnet (both from tunnel space,\n"
              "    covered by the server's AllowedIPs)\n");
      return SET_ERR;
    }
    cfg->ap.enabled = 1;
    return SET_AP;
  }
  out(io, "ERR unknown key (ssid|pass|country|debug|key|peer|psk|endpoint|addr|"
          "hostip|dns|keepalive|mtu|routes|apssid|appass|apaddr|apclient|ap)\n");
  return SET_ERR;
}

// --- menu handlers ------------------------------------------------------------

static void handle_main(const cfg_io_t *io, char *cmd, char *args, config_t *cfg) {
  if (strcasecmp(cmd, "SET") == 0 && args) {
    int r = cmd_set(io, args, cfg);
    if (r == SET_ERR) {
      return; // error already printed
    }
    if (r == SET_WIFI && g_apply) {
      out(io, "[*] applying -- re-associating\n");
      g_apply(cfg); // re-associate with the new credentials immediately
    } else if (r == SET_WG && g_apply_wg) {
      out(io, "[*] applying -- restarting tunnel\n");
      g_apply_wg(cfg); // re-address the USB link and re-create the tunnel
    } else if (r == SET_AP && g_apply_ap) {
      out(io, "[*] applying -- reconfiguring AP\n");
      g_apply_ap(cfg); // bring the AP up/down to match (no-op if unchanged)
    } else if (r == SET_OTHER) {
      out(io, "[*] updated\n");
    }
    config_proto_dump(io, cfg);
  } else if (strcasecmp(cmd, "LIST") == 0) {
    list_profiles(io, cfg);
  } else if (strcasecmp(cmd, "JOIN") == 0 && args) {
    // Join a network by name: select-or-create its profile and associate if
    // the credentials suffice. The portal's scan picker sends this.
    join_ssid(io, cfg, args, -1);
    config_proto_dump(io, cfg);
  } else if (strcasecmp(cmd, "USE") == 0 && args) {
    int i = parse_index(args, cfg->profile_count);
    if (i < 0) {
      out(io, "ERR usage: use <n> (see list)\n");
      return;
    }
    cfg->active = (uint8_t)i;
    if (g_apply) {
      out(io, "[*] applying -- re-associating\n");
      g_apply(cfg);
    }
    config_proto_dump(io, cfg);
  } else if (strcasecmp(cmd, "DEL") == 0 && args) {
    int i = parse_index(args, cfg->profile_count);
    if (i < 0) {
      // Not a list index: try it as an SSID. The portal deletes by name, so
      // a concurrent MRU reorder can't make it forget the wrong network.
      i = config_find_profile(cfg, args);
    }
    if (i < 0) {
      out(io, "ERR usage: del <n|ssid> (see list)\n");
      return;
    }
    config_del_profile(cfg, i);
    out(io, "[*] deleted (save to persist)\n");
    if (g_apply) {
      g_apply(cfg); // active profile may have changed
    }
    config_proto_dump(io, cfg);
  } else if (strcasecmp(cmd, "PCAP") == 0 && args) {
    // Runtime toggle for the USB-link packet capture (not persisted).
    if (strcasecmp(args, "on") == 0) {
      pcap_set_enabled(true);
      out(io, "[*] capturing the USB link (download via the portal: /api/pcap)\n");
    } else if (strcasecmp(args, "off") == 0) {
      pcap_set_enabled(false);
      out(io, "[*] capture stopped (ring kept -- 'pcap clear' to discard)\n");
    } else if (strcasecmp(args, "clear") == 0) {
      pcap_clear();
      out(io, "[*] capture ring cleared\n");
    } else {
      out(io, "ERR usage: pcap <on|off|clear>\n");
    }
  } else if (strcasecmp(cmd, "GENKEY") == 0) {
    // Generate the WireGuard identity on-device: the private key goes straight
    // from the TRNG into the config and is never printed anywhere; only the
    // public key is shown, which is what the server admin needs.
    if (cfg->wg.private_key[0] && !(args && strcasecmp(args, "force") == 0)) {
      out(io, "ERR a private key is already set -- 'genkey force' replaces it\n"
              "    (the server must then be given the new public key)\n");
      return;
    }
    uint8_t priv[32], pub[32];
    char b64[48];
    if (!wg_keypair_generate(pub, priv)) {
      out(io, "[!] key generation failed\n");
      return;
    }
    size_t olen = CONFIG_WGKEY_MAX;
    wireguard_base64_encode(priv, sizeof(priv), cfg->wg.private_key, &olen);
    memset(priv, 0, sizeof(priv));
    olen = sizeof(b64);
    wireguard_base64_encode(pub, sizeof(pub), b64, &olen);
    out(io, "[*] keypair generated on-device; the private key never leaves it\n");
    out(io, "    public key: ");
    out(io, b64);
    out(io, "\n    give this to the WireGuard admin, then `save`\n");
    if (g_apply_wg) {
      g_apply_wg(cfg); // restart the tunnel under the new identity
    }
    config_proto_dump(io, cfg);
  } else if (strcasecmp(cmd, "PUBKEY") == 0) {
    // Reprint the public key alone (script-friendly single line).
    char b64[48];
    if (config_proto_pubkey(cfg, b64, sizeof(b64))) {
      out(io, b64);
      out(io, "\n");
    } else {
      out(io, "ERR no usable private key -- genkey (or set key <b64>) first\n");
    }
  } else if (strcasecmp(cmd, "BOOTSEL") == 0 || strcasecmp(cmd, "REBOOT") == 0) {
    // Development conveniences: restart without touching the board. BOOTSEL
    // lands in the UF2 bootloader for reflashing; REBOOT is a plain restart.
    // (Opening either CDC port at 1200 baud also triggers BOOTSEL.)
    bool to_bootloader = (toupper((unsigned char)cmd[0]) == 'B');
    out(io, to_bootloader ? "[*] rebooting to UF2 bootloader...\n" : "[*] rebooting...\n");
    for (int i = 0; i < 20; i++) { // give USB a moment to drain the goodbye
      tud_task();
      busy_wait_ms(2);
    }
    if (to_bootloader) {
      watchdog_disable(); // an armed watchdog would fire inside the bootloader
      reset_usb_boot(0, 0);
    } else {
      watchdog_reboot(0, 0, 0);
    }
    while (true) tight_loop_contents(); // unreachable
  } else if (strcasecmp(cmd, "SCAN") == 0) {
    start_scan(io);
  } else if (strcasecmp(cmd, "SAVE") == 0) {
    bool ok = config_save(cfg);
    if (ok) {
      wifi_conn_note_saved(); // staged credentials are in flash now
    }
    out(io, ok ? "[*] saved to flash\n" : "[!] save failed\n");
    config_proto_dump(io, cfg);
  } else if (strcasecmp(cmd, "RESTORE") == 0) {
    config_load(cfg); // discard unsaved edits: reload the saved (or default) record
    wifi_conn_note_saved(); // staged credentials were just discarded with the rest
    out(io, "[*] restored saved settings\n");
    if (g_apply) {
      g_apply(cfg);
    }
    if (g_apply_wg) {
      g_apply_wg(cfg); // also re-applies the AP (apply_wg calls ap_apply)
    }
    config_proto_dump(io, cfg);
  } else {
    out(io, "[!] commands: set <ssid|pass|country|debug|key|peer|psk|endpoint|addr|"
            "hostip|dns|keepalive|mtu|routes|apssid|appass|apaddr|apclient|ap> <val> | "
            "genkey [force] | pubkey | pcap <on|off|clear> | list | join <ssid> | "
            "use <n> | del <n> | scan | save | restore | reboot | bootsel\n");
  }
}

static void handle_scan(const cfg_io_t *io, char *cmd, char *args, config_t *cfg) {
  if (strcasecmp(cmd, "BACK") == 0) {
    g_mode = MODE_MAIN;
    config_proto_dump(io, cfg);
  } else if (strcasecmp(cmd, "SCAN") == 0) {
    start_scan(io); // re-run the scan
  } else if (strcasecmp(cmd, "LIVE") == 0) {
    // Continuous scan: stream access points until any key is pressed, staying
    // disassociated for the duration.
    cyw43_wifi_leave(&cyw43_state, CYW43_ITF_STA);
    if (wifi_scan_start()) {
      g_mode = MODE_CONTSCAN;
      out(io, "[*] live scan -- press any key to stop\n");
    } else {
      out(io, "[!] scan failed to start\n");
    }
  } else if (strcasecmp(cmd, "JOIN") == 0 && args) {
    int i = parse_index(args, wifi_scan_count());
    if (i < 0) {
      out(io, "ERR usage: join <n> (see the list)\n");
      return;
    }
    const wifi_scan_entry_t *e = wifi_scan_get((uint8_t)i);
    g_mode = MODE_MAIN;
    join_ssid(io, cfg, e->ssid, e->auth == 0);
    config_proto_dump(io, cfg);
  } else {
    out(io, "[!] scan: back | join <n> | scan | live\n");
  }
}

// --- line handling ------------------------------------------------------------

void config_proto_handle_line(const cfg_io_t *io, char *line, config_t *cfg) {
  size_t n = strlen(line);
  while (n > 0 && (line[n - 1] == '\r' || line[n - 1] == ' ')) {
    line[--n] = '\0';
  }
  if (n == 0) { // bare Enter reprints the current view
    if (g_mode == MODE_SCAN) {
      list_scan(io, cfg);
    } else {
      config_proto_dump(io, cfg);
    }
    return;
  }

  char *args = strchr(line, ' ');
  if (args != NULL) {
    *args++ = '\0'; // line is the command word, args the remainder
  }

  if (g_mode == MODE_SCAN) {
    handle_scan(io, line, args, cfg);
  } else {
    handle_main(io, line, args, cfg);
  }
}

bool config_proto_scanning(void) {
  return wifi_scan_in_progress() || g_mode == MODE_CONTSCAN || scan_rounds > 0;
}

void config_proto_poll(const cfg_io_t *io, config_t *cfg) {
  (void)cfg;
  if (g_mode == MODE_CONTSCAN) {
    if (wifi_scan_poll()) {
      stream_scan(io); // a pass finished: print it...
    }
    if (!wifi_scan_in_progress()) {
      wifi_scan_start(); // ...and keep a fresh pass running
    }
    return;
  }

  // Single scan: union SCAN_PASSES passive passes before showing the list.
  // Nothing of ours in flight -> hands off wifi_scan entirely: a wifi_conn
  // (manager) scan may be running, and polling here would eat its completion.
  if (scan_rounds == 0) {
    return;
  }
  bool done = wifi_scan_poll();
  if (done && --scan_rounds > 0) {
    out(io, "."); // a pass finished, more to go
  }
  if (scan_rounds > 0) {
    if (!wifi_scan_in_progress()) {
      wifi_scan_again(); // next accumulating pass
    }
  } else if (g_mode == MODE_SCAN) {
    out(io, "\n");
    list_scan(io, cfg);
    out(io, config_proto_prompt());
  }
}

const char *config_proto_prompt(void) {
  if (g_mode == MODE_CONTSCAN) {
    return ""; // streaming; any key stops it, so no prompt
  }
  if (g_mode == MODE_SCAN) {
    // Same shape as the main prompt: the verbs in parentheses before the '#'.
    return wifi_scan_in_progress() ? "" : "(back|join|scan|live) # ";
  }
  return "(set|scan|join|list|use|save) # ";
}

bool config_proto_contscan_active(void) { return g_mode == MODE_CONTSCAN; }

bool config_proto_owns_scan(void) {
  // Scan passes pending, or any scan-view mode: while a user is looking at
  // (or collecting) a numbered result list, the connection manager must not
  // start a scan of its own -- wifi_scan_start resets the results, which
  // would renumber the list their `join <n>` refers to.
  return scan_rounds > 0 || g_mode != MODE_MAIN;
}

void config_proto_contscan_stop(const cfg_io_t *io, config_t *cfg) {
  wifi_scan_stop();   // abandon the in-flight pass: no further auto-print
  scan_rounds = 0;
  g_mode = MODE_SCAN; // back to the scan submenu with the last results
  out(io, "\n[*] stopped\n");
  list_scan(io, cfg);
}
