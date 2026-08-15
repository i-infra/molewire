// Wi-Fi connection manager. See wifi_conn.h.
//
// A small state machine ticked from the main loop:
//
//   UP ----link lost----> (fast rejoin x2) ----> SCAN ---> TRY ---> UP
//                                                 ^          |
//                                                 +-- WAIT <-+  (all failed:
//                                                                backoff, rescan)
//
// The scan/candidate plumbing is shared with the console: wifi_scan is a
// singleton, so the manager keeps its hands off it whenever the console's
// scan submenu or live scan is active (config_proto_owns_scan()), and the
// console's completed results are reused when fresh instead of re-scanning.

#include <stdio.h>
#include <string.h>

#include <lwip/netif.h>
#include <pico/cyw43_arch.h>

#include "config_proto.h" // config_proto_owns_scan: console owns the scan machinery
#include "debug_console.h"
#include "wifi_conn.h"
#include "wifi_scan.h"

#define JOIN_TIMEOUT_MS 12000u  // per-candidate association deadline
#define FAST_RETRIES 2          // rejoins of the same profile before a full cycle
#define MGR_SCAN_PASSES 2       // passive passes per manager scan (console uses 4)
#define SCAN_FRESH_MS 15000u    // results younger than this are reused, not redone
#define BACKOFF_MIN_MS 8000u    // between cycles when nothing was joinable...
#define BACKOFF_MAX_MS 60000u   // ...doubling up to this cap
#define BADPASS_RETRY_MS 600000u // a bad-password mark decays after 10 minutes

static config_t *g_cfg;

static enum { ST_IDLE, ST_SCAN, ST_TRY, ST_WAIT, ST_UP } state;
static wifi_prof_state_t prof[CONFIG_PROFILE_MAX]; // runtime status, RAM only
static uint32_t badpass_at[CONFIG_PROFILE_MAX];    // when BADPASS was marked
static uint8_t order[CONFIG_PROFILE_MAX];          // this cycle's candidates
static uint8_t order_n, order_ix;
static uint8_t trying;       // profile index of the in-flight attempt
static uint8_t rr_unseen;    // rotates the one-unseen-per-cycle slot
static uint8_t fast_tries;   // same-profile rejoins left before a full cycle
static uint32_t attempt_at;  // when the current attempt started
static uint32_t wait_until;  // ST_WAIT deadline
static uint32_t backoff_ms = BACKOFF_MIN_MS;
static uint8_t scan_passes_left; // manager-scan passes still to run
static uint32_t scan_done_at;    // completion time of the last scan
static bool scan_ever;
static bool scan_requested;   // portal asked for a scan
static bool creds_unsaved;    // joined-profile credentials not yet in flash

// Map the latest scan results onto the profiles: RSSI per saved SSID.
static void snapshot_rssi(void) {
  for (uint8_t i = 0; i < CONFIG_PROFILE_MAX; i++) {
    prof[i].rssi = WIFI_RSSI_UNSEEN;
  }
  if (!g_cfg) {
    return;
  }
  for (uint8_t i = 0; i < wifi_scan_count(); i++) {
    const wifi_scan_entry_t *e = wifi_scan_get(i);
    int p = config_find_profile(g_cfg, e->ssid);
    if (p >= 0) {
      prof[p].rssi = e->rssi;
    }
  }
}

static void enter_wait(uint32_t now) {
  state = ST_WAIT;
  wait_until = now + backoff_ms;
  if (g_cfg->debug_enabled) {
    debug_printf("wifi: no joinable network, rescanning in %lus\n",
                 (unsigned long)(backoff_ms / 1000u));
  }
  backoff_ms *= 2;
  if (backoff_ms > BACKOFF_MAX_MS) {
    backoff_ms = BACKOFF_MAX_MS;
  }
}

// Kick off the candidate at order[order_ix], skipping any the radio refuses;
// falls into WAIT when the list is exhausted.
static void try_from(uint32_t now) {
  while (order_ix < order_n) {
    uint8_t i = order[order_ix];
    const wifi_profile_t *p = &g_cfg->profiles[i];
    cyw43_wifi_leave(&cyw43_state, CYW43_ITF_STA); // reset any half-done join
    if (cyw43_arch_wifi_connect_async(
            p->ssid, p->password,
            p->password[0] ? CYW43_AUTH_WPA3_WPA2_AES_PSK : CYW43_AUTH_OPEN) == 0) {
      trying = i;
      attempt_at = now;
      state = ST_TRY;
      return;
    }
    order_ix++;
  }
  enter_wait(now);
}

// Order the candidates from the (already snapshotted) scan and start trying.
static void build_and_try(uint32_t now) {
  order_n = wifi_pick_order(prof, g_cfg->profile_count, g_cfg->active, rr_unseen, order);
  rr_unseen++; // next cycle's blind slot goes to the next unseen profile
  order_ix = 0;
  try_from(now);
}

static void start_cycle(uint32_t now) {
  if (g_cfg->profile_count == 0) {
    state = ST_IDLE;
    return;
  }
  state = ST_SCAN;
  if (scan_ever && (uint32_t)(now - scan_done_at) < SCAN_FRESH_MS) {
    snapshot_rssi(); // console results may be newer than our last snapshot
    build_and_try(now);
    return;
  }
  if (wifi_scan_start()) {
    scan_passes_left = MGR_SCAN_PASSES;
  } else {
    enter_wait(now);
  }
}

// Association came up for profile `trying`: record it, move the profile to
// the front of the MRU list (the flash eviction order), and persist newly
// proven credentials.
static void joined(uint32_t now) {
  (void)now;
  if (trying >= g_cfg->profile_count) { // list edited under us; just track link
    state = ST_UP;
    fast_tries = FAST_RETRIES;
    return;
  }
  for (uint8_t i = 0; i < CONFIG_PROFILE_MAX; i++) {
    if (prof[i].status == WIFI_PROF_CONNECTED) {
      prof[i].status = WIFI_PROF_UNTRIED;
    }
  }
  // MRU reorder, permuting the runtime state arrays the same way. `active`
  // follows the connection (so `set pass` etc. edit the network we are on);
  // the reorder itself is persisted lazily, by whichever save comes next.
  g_cfg->active = trying;
  if (trying > 0) {
    wifi_prof_state_t mp = prof[trying];
    uint32_t mb = badpass_at[trying];
    memmove(&prof[1], &prof[0], (size_t)trying * sizeof(prof[0]));
    memmove(&badpass_at[1], &badpass_at[0], (size_t)trying * sizeof(badpass_at[0]));
    prof[0] = mp;
    badpass_at[0] = mb;
    config_touch_profile(g_cfg, trying);
    trying = 0;
  }
  prof[trying].status = WIFI_PROF_CONNECTED;
  state = ST_UP;
  fast_tries = FAST_RETRIES;
  backoff_ms = BACKOFF_MIN_MS;

  // Auto-save exactly when this join proved credentials flash doesn't hold
  // (profile just added or password just changed): a network joined once from
  // the picker is remembered across reboots without an explicit `save`. Note
  // this writes the whole config record, staged edits included.
  bool saved = false;
  if (creds_unsaved) {
    saved = config_save(g_cfg);
    creds_unsaved = false;
  }
  printf("wifi: associated to '%s'%s\n", g_cfg->profiles[trying].ssid,
         saved ? " (credentials saved to flash)" : "");
  if (g_cfg->debug_enabled) {
    debug_printf("wifi: associated to %s%s\n", g_cfg->profiles[trying].ssid,
                 saved ? " (saved)" : "");
  }
}

void wifi_conn_init(config_t *cfg) {
  g_cfg = cfg;
  memset(prof, 0, sizeof(prof));
  snapshot_rssi(); // all-unseen (no scan yet)
  if (cfg->active < cfg->profile_count) {
    printf("associating to '%s' ...\n", cfg->profiles[cfg->active].ssid);
    order[0] = cfg->active;
    order_n = 1;
    order_ix = 0;
    try_from(to_ms_since_boot(get_absolute_time()));
  } else if (cfg->profile_count > 0) {
    printf("scanning for a saved Wi-Fi network ...\n");
    state = ST_WAIT;
    wait_until = 0; // first task tick starts the cycle
  } else {
    printf("no Wi-Fi networks saved; provision over the serial console or portal\n");
    state = ST_IDLE;
  }
}

void wifi_conn_apply(const config_t *cfg) {
  (void)cfg; // same object as g_cfg; the parameter is the g_apply signature
  if (!g_cfg) {
    return;
  }
  uint32_t now = to_ms_since_boot(get_absolute_time());
  // The list may have been edited or reordered, so the per-profile statuses
  // no longer line up -- and an edit or explicit selection is the user asking
  // for a fresh attempt anyway. Reset statuses, keep scan-derived RSSIs.
  memset(prof, 0, sizeof(prof));
  snapshot_rssi();
  backoff_ms = BACKOFF_MIN_MS;
  cyw43_wifi_leave(&cyw43_state, CYW43_ITF_STA);
  if (g_cfg->active < g_cfg->profile_count) {
    // Pin: try exactly the chosen profile now; failure falls back to the
    // normal scan cycle via WAIT.
    order[0] = g_cfg->active;
    order_n = 1;
    order_ix = 0;
    try_from(now);
  } else {
    state = ST_WAIT;
    wait_until = now; // no active profile: straight to a scan cycle (or IDLE)
  }
}

void wifi_conn_mark_creds_unsaved(void) { creds_unsaved = true; }
void wifi_conn_note_saved(void) { creds_unsaved = false; }

void wifi_conn_request_scan(void) { scan_requested = true; }

bool wifi_conn_scanning(void) { return scan_passes_left > 0; }

uint32_t wifi_conn_scan_age_ms(void) {
  if (!scan_ever) {
    return UINT32_MAX;
  }
  return to_ms_since_boot(get_absolute_time()) - scan_done_at;
}

const char *wifi_conn_state_str(void) {
  switch (state) {
    case ST_UP: return "up";
    case ST_TRY: return "joining";
    case ST_SCAN: return "scanning";
    case ST_WAIT: return "backoff";
    default: return "idle";
  }
}

wifi_prof_status_t wifi_conn_prof_status(uint8_t i) {
  return i < CONFIG_PROFILE_MAX ? (wifi_prof_status_t)prof[i].status : WIFI_PROF_UNTRIED;
}

int16_t wifi_conn_prof_rssi(uint8_t i) {
  return i < CONFIG_PROFILE_MAX ? prof[i].rssi : WIFI_RSSI_UNSEEN;
}

void wifi_conn_task(uint32_t now) {
  if (!g_cfg) {
    return;
  }
  static uint32_t last_tick;
  if ((uint32_t)(now - last_tick) < 100u) {
    return; // everything below is deadline-based; 10 Hz is plenty
  }
  last_tick = now;

  // Bad-password marks decay: an AP-side hiccup that looked like a rejected
  // password must not blacklist a good profile forever.
  for (uint8_t i = 0; i < g_cfg->profile_count; i++) {
    if (prof[i].status == WIFI_PROF_BADPASS &&
        (uint32_t)(now - badpass_at[i]) >= BADPASS_RETRY_MS) {
      prof[i].status = WIFI_PROF_UNTRIED;
    }
  }

  // The console's scan submenu / live scan owns the radio and the wifi_scan
  // singleton; hold everything until it is done (its results get reused).
  if (config_proto_owns_scan()) {
    return;
  }

  bool link = netif_is_link_up(&cyw43_state.netif[CYW43_ITF_STA]);

  // Drive an in-progress manager scan -- the down-cycle scan or a portal-
  // requested one. If the console stole/stopped the scan underneath us,
  // in_progress goes false and this self-heals by consuming what was
  // collected.
  if (scan_passes_left > 0) {
    wifi_scan_poll(); // drops the in-progress latch when a pass completes
    if (!wifi_scan_in_progress()) {
      if (--scan_passes_left > 0 && !wifi_scan_again()) {
        scan_passes_left = 0; // radio refused another pass: use what we have
      }
      if (scan_passes_left == 0) {
        snapshot_rssi();
        scan_done_at = now;
        scan_ever = true;
        if (state == ST_SCAN) {
          build_and_try(now);
        }
      }
    }
  } else if (scan_requested && state != ST_TRY) {
    // Portal-requested scan; allowed while associated (the radio goes briefly
    // off-channel, an established link survives), deferred past a join.
    scan_requested = false;
    if (wifi_scan_start()) {
      scan_passes_left = MGR_SCAN_PASSES;
      if (state == ST_WAIT) {
        state = ST_SCAN; // let the fresh results drive an immediate join
      }
    }
  }

  switch (state) {
    case ST_UP:
      if (!link) {
        for (uint8_t i = 0; i < CONFIG_PROFILE_MAX; i++) {
          if (prof[i].status == WIFI_PROF_CONNECTED) {
            prof[i].status = WIFI_PROF_UNTRIED;
          }
        }
        printf("wifi: link lost\n");
        if (g_cfg->debug_enabled) {
          debug_printf("wifi: link lost\n");
        }
        if (fast_tries > 0 && g_cfg->active < g_cfg->profile_count) {
          // Fast path: the AP probably just rebooted -- rejoin it directly
          // before paying for a scan cycle.
          fast_tries--;
          order[0] = g_cfg->active;
          order_n = 1;
          order_ix = 0;
          try_from(now);
        } else {
          start_cycle(now);
        }
      }
      break;

    case ST_TRY: {
      if (link) {
        joined(now);
        break;
      }
      int ls = cyw43_wifi_link_status(&cyw43_state, CYW43_ITF_STA);
      if (ls == CYW43_LINK_BADAUTH) {
        prof[trying].status = WIFI_PROF_BADPASS;
        badpass_at[trying] = now;
        printf("wifi: '%s' rejected the password; skipping it for a while\n",
               g_cfg->profiles[trying].ssid);
        order_ix++;
        try_from(now);
      } else if (ls == CYW43_LINK_FAIL || ls == CYW43_LINK_NONET ||
                 (uint32_t)(now - attempt_at) >= JOIN_TIMEOUT_MS) {
        prof[trying].status = WIFI_PROF_NOJOIN;
        order_ix++;
        try_from(now);
      }
      break;
    }

    case ST_SCAN:
    case ST_WAIT:
      if (link) { // a late async join landed (e.g. a pin issued mid-scan)
        joined(now);
        break;
      }
      if (state == ST_WAIT && (int32_t)(now - wait_until) >= 0) {
        start_cycle(now);
      }
      break;

    case ST_IDLE:
      if (g_cfg->profile_count > 0) {
        start_cycle(now);
      }
      break;
  }
}
