// Asynchronous Wi-Fi network scan. See wifi_scan.h.

#include <string.h>

#include <lwip/netif.h>
#include <pico/cyw43_arch.h>

#include "wifi_scan.h"

static wifi_scan_entry_t results[WIFI_SCAN_MAX];
static uint8_t result_count;
static volatile bool scanning;

static void fill_entry(wifi_scan_entry_t *e, const cyw43_ev_scan_result_t *r, uint8_t len) {
  memcpy(e->ssid, r->ssid, len);
  e->ssid[len] = '\0';
  e->rssi = r->rssi;
  e->channel = r->channel;
  memcpy(e->bssid, r->bssid, 6);
  e->auth = r->auth_mode;
}

// Scan result callback. Fires in the background cyw43 context; callers serialise
// against it with the cyw43 lock. Duplicate SSIDs (the same AP seen on more than
// one beacon, or several APs sharing an SSID) collapse to the strongest signal.
static int scan_cb(void *env, const cyw43_ev_scan_result_t *r) {
  (void)env;
  if (r == NULL || r->ssid_len == 0) {
    return 0; // skip the scan-complete marker and hidden networks
  }
  uint8_t len = r->ssid_len > 32 ? 32 : r->ssid_len;

  for (uint8_t i = 0; i < result_count; i++) {
    if (strncmp(results[i].ssid, (const char *)r->ssid, CONFIG_SSID_MAX) == 0 &&
        results[i].ssid[len] == '\0') {
      if (r->rssi > results[i].rssi) {
        fill_entry(&results[i], r, len);
      }
      return 0;
    }
  }

  if (result_count < WIFI_SCAN_MAX) {
    fill_entry(&results[result_count++], r, len);
    return 0;
  }
  // Table full: keep the strongest. Replace the weakest entry if this network
  // beats it, so a strong AP seen on a later channel is not lost.
  uint8_t weakest = 0;
  for (uint8_t i = 1; i < result_count; i++) {
    if (results[i].rssi < results[weakest].rssi) {
      weakest = i;
    }
  }
  if (r->rssi > results[weakest].rssi) {
    fill_entry(&results[weakest], r, len);
  }
  return 0;
}

bool wifi_scan_start(void) {
  if (scanning) {
    return true;
  }
  result_count = 0;
  // If we are not associated, abort any in-flight or stuck join (e.g. a network
  // whose authentication keeps failing) so it cannot block the scan. A healthy
  // association is left alone: the scan briefly goes off-channel and survives.
  if (!netif_is_link_up(&cyw43_state.netif[CYW43_ITF_STA])) {
    cyw43_wifi_leave(&cyw43_state, CYW43_ITF_STA);
  }
  cyw43_wifi_scan_options_t opts = {0};
  // Passive scan: dwell on each channel and collect beacons, rather than the
  // default active scan that probes and misses APs that do not answer in the
  // brief per-channel window. The driver preserves scan_type (it overrides the
  // dwell times to firmware defaults, which cover a beacon interval).
  opts.scan_type = 1;
  if (cyw43_wifi_scan(&cyw43_state, &opts, NULL, scan_cb) != 0) {
    return false;
  }
  scanning = true;
  return true;
}

bool wifi_scan_again(void) {
  if (scanning) {
    return true;
  }
  // Another pass that accumulates into the existing results -- no reset, no
  // leave. One passive pass catches only a subset of beacons, so several passes
  // are unioned (deduping by SSID, keeping the strongest) into a complete list.
  cyw43_wifi_scan_options_t opts = {0};
  opts.scan_type = 1;
  if (cyw43_wifi_scan(&cyw43_state, &opts, NULL, scan_cb) != 0) {
    return false;
  }
  scanning = true;
  return true;
}

bool wifi_scan_in_progress(void) { return scanning; }

void wifi_scan_stop(void) { scanning = false; }

bool wifi_scan_poll(void) {
  if (scanning && !cyw43_wifi_scan_active(&cyw43_state)) {
    scanning = false;
    return true; // just completed
  }
  return false;
}

uint8_t wifi_scan_count(void) { return result_count; }

const wifi_scan_entry_t *wifi_scan_get(uint8_t i) {
  return i < result_count ? &results[i] : NULL;
}
