// Wi-Fi connection manager: keeps the station uplink associated to whichever
// saved network is actually in range.
//
// Replaces the old fixed-profile retry loop. When the link is down it scans,
// intersects the results with the saved profiles, and tries candidates in
// wifi_pick order (strongest first, sticky toward the last-good network, one
// blind attempt per cycle for hidden SSIDs). Attempt outcomes are tracked per
// profile (RAM only) so a wrong password is skipped instead of hammered, and
// surfaced to the console/portal UIs. A successful join moves the profile to
// the front of the MRU-ordered list and -- when the join proved credentials
// that flash doesn't hold yet -- auto-saves, so a network joined once from the
// scan picker is remembered without an explicit `save`.

#ifndef WIFI_CONN_H
#define WIFI_CONN_H

#include <stdbool.h>
#include <stdint.h>

#include "config.h"
#include "wifi_pick.h"

// Take ownership of station association (call once, after cyw43 STA mode is
// up). Kicks off the boot-time join: the active profile directly if one is
// set, else a scan cycle.
void wifi_conn_init(config_t *cfg);

// Drive the state machine. Main loop; cheap (internally rate-limited).
void wifi_conn_task(uint32_t now_ms);

// Wi-Fi config changed (set ssid/pass/country, use, join, del, restore):
// re-pin to the active profile and try it now; falls back to the normal scan
// cycle if that fails. Also resets per-profile statuses -- an edit or an
// explicit selection is the user asking for a fresh attempt.
void wifi_conn_apply(const config_t *cfg);

// The joined profile's credentials are not yet saved to flash: auto-save once
// the join succeeds. Set by the config protocol when a join/set stages new
// credentials; cleared by the save that it triggers (or an explicit SAVE,
// which reports in via wifi_conn_note_saved).
void wifi_conn_mark_creds_unsaved(void);
void wifi_conn_note_saved(void);

// UI-requested background scan (portal "scan" button). Runs even while
// associated -- the radio goes briefly off-channel; an established link
// survives. Results land in wifi_scan and refresh the per-profile RSSIs.
void wifi_conn_request_scan(void);

// True while a manager-driven scan is collecting passes.
bool wifi_conn_scanning(void);

// Milliseconds since the last completed scan, UINT32_MAX if none yet.
uint32_t wifi_conn_scan_age_ms(void);

// Manager state for status displays: "up", "joining", "scanning", "backoff",
// or "idle" (no profiles to try).
const char *wifi_conn_state_str(void);

// Per-profile runtime state for the UIs (i out of range: UNTRIED/UNSEEN).
wifi_prof_status_t wifi_conn_prof_status(uint8_t i);
int16_t wifi_conn_prof_rssi(uint8_t i);

#endif // WIFI_CONN_H
