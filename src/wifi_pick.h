// Candidate ordering for the Wi-Fi connection manager: given the saved
// profiles' runtime state (latest-scan RSSI, attempt outcomes), decide which
// profiles to try this cycle and in what order.
//
// Pure logic with no SDK dependencies, split out of wifi_conn.c so the host
// tests (tests/test_main.c) exercise it directly.

#ifndef WIFI_PICK_H
#define WIFI_PICK_H

#include <stdint.h>

#include "config.h" // CONFIG_PROFILE_MAX

// Per-profile runtime status. RAM only -- parallel to cfg->profiles, never
// persisted, reset whenever the profile list is edited.
typedef enum {
  WIFI_PROF_UNTRIED = 0, // no attempt since boot / list edit / status decay
  WIFI_PROF_CONNECTED,   // currently associated (at most one profile)
  WIFI_PROF_NOJOIN,      // last attempt timed out or failed short of auth
  WIFI_PROF_BADPASS,     // authentication rejected: excluded from auto-join
                         // until the decay timer or a credential edit clears it
} wifi_prof_status_t;

#define WIFI_RSSI_UNSEEN INT16_MIN // profile's SSID was not in the latest scan

typedef struct {
  int16_t rssi;   // latest-scan RSSI, or WIFI_RSSI_UNSEEN
  uint8_t status; // wifi_prof_status_t
} wifi_prof_state_t;

// The active (last-good / last-chosen) profile beats a stronger network within
// this many dB, so a marginal signal difference doesn't flap the choice away
// from the network that is known to work.
#define WIFI_PICK_ACTIVE_BONUS_DB 10

// Build the order profiles are tried in this cycle:
//   1. profiles seen in the latest scan (excluding BADPASS), strongest first,
//      with `active` given WIFI_PICK_ACTIVE_BONUS_DB; ties keep list order
//      (which is most-recently-used order);
//   2. then at most ONE unseen non-BADPASS profile, rotating by rr_unseen
//      across cycles -- so hidden-SSID networks still get a periodic attempt
//      without a full cycle costing 8 blind join timeouts.
// Returns the number of indices written to out[].
uint8_t wifi_pick_order(const wifi_prof_state_t *st, uint8_t count, uint8_t active,
                        uint8_t rr_unseen, uint8_t out[CONFIG_PROFILE_MAX]);

#endif // WIFI_PICK_H
