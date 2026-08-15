// Candidate ordering for the Wi-Fi connection manager. See wifi_pick.h.

#include "wifi_pick.h"

uint8_t wifi_pick_order(const wifi_prof_state_t *st, uint8_t count, uint8_t active,
                        uint8_t rr_unseen, uint8_t out[CONFIG_PROFILE_MAX]) {
  if (count > CONFIG_PROFILE_MAX) {
    count = CONFIG_PROFILE_MAX;
  }
  uint8_t n = 0;
  int32_t score[CONFIG_PROFILE_MAX];

  // Seen, non-BADPASS profiles by descending score. Insertion keeps equal
  // scores in list order (most-recently-used first).
  for (uint8_t i = 0; i < count; i++) {
    if (st[i].rssi == WIFI_RSSI_UNSEEN || st[i].status == WIFI_PROF_BADPASS) {
      continue;
    }
    int32_t s = (int32_t)st[i].rssi + (i == active ? WIFI_PICK_ACTIVE_BONUS_DB : 0);
    uint8_t j = n;
    while (j > 0 && score[j - 1] < s) {
      out[j] = out[j - 1];
      score[j] = score[j - 1];
      j--;
    }
    out[j] = i;
    score[j] = s;
    n++;
  }

  // One unseen profile per cycle, rotating: hidden networks don't beacon their
  // SSID, so a profile absent from the scan may still be joinable.
  for (uint8_t k = 0; k < count; k++) {
    uint8_t i = (uint8_t)((rr_unseen + k) % count);
    if (st[i].rssi == WIFI_RSSI_UNSEEN && st[i].status != WIFI_PROF_BADPASS) {
      out[n++] = i;
      break;
    }
  }
  return n;
}
