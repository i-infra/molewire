// Asynchronous Wi-Fi network scan.
//
// The CYW43 scan returns results over a few seconds via a callback that fires in
// the background cyw43 context, so it cannot complete inside one synchronous
// console command. This module wraps it as a small state machine the main loop
// drives: start a scan, poll for completion, then read the collected results.
//
// All entry points touch cyw43 / the shared results buffer, so every call must
// be made with the cyw43 lock held (cyw43_arch_lwip_begin/end).

#ifndef WIFI_SCAN_H
#define WIFI_SCAN_H

#include <stdbool.h>
#include <stdint.h>

#include "config.h" // CONFIG_SSID_MAX

#define WIFI_SCAN_MAX 24 // most networks we keep (the strongest, if more are seen)

typedef struct {
  char ssid[CONFIG_SSID_MAX]; // NUL-terminated; hidden/empty SSIDs are skipped
  int16_t rssi;               // signal strength, dBm (higher is stronger)
  uint16_t channel;
  uint8_t bssid[6];
  uint8_t auth; // cyw43 auth_mode from the beacon; 0 = open, nonzero = secured
} wifi_scan_entry_t;

// Start a scan, clearing any previous results (no-op returning true if one is
// already running). Returns false if the scan could not be started.
bool wifi_scan_start(void);

// Start another pass that accumulates into the existing results (no reset).
// Unioning several passes builds a complete list, since one passive pass catches
// only a subset of the beacons present.
bool wifi_scan_again(void);

// True while a scan is in progress (results not yet ready).
bool wifi_scan_in_progress(void);

// Drop the in-progress latch when leaving a scan mode, so wifi_scan_in_progress()
// reports false and association can resume. A cyw43 scan still running finishes
// on its own; its late results are simply ignored.
void wifi_scan_stop(void);

// Drive an in-progress scan; returns true exactly once -- on the tick the scan
// has just finished and the results are ready to read.
bool wifi_scan_poll(void);

// Number of collected results, and accessor (returns NULL if i is out of range).
uint8_t wifi_scan_count(void);
const wifi_scan_entry_t *wifi_scan_get(uint8_t i);

#endif // WIFI_SCAN_H
