// HTTP configuration/status portal, served on the USB link only.
//
// A tiny raw-TCP HTTP server (port 80, v4 + v6) with three endpoints:
//   GET  /            the embedded single-file SPA (gzipped in flash)
//   GET  /api/status  live device state as JSON
//   POST /api/cmd     one console-protocol line (config_proto), text reply
//
// The SPA talks plain HTTP to the device that served it, so it works in every
// browser with no WebSerial and no secure-context requirement. Connections
// arriving on any netif other than the USB link (e.g. from the tunnel side)
// are refused, keeping the portal exactly as local as the serial console.

#ifndef HTTP_PORTAL_H
#define HTTP_PORTAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"

// Start listening. cfg is the live config (owned by main), mutated by
// /api/cmd exactly as the serial console would.
void http_portal_init(config_t *cfg);

#ifdef __cplusplus
}
#endif

#endif // HTTP_PORTAL_H
