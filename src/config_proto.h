// Runtime configuration control protocol, transport-agnostic.
//
// A small line protocol that reads and mutates the live config_t, applies
// changes immediately, and persists on demand. It is driven over the CDC-ACM
// management console (serial_console.c) via an output sink; the protocol never
// touches a USB endpoint directly.
//
// Up to CONFIG_PROFILE_MAX credential profiles are stored; one is "active" and
// the device associates with it. `set ssid`/`set pass` edit the active profile.
//
// Every command prints the full device state (settings + live status), so there
// is no separate "show" command. An empty line reprints it. Command words are
// case-insensitive; the console shows them in lower case.
//
// Main commands (one per line):
//   set ssid <text...>    set the active profile's SSID (applied immediately)
//   set pass <text...>    set the active profile's password, WPA2 (applied)
//   set country <CC|WORLDWIDE>   set the regulatory country
//   set debug <on|off>    stream diagnostics on the second serial port
//   set key <base64>      this device's WireGuard private key
//   set peer <base64>     the server's WireGuard public key
//   set psk <base64|off>  optional preshared key
//   set endpoint <host|ip> <port>   the WireGuard server endpoint
//   set addr <a.b.c.d/nn> device tunnel address + USB-link prefix (e.g. /30)
//   set hostip <a.b.c.d>  the tunnel address DHCP leases to the USB host
//   set dns <a.b.c.d>     resolver handed to the host (reached via the tunnel)
//   set keepalive <secs>  persistent keepalive (0 = off)
//   set mtu <bytes>       MTU handed to the host via DHCP (0 = WG default 1420;
//                         set 1280 when the server bridges into Tailscale)
//   set routes <cidr,...> split mode: host keeps its own default route; only
//                         these subnets (max 4) route via the dongle (opt 121)
//   set routes off        full-gateway mode: host default-routes through tunnel
//   set dns off           offer the host no resolver (keep its own DNS)
//   set apssid <text...>  quarantine AP's SSID
//   set appass <text...>  quarantine AP's WPA2 password (8-63 chars; no open AP)
//   set apaddr <a.b.c.d/nn>  device's AP-link address + prefix (e.g. /30)
//   set apclient <a.b.c.d>   the tunnel address DHCP leases to the AP client
//   set ap <on|off>       bring the quarantine AP up/down (needs the above set;
//                         the AP pair must be inside the server's AllowedIPs)
//   genkey [force]        generate the WireGuard keypair on-device (TRNG) and
//                         print ONLY the public key; force replaces an
//                         existing key (re-register with the server after)
//   pubkey                reprint the public key of the stored private key
//   pcap <on|off|clear>   toggle/clear the USB-link packet capture ring
//                         (download via the portal at /api/pcap)
//   list                  list the saved profiles
//   use <n>               make profile n active and re-associate
//   del <n>               delete profile n
//   scan                  scan for nearby networks (enters the scan submenu)
//   save                  persist the current settings to flash
//   restore               discard unsaved changes (reload the saved settings)
//   reboot                restart the firmware
//   bootsel               restart into the UF2 bootloader (reflash without
//                         touching the board; a 1200-baud CDC open does the same)
//
// Scan submenu (after scan, once results are listed):
//   join <n>              stage scanned network n as the active profile
//   scan                  scan again
//   live                  continuous scan: stream APs until any key (disassociated)
//   back                  return to the main menu

#ifndef CONFIG_PROTO_H
#define CONFIG_PROTO_H

#include <stddef.h> // size_t in config_proto_pubkey

#include "config.h"

// Output sink. write() emits a short, NUL-terminated string to the transport;
// the transport owns any buffering and flushing.
typedef struct {
  void (*write)(void *ctx, const char *s);
  void *ctx;
} cfg_io_t;

// Called after a command changes the live config, to apply it immediately (e.g.
// re-associate Wi-Fi). Registered once by the application.
typedef void (*config_apply_fn)(const config_t *cfg);
void config_proto_set_apply(config_apply_fn cb);

// Same, for WireGuard/addressing changes (re-address the USB link, restart the
// DHCP server, re-create the tunnel).
void config_proto_set_apply_wg(config_apply_fn cb);

// Same, for quarantine-AP changes (bring the AP up/down to match the config).
void config_proto_set_apply_ap(config_apply_fn cb);

// Process one complete line (without its newline). The buffer is mutated in
// place (tokenised). Call under the lwIP lock.
void config_proto_handle_line(const cfg_io_t *io, char *line, config_t *cfg);

// True while a scan is in flight and config_proto_poll() must be driven. Cheap
// and lock-free, so the console can avoid taking the cyw43 lock every tick.
bool config_proto_scanning(void);

// Drive a pending asynchronous scan: when results arrive, print the numbered
// list and the scan prompt. Call once per console tick (while
// config_proto_scanning() is true), under the lwIP lock.
void config_proto_poll(const cfg_io_t *io, config_t *cfg);

// The prompt for the current menu (main vs scan); "" while a scan is running.
const char *config_proto_prompt(void);

// Return to the main menu (e.g. when a fresh terminal attaches), dropping any
// scan in progress.
void config_proto_reset(void);

// True while the live (continuous) scan is streaming. The console turns any
// keypress into a stop; main uses it for the breathing LED and to hold off
// association.
bool config_proto_contscan_active(void);

// Stop the live scan and return to the scan submenu, printing the last results.
void config_proto_contscan_stop(const cfg_io_t *io, config_t *cfg);

// Print the full device state: settings plus live association and host address.
void config_proto_dump(const cfg_io_t *io, const config_t *cfg);

// Derive the public key of the stored private key, base64 into out (>= 45
// bytes). False if no key is set or it does not decode. (~14 ms of X25519.)
bool config_proto_pubkey(const config_t *cfg, char *out, size_t n);

#endif // CONFIG_PROTO_H
