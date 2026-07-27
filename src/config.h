// Persistent device configuration.
//
// Holds the runtime-configurable settings (a list of saved Wi-Fi credential
// profiles plus regulatory country) in a single struct loaded from the last
// flash sector at boot and written back on demand. If flash holds no valid
// config (first boot, or a corrupted/old layout), the compile-time defaults from
// wifi_config.h are used.
//
// The bridge runs no IP of its own, so there is no addressing to configure --
// only what is needed to join the access point.

#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>
#include <stdint.h>

// "PWGD" marks this firmware's record layout (Wi-Fi profiles + WireGuard). Any
// other magic (including pico-usb-wifi's "PWF2") fails the check and falls back
// to defaults. No migration -- the device boots unprovisioned and is
// reconfigured once.
#define CONFIG_MAGIC 0x44475750u // "PWGD" (little-endian)
#define CONFIG_SSID_MAX 33 // 32 chars + NUL
#define CONFIG_PASS_MAX 64 // 63 chars + NUL
#define CONFIG_PROFILE_MAX 8 // saved credential sets (bounded by the flash sector)
#define CONFIG_ACTIVE_NONE 0xFFu // cfg->active when no profile is selected
#define CONFIG_WGKEY_MAX 46     // 44 base64 chars + NUL, rounded up
#define CONFIG_ENDPOINT_MAX 64  // WireGuard endpoint hostname or IPv4 literal

// WireGuard settings. Addresses are IPv4 in network byte order (as produced by
// ipaddr_aton), zero = unset. The device and host addresses are two tunnel
// addresses covered by the peer's AllowedIPs on the server; prefix is the mask
// length of the little USB-link subnet that contains them both (typically /30).
typedef struct {
  char private_key[CONFIG_WGKEY_MAX]; // this device's key, base64 ("" = unset)
  char peer_public[CONFIG_WGKEY_MAX]; // server's public key, base64
  char psk[CONFIG_WGKEY_MAX];         // optional preshared key ("" = none)
  char endpoint[CONFIG_ENDPOINT_MAX]; // server endpoint, IPv4 literal or hostname
  uint16_t endpoint_port;
  uint16_t keepalive;   // persistent-keepalive seconds, 0 = off
  uint16_t host_mtu;    // MTU handed to the host via DHCP; 0 = the WG MTU (1420).
                        // Set 1280 when the far side bridges into Tailscale.
  uint16_t _pad0;       // keep the u32 fields below aligned
  uint32_t addr;        // this device's tunnel address (USB-side gateway)
  uint32_t host_addr;   // the address DHCP leases to the USB host
  uint32_t dns;         // resolver handed to the host (reached through the tunnel)
  uint8_t prefix;       // USB-link subnet prefix length (e.g. 30)
  uint8_t _wgpad[3];
} wg_config_t;

// One saved network's credentials.
typedef struct {
  char ssid[CONFIG_SSID_MAX];
  char password[CONFIG_PASS_MAX]; // WPA2-PSK passphrase ("" = open network)
} wifi_profile_t;

// The full configuration record, kept in the last flash sector. A change to this
// layout just invalidates any record already in flash (the CRC/magic no longer
// match), and the compile-time defaults are used until the next SAVE -- there is
// no migration, by design.
typedef struct {
  uint32_t magic; // CONFIG_MAGIC

  uint8_t profile_count;  // number of valid entries in profiles[] (0..CONFIG_PROFILE_MAX)
  uint8_t active;         // index of the profile in use, or CONFIG_ACTIVE_NONE
  uint8_t debug_enabled;  // 1 = stream diagnostics on the second serial port
  uint8_t _pad;           // keep the following fields aligned
  uint32_t country;       // CYW43 country code (e.g. CYW43_COUNTRY_WORLDWIDE)
  wifi_profile_t profiles[CONFIG_PROFILE_MAX];
  wg_config_t wg;

  uint32_t crc32; // CRC-32 over every preceding byte of this struct; MUST be last
} config_t;

// True when every field required to bring the tunnel up is present.
bool config_wg_complete(const config_t *cfg);

// Fill cfg with the compile-time defaults (from wifi_config.h).
void config_defaults(config_t *cfg);

// Load cfg from flash. Falls back to config_defaults() if the stored record is
// absent, has the wrong magic, or fails its CRC.
void config_load(config_t *cfg);

// Compute the CRC and write cfg to the last flash sector. Returns false if the
// flash operation did not complete. Infrequent by design (a config change).
bool config_save(config_t *cfg);

// --- active-profile accessors (never NULL; "" when no profile is selected) ----

const char *config_active_ssid(const config_t *cfg);
const char *config_active_pass(const config_t *cfg);

// --- profile list operations --------------------------------------------------

// Index of the profile whose SSID matches, or -1 if none.
int config_find_profile(const config_t *cfg, const char *ssid);

// Append a profile {ssid, ""} and return its index, or -1 if the list is full.
int config_add_profile(config_t *cfg, const char *ssid);

// Remove profile i, shifting later entries down and fixing up `active`.
void config_del_profile(config_t *cfg, int i);

#endif // CONFIG_H
