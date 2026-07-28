// Persistent device configuration: flash-backed storage with compile-time
// defaults. See config.h.

#include <stddef.h>
#include <string.h>

#include <hardware/flash.h>
#include <pico/cyw43_arch.h> // for the CYW43_COUNTRY_* default
#include <pico/flash.h>

#include "config.h"
#include "wifi_config.h"

// Store the record near the end of flash, clear of the program image (which is
// linked from the start of flash and is far smaller than the device's flash).
// NOT the last sector: the RP2350 bootrom claims the final 256 bytes of flash
// as UF2-download scratch (erratum RP2350-E10), erasing that whole sector on
// every BOOTSEL drag-and-drop. Layout from the top of flash:
//   -1 sector: reserved (bootrom E10 scratch)
//   -2 sector: TAI64N boot counter (wg.c)
//   -3 sector: this config record
// XIP_BASE maps flash for reads; offsets are relative to flash.
#define CONFIG_FLASH_OFFSET (PICO_FLASH_SIZE_BYTES - 3 * FLASH_SECTOR_SIZE)

_Static_assert(sizeof(config_t) <= FLASH_SECTOR_SIZE,
               "config_t must fit in one flash sector");

// --- CRC-32 (IEEE 802.3, reflected) over the struct minus its own crc field ---

static uint32_t crc32(const void *data, size_t len) {
  const uint8_t *p = (const uint8_t *)data;
  uint32_t crc = 0xFFFFFFFFu;
  for (size_t i = 0; i < len; i++) {
    crc ^= p[i];
    for (int b = 0; b < 8; b++) {
      crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(crc & 1)));
    }
  }
  return crc ^ 0xFFFFFFFFu;
}

static uint32_t config_compute_crc(const config_t *cfg) {
  // CRC covers everything up to (but not including) the trailing crc32 field.
  return crc32(cfg, offsetof(config_t, crc32));
}

// --- defaults -----------------------------------------------------------------

void config_defaults(config_t *cfg) {
  memset(cfg, 0, sizeof(*cfg));
  cfg->magic = CONFIG_MAGIC;
  cfg->country = WIFI_COUNTRY;
  cfg->active = CONFIG_ACTIVE_NONE;

  // A baked compile-time SSID becomes the single active profile; left blank, the
  // device comes up unprovisioned and is configured over the console.
  if (WIFI_SSID[0]) {
    strncpy(cfg->profiles[0].ssid, WIFI_SSID, CONFIG_SSID_MAX - 1);
    strncpy(cfg->profiles[0].password, WIFI_PASSWORD, CONFIG_PASS_MAX - 1);
    cfg->profile_count = 1;
    cfg->active = 0;
  }

  cfg->crc32 = config_compute_crc(cfg);
}

// --- load ---------------------------------------------------------------------

void config_load(config_t *cfg) {
  const uint8_t *flash = (const uint8_t *)(XIP_BASE + CONFIG_FLASH_OFFSET);
  const config_t *stored = (const config_t *)flash;

  // Accept the record only on an exact match of magic and CRC. Any layout change
  // fails the CRC and falls back to defaults -- there is no migration.
  if (stored->magic == CONFIG_MAGIC) {
    uint32_t stored_crc;
    memcpy(&stored_crc, flash + offsetof(config_t, crc32), 4u);
    if (crc32(flash, offsetof(config_t, crc32)) == stored_crc) {
      memcpy(cfg, flash, sizeof(*cfg));
      return;
    }
  }
  config_defaults(cfg);
}

// --- save ---------------------------------------------------------------------

// Sector-sized buffer handed to the flash routine: config_t now spans several
// flash pages, so the whole sector is programmed in one shot (the erase is
// sector-wide regardless). Static so it does not sit on the stack while
// interrupts are disabled inside flash_safe_execute().
static uint8_t flash_buf[FLASH_SECTOR_SIZE];

static void config_flash_write(void *param) {
  (void)param;
  flash_range_erase(CONFIG_FLASH_OFFSET, FLASH_SECTOR_SIZE);
  flash_range_program(CONFIG_FLASH_OFFSET, flash_buf, FLASH_SECTOR_SIZE);
}

bool config_save(config_t *cfg) {
  cfg->magic = CONFIG_MAGIC;
  cfg->crc32 = config_compute_crc(cfg);

  memset(flash_buf, 0xFF, sizeof(flash_buf));
  memcpy(flash_buf, cfg, sizeof(config_t));

  // flash_safe_execute coordinates the erase/program against the other core and
  // disables interrupts for the duration (a few ms); the background Wi-Fi
  // context is paused meanwhile, which is acceptable for an infrequent save.
  return flash_safe_execute(config_flash_write, NULL, 1000) == PICO_OK;
}

// --- active-profile accessors -------------------------------------------------

static const wifi_profile_t *active_profile(const config_t *cfg) {
  if (cfg->active < cfg->profile_count) {
    return &cfg->profiles[cfg->active];
  }
  return NULL;
}

const char *config_active_ssid(const config_t *cfg) {
  const wifi_profile_t *p = active_profile(cfg);
  return p ? p->ssid : "";
}

const char *config_active_pass(const config_t *cfg) {
  const wifi_profile_t *p = active_profile(cfg);
  return p ? p->password : "";
}

bool config_wg_complete(const config_t *cfg) {
  const wg_config_t *w = &cfg->wg;
  return w->private_key[0] && w->peer_public[0] && w->endpoint[0] &&
         w->endpoint_port != 0 && w->addr != 0 && w->host_addr != 0 &&
         w->prefix >= 8 && w->prefix <= 30;
}

// --- profile list operations --------------------------------------------------

int config_find_profile(const config_t *cfg, const char *ssid) {
  for (int i = 0; i < cfg->profile_count; i++) {
    if (strncmp(cfg->profiles[i].ssid, ssid, CONFIG_SSID_MAX) == 0) {
      return i;
    }
  }
  return -1;
}

int config_add_profile(config_t *cfg, const char *ssid) {
  if (cfg->profile_count >= CONFIG_PROFILE_MAX) {
    return -1;
  }
  int i = cfg->profile_count++;
  memset(&cfg->profiles[i], 0, sizeof(cfg->profiles[i]));
  strncpy(cfg->profiles[i].ssid, ssid, CONFIG_SSID_MAX - 1);
  return i;
}

void config_del_profile(config_t *cfg, int i) {
  if (i < 0 || i >= cfg->profile_count) {
    return;
  }
  for (int j = i; j + 1 < cfg->profile_count; j++) {
    cfg->profiles[j] = cfg->profiles[j + 1];
  }
  cfg->profile_count--;
  // Keep `active` pointing at the same profile across the shift.
  if (cfg->active == (uint8_t)i || cfg->profile_count == 0) {
    cfg->active = cfg->profile_count ? 0 : CONFIG_ACTIVE_NONE;
  } else if (cfg->active != CONFIG_ACTIVE_NONE && cfg->active > (uint8_t)i) {
    cfg->active--;
  }
}
