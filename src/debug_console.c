// CDC-ACM debug console. See debug_console.h.

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <tusb.h>

#include "debug_console.h"

// The debug console is the second CDC-ACM instance (the management console is 0).
#define DEBUG_ITF 1

static void put(const char *buf, size_t len) {
  size_t off = 0;
  for (int tries = 0; off < len && tries < 16; tries++) {
    uint32_t w = tud_cdc_n_write(DEBUG_ITF, buf + off, (uint32_t)(len - off));
    off += w;
    tud_cdc_n_write_flush(DEBUG_ITF);
  }
}

void debug_printf(const char *fmt, ...) {
  if (!tud_cdc_n_connected(DEBUG_ITF)) {
    return; // nothing attached: drop without formatting cost beyond the check
  }
  // Large enough for the worst-case line: the periodic stats line and the
  // RECOVERED report each approach ~260 bytes once their uint32 counters reach
  // full width. vsnprintf is bounded regardless (a longer line just truncates,
  // never overflows), but this keeps the whole line intact.
  char buf[320];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (n <= 0) {
    return;
  }
  // Expand bare LF to CRLF so a raw serial terminal renders lines cleanly.
  char out[384];
  size_t m = 0;
  for (const char *p = buf; *p && m < sizeof(out) - 2; p++) {
    if (*p == '\n') {
      out[m++] = '\r';
    }
    out[m++] = *p;
  }
  put(out, m);
}

void debug_console_task(void) {
  // Write-only channel: drain and discard any bytes the host sends so its TX
  // buffer never stalls.
  while (tud_cdc_n_available(DEBUG_ITF)) {
    uint8_t scratch[64];
    if (tud_cdc_n_read(DEBUG_ITF, scratch, sizeof(scratch)) == 0) {
      break;
    }
  }
}
