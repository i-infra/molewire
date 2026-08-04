// CDC-ACM management console. See serial_console.h.

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <hardware/watchdog.h> // disarm before entering the bootloader
#include <pico/bootrom.h>      // reset_usb_boot for the 1200-baud touch
#include <pico/cyw43_arch.h>   // lwIP lock for the protocol's lwIP/config reads
#include <tusb.h>

#include "config.h"
#include "config_proto.h"
#include "debug_console.h" // debug_console_line_state (shared CDC callback)
#include "serial_bridge.h" // line-coding pass-through for the bridge port
#include "serial_console.h"

// The CDC-ACM management console is the only CDC-ACM instance (the network
// class is a separate USB function), so it is always CDC index 0.
#define CONSOLE_ITF 0

// Arduino-style development convenience: opening a console CDC port at 1200
// baud reboots into the UF2 bootloader, so a new image can be flashed without
// touching the board ("stty -f /dev/cu.usbmodem* 1200", or picotool). The rate
// is otherwise meaningless on the console ports, so nothing legitimate
// collides. The serial-bridge port is exempt -- there the line coding is real
// (it retunes the physical UART, and 1200 baud is a legitimate target rate).
void tud_cdc_line_coding_cb(uint8_t itf, cdc_line_coding_t const *coding) {
  if (itf == SERIAL_BRIDGE_ITF) {
    serial_bridge_apply_coding(coding->bit_rate, coding->data_bits, coding->parity,
                               coding->stop_bits);
    return;
  }
  if (coding->bit_rate == 1200) {
    // The main-loop watchdog stays armed across reset_usb_boot and would fire
    // inside the bootloader (the bench firmware works without this only
    // because it runs no watchdog). Disarm before jumping.
    watchdog_disable();
    reset_usb_boot(0, 0);
  }
}

#ifndef FW_VERSION
#define FW_VERSION "0.0.0-dev"
#endif

static config_t *g_cfg;
static char line_buf[192];
static uint16_t line_len;
static bool was_connected; // DTR edge: greet once when a terminal attaches
static bool banner_sent;   // identification banner for this port-open session

// --- output -------------------------------------------------------------------

// Push raw bytes into the CDC TX FIFO, flushing to make room. A console reply is
// short and a terminal drains it promptly; if it still will not fit after a few
// flushes the surplus is dropped rather than block the main loop.
static void console_put(const char *buf, size_t len) {
  size_t off = 0;
  for (int tries = 0; off < len && tries < 16; tries++) {
    uint32_t w = tud_cdc_n_write(CONSOLE_ITF, buf + off, (uint32_t)(len - off));
    off += w;
    tud_cdc_n_write_flush(CONSOLE_ITF);
  }
}

// Emit a string to the console, expanding bare LF to CRLF so a raw serial
// terminal (picocom, screen) renders one line per line instead of stair-
// stepping. The protocol itself uses '\n' line endings.
static void console_emit(const char *s) {
  if (!tud_cdc_n_connected(CONSOLE_ITF)) {
    return;
  }
  char out[256];
  size_t n = 0;
  for (const char *p = s; *p; p++) {
    if (n >= sizeof(out) - 2) { // keep room for a possible CRLF pair
      console_put(out, n);
      n = 0;
    }
    if (*p == '\n') {
      out[n++] = '\r';
    }
    out[n++] = *p;
  }
  if (n) {
    console_put(out, n);
  }
}

static void console_io_write(void *ctx, const char *s) {
  (void)ctx;
  console_emit(s);
}

// Identification banner, pushed into the TX FIFO unconditionally -- even with
// DTR never asserted -- so any tool that opens the port (e.g. something
// probing serial devices for a GDB server) reads spontaneous ASCII on its
// first read and can classify this as not-its-protocol immediately, instead
// of seeing only its own bytes echoed back. Sent once per port-open session:
// on any control-line activity, or before the first echoed byte as fallback.
static void console_banner(void) {
  static const char banner[] =
      "\r\npico-wg-dongle " FW_VERSION " -- WireGuard USB dongle configuration console\r\n"
      "params: ssid pass country debug key peer psk endpoint addr hostip dns "
      "keepalive mtu routes apssid appass apaddr apclient ap (set <param> <val>); "
      "genkey pubkey pcap list use del scan save restore reboot bootsel; "
      "Enter for status\r\n";
  console_put(banner, sizeof(banner) - 1);
  banner_sent = true;
}

// Host opened/closed the port (SET_CONTROL_LINE_STATE). Identify ourselves on
// any opening activity; a fully dropped line state marks the session closed so
// the next opener is greeted again. The management console is CDC 0; the
// debug console (CDC 1) gets the same treatment in debug_console.c.
void tud_cdc_line_state_cb(uint8_t itf, bool dtr, bool rts) {
  if (itf != CONSOLE_ITF) {
    debug_console_line_state(itf, dtr, rts);
    return;
  }
  if (!dtr && !rts) {
    banner_sent = false;
  } else if (!banner_sent) {
    console_banner();
  }
}

// The interactive prompt, shown after each reply so the user has a cursor. The
// protocol chooses it (main vs scan menu), and returns "" to suppress it while a
// scan is running -- the prompt then reappears with the results.
static void console_prompt(void) {
  console_emit(config_proto_prompt());
}

void serial_console_print(const char *s) {
  console_emit(s);
}

void serial_console_printf(const char *fmt, ...) {
  char buf[200];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  console_emit(buf);
}

// --- task ---------------------------------------------------------------------

void serial_console_init(config_t *cfg) {
  g_cfg = cfg;
  line_len = 0;
  was_connected = false;
}

void serial_console_task(void) {
  // Greet a terminal on the rising edge of the connection (DTR asserted).
  bool connected = tud_cdc_n_connected(CONSOLE_ITF);
  if (connected && !was_connected) {
    cfg_io_t io = {.write = console_io_write, .ctx = NULL};
    config_proto_reset(); // a fresh terminal starts at the main menu
    cyw43_arch_lwip_begin(); // reads cyw43/lwIP link state
    config_proto_dump(&io, g_cfg);
    cyw43_arch_lwip_end();
    console_prompt();
    line_len = 0;
  } else if (!connected && was_connected) {
    // Terminal dropped: leave any scan/live mode so the device resumes normal
    // operation (and re-associates) without waiting for a key that cannot come.
    config_proto_reset();
    banner_sent = false;
  }
  was_connected = connected;

  // Fallback identification: bytes arriving on a session that never produced
  // control-line activity (a prober blind-writing its protocol) still get the
  // banner before anything is echoed.
  if (!banner_sent && tud_cdc_n_available(CONSOLE_ITF)) {
    console_banner();
  }

  // Drive a pending network scan: when it finishes, the protocol prints the
  // results and a new prompt. Runs under the lwIP lock like the command path,
  // but only while a scan is actually in flight -- otherwise the bridging hot
  // path takes no extra lock.
  if (connected && config_proto_scanning()) {
    cfg_io_t io = {.write = console_io_write, .ctx = NULL};
    cyw43_arch_lwip_begin();
    config_proto_poll(&io, g_cfg);
    cyw43_arch_lwip_end();
  }

  // Live (continuous) scan: any keypress stops it and returns to the scan
  // submenu. Consume the raw input here rather than letting it edit a line.
  if (config_proto_contscan_active()) {
    if (tud_cdc_n_available(CONSOLE_ITF)) {
      uint8_t scratch[64];
      while (tud_cdc_n_available(CONSOLE_ITF)) {
        tud_cdc_n_read(CONSOLE_ITF, scratch, sizeof(scratch));
      }
      cfg_io_t io = {.write = console_io_write, .ctx = NULL};
      cyw43_arch_lwip_begin();
      config_proto_contscan_stop(&io, g_cfg);
      cyw43_arch_lwip_end();
      console_prompt();
      line_len = 0;
    }
    return;
  }

  while (tud_cdc_n_available(CONSOLE_ITF)) {
    uint8_t ch;
    if (tud_cdc_n_read(CONSOLE_ITF, &ch, 1) != 1) {
      break;
    }
    if (ch == '\n' || ch == '\r') {
      // Accept CR, LF, or CRLF as the line terminator (a raw serial terminal
      // such as picocom sends CR on Enter). A bare Enter reprints the state.
      console_put("\r\n", 2); // echo the newline
      line_buf[line_len] = '\0';
      cfg_io_t io = {.write = console_io_write, .ctx = NULL};
      // The protocol reads lwIP/cyw43 state and may write flash, so run it
      // under the lwIP lock.
      cyw43_arch_lwip_begin();
      config_proto_handle_line(&io, line_buf, g_cfg);
      cyw43_arch_lwip_end();
      console_prompt();
      line_len = 0;
    } else if (ch == '\b' || ch == 0x7f) { // backspace / delete
      if (line_len > 0) {
        line_len--;
        console_put("\b \b", 3); // erase the character on the terminal
      }
    } else if (ch >= 0x20 && ch < 0x7f && line_len < sizeof(line_buf) - 1) {
      line_buf[line_len++] = (char)ch;
      console_put((const char *)&ch, 1); // echo so the terminal need not local-echo
    }
  }
}
