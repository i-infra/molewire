// CDC-ACM management console: the out-of-band control plane.
//
// Drives the runtime configuration protocol (config_proto.h) over the device's
// second USB function, a CDC-ACM serial port (e.g. /dev/ttyACM0). Unlike the
// network-side TCP channel, this is reachable the instant USB enumerates --
// before Wi-Fi is up and without any IP on the network side -- so the device
// can always be provisioned and observed. Diagnostics are printed here too.

#ifndef SERIAL_CONSOLE_H
#define SERIAL_CONSOLE_H

#include "config.h"

// Register the live config. cfg must outlive the console.
void serial_console_init(config_t *cfg);

// Pump the console: drain received bytes, run completed command lines, and
// greet a newly attached terminal. Call once per main-loop iteration, from the
// main loop only (TinyUSB is not safe off the main loop).
void serial_console_task(void);

// Emit a line of diagnostics/status to the console (no-op if nothing attached).
void serial_console_print(const char *s);
void serial_console_printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#endif // SERIAL_CONSOLE_H
