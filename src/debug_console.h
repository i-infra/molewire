// CDC-ACM debug console: a write-only diagnostics stream on a second serial
// port (e.g. /dev/ttyACM1), separate from the management console so diagnostics
// never interfere with it. Output is produced only when enabled (SET debug on)
// and a terminal is attached, so it costs nothing in the common case.

#ifndef DEBUG_CONSOLE_H
#define DEBUG_CONSOLE_H

#include <stdbool.h>

// Service the debug port (drain and discard any input). Main loop only.
void debug_console_task(void);

// Emit a diagnostics line if a terminal is attached. The caller gates on the
// `debug` setting so nothing is formatted when diagnostics are off.
void debug_printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#endif // DEBUG_CONSOLE_H
