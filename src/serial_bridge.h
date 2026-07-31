// Serial party line: one byte stream with three endpoints -- the third
// CDC-ACM port on the USB host, hardware UART1 (GP4 TX / GP5 RX), and a TCP
// socket reachable at the device's addresses from the WireGuard side (and
// the USB link, for loopback testing): :2323 raw, :3323 telnet/RFC 2217
// (remote baud/format/DTR/RTS control; DTR -> GP7, RTS -> GP6, asserted =
// low, for esptool-style target reset). Bytes arriving at any endpoint fan
// out to the other two, so the dongle doubles as a network serial adapter:
// wire GP4/GP5 to a target's console and both the USB host and any tunnel
// peer can talk to it; with the pins unwired it is a host<->VPN out-of-band
// serial channel.
//
// Flow control: a transfer happens only when every *active* sink can take a
// byte (absent sinks -- no TCP client, host port closed -- drop instead of
// stalling the line). The physical UART's baud/format follows the host's CDC
// line coding, so `stty` on the host retunes the pins; default 115200 8N1.

#ifndef SERIAL_BRIDGE_H
#define SERIAL_BRIDGE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

// The bridge is CDC instance 2 (management console 0, debug 1). The 1200-baud
// bootloader touch is disabled on this instance -- 1200 baud is a legitimate
// rate for a real serial target.
#define SERIAL_BRIDGE_ITF 2

struct cdc_line_coding_t;

// Bring up UART1 and the TCP listener. Call after lwIP is initialised.
void serial_bridge_init(void);

// Pump all three directions. Main loop only; bounded work per call.
void serial_bridge_task(void);

// Apply the host's CDC line coding to the physical UART (from the shared
// tud_cdc_line_coding_cb in serial_console.c).
void serial_bridge_apply_coding(uint32_t bit_rate, uint8_t data_bits, uint8_t parity,
                                uint8_t stop_bits);

// For status displays.
bool serial_bridge_client_connected(void);
uint32_t serial_bridge_baud(void);

#ifdef __cplusplus
}
#endif

#endif // SERIAL_BRIDGE_H
