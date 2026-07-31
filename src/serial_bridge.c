// Serial party line: CDC-ACM <-> UART1 <-> TCP. See serial_bridge.h.
//
// Two TCP listeners feed the same single-client line: :2323 is a raw byte
// stream (nc-friendly, binary-clean), :3323 speaks telnet + RFC 2217
// (COM-PORT-CONTROL), so pyserial's rfc2217:// URLs -- and therefore esptool
// -- can set the UART baud/format and toggle DTR/RTS remotely. DTR/RTS map
// to GPIOs for target reset: GP6 follows RTS and GP7 follows DTR (asserted =
// driven low), which with GP6 -> EN and GP7 -> IO0 reproduces esptool's
// auto-reset-into-bootloader sequence on a directly-wired ESP32.
//
// Context model: the TCP callbacks run wherever tunnel input is processed
// (the cyw43 background context), so they only touch the pcb and the held
// pbuf chain. All byte movement -- including every CDC and UART access and
// all telnet protocol replies -- happens in serial_bridge_task() in the main
// loop, under the lwIP lock, which also excludes the background context.

#include <stdio.h>
#include <string.h>

#include <hardware/gpio.h>
#include <hardware/uart.h>
#include <lwip/ip.h> // ip_current_netif() for the accept-side netif check
#include <lwip/tcp.h>
#include <pico/cyw43_arch.h>
#include <tusb.h>

#include "serial_bridge.h"
#include "usb_net.h"
#include "wg.h"

#define BRIDGE_UART uart1
#define BRIDGE_UART_TX_PIN 4
#define BRIDGE_UART_RX_PIN 5
#define BRIDGE_RTS_PIN 6 // follows RFC2217 RTS; wire to ESP32 EN
#define BRIDGE_DTR_PIN 7 // follows RFC2217 DTR; wire to ESP32 IO0
#define BRIDGE_TCP_RAW_PORT 2323
#define BRIDGE_TCP_2217_PORT 3323
#define TICK_BYTE_BUDGET 128 // per-direction bound so the pump never hogs a tick

static struct tcp_pcb *client;
static struct pbuf *rx;     // unconsumed TCP->line data; TCP window stays
static uint16_t rx_off;     // closed for it until it drains (tcp_recved)
static bool telnet_mode;    // client came in via the RFC 2217 port

static uint32_t cur_baud = 115200;
static uint8_t cur_databits = 8;
static uint8_t cur_stop = 1;
static uart_parity_t cur_parity = UART_PARITY_NONE;

static void apply_format(void) {
  uart_set_format(BRIDGE_UART, cur_databits, cur_stop, cur_parity);
}

// --- telnet / RFC 2217 ----------------------------------------------------------

#define TN_IAC 255
#define TN_DONT 254
#define TN_DO 253
#define TN_WONT 252
#define TN_WILL 251
#define TN_SB 250
#define TN_SE 240
#define TNOPT_BINARY 0
#define TNOPT_SGA 3
#define TNOPT_COMPORT 44

enum { T_DATA, T_IAC, T_VERB, T_SB, T_SB_IAC };
static uint8_t tn_state;
static uint8_t tn_verb;
static uint8_t sb_buf[24]; // option byte + longest subneg (SET_BAUDRATE: 5)
static uint8_t sb_len;
static bool comport_active;

// Tiny protocol replies; sndbuf pressure just drops them (the peer retries).
static void tn_send(const uint8_t *d, uint16_t n) {
  if (client) {
    tcp_write(client, d, n, TCP_WRITE_FLAG_COPY);
  }
}

// COM-PORT response: IAC SB 44 <cmd+100> <payload, IAC-escaped> IAC SE.
static void tn_comport_ack(uint8_t cmd, const uint8_t *payload, uint8_t n) {
  uint8_t buf[24];
  uint8_t w = 0;
  buf[w++] = TN_IAC;
  buf[w++] = TN_SB;
  buf[w++] = TNOPT_COMPORT;
  buf[w++] = (uint8_t)(cmd + 100);
  for (uint8_t i = 0; i < n && w < sizeof(buf) - 3; i++) {
    if (payload[i] == TN_IAC) {
      buf[w++] = TN_IAC;
    }
    buf[w++] = payload[i];
  }
  buf[w++] = TN_IAC;
  buf[w++] = TN_SE;
  tn_send(buf, w);
}

static void tn_handle_verb(uint8_t verb, uint8_t opt) {
  bool ok = (opt == TNOPT_BINARY || opt == TNOPT_SGA || opt == TNOPT_COMPORT);
  if (verb == TN_WILL) {
    uint8_t r[3] = {TN_IAC, ok ? TN_DO : TN_DONT, opt};
    tn_send(r, 3);
  } else if (verb == TN_DO) {
    uint8_t r[3] = {TN_IAC, ok ? TN_WILL : TN_WONT, opt};
    tn_send(r, 3);
  } // WONT/DONT need no reply
  if (ok && opt == TNOPT_COMPORT && !comport_active) {
    comport_active = true;
    // Unsolicited NOTIFY_MODEMSTATE (DSR|CTS): some clients wait for one.
    uint8_t ms = 0x30;
    tn_comport_ack(7, &ms, 1); // 7+100 = 107 NOTIFY_MODEMSTATE
  }
}

static void tn_handle_sb(void) {
  if (sb_len < 2 || sb_buf[0] != TNOPT_COMPORT) {
    return; // not COM-PORT-CONTROL: ignore
  }
  uint8_t cmd = sb_buf[1];
  const uint8_t *pl = sb_buf + 2;
  uint8_t pln = (uint8_t)(sb_len - 2);
  switch (cmd) {
    case 1: { // SET_BAUDRATE, 4 bytes BE; 0 = query
      if (pln >= 4) {
        uint32_t want = ((uint32_t)pl[0] << 24) | ((uint32_t)pl[1] << 16) |
                        ((uint32_t)pl[2] << 8) | pl[3];
        if (want >= 300 && want <= 1500000) {
          // Track (and ack) the REQUESTED rate, not the achieved divisor
          // rate: pyserial rejects any ack that isn't a byte-exact echo.
          uart_set_baudrate(BRIDGE_UART, want);
          cur_baud = want;
        }
      }
      uint8_t out[4] = {(uint8_t)(cur_baud >> 24), (uint8_t)(cur_baud >> 16),
                        (uint8_t)(cur_baud >> 8), (uint8_t)cur_baud};
      tn_comport_ack(cmd, out, 4);
      break;
    }
    case 2: { // SET_DATASIZE; 0 = query
      if (pln >= 1 && pl[0] >= 5 && pl[0] <= 8) {
        cur_databits = pl[0];
        apply_format();
      }
      tn_comport_ack(cmd, &cur_databits, 1);
      break;
    }
    case 3: { // SET_PARITY: 1 none, 2 odd, 3 even (mark/space unsupported)
      if (pln >= 1 && pl[0] >= 1 && pl[0] <= 3) {
        cur_parity = (pl[0] == 2) ? UART_PARITY_ODD
                     : (pl[0] == 3) ? UART_PARITY_EVEN
                                    : UART_PARITY_NONE;
        apply_format();
      }
      uint8_t v = (cur_parity == UART_PARITY_ODD) ? 2 : (cur_parity == UART_PARITY_EVEN) ? 3 : 1;
      tn_comport_ack(cmd, &v, 1);
      break;
    }
    case 4: { // SET_STOPSIZE: 1 or 2 (1.5 maps to 1)
      if (pln >= 1 && (pl[0] == 1 || pl[0] == 2)) {
        cur_stop = pl[0];
        apply_format();
      }
      tn_comport_ack(cmd, &cur_stop, 1);
      break;
    }
    case 5: { // SET_CONTROL: DTR/RTS drive the reset GPIOs (asserted = low)
      if (pln >= 1) {
        switch (pl[0]) {
          case 8: gpio_put(BRIDGE_DTR_PIN, 0); break;  // DTR on
          case 9: gpio_put(BRIDGE_DTR_PIN, 1); break;  // DTR off
          case 11: gpio_put(BRIDGE_RTS_PIN, 0); break; // RTS on
          case 12: gpio_put(BRIDGE_RTS_PIN, 1); break; // RTS off
          default: break; // flow-control requests: nothing to do
        }
        tn_comport_ack(cmd, pl, 1);
      }
      break;
    }
    default: // PURGE_DATA, masks, ...: acknowledge so clients don't stall
      tn_comport_ack(cmd, pl, pln);
      break;
  }
}

// Feed one TCP byte through the telnet layer. Returns true if *out is a data
// byte for the party line.
static bool tn_process(uint8_t b, uint8_t *out) {
  switch (tn_state) {
    case T_DATA:
      if (b == TN_IAC) {
        tn_state = T_IAC;
        return false;
      }
      *out = b;
      return true;
    case T_IAC:
      if (b == TN_IAC) { // escaped literal 0xFF
        tn_state = T_DATA;
        *out = b;
        return true;
      }
      if (b == TN_SB) {
        tn_state = T_SB;
        sb_len = 0;
        return false;
      }
      if (b >= TN_WILL && b <= TN_DONT) {
        tn_verb = b;
        tn_state = T_VERB;
        return false;
      }
      tn_state = T_DATA; // NOP/other command: swallow
      return false;
    case T_VERB:
      tn_handle_verb(tn_verb, b);
      tn_state = T_DATA;
      return false;
    case T_SB:
      if (b == TN_IAC) {
        tn_state = T_SB_IAC;
      } else if (sb_len < sizeof(sb_buf)) {
        sb_buf[sb_len++] = b;
      }
      return false;
    case T_SB_IAC:
      if (b == TN_IAC) { // escaped 0xFF inside subnegotiation
        if (sb_len < sizeof(sb_buf)) {
          sb_buf[sb_len++] = TN_IAC;
        }
        tn_state = T_SB;
      } else { // IAC SE (or anything) ends the subnegotiation
        tn_handle_sb();
        tn_state = T_DATA;
      }
      return false;
  }
  return false;
}

// True when the next TCP byte would be party-line data (vs telnet protocol),
// decided WITHOUT consuming it -- protocol bytes must flow even when the
// line's sinks are full.
static bool tn_next_is_data(uint8_t b) {
  if (!telnet_mode) {
    return true;
  }
  return (tn_state == T_DATA && b != TN_IAC) || (tn_state == T_IAC && b == TN_IAC);
}

// --- endpoints ------------------------------------------------------------------

enum { SRC_UART, SRC_CDC, SRC_TCP };

// A byte may move only if every *active* sink other than the source can take
// it. Inactive sinks (no TCP client, host port closed) drop instead of
// stalling the line. The TCP sink needs 2 bytes: 0xFF escapes to IAC IAC.
static bool sinks_ready(int src) {
  if (src != SRC_CDC && tud_cdc_n_connected(SERIAL_BRIDGE_ITF) &&
      tud_cdc_n_write_available(SERIAL_BRIDGE_ITF) == 0) {
    return false;
  }
  if (src != SRC_TCP && client && tcp_sndbuf(client) < 2) {
    return false;
  }
  if (src != SRC_UART && !uart_is_writable(BRIDGE_UART)) {
    return false;
  }
  return true;
}

static void fan_out(int src, uint8_t b) {
  if (src != SRC_CDC && tud_cdc_n_connected(SERIAL_BRIDGE_ITF)) {
    tud_cdc_n_write(SERIAL_BRIDGE_ITF, &b, 1);
  }
  if (src != SRC_TCP && client) {
    // Byte-wise, but tcp_write coalesces into the current unsent segment;
    // tcp_output once per tick sends it. Serial rates make this cheap.
    if (telnet_mode && b == TN_IAC) {
      static const uint8_t esc[2] = {TN_IAC, TN_IAC};
      tcp_write(client, esc, 2, TCP_WRITE_FLAG_COPY);
    } else {
      tcp_write(client, &b, 1, TCP_WRITE_FLAG_COPY);
    }
  }
  if (src != SRC_UART) {
    uart_putc_raw(BRIDGE_UART, (char)b); // sinks_ready guaranteed writable
  }
}

// --- TCP side -------------------------------------------------------------------

static void tcp_drop_client(bool do_abort) {
  if (rx) {
    pbuf_free(rx);
    rx = NULL;
    rx_off = 0;
  }
  // Release the reset lines so a wired target isn't held in reset/bootloader.
  gpio_put(BRIDGE_DTR_PIN, 1);
  gpio_put(BRIDGE_RTS_PIN, 1);
  telnet_mode = false;
  comport_active = false;
  tn_state = T_DATA;
  if (client) {
    struct tcp_pcb *pcb = client;
    client = NULL;
    tcp_arg(pcb, NULL);
    tcp_recv(pcb, NULL);
    tcp_err(pcb, NULL);
    if (do_abort) {
      tcp_abort(pcb);
    } else if (tcp_close(pcb) != ERR_OK) {
      tcp_abort(pcb);
    }
  }
}

static err_t bridge_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
  (void)arg;
  (void)err;
  if (!p) { // remote closed: drop our side (any undrained bytes go with it)
    if (pcb == client) {
      tcp_drop_client(false);
    } else {
      tcp_close(pcb);
    }
    return ERR_OK;
  }
  if (pcb != client) {
    pbuf_free(p);
    return ERR_OK;
  }
  // Hold the chain; the pump consumes it and opens the window as it drains.
  if (rx) {
    pbuf_cat(rx, p);
  } else {
    rx = p;
    rx_off = 0;
  }
  return ERR_OK;
}

static void bridge_err(void *arg, err_t err) {
  (void)arg;
  (void)err;
  client = NULL; // pcb already freed by lwIP
  if (rx) {
    pbuf_free(rx);
    rx = NULL;
    rx_off = 0;
  }
  gpio_put(BRIDGE_DTR_PIN, 1);
  gpio_put(BRIDGE_RTS_PIN, 1);
  telnet_mode = false;
  comport_active = false;
  tn_state = T_DATA;
}

static err_t bridge_accept(void *arg, struct tcp_pcb *newpcb, err_t err) {
  if (err != ERR_OK || !newpcb) {
    return ERR_VAL;
  }
  // Reachable from the WireGuard side (the point) and the USB link (loopback
  // testing) -- never from Wi-Fi, where the STA address would otherwise
  // expose the line to the upstream LAN.
  struct netif *in = ip_current_netif();
  if (in != usb_net_netif() && in != wg_active_netif()) {
    tcp_abort(newpcb);
    return ERR_ABRT;
  }
  if (client) { // single line, single client (either port)
    tcp_abort(newpcb);
    return ERR_ABRT;
  }
  client = newpcb;
  telnet_mode = (arg != NULL); // listener arg marks the RFC 2217 port
  comport_active = false;
  tn_state = T_DATA;
  tcp_recv(newpcb, bridge_recv);
  tcp_err(newpcb, bridge_err);
  // Reap dead peers (roamed tailnet clients) so they can't hold the one slot:
  // idle 30 s, then 4 probes 5 s apart.
  ip_set_option(newpcb, SOF_KEEPALIVE);
  newpcb->keep_idle = 30000;
  newpcb->keep_intvl = 5000;
  newpcb->keep_cnt = 4;
  return ERR_OK;
}

static void bridge_listen(uint16_t port, void *accept_arg) {
  struct tcp_pcb *l = tcp_new_ip_type(IPADDR_TYPE_ANY);
  if (!l || tcp_bind(l, IP_ANY_TYPE, port) != ERR_OK) {
    if (l) tcp_abort(l);
    printf("serial_bridge: bind :%u failed\n", port);
    return;
  }
  // tcp_listen allocates from MEMP_TCP_PCB_LISTEN and returns NULL (leaving
  // the bound pcb) if that pool is exhausted -- size it for every listener.
  struct tcp_pcb *ll = tcp_listen_with_backlog(l, 1);
  if (!ll) {
    tcp_abort(l);
    printf("serial_bridge: listen :%u failed (MEMP_TCP_PCB_LISTEN)\n", port);
    return;
  }
  tcp_arg(ll, accept_arg);
  tcp_accept(ll, bridge_accept);
}

// --- public ---------------------------------------------------------------------

void serial_bridge_init(void) {
  uart_init(BRIDGE_UART, cur_baud);
  gpio_set_function(BRIDGE_UART_TX_PIN, GPIO_FUNC_UART);
  gpio_set_function(BRIDGE_UART_RX_PIN, GPIO_FUNC_UART);
  uart_set_hw_flow(BRIDGE_UART, false, false);
  uart_set_fifo_enabled(BRIDGE_UART, true);
  // Reset lines idle high (deasserted).
  gpio_init(BRIDGE_DTR_PIN);
  gpio_init(BRIDGE_RTS_PIN);
  gpio_put(BRIDGE_DTR_PIN, 1);
  gpio_put(BRIDGE_RTS_PIN, 1);
  gpio_set_dir(BRIDGE_DTR_PIN, GPIO_OUT);
  gpio_set_dir(BRIDGE_RTS_PIN, GPIO_OUT);

  cyw43_arch_lwip_begin();
  bridge_listen(BRIDGE_TCP_RAW_PORT, NULL);
  bridge_listen(BRIDGE_TCP_2217_PORT, (void *)1);
  cyw43_arch_lwip_end();
}

void serial_bridge_apply_coding(uint32_t bit_rate, uint8_t data_bits, uint8_t parity,
                                uint8_t stop_bits) {
  if (bit_rate < 300 || bit_rate > 1500000) {
    return; // out of UART range; keep the current rate
  }
  uart_set_baudrate(BRIDGE_UART, bit_rate);
  cur_baud = bit_rate; // requested rate, matching the RFC2217 echo policy
  // CDC encoding: parity 0/1/2 = none/odd/even; stop 0/1/2 = 1/1.5/2 bits.
  cur_parity = (parity == 1) ? UART_PARITY_ODD
               : (parity == 2) ? UART_PARITY_EVEN
                               : UART_PARITY_NONE;
  cur_databits = (data_bits >= 5 && data_bits <= 8) ? data_bits : 8;
  cur_stop = (stop_bits == 2) ? 2 : 1;
  apply_format();
}

bool serial_bridge_client_connected(void) { return client != NULL; }
uint32_t serial_bridge_baud(void) { return cur_baud; }

void serial_bridge_task(void) {
  // Fast path: nothing pending on any endpoint (racy reads are fine -- a
  // missed byte is picked up next tick).
  if (!uart_is_readable(BRIDGE_UART) && !tud_cdc_n_available(SERIAL_BRIDGE_ITF) &&
      rx == NULL) {
    return;
  }

  cyw43_arch_lwip_begin();

  int budget = TICK_BYTE_BUDGET;
  while (budget > 0 && uart_is_readable(BRIDGE_UART) && sinks_ready(SRC_UART)) {
    fan_out(SRC_UART, (uint8_t)uart_getc(BRIDGE_UART));
    budget--;
  }

  budget = TICK_BYTE_BUDGET;
  while (budget > 0 && tud_cdc_n_available(SERIAL_BRIDGE_ITF) && sinks_ready(SRC_CDC)) {
    uint8_t b;
    if (tud_cdc_n_read(SERIAL_BRIDGE_ITF, &b, 1) != 1) {
      break;
    }
    fan_out(SRC_CDC, b);
    budget--;
  }

  budget = TICK_BYTE_BUDGET;
  uint16_t consumed = 0;
  while (budget > 0 && rx) {
    uint8_t b = ((const uint8_t *)rx->payload)[rx_off];
    // Telnet protocol bytes flow regardless; data bytes wait for the sinks.
    if (tn_next_is_data(b) && !sinks_ready(SRC_TCP)) {
      break;
    }
    rx_off++;
    consumed++;
    budget--;
    uint8_t data;
    if (!telnet_mode) {
      fan_out(SRC_TCP, b);
    } else if (tn_process(b, &data)) {
      fan_out(SRC_TCP, data);
    }
    if (rx_off == rx->len) { // this pbuf fully drained: step to the next
      struct pbuf *next = rx->next;
      if (next) {
        pbuf_ref(next); // keep the tail alive across freeing the head
      }
      pbuf_free(rx);
      rx = next;
      rx_off = 0;
    }
  }
  if (consumed && client) {
    tcp_recved(client, consumed); // reopen the receive window as bytes drain
  }

  if (client) {
    tcp_output(client);
  }
  tud_cdc_n_write_flush(SERIAL_BRIDGE_ITF);

  cyw43_arch_lwip_end();
}
