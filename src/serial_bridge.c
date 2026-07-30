// Serial party line: CDC-ACM <-> UART1 <-> TCP. See serial_bridge.h.
//
// Context model: the TCP callbacks run wherever tunnel input is processed
// (the cyw43 background context), so they only touch the pcb and the held
// pbuf chain. All byte movement -- including every CDC and UART access --
// happens in serial_bridge_task() in the main loop, under the lwIP lock,
// which also excludes the background context.

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
#define BRIDGE_TCP_PORT 2323
#define TICK_BYTE_BUDGET 128 // per-direction bound so the pump never hogs a tick

static struct tcp_pcb *client;
static struct pbuf *rx;     // unconsumed TCP->line data; TCP window stays
static uint16_t rx_off;     // closed for it until it drains (tcp_recved)
static uint32_t cur_baud = 115200;

// --- endpoints ------------------------------------------------------------------

enum { SRC_UART, SRC_CDC, SRC_TCP };

// A byte may move only if every *active* sink other than the source can take
// it. Inactive sinks (no TCP client, host port closed) drop instead of
// stalling the line.
static bool sinks_ready(int src) {
  if (src != SRC_CDC && tud_cdc_n_connected(SERIAL_BRIDGE_ITF) &&
      tud_cdc_n_write_available(SERIAL_BRIDGE_ITF) == 0) {
    return false;
  }
  if (src != SRC_TCP && client && tcp_sndbuf(client) == 0) {
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
    tcp_write(client, &b, 1, TCP_WRITE_FLAG_COPY);
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
}

static err_t bridge_accept(void *arg, struct tcp_pcb *newpcb, err_t err) {
  (void)arg;
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
  if (client) { // single line, single client
    tcp_abort(newpcb);
    return ERR_ABRT;
  }
  client = newpcb;
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

// --- public ---------------------------------------------------------------------

void serial_bridge_init(void) {
  uart_init(BRIDGE_UART, cur_baud);
  gpio_set_function(BRIDGE_UART_TX_PIN, GPIO_FUNC_UART);
  gpio_set_function(BRIDGE_UART_RX_PIN, GPIO_FUNC_UART);
  uart_set_hw_flow(BRIDGE_UART, false, false);
  uart_set_fifo_enabled(BRIDGE_UART, true);

  cyw43_arch_lwip_begin();
  struct tcp_pcb *l = tcp_new_ip_type(IPADDR_TYPE_ANY);
  if (l && tcp_bind(l, IP_ANY_TYPE, BRIDGE_TCP_PORT) == ERR_OK) {
    l = tcp_listen_with_backlog(l, 1);
    tcp_accept(l, bridge_accept);
  } else if (l) {
    tcp_abort(l);
    printf("serial_bridge: bind failed\n");
  }
  cyw43_arch_lwip_end();
}

void serial_bridge_apply_coding(uint32_t bit_rate, uint8_t data_bits, uint8_t parity,
                                uint8_t stop_bits) {
  if (bit_rate < 300 || bit_rate > 921600) {
    return; // out of UART range; keep the current rate
  }
  cur_baud = bit_rate;
  uart_set_baudrate(BRIDGE_UART, bit_rate);
  // CDC encoding: parity 0/1/2 = none/odd/even; stop 0/1/2 = 1/1.5/2 bits.
  uart_parity_t p = (parity == 1) ? UART_PARITY_ODD
                    : (parity == 2) ? UART_PARITY_EVEN
                                    : UART_PARITY_NONE;
  uint db = (data_bits >= 5 && data_bits <= 8) ? data_bits : 8;
  uart_set_format(BRIDGE_UART, db, (stop_bits == 2) ? 2 : 1, p);
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
  while (budget > 0 && rx && sinks_ready(SRC_TCP)) {
    fan_out(SRC_TCP, ((const uint8_t *)rx->payload)[rx_off]);
    rx_off++;
    consumed++;
    budget--;
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
