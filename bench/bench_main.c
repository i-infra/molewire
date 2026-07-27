// On-device crypto profiling bench for the WireGuard dongle.
//
// Flash this to a Pico 2 W and open its USB serial port (or the UART): it
// repeatedly measures the vendored crypto primitives on the actual silicon and
// prints throughput plus a derived tunnel-throughput estimate. Use it to
// answer "is crypto or the USB link the bottleneck?" with numbers instead of
// folklore, and to compare the reference X25519 against the Cortex-M0 assembly
// implementation that upstream ships (crypto/cortex).
//
// The interesting figures:
//   - ChaCha20-Poly1305 at 1420 B (tunnel MTU): the per-packet data-path cost.
//     Compare its Mbit/s against the ~5 Mbit/s the USB Full-Speed link
//     delivers in practice; the smaller number is the ceiling.
//   - X25519: the handshake/rekey cost. WireGuard rekeys every ~120 s
//     (REKEY_AFTER_TIME); each rekey performs a handful of scalar
//     multiplications, and in a NO_SYS build they run inside the lwIP lock --
//     a long X25519 means a periodic stall of the datapath.

#include <stdio.h>
#include <string.h>

#include <hardware/clocks.h>
#include <pico/rand.h>
#include <pico/stdlib.h>

#include "crypto.h"
#include "crypto/cortex/scalarmult.h"
#include "crypto/refc/chacha20poly1305.h"

#define WG_MTU 1420
#define AEAD_ITERS 500
#define SMALL_ITERS 4000
#define X25519_ITERS 8

// Rough per-rekey scalar-multiplication count for the initiator (ephemeral
// keygen + DHs across initiation and response processing).
#define REKEY_DH_OPS 4

static uint8_t key[32];
static uint8_t buf_in[WG_MTU];
static uint8_t buf_out[WG_MTU + 16];

static void fill_random(uint8_t *p, size_t n) {
  while (n >= 8) {
    uint64_t r = get_rand_64();
    memcpy(p, &r, 8);
    p += 8;
    n -= 8;
  }
  if (n) {
    uint64_t r = get_rand_64();
    memcpy(p, &r, n);
  }
}

// Returns microseconds for `iters` AEAD-encrypts of `len` bytes.
static uint64_t bench_aead(size_t len, int iters) {
  uint64_t t0 = time_us_64();
  for (int i = 0; i < iters; i++) {
    chacha20poly1305_encrypt(buf_out, buf_in, len, NULL, 0, (uint64_t)i, key);
  }
  return time_us_64() - t0;
}

static uint64_t bench_blake2s(int iters) {
  static uint8_t out[32];
  uint64_t t0 = time_us_64();
  for (int i = 0; i < iters; i++) {
    blake2s(out, 32, NULL, 0, buf_in, 1024);
  }
  return time_us_64() - t0;
}

typedef int (*scalarmult_fn)(uint8_t *out, const uint8_t *scalar, const uint8_t *point);

static int refc_scalarmult(uint8_t *out, const uint8_t *scalar, const uint8_t *point) {
  return wireguard_x25519(out, scalar, point);
}

static int cortex_scalarmult(uint8_t *out, const uint8_t *scalar, const uint8_t *point) {
  return crypto_scalarmult_curve25519(out, scalar, point);
}

static uint64_t bench_x25519(scalarmult_fn fn, uint8_t *out) {
  static uint8_t scalar[32];
  static uint8_t point[32] = {9}; // basepoint
  fill_random(scalar, 32);
  uint64_t t0 = time_us_64();
  for (int i = 0; i < X25519_ITERS; i++) {
    fn(out, scalar, point);
  }
  return time_us_64() - t0;
}

int main(void) {
  stdio_init_all();
  fill_random(key, sizeof(key));
  fill_random(buf_in, sizeof(buf_in));

  while (true) {
    uint32_t sys_khz = clock_get_hz(clk_sys) / 1000;
    printf("\n=== pico-wg-dongle crypto bench (sys clk %lu.%03lu MHz) ===\n",
           (unsigned long)(sys_khz / 1000), (unsigned long)(sys_khz % 1000));

    // Data path: AEAD at tunnel MTU and at ack-sized packets.
    uint64_t us = bench_aead(WG_MTU, AEAD_ITERS);
    uint64_t bytes = (uint64_t)WG_MTU * AEAD_ITERS;
    uint32_t kbps = (uint32_t)(bytes * 8000 / us); // kbit/s
    // cycles = sys_khz * us / 1000, so milli-cycles-per-byte = sys_khz*us/bytes
    uint32_t cpb_milli = (uint32_t)((uint64_t)sys_khz * us / bytes);
    printf("chacha20poly1305 encrypt %u B x%u: %llu us  ->  %lu.%03lu Mbit/s, %lu.%03lu cyc/B\n",
           WG_MTU, AEAD_ITERS, (unsigned long long)us, (unsigned long)(kbps / 1000),
           (unsigned long)(kbps % 1000), (unsigned long)(cpb_milli / 1000),
           (unsigned long)(cpb_milli % 1000));

    us = bench_aead(64, SMALL_ITERS);
    printf("chacha20poly1305 encrypt   64 B x%u: %llu us  ->  %lu pkt/s\n", SMALL_ITERS,
           (unsigned long long)us, (unsigned long)((uint64_t)SMALL_ITERS * 1000000 / us));

    us = bench_blake2s(500);
    uint32_t b2s_kbps = (uint32_t)(500ull * 1024 * 8000 / us);
    printf("blake2s 1 KiB x500: %llu us  ->  %lu.%03lu Mbit/s\n", (unsigned long long)us,
           (unsigned long)(b2s_kbps / 1000), (unsigned long)(b2s_kbps % 1000));

    // Handshake path: reference C vs the uNaCl Cortex-M0 assembly.
    static uint8_t out_r[32], out_c[32];
    uint64_t us_r = bench_x25519(refc_scalarmult, out_r);
    uint64_t us_c = bench_x25519(cortex_scalarmult, out_c);
    printf("x25519 refc:   %lu us/op\n", (unsigned long)(us_r / X25519_ITERS));
    printf("x25519 cortex: %lu us/op  (%lu%% of refc time)\n",
           (unsigned long)(us_c / X25519_ITERS), (unsigned long)(us_c * 100 / us_r));

    // Cross-check the two implementations against each other on a shared
    // random scalar so a broken optimization can't go unnoticed.
    static uint8_t scalar[32], point[32] = {9};
    fill_random(scalar, 32);
    refc_scalarmult(out_r, scalar, point);
    cortex_scalarmult(out_c, scalar, point);
    printf("x25519 refc/cortex agree: %s\n", memcmp(out_r, out_c, 32) == 0 ? "YES" : "NO !!");

    // What it means for the tunnel.
    uint64_t rekey_us_r = (uint64_t)REKEY_DH_OPS * us_r / X25519_ITERS;
    uint64_t rekey_us_c = (uint64_t)REKEY_DH_OPS * us_c / X25519_ITERS;
    printf("--\n");
    printf("estimated rekey stall (~%u DH ops): refc %llu ms, cortex %llu ms\n", REKEY_DH_OPS,
           (unsigned long long)(rekey_us_r / 1000), (unsigned long long)(rekey_us_c / 1000));
    printf("USB FS practical budget ~5 Mbit/s -> AEAD at that rate uses ~%lu%% of one core\n",
           (unsigned long)((5000ull * 100) / kbps));
    printf("(bottleneck: %s)\n", kbps > 5000 ? "USB Full-Speed link" : "crypto");

    sleep_ms(5000);
  }
}
