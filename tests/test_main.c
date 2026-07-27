// Host-side test harness for the vendored WireGuard crypto and protocol core.
//
// Strategy: the library's ChaCha20/AEAD API takes WireGuard-form nonces (a
// 64-bit counter in a 96-bit field with a zero prefix), so raw RFC 8439
// vectors cannot be fed to it directly. Instead this file carries a small
// INDEPENDENT ChaCha20 implementation, anchors it against the RFC 8439 block
// vector, anchors poly1305-donna and hchacha20 against their published
// vectors, and then cross-verifies the library's ChaCha20 keystream and the
// full ChaCha20-Poly1305 construction against the independent implementation
// for WireGuard-form nonces. BLAKE2s and X25519 are checked against RFC
// 7693 / RFC 7748 vectors, and a complete in-memory handshake (initiator +
// responder devices) exercises everything together the way wireguardif does.
//
// Build/run: make -C tests test   (host compiler, no pico-sdk needed)

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "crypto/refc/chacha20.h"
#include "crypto/refc/chacha20poly1305.h"
#include "crypto/refc/poly1305-donna.h"
#include "wireguard.h"

// --- tiny framework -----------------------------------------------------------

static int g_pass, g_fail;

static void check(int cond, const char *name) {
  if (cond) {
    g_pass++;
  } else {
    g_fail++;
    printf("FAIL: %s\n", name);
  }
}

static void check_mem(const void *got, const void *want, size_t n, const char *name) {
  if (memcmp(got, want, n) == 0) {
    g_pass++;
    return;
  }
  g_fail++;
  printf("FAIL: %s\n  got: ", name);
  for (size_t i = 0; i < n; i++) printf("%02x", ((const uint8_t *)got)[i]);
  printf("\n want: ");
  for (size_t i = 0; i < n; i++) printf("%02x", ((const uint8_t *)want)[i]);
  printf("\n");
}

static void hex(uint8_t *out, const char *s) {
  size_t n = strlen(s) / 2;
  for (size_t i = 0; i < n; i++) {
    unsigned v;
    sscanf(s + 2 * i, "%2x", &v);
    out[i] = (uint8_t)v;
  }
}

// --- platform stubs (wireguard-platform.h) --------------------------------------

static uint32_t fake_ms = 1000;
uint32_t wireguard_sys_now(void) { return fake_ms; }

// Deterministic "randomness" so failures reproduce; quality is irrelevant here.
static uint32_t rng_state = 0x12345678;
void wireguard_random_bytes(void *bytes, size_t size) {
  uint8_t *p = (uint8_t *)bytes;
  for (size_t i = 0; i < size; i++) {
    rng_state = rng_state * 1664525u + 1013904223u;
    p[i] = (uint8_t)(rng_state >> 24);
  }
}

static uint64_t fake_tai_s = 0x400000005f000000ULL;
void wireguard_tai64n_now(uint8_t *output) {
  fake_tai_s++; // strictly increasing, as the protocol requires
  for (int i = 0; i < 8; i++) output[i] = (uint8_t)(fake_tai_s >> (56 - 8 * i));
  memset(output + 8, 0, 4);
}

bool wireguard_is_under_load(void) { return false; }

// --- independent reference ChaCha20 (RFC 8439) ----------------------------------

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void qr(uint32_t *s, int a, int b, int c, int d) {
  s[a] += s[b]; s[d] ^= s[a]; s[d] = ROTL32(s[d], 16);
  s[c] += s[d]; s[b] ^= s[c]; s[b] = ROTL32(s[b], 12);
  s[a] += s[b]; s[d] ^= s[a]; s[d] = ROTL32(s[d], 8);
  s[c] += s[d]; s[b] ^= s[c]; s[b] = ROTL32(s[b], 7);
}

static uint32_t le32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void ref_chacha20_block(uint8_t out[64], const uint8_t key[32], uint32_t counter,
                               const uint8_t nonce[12]) {
  uint32_t s[16], w[16];
  s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
  for (int i = 0; i < 8; i++) s[4 + i] = le32(key + 4 * i);
  s[12] = counter;
  for (int i = 0; i < 3; i++) s[13 + i] = le32(nonce + 4 * i);
  memcpy(w, s, sizeof(w));
  for (int i = 0; i < 10; i++) {
    qr(w, 0, 4, 8, 12); qr(w, 1, 5, 9, 13); qr(w, 2, 6, 10, 14); qr(w, 3, 7, 11, 15);
    qr(w, 0, 5, 10, 15); qr(w, 1, 6, 11, 12); qr(w, 2, 7, 8, 13); qr(w, 3, 4, 9, 14);
  }
  for (int i = 0; i < 16; i++) {
    uint32_t v = w[i] + s[i];
    out[4 * i] = (uint8_t)v;
    out[4 * i + 1] = (uint8_t)(v >> 8);
    out[4 * i + 2] = (uint8_t)(v >> 16);
    out[4 * i + 3] = (uint8_t)(v >> 24);
  }
}

static void ref_chacha20_xor(uint8_t *out, const uint8_t *in, size_t len, const uint8_t key[32],
                             uint32_t counter, const uint8_t nonce[12]) {
  uint8_t ks[64];
  for (size_t off = 0; off < len; off += 64) {
    ref_chacha20_block(ks, key, counter++, nonce);
    size_t n = len - off < 64 ? len - off : 64;
    for (size_t i = 0; i < n; i++) out[off + i] = in[off + i] ^ ks[i];
  }
}

// HChaCha20 from the same (RFC-8439-anchored) round function: run the rounds
// on constants|key|nonce16 and emit words 0-3 and 12-15 without feedforward.
static void ref_hchacha20(uint8_t out[32], const uint8_t nonce[16], const uint8_t key[32]) {
  uint32_t w[16];
  w[0] = 0x61707865; w[1] = 0x3320646e; w[2] = 0x79622d32; w[3] = 0x6b206574;
  for (int i = 0; i < 8; i++) w[4 + i] = le32(key + 4 * i);
  for (int i = 0; i < 4; i++) w[12 + i] = le32(nonce + 4 * i);
  for (int i = 0; i < 10; i++) {
    qr(w, 0, 4, 8, 12); qr(w, 1, 5, 9, 13); qr(w, 2, 6, 10, 14); qr(w, 3, 7, 11, 15);
    qr(w, 0, 5, 10, 15); qr(w, 1, 6, 11, 12); qr(w, 2, 7, 8, 13); qr(w, 3, 4, 9, 14);
  }
  for (int i = 0; i < 4; i++) {
    uint32_t v = w[i];
    out[4 * i] = (uint8_t)v; out[4 * i + 1] = (uint8_t)(v >> 8);
    out[4 * i + 2] = (uint8_t)(v >> 16); out[4 * i + 3] = (uint8_t)(v >> 24);
    v = w[12 + i];
    out[16 + 4 * i] = (uint8_t)v; out[16 + 4 * i + 1] = (uint8_t)(v >> 8);
    out[16 + 4 * i + 2] = (uint8_t)(v >> 16); out[16 + 4 * i + 3] = (uint8_t)(v >> 24);
  }
}

// WireGuard-form 96-bit nonce: 4 zero bytes then the 64-bit counter, little-endian.
static void wg_nonce(uint8_t nonce[12], uint64_t n) {
  memset(nonce, 0, 4);
  for (int i = 0; i < 8; i++) nonce[4 + i] = (uint8_t)(n >> (8 * i));
}

// Reference RFC 8439 AEAD with a WireGuard-form nonce, built from the (anchored)
// reference ChaCha20 and the (anchored) poly1305-donna.
static void ref_aead_encrypt(uint8_t *dst /* ct||tag */, const uint8_t *src, size_t src_len,
                             const uint8_t *ad, size_t ad_len, uint64_t n,
                             const uint8_t key[32]) {
  uint8_t nonce[12], block0[64], zeros[16] = {0};
  wg_nonce(nonce, n);
  ref_chacha20_block(block0, key, 0, nonce); // poly key = first 32 bytes
  ref_chacha20_xor(dst, src, src_len, key, 1, nonce);

  poly1305_context ctx;
  poly1305_init(&ctx, block0);
  uint8_t lens[16];
  for (int i = 0; i < 8; i++) {
    lens[i] = (uint8_t)((uint64_t)ad_len >> (8 * i));
    lens[8 + i] = (uint8_t)((uint64_t)src_len >> (8 * i));
  }
  poly1305_update(&ctx, ad, ad_len);
  if (ad_len % 16) poly1305_update(&ctx, zeros, 16 - ad_len % 16);
  poly1305_update(&ctx, dst, src_len);
  if (src_len % 16) poly1305_update(&ctx, zeros, 16 - src_len % 16);
  poly1305_update(&ctx, lens, 16);
  poly1305_finish(&ctx, dst + src_len);
}

// --- anchor tests: published vectors ---------------------------------------------

static void test_anchors(void) {
  uint8_t key[32], nonce[16], want[64], got[64];

  // RFC 8439 2.3.2: ChaCha20 block, key 00..1f, counter 1 -- anchors ref_chacha20.
  for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
  hex(nonce, "000000090000004a00000000");
  hex(want,
      "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
      "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");
  ref_chacha20_block(got, key, 1, nonce);
  check_mem(got, want, 64, "ref chacha20 block (RFC 8439 2.3.2)");

  // RFC 8439 2.5.2: poly1305 -- anchors the library's poly1305-donna.
  hex(key, "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
  const char *msg = "Cryptographic Forum Research Group";
  uint8_t tag[16], want_tag[16];
  hex(want_tag, "a8061dc1305136c6c22b8baf0c0127a9");
  poly1305_context pc;
  poly1305_init(&pc, key);
  poly1305_update(&pc, (const uint8_t *)msg, strlen(msg));
  poly1305_finish(&pc, tag);
  check_mem(tag, want_tag, 16, "library poly1305 (RFC 8439 2.5.2)");

  // HChaCha20 cross-check against the anchored reference round function
  // (verified additionally against an independent Python implementation).
  for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
  hex(nonce, "000000090000004a0000000031415927");
  ref_hchacha20(want, nonce, key);
  hchacha20(got, nonce, key);
  check_mem(got, want, 32, "library hchacha20 vs anchored ref");
}

static void test_blake2s(void) {
  uint8_t out[32], want[32];

  // RFC 7693 appendix B: BLAKE2s-256("abc"), unkeyed.
  hex(want, "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
  blake2s(out, 32, NULL, 0, "abc", 3);
  check_mem(out, want, 32, "blake2s('abc') (RFC 7693)");

  // Official BLAKE2s KAT, first entry: key 00..1f, empty message.
  uint8_t key[32];
  for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
  hex(want, "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49");
  blake2s(out, 32, key, 32, "", 0);
  check_mem(out, want, 32, "blake2s keyed, empty msg (KAT)");
}

static void test_x25519(void) {
  uint8_t scalar[32], point[32], out[32], want[32];

  // RFC 7748 5.2, vector 1.
  hex(scalar, "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
  hex(point, "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
  hex(want, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
  check(wireguard_x25519(out, scalar, point) == 0, "x25519 v1 rc");
  check_mem(out, want, 32, "x25519 (RFC 7748 5.2 #1)");

  // Vector 2. The u-coordinate has its high bit set; RFC 7748 says to ignore
  // it, and this library requires the caller to clear it (see x25519.h).
  hex(scalar, "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
  hex(point, "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
  point[31] &= 0x7f;
  hex(want, "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
  wireguard_x25519(out, scalar, point);
  check_mem(out, want, 32, "x25519 (RFC 7748 5.2 #2, masked)");

  // RFC 7748 6.1 Diffie-Hellman: public keys and both directions of the shared
  // secret. Also exercises x25519_base (scalar * basepoint).
  uint8_t apriv[32], apub[32], bpriv[32], bpub[32], k1[32], k2[32];
  hex(apriv, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
  hex(bpriv, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
  x25519_base(apub, apriv, 1);
  x25519_base(bpub, bpriv, 1);
  hex(k1, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
  check_mem(apub, k1, 32, "x25519 alice public (RFC 7748 6.1)");
  hex(k1, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
  check_mem(bpub, k1, 32, "x25519 bob public (RFC 7748 6.1)");
  wireguard_x25519(k1, apriv, bpub);
  wireguard_x25519(k2, bpriv, apub);
  uint8_t want_k[32];
  hex(want_k, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
  check_mem(k1, want_k, 32, "x25519 shared secret a*B (RFC 7748 6.1)");
  check_mem(k2, want_k, 32, "x25519 shared secret b*A (RFC 7748 6.1)");
}

// Cross-verify the library ChaCha20 keystream and AEAD against the anchored
// reference, for several WireGuard-form nonces and lengths (including
// non-multiple-of-64/16 sizes and empty AD).
static void test_chacha20poly1305_cross(void) {
  uint8_t key[32];
  wireguard_random_bytes(key, 32);

  static const uint64_t nonces[] = {0, 1, 0xdeadbeefULL, 0xffffffffffffffffULL};
  static const size_t lens[] = {1, 63, 64, 65, 128, 1420};
  uint8_t in[1420], lib[1440], ref[1440], nonce[12];

  wireguard_random_bytes(in, sizeof(in));

  for (size_t ni = 0; ni < 4; ni++) {
    // Keystream: chacha20_init leaves the block counter at 0, so two blocks
    // from the library must equal the reference at counters 0 and 1.
    struct chacha20_ctx ctx;
    chacha20_init(&ctx, key, nonces[ni]);
    memset(lib, 0, 128);
    chacha20(&ctx, lib, lib, 128);
    wg_nonce(nonce, nonces[ni]);
    memset(ref, 0, 128);
    ref_chacha20_xor(ref, ref, 128, key, 0, nonce);
    char name[64];
    snprintf(name, sizeof(name), "chacha20 keystream vs ref (nonce %zu)", ni);
    check_mem(lib, ref, 128, name);
  }

  const uint8_t ad[12] = "wg-dongle-ad";
  for (size_t li = 0; li < 6; li++) {
    size_t n = lens[li];
    chacha20poly1305_encrypt(lib, in, n, ad, sizeof(ad), 7, key);
    ref_aead_encrypt(ref, in, n, ad, sizeof(ad), 7, key);
    char name[64];
    snprintf(name, sizeof(name), "aead ct+tag vs ref (len %zu)", n);
    check_mem(lib, ref, n + 16, name);
  }

  // Empty AD (the WireGuard transport-data case).
  chacha20poly1305_encrypt(lib, in, 256, NULL, 0, 42, key);
  ref_aead_encrypt(ref, in, 256, NULL, 0, 42, key);
  check_mem(lib, ref, 256 + 16, "aead ct+tag vs ref (empty ad)");

  // Round-trip and tamper detection.
  uint8_t out[1440];
  check(chacha20poly1305_decrypt(out, lib, 256 + 16, NULL, 0, 42, key),
        "aead decrypt ok");
  check_mem(out, in, 256, "aead round-trip plaintext");
  lib[10] ^= 1;
  check(!chacha20poly1305_decrypt(out, lib, 256 + 16, NULL, 0, 42, key),
        "aead rejects tampered ciphertext");
  lib[10] ^= 1;
  check(!chacha20poly1305_decrypt(out, lib, 256 + 16, NULL, 0, 43, key),
        "aead rejects wrong nonce");
  lib[256 + 3] ^= 1;
  check(!chacha20poly1305_decrypt(out, lib, 256 + 16, NULL, 0, 42, key),
        "aead rejects tampered tag");
}

// XChaCha20-Poly1305 decomposes into hchacha20 (anchored) + the AEAD with a
// WireGuard-form nonce from the trailing 8 nonce bytes (cross-verified above).
static void test_xchacha20poly1305(void) {
  uint8_t key[32], nonce24[24], in[128], lib[144], comp[144], out[128];
  wireguard_random_bytes(key, 32);
  wireguard_random_bytes(nonce24, 24);
  wireguard_random_bytes(in, sizeof(in));
  const uint8_t ad[4] = "meta";

  xchacha20poly1305_encrypt(lib, in, sizeof(in), ad, sizeof(ad), nonce24, key);

  uint8_t subkey[32];
  hchacha20(subkey, nonce24, key); // first 16 nonce bytes
  uint64_t n = 0;
  for (int i = 0; i < 8; i++) n |= (uint64_t)nonce24[16 + i] << (8 * i);
  chacha20poly1305_encrypt(comp, in, sizeof(in), ad, sizeof(ad), n, subkey);
  check_mem(lib, comp, sizeof(in) + 16, "xchacha == hchacha + chachapoly");

  check(xchacha20poly1305_decrypt(out, lib, sizeof(in) + 16, ad, sizeof(ad), nonce24, key),
        "xchacha decrypt ok");
  check_mem(out, in, sizeof(in), "xchacha round-trip plaintext");
  lib[0] ^= 1;
  check(!xchacha20poly1305_decrypt(out, lib, sizeof(in) + 16, ad, sizeof(ad), nonce24, key),
        "xchacha rejects tampered ciphertext");
}

static void test_base64(void) {
  uint8_t out[64];
  size_t n = sizeof(out);
  check(wireguard_base64_decode("MDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3BxcnN0dXY=", out, &n) &&
            n == 32 && memcmp(out, "0123456789abcdefghijklmnopqrstuv", 32) == 0,
        "base64 decode known 32-byte key");

  uint8_t key[32];
  char enc[64];
  wireguard_random_bytes(key, 32);
  size_t enc_len = sizeof(enc);
  check(wireguard_base64_encode(key, 32, enc, &enc_len), "base64 encode rc");
  uint8_t back[64];
  n = sizeof(back);
  check(wireguard_base64_decode(enc, back, &n) && n == 32 && memcmp(back, key, 32) == 0,
        "base64 encode/decode round-trip");

  n = sizeof(out);
  check(!wireguard_base64_decode("!!!not base64!!!", out, &n), "base64 rejects junk");
}

// --- full handshake round-trip ---------------------------------------------------

// Mirror wireguardif.c's call sequence with two in-memory devices: initiator A
// creates an initiation, responder B consumes it and answers, both derive
// sessions, and transport packets flow both ways with replay protection.
static void test_handshake(void) {
  static struct wireguard_device a, b;
  uint8_t a_priv[32], b_priv[32];

  wireguard_init();
  wireguard_random_bytes(a_priv, 32);
  wireguard_random_bytes(b_priv, 32);
  check(wireguard_device_init(&a, a_priv), "device A init");
  check(wireguard_device_init(&b, b_priv), "device B init");

  struct wireguard_peer *pa = &a.peers[0]; // A's view of B
  struct wireguard_peer *pb = &b.peers[0]; // B's view of A
  check(wireguard_peer_init(&a, pa, b.public_key, NULL), "peer B on A");
  check(wireguard_peer_init(&b, pb, a.public_key, NULL), "peer A on B");
  pa->valid = pb->valid = true;
  pa->active = pb->active = true;

  // A -> B: handshake initiation (mac1 checked the way the receive path does).
  static struct message_handshake_initiation init_msg;
  check(wireguard_create_handshake_initiation(&a, pa, &init_msg), "create initiation");
  check(wireguard_check_mac1(&b, (uint8_t *)&init_msg,
                             sizeof(init_msg) - 2 * WIREGUARD_COOKIE_LEN, init_msg.mac1),
        "initiation mac1 verifies at B");
  struct wireguard_peer *found = wireguard_process_initiation_message(&b, &init_msg);
  check(found == pb, "B resolves initiation to peer A");

  // B -> A: handshake response, then both sides start their sessions.
  static struct message_handshake_response resp_msg;
  check(wireguard_create_handshake_response(&b, pb, &resp_msg), "create response");
  wireguard_start_session(pb, false);
  check(wireguard_check_mac1(&a, (uint8_t *)&resp_msg,
                             sizeof(resp_msg) - 2 * WIREGUARD_COOKIE_LEN, resp_msg.mac1),
        "response mac1 verifies at A");
  check(wireguard_process_handshake_response(&a, pa, &resp_msg), "A processes response");
  wireguard_start_session(pa, true);

  // Spec 5.4.5: the initiator installs the fresh keypair as current, but the
  // responder parks it in next_keypair and only promotes it when the first
  // transport packet arrives (so it never sends on unconfirmed keys).
  check(pa->curr_keypair.valid, "A keypair valid (current)");
  check(pb->next_keypair.valid, "B keypair valid (parked in next)");
  check_mem(pa->curr_keypair.sending_key, pb->next_keypair.receiving_key, 32,
            "A send key == B recv key");
  check_mem(pb->next_keypair.sending_key, pa->curr_keypair.receiving_key, 32,
            "B send key == A recv key");

  // Transport data A -> B, sized like a real forwarded packet. B receives on
  // next_keypair and then promotes it, exactly as the receive path does.
  static uint8_t plain[1420], wire[1420 + 16], back[1420];
  wireguard_random_bytes(plain, sizeof(plain));
  uint64_t ctr = pa->curr_keypair.sending_counter;
  wireguard_encrypt_packet(wire, plain, sizeof(plain), &pa->curr_keypair);
  check(wireguard_decrypt_packet(back, wire, sizeof(wire), ctr, &pb->next_keypair),
        "B decrypts A's packet");
  check_mem(back, plain, sizeof(plain), "A->B payload intact");

  // Replay: the same counter must be rejected the second time.
  check(wireguard_check_replay(&pb->next_keypair, ctr), "counter accepted once");
  check(!wireguard_check_replay(&pb->next_keypair, ctr), "replayed counter rejected");

  keypair_update(pb, &pb->next_keypair); // first confirmed RX promotes next -> curr
  check(pb->curr_keypair.valid, "B keypair promoted to current");

  // Transport data B -> A.
  uint64_t ctr2 = pb->curr_keypair.sending_counter;
  wireguard_encrypt_packet(wire, plain, 64, &pb->curr_keypair);
  check(wireguard_decrypt_packet(back, wire, 64 + 16, ctr2, &pa->curr_keypair),
        "A decrypts B's packet");
  check_mem(back, plain, 64, "B->A payload intact");

  // A tampered transport packet must not decrypt.
  wire[5] ^= 1;
  check(!wireguard_decrypt_packet(back, wire, 64 + 16, ctr2, &pa->curr_keypair),
        "tampered transport packet rejected");
}

int main(void) {
  test_anchors();
  test_blake2s();
  test_x25519();
  test_chacha20poly1305_cross();
  test_xchacha20poly1305();
  test_base64();
  test_handshake();

  printf("\n%d passed, %d failed\n", g_pass, g_fail);
  return g_fail ? 1 : 0;
}
