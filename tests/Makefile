# Host-side tests for the vendored WireGuard core. No pico-sdk required: the
# crypto is portable C and wireguard.c's lwIP types are satisfied by the stub
# headers in fake_lwip/ (it stores but never dereferences them).

CC ?= cc
WG := ../wireguard
CFLAGS := -O1 -g -Wall -Wextra -Wno-unused-parameter \
          -I$(WG) -Ifake_lwip

SRCS := test_main.c \
        $(WG)/wireguard.c \
        $(WG)/crypto.c \
        $(WG)/crypto/refc/blake2s.c \
        $(WG)/crypto/refc/chacha20.c \
        $(WG)/crypto/refc/chacha20poly1305.c \
        $(WG)/crypto/refc/poly1305-donna.c \
        $(WG)/crypto/refc/x25519.c

test_main: $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS)

.PHONY: test clean
test: test_main
	./test_main

clean:
	rm -f test_main
