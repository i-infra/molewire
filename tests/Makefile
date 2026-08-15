# Host-side tests for the vendored WireGuard core (plus the pure Wi-Fi
# candidate-ordering logic). No pico-sdk required: the crypto is portable C
# and wireguard.c's lwIP types are satisfied by the stub headers in fake_lwip/
# (it stores but never dereferences them). wifi_pick.c depends only on
# config.h, which is SDK-free.

CC ?= cc
WG := ../wireguard
SRC := ../src
CFLAGS := -O1 -g -Wall -Wextra -Wno-unused-parameter \
          -I$(WG) -I$(SRC) -Ifake_lwip

SRCS := test_main.c \
        $(SRC)/wifi_pick.c \
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
