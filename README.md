<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo-dark.svg">
    <img src="docs/logo.svg" alt="molewire" width="340">
  </picture>
</p>

<p align="center"><em>It looks like a flash drive. The computer thinks it's a network cable.<br>
The computer can't see the Wi-Fi network, and the network sees nothing but encrypted traffic.</em></p>

<!-- PHOTO SLOT: when docs/photo.jpg exists, replace this comment with:
<p align="center"><img src="docs/photo.jpg" alt="A Pico 2 W next to a USB flash drive" width="560"></p>
Best shot: the dongle beside an actual flash drive (proves the hook), or plugged into a laptop port.
-->

A USB WireGuard adapter for the Raspberry Pi Pico 2 W (RP2350). Plug it into
any computer and it shows up as a standard USB network interface (CDC-NCM, with
in-box drivers on Linux, macOS, Windows 10/11). The Pico joins an upstream
Wi-Fi network, runs WireGuard on-device, and routes the host through the
tunnel, **and nothing else**: the host never gets an address on, or a route
to, the upstream LAN, and the firmware fails closed (no tunnel, no
forwarding).

## TL;DR

1. Go to Micro Center (or any Raspberry Pi vendor) and buy a **Pico 2 W** (~$8).
2. Hold the BOOTSEL button while plugging it into your computer, then copy
   `molewire.uf2` from the [latest release](https://github.com/i-infra/molewire/releases/latest)
   onto the `RP2350` drive that appears.
3. Eject, unplug, replug. Browse to **https://i-infra.github.io/molewire/**,
   which opens the dongle's config portal: pick your Wi-Fi, *generate
   keypair*, give the public key to your WireGuard admin, enter the address
   pair + endpoint they hand back, *apply*, *save*.

## Why

The usual way to protect a connection is to configure the computer: install a
VPN client, sign in, hope nothing leaks around it. Molewire inverts that: the
tunnel lives in an $8 USB device and the computer just sees an ordinary
network cable. This means it works on machines you can't configure
(locked-down, legacy, not yours) and machines you shouldn't trust (borrowed,
sketchy, IoT). Instead of walking someone through VPN setup over the phone,
you set the plug up once and mail it to them.

## How it works

```
 host ──USB (CDC-NCM)── [usb netif] ──forward── [wg netif] ══tunnel══ WG server
                              Pico 2 W              │
                                          [wifi sta netif] ~~~ upstream Wi-Fi
                                          (outer UDP only)
      AP client ~~802.11~~ [ap netif] ──forward──┘   (optional, one client)
```

- **No NAT.** The host's DHCP lease *is* a tunnel address: the server peer's
  AllowedIPs covers a small subnet (e.g. a `/30`): one address is the Pico,
  the other is leased to the host. Packets forward with addresses untouched.
- **Isolation is structural, not a filter list.** An lwIP source-routing hook
  (`wg_ip4_route_hook` in `src/wg.c`) routes every forwarded packet to its
  client link or into the tunnel: never to the Wi-Fi netif, never between
  USB host and AP client, and into a blackhole before the tunnel exists.
- **No DNS leaks.** No DNS forwarder on the device; DHCP hands the host the
  tunnel-side resolver and queries ride the tunnel like any other packet.
- **MTU handled twice.** DHCP offers the tunnel MTU (1420; `set mtu` to
  lower) and the dongle clamps forwarded TCP MSS in both directions, so TCP
  fits even through servers that re-encapsulate.
- **No NTP dependency** (a flash-backed boot counter keeps handshake
  timestamps monotonic) and **real randomness** (RP2350 TRNG, one reason
  the project is RP2350-only).

## Building

Requirements: `arm-none-eabi-gcc`, `cmake`, `ninja`, pico-sdk 2.2.0 with the
`cyw43-driver`, `lwip`, `tinyusb`, `mbedtls` submodules. Copy
`src/wifi_config.h.example` to `src/wifi_config.h` first (blank is fine).

```sh
PICO_SDK_PATH=/path/to/pico-sdk cmake -S . -B build -G Ninja -DPICO_BOARD=pico2_w
cmake --build build
```

CI builds `molewire.uf2` on every push and attaches it to a Release on `v*`
tags. After the first BOOTSEL flash the button is never needed again: type
`bootsel` on the console, open a console CDC port at 1200 baud, or
`picotool reboot -f -u`. Typical loop:

```sh
cmake --build build && stty -f /dev/cu.usbmodem* 1200 ; sleep 2 && cp build/molewire.uf2 /Volumes/RP2350/
```

## Provisioning

**Portal:** http://molewire.local, served by the device itself, reachable in
every config state (IPv6 link-local + mDNS on the USB link only; before
provisioning it also leases the host a routeless 172.31.255.2/30 island, so
your connectivity is untouched, and the portal is reachable at
**http://172.31.255.1/** even where mDNS is broken; once provisioned, the
dongle's tunnel-side USB address serves the same role). Live status, scan-and-join, key generation,
and a console box. The device also carries a WebUSB landing descriptor
pointing at https://i-infra.github.io/molewire/. The dongle remembers the 8
most recently used Wi-Fi networks and auto-joins the strongest known one
whenever the uplink drops; bad passwords are benched for 10 minutes, hidden
SSIDs are blind-retried.

**Console:** the first of three CDC-ACM serial ports (e.g. `screen /dev/ttyACM0`):

```
set ssid MyUpstreamNet
set pass wifi-password
genkey                          # prints ONLY the public key; private never leaves
set peer <server public key>
set endpoint vpn.example.com 51820
set addr 10.66.0.249/30
set hostip 10.66.0.250
set dns 10.66.0.1
save
```

On the server, the peer's AllowedIPs must cover both addresses (pick an
aligned `/30`, use the middle two). Full command reference:
`src/config_proto.h`. `tools/provision-mullvad.py` scripts the whole thing
against Mullvad (registers the on-device key via the app API, picks a relay,
configures full-gateway mode; account number from file or stdin).

**Gateway vs split:** by default the dongle is the host's default router
(all traffic rides the tunnel). `set routes <cidr>[,<cidr>...]` switches to
split mode: only those subnets route via the dongle (DHCP option 121) and
the host keeps its own default route and DNS. `set dns off` / `set routes
off` to taste. LED: solid = tunnel up, slow blink = connecting, fast blink =
unprovisioned.

## Quarantine access point

The radio can run a WPA2 AP beside the station uplink: **one** wireless
client gets a tunnel address and is routed exactly like the USB host:
tunnel or nothing, no LAN path, no AP↔USB cross-talk. A bring-up pen for
untrusted IoT gadgets (`pcap on` watches what they do). Config: `set apssid`
/ `set appass` / `set apaddr 10.66.0.253/30` / `set apclient 10.66.0.254` /
`set ap on`; the AP pair must also be inside the server's AllowedIPs. AP and
station share one radio; expect ~half the USB path's throughput.

## Serial party line

The third CDC port, hardware **UART1 (GP4 TX / GP5 RX)**, and TCP port
**2323** (raw, tunnel/USB side only) are bridged byte-for-byte: wire GP4/5
to a target's console and both the USB host and any tunnel peer
(`nc <device-ip> 2323`) can talk to it. The host tty's line coding retunes
the physical UART. Port **3323** speaks telnet/RFC 2217: baud, format, and
DTR/RTS (**GP7/GP6**) remotely, so
`esptool --port rfc2217://<device-ip>:3323 flash_id` works across the VPN.

## Packet capture

`pcap on` records the USB and AP links (plaintext side, post-checksum-repair)
into a 64 KB RAM ring, snaplen 256. Download Wireshark-ready from
`/api/pcap`, for "the host says it sent X, what did the dongle see?"

## Security notes

- Keys and Wi-Fi credentials sit **unencrypted** in flash (a sector the
  bootrom's UF2 scratch erasure doesn't touch, so config survives reflashes).
  Physical possession = compromise: rotate keys if you lose the dongle.
- `genkey` generates on-device from the TRNG; the private key appears in no
  console output, page, or API response.
- Portal and bridge accept connections from their own links only; the AP
  refuses open (no-password) mode.
- IPv6 exists only as link-local on the USB link and is unroutable: no v6
  side channel around the v4 tunnel.

## Performance (measured)

USB Full Speed (12 Mbit/s) is the bottleneck: 4.65 Mbit/s TCP end-to-end
through a WireGuard→Tailscale bridge ≈ 98% of the no-crypto baseline. Crypto
is effectively free at USB FS rates (ChaCha20-Poly1305 37 Mbit/s on-device;
bench firmware: `molewire-bench.uf2`). The second core is idle headroom.

## Lineage and licenses

MIT. USB/NCM layer, console, and config store adapted from
[pico-usb-wifi](https://gitlab.com/baiyibai/pico-usb-wifi) (MIT); WireGuard
from [wireguard-lwip](https://github.com/smartalock/wireguard-lwip)
(BSD-3-Clause), vendored in `wireguard/` with local patches (shutdown,
include order, restoring zeroed L4 checksums before encryption, dual-stack
type fixes); pico-sdk (BSD-3-Clause).

## Development

- `make -C tests test`: 69 host-side tests (RFC-vector crypto, AEAD
  cross-checks, Wi-Fi candidate ordering, full in-memory handshake).
  CI runs them plus the firmware build on every push.
- Portal page `web/index.html` is gzipped into the firmware at build time;
  `docs/index.html` is the GitHub Pages WebUSB landing page.
