# pico-wg-dongle

A USB WireGuard adapter for the Raspberry Pi Pico 2 W (RP2350).

Plug it into any computer and it shows up as a standard USB network interface
(CDC-NCM — in-box drivers on Linux, macOS, and Windows 10/11). The Pico joins
an upstream Wi-Fi network, runs a WireGuard tunnel on-device, and routes the
host's traffic through it. **The host can reach the WireGuard network and
nothing else** — it never gets an address on, or a route to, the upstream
Wi-Fi LAN, and the firmware fails closed: no tunnel, no forwarding.

## How it works

```
 host ──USB (CDC-NCM)── [usb netif] ──forward── [wg netif] ══tunnel══ WG server
                              Pico 2 W              │
                                          [wifi sta netif] ~~~ upstream Wi-Fi
                                          (outer UDP only)
```

- **No NAT.** The host's DHCP lease *is* a tunnel address. The WireGuard peer's
  AllowedIPs on the server covers a small subnet (e.g. a `/30`): one address is
  the Pico (USB-side gateway), the other is leased to the host. Packets forward
  between USB and tunnel with their addresses untouched.
- **Isolation is structural, not a filter list.** An lwIP source-routing hook
  (`wg_ip4_route_hook` in `src/wg.c`) routes every *forwarded* packet either to
  the USB link or into the WireGuard netif — never to the Wi-Fi station netif.
  Before the tunnel exists, forwarded packets go to a blackhole. Only the
  Pico's own traffic (DHCP client, DNS lookup of the endpoint, and the tunnel's
  outer UDP, which is pinned to the station netif) can touch Wi-Fi.
- **No DNS leaks.** The device runs no DNS forwarder at all. DHCP option 6
  hands the host the tunnel-side resolver; queries ride the tunnel like any
  other packet.
- **MTU is handled.** DHCP option 26 sets the host's interface MTU to the
  WireGuard MTU (1420), so TCP MSS comes out right and nothing black-holes.
- **No NTP dependency.** WireGuard handshake timestamps only need to increase
  monotonically; a flash-backed boot counter provides that across reboots
  (`wg_time_init`), so the tunnel can come up before any time sync exists.
- **Real randomness.** Session keys draw from `pico_rand`, TRNG-backed on the
  RP2350. (This is one reason the project is RP2350-only.)

## Building

Requirements: `arm-none-eabi-gcc`, `cmake`, `ninja`, and the pico-sdk (2.2.0)
with the `cyw43-driver`, `lwip`, `tinyusb`, and `mbedtls` submodules.

```sh
PICO_SDK_PATH=/path/to/pico-sdk cmake -S . -B build -G Ninja -DPICO_BOARD=pico2_w
cmake --build build
# first flash: hold BOOTSEL, plug in, copy build/pico-wg-dongle.uf2 to the drive
```

### Reflashing without touching the board

Once this firmware (or the bench) is running, the button is never needed again —
three ways to land back in the UF2 bootloader:

- type `bootsel` on the management console (`reboot` for a plain restart);
- open either CDC port at 1200 baud: `stty -f /dev/cu.usbmodem<n> 1200`
  (Linux: `stty -F /dev/ttyACM0 1200`);
- `picotool reboot -f -u` (needs a USB-capable picotool, e.g. `brew install picotool`).

A typical development loop is then:

```sh
cmake --build build \
  && stty -f /dev/cu.usbmodem* 1200 ; sleep 2 \
  && cp build/pico-wg-dongle.uf2 /Volumes/RP2350/
```

The bench firmware honors the 1200-baud reset too (via pico_stdio_usb).

## Provisioning

The device enumerates three USB functions: the network interface plus two
CDC-ACM serial ports — a management console and a debug console. Open the
first serial port (e.g. `screen /dev/ttyACM0`) and press Enter for the status
view. Then:

```
set ssid MyUpstreamNet
set pass wifi-password
genkey
set peer <server public key, base64>
set endpoint vpn.example.com 51820
set addr 10.66.0.249/30
set hostip 10.66.0.250
set dns 10.66.0.1
set keepalive 25
save
```

`genkey` creates the device's identity from the RP2350 hardware TRNG and
prints **only the public key** (reprint it anytime with `pubkey`; it also
appears in the status view) — the private key is written to the config and
never leaves the device. Give the public key to the WireGuard admin; they hand
back the address pair and endpoint. To import an identity generated elsewhere
instead, `set key <private key, base64>`.

`scan` / `join <n>` browse nearby networks; `set psk <key>` adds an optional
preshared key. Every change applies live. On the server, add the peer with
AllowedIPs covering both addresses:

```
[Peer]
PublicKey  = <device public key>
AllowedIPs = 10.66.0.248/30
```

Address rules: pick a `/30` aligned block (start divisible by 4) inside your
tunnel space that overlaps no other peer's AllowedIPs; use the middle two
addresses (the host's OS applies real subnet semantics to its lease). The
endpoint may be an IPv4 literal or a hostname (resolved via the upstream
network's resolver once Wi-Fi associates — the one pre-tunnel lookup the
device makes).

LED: solid = tunnel up; slow blink = associating/handshaking; fast blink =
unprovisioned; off = USB not ready.

## Security notes

- WireGuard keys and Wi-Fi credentials are stored **unencrypted** in a flash
  sector near the top of flash (third from the end — the last sector is
  scratch space the RP2350 bootrom erases on every UF2 download, erratum
  RP2350-E10 — so the config now survives reflashing). Anyone with physical
  possession can extract them (this is true of nearly all hobby-firmware
  devices; the RP2350's OTP + secure boot could harden it later). Treat a lost
  dongle as a compromised peer and rotate keys.
- With `genkey`, the private key is generated on-device from the hardware TRNG
  and is never printed on any console or included in any status output.
- IPv4 only, end to end: the USB link runs no IPv6, so there is no v6 side
  channel around the tunnel.

## Performance expectations

USB Full Speed caps the wire at 12 Mbit/s; the parent project bridges ~4.75
Mbit/s of TCP payload without crypto. ChaCha20-Poly1305 (reference C
implementation) will cost a chunk of that. Headroom exists: the second core is
idle, and `wireguard/crypto/cortex/` carries Cortex-M assembly X25519 if
handshake latency ever matters.

## Lineage and licenses

- USB/NCM layer, console, config store, robustness scaffolding: adapted from
  [pico-usb-wifi](https://gitlab.com/baiyibai/pico-usb-wifi) (MIT) — the
  routed datapath replaces its transparent L2 bridge.
- WireGuard implementation: [wireguard-lwip](https://github.com/smartalock/wireguard-lwip)
  (BSD-3-Clause), vendored in `wireguard/` with two local additions
  (`wireguardif_shutdown`, an include-order fix).
- pico-sdk: BSD-3-Clause.

This project: MIT.
