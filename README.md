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

### The portal (the easy way)

Plug the dongle in and browse to **http://pico-wg.local** — a configuration
and status page served by the device itself (Chromium-family browsers on
macOS/Linux even prompt "Go to pico-wg.local" at plug-in, via a WebUSB
landing-page descriptor). Fill in Wi-Fi and WireGuard settings, press
*generate keypair*, give the shown public key to your WireGuard admin, enter
the address pair and endpoint they hand back, *apply*, *save*. The page also
shows live status (tunnel state, lease, USB counters) and has a console box
that accepts every serial-console command.

Reachability is engineered to survive any config state:

- The USB link always carries an IPv6 **link-local** address (the portal's
  permanent home), and an mDNS responder answers `pico-wg.local` (A + AAAA) on
  the USB link only — no host DNS or routing configuration is touched, ever.
- Unprovisioned, the device additionally leases the host `172.31.255.2/30`
  with **no router, no routes, no DNS** (a bring-up island): the portal is
  also at `http://172.31.255.1/` and the host's own connectivity is
  unaffected. Once provisioned, the island is replaced by the tunnel
  addressing; `pico-wg.local` follows automatically.
- The portal is refused to connections arriving from anywhere but the USB
  link (same trust boundary as the serial console), and the private key is
  never included in any page, API response, or console output.

### The serial console

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

## Serial party line

The third CDC-ACM port is a raw byte channel with three endpoints bridged
together: the USB host's tty, hardware **UART1 on GP4 (TX) / GP5 (RX)**, and
a single-client **TCP socket on port 2323** at the device's addresses —
reachable from the WireGuard side (and the USB link, for loopback), never
from Wi-Fi. Bytes from any endpoint fan out to the other two:

- Wire GP4/GP5 to a target's console (3.3 V!) and both the USB host and any
  tunnel peer (`nc <device-tunnel-ip> 2323`) can talk to it — a network
  serial adapter that lives inside your VPN.
- Leave the pins unwired and it's an out-of-band serial channel between the
  USB host and the tunnel network.

The host's line coding sets the physical UART: `stty -f /dev/cu.usbmodemXXX7
9600` retunes the pins (default 115200 8N1; the 1200-baud bootloader touch is
disabled on this port only). The TCP side is a raw stream — no telnet/RFC2217
negotiation — and dead clients are reaped by TCP keepalive in about a minute.
This port deliberately prints no banner: the stream stays byte-clean.

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
- IPv6 exists **only** as link-local on the USB link (it is the portal's
  stable address) and is deliberately unroutable: the Wi-Fi station netif has
  its auto-created v6 address stripped and SLAAC disabled, and v6 forwarding
  is off — so there is still no v6 side channel around the (v4) tunnel; v6
  packets can reach the device itself and nothing beyond.

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
