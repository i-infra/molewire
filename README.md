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
      AP client ~~802.11~~ [ap netif] ──forward──┘   (optional, one client)
```

- **No NAT.** The host's DHCP lease *is* a tunnel address. The WireGuard peer's
  AllowedIPs on the server covers a small subnet (e.g. a `/30`): one address is
  the Pico (USB-side gateway), the other is leased to the host. Packets forward
  between USB and tunnel with their addresses untouched. The optional
  quarantine AP works the same way with a second small subnet.
- **Isolation is structural, not a filter list.** An lwIP source-routing hook
  (`wg_ip4_route_hook` in `src/wg.c`) routes every *forwarded* packet either to
  its client link or into the WireGuard netif — never to the Wi-Fi station
  netif, and never between the USB host and the AP client. Before the tunnel
  exists, forwarded packets go to a blackhole. Only the Pico's own traffic
  (DHCP client, DNS lookup of the endpoint, and the tunnel's outer UDP, which
  is pinned to the station netif) can touch Wi-Fi.
- **No DNS leaks.** The device runs no DNS forwarder at all. DHCP option 6
  hands the host the tunnel-side resolver; queries ride the tunnel like any
  other packet.
- **MTU is handled, twice.** DHCP option 26 offers the host the tunnel MTU
  (1420 by default, `set mtu` to lower it), and because hosts ignore or floor
  that (macOS refuses < 1280), the dongle also rewrites the MSS option of
  forwarded TCP SYNs in both directions — so TCP fits even through servers
  that re-encapsulate (e.g. a WireGuard→Tailscale bridge, true path MTU 1216).
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

`src/wifi_config.h` (compile-time default Wi-Fi credentials, gitignored) must
exist; copy `src/wifi_config.h.example` and leave it blank to build an
unprovisioned image. Prebuilt `.uf2` files: every push to `main` builds them
as a GitHub Actions artifact, and every `v*` tag publishes them (plus
`SHA256SUMS`) as a GitHub Release.

### Reflashing without touching the board

Once this firmware (or the bench) is running, the button is never needed again —
three ways to land back in the UF2 bootloader:

- type `bootsel` on the management console (`reboot` for a plain restart);
- open either console CDC port at 1200 baud: `stty -f /dev/cu.usbmodem<n> 1200`
  (Linux: `stty -F /dev/ttyACM0 1200`; the serial-bridge port is exempt —
  1200 baud is a legitimate rate there);
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
and status page served by the device itself. (The device also carries a
WebUSB landing-page descriptor naming that URL; Chromium-family browsers
*may* prompt "Go to pico-wg.local" at plug-in, but current builds often ship
that notification disabled, so don't count on it.) Press *scan for networks*
and pick the upstream Wi-Fi from the list (a password prompt appears only for
secured networks it doesn't know; typing an SSID is only ever needed for a
hidden one). Then press *generate keypair*, give the shown public key to your
WireGuard admin, enter the address pair and endpoint they hand back, *apply*,
*save*. The page also shows live status (tunnel state, lease, USB counters)
and has a console box that accepts every serial-console command.

#### Saved networks and auto-join

The dongle remembers the **8 most recently used networks** (least recently
used is evicted) and needs no reconfiguration to move between them: whenever
the uplink is down it scans, matches the results against the saved list, and
joins the strongest known network — preferring the one that last worked,
skipping any that rejected its password (marked *bad password?* in the UIs
and retried after 10 minutes), and periodically blind-trying saved networks
absent from the scan so hidden SSIDs keep working. A network joined once is
persisted automatically the moment the join succeeds; roaming between
already-saved networks never writes flash.

Reachability is engineered to survive any config state:

- The USB link always carries an IPv6 **link-local** address (the portal's
  permanent home), and an mDNS responder answers `pico-wg.local` (A + AAAA) on
  the USB link only — no host DNS or routing configuration is touched, ever.
- Unprovisioned, the device additionally leases the host `172.31.255.2/30`
  with **no router, no routes, no DNS** (a bring-up island): the portal is
  also at `http://172.31.255.1/` and the host's own connectivity is
  unaffected. Once provisioned, the island is replaced by the tunnel
  addressing; `pico-wg.local` follows automatically, and the device replugs
  itself (a brief USB bounce) so the host re-DHCPs onto the new subnet
  without any manual step.
- The portal is refused to connections arriving from anywhere but the USB
  link (same trust boundary as the serial console), and the private key is
  never included in any page, API response, or console output.

### Mullvad, scripted

`tools/provision-mullvad.py` takes a freshly-flashed dongle to a working
Mullvad tunnel in one run: it prompts for the upstream Wi-Fi, has the dongle
`genkey` (the private key never leaves it), registers the public key as a
Mullvad device via the app API, prompts country → city and picks a random
active relay, and configures full-gateway mode with Mullvad's in-tunnel DNS.
The account number comes from a file argument or stdin; `--dry-run` previews
without writing anything (to the dongle or to Mullvad).

```sh
python3 tools/provision-mullvad.py ~/.mullvad-account
# or: echo "1234 5678 9012 3456" | python3 tools/provision-mullvad.py
```

Addressing subtlety, since Mullvad assigns one `/32` per device: that address
goes to the **USB host** (the only party whose packets enter the tunnel), and
the dongle's USB-side gateway address is a neighbouring address in the
smallest enclosing subnet — link-local fiction that never appears on the wire
toward Mullvad. This also means the USB host is the tunnel's one first-class
client under Mullvad; the quarantine AP's client can't be covered by the same
`/32` (point `apclient` at the assigned address *instead of* `hostip` if the
AP client is the one you want tunnelled). Accounts hold at most 5 devices;
the script offers to revoke one interactively when the limit is hit.

### tailguard, scripted

`tools/provision-tailguard.py` does the same against a self-hosted
WireGuard→tailnet bridge: it allocates the next free `/30` from the bridge's
`wg0.conf` over ssh, registers the dongle's public key as a peer (hot-added
with `wg set`, so existing tunnels don't blip), and configures the dongle in
split mode. It is written for one specific deployment; treat it as a template.

### The serial console

The device enumerates the network interface, three CDC-ACM serial ports — the
management console, a debug-diagnostics stream (`set debug on`), and the
serial bridge (below) — and a WebUSB vendor interface. Open the first serial
port (e.g. `screen /dev/ttyACM0`) and press Enter for the status view. Then:

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

`scan` / `join <n>` browse nearby networks (known ones are marked `[saved]`,
`[connected]`, `[open]`, or `[saved, bad password?]`), and `join <ssid>` joins
by name; `set psk <key>` adds an optional preshared key. Every change applies
live. On the server, add the peer with AllowedIPs covering both addresses:

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
device makes). The full command reference lives in `src/config_proto.h`.

### Gateway vs split-tunnel mode

By default the host is offered the dongle as its **default router** (DHCP
option 3): all host traffic rides the tunnel — the VPN-appliance mode. That
also means the dongle takes over the host's default route and (if `set dns`
is configured) its resolver, which you may not want on your daily machine.

`set routes <cidr>[,<cidr>...]` (max 4) switches to **split mode**: no router
option; only the listed subnets are pushed as classless static routes via the
dongle (DHCP option 121), so the host keeps its own default route and DNS
while the VPN subnets ride the tunnel. `set dns off` keeps the host's
resolver in either mode; `set routes off` returns to full-gateway. When the
server re-encapsulates (e.g. bridges into Tailscale), also `set mtu` to the
true path MTU — the dongle then advertises it via DHCP *and* clamps forwarded
TCP MSS, which is what actually prevents black-holed connections.

LED: solid = tunnel up; slow blink = associating/handshaking; fast blink =
unprovisioned; off = USB not ready.

## Quarantine access point

The CYW43 can run an access point alongside its station uplink: **one**
wireless client DHCPs a tunnel address and is routed through WireGuard
exactly like the USB host — and nowhere else. The route hook confines
AP-sourced packets to the tunnel (blackholed before it exists) and denies
AP↔USB-host cross-talk in both directions; there is no path to your LAN
because the route structurally does not exist, not because a filter blocks
it. That makes it a bring-up pen for untrusted devices — point the tunnel at
a commercial VPN endpoint and an IoT gadget gets internet with zero
visibility of your network — and `pcap on` captures the AP link too, so you
can watch exactly what the contained device does.

Configure from the portal's AP card or the console:

```
set apssid quarantine
set appass <8-63 chars>        # WPA2 only; an open AP is refused
set apaddr 10.66.0.253/30      # device's AP-link address (tunnel space)
set apclient 10.66.0.254       # the one client's address
set ap on                      # (set ap off to stop)
save
```

Like the USB pair, the AP pair must be covered by the server peer's
AllowedIPs. Single-client is enforced three ways — the radio caps
associations at one (`maxassoc`), the DHCP scope holds one lease, and the
subnet is tiny — which is what keeps the whole device NAT-free.

Physics disclaimer: AP and station share one radio (the AP always follows the
station's channel), so every forwarded packet pays airtime and the gSPI bus
twice. Expect roughly half the USB path's throughput; this feature is about
isolation, not speed.

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
disabled on this port only). Port 2323 is a raw stream; dead clients are
reaped by TCP keepalive in about a minute. This port deliberately prints no
banner: the stream stays byte-clean.

Port **3323** speaks telnet + **RFC 2217** (COM-PORT-CONTROL): remote clients
can set the UART baud/format and toggle DTR/RTS, which drive **GP7/GP6**
(asserted = driven low). Wire GP6 → ESP32 EN and GP7 → IO0 and esptool's
auto-reset works across the VPN:

```sh
esptool --port rfc2217://<device-tunnel-ip>:3323 flash_id
```

## Packet capture

`pcap on` (console or portal button) records the USB link — both directions,
after checksum repair, i.e. the plaintext side of the tunnel — and the
quarantine AP link into a 64 KB RAM ring (snaplen 256, oldest evicted). Download it as a Wireshark-ready file
from `/api/pcap`; timestamps are seconds-since-boot. This is the tool for
"the host says it sent X, what did the dongle actually see" questions.

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
- The quarantine AP is WPA2-PSK only (an open AP would hand the tunnel to
  anyone in radio range — the console refuses it), and its client can reach
  the tunnel and nothing else: not the LAN, not the USB host, not the config
  portal or serial bridge (both accept connections from their own links only).
- IPv6 exists **only** as link-local on the USB link (it is the portal's
  stable address) and is deliberately unroutable: the Wi-Fi station netif has
  its auto-created v6 address stripped and SLAAC disabled, and v6 forwarding
  is off — so there is still no v6 side channel around the (v4) tunnel; v6
  packets can reach the device itself and nothing beyond.

## Performance (measured)

USB Full Speed caps the wire at 12 Mbit/s and is the bottleneck by a wide
margin. Measured end to end (Mac → dongle → WireGuard → Tailscale-bridged
server → tailnet): **4.65 Mbit/s** of TCP payload ≈ 98% of the no-crypto L2
bridge baseline — the crypto is effectively free at USB FS rates. On-device
bench (`pico-wg-bench.uf2`): ChaCha20-Poly1305 37.3 Mbit/s at 1420 B (~32
cycles/byte), X25519 14.2 ms/op (reference C), rekey stall ~56 ms every ~2
minutes. The Cortex-M0 assembly X25519 in `wireguard/crypto/cortex/` measured
65% *slower* than the C on the M33 — don't use it. Remaining headroom if it
ever matters: the second core is idle.

## Lineage and licenses

- USB/NCM layer, console, config store, robustness scaffolding: adapted from
  [pico-usb-wifi](https://gitlab.com/baiyibai/pico-usb-wifi) (MIT) — the
  routed datapath replaces its transparent L2 bridge.
- WireGuard implementation: [wireguard-lwip](https://github.com/smartalock/wireguard-lwip)
  (BSD-3-Clause), vendored in `wireguard/` with four local patches:
  `wireguardif_shutdown`, an include-order fix, restoring zeroed L4 checksums
  before encryption (`CHECKSUM_GEN_TCP/UDP/ICMP` are off in `lwipopts.h` so
  lwIP 2.2's `ip4_forward` leaves transit checksums alone — it would otherwise
  zero them expecting a hardware NIC to refill; locally originated packets
  then leave the stack with checksum 0 and each egress link repairs them),
  and dual-stack (`LWIP_IPV6`) type fixes.
- pico-sdk: BSD-3-Clause.

This project: MIT.

## Development

- `make -C tests test` — 69 host-side tests: RFC-vector-anchored crypto
  primitives (independent ChaCha20 reference, BLAKE2s, Poly1305, X25519),
  AEAD cross-verification, base64, the Wi-Fi candidate-ordering logic, and a
  full two-device in-memory handshake. `tests/fake_lwip/` stubs make
  `wireguard.c` compile on the host. CI (`.github/workflows/build.yml`) runs
  these and the firmware build on every push.
- `build/pico-wg-bench.uf2` — on-device crypto/throughput bench (separate
  firmware; prints over USB serial and UART).
- The portal page is `web/index.html`, gzipped into the firmware at build
  time by `tools/gen_web_page.py`.
- `site/index.html` is the static https entry page the WebUSB landing
  descriptor points at (host it anywhere static, e.g. GitHub Pages); it just
  navigates to the on-device portal.
