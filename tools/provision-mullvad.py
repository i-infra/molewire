#!/usr/bin/env python3
"""Provision a freshly-flashed pico-wg-dongle against Mullvad.

Reads a Mullvad account number from a file (first argument) or stdin, has the
dongle generate its WireGuard identity on-device (the private key never exists
outside the dongle), registers the public key as a Mullvad "device" via the
app API, lets you pick a relay (country -> city -> random active server), and
configures the dongle over its USB serial console: full-gateway mode with
Mullvad's in-tunnel resolver.

The one subtle piece is addressing. Mullvad assigns each registered key a
single /32; the dongle's NAT-free design needs TWO addresses in one small
subnet (the USB host's and the dongle's own USB-side gateway address). The
assigned /32 goes to the USB HOST -- the only party whose traffic enters the
tunnel -- and the dongle's gateway address is a neighbouring address in the
smallest enclosing subnet: pure USB-link fiction that never appears on the
wire toward Mullvad (Mullvad drops non-assigned sources by crypto-routing,
and inbound traffic for the neighbour belongs to some other customer's
tunnel, not ours). Consequence: with Mullvad, the USB host is the tunnel's
one first-class client; the quarantine AP's client address cannot be covered
at the same time.

API endpoints (the ones the official apps use):
  POST /auth/v1/token            {"account_number"} -> {"access_token"}
  GET  /accounts/v1/devices      Bearer -> [{pubkey, ipv4_address, name, id}]
  POST /accounts/v1/devices      {"pubkey", "hijack_dns"} -> ditto
  DELETE /accounts/v1/devices/id (used to free a slot; 5 device max)
Relay list (public): GET https://api.mullvad.net/www/relays/wireguard/

Stdlib only (no pyserial); POSIX (macOS/Linux).
"""

import argparse
import glob
import ipaddress
import json
import os
import random
import re
import select
import sys
import termios
import time
import urllib.error
import urllib.request

MULLVAD_API = "https://api.mullvad.net"
RELAY_LIST_URL = MULLVAD_API + "/www/relays/wireguard/"
MULLVAD_DNS = "10.64.0.1"  # the in-tunnel resolver every Mullvad WG server offers
WG_PORT = 51820
CONSOLE_BAUD = termios.B115200  # NOT 1200: a 1200-baud open reboots to bootloader
BANNER = "WireGuard USB dongle configuration console"
DUMP_HEADER = "-- pico-wg-dongle"
B64_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")


def die(msg, code=1):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


# --- interactive input (stdin may be consumed by the account pipe) ----------------

def open_tty():
    try:
        return open("/dev/tty", "r")
    except OSError:
        return None


TTY = None  # set in main


def ask(prompt):
    if TTY is None:
        die("interactive choice needed but no terminal available "
            "(use --country/--city/--ssid/--pass for unattended runs)")
    print(prompt, end="", flush=True)
    line = TTY.readline()
    if not line:
        die("terminal closed")
    return line.strip()


# --- dongle serial console --------------------------------------------------------

class Console:
    """The dongle's management console: line in, quiet-window-delimited text out."""

    def __init__(self, port):
        self.port = port
        self.fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        attrs = termios.tcgetattr(self.fd)
        attrs[0] = attrs[1] = attrs[3] = 0  # raw: no echo, no line discipline
        attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
        attrs[4] = attrs[5] = CONSOLE_BAUD
        termios.tcsetattr(self.fd, termios.TCSANOW, attrs)
        time.sleep(0.3)
        self._drain()

    def close(self):
        os.close(self.fd)

    def _drain(self):
        try:
            while os.read(self.fd, 65536):
                pass
        except BlockingIOError:
            pass

    def _read_until_quiet(self, quiet_s, max_s):
        out = b""
        last = time.time()
        start = last
        while time.time() - last < quiet_s and time.time() - start < max_s:
            r, _, _ = select.select([self.fd], [], [], 0.1)
            if r:
                try:
                    d = os.read(self.fd, 65536)
                except BlockingIOError:
                    continue
                if d:
                    out += d
                    last = time.time()
        return out.decode(errors="replace")

    def cmd(self, line, quiet_s=0.9, max_s=15):
        """Send one command line, return everything printed until output goes
        quiet (the console prints a full status dump after most commands)."""
        self._drain()
        os.write(self.fd, line.encode() + b"\n")
        return self._read_until_quiet(quiet_s, max_s)


def find_console(explicit_port):
    """Locate the management console among the dongle's three CDC ports by its
    self-identifying banner / status dump."""
    candidates = ([explicit_port] if explicit_port else
                  sorted(glob.glob("/dev/cu.usbmodem*")) + sorted(glob.glob("/dev/ttyACM*")))
    if not candidates:
        die("no USB serial ports found -- is the dongle plugged in?")
    for port in candidates:
        try:
            con = Console(port)
        except OSError:
            continue
        # The banner is pushed on open; an empty line prints the status dump.
        greeting = con._read_until_quiet(0.5, 2)
        if BANNER not in greeting:
            greeting = con.cmd("")
        if BANNER in greeting or DUMP_HEADER in greeting:
            print(f"[*] dongle console: {port}")
            return con
        con.close()
    die("no pico-wg-dongle management console found among: " + ", ".join(candidates)
        + (" (is that the right port?)" if explicit_port else ""))


def console_pubkey(con, allow_genkey):
    """The device's WireGuard public key, generating the keypair on-device if
    none exists yet. The private key never crosses the wire."""
    out = con.cmd("pubkey")
    for ln in out.splitlines():
        if B64_KEY_RE.match(ln.strip()):
            return ln.strip(), False
    if not allow_genkey:
        return None, False
    print("[*] no key on the device -- generating one on-device (TRNG)")
    con.cmd("genkey", max_s=20)  # ~a second of X25519 + a tunnel re-apply
    out = con.cmd("pubkey")
    for ln in out.splitlines():
        if B64_KEY_RE.match(ln.strip()):
            return ln.strip(), True
    die("genkey did not yield a public key; console said:\n" + out)


# --- Mullvad API ------------------------------------------------------------------

def api(path, token=None, body=None, method=None):
    req = urllib.request.Request(
        MULLVAD_API + path,
        data=json.dumps(body).encode() if body is not None else None,
        method=method or ("POST" if body is not None else "GET"),
        headers={"Content-Type": "application/json", "Accept": "application/json",
                 **({"Authorization": "Bearer " + token} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            data = r.read()
            return json.loads(data) if data else {}
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read())
        except Exception:
            detail = {}
        code = detail.get("code", str(e.code))
        if e.code in (400, 401, 404) and path == "/auth/v1/token":
            die(f"Mullvad rejected the account number ({code})")
        return {"_error": code, "_status": e.code, **detail}


def mullvad_token(account):
    return api("/auth/v1/token", body={"account_number": account})["access_token"]


def mullvad_find(token, pubkey):
    """The already-registered device for this key, or None. Read-only."""
    for d in api("/accounts/v1/devices", token=token):
        if d.get("pubkey") == pubkey:
            return d
    return None


def mullvad_register(token, pubkey):
    """Return (ipv4_address_cidr, device_name), registering the key if needed."""
    devices = api("/accounts/v1/devices", token=token)
    for d in devices:
        if d.get("pubkey") == pubkey:
            print(f"[*] key already registered as Mullvad device \"{d['name']}\"")
            return d["ipv4_address"], d["name"]

    d = api("/accounts/v1/devices", token=token,
            body={"pubkey": pubkey, "hijack_dns": False})
    if d.get("_error") == "MAX_DEVICES_REACHED":
        print(f"[!] this account already has {len(devices)} devices (the maximum):")
        for i, dev in enumerate(devices):
            print(f"      {i + 1}  \"{dev['name']}\"  {dev['ipv4_address']}"
                  f"  created {dev.get('created', '?')[:10]}")
        pick = ask("revoke which to free a slot? [1-{}, empty aborts]: ".format(len(devices)))
        if not pick.isdigit() or not 1 <= int(pick) <= len(devices):
            die("aborted; revoke a device at https://mullvad.net/account and re-run")
        victim = devices[int(pick) - 1]
        api(f"/accounts/v1/devices/{victim['id']}", token=token, method="DELETE")
        print(f"[*] revoked \"{victim['name']}\"")
        d = api("/accounts/v1/devices", token=token,
                body={"pubkey": pubkey, "hijack_dns": False})
    if "_error" in d:
        die(f"Mullvad device registration failed: {d['_error']} {d}")
    print(f"[*] registered as Mullvad device \"{d['name']}\" -> {d['ipv4_address']}")
    return d["ipv4_address"], d["name"]


# --- relay selection --------------------------------------------------------------

def pick(items, label, key, preset):
    """Number-or-code prompt over a sorted unique list of (code, display)."""
    if preset:
        for code, disp in items:
            if preset.lower() in (code.lower(), disp.lower()):
                return code
        die(f"no such {label}: {preset}")
    for i, (code, disp) in enumerate(items):
        end = "\n" if i % 2 == 1 or i == len(items) - 1 else ""
        print(f"  {i + 1:3} {disp} ({code})".ljust(40), end=end)
    while True:
        got = ask(f"{label} [number or code]: ")
        if got.isdigit() and 1 <= int(got) <= len(items):
            return items[int(got) - 1][0]
        for code, _ in items:
            if got.lower() == code.lower():
                return code
        print("  ?")


def choose_relay(country, city):
    with urllib.request.urlopen(RELAY_LIST_URL, timeout=20) as r:
        relays = [x for x in json.load(r) if x.get("active")]
    countries = sorted({(x["country_code"], x["country_name"]) for x in relays},
                       key=lambda c: c[1])
    print(f"[*] {len(relays)} active WireGuard relays in {len(countries)} countries")
    cc = pick(countries, "country", "country_code", country)
    pool = [x for x in relays if x["country_code"] == cc]
    cities = sorted({(x["city_code"], x["city_name"]) for x in pool}, key=lambda c: c[1])
    if len(cities) > 1:
        cities = [("any", "(any city)")] + cities
        city_code = pick(cities, "city", "city_code", city)
        if city_code != "any":
            pool = [x for x in pool if x["city_code"] == city_code]
    relay = random.choice(pool)
    print(f"[*] relay: {relay['hostname']} ({relay['city_name']}, "
          f"{relay['country_name']}) {relay['ipv4_addr_in']} "
          f"[{'Mullvad-owned' if relay['owned'] else 'rented/' + relay['provider']}]")
    return relay


# --- addressing -------------------------------------------------------------------

def plan_addresses(assigned_cidr):
    """Mullvad hands one /32; the USB host gets it. Find the smallest enclosing
    subnet in which both it and a neighbouring dongle address are usable hosts."""
    host = ipaddress.IPv4Address(assigned_cidr.split("/")[0])
    for prefix in range(30, 23, -1):
        net = ipaddress.ip_network(f"{host}/{prefix}", strict=False)
        usable = [a for a in net.hosts()]
        if host in usable:
            for a in usable:
                if a != host:
                    return str(host), str(a), prefix
    die(f"could not find a workable subnet around {assigned_cidr}")


# --- main -------------------------------------------------------------------------

def read_account(path):
    if path:
        with open(path) as f:
            raw = f.read()
    elif sys.stdin.isatty():
        print("Mullvad account number: ", end="", flush=True)
        raw = sys.stdin.readline()
    else:
        raw = sys.stdin.read()
    account = re.sub(r"[\s-]", "", raw)
    if not account.isdigit():
        die("account number must be digits (spaces/dashes are fine)")
    if len(account) != 16:
        print(f"[!] account number is {len(account)} digits (expected 16) -- continuing")
    return account


def main():
    global TTY
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("account_file", nargs="?",
                    help="file holding the Mullvad account number (default: stdin)")
    ap.add_argument("--port", help="management console port (default: auto-detect)")
    ap.add_argument("--country", help="country name or code (skips the prompt)")
    ap.add_argument("--city", help="city name or code (skips the prompt)")
    ap.add_argument("--ssid", help="Wi-Fi SSID to configure")
    ap.add_argument("--pass", dest="password", help="Wi-Fi password")
    ap.add_argument("--force", action="store_true",
                    help="reconfigure a dongle that already has a WireGuard peer set")
    ap.add_argument("--dry-run", action="store_true",
                    help="no writes: detect the dongle, talk to Mullvad read-only, "
                         "print the console commands that would run")
    args = ap.parse_args()

    TTY = open_tty()
    account = read_account(args.account_file)
    con = find_console(args.port)

    status = con.cmd("")
    if "wg peer:    set" in status and not (args.force or args.dry_run):
        die("this dongle already has a WireGuard peer configured -- "
            "re-run with --force to overwrite (the device key is kept)")

    # Wi-Fi first: the tunnel can't come up without the uplink.
    wifi_unset = "ssid:       (unset)" in status
    ssid, password = args.ssid, args.password
    if wifi_unset and not ssid and not args.dry_run:
        ssid = ask("Wi-Fi SSID for the upstream network: ")
        password = ask("Wi-Fi password (empty = open network): ")

    pubkey, generated = console_pubkey(con, allow_genkey=not args.dry_run)
    if pubkey:
        print(f"[*] device public key: {pubkey}")
    elif args.dry_run:
        print("[*] dry-run: device has no key yet (a real run would genkey)")

    relay = choose_relay(args.country, args.city)

    token = mullvad_token(account)
    if args.dry_run:
        d = mullvad_find(token, pubkey) if pubkey else None
        if d:
            print(f"[*] dry-run: key is already Mullvad device \"{d['name']}\"")
            host_ip, dev_ip, prefix = plan_addresses(d["ipv4_address"])
        else:
            print("[*] dry-run: key not registered (a real run would register it)")
            host_ip, dev_ip, prefix = "<assigned>", "<neighbour>", "<nn>"
    else:
        assigned, _name = mullvad_register(token, pubkey)
        host_ip, dev_ip, prefix = plan_addresses(assigned)
        print(f"[*] Mullvad assigned {assigned}: host <- {host_ip}, "
              f"dongle gateway <- {dev_ip}/{prefix} (link-local fiction)")

    cmds = []
    if ssid:
        cmds.append(f"set ssid {ssid}")
        if password:
            cmds.append(f"set pass {password}")
    cmds += [
        f"set peer {relay['pubkey']}",
        f"set endpoint {relay['ipv4_addr_in']} {WG_PORT}",
        f"set addr {dev_ip}/{prefix}",
        f"set hostip {host_ip}",
        f"set dns {MULLVAD_DNS}",
        "set routes off",   # full-gateway: every host packet rides Mullvad
        "set keepalive 25",
        "save",
    ]

    if args.dry_run:
        print("[*] dry-run; would send to the console:")
        for c in cmds:
            print("      " + (c if not c.startswith("set pass") else "set pass ****"))
        return

    for c in cmds:
        out = con.cmd(c, max_s=20)
        if "ERR" in out:
            die(f"console rejected '{c}':\n{out}\n"
                "(the dongle holds partial unsaved config; 'restore' resets it)")
    print("[*] configuration saved to flash")

    # A few seconds after the last command the dongle replugs its USB link so
    # the host re-DHCPs onto the new subnet -- taking this console with it.
    # Ride through the disappearance and reopen when it re-enumerates.
    port = con.port
    print("[*] waiting for the tunnel (the USB link will briefly replug)",
          end="", flush=True)
    state = "?"
    deadline = time.time() + 90
    while time.time() < deadline:
        time.sleep(2)
        try:
            dump = con.cmd("")
        except OSError:
            print("~", end="", flush=True)
            try:
                con.close()
            except OSError:
                pass
            con = None
            for _ in range(20):
                time.sleep(1)
                try:
                    con = Console(port)
                    break
                except OSError:
                    continue
            if con is None:
                die(f"\nconsole did not come back after the replug ({port})")
            continue
        m = re.search(r"tunnel state: (\w+)", dump)
        state = m.group(1) if m else "?"
        if state == "up":
            break
        print(".", end="", flush=True)
    print(f"\n[*] tunnel state: {state}")
    if state != "up":
        print("    not up yet -- check the Wi-Fi credentials, that the account has "
              "time left, and give it a minute; status: http://pico-wg.local")
    else:
        print("    done: the USB host now egresses via " + relay["hostname"] +
              ". Check https://am.i.mullvad.net/connected from the host.")
    con.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        sys.exit(130)
