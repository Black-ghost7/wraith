#!/usr/bin/env python3
"""WRAITH - route system traffic through Tor with a terminal interface.

Starts its own Tor instance, redirects TCP and DNS traffic to it with iptables,
and blocks everything else (kill switch). Standard library only.
For education and authorized testing only.
"""

import argparse
import collections
import ipaddress
import json
import os
import pwd
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request

try:
    import readline  # noqa: F401  (line editing in the menu prompt)
except ImportError:
    pass

VERSION = "2.0.0"
AUTHOR = "Black-ghost7"
REPO = "https://github.com/Black-ghost7/wraith"

ETC_DIR = "/etc/wraith"
DATA_DIR = "/var/lib/wraith"
RUN_DIR = "/run/wraith"
LOG_DIR = "/var/log/wraith"
TORRC = ETC_DIR + "/torrc"
CONFIG = ETC_DIR + "/config.json"
PIDFILE = RUN_DIR + "/tor.pid"
COOKIE = DATA_DIR + "/control_auth_cookie"

TRANS_PORT = 9040
DNS_PORT = 5300
SOCKS_PORT = 9150
CONTROL_PORT = 9151
VIRTUAL_NET = "10.192.0.0/10"

NAT_CHAIN = "WRAITH_NAT"
OUT_CHAIN = "WRAITH_OUT"
OUT6_CHAIN = "WRAITH_OUT6"
TOR_USERS = ("debian-tor", "tor", "_tor")

COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ
DRY = False

BANNER = """\
██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗
██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║
██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║
██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║
╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║
 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝"""

COUNTRIES = {
    "AT": "Austria", "AU": "Australia", "BE": "Belgium", "BG": "Bulgaria",
    "BR": "Brazil", "CA": "Canada", "CH": "Switzerland", "CL": "Chile",
    "CZ": "Czechia", "DE": "Germany", "DK": "Denmark", "EE": "Estonia",
    "ES": "Spain", "FI": "Finland", "FR": "France", "GB": "United Kingdom",
    "HK": "Hong Kong", "HR": "Croatia", "HU": "Hungary", "IE": "Ireland",
    "IN": "India", "IS": "Iceland", "IT": "Italy", "JP": "Japan",
    "KR": "South Korea", "LT": "Lithuania", "LU": "Luxembourg", "LV": "Latvia",
    "MD": "Moldova", "NL": "Netherlands", "NO": "Norway", "NZ": "New Zealand",
    "PL": "Poland", "PT": "Portugal", "RO": "Romania", "RS": "Serbia",
    "SE": "Sweden", "SG": "Singapore", "SK": "Slovakia", "UA": "Ukraine",
    "US": "United States", "ZA": "South Africa",
}

TorUser = collections.namedtuple("TorUser", "pw_name pw_uid")


class WraithError(Exception):
    pass


# ---------------------------------------------------------------- output

def paint(code, text):
    return "\033[%sm%s\033[0m" % (code, text) if COLOR else text


def yellow(text):
    return paint("93", text)


def red(text):
    return paint("91", text)


def gray(text):
    return paint("90", text)


def ok(msg):
    print("%s %s" % (yellow("[+]"), msg))


def info(msg):
    print("%s %s" % (yellow("[*]"), msg))


def warn(msg):
    print("%s %s" % (red("[!]"), msg))


def fail(msg):
    print("%s %s" % (red("[-]"), msg))


def clear_screen():
    if COLOR:
        print("\033[2J\033[H", end="")


def rule():
    return red("═" * 46)


# ---------------------------------------------------------------- system

def run(cmd, check=True):
    if DRY:
        print(gray("    $ " + " ".join(cmd)))
        return subprocess.CompletedProcess(cmd, 0, "", "")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        raise WraithError("command not found: " + cmd[0])
    if check and proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()
        raise WraithError("%s failed: %s" % (" ".join(cmd), detail))
    return proc


def write_file(path, text, mode=0o644):
    if DRY:
        print(gray("    write " + path))
        return
    with open(path, "w") as handle:
        handle.write(text)
    os.chmod(path, mode)


def load_config():
    try:
        with open(CONFIG) as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_config(cfg):
    os.makedirs(ETC_DIR, exist_ok=True)
    write_file(CONFIG, json.dumps(cfg))


def tor_user():
    for name in TOR_USERS:
        try:
            entry = pwd.getpwnam(name)
            return TorUser(entry.pw_name, entry.pw_uid)
        except KeyError:
            continue
    if DRY:
        return TorUser("debian-tor", 0)
    raise WraithError("no Tor system user found. Is the tor package installed?")


def require_tools():
    for tool in ("tor", "iptables"):
        if not shutil.which(tool):
            raise WraithError("'%s' is not installed. Run install.sh first." % tool)


def prepare_dirs(user):
    plan = (
        (ETC_DIR, 0o755, False),
        (DATA_DIR, 0o700, True),
        (RUN_DIR, 0o755, True),
        (LOG_DIR, 0o755, True),
    )
    for path, mode, owned in plan:
        if DRY:
            print(gray("    mkdir -p " + path))
            continue
        os.makedirs(path, exist_ok=True)
        os.chmod(path, mode)
        if owned:
            shutil.chown(path, user=user.pw_name)


def build_torrc(user_name, country):
    lines = [
        "User " + user_name,
        "DataDirectory " + DATA_DIR,
        "PidFile " + PIDFILE,
        "Log notice file " + LOG_DIR + "/tor.log",
        "RunAsDaemon 1",
        "SocksPort 127.0.0.1:%d" % SOCKS_PORT,
        "ControlPort 127.0.0.1:%d" % CONTROL_PORT,
        "CookieAuthentication 1",
        "AvoidDiskWrites 1",
        "VirtualAddrNetworkIPv4 " + VIRTUAL_NET,
        "AutomapHostsOnResolve 1",
        "TransPort 127.0.0.1:%d" % TRANS_PORT,
        "DNSPort 127.0.0.1:%d" % DNS_PORT,
    ]
    if country:
        lines.append("ExitNodes {%s}" % country)
        lines.append("StrictNodes 1")
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------- tor

def tor_pid():
    try:
        with open(PIDFILE) as handle:
            pid = int(handle.read().strip())
        with open("/proc/%d/comm" % pid) as handle:
            if handle.read().strip() == "tor":
                return pid
    except (OSError, ValueError):
        pass
    return None


def stop_tor():
    pid = tor_pid()
    if DRY:
        print(gray("    $ stop the WRAITH Tor process (SIGTERM)"))
        return
    if pid is None:
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    for _ in range(50):
        time.sleep(0.2)
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


class Control:
    """Minimal Tor control-port client (cookie authentication)."""

    def __enter__(self):
        deadline = time.time() + 30
        last = None
        while time.time() < deadline:
            try:
                with open(COOKIE, "rb") as handle:
                    cookie = handle.read().hex()
                self.sock = socket.create_connection(("127.0.0.1", CONTROL_PORT), timeout=15)
                self.rf = self.sock.makefile("r", encoding="utf-8", newline="")
                self.cmd("AUTHENTICATE " + cookie)
                return self
            except (OSError, WraithError) as err:
                last = err
                self._close()
                time.sleep(0.5)
        raise WraithError("cannot reach the Tor control port: %s" % last)

    def __exit__(self, *exc):
        self._close()

    def _close(self):
        for name in ("rf", "sock"):
            obj = getattr(self, name, None)
            if obj is not None:
                try:
                    obj.close()
                except OSError:
                    pass
            setattr(self, name, None)

    def cmd(self, line):
        self.sock.sendall((line + "\r\n").encode())
        status = None
        out = []
        while True:
            raw = self.rf.readline()
            if not raw:
                raise WraithError("Tor control connection closed")
            raw = raw.rstrip("\r\n")
            if len(raw) < 4:
                continue
            code, sep, text = raw[:3], raw[3], raw[4:]
            if status is None:
                status = code
            out.append(text)
            if sep == " ":
                break
        if status != "250":
            raise WraithError("Tor replied: " + " ".join(out))
        return out


def wait_bootstrap(timeout=120):
    deadline = time.time() + timeout
    last = -1
    with Control() as ctl:
        while time.time() < deadline:
            lines = ctl.cmd("GETINFO status/bootstrap-phase")
            match = re.search(r"PROGRESS=(\d+)", " ".join(lines))
            pct = int(match.group(1)) if match else 0
            if pct != last:
                last = pct
                bar = "#" * (pct // 5) + "-" * (20 - pct // 5)
                print("\r%s Bootstrapping Tor [%s] %3d%%" % (yellow("[*]"), bar, pct),
                      end="", flush=True)
            if pct >= 100:
                print()
                return
            time.sleep(1)
    print()
    raise WraithError("Tor did not finish bootstrapping in time (see %s/tor.log)" % LOG_DIR)


def exit_info():
    """Ask check.torproject.org which exit we use; look up its country offline."""
    request = urllib.request.Request(
        "https://check.torproject.org/api/ip",
        headers={"User-Agent": "wraith/" + VERSION},
    )
    with urllib.request.urlopen(request, timeout=30) as reply:
        data = json.load(reply)
    ip = str(ipaddress.ip_address(str(data.get("IP", ""))))
    is_tor = bool(data.get("IsTor"))
    country = None
    try:
        with Control() as ctl:
            lines = ctl.cmd("GETINFO ip-to-country/" + ip)
            match = re.search(r"=(\w+)", lines[0])
            if match and match.group(1) != "??":
                country = match.group(1).upper()
    except WraithError:
        pass
    return ip, is_tor, country


# -------------------------------------------------------------- firewall

def ipt(*args, v6=False, check=True):
    return run(["ip6tables" if v6 else "iptables", "-w"] + list(args), check=check)


def is_active():
    if DRY:
        return False
    try:
        return ipt("-t", "nat", "-C", "OUTPUT", "-j", NAT_CHAIN, check=False).returncode == 0
    except WraithError:
        return False


def ipv6_blocked():
    if DRY or not shutil.which("ip6tables"):
        return False
    return ipt("-C", "OUTPUT", "-j", OUT6_CHAIN, v6=True, check=False).returncode == 0


def cleanup_rules():
    targets = (
        ("nat", NAT_CHAIN, False),
        ("filter", OUT_CHAIN, False),
        ("filter", OUT6_CHAIN, True),
    )
    for table, chain, v6 in targets:
        exe = "ip6tables" if v6 else "iptables"
        if not DRY and not shutil.which(exe):
            continue
        for _ in range(5):
            proc = ipt("-t", table, "-D", "OUTPUT", "-j", chain, v6=v6, check=False)
            if proc.returncode != 0 or DRY:
                break
        ipt("-t", table, "-F", chain, v6=v6, check=False)
        ipt("-t", table, "-X", chain, v6=v6, check=False)


def backup_rules():
    for exe, name in (("iptables-save", "iptables.backup"),
                      ("ip6tables-save", "ip6tables.backup")):
        if DRY:
            print(gray("    $ %s > %s/%s" % (exe, ETC_DIR, name)))
        elif shutil.which(exe):
            proc = run([exe], check=False)
            if proc.returncode == 0:
                write_file("%s/%s" % (ETC_DIR, name), proc.stdout, 0o600)


def apply_rules(uid):
    uid = str(uid)
    ipt("-t", "nat", "-N", NAT_CHAIN)
    nat = ["-t", "nat", "-A", NAT_CHAIN]
    ipt(*nat, "-m", "owner", "--uid-owner", uid, "-j", "RETURN")
    ipt(*nat, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", str(DNS_PORT))
    ipt(*nat, "-d", VIRTUAL_NET, "-p", "tcp", "-j", "REDIRECT", "--to-ports", str(TRANS_PORT))
    ipt(*nat, "-d", "127.0.0.0/8", "-j", "RETURN")
    ipt(*nat, "-p", "tcp", "--syn", "-j", "REDIRECT", "--to-ports", str(TRANS_PORT))
    ipt("-t", "nat", "-I", "OUTPUT", "1", "-j", NAT_CHAIN)

    ipt("-N", OUT_CHAIN)
    out = ["-A", OUT_CHAIN]
    # After the NAT redirect the packet keeps its original output interface in
    # the filter table, so accept by destination (127.0.0.0/8 never leaves the host).
    ipt(*out, "-d", "127.0.0.0/8", "-j", "ACCEPT")
    ipt(*out, "-o", "lo", "-j", "ACCEPT")
    ipt(*out, "-m", "owner", "--uid-owner", uid, "-j", "ACCEPT")
    ipt(*out, "-p", "udp", "--sport", "68", "--dport", "67", "-j", "ACCEPT")
    ipt(*out, "-j", "REJECT")
    ipt("-I", "OUTPUT", "1", "-j", OUT_CHAIN)

    if DRY or shutil.which("ip6tables"):
        ipt("-N", OUT6_CHAIN, v6=True)
        ipt("-A", OUT6_CHAIN, "-d", "::1/128", "-j", "ACCEPT", v6=True)
        ipt("-A", OUT6_CHAIN, "-o", "lo", "-j", "ACCEPT", v6=True)
        ipt("-A", OUT6_CHAIN, "-j", "REJECT", v6=True)
        ipt("-I", "OUTPUT", "1", "-j", OUT6_CHAIN, v6=True)
    else:
        warn("ip6tables not found: IPv6 is NOT blocked. Disable IPv6 manually.")


# --------------------------------------------------------------- actions

def normalize_country(code):
    value = code.strip().lower()
    if value in ("", "any", "none", "off", "random"):
        return None
    if value.upper() not in COUNTRIES:
        raise WraithError("unknown country code '%s'. Use the menu to see the list." % code)
    return value


def country_label(code):
    if not code:
        return "any"
    return "%s (%s)" % (COUNTRIES.get(code.upper(), code.upper()), code.upper())


def start(country=None):
    if not DRY:
        require_tools()
    user = tor_user()
    cfg = load_config()
    chosen = normalize_country(country) if country is not None else cfg.get("country")
    if is_active():
        info("Protection is already ON. Use 'wraith status' to inspect it.")
        return
    info("Preparing Tor (exit country: %s)" % country_label(chosen))
    prepare_dirs(user)
    stop_tor()
    write_file(TORRC, build_torrc(user.pw_name, chosen))
    run(["tor", "--verify-config", "-f", TORRC])
    run(["tor", "-f", TORRC])
    try:
        if DRY:
            print(gray("    (wait for Tor to bootstrap)"))
        else:
            wait_bootstrap()
        info("Applying firewall rules (kill switch)")
        cleanup_rules()
        backup_rules()
        apply_rules(user.pw_uid)
    except (Exception, KeyboardInterrupt):
        cleanup_rules()
        stop_tor()
        raise
    if DRY:
        return
    cfg["country"] = chosen
    save_config(cfg)
    ok("Protection ON: TCP and DNS go through Tor, everything else is blocked")
    try:
        ip, is_tor, cc = exit_info()
        if is_tor:
            ok("Verified by check.torproject.org: exit IP %s (%s)" % (ip, cc or "country unknown"))
        else:
            warn("check.torproject.org says this connection is NOT using Tor (%s). "
                 "Run 'wraith stop' and investigate." % ip)
    except (OSError, ValueError, WraithError) as err:
        warn("Protection is ON, but the Tor check could not complete: %s" % err)


def stop():
    info("Removing WRAITH firewall rules")
    cleanup_rules()
    info("Stopping Tor")
    stop_tor()
    ok("Protection OFF: normal network restored")


def status():
    if not is_active():
        ok("Protection   %s" % red("OFF"))
        cfg = load_config()
        info("Exit country configured for next start: %s" % country_label(cfg.get("country")))
        return
    pid = tor_pid()
    ok("Protection   %s" % yellow("ON"))
    ok("Tor process  %s" % ("running (pid %d)" % pid if pid else red("NOT running")))
    ok("Kill switch  active (non-Tor traffic is rejected)")
    ok("IPv6         %s" % ("blocked" if ipv6_blocked() else red("not blocked")))
    ok("Exit country configured: %s" % country_label(load_config().get("country")))
    try:
        ip, is_tor, cc = exit_info()
        ok("Exit IP      %s (%s)" % (ip, cc or "country unknown"))
        if is_tor:
            ok("Tor check    passed")
        else:
            warn("Tor check    FAILED: traffic is not leaving through Tor")
    except (OSError, ValueError, WraithError) as err:
        warn("Tor check could not complete: %s" % err)


def new_identity():
    if not is_active():
        raise WraithError("Protection is OFF. Start it first.")
    with Control() as ctl:
        ctl.cmd("SIGNAL NEWNYM")
    ok("New Tor identity requested (Tor allows this about once every 10 seconds)")


def set_country(code):
    chosen = normalize_country(code)
    cfg = load_config()
    cfg["country"] = chosen
    save_config(cfg)
    if not is_active():
        ok("Exit country saved: %s. It applies on the next start." % country_label(chosen))
        return
    with Control() as ctl:
        if chosen:
            ctl.cmd('SETCONF ExitNodes="{%s}" StrictNodes=1' % chosen)
        else:
            ctl.cmd("RESETCONF ExitNodes StrictNodes")
        ctl.cmd("SIGNAL NEWNYM")
    ok("Exit country set to %s. New connections use it." % country_label(chosen))
    if chosen:
        warn("If Tor cannot find an exit there, connections will fail until you pick 'any'.")


def rotate(seconds):
    if seconds < 15:
        raise WraithError("minimum interval is 15 seconds")
    if not is_active():
        raise WraithError("Protection is OFF. Start it first.")
    info("New identity every %d s. Press Ctrl+C to stop. Open sessions will break." % seconds)
    count = 0
    try:
        while True:
            with Control() as ctl:
                ctl.cmd("SIGNAL NEWNYM")
            count += 1
            ok("Identity #%d at %s" % (count, time.strftime("%H:%M:%S")))
            time.sleep(seconds)
    except KeyboardInterrupt:
        print()
        info("Rotation stopped. Protection stays ON.")


def about():
    print(yellow("WRAITH v%s" % VERSION))
    print("Route system traffic through Tor: transparent proxy, DNS through Tor,")
    print("kill switch, IPv6 blocked, exit country selection.")
    print()
    print("Author : %s" % AUTHOR)
    print("Source : %s" % REPO)
    print()
    print(red("For education and authorized testing only."))
    print("Tor does not make you anonymous on its own: browser fingerprints and")
    print("logging in to real accounts can still identify you.")


# ------------------------------------------------------------------ menu

MENU = (
    ("1", "Start", "Route all traffic via Tor"),
    ("2", "Stop", "Restore normal network"),
    ("3", "Exit country", "Choose where you exit"),
    ("4", "New identity", "Fresh Tor circuit"),
    ("5", "Status", "Real IP and leak check"),
    ("6", "About", "Version and usage"),
)


def prompt_text():
    if COLOR:
        return "\001\033[91m\002wraith\001\033[0m\002 \001\033[93m\002>\001\033[0m\002 "
    return "wraith > "


def show_menu():
    clear_screen()
    print(yellow(BANNER))
    print(rule())
    print(yellow(" Tor traffic router  |  v%s  |  %s" % (VERSION, AUTHOR)))
    print(rule())
    print()
    active = is_active()
    state = yellow("PROTECTION ON") if active else red("PROTECTION OFF")
    chosen = load_config().get("country")
    print("%s %s%s" % (red("[+]"), yellow("Status      "), state))
    print("%s %s%s" % (red("[+]"), yellow("Exit        "),
                       gray(country_label(chosen) if chosen else "not set")))
    print()
    for key, label, desc in MENU:
        print("%s %s%s" % (red("[%s]" % key), yellow(label.ljust(14)), gray(desc)))
    print("%s %s" % (red("[0]"), yellow("Exit")))
    print()


def pause():
    try:
        input(gray("Press Enter to continue..."))
    except (EOFError, KeyboardInterrupt):
        print()


def flow_country():
    items = ["%s %-15s" % (code, name) for code, name in sorted(COUNTRIES.items())]
    for i in range(0, len(items), 4):
        print("  " + "".join(yellow(item[:2]) + item[2:] for item in items[i:i + 4]))
    print()
    print(gray("Availability depends on the exit relays Tor has right now."))
    code = input("Country code, or 'any': ")
    set_country(code)


def main_menu():
    actions = {
        "1": start,
        "2": stop,
        "3": flow_country,
        "4": new_identity,
        "5": status,
        "6": about,
    }
    while True:
        show_menu()
        try:
            choice = input(prompt_text()).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if choice == "0":
            if is_active():
                warn("Protection stays ON. Run 'sudo wraith stop' to turn it off.")
            break
        action = actions.get(choice)
        if action is None:
            fail("Invalid choice")
            time.sleep(1)
            continue
        print()
        try:
            action()
        except WraithError as err:
            fail(str(err))
        except KeyboardInterrupt:
            print()
            warn("Interrupted")
        print()
        pause()


# ------------------------------------------------------------------- cli

def build_parser():
    parser = argparse.ArgumentParser(
        prog="wraith",
        description="Route system traffic through Tor. Run without a command for the menu.",
        epilog="For education and authorized testing only.",
    )
    parser.add_argument("--version", action="version", version="wraith " + VERSION)
    parser.add_argument("--no-color", action="store_true", help="disable colors")
    parser.add_argument("--dry-run", action="store_true",
                        help="with start/stop: print the system commands without running them")
    sub = parser.add_subparsers(dest="command")
    start_p = sub.add_parser("start", help="turn protection on")
    start_p.add_argument("-c", "--country", help="exit country code (e.g. de) or 'any'")
    sub.add_parser("stop", help="turn protection off and restore the network")
    sub.add_parser("status", help="show state, exit IP and a Tor check")
    sub.add_parser("newid", help="request a new Tor identity")
    country_p = sub.add_parser("country", help="set the exit country")
    country_p.add_argument("code", help="country code (e.g. de) or 'any'")
    rotate_p = sub.add_parser("rotate", help="new identity every N seconds (min 15)")
    rotate_p.add_argument("seconds", type=int)
    sub.add_parser("about", help="version and notes")
    return parser


def main(argv=None):
    global COLOR, DRY
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.no_color:
        COLOR = False
    DRY = args.dry_run
    if DRY and args.command not in ("start", "stop"):
        parser.error("--dry-run works with 'start' and 'stop' only")
    if args.command != "about" and not DRY and os.geteuid() != 0:
        fail("Root privileges are required. Run: sudo wraith")
        return 1
    try:
        if args.command is None:
            main_menu()
        elif args.command == "start":
            start(args.country)
        elif args.command == "stop":
            stop()
        elif args.command == "status":
            status()
        elif args.command == "newid":
            new_identity()
        elif args.command == "country":
            set_country(args.code)
        elif args.command == "rotate":
            rotate(args.seconds)
        elif args.command == "about":
            about()
    except WraithError as err:
        fail(str(err))
        return 1
    except KeyboardInterrupt:
        print()
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
