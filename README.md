# WRAITH

Route your system traffic through Tor with one command. Terminal interface, kill switch, and honest limits.

```
██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗
██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║
██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║
██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║
╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║
 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝
```

WRAITH starts its own Tor instance, redirects the machine's TCP and DNS traffic to it with iptables, and blocks everything else. It is a single Python file that uses only the standard library.

> For education and authorized testing only. See [Responsible use](#responsible-use).

## Features

| Feature | How it works |
|---|---|
| Transparent Tor routing | iptables redirects outgoing TCP to Tor's `TransPort`. No per-app proxy settings needed. |
| DNS through Tor | UDP port 53 is redirected to Tor's `DNSPort`, so lookups do not reach your ISP resolver. |
| Kill switch | A firewall chain rejects all traffic that does not go through Tor. If Tor stops, nothing leaks. |
| IPv6 blocked | An `ip6tables` chain rejects IPv6, so it cannot bypass Tor. |
| Exit country | Choose an exit country with the Tor `ExitNodes` setting. Changes apply live through the control port. |
| New identity | Requests a fresh Tor circuit (`NEWNYM`). Optional timed rotation with `wraith rotate`. |
| Real status check | Asks `check.torproject.org` which IP you exit from and whether it is a Tor exit. |
| Clean stop | Only WRAITH's own firewall chains are removed. Your other rules are untouched. |
| Dry run | `--dry-run` prints every system command for `start` and `stop` without running anything. |

## Requirements

- Linux with `iptables` (Kali, Ubuntu, Debian and derivatives)
- Python 3.8 or newer
- `tor` and `tor-geoipdb` packages
- Root privileges

## Install

```bash
git clone https://github.com/Black-ghost7/wraith.git
cd wraith
sudo ./install.sh
```

The installer installs the dependencies and copies the tool to `/usr/local/bin/wraith`. To remove it later, run `sudo ./uninstall.sh`.

## Usage

Run `sudo wraith` for the menu:

```
[1] Start         Route all traffic via Tor
[2] Stop          Restore normal network
[3] Exit country  Choose where you exit
[4] New identity  Fresh Tor circuit
[5] Status        Real IP and leak check
[6] About         Version and usage
[0] Exit
```

Or use commands directly:

| Command | What it does |
|---|---|
| `sudo wraith start` | Turn protection on. Add `-c de` to pick an exit country. |
| `sudo wraith stop` | Turn protection off and restore the network. |
| `sudo wraith status` | Show state, exit IP, exit country and a Tor check. |
| `sudo wraith newid` | Request a new Tor identity. |
| `sudo wraith country de` | Set the exit country. Use `any` to clear it. |
| `sudo wraith rotate 60` | New identity every 60 seconds (minimum 15). Open sessions will break. |
| `wraith --dry-run start` | Print the commands without running them. |

Leaving the menu does not turn protection off. Use `sudo wraith stop` for that.

## Read this before you run it

- **Test in a virtual machine first.** WRAITH changes firewall rules. A mistake can cut your connection until you run `sudo wraith stop`.
- **Existing connections are dropped** when protection starts, because they were not made through Tor.
- **Local network access stops working.** LAN traffic is also sent through Tor, which cannot reach private addresses. The only exception is DHCP.
- **Only TCP and DNS work.** Other UDP traffic (for example QUIC and many VoIP apps) is blocked.
- **A copy of your original rules** is saved in `/etc/wraith/iptables.backup` before they are changed.

## Limits

Tor does not make you anonymous by itself.

- Browser fingerprints, cookies and logging in to your real accounts can still identify you.
- The exit relay can read any traffic that is not encrypted (use HTTPS).
- Forcing a single exit country reduces your anonymity set and fails if Tor has no exit there.
- Frequent identity rotation breaks sessions and can make your traffic pattern stand out.
- WRAITH has not been audited by a security professional.

## How it works

1. WRAITH writes its own `torrc` (`/etc/wraith/torrc`) and starts a separate Tor process, so your system Tor service is not modified.
2. After Tor has bootstrapped, it creates the chains `WRAITH_NAT`, `WRAITH_OUT` and `WRAITH_OUT6`.
3. The NAT chain redirects DNS and TCP to Tor, except traffic from the Tor user itself.
4. The filter chain accepts only loopback destinations and the Tor process, and rejects the rest.
5. `stop` deletes those chains and stops the Tor process.

Run `wraith --dry-run start` to see the exact commands.

## Troubleshooting

| Problem | Fix |
|---|---|
| No internet after a crash | Run `sudo wraith stop`. If that fails, run `sudo iptables -F WRAITH_OUT` and `sudo iptables -t nat -F WRAITH_NAT`, or reboot. |
| Tor does not bootstrap | Check `/var/log/wraith/tor.log`. Make sure you have a working connection before starting. |
| Exit country fails | Tor may have no exit there right now. Run `sudo wraith country any`. |
| Country shows as unknown | Install `tor-geoipdb`. |

## Responsible use

WRAITH is a privacy and learning tool. Use it only on systems and networks you own or are authorized to test. Tor is legal in most places, but what you do through it must also be legal. The author is not responsible for misuse.

## History

Version 2.0.0 is a full rewrite in Python. The earlier Shell version (1.x) was a menu prototype and did not route traffic. This version implements the features listed above.

## Connect

- GitHub: https://github.com/Black-ghost7
- LinkedIn: https://www.linkedin.com/in/black-ghost7
- Facebook: https://www.facebook.com/share/1a8LnoWP7b/
- Discord: bk.ghost7
- TryHackMe: https://tryhackme.com/p/Blackghost7

## License

Released under the [MIT License](LICENSE).
