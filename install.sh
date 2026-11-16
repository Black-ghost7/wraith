#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "[-] Run as root: sudo ./install.sh"
    exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
    echo "[-] This installer supports Debian-based systems (Kali, Ubuntu, Debian)."
    echo "    Install tor, iptables and python3 manually, then copy wraith.py to /usr/local/bin/wraith."
    exit 1
fi

echo "[*] Installing dependencies: tor, tor-geoipdb, iptables, python3"
apt-get update -qq
apt-get install -y tor tor-geoipdb iptables python3

echo "[*] Installing WRAITH to /usr/local/bin/wraith"
install -m 0755 "$(dirname "$0")/wraith.py" /usr/local/bin/wraith

echo "[+] Done. Start with: sudo wraith"
echo "[!] If you ever lose your connection, run: sudo wraith stop"
