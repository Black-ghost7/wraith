#!/usr/bin/env bash
set -uo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "[-] Run as root: sudo ./uninstall.sh"
    exit 1
fi

if command -v wraith >/dev/null 2>&1; then
    echo "[*] Turning protection off"
    wraith stop || true
fi

echo "[*] Removing WRAITH files"
rm -f /usr/local/bin/wraith
rm -rf /etc/wraith /var/lib/wraith /var/log/wraith /run/wraith

echo "[+] WRAITH removed. The tor and iptables packages were left installed."
