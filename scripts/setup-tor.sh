#!/usr/bin/env bash
# op4 Tor hardening script
# Installs and configures Vanguards (guard discovery protection) and
# hardens the local /etc/tor/torrc for op4's hidden service operation.
#
# Run as root: sudo bash scripts/setup-tor.sh
#
# References:
#   Vanguards: https://github.com/mikeperry-tor/vanguards
#   Tor Project blog: https://blog.torproject.org/announcing-vanguards-add-onion-services/
#   Tor Manual: https://2019.www.torproject.org/docs/tor-manual.html.en

set -euo pipefail

# ── Checks ─────────────────────────────────────────────────────────────────────

if [[ "$(id -u)" -ne 0 ]]; then
    echo "[error] This script must be run as root (sudo)." >&2
    exit 1
fi

if ! command -v tor &>/dev/null; then
    echo "[error] Tor is not installed. Install it first:" >&2
    echo "        sudo apt-get install tor" >&2
    exit 1
fi

if ! command -v python3 &>/dev/null; then
    echo "[error] python3 is required for Vanguards." >&2
    echo "        sudo apt-get install python3 python3-pip" >&2
    exit 1
fi

# ── 1. Install Vanguards ───────────────────────────────────────────────────────

echo "[+] Installing Vanguards..."
if python3 -c "import vanguards" &>/dev/null 2>&1; then
    echo "[info] Vanguards already installed."
else
    pip3 install vanguards
    echo "[ok] Vanguards installed."
fi

VANGUARDS_BIN=$(python3 -c "import shutil; print(shutil.which('vanguards') or '')")
if [[ -z "$VANGUARDS_BIN" ]]; then
    VANGUARDS_BIN=$(python3 -m vanguards --help &>/dev/null && echo "python3 -m vanguards" || echo "")
fi
echo "[info] Vanguards: ${VANGUARDS_BIN:-python3 -m vanguards}"

# ── 2. Harden /etc/tor/torrc ──────────────────────────────────────────────────

TORRC="/etc/tor/torrc"
TORRC_BACKUP="${TORRC}.bak.$(date +%Y%m%d%H%M%S)"

echo "[+] Backing up $TORRC → $TORRC_BACKUP"
cp "$TORRC" "$TORRC_BACKUP"

# Append op4-specific hardening if not already present.
if grep -q "op4 hardening" "$TORRC"; then
    echo "[info] Torrc already has op4 hardening block — skipping."
else
    echo "[+] Appending hardening options to $TORRC"
    cat >> "$TORRC" << 'TORRC_BLOCK'

# ── op4 hardening (added by scripts/setup-tor.sh) ────────────────────────────

# Control port: required for op4 to register the hidden service and
# for Vanguards to connect.
ControlPort 9051
CookieAuthentication 1
CookieAuthFileGroupReadable 1

# Stream isolation: each peer connection gets its own Tor circuit.
# (op4 sets IsolateSOCKSAuth via SOCKS5 credentials per peer.)
SOCKSPort 9050 IsolateSOCKSAuth IsolateClientAddr

# Performance and privacy: prefer faster circuits while maintaining security.
LearnCircuitBuildTimeout 1
CircuitBuildTimeout 60

# Minimize disk writes (avoids forensic traces on disk).
AvoidDiskWrites 1

# Safe logging: scrub potentially identifying data from log output.
SafeLogging 1
Log notice file /var/log/tor/notices.log

# Disable DNS port (op4 never uses DNS; all resolution is via .onion).
# DNSPort 0  # Uncomment if no other apps need Tor DNS resolution.

# Disable all exit traffic (op4 is hidden-service-only, no exit needed).
# ClientOnly 1  # Uncomment to fully disable relay functionality.

# ─────────────────────────────────────────────────────────────────────────────
TORRC_BLOCK
    echo "[ok] Torrc hardening appended."
fi

# ── 3. Ensure op4 user can read the Tor cookie ────────────────────────────────

TOR_COOKIE_DIR="/run/tor"
TOR_GROUP="debian-tor"

# Detect Tor group (varies by distro)
if getent group "$TOR_GROUP" &>/dev/null; then
    echo "[info] Tor group: $TOR_GROUP"
elif getent group "tor" &>/dev/null; then
    TOR_GROUP="tor"
    echo "[info] Tor group: $TOR_GROUP (Fedora/RHEL)"
else
    echo "[warn] Could not detect Tor group. Add your user manually."
fi

CURRENT_USER="${SUDO_USER:-$USER}"
if [[ -n "$CURRENT_USER" && "$CURRENT_USER" != "root" ]]; then
    echo "[+] Adding $CURRENT_USER to $TOR_GROUP group..."
    usermod -aG "$TOR_GROUP" "$CURRENT_USER"
    echo "[ok] Added. Log out and back in for the group change to take effect."
fi

# ── 4. Reload Tor ─────────────────────────────────────────────────────────────

echo "[+] Reloading Tor configuration..."
if systemctl reload tor 2>/dev/null || service tor reload 2>/dev/null; then
    echo "[ok] Tor reloaded."
else
    echo "[warn] Could not auto-reload Tor. Run: sudo systemctl restart tor"
fi

# ── 5. Install Vanguards systemd service ──────────────────────────────────────

VANGUARDS_SERVICE="/etc/systemd/system/vanguards.service"
if [[ -f "$VANGUARDS_SERVICE" ]]; then
    echo "[info] Vanguards systemd service already exists."
else
    echo "[+] Creating Vanguards systemd service..."
    cat > "$VANGUARDS_SERVICE" << 'SERVICE'
[Unit]
Description=Vanguards: Tor onion service guard protection
After=tor.service
Requires=tor.service

[Service]
Type=simple
User=debian-tor
ExecStart=python3 -m vanguards --control_port 9051 --state_file /var/lib/tor/vanguards.state
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full

[Install]
WantedBy=multi-user.target
SERVICE

    systemctl daemon-reload
    systemctl enable vanguards
    systemctl start vanguards
    echo "[ok] Vanguards service installed and started."
fi

# ── 6. Summary ────────────────────────────────────────────────────────────────

echo ""
echo "══════════════════════════════════════════════════════"
echo "  op4 Tor hardening complete"
echo "══════════════════════════════════════════════════════"
echo ""
echo "  Configured:"
echo "    ✓ ControlPort 9051 + CookieAuthentication"
echo "    ✓ SOCKSPort 9050 with IsolateSOCKSAuth"
echo "    ✓ AvoidDiskWrites + SafeLogging"
echo "    ✓ Vanguards guard-discovery protection"
echo ""
echo "  Next steps:"
echo "    1. Log out and back in (group membership change)"
echo "    2. Check Vanguards status: systemctl status vanguards"
echo "    3. Run op4 normally — Tor will create the .onion service"
echo ""
echo "  Tor backup: $TORRC_BACKUP"
echo ""
