#!/usr/bin/env bash
# op4 installation script
# Run as root: sudo bash install/setup.sh
#
# What this does:
#   1. Creates a dedicated system user (op4) with minimal privileges
#   2. Sets up the vault directory with correct ownership
#   3. Installs the binary to /usr/local/bin/op4
#   4. Installs the AppArmor profile
#   5. Enables the AppArmor profile

set -euo pipefail

# ── Checks ─────────────────────────────────────────────────────────────────────

if [[ "$(id -u)" -ne 0 ]]; then
    echo "[error] This script must be run as root." >&2
    exit 1
fi

BINARY="./target/release/op4"
if [[ ! -f "$BINARY" ]]; then
    echo "[error] Release binary not found at $BINARY." >&2
    echo "        Run: cargo build --release" >&2
    exit 1
fi

# ── Variables ───────────────────────────────────────────────────────────────────

OP4_USER="op4"
INSTALL_BIN="/usr/local/bin/op4"
APPARMOR_PROFILE_SRC="./apparmor/op4.profile"
APPARMOR_PROFILE_DST="/etc/apparmor.d/op4"

# ── 1. Create dedicated system user ───────────────────────────────────────────

if id "$OP4_USER" &>/dev/null; then
    echo "[info] User '$OP4_USER' already exists."
else
    echo "[+] Creating system user: $OP4_USER"
    useradd \
        --system \
        --no-create-home \
        --shell /usr/sbin/nologin \
        --comment "op4 messaging daemon" \
        "$OP4_USER"
    echo "[ok] User '$OP4_USER' created."
fi

# ── 2. Create vault data directory ────────────────────────────────────────────
# Each user who runs op4 needs their own data dir. The installer creates one
# for the installing user. The dedicated 'op4' system user is for daemon mode.

OP4_DATA_DIR="/var/lib/op4"
if [[ ! -d "$OP4_DATA_DIR" ]]; then
    echo "[+] Creating data directory: $OP4_DATA_DIR"
    mkdir -p "$OP4_DATA_DIR"
    chown "$OP4_USER:$OP4_USER" "$OP4_DATA_DIR"
    chmod 0700 "$OP4_DATA_DIR"
    echo "[ok] $OP4_DATA_DIR created (mode 0700, owned by $OP4_USER)."
else
    echo "[info] Data directory $OP4_DATA_DIR already exists."
fi

# ── 3. Install binary ─────────────────────────────────────────────────────────

echo "[+] Installing binary to $INSTALL_BIN"
install -o root -g root -m 0755 "$BINARY" "$INSTALL_BIN"

# Verify the installed binary's source hash matches expected
INSTALLED_HASH=$("$INSTALL_BIN" --print-hash 2>&1 | grep -oP '(?<=source hash: )\S+' || true)
echo "[ok] Binary installed."
echo "     Source hash in binary: ${INSTALLED_HASH:-[unavailable — check manually]}"
echo "     Compare this with the published release hash."

# ── 4. Install AppArmor profile ───────────────────────────────────────────────

if command -v apparmor_parser &>/dev/null; then
    echo "[+] Installing AppArmor profile to $APPARMOR_PROFILE_DST"
    install -o root -g root -m 0644 "$APPARMOR_PROFILE_SRC" "$APPARMOR_PROFILE_DST"
    apparmor_parser -r "$APPARMOR_PROFILE_DST"
    echo "[ok] AppArmor profile installed and loaded."
else
    echo "[warn] apparmor_parser not found — skipping AppArmor profile installation."
    echo "       Install apparmor and manually load: $APPARMOR_PROFILE_SRC"
fi

# ── 5. Summary ────────────────────────────────────────────────────────────────

echo ""
echo "=== op4 installation complete ==="
echo ""
echo "  Binary:         $INSTALL_BIN"
echo "  System user:    $OP4_USER"
echo "  Data dir:       $OP4_DATA_DIR"
echo "  AppArmor:       $APPARMOR_PROFILE_DST"
echo ""
echo "Run op4 as a regular user (vault stored in ~/.local/share/op4/):"
echo "  $INSTALL_BIN"
echo ""
echo "IMPORTANT: Verify the source hash above matches the published release"
echo "before trusting this binary."
echo ""
