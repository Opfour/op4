#!/usr/bin/env bash
# op4 installation script
# Run as root from the project root: sudo bash install/setup.sh
#
# What this does:
#   0. Installs build dependencies (Rust toolchain, Tor) if missing
#   1. Builds the release binary
#   2. Creates a dedicated system user (op4) with minimal privileges
#   3. Sets up the vault directory with correct ownership
#   4. Installs the binary to /usr/local/bin/op4
#   5. Installs the AppArmor profile

set -euo pipefail

# ── Root check ──────────────────────────────────────────────────────────────────

if [[ "$(id -u)" -ne 0 ]]; then
    echo "[error] This script must be run as root." >&2
    echo "        Try: sudo bash install/setup.sh" >&2
    exit 1
fi

# ── Must run from project root ──────────────────────────────────────────────────

if [[ ! -f "Cargo.toml" ]]; then
    echo "[error] Run this script from the op4 project root, not from install/." >&2
    echo "        cd /path/to/op4 && sudo bash install/setup.sh" >&2
    exit 1
fi

# ── Variables ───────────────────────────────────────────────────────────────────

OP4_USER="op4"
INSTALL_BIN="/usr/local/bin/op4"
APPARMOR_PROFILE_SRC="./apparmor/op4.profile"
APPARMOR_PROFILE_DST="/etc/apparmor.d/op4"
BINARY="./target/release/op4"

# ── 0a. Build dependencies (C toolchain, pkg-config, OpenSSL headers) ──────────

# These are required by cargo build — catch them early with a clear message.
BUILD_PKGS=()
command -v cc      &>/dev/null || BUILD_PKGS+=(build-essential)
command -v pkg-config &>/dev/null || BUILD_PKGS+=(pkg-config)
dpkg -s libssl-dev &>/dev/null 2>&1     || BUILD_PKGS+=(libssl-dev)
command -v setcap  &>/dev/null || BUILD_PKGS+=(libcap2-bin)

if [[ ${#BUILD_PKGS[@]} -gt 0 ]]; then
    echo "[+] Installing build dependencies: ${BUILD_PKGS[*]}"
    apt-get update -qq
    apt-get install -y "${BUILD_PKGS[@]}"
    echo "[ok] Build dependencies installed."
else
    echo "[info] Build dependencies already present."
fi

# ── 0b. Rust / Cargo ─────────────────────────────────────────────────────────

# Source cargo env in case rustup is installed but not yet in PATH
if [[ -f "$HOME/.cargo/env" ]]; then
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
fi

if ! command -v cargo &>/dev/null; then
    echo "[+] Rust not found. Installing rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
    echo "[ok] Rust installed."
else
    echo "[info] Rust/Cargo already available: $(cargo --version)"
fi

# ── 0c. Tor ─────────────────────────────────────────────────────────────────────

if ! command -v tor &>/dev/null; then
    echo "[+] Tor not found. Installing via apt..."
    apt-get update -qq
    apt-get install -y tor
    echo "[ok] Tor installed."
else
    echo "[info] Tor already available: $(tor --version 2>&1 | head -1)"
fi

# Check Tor control port config
if ! grep -q "^ControlPort" /etc/tor/torrc 2>/dev/null; then
    echo "[+] Enabling Tor control port..."
    echo "" >> /etc/tor/torrc
    echo "ControlPort 9051"       >> /etc/tor/torrc
    echo "CookieAuthentication 1" >> /etc/tor/torrc
    systemctl restart tor 2>/dev/null || service tor restart 2>/dev/null || true
    echo "[ok] Tor control port enabled (9051, cookie auth)."
else
    echo "[info] Tor control port already configured."
fi

# Add the installing user to the debian-tor group so they can read the Tor
# cookie file at /run/tor/control.authcookie (required for control port auth).
# Determine the real user: prefer $SUDO_USER, fall back to logname.
REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || echo '')}"
TOR_GROUP=""
if getent group debian-tor &>/dev/null; then
    TOR_GROUP="debian-tor"
elif getent group tor &>/dev/null; then
    TOR_GROUP="tor"
fi

if [[ -n "$TOR_GROUP" && -n "$REAL_USER" ]]; then
    if id -nG "$REAL_USER" | grep -qw "$TOR_GROUP"; then
        echo "[info] $REAL_USER is already a member of $TOR_GROUP."
    else
        echo "[+] Adding $REAL_USER to $TOR_GROUP group (required for Tor cookie auth)..."
        usermod -aG "$TOR_GROUP" "$REAL_USER"
        echo "[ok] Added. You must log out and back in for the group to take effect."
    fi
else
    echo "[warn] Could not determine Tor group or real user — add yourself to the tor group manually."
fi

# ── 0d. Build release binary ────────────────────────────────────────────────────

if [[ ! -f "$BINARY" ]]; then
    echo "[+] Building op4 release binary (this takes a few minutes)..."
    # Run build as the invoking user if SUDO_USER is set, otherwise as current user
    if [[ -n "${SUDO_USER:-}" ]]; then
        sudo -u "$SUDO_USER" cargo build --release --locked
    else
        cargo build --release --locked
    fi
    echo "[ok] Build complete."
else
    echo "[info] Release binary already built."
fi

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

# Grant CAP_IPC_LOCK so op4 can lock memory pages (mlockall) without root.
# Without this, mlockall fails with ENOMEM on systems with a low RLIMIT_MEMLOCK.
if command -v setcap &>/dev/null; then
    setcap cap_ipc_lock=+ep "$INSTALL_BIN"
    echo "[ok] CAP_IPC_LOCK granted (memory pages will be locked on startup)."
else
    echo "[warn] setcap not found — install libcap2-bin to enable memory locking."
    echo "       Without it, op4 will warn that key pages may be swappable."
fi

# --print-hash prints just the raw hash to stdout (no prefix).
INSTALLED_HASH=$("$INSTALL_BIN" --print-hash 2>/dev/null || true)
echo "[ok] Binary installed."
echo "     Source hash: ${INSTALLED_HASH:-[unavailable — check manually]}"
echo "     Compare this with the published release hash."

# ── 4. Install AppArmor profile ───────────────────────────────────────────────

if command -v apparmor_parser &>/dev/null; then
    echo "[+] Installing AppArmor profile to $APPARMOR_PROFILE_DST"
    install -o root -g root -m 0644 "$APPARMOR_PROFILE_SRC" "$APPARMOR_PROFILE_DST"
    apparmor_parser -r "$APPARMOR_PROFILE_DST"
    echo "[ok] AppArmor profile installed and loaded."
else
    echo "[warn] apparmor_parser not found — skipping AppArmor profile installation."
fi

# ── 5. Summary ────────────────────────────────────────────────────────────────

echo ""
echo "=== op4 installation complete ==="
echo ""
echo "  Binary:      $INSTALL_BIN"
echo "  System user: $OP4_USER"
echo "  Data dir:    $OP4_DATA_DIR"
echo "  AppArmor:    $APPARMOR_PROFILE_DST"
echo ""
echo "Run op4 as a regular user:"
echo "  $INSTALL_BIN"
echo ""
echo "NOTE: If this is a first install, log out and back in before running op4."
echo "      (Required for the Tor group membership to take effect.)"
echo ""
echo "IMPORTANT: Verify the source hash above matches the published release"
echo "before trusting this binary."
echo ""
