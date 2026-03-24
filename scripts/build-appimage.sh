#!/usr/bin/env bash
# Build an AppImage for op4
# Usage: bash scripts/build-appimage.sh
#
# Prerequisites:
#   - Release binary at target/release/op4 (run: cargo build --release --locked)
#   - wget (to fetch appimagetool if not present)
#
# Output: op4-x86_64.AppImage in the project root

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

BINARY="target/release/op4"
APPDIR="build/AppDir"
APPIMAGETOOL="build/appimagetool-x86_64.AppImage"
VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')

# ── Verify binary exists ────────────────────────────────────────────────────

if [[ ! -f "$BINARY" ]]; then
    echo "[error] Release binary not found at $BINARY" >&2
    echo "        Run: cargo build --release --locked" >&2
    exit 1
fi

echo "[+] Building AppImage for op4 v${VERSION}"

# ── Fetch appimagetool if needed ────────────────────────────────────────────

mkdir -p build
if [[ ! -f "$APPIMAGETOOL" ]]; then
    echo "[+] Downloading appimagetool..."
    wget -q -O "$APPIMAGETOOL" \
        "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage"
    chmod +x "$APPIMAGETOOL"
fi

# ── Assemble AppDir ─────────────────────────────────────────────────────────

rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin"

# Binary
cp "$BINARY" "$APPDIR/usr/bin/op4"

# Desktop file
cp install/op4.desktop "$APPDIR/op4.desktop"

# Icon — convert the logo to PNG if needed, or use a simple placeholder
if command -v convert &>/dev/null && [[ -f docs/logo.jpeg ]]; then
    convert docs/logo.jpeg -resize 256x256 "$APPDIR/op4.png"
else
    cp docs/logo.jpeg "$APPDIR/op4.png" 2>/dev/null || true
fi

# AppRun entry point
cat > "$APPDIR/AppRun" << 'APPRUN'
#!/bin/bash
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/usr/bin/op4" "$@"
APPRUN
chmod +x "$APPDIR/AppRun"

# ── Build the AppImage ──────────────────────────────────────────────────────

echo "[+] Packaging AppImage..."
ARCH=x86_64 "$APPIMAGETOOL" "$APPDIR" "op4-${VERSION}-x86_64.AppImage" 2>&1

# Generate checksum
sha256sum "op4-${VERSION}-x86_64.AppImage" > "op4-${VERSION}-x86_64.AppImage.sha256"

echo ""
echo "[ok] AppImage built: op4-${VERSION}-x86_64.AppImage"
echo "     Checksum:       op4-${VERSION}-x86_64.AppImage.sha256"
echo ""
cat "op4-${VERSION}-x86_64.AppImage.sha256"
