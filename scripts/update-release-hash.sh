#!/usr/bin/env bash
# update-release-hash.sh
#
# Rebuilds the release binary (if needed), extracts the embedded source hash,
# and updates the hash table in README.md for the current Cargo.toml version.
#
# Run this before submitting any PR that modifies:
#   - src/**/*.rs
#   - Cargo.toml / Cargo.lock
#   - build.rs
#
# Usage (from project root):
#   bash scripts/update-release-hash.sh

set -euo pipefail

cd "$(dirname "$0")/.."

# ── Build ─────────────────────────────────────────────────────────────────────

if [[ ! -f target/release/op4 ]]; then
    echo "[+] Release binary not found — building now..."
    cargo build --release --locked
    echo "[ok] Build complete."
else
    echo "[info] Using existing release binary."
fi

# ── Extract version and hash ──────────────────────────────────────────────────

VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
HASH=$(./target/release/op4 --print-hash)

echo "Version : $VERSION"
echo "Hash    : $HASH"

# ── Update README.md ──────────────────────────────────────────────────────────

python3 - "$VERSION" "$HASH" <<'PYEOF'
import sys
import re

version, hash_val = sys.argv[1], sys.argv[2]
new_row = f"| `{version}` | `{hash_val}` |"

with open("README.md", "r") as f:
    content = f.read()

# Replace an existing row for this version, or insert a new one.
pattern = rf"\| `{re.escape(version)}` \| `[^`]+` \|"
if re.search(pattern, content):
    new_content = re.sub(pattern, new_row, content)
    action = "Updated"
else:
    # Append a new row directly after the |---|---| separator line.
    separator = "| Version | Source hash |\n|---|---|\n"
    if separator not in content:
        print("[error] Cannot find hash table in README.md", file=sys.stderr)
        sys.exit(1)
    new_content = content.replace(separator, separator + new_row + "\n")
    action = "Added"

with open("README.md", "w") as f:
    f.write(new_content)

print(f"[ok] {action} hash for v{version} in README.md")
PYEOF
