# Download & Install op4

Choose the installation method that suits your setup. All methods require
**Tor** running on your system with the control port enabled.

---

## Option 1 — AppImage (recommended)

A single portable binary. No installation required.

1. Download the latest AppImage from the
   [Releases page](https://github.com/Opfour/op4/releases/latest).

2. Make it executable and run:

   ```bash
   chmod +x op4-*-x86_64.AppImage
   ./op4-*-x86_64.AppImage
   ```

3. Verify the source hash:

   ```bash
   ./op4-*-x86_64.AppImage --print-hash
   ```

   Compare it against the
   [release hash table](https://github.com/Opfour/op4#release-hash-verification)
   in the README.

> **Note:** The AppImage does not install Tor or configure the control port
> for you. See [Tor setup](#tor-setup) below.

---

## Option 2 — Automated installer (Debian / Ubuntu)

The setup script handles everything: Rust toolchain, Tor, build, system user,
AppArmor profile, and binary installation.

```bash
git clone https://github.com/Opfour/op4.git
cd op4
sudo bash install/setup.sh
```

After the script finishes, **log out and log back in** so the `debian-tor`
group takes effect. Then run:

```bash
op4
```

---

## Option 3 — Clone & build from source

Build the binary yourself from the Git repository.

### Prerequisites

- Rust 1.88+ (pinned to 1.89.0 via `rust-toolchain.toml`)
- C compiler (`gcc` or `cc`)
- `pkg-config`
- Tor daemon

### Steps

```bash
git clone https://github.com/Opfour/op4.git
cd op4
cargo build --release --locked
```

The binary is at `target/release/op4`. Run it directly or install system-wide:

```bash
# Run directly
./target/release/op4

# Or install to /usr/local/bin
sudo install -m 0755 target/release/op4 /usr/local/bin/op4
```

### Verify the build

```bash
./target/release/op4 --print-hash
```

Two builds from the same source should produce the same hash
(`SOURCE_DATE_EPOCH=0` is set automatically).

---

## Option 4 — Source tarball

Download a versioned source archive from the
[Releases page](https://github.com/Opfour/op4/releases/latest).

```bash
# Download and extract
tar xzf op4-<version>.tar.gz
cd op4-<version>

# Verify checksum
sha256sum -c op4-<version>.tar.gz.sha256

# Build
cargo build --release --locked
./target/release/op4
```

---

## Tor setup

op4 requires the Tor daemon running locally with the control port enabled.

### Debian / Ubuntu

```bash
sudo apt install tor
```

Add to `/etc/tor/torrc`:

```
ControlPort 9051
CookieAuthentication 1
```

```bash
sudo systemctl restart tor
sudo usermod -aG debian-tor $USER
```

**Log out and back in** for the group change to apply.

### Fedora

```bash
sudo dnf install tor
```

Add the same `ControlPort` and `CookieAuthentication` lines to `/etc/tor/torrc`, then:

```bash
sudo systemctl restart tor
sudo usermod -aG tor $USER
```

### Arch Linux

```bash
sudo pacman -S tor
```

Same torrc configuration, then:

```bash
sudo systemctl restart tor
sudo usermod -aG tor $USER
```

---

## Supported platforms

| Distro | Status |
|--------|--------|
| Ubuntu 22.04 / 24.04 | Supported |
| Debian 12 | Supported |
| Fedora 39+ | Supported |
| Arch Linux (current) | Supported |
| macOS / Windows / WSL1 | Not supported |

**Architecture:** x86-64 (aarch64 untested but should work).
**Minimum kernel:** 4.15 (5.4+ recommended).

---

## Integrity verification

Every release includes SHA-256 checksums (`.sha256` files) alongside the
downloads. The binary also embeds a source hash that you can verify:

```bash
op4 --print-hash
```

Compare the output against the
[release hash table](https://github.com/Opfour/op4#release-hash-verification)
in the README. If the hash does not match, **do not use the binary**.
