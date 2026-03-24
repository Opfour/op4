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

## Option 5 — Tails OS (Persistent Storage)

Running op4 on [Tails](https://tails.net) combines op4's end-to-end
encryption with Tails' amnesic, Tor-only operating system. This is the
strongest deployment option available.

### Why Tails + op4

Tails is a portable Linux distribution that boots from a USB drive, routes
**all** network traffic through Tor, and leaves no trace on the host
computer when shut down. Combining it with op4 provides defense in depth
that neither tool achieves alone:

| Threat | op4 alone | Tails alone | op4 + Tails |
|--------|-----------|-------------|-------------|
| Message content exposed | Protected (E2EE + Double Ratchet) | N/A (no messenger) | Protected |
| IP address leaked | Protected (Tor hidden services) | Protected (all traffic over Tor) | Protected (double guarantee) |
| Forensic recovery from disk | Vault encrypted, but host OS may cache/swap/log | Amnesic — RAM wiped on shutdown, no disk writes | Vault in encrypted Persistent Storage, host RAM wiped on shutdown |
| Malware on host OS | Vulnerable (keylogger, screen capture) | Boots clean every time from read-only media | Boots clean every time |
| MAC address tracking | Not addressed | Spoofed automatically on every boot | Spoofed automatically |
| Local network fingerprinting | Tor entry visible to ISP | Tor bridges + pluggable transports available | Tor bridges available |
| Seized device (powered off) | Vault protected by Argon2id passphrase | No data on host; USB requires LUKS passphrase | Vault inside LUKS-encrypted Persistent Storage — two layers of encryption |
| Seized device (powered on) | Memory contains key material | Cold boot attack possible but brief | Same risk, mitigated by mlockall preventing swap |

**Key benefits:**

- **No trace on the host computer.** Tails boots from USB and runs
  entirely in RAM. When you shut down, the host machine has zero
  evidence that op4 (or anything else) was ever used.
- **Tor is already running.** Tails routes all traffic through Tor by
  default. op4's hidden service runs on top of an already-Tor'd system,
  so even a misconfigured application on Tails cannot leak your real IP.
- **Encrypted Persistent Storage.** Tails offers an optional encrypted
  partition on the USB drive (LUKS). Your op4 vault lives inside this
  partition, meaning an attacker who physically seizes the USB must
  break both the LUKS encryption and the Argon2id vault passphrase.
- **Clean-boot guarantee.** Every session starts from a known-good state.
  Malware, keyloggers, or rootkits from a previous session cannot persist
  (unless they compromise the Persistent Storage itself, which Tails
  isolates from the base OS).
- **MAC address spoofing.** Tails randomizes your network interface MAC
  address on every boot, preventing local network operators from
  correlating sessions to a physical device.

### Tor compatibility

op4 communicates with Tor through two standard interfaces:

- **Control port** (TCP 9051) — stable text protocol. The `ADD_ONION`
  command for v3 hidden services has been supported since Tor 0.3.3
  (2018). Tails ships Tor 0.4.8+.
- **SOCKS5 proxy** (TCP 9050) — RFC 1928/1929, supported by every Tor
  version.

There is no version-specific dependency. Any Tor release from the last
6+ years works.

### Setup

Tails manages Tor through its own wrapper and does not enable the control
port by default. The steps below enable it for the current session and
optionally persist the configuration across reboots.

#### 1. Enable Persistent Storage

If you haven't already, create a Persistent Storage volume on your
Tails USB:

1. Boot into Tails
2. Go to **Applications → Tails → Persistent Storage**
3. Create the encrypted volume and set a strong passphrase
4. Enable **Additional Software** and **Dotfiles** persistence features

#### 2. Download the AppImage

From within Tails (all downloads go through Tor automatically):

```bash
# Download to Persistent Storage
cd ~/Persistent
torsocks wget https://github.com/Opfour/op4/releases/latest/download/op4-<version>-x86_64.AppImage
torsocks wget https://github.com/Opfour/op4/releases/latest/download/op4-<version>-x86_64.AppImage.sha256

# Verify checksum
sha256sum -c op4-*-x86_64.AppImage.sha256

# Make executable
chmod +x op4-*-x86_64.AppImage
```

> **Note:** Replace `<version>` with the actual version number from the
> [Releases page](https://github.com/Opfour/op4/releases/latest).

Alternatively, download on another machine and copy the AppImage to the
USB drive's Persistent Storage partition.

#### 3. Enable the Tor control port

Tails does not expose the control port by default. You need to add the
configuration and grant your user access to the cookie file.

**Per-session setup** (must repeat after each reboot):

```bash
# Add control port configuration
sudo sh -c 'echo "ControlPort 9051" >> /etc/tor/torrc'
sudo sh -c 'echo "CookieAuthentication 1" >> /etc/tor/torrc'

# Restart Tor to apply
sudo systemctl restart tor@default

# Wait for Tor to reconnect (Tails routes everything through Tor,
# so give it a moment to re-establish circuits)
sleep 10

# Grant access to the Tor cookie file
# Tails uses the debian-tor group
sudo usermod -aG debian-tor amnesia

# Apply the group change without logging out
newgrp debian-tor
```

**Persistent setup** (survives reboots):

To avoid repeating this every session, save a setup script to your
Persistent Storage:

```bash
cat > ~/Persistent/op4-tor-setup.sh << 'SETUP'
#!/bin/bash
# Enable Tor control port for op4 on Tails
set -e
sudo sh -c 'grep -q "^ControlPort 9051" /etc/tor/torrc || echo "ControlPort 9051" >> /etc/tor/torrc'
sudo sh -c 'grep -q "^CookieAuthentication 1" /etc/tor/torrc || echo "CookieAuthentication 1" >> /etc/tor/torrc'
sudo systemctl restart tor@default
sleep 10
sudo usermod -aG debian-tor amnesia
echo "[ok] Tor control port enabled. Run: newgrp debian-tor && ~/Persistent/op4-*-x86_64.AppImage"
SETUP
chmod +x ~/Persistent/op4-tor-setup.sh
```

Then on each boot:

```bash
bash ~/Persistent/op4-tor-setup.sh
newgrp debian-tor
```

#### 4. Run op4

```bash
~/Persistent/op4-*-x86_64.AppImage
```

On first launch, op4 creates its vault. Because your home directory
is on the Persistent Storage volume, the vault at
`~/.local/share/op4/vault.op4` is automatically stored on the encrypted
USB partition.

#### 5. Verify the binary

```bash
~/Persistent/op4-*-x86_64.AppImage --print-hash
```

Compare against the
[release hash table](https://github.com/Opfour/op4#release-hash-verification).

### Directory layout on Tails

After setup, your Persistent Storage contains:

```
~/Persistent/
├── op4-<version>-x86_64.AppImage      # The binary
├── op4-<version>-x86_64.AppImage.sha256
└── op4-tor-setup.sh                   # Tor config script

~/.local/share/op4/
└── vault.op4                          # Encrypted vault (auto-created)
```

Both directories live on the LUKS-encrypted Persistent Storage partition.
When Tails shuts down, the USB is the only place any op4 data exists —
the host machine retains nothing.

### Known limitations on Tails

- **Control port config resets on reboot.** Tails rebuilds `/etc/tor/torrc`
  from scratch on every boot. The setup script must run each session.
- **No AppArmor profile auto-install.** Tails has its own AppArmor
  policy. The op4 AppArmor profile (`apparmor/op4.profile`) can be
  loaded manually with `sudo apparmor_parser -r` but will not persist
  across reboots without additional Persistent Storage configuration.
- **Tails upgrades may change Tor paths.** If a future Tails release
  moves the cookie file or changes the Tor group name, the setup script
  may need adjustment. The underlying Tor protocol remains compatible.
- **Performance.** Tails runs from USB and RAM. Argon2id vault
  derivation and Tor circuit setup may be slower than on a native
  install, especially on older hardware.

### Security notes

- **Do not disable Tails' firewall.** Tails blocks all non-Tor traffic
  by default. op4 works within this constraint because it only connects
  to `127.0.0.1` (the local Tor daemon).
- **Use bridges if needed.** If your network blocks Tor, configure
  bridges in Tails' Tor Connection settings before starting op4. op4
  benefits from this automatically since it uses Tails' Tor instance.
- **The duress passphrase works on Tails.** If coerced into unlocking
  your vault, enter the duress passphrase. The decoy inbox appears
  identical to a real (empty) vault. Combined with Tails' amnesic
  properties, this provides plausible deniability — there is no
  filesystem artifact on the host to contradict the decoy.

---

## Supported platforms

| Distro | Status |
|--------|--------|
| Ubuntu 22.04 / 24.04 | Supported |
| Debian 12 | Supported |
| Fedora 39+ | Supported |
| Arch Linux (current) | Supported |
| Tails OS | Supported (see [Tails setup](#option-5--tails-os-persistent-storage)) |
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
