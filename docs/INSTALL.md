# Installing and Uninstalling op4

---

## Requirements

| Requirement | Minimum version | Notes |
|---|---|---|
| Linux (x86_64) | Kernel 5.4+ | seccomp-bpf required |
| Rust toolchain | 1.88.0 | Pinned in `rust-toolchain.toml` |
| Tor | Any recent | Package: `tor` |
| gcc / linker | Any recent | For Rust build |
| pkg-config | Any | For Rust build |

The app has **no runtime shared-library dependencies** beyond what is
standard on any modern Linux system (`libseccomp2`, `libc`).

---

## Step 1 — Install Tor

Tor must be installed and running before op4 can start.

### Debian / Ubuntu / Mint

```bash
sudo apt update
sudo apt install tor
```

### Fedora / RHEL / CentOS

```bash
sudo dnf install tor
```

### Arch Linux

```bash
sudo pacman -S tor
```

After installing, verify Tor is running:

```bash
systemctl status tor
```

---

## Step 2 — Configure Tor

Two lines must be present in `/etc/tor/torrc`. Open the file:

```bash
sudo nano /etc/tor/torrc
```

Add or uncomment these two lines:

```
ControlPort 9051
CookieAuthentication 1
```

Save the file, then restart Tor:

```bash
sudo systemctl restart tor
```

Verify the control port is listening:

```bash
ss -tlnp | grep 9051
# Expected: LISTEN  127.0.0.1:9051
```

---

## Step 3 — Join the debian-tor group

op4 reads Tor's authentication cookie to prove it is allowed to use the
control port. The cookie file is owned by the `debian-tor` group and is
readable only by members of that group.

```bash
sudo adduser $USER debian-tor
```

**You must log out and log back in** (or start a new login shell) for
the group change to take effect. Verify:

```bash
groups
# Your username should appear next to debian-tor
```

> **Note for non-Debian systems:** The group may be named `tor` instead
> of `debian-tor`. Adjust accordingly and check the group ownership of
> `/run/tor/control.authcookie`.

---

## Step 4 — Install the Rust toolchain

If Rust is not already installed:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

The correct toolchain version (1.88.0) is pinned in `rust-toolchain.toml`
and will be downloaded automatically by Cargo on first build.

---

## Step 5 — Build op4

```bash
cd /path/to/op4
cargo build --release
```

The compiled binary is at:

```
target/release/op4
```

Build time is approximately 1–3 minutes on a modern machine. The binary
is fully statically linked against Rust's standard library and has no
Rust-level shared dependencies.

---

## Step 6 — Install system-wide (optional)

The included installation script copies the binary to `/usr/local/bin`,
installs the AppArmor profile, and creates a system user.

**Run as root:**

```bash
sudo bash install/setup.sh
```

The script will:

1. Create a `op4` system user (no login shell, no home directory).
2. Create `/var/lib/op4` with mode 0700.
3. Copy `target/release/op4` to `/usr/local/bin/op4`.
4. Install `apparmor/op4.profile` to `/etc/apparmor.d/op4`.
5. Load the AppArmor profile immediately (`apparmor_parser -r`).

After installation, any user on the system can run `op4` from their
terminal. Each user's vault is stored separately in their own
`~/.local/share/op4/` directory.

### Manual install (without the script)

```bash
# Copy binary
sudo install -o root -g root -m 0755 target/release/op4 /usr/local/bin/op4

# Install AppArmor profile (optional but recommended)
sudo install -o root -g root -m 0644 apparmor/op4.profile /etc/apparmor.d/op4
sudo apparmor_parser -r /etc/apparmor.d/op4
```

---

## Verifying the Build

op4 embeds a SHA-256 hash of all its source files at compile time. On
every startup it prints this hash to stderr before the TUI launches:

```
op4  source hash: a3f8c2d1e5b7...
     Verify this matches the published release hash before trusting this build.
```

Compare this with the hash published in the release notes. A mismatch
means either the source was modified or the build is not reproducible.

---

## Uninstalling op4

### Remove the binary

```bash
sudo rm /usr/local/bin/op4
```

### Remove the AppArmor profile

```bash
sudo apparmor_parser -R /etc/apparmor.d/op4
sudo rm /etc/apparmor.d/op4
```

### Remove your vault and all stored data

```bash
rm -rf ~/.local/share/op4/
```

> **This is irreversible.** All contacts, conversations, and identity
> keys are deleted. There is no recovery mechanism — the vault is
> encrypted and only you hold the passphrase.

### Remove the system user (if using system-wide install)

```bash
sudo deluser op4
sudo rm -rf /var/lib/op4
```

### Remove from debian-tor group (optional)

```bash
sudo deluser $USER debian-tor
```

### Uninstall Tor (only if you don't use it for anything else)

```bash
sudo apt remove tor
```
