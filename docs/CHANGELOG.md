# Changelog

All notable changes to op4 will be documented here.

Format: [Semantic Versioning](https://semver.org/) —
`MAJOR.MINOR.PATCH[-dev]`

---

## [0.1.0-dev] — 2026-03-15

Initial development release. Not yet suitable for production use.

### Added

**Cryptography**
- Hybrid post-quantum key exchange: X25519 + ML-KEM-768 (FIPS 203)
- Hybrid post-quantum signatures: Ed25519 + ML-DSA-65 (FIPS 204)
- Double Ratchet protocol with per-message ChaCha20-Poly1305 encryption
- HKDF-SHA256 key derivation throughout the ratchet
- HMAC-SHA256 deniable authentication tags on all wire messages
- Argon2id vault key derivation (64 MiB, 3 iterations, parallelism 1)
- ChaCha20-Poly1305 vault encryption with AEAD additional data

**Vault**
- Encrypted vault at `~/.local/share/op4/vault.op4`
- Dual-passphrase vault: normal passphrase + independent duress passphrase
- Visually identical duress inbox (decoy under coercion)
- Atomic vault writes (write to `.tmp`, fsync, rename)
- Passphrase strength enforcement via zxcvbn (score ≥ 3 required)

**Network transport**
- Tor v3 hidden-service transport (replaces Nym SDK stub)
- Hidden-service key derived deterministically from identity signing key
  via HKDF-SHA256 + SHA-512 with Ed25519 scalar clamping
- Tor control port authentication (cookie auth + NULL auth fallback)
- Tor SOCKS5 outbound connections to peer `.onion` addresses
- Inbound TCP listener on `127.0.0.1:14101`
- 4-byte big-endian length-prefixed wire framing
- Poisson-distributed cover traffic (mean 30 s) to self

**Terminal UI**
- Three-tab TUI: Contacts, Messages, Settings
- Contacts tab: add contact, export contact code, view fingerprint,
  verify fingerprint, delete contact
- Messages tab: compose and send messages, conversation view
- Settings tab: settings list (editing not yet connected)
- Key change alert overlay
- Duress mode inbox (visually identical to normal mode)
- Input sanitisation: strips ANSI CSI and OSC escape sequences,
  drops C0/C1 control characters

**OS hardening**
- `mlockall(MCL_CURRENT | MCL_FUTURE)` — no swapping of memory pages
- `RLIMIT_CORE = 0` — no core dumps
- `PR_SET_DUMPABLE = 0` — no ptrace attach from other processes
- seccomp-bpf syscall allowlist (default action: SIGSYS)
- AppArmor profile (`apparmor/op4.profile`)

**Build**
- Source hash (SHA-256 over `src/**/*.rs`) embedded at build time
- Printed to stderr on every startup for build verification
- Rust toolchain pinned to 1.88.0 via `rust-toolchain.toml`
- `cargo-deny` rules: no unmaintained/yanked/vulnerable/copyleft crates

**Installation**
- `install/setup.sh` system installation script
- Creates `op4` system user, installs binary, loads AppArmor profile

### Known Limitations (in progress)

- Identity keypair generation not yet wired to first-run setup
- Contact code export shows a placeholder, not the real serialized key bundle
- Message send in the UI does not yet call the Tor transport layer
- Inbound messages are not yet displayed in the conversation view

---

## Roadmap

Items planned for the next release (0.2.0):

- Wire identity keypair generation into first-run vault creation
- Implement real contact code serialisation (`PublicKeyBundle` → Base58)
- Connect message send to `NymClient::send()`
- Poll `NymClient::try_recv_msg()` in TUI event loop
- Contact rename in the UI
- Editable settings (Tor SOCKS5 address, auto-delete threshold)
- Multi-platform CI (GitHub Actions)
