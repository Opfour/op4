# Post Title

op4 — Terminal-based encrypted messenger with post-quantum crypto, Tor routing, and a duress vault [Rust, Linux, pre-release]

# Post Body

**Repo:** https://github.com/Opfour/op4

op4 is a terminal-based encrypted messenger written in Rust. Two people can exchange private messages without revealing their IP addresses or real identities. There is no server, no cloud account, and no GUI — everything runs locally over Tor hidden services.

### What it does

- **End-to-end encrypted** using a Double Ratchet protocol (same design as Signal)
- **Post-quantum hardened** — hybrid key exchange combining X25519 + ML-KEM-768 (NIST FIPS 203), so a future quantum computer can't retroactively decrypt recorded traffic
- **Fully anonymous** — all traffic routed through Tor v3 hidden services; your IP is never exposed to your contact or any observer
- **Local-only storage** — messages and keys live in an encrypted vault on your machine (Argon2id + ChaCha20-Poly1305)
- **Duress vault** — a second passphrase opens a decoy empty inbox, indistinguishable from the real one, for coercion scenarios
- **OS hardening** — mlockall (no swap), disabled core dumps, seccomp-bpf syscall allowlist, AppArmor profile
- **Deniable authentication** — HMAC-based auth means messages can't be cryptographically attributed to a specific sender
- **Cover traffic** — Poisson-distributed dummy messages prevent traffic analysis

### Installation

One-line install on Debian/Ubuntu:

```
git clone https://github.com/Opfour/op4.git && cd op4 && sudo bash install/setup.sh
```

Also supports Fedora, Arch, and Tails OS. AppImage and source tarball available on the [Releases page](https://github.com/Opfour/op4/releases/latest). Reproducible builds are verified in CI.

### Current status: 0.2.0-dev (pre-release)

The core is feature-complete and tested (62 active unit tests, all passing). CI pipeline runs clippy, cargo audit, cargo-deny, and reproducible build verification on every push. All crypto uses audited RustCrypto libraries — no custom implementations.

### Caveats — read these before trying it

- **Linux only.** seccomp and prctl hardening means no macOS or Windows support yet. Ubuntu 22.04+, Debian 12, Fedora 39+, Arch, and Tails are supported.
- **Both parties must be online.** There is no server to queue messages. You and your contact need to be running op4 simultaneously.
- **Tor is required.** You need the Tor daemon running locally. The install script handles this on Debian/Ubuntu, but it's a setup step on other distros.
- **Terminal only.** This is a TUI app. If you're not comfortable in a terminal, this isn't for you (yet).
- **Android port is experimental.** It compiles but is not ready for testing. Don't use it.

### Looking for feedback

This is a pre-release. I'm looking for people willing to do exploratory testing — especially around the messaging flow, Tor connectivity, vault persistence, and fingerprint verification. There's a [tester guide](https://github.com/Opfour/op4/docs/TESTING.md) with specific test cases and keyboard shortcuts.

You'll need a partner to test messaging (both parties must be online), so if you want to try it, pair up in the comments.

Issues and feedback: https://github.com/Opfour/op4/issues
