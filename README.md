# op4 — Secure Terminal Messenger

op4 is a terminal-based encrypted messaging application written in Rust.
It provides end-to-end encrypted private messaging with post-quantum
cryptography, routed entirely through the Tor anonymity network so that
neither the content of your messages nor your IP address is exposed to
anyone — not even the person you are talking to.

---

## Table of Contents

1. [What op4 Does](#what-op4-does)
2. [Security Model](#security-model)
3. [Architecture Overview](#architecture-overview)
4. [Project Layout](#project-layout)
5. [Current Status](#current-status)

---

## What op4 Does

op4 lets two people exchange private messages without either party
revealing their IP address or real identity. Every message is:

- **End-to-end encrypted** using a Double Ratchet protocol — the same
  fundamental design used by Signal.
- **Post-quantum hardened** — the key exchange layer combines classical
  X25519 with ML-KEM-768 (NIST-standardised lattice-based KEM), so a
  future quantum computer cannot retroactively decrypt recorded traffic.
- **Anonymised** — all traffic travels over Tor hidden services
  (.onion addresses). Your IP address is never exposed to your contact or
  to any network observer.
- **Stored locally** — there is no server. Your messages and contacts live
  in an encrypted vault file on your own machine, and nowhere else.

op4 runs entirely in the terminal. It has no GUI, no browser component,
and no cloud account. The only external process it contacts is the Tor
daemon running on your own machine.

---

## Security Model

### Cryptographic primitives (all from the RustCrypto ecosystem)

| Purpose | Algorithm |
|---|---|
| Vault key derivation | Argon2id (m=64 MiB, t=3, p=1) |
| Vault encryption | ChaCha20-Poly1305 (256-bit key, 96-bit nonce) |
| Message encryption | ChaCha20-Poly1305 (per-message key from ratchet) |
| Key derivation (ratchet) | HKDF-SHA256 |
| Deniable authentication | HMAC-SHA256 |
| Classical key exchange | X25519 |
| Post-quantum key exchange | ML-KEM-768 (FIPS 203) |
| Classical signatures | Ed25519 |
| Post-quantum signatures | ML-DSA-65 (FIPS 204) |
| Transport anonymity | Tor v3 hidden services (.onion) |

### Double Ratchet

op4 uses a Double Ratchet protocol (similar to Signal Protocol) for
forward secrecy. This means:

- Each message is encrypted with a unique key derived from a ratchet chain.
- Compromising one message key does not expose any other message.
- If your device is seized, past messages that have already been deleted
  cannot be decrypted even if the attacker learns your vault passphrase.

### Hybrid post-quantum key exchange

The KEM step combines X25519 and ML-KEM-768 as follows:

```
shared_secret = HKDF(X25519_ss || MLKEM_ss)
```

An attacker must break **both** algorithms to compromise the key exchange.
This protects against a quantum adversary (ML-KEM-768) while remaining
secure against classical attacks if ML-KEM-768 has an unknown flaw
(X25519 fallback).

### Deniable authentication

Messages are authenticated with HMAC-SHA256 using a key derived from the
shared ratchet state. Because both parties hold the same HMAC key, either
party could have produced any given MAC. This is the same deniability
property used by OTR and Signal: messages cannot be cryptographically
attributed to a specific sender in a court proceeding.

### Vault and duress passphrase

The vault file at `~/.local/share/op4/vault.op4` stores all contacts,
conversations, and identity keys. It is protected with two independent
Argon2id-derived keys:

- **Normal passphrase** — unlocks your real contacts and messages.
- **Duress passphrase** — unlocks a visually identical but empty decoy
  inbox. Use this if you are coerced into unlocking the app. From the
  outside the two passphrases are indistinguishable.

### Network anonymity

op4 creates a Tor v3 hidden service for your inbox. Your `.onion` address
is derived deterministically from your identity key (via HKDF), so it is
stable across restarts without needing to store a separate key. Outbound
messages are sent through the Tor SOCKS5 proxy. Your real IP address never
appears in any network packet related to op4.

Cover traffic (Poisson-distributed dummy messages sent to self,
mean interval 30 seconds) prevents a network observer from learning
whether you are actively messaging someone by watching traffic volume.

### OS-level hardening

- **mlockall** — prevents vault keys and plaintext from being written
  to swap.
- **RLIMIT_CORE = 0** — disables core dumps that could expose memory.
- **PR_SET_DUMPABLE = 0** — prevents other processes from attaching a
  debugger.
- **seccomp-bpf** — installs a syscall allowlist. Any syscall not in
  the list causes the process to be killed immediately.
- **AppArmor profile** (`apparmor/op4.profile`) — restricts filesystem
  access to only the vault directory, terminal devices, and Tor.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        op4 process                          │
│                                                             │
│  ┌──────────┐   ┌──────────────────┐   ┌────────────────┐  │
│  │   TUI    │   │  Double Ratchet  │   │  Tor Transport │  │
│  │ (ratatui)│──▶│  + Hybrid PQ     │──▶│  nym_client.rs │  │
│  │          │   │  Crypto          │   │                │  │
│  └──────────┘   └──────────────────┘   └───────┬────────┘  │
│                                                │           │
│  ┌──────────────────────────────┐              │           │
│  │  Encrypted Vault             │    SOCKS5 / control port │
│  │  ~/.local/share/op4/vault.op4│              │           │
│  └──────────────────────────────┘              │           │
└────────────────────────────────────────────────┼───────────┘
                                                 │
                                    ┌────────────▼────────────┐
                                    │      Tor daemon         │
                                    │  127.0.0.1:9050 (SOCKS) │
                                    │  127.0.0.1:9051 (ctrl)  │
                                    └────────────┬────────────┘
                                                 │
                                         Tor network
                                                 │
                                    ┌────────────▼────────────┐
                                    │  Peer's .onion address  │
                                    │  (their hidden service) │
                                    └─────────────────────────┘
```

---

## Project Layout

```
op4/
├── src/
│   ├── main.rs                  Entry point, startup sequence
│   ├── error.rs                 Unified error types
│   ├── crypto/
│   │   ├── keys.rs              Hybrid KEM + signature keypairs
│   │   ├── primitives.rs        AEAD, HKDF, HMAC, Argon2id
│   │   ├── ratchet.rs           Double Ratchet implementation
│   │   ├── hmac_auth.rs         Deniable authentication tags
│   │   └── handshake.rs         Initial key agreement (X3DH-style)
│   ├── network/
│   │   ├── nym_client.rs        Tor hidden-service transport
│   │   └── message.rs           Wire message format + padding
│   ├── storage/
│   │   └── vault.rs             Encrypted vault (Argon2id + AEAD)
│   ├── identity/
│   │   ├── profile.rs           Contact codes, stored contacts
│   │   └── revocation.rs        Key revocation records
│   ├── hardening/
│   │   ├── memory.rs            mlockall, RLIMIT_CORE, dumpable
│   │   └── seccomp.rs           seccomp-bpf syscall filter
│   └── ui/
│       ├── app.rs               TUI event loop and state machine
│       ├── contacts.rs          Contacts tab rendering
│       ├── conversation.rs      Messages tab rendering
│       ├── settings.rs          Settings tab rendering
│       ├── duress.rs            Duress inbox rendering
│       ├── input.rs             Input sanitization (CSI/OSC strip)
│       └── passphrase.rs        Secure passphrase prompts
├── apparmor/
│   └── op4.profile              AppArmor MAC profile
├── install/
│   └── setup.sh                 System installation script
├── build.rs                     Embeds source hash at compile time
├── deny.toml                    cargo-deny licence + advisory rules
├── rust-toolchain.toml          Pins Rust 1.88.0
└── docs/                        This documentation
```

---

## Current Status

**Version: 0.1.0-dev (pre-release)**

op4 is under active development. The following layers are complete and
tested:

- Vault (create, unlock, save, duress mode)
- All cryptographic primitives (12/12 unit tests passing)
- Tor hidden-service transport (connect, send, receive, cover traffic)
- Terminal UI (navigation, contacts management, conversation view)
- OS hardening (memory, seccomp, AppArmor)

All layers are now wired end-to-end:

- Identity keypairs (X25519+ML-KEM-768, Ed25519+ML-DSA-65) are generated
  on first run and stored encrypted in the vault.
- Contact code export produces a real Base58-encoded `PublicKeyBundle`
  (your full public key set + onion address).
- Sending a message performs a full X3DH-style handshake on the first
  message to a contact, then Double Ratchet encryption on subsequent
  messages, transmitted over Tor.
- Inbound messages are polled from the Tor transport in the TUI event
  loop and displayed in the conversation view (sealed-sender pattern:
  the routing layer never reveals who sent the message).

All known limitations from the previous release have been resolved:

- **HMAC deniable authentication** is now fully wired. Every outbound data
  message carries an HMAC-SHA256 tag computed from the per-message ratchet
  key over `(conversation_id || message_counter || ciphertext)`. Inbound
  messages are verified before being accepted; zero-filled tags from older
  peers are tolerated for backward compatibility.
- **Message history persists across restarts.** The full conversation log
  is encrypted with a per-conversation HKDF-derived key and stored in the
  vault's `message_log_ct` field. Messages are loaded from the vault when
  a conversation is opened and written back after each send or receive.
- **Inbound contact requests** from unknown parties are now queued rather
  than dropped. The Contacts tab shows a badge when requests are waiting.
  Press `[p]` to review: you see the sender's fingerprint and their first
  message, type a name, and press Enter to accept (or Esc to reject). On
  acceptance the contact is added, the Double Ratchet is initialised, and
  the initial message is saved to the vault.
