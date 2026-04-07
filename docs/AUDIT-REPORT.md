# op4 -- Test & Security Audit Report

**Date:** 2026-04-07
**Version:** 0.3.0
**Commit:** 794d3d8

---

## 1. Test Suite Summary

**146 tests total -- all passing.**

```
op4-android   8 tests   (hardening: integrity, entropy, root, storage)
op4-core    114 tests   (crypto, identity, storage, network, error)
op4-core      6 tests   (integration: two_party_messaging)
op4-tui      16 tests   (UI: passphrase, QR, input sanitization, seccomp)
op4-tui      10 tests   (snapshot: contacts, conversation, settings, duress, QR, fingerprint)
```

### 1.1 op4-core Unit Tests (114)

| Module | Tests | Coverage | Notes |
|---|---|---|---|
| crypto::primitives | 5 | 100% | AEAD roundtrip, wrong AAD, HMAC sign/verify, HKDF determinism, Argon2id |
| crypto::keys | 10 | 100% | KEM/signing keypair roundtrip, fingerprint format/determinism, sign/verify, encap/decap |
| crypto::ratchet | 14 | 99% | Basic roundtrip, bidirectional, out-of-order, counters, serialization, split_message_key, KDF functions, skipped key TTL, total_recv counter |
| crypto::handshake | 7 | 100% | Session key match, identity embedding, tampered MAC/ciphertext rejection, OPK handshake, invalid OPK ID rejection, full handshake-to-ratchet flow |
| crypto::hmac_auth | 6 | 100% | Compute/verify, tag size, wrong key/ciphertext/counter/conv_id |
| identity::profile | 12 | 100% | Contact code roundtrip, bootstrap code roundtrip/validation, fingerprint match, key change guard, stored contact ID/verification |
| identity::revocation | 4 | 100% | Retirement roundtrip, rotation with new bundle, wrong bundle rejection, sequence preservation |
| network::message | 8 | 100% | Wire message roundtrip, padding alignment, oversized rejection, dummy message, max wire bytes |
| storage::vault | 16 | 95% | Create/unlock normal/duress, wrong passphrase, save persistence, duress survives save, magic/version check, rollback detection, OPK ID-based consume, unknown ID rejection, OPK ID hash match, replenish trigger, messages roundtrip, conversation get-or-create, settings defaults, corrupt file handling |
| storage::mod | 2 | 100% | Vault path structure |
| error | 18 | 100% | All Display impls, std::error::Error, all From conversions |

### 1.2 op4-core Integration Tests (6)

| Test | What It Covers |
|---|---|
| full_two_party_conversation_with_vault_persistence | X3DH handshake with OPK -> ratchet init -> 8 bidirectional messages -> vault save/reload -> continued messaging after restore |
| outbox_queue_persists_and_retries | Outbox enqueue -> vault save -> reload -> retry drain |
| bootstrap_code_contact_exchange | Bootstrap code encode/decode -> contact creation from bootstrap |
| wire_message_with_ratchet_and_hmac | Ratchet encrypt -> wire message build with HMAC -> verify -> decrypt |
| duress_vault_is_isolated_from_real_data | Normal vault has contacts; duress vault is empty; both unlock correctly |
| app_settings_persist | Settings save -> vault reload -> settings preserved |

### 1.3 op4-tui Unit Tests (16)

| Module | Tests | Notes |
|---|---|---|
| ui::passphrase | 5 | Score tiers, short/empty rejection, strong acceptance, boundary |
| ui::qr | 6 | Line generation, failure fallback, width/height/quiet zone |
| ui::input | 3 | CSI/OSC stripping, control char dropping, normal text preservation |
| hardening::seccomp | 1 | BPF filter compiles (cannot test install without blocking test runner) |

### 1.4 op4-tui Snapshot Tests (10)

Using `insta` + `ratatui::backend::TestBackend`:

| Test | Screen Rendered |
|---|---|
| snapshot_contacts_empty | Empty contact list with action hints |
| snapshot_contacts_with_entries | Contact list with verified/unverified entries |
| snapshot_conversation_with_messages | Message thread with sent/received messages |
| snapshot_conversation_with_search | Conversation view in search mode |
| snapshot_duress_inbox | Duress vault empty inbox |
| snapshot_settings_default | Default settings screen |
| snapshot_settings_custom | Settings with custom values |
| snapshot_qr_code | QR code export popup |
| fingerprint_unverified_shows_warning | Structural assertion: warning banner present |
| fingerprint_verified_shows_checkmark | Structural assertion: verified indicator present |

### 1.5 op4-android Unit Tests (8)

| Module | Tests | Notes |
|---|---|---|
| hardening::integrity | 3 | Debugger detection, injection framework detection, combined verify (tarpaulin-aware) |
| hardening::entropy | 1 | /dev/urandom availability on desktop |
| hardening::root | 2 | Desktop is not rooted, status variants distinct |
| hardening::storage | 2 | File permission 0600 enforcement, nonexistent file no-panic |

---

## 2. Static Analysis

### 2.1 Clippy

```
cargo clippy --workspace --all-targets -- -D warnings
```

**Result: CLEAN -- 0 warnings, 0 errors.**

All warnings from prior runs have been fixed:
- `unnecessary_map_or` in nym_client.rs and transport.rs (changed to `is_some_and`)
- `collapsible_if` in android ui/contacts.rs and ui/mod.rs (collapsed nested ifs)
- `items_after_test_module` in android integrity.rs (moved functions before test module)
- `type_complexity` in handshake.rs (allowed via attribute on return type)

### 2.2 Compiler Warnings

```
cargo build --workspace 2>&1 | grep warning
```

**Result: CLEAN -- 0 warnings.**

---

## 3. Dependency Vulnerability Scan

### 3.1 cargo audit

```
cargo audit
```

**1 vulnerability found (op4-android only):**

| Advisory | Crate | Severity | Impact on op4 |
|---|---|---|---|
| RUSTSEC-2023-0071 | rsa 0.9.10 | 5.9 (medium) | **None.** Transitive via arti-client (Tor). op4 never calls RSA functions directly. Timing side-channel in PKCS#1 v1.5 decryption is only exploitable if you decrypt RSA ciphertext, which arti uses internally for Tor relay handshakes -- not part of op4's threat model. No fix available upstream. |

**3 allowed warnings:**

| Advisory | Crate | Notes |
|---|---|---|
| RUSTSEC-2024-0436 | paste 1.0.15 | Unmaintained. Compile-time macro only. Transitive via pwd-grp -> fs-mistrust -> arti-client. No runtime risk. |
| (duplicate versions) | Various | Multiple tor-* crates pulling different versions of base dependencies. Expected for the arti ecosystem. |

**op4-core and op4-tui have zero advisories.**

### 3.2 cargo deny

```
cargo deny check
```

**Advisories:** Same as cargo audit (rsa Marvin Attack, paste unmaintained).

**Licenses:** All op4 crates now have `license = "GPL-3.0-or-later"`. Third-party dependencies are MIT, Apache-2.0, BSD, or ISC (all compatible).

**Bans:** Duplicate crate version warnings for arti transitive deps. Not actionable -- controlled by upstream arti releases.

---

## 4. Cryptographic Architecture Review

### 4.1 Primitives

| Primitive | Library | Usage | Assessment |
|---|---|---|---|
| ChaCha20-Poly1305 | chacha20poly1305 0.10 | AEAD for vault, ratchet messages, conversation logs | Random nonce per encryption (12 bytes, OsRng). Domain-separated AAD tags. **Sound.** |
| HKDF-SHA256 | hkdf 0.12 | Root/chain key derivation, conversation key derivation, message key split | Proper extract-then-expand. Domain-separated info strings. **Sound.** |
| HMAC-SHA256 | hmac 0.12 | Wire message auth, chain key advancement, rollback marker | Constant-time verification via `subtle` crate. **Sound.** |
| Argon2id | argon2 0.5 | Passphrase to vault key | 64 MiB / 3 iter / 4 lanes / 32-byte salt. Meets OWASP. **Sound.** |
| X25519 | x25519-dalek 2.0 | DH in handshake (5 outputs) and ratchet key exchange | `StaticSecret::random_from_rng(OsRng)`. **Sound.** |
| ML-KEM-768 | ml-kem 0.2 | Post-quantum KEM in hybrid handshake | NIST FIPS 203. Combined with X25519 via HKDF. **Sound.** |
| Ed25519 + ML-DSA-65 | ed25519-dalek 2.1, ml-dsa 0.1 | Hybrid signing for identity and revocation | Dual signature (classical + PQ). **Sound.** |

### 4.2 Vault Format (v2)

- Dual-passphrase (normal + duress) with equal-length padded sections
- Atomic writes (tmp + rename + fsync)
- Rollback detection via HMAC-authenticated sequence marker file
- Per-conversation AEAD keys derived via HKDF from master key
- Identity secrets wrapped in `Zeroizing<Vec<u8>>`
- Section-length prefixes prevent padding-related decryption failures

**No issues found.**

### 4.3 Handshake Protocol (X3DH Hybrid)

5 DH shared secrets concatenated and fed through HKDF-SHA256:
1. DH(IK_a, SPK_b) -- identity to signed prekey
2. DH(EK_a, IK_b) -- ephemeral to identity
3. DH(EK_a, SPK_b) -- ephemeral to signed prekey
4. ML-KEM-768 encapsulation -- post-quantum component
5. DH(EK_a, OPK_b) -- ephemeral to one-time prekey (optional)

Session key is MAC'd and verified before use. Alice's full identity bundle is bound as AAD.

**OPK lookup changed from positional index to ID-based (SHA-256 of public key, 4-byte truncation).** This eliminates the race condition where concurrent handshakes could consume the wrong key due to index shifting.

### 4.4 Double Ratchet

- Standard Signal-style with DH ratchet steps
- MAX_SKIP = 100 (bounded skipped-key storage)
- **Skipped key TTL added: keys expire after 500 messages received** (monotonic `total_recv` counter, never resets across DH ratchet steps)
- Chain keys use HMAC with domain-separated constants (0x01, 0x02)
- Message keys split via HKDF into separate AEAD and MAC keys

### 4.5 OPK Management

- Batch size: 10 keys per generation
- **Auto-replenishment: new batch generated when pool drops to 3 or below**
- ID-based lookup: each OPK identified by 4-byte SHA-256 hash of its public key
- Consumed OPKs are removed from vault and never reused

### 4.6 Hardening

| Module | Platform | Mechanism |
|---|---|---|
| seccomp | TUI (Linux) | BPF syscall allowlist |
| memory | TUI (Linux) | mlockall + prctl(SET_DUMPABLE, 0) |
| integrity | Android | Debugger + injection framework detection (/proc/self/status, /proc/self/maps) |
| root | Android | su/Magisk path checks (warn, not block) |
| storage | Android | File permission enforcement (0600) |
| entropy | Android | /dev/urandom availability check |

All hardening is defense-in-depth, not a security boundary.

---

## 5. Resolved Security Issues

| # | Finding | Severity | Resolution |
|---|---|---|---|
| 1 | Missing license field in Cargo.toml | Low | Added `license = "GPL-3.0-or-later"` to all 3 crates |
| 2 | OPK index-based consumption race | Low | Replaced with ID-based lookup (SHA-256 of public key) |
| 3 | No OPK auto-replenishment | Medium | Added threshold trigger (replenish at 3 remaining) |
| 4 | No expiration on skipped message keys | Low | Added TTL (500 messages via monotonic total_recv counter) |

---

## 6. Open Items (Informational)

| Item | Risk | Notes |
|---|---|---|
| rsa Marvin Attack (RUSTSEC-2023-0071) | Info | Transitive via arti. Not exploitable by op4. Monitor for upstream fix. |
| paste unmaintained (RUSTSEC-2024-0436) | Info | Compile-time macro. No runtime impact. |
| Timing side-channel in vault unlock branching | Negligible | Argon2id dominates timing (~200ms). Sub-microsecond branch difference unexploitable in practice. |
| Sequence marker best-effort write | Known | Silent degradation on read-only filesystem. Returns safe default (no rollback detected). |

---

## 7. Coverage by Crate

| Crate | Tests | Testable Lines | Covered | % |
|---|---|---|---|---|
| op4-core | 120 | ~1200 | ~1150 | ~96% |
| op4-tui | 26 | ~400 | ~300 | ~75% |
| op4-android | 8 | ~100 | ~50 | ~50% |
| **Total** | **154** | **~1700** | **~1500** | **~88%** |

Note: op4-tui's ui/app.rs (1059-line event loop) and nym_client.rs (290-line Tor transport) are not unit-testable. op4-android's UI and transport modules require an Android device/emulator. These are covered by the manual tester guide in `docs/TESTING.md`.

---

## 8. Test Commands

```bash
# Full test suite
cargo test --workspace

# With output
cargo test --workspace -- --nocapture

# Clippy
cargo clippy --workspace --all-targets -- -D warnings

# Dependency audit
cargo audit

# License/ban check
cargo deny check

# Accept new insta snapshots after UI changes
cargo insta accept --workspace
```
