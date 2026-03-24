# op4 Android Port — Roadmap

Roadmap for porting op4 to Android as a sideloaded APK (F-Droid / direct install).
This is an exploratory document covering what works, what doesn't, and what
needs to be built.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    Android App                          │
│                                                         │
│  ┌──────────────┐   ┌──────────────┐   ┌────────────┐  │
│  │  Jetpack     │   │  op4-core    │   │   Arti     │  │
│  │  Compose UI  │──▶│  (Rust FFI)  │──▶│  (Rust Tor)│  │
│  │              │   │              │   │            │  │
│  └──────────────┘   └──────┬───────┘   └─────┬──────┘  │
│                            │                 │          │
│  ┌──────────────┐   ┌──────▼───────┐         │          │
│  │  Android     │   │  Encrypted   │   SOCKS5 proxy    │
│  │  Keystore +  │   │  Vault       │         │          │
│  │  Hardening   │   │  (app-private│         │          │
│  │              │   │   storage)   │         │          │
│  └──────────────┘   └──────────────┘         │          │
└──────────────────────────────────────────────┼──────────┘
                                               │
                                       Tor network
                                               │
                                  ┌────────────▼────────────┐
                                  │  Peer's .onion address  │
                                  └─────────────────────────┘
```

---

## What Works (Reusable As-Is)

These modules are pure Rust with no platform dependencies. They compile
to Android NDK targets (`aarch64-linux-android`, `x86_64-linux-android`)
with zero changes.

| Module | Lines | Notes |
|--------|-------|-------|
| `crypto/keys.rs` | 150 | ML-KEM-768, ML-DSA-65, X25519, Ed25519 |
| `crypto/primitives.rs` | 80 | ChaCha20-Poly1305, HKDF, HMAC, Argon2id |
| `crypto/ratchet.rs` | 200 | Double Ratchet protocol |
| `crypto/handshake.rs` | — | X3DH-style key agreement |
| `crypto/hmac_auth.rs` | — | Deniable authentication |
| `identity/profile.rs` | 80 | Contact codes, public key bundles |
| `identity/revocation.rs` | — | Key revocation certificates |
| `network/message.rs` | 199 | Wire protocol, padding, serialization |
| `storage/vault.rs` | 450 | Core encrypt/decrypt logic (path abstraction needed) |
| `error.rs` | — | Unified error types |

**Total reusable: ~3,900 lines (~60% of codebase)**

All RustCrypto dependencies (`ml-kem`, `ml-dsa`, `x25519-dalek`,
`ed25519-dalek`, `chacha20poly1305`, `argon2`, etc.) are pure Rust and
cross-compile cleanly.

---

## What Doesn't Work (Needs Replacement)

### 1. Terminal UI → Jetpack Compose

**Problem:** `ratatui` + `crossterm` require a terminal. Android has no
terminal (unless running inside Termux, which defeats the purpose of
an APK).

**Solution:** Replace with Jetpack Compose (Kotlin) calling into Rust
via JNI/UniFFI.

**Effort:** Full rewrite of the UI layer (~1,500 lines), but the
business logic (state machine, contact management, message routing)
in `ui/app.rs` can be extracted into `op4-core` and called from Kotlin.

### 2. Tor Integration → Arti (Rust Tor Client)

**Problem:** op4 currently connects to an external Tor daemon via
control port (`127.0.0.1:9051`) and reads a cookie file at
`/run/tor/control.authcookie`. Android doesn't have a system Tor daemon.

**Solution:** Embed [Arti](https://gitlab.torproject.org/tpo/core/arti)
(the Tor Project's official Rust Tor implementation) directly into
the app. Arti runs as an in-process SOCKS5 proxy and can create
hidden services programmatically.

**Alternative:** Bundle `tor` binary for Android and manage it as a
subprocess (how Orbot works). Less clean but proven approach.

**Effort:** New `trait TorTransport` abstraction, then an `ArtiTransport`
implementation. The SOCKS5 client code in `nym_client.rs` is reusable —
only the hidden service setup and authentication change.

### 3. OS Hardening → Android Security APIs

**Problem:** `seccomp-bpf`, `mlockall`, `PR_SET_DUMPABLE` — Linux
kernel interfaces that either don't work or are restricted on Android.

| Desktop Feature | Android Equivalent | Status |
|-----------------|-------------------|--------|
| `seccomp-bpf` syscall filter | SELinux + app sandbox | Provided by OS |
| `mlockall()` | Not available without root | **Degraded** |
| `PR_SET_DUMPABLE = 0` | `android:debuggable=false` in manifest | Equivalent |
| `RLIMIT_CORE = 0` | Android doesn't generate core dumps by default | N/A |
| AppArmor profile | SELinux app domain | Provided by OS |

**What's lost:** Memory locking. Android's zygote process model and
lack of `CAP_IPC_LOCK` for normal apps means key material *could*
theoretically be paged to flash storage. Mitigations:
- Use Android Keystore for master key storage (hardware-backed on
  most devices)
- Call `madvise(MADV_DONTDUMP)` on sensitive buffers (works without root)
- Keep sensitive data lifetime short (zeroize on drop — already
  implemented)

**Effort:** New `hardening/android.rs` module (~100 lines). The app
sandbox provides most of what seccomp + AppArmor give on desktop.

### 4. Vault Path → App-Private Storage

**Problem:** Hardcoded `$HOME/.local/share/op4/vault.op4` (XDG
convention). Android uses `Context.getFilesDir()` for app-private
storage.

**Solution:** Abstract behind `trait VaultStorage`:

```rust
trait VaultStorage {
    fn vault_path(&self) -> PathBuf;
}

// Desktop
struct LinuxVaultStorage;
impl VaultStorage for LinuxVaultStorage {
    fn vault_path(&self) -> PathBuf {
        dirs::data_dir().unwrap().join("op4/vault.op4")
    }
}

// Android
struct AndroidVaultStorage { base: PathBuf }
impl VaultStorage for AndroidVaultStorage {
    fn vault_path(&self) -> PathBuf {
        self.base.join("vault.op4")
        // base = Context.getFilesDir() passed from Kotlin
    }
}
```

**Effort:** Small refactor (~50 lines).

### 5. Passphrase Input → Android System UI

**Problem:** `ui/input.rs` reads passphrases from `/dev/tty` with
`tcgetattr`/`tcsetattr` (raw terminal mode). Not applicable on Android.

**Solution:** Standard Android `EditText` with `inputType=textPassword`
or biometric prompt (`BiometricPrompt` API) as an unlock alternative.

---

## What's Degraded (Works But Weaker)

### Background Connectivity

**Desktop:** Tor hidden service runs continuously. You're always
reachable. Cover traffic runs 24/7.

**Android:** The OS kills background processes aggressively (Doze mode,
app standby buckets). Realistic options:

| Approach | Reachability | Battery | Metadata Leak |
|----------|-------------|---------|---------------|
| Foreground service with notification | Good | High | None |
| WorkManager periodic sync | 15-min minimum | Low | None |
| Push notification relay | Instant | Minimal | **Server knows when you get messages** |
| Only active when app is open | Manual | None | None |

**Recommendation:** Foreground service (persistent notification:
"op4 is running") for users who want always-on. Fall back to
"active only when open" for casual use. **No push notification relay** —
it defeats the threat model.

### Cover Traffic

**Desktop:** Poisson-distributed dummy messages (mean 30s) mask
real traffic patterns.

**Android:** Only feasible while the foreground service is active.
When the app is backgrounded without the service, cover traffic stops
and a timing-analysis adversary can see when you open the app.

**Mitigation:** Document this as a known limitation. Users who need
cover traffic must keep the foreground service running.

### Memory Protections

**Desktop:** `mlockall` pins all pages, preventing swap.

**Android:** No swap on most devices (uses `zram` compressed RAM
instead), so the risk is lower than on desktop. Key material in
compressed RAM is harder to extract than from a swap partition, but
not impossible with physical access.

**Mitigation:** Use `zeroize` aggressively (already implemented),
keep key lifetimes short, and optionally store the vault master key
in Android Keystore (hardware-backed TEE/SE on modern devices).

---

## Phase Plan

### Phase 0 — Workspace Restructuring

Restructure the repo into a Cargo workspace so the core logic is a
separate library crate that both the terminal app and Android app
depend on.

```
op4/
├── Cargo.toml              (workspace root)
├── op4-core/               (library crate)
│   ├── Cargo.toml
│   └── src/
│       ├── crypto/         (moved from src/crypto/)
│       ├── network/        (moved from src/network/)
│       ├── storage/        (moved from src/storage/)
│       ├── identity/       (moved from src/identity/)
│       └── lib.rs
├── op4-cli/                (terminal binary — current app)
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── hardening/
│       └── ui/
├── op4-android/            (Android project)
│   ├── app/
│   │   └── src/main/
│   │       ├── kotlin/     (Compose UI + JNI bridge)
│   │       └── jniLibs/    (compiled .so from op4-core)
│   └── rust/               (JNI wrapper crate)
│       ├── Cargo.toml
│       └── src/lib.rs
└── docs/
```

**Key decisions:**
- `op4-core` has no platform-specific code (no `libc`, no `seccompiler`,
  no `ratatui`)
- Platform traits (`TorTransport`, `VaultStorage`, `Hardening`) defined
  in `op4-core`, implemented in `op4-cli` and `op4-android`
- Terminal binary (`op4-cli`) remains fully functional — no regressions

**Deliverable:** `cargo test` passes on the workspace, `op4-cli` binary
is identical in behavior to current `op4`.

### Phase 1 — Core Library Extraction

Extract all portable code into `op4-core`:

1. Move `crypto/`, `identity/`, `network/message.rs`, `storage/vault.rs`
   into `op4-core/src/`
2. Define platform abstraction traits:
   - `trait TorTransport` — connect, send, receive, create hidden service
   - `trait VaultStorage` — vault path, read, write
   - `trait SecureInput` — passphrase prompts
3. Extract `AppState` from `ui/app.rs` — all business logic (contact
   CRUD, message send/receive, crypto operations) without any rendering
4. Unit tests for `op4-core` independent of any platform

**Deliverable:** `op4-core` compiles for `aarch64-linux-android` target.

### Phase 2 — Tor on Android

Integrate Arti (Rust Tor client) as the Android transport backend.

1. Add `arti-client` dependency to `op4-android/rust/`
2. Implement `ArtiTransport` satisfying `TorTransport` trait:
   - Embedded SOCKS5 proxy (no external daemon)
   - Programmatic hidden service creation
   - Connection through Android's network stack
3. Test: two Android emulators exchange messages over Tor

**Risks:**
- Arti is still maturing — hidden service hosting (not just client
  connections) may have gaps
- Arti binary size adds ~5-10 MB to the APK
- If Arti hidden services aren't ready, fall back to bundling `tor`
  binary for Android (ARM64) and managing it as a subprocess

**Deliverable:** End-to-end encrypted message exchange between two
Android emulators over real Tor.

### Phase 3 — Android UI (Jetpack Compose)

Build the Android UI with Kotlin + Jetpack Compose, calling `op4-core`
through JNI (using [UniFFI](https://github.com/mozilla/uniffi-rs) for
ergonomic Rust↔Kotlin bindings).

**Screens:**
1. **Unlock** — Passphrase entry (with biometric option via Keystore)
2. **Contacts** — List, add (paste or scan QR), delete, pending requests
3. **Conversation** — Message list, input, send
4. **Settings** — Tor status, auto-delete threshold, key rotation
5. **Export** — Contact code display + QR code

**Design principles:**
- Material 3 / Material You theming
- Dark mode default (consistent with privacy-focused aesthetic)
- No analytics, no telemetry, no network calls except Tor
- Foreground service toggle in settings

**Deliverable:** Functional APK that can unlock vault, manage contacts,
and send/receive messages.

### Phase 4 — Android Hardening

Implement Android-specific security measures:

1. **Manifest hardening:**
   - `android:debuggable="false"`
   - `android:allowBackup="false"` (vault should not be in cloud backups)
   - `android:usesCleartextTraffic="false"`
   - `networkSecurityConfig` restricting to localhost only (Tor SOCKS5)

2. **Android Keystore integration:**
   - Store vault master key in hardware-backed keystore
   - Require biometric or PIN to unlock keystore entry
   - `setUserAuthenticationRequired(true)`

3. **Memory protections:**
   - `madvise(MADV_DONTDUMP)` on sensitive buffers (via JNI)
   - `FLAG_SECURE` on all activities (prevents screenshots/screen recording)
   - Zeroize on drop (already in `op4-core`)

4. **Root/tamper detection (optional, document tradeoffs):**
   - SafetyNet/Play Integrity attestation (requires Google Play — conflicts
     with sideloading philosophy)
   - Basic root detection (check for `su`, Magisk) — trivially bypassable,
     document as advisory only

**Deliverable:** Hardened APK with keystore integration and screenshot
protection.

### Phase 5 — Distribution & Testing

1. **Sideload APK:**
   - Signed with self-managed key (not Play Store)
   - Reproducible builds (match APK hash across independent builds)
   - SHA-256 checksum published alongside APK

2. **F-Droid:**
   - Add `metadata/` directory with F-Droid build recipe
   - F-Droid builds from source (reproducible build verification)
   - No proprietary dependencies (no Google Play Services)

3. **Testing matrix:**
   - Android 10+ (API 29+) — minimum for modern Keystore APIs
   - ARM64 primary, x86_64 emulator secondary
   - Test on: Pixel (stock), Samsung (OneUI), OnePlus (OxygenOS)
   - Battery drain benchmarks with foreground service active

4. **CI/CD:**
   - GitHub Actions workflow: build APK on tag push
   - Cross-compile Rust to `aarch64-linux-android`
   - Run `op4-core` unit tests in CI
   - Instrument Android tests with Espresso/Compose testing

**Deliverable:** Signed APK on GitHub Releases, F-Droid listing.

---

## Risk Register

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Arti hidden services not stable | Blocks Phase 2 | Medium | Fall back to bundled `tor` binary |
| Foreground service killed by OEM battery optimization | Breaks reachability | High | Document per-OEM workarounds (Samsung, Xiaomi, Huawei all have aggressive killers) |
| Argon2id too slow on low-end Android devices | Poor UX on unlock | Medium | Tune parameters (lower memory/iterations), add progress indicator |
| APK size bloat from Arti + Rust | >50 MB APK | Low | Strip symbols, LTO, consider `tor` subprocess instead |
| `ml-kem` / `ml-dsa` performance on ARM64 | Slow key exchange | Low | Benchmark; these are already optimized for ARM NEON |
| Users forget foreground service is draining battery | Bad reviews, uninstalls | High | Clear notification, auto-stop after configurable idle period |

---

## Open Questions

1. **Minimum Android version?** API 29 (Android 10) gives modern Keystore
   and scoped storage. API 26 (Android 8) is possible but loses some
   hardening options.

2. **Arti vs bundled Tor binary?** Arti is cleaner (in-process, pure Rust)
   but less mature for hidden services. Bundled `tor` is battle-tested
   but requires subprocess management and adds ~8 MB.

3. **Biometric unlock?** Store vault key in Android Keystore behind
   biometric gate? Convenient but changes the threat model (biometric
   is coercible). The duress passphrase feature assumes two passphrases —
   biometric would need a separate duress trigger.

4. **Notification content?** When a message arrives and the app is in
   foreground service mode, show "New message from [contact name]"
   (leaks metadata to anyone who sees the notification) or just
   "New message" (privacy-preserving but less useful)?

5. **Tablet / foldable support?** Compose handles responsive layouts
   well, but conversation + contacts side-by-side on tablets would need
   additional layout work.
