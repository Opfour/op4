# Security Policy and Threat Model

---

## Threat Model

op4 is designed to protect against the following adversaries:

### 1. Passive network observer

An adversary who can monitor network traffic (ISP, VPN provider, coffee
shop Wi-Fi operator, national firewall) sees only encrypted Tor traffic.
They cannot determine:

- Who you are messaging
- When you are messaging (cover traffic obscures idle vs. active periods)
- The content of any message

### 2. Active network attacker (man-in-the-middle)

An attacker who attempts to intercept and substitute contact codes is
defeated by the out-of-band fingerprint verification step. Once
fingerprints are verified, any tampering with subsequent messages causes
AEAD authentication to fail and the message is silently dropped.

### 3. Server-side compromise

There is no server. Messages are routed peer-to-peer over Tor hidden
services. There is nothing to compromise.

### 4. Device seizure (past messages)

If your device is seized and your vault passphrase is extracted, the
attacker can read messages that are still stored in your vault. Messages
that have already been deleted are not recoverable.

Future messages cannot be read — forward secrecy means that
compromising today's keys does not expose messages encrypted with
yesterday's keys.

### 5. Device seizure under coercion

The duress passphrase opens a visually identical empty inbox. An
attacker who coerces you into unlocking op4 sees a decoy that is
indistinguishable from a legitimate but inactive account.

### 6. Quantum computer (future threat)

A quantum computer large enough to run Shor's algorithm could break
X25519 and Ed25519. op4 combines these with ML-KEM-768 and ML-DSA-65
(NIST FIPS 203 and FIPS 204) so that both classical and quantum attacks
must succeed simultaneously to compromise any key exchange.

---

## What op4 Does Not Protect Against

### Endpoint compromise

If an attacker has root on your machine, or has installed a keylogger,
no encryption software can protect you. Secure your device first.

### Metadata beyond IP address

op4 hides your IP address via Tor. It does not hide:
- The fact that you are running Tor (visible to your ISP)
- Message timing at the application layer if both parties are online
  simultaneously and cover traffic is stripped (advanced traffic analysis)
- The existence of the vault file on your disk

### Offline message delivery

op4 has no server to buffer messages. If you are offline when a contact
tries to message you, the message is lost. Both parties must be online
simultaneously.

### Weak passphrases

Argon2id with 64 MiB memory and 3 iterations makes brute-force attacks
expensive, but a very short or common passphrase can still be cracked.
The built-in zxcvbn check enforces a minimum strength but cannot account
for all possible weak choices.

---

## Reporting a Vulnerability

If you discover a security vulnerability in op4:

1. **Do not open a public issue.** Public disclosure before a patch is
   ready puts all users at risk.

2. Email a description of the vulnerability to the maintainers. Include:
   - A description of the issue and its potential impact
   - Steps to reproduce
   - Any proof-of-concept code (if applicable)
   - Your suggested fix (if you have one)

3. You will receive an acknowledgement within 72 hours.

4. A patch will be developed, tested, and released before public
   disclosure. Credit will be given to the reporter unless they prefer
   to remain anonymous.

---

## Cryptographic Library Audit Status

All cryptographic implementations used by op4 are from the
[RustCrypto](https://github.com/RustCrypto) project. These are
maintained, widely-reviewed community libraries.

op4 uses only high-level RustCrypto APIs. It does not implement any
cryptographic primitives itself.

The `deny.toml` file in the repository root enforces:
- No unmaintained crates
- No yanked crate versions
- No known-vulnerable crate versions (RustSec advisory database)
- No copyleft dependencies
- Dependencies from crates.io only (no unknown git sources)

---

## Build Reproducibility

op4 embeds a SHA-256 hash of all `src/**/*.rs` files at compile time
(via `build.rs`). This hash is printed to stderr on every startup. Users
who build from source should compare this hash against the hash published
in the release notes to confirm their binary was built from unmodified
source.
