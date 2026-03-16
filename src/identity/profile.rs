use serde::{Deserialize, Serialize};
use std::time::Instant;

use crate::crypto::keys::PublicKeyBundle;
use crate::error::IdentityError;

// ─── Bootstrap Code ───────────────────────────────────────────────────────────

/// Version prefix that identifies a bootstrap contact code (v2: sealed bundle exchange).
pub const BOOTSTRAP_PREFIX: &str = "op4b2:";

/// Compact contact code (~145 bytes serialised) that fits inside a QR code.
///
/// Contains the transport address, the Ed25519 verifying key, the X25519 public
/// key (used to seal the `BundleRequest` so Tor relays cannot read the social
/// graph), and the full 32-byte SHA-256 fingerprint of the `PublicKeyBundle`.
/// The recipient scans the QR, pastes the code into op4's *Add contact* prompt,
/// and op4 automatically sends an encrypted `WireMessageType::BundleRequest`.
/// Once the peer replies with a `BundleResponse`, op4 verifies the fingerprint
/// and adds the contact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapCode {
    /// Tor hidden-service address the peer is listening on.
    pub nym_address: String,
    /// Ed25519 verifying key — used to match a `BundleResponse` to this request.
    pub ed25519_vk: [u8; 32],
    /// X25519 public key — used by the requester to seal the `BundleRequest`
    /// via ephemeral ECDH, hiding the requester's identity from Tor relays.
    pub x25519_pub: [u8; 32],
    /// Full 32-byte SHA-256 fingerprint of the `PublicKeyBundle`.
    /// Verified when the bundle is received so the caller cannot be spoofed.
    pub fingerprint_prefix: [u8; 32],
}

impl BootstrapCode {
    /// Build a bootstrap code from an already-constructed `PublicKeyBundle`.
    pub fn from_bundle(bundle: &PublicKeyBundle) -> Self {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(bundle.x25519_pub);
        h.update(&bundle.mlkem_ek);
        h.update(bundle.ed25519_vk);
        h.update(&bundle.mldsa_vk);
        h.update(bundle.ratchet_pub);
        let digest: [u8; 32] = h.finalize().into();
        Self {
            nym_address: bundle.nym_address.clone(),
            ed25519_vk: bundle.ed25519_vk,
            x25519_pub: bundle.x25519_pub,
            fingerprint_prefix: digest,
        }
    }

    /// Encode to a human-readable, paste-able string prefixed with `op4b1:`.
    pub fn encode(&self) -> String {
        let bytes = postcard::to_allocvec(self).expect("BootstrapCode serialisation cannot fail");
        format!("{}{}", BOOTSTRAP_PREFIX, bs58::encode(bytes).into_string())
    }

    /// Decode from the string produced by `encode()`.
    pub fn decode(s: &str) -> Result<Self, IdentityError> {
        let inner = s
            .trim()
            .strip_prefix(BOOTSTRAP_PREFIX)
            .ok_or(IdentityError::InvalidFormat)?;
        let bytes = bs58::decode(inner)
            .into_vec()
            .map_err(|_| IdentityError::InvalidBase58)?;
        postcard::from_bytes(&bytes).map_err(|_| IdentityError::InvalidFormat)
    }

    /// Return `true` when the string looks like a bootstrap code (has the right prefix).
    pub fn is_bootstrap(s: &str) -> bool {
        s.trim_start().starts_with(BOOTSTRAP_PREFIX)
    }
}

/// A decoded contact code (what users exchange out-of-band).
/// Base58-encoded `PublicKeyBundle` via postcard serialization.
pub struct ContactCode(pub PublicKeyBundle);

impl ContactCode {
    pub fn encode(&self) -> String {
        let bytes = postcard::to_allocvec(&self.0).expect("serialization cannot fail");
        bs58::encode(bytes).into_string()
    }

    pub fn decode(s: &str) -> Result<Self, IdentityError> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|_| IdentityError::InvalidBase58)?;
        let bundle: PublicKeyBundle =
            postcard::from_bytes(&bytes).map_err(|_| IdentityError::InvalidFormat)?;
        Ok(ContactCode(bundle))
    }

    pub fn bundle(&self) -> &PublicKeyBundle {
        &self.0
    }

    pub fn fingerprint(&self) -> String {
        self.0.fingerprint()
    }
}

/// A stored contact in the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredContact {
    pub id: [u8; 32], // SHA-256 of their full contact code bytes
    pub bundle: PublicKeyBundle,
    pub display_name: String,
    pub verified: bool,    // did user verify fingerprint out-of-band?
    pub last_key_seq: u64, // monotonic sequence to detect key changes
    pub added_seq: u64,    // monotonic counter at time of addition (no wall clock)
}

impl StoredContact {
    pub fn new(bundle: PublicKeyBundle, display_name: String, seq: u64) -> Self {
        use sha2::{Digest, Sha256};
        let bytes = postcard::to_allocvec(&bundle).unwrap_or_default();
        let mut h = Sha256::new();
        h.update(&bytes);
        let id = h.finalize().into();
        Self {
            id,
            bundle,
            display_name,
            verified: false,
            last_key_seq: 0,
            added_seq: seq,
        }
    }
}

/// Rate-limit tracker for key changes.
/// Max 1 key change per 24 hours using monotonic time only.
pub struct KeyChangeGuard {
    last_changed: Option<Instant>,
}

impl KeyChangeGuard {
    pub fn new() -> Self {
        Self { last_changed: None }
    }

    pub fn can_change_key(&self) -> bool {
        match self.last_changed {
            None => true,
            Some(t) => t.elapsed().as_secs() >= 24 * 3600,
        }
    }

    pub fn record_change(&mut self) -> Result<(), IdentityError> {
        if !self.can_change_key() {
            return Err(IdentityError::KeyChangeTooFrequent);
        }
        self.last_changed = Some(Instant::now());
        Ok(())
    }
}

impl Default for KeyChangeGuard {
    fn default() -> Self {
        Self::new()
    }
}
