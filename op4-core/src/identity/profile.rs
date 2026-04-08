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

    /// Replace this contact's OPK pool with fresh keys from an OpkRefresh message.
    /// Returns the number of new OPKs accepted.
    pub fn apply_opk_refresh(&mut self, opk_pubs: Vec<[u8; 32]>, opk_ids: Vec<[u8; 4]>) -> usize {
        let count = opk_pubs.len().min(opk_ids.len());
        self.bundle.opk_pubs = opk_pubs[..count].to_vec();
        self.bundle.opk_ids = opk_ids[..count].to_vec();
        count
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{HybridKemKeypair, HybridSigningKeypair, PublicKeyBundle};

    fn make_bundle() -> PublicKeyBundle {
        let kem = HybridKemKeypair::generate();
        let signing = HybridSigningKeypair::generate();
        PublicKeyBundle::from_keypairs(&kem, &signing, [0u8; 32], "test_addr".into())
    }

    // ── BootstrapCode ─────────────────────────────────────────────────────────

    #[test]
    fn bootstrap_code_roundtrip() {
        let bundle = make_bundle();
        let code = BootstrapCode::from_bundle(&bundle);
        let encoded = code.encode();
        assert!(encoded.starts_with(BOOTSTRAP_PREFIX));
        let decoded = BootstrapCode::decode(&encoded).unwrap();
        assert_eq!(decoded.nym_address, code.nym_address);
        assert_eq!(decoded.ed25519_vk, code.ed25519_vk);
        assert_eq!(decoded.x25519_pub, code.x25519_pub);
        assert_eq!(decoded.fingerprint_prefix, code.fingerprint_prefix);
    }

    #[test]
    fn bootstrap_code_fingerprint_matches_bundle_sha256() {
        use sha2::{Digest, Sha256};
        let bundle = make_bundle();
        let code = BootstrapCode::from_bundle(&bundle);
        let mut h = Sha256::new();
        h.update(bundle.x25519_pub);
        h.update(&bundle.mlkem_ek);
        h.update(bundle.ed25519_vk);
        h.update(&bundle.mldsa_vk);
        h.update(bundle.ratchet_pub);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(code.fingerprint_prefix, expected);
    }

    #[test]
    fn bootstrap_code_wrong_prefix_fails() {
        let bundle = make_bundle();
        let encoded = BootstrapCode::from_bundle(&bundle).encode();
        // Strip the real prefix and add a wrong one
        let payload = &encoded[BOOTSTRAP_PREFIX.len()..];
        let wrong = format!("op4x:{payload}");
        assert!(BootstrapCode::decode(&wrong).is_err());
    }

    #[test]
    fn bootstrap_code_garbage_base58_fails() {
        let garbled = format!("{BOOTSTRAP_PREFIX}!!!invalid!!!");
        assert!(BootstrapCode::decode(&garbled).is_err());
    }

    #[test]
    fn is_bootstrap_recognises_prefix() {
        let bundle = make_bundle();
        let encoded = BootstrapCode::from_bundle(&bundle).encode();
        assert!(BootstrapCode::is_bootstrap(&encoded));
        assert!(!BootstrapCode::is_bootstrap("op4x:abc"));
        assert!(!BootstrapCode::is_bootstrap(""));
    }

    // ── ContactCode ───────────────────────────────────────────────────────────

    #[test]
    fn contact_code_roundtrip() {
        let bundle = make_bundle();
        let encoded = ContactCode(bundle.clone()).encode();
        let decoded = ContactCode::decode(&encoded).unwrap();
        assert_eq!(decoded.0.version, bundle.version);
        assert_eq!(decoded.0.nym_address, bundle.nym_address);
        assert_eq!(decoded.0.x25519_pub, bundle.x25519_pub);
        assert_eq!(decoded.0.ed25519_vk, bundle.ed25519_vk);
    }

    #[test]
    fn contact_code_no_prefix() {
        // ContactCode uses plain base58 with no "op4..." prefix
        let bundle = make_bundle();
        let encoded = ContactCode(bundle).encode();
        assert!(!BootstrapCode::is_bootstrap(&encoded));
    }

    #[test]
    fn contact_code_garbage_fails() {
        // Invalid base58 characters
        assert!(ContactCode::decode("!!!not-base58!!!").is_err());
    }

    // ── StoredContact ─────────────────────────────────────────────────────────

    #[test]
    fn stored_contact_starts_unverified_with_correct_seq() {
        let bundle = make_bundle();
        let c = StoredContact::new(bundle, "Alice".into(), 7);
        assert!(!c.verified, "new contacts must start unverified");
        assert_eq!(c.added_seq, 7);
        assert_eq!(c.last_key_seq, 0);
        assert_eq!(c.display_name, "Alice");
    }

    #[test]
    fn stored_contact_id_is_sha256_of_postcard_bundle() {
        use sha2::{Digest, Sha256};
        let bundle = make_bundle();
        let bytes = postcard::to_allocvec(&bundle).unwrap();
        let expected: [u8; 32] = Sha256::digest(&bytes).into();
        let c = StoredContact::new(bundle, "Bob".into(), 0);
        assert_eq!(c.id, expected);
    }

    #[test]
    fn apply_opk_refresh_replaces_pool() {
        let mut c = StoredContact::new(make_bundle(), "Eve".into(), 0);
        assert!(c.bundle.opk_pubs.is_empty());

        let pubs = vec![[0xAA; 32], [0xBB; 32], [0xCC; 32]];
        let ids = vec![[1, 0, 0, 0], [2, 0, 0, 0], [3, 0, 0, 0]];
        let n = c.apply_opk_refresh(pubs.clone(), ids.clone());
        assert_eq!(n, 3);
        assert_eq!(c.bundle.opk_pubs, pubs);
        assert_eq!(c.bundle.opk_ids, ids);
    }

    #[test]
    fn apply_opk_refresh_mismatched_lengths_takes_min() {
        let mut c = StoredContact::new(make_bundle(), "Eve".into(), 0);
        let pubs = vec![[0xAA; 32], [0xBB; 32]];
        let ids = vec![[1, 0, 0, 0]]; // only 1 id
        let n = c.apply_opk_refresh(pubs, ids);
        assert_eq!(n, 1);
        assert_eq!(c.bundle.opk_pubs.len(), 1);
        assert_eq!(c.bundle.opk_ids.len(), 1);
    }

    #[test]
    fn stored_contact_ids_differ_for_different_bundles() {
        let c1 = StoredContact::new(make_bundle(), "A".into(), 0);
        let c2 = StoredContact::new(make_bundle(), "B".into(), 0);
        assert_ne!(c1.id, c2.id);
    }

    // ── ContactCode helpers ──────────────────────────────────────────────────

    #[test]
    fn contact_code_bundle_returns_inner() {
        let bundle = make_bundle();
        let cc = ContactCode(bundle.clone());
        assert_eq!(cc.bundle().nym_address, bundle.nym_address);
        assert_eq!(cc.bundle().x25519_pub, bundle.x25519_pub);
    }

    #[test]
    fn contact_code_fingerprint_matches_bundle_fingerprint() {
        let bundle = make_bundle();
        let expected = bundle.fingerprint();
        let cc = ContactCode(bundle);
        assert_eq!(cc.fingerprint(), expected);
    }

    // ── KeyChangeGuard ───────────────────────────────────────────────────────

    #[test]
    fn key_change_guard_allows_first_change() {
        let mut g = KeyChangeGuard::new();
        assert!(g.can_change_key());
        assert!(g.record_change().is_ok());
    }

    #[test]
    fn key_change_guard_blocks_rapid_second_change() {
        let mut g = KeyChangeGuard::new();
        g.record_change().unwrap();
        assert!(!g.can_change_key());
        let result = g.record_change();
        assert!(matches!(result, Err(IdentityError::KeyChangeTooFrequent)));
    }

    #[test]
    fn key_change_guard_default_impl() {
        let g = KeyChangeGuard::default();
        assert!(g.can_change_key());
    }
}
