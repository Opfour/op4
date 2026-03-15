use serde::{Deserialize, Serialize};
use std::time::Instant;

use crate::crypto::keys::PublicKeyBundle;
use crate::error::IdentityError;

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
    pub id: [u8; 32],          // SHA-256 of their full contact code bytes
    pub bundle: PublicKeyBundle,
    pub display_name: String,
    pub verified: bool,        // did user verify fingerprint out-of-band?
    pub last_key_seq: u64,     // monotonic sequence to detect key changes
    pub added_seq: u64,        // monotonic counter at time of addition (no wall clock)
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
