use serde::{Deserialize, Serialize};

use crate::crypto::keys::{
    hybrid_sign, hybrid_verify, HybridSignature, HybridSigningKeypair, PublicKeyBundle,
};
use crate::error::IdentityError;

/// Reason a key is being revoked.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum RevocationReason {
    Compromised = 0,
    Rotation = 1,
    Retirement = 2,
}

/// Signed revocation certificate. Propagated to all contacts via Nym.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationCertificate {
    pub version: u8,
    /// Fingerprint of the key being revoked (SHA-256 over all pubkey fields)
    pub revoked_fingerprint: String,
    /// X25519 public key bytes of the revoked identity
    pub revoked_x25519_pub: [u8; 32],
    pub reason: RevocationReason,
    /// Monotonic sequence number (not wall-clock time)
    pub sequence: u64,
    /// New key bundle if this is a rotation (None if retirement)
    pub new_bundle: Option<PublicKeyBundle>,
    /// Hybrid signature over all fields above
    pub signature: HybridSignature,
}

impl RevocationCertificate {
    /// Create and sign a revocation certificate.
    pub fn create(
        signing_keypair: &HybridSigningKeypair,
        revoked_fingerprint: String,
        revoked_x25519_pub: [u8; 32],
        reason: RevocationReason,
        sequence: u64,
        new_bundle: Option<PublicKeyBundle>,
    ) -> Self {
        let to_sign = Self::signable_bytes(
            &revoked_fingerprint,
            &revoked_x25519_pub,
            reason,
            sequence,
            new_bundle.as_ref(),
        );
        let signature = hybrid_sign(signing_keypair, &to_sign);
        Self {
            version: 1,
            revoked_fingerprint,
            revoked_x25519_pub,
            reason,
            sequence,
            new_bundle,
            signature,
        }
    }

    /// Verify the certificate against the contact's known public key bundle.
    pub fn verify(&self, against_bundle: &PublicKeyBundle) -> Result<(), IdentityError> {
        let to_verify = Self::signable_bytes(
            &self.revoked_fingerprint,
            &self.revoked_x25519_pub,
            self.reason,
            self.sequence,
            self.new_bundle.as_ref(),
        );
        hybrid_verify(against_bundle, &to_verify, &self.signature)
            .map_err(|_| IdentityError::SignatureVerification)
    }

    fn signable_bytes(
        revoked_fingerprint: &str,
        revoked_x25519_pub: &[u8; 32],
        reason: RevocationReason,
        sequence: u64,
        new_bundle: Option<&PublicKeyBundle>,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(revoked_fingerprint.as_bytes());
        bytes.extend_from_slice(revoked_x25519_pub);
        bytes.push(reason as u8);
        bytes.extend_from_slice(&sequence.to_be_bytes());
        if let Some(bundle) = new_bundle {
            if let Ok(b) = postcard::to_allocvec(bundle) {
                bytes.extend_from_slice(&b);
            }
        }
        bytes
    }
}
