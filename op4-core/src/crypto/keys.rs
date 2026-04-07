use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ml_kem::{
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey},
    EncodedSizeUser, KemCore, MlKem768, MlKem768Params,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::crypto::primitives::{hkdf_expand, SymKey, AEAD_KEY_LEN};
use crate::error::CryptoError;

// ─── Hybrid KEM Keypair ───────────────────────────────────────────────────────

/// Combined X25519 + ML-KEM-768 keypair for key exchange.
/// Both keys are required; breaking either alone is insufficient.
///
/// Zeroization notes (ml-kem 0.2.3 does not impl `Zeroize` for `DecapsulationKey`):
/// - `x25519_secret` — zeroed on drop by StaticSecret's own ZeroizeOnDrop.
/// - `mlkem_dk` — NOT zeroed on drop (library limitation); mitigated by
///   `mlkem_dk_raw` which stores the same bytes in a `Zeroizing<Vec<u8>>`
///   and IS zeroed on drop.
/// - `mlkem_ek` — public key, contains no secret material; skip zeroize.
#[derive(ZeroizeOnDrop)]
pub struct HybridKemKeypair {
    pub x25519_secret: StaticSecret,
    pub x25519_public: X25519PublicKey,
    /// Parsed decapsulation key — NOT zeroed on drop (ml-kem 0.2.3 limitation).
    /// Use `mlkem_dk_raw` as the authoritative secret-at-rest; this field is
    /// reconstructed from those bytes and used only for crypto operations.
    #[zeroize(skip)]
    pub mlkem_dk: Box<DecapsulationKey<MlKem768Params>>,
    /// Public encapsulation key — no secret material.
    #[zeroize(skip)]
    pub mlkem_ek: Box<EncapsulationKey<MlKem768Params>>,
    /// Raw 2400-byte decapsulation key bytes in a Zeroizing wrapper.
    /// Zeroed on drop as a best-effort mitigation for memory forensics.
    mlkem_dk_raw: Zeroizing<Vec<u8>>,
}

impl HybridKemKeypair {
    pub fn generate() -> Self {
        let x25519_secret = StaticSecret::random_from_rng(OsRng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);
        let (mlkem_dk, mlkem_ek) = MlKem768::generate(&mut OsRng);
        let mlkem_dk_raw = Zeroizing::new(mlkem_dk.as_bytes().to_vec());
        Self {
            x25519_secret,
            x25519_public,
            mlkem_dk: Box::new(mlkem_dk),
            mlkem_ek: Box::new(mlkem_ek),
            mlkem_dk_raw,
        }
    }

    /// Export the encapsulation (public) key bytes for inclusion in contact codes.
    pub fn mlkem_ek_bytes(&self) -> Vec<u8> {
        self.mlkem_ek.as_bytes().to_vec()
    }

    /// Serialize to bytes: X25519 secret (32) || ML-KEM-768 decapsulation key (2400).
    /// Total: 2432 bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2432);
        out.extend_from_slice(&self.x25519_secret.to_bytes());
        out.extend_from_slice(&self.mlkem_dk.as_bytes());
        out
    }

    /// Reconstruct from the 2432 bytes produced by `to_bytes()`.
    pub fn from_bytes(b: &[u8]) -> Result<Self, CryptoError> {
        if b.len() != 2432 {
            return Err(CryptoError::KeyParse);
        }
        let x25519_bytes: [u8; 32] = b[0..32].try_into().map_err(|_| CryptoError::KeyParse)?;
        let x25519_secret = StaticSecret::from(x25519_bytes);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        let dk_bytes: &[u8; 2400] = b[32..2432].try_into().map_err(|_| CryptoError::KeyParse)?;
        let mlkem_dk_raw = Zeroizing::new(dk_bytes.to_vec());
        let mlkem_dk = DecapsulationKey::<MlKem768Params>::from_bytes(dk_bytes.into());
        let mlkem_ek = Box::new(mlkem_dk.encapsulation_key().clone());

        Ok(Self {
            x25519_secret,
            x25519_public,
            mlkem_dk: Box::new(mlkem_dk),
            mlkem_ek,
            mlkem_dk_raw,
        })
    }
}

// ─── Hybrid Signing Keypair ───────────────────────────────────────────────────

/// Combined Ed25519 + ML-DSA-65 signing keypair.
/// Both signatures are produced and required for verification.
///
/// ML-DSA key material is held in a `KeyPair<MlDsa65>` which gives access to
/// both the signing key and verifying key.  We use `from_seed` (not `key_gen`)
/// to generate keys so we can supply entropy from `getrandom` directly and
/// avoid the rand_core 0.6 vs 0.10 version mismatch that would otherwise occur
/// when passing `OsRng` to ml-dsa's `CryptoRng`-bounded `key_gen`.
///
/// Zeroization notes (ml-dsa 0.1.0-rc.7 does not impl `Zeroize` for `KeyPair`):
/// - `ed25519_sk` — zeroed on drop by ed25519-dalek's own ZeroizeOnDrop.
/// - `mldsa_seed` — zeroed on drop (32-byte seed, the true secret).  The
///   full derived keypair on heap is NOT zeroed; but with the seed wiped
///   an attacker cannot re-derive the keypair.
/// - `mldsa_keypair` — NOT zeroed on drop (library limitation).
#[derive(ZeroizeOnDrop)]
pub struct HybridSigningKeypair {
    pub ed25519_sk: SigningKey,
    #[zeroize(skip)]
    pub ed25519_vk: VerifyingKey,
    /// ML-DSA keypair — NOT zeroed on drop (ml-dsa 0.1.0-rc.7 limitation).
    /// The 32-byte `mldsa_seed` below IS zeroed and is sufficient for re-deriving.
    #[zeroize(skip)]
    pub mldsa_keypair: Box<ml_dsa::KeyPair<ml_dsa::MlDsa65>>,
    /// ML-DSA 32-byte seed — zeroed on drop.  Used for serialization and
    /// to reconstruct the keypair from the vault without storing the full 4 KB key.
    mldsa_seed: [u8; 32],
}

impl HybridSigningKeypair {
    pub fn generate() -> Self {
        use hybrid_array::{typenum::U32, Array};
        use ml_dsa::KeyGen;

        let ed25519_sk = SigningKey::generate(&mut OsRng);
        let ed25519_vk = ed25519_sk.verifying_key();

        // Derive 32 bytes of entropy via getrandom (rand_core 0.6-compatible).
        // `from_seed` performs the full key derivation internally so this single
        // random draw is all that is needed.
        let mut seed_bytes = [0u8; 32];
        getrandom::getrandom(&mut seed_bytes).expect("getrandom failed");
        // Convert to the Array<u8, U32> type that from_seed accepts.
        // TryFrom<&[u8]> for Array<T,N> is implemented in hybrid-array 0.2.x.
        let seed: Array<u8, U32> = seed_bytes[..].try_into().expect("seed is 32 bytes");
        let mldsa_keypair = ml_dsa::MlDsa65::from_seed(&seed);

        Self {
            ed25519_sk,
            ed25519_vk,
            mldsa_keypair: Box::new(mldsa_keypair),
            mldsa_seed: seed_bytes,
        }
    }

    /// Serialize to 64 bytes: Ed25519 secret key (32) || ML-DSA seed (32).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&self.ed25519_sk.to_bytes());
        out.extend_from_slice(&self.mldsa_seed);
        out
    }

    /// Reconstruct from the 64 bytes produced by `to_bytes()`.
    pub fn from_bytes(b: &[u8]) -> Result<Self, CryptoError> {
        use hybrid_array::{typenum::U32, Array};
        use ml_dsa::KeyGen;

        if b.len() != 64 {
            return Err(CryptoError::KeyParse);
        }
        let ed25519_sk_bytes: [u8; 32] = b[0..32].try_into().map_err(|_| CryptoError::KeyParse)?;
        let mldsa_seed: [u8; 32] = b[32..64].try_into().map_err(|_| CryptoError::KeyParse)?;

        let ed25519_sk = SigningKey::from_bytes(&ed25519_sk_bytes);
        let ed25519_vk = ed25519_sk.verifying_key();

        let seed: Array<u8, U32> = mldsa_seed[..].try_into().expect("seed is 32 bytes");
        let mldsa_keypair = ml_dsa::MlDsa65::from_seed(&seed);

        Ok(Self {
            ed25519_sk,
            ed25519_vk,
            mldsa_keypair: Box::new(mldsa_keypair),
            mldsa_seed,
        })
    }
}

// ─── Public Key Bundle (contact code contents) ───────────────────────────────

/// Serializable bundle of all public keys for a contact.
/// This is what gets encoded into a contact code and shared out-of-band.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyBundle {
    pub version: u8,
    pub nym_address: String,
    pub x25519_pub: [u8; 32],
    pub mlkem_ek: Vec<u8>, // 1184 bytes for ML-KEM-768
    pub ed25519_vk: [u8; 32],
    pub mldsa_vk: Vec<u8>, // 1952 bytes for ML-DSA-65
    /// Dedicated X25519 public key for Double Ratchet bootstrap (separate from KEM key).
    pub ratchet_pub: [u8; 32],
    /// One-time prekey X25519 public keys for forward secrecy in handshakes.
    /// Each OPK is used at most once and the secret is deleted after use.
    #[serde(default)]
    pub opk_pubs: Vec<[u8; 32]>,
    /// 4-byte IDs for each OPK (SHA-256 of the public key, truncated).
    /// Used for stable lookup during handshake (not positional index).
    #[serde(default)]
    pub opk_ids: Vec<[u8; 4]>,
}

impl PublicKeyBundle {
    /// Build a bundle from our keypairs, dedicated ratchet public key, and Nym address.
    pub fn from_keypairs(
        kem: &HybridKemKeypair,
        signing: &HybridSigningKeypair,
        ratchet_pub: [u8; 32],
        nym_address: String,
    ) -> Self {
        Self::from_keypairs_with_opks(kem, signing, ratchet_pub, nym_address, Vec::new(), Vec::new())
    }

    /// Build a bundle with one-time prekey public keys and their IDs included.
    pub fn from_keypairs_with_opks(
        kem: &HybridKemKeypair,
        signing: &HybridSigningKeypair,
        ratchet_pub: [u8; 32],
        nym_address: String,
        opk_pubs: Vec<[u8; 32]>,
        opk_ids: Vec<[u8; 4]>,
    ) -> Self {
        let mldsa_vk_bytes: Vec<u8> = signing.mldsa_keypair.verifying_key().encode().to_vec();
        Self {
            version: 1,
            nym_address,
            x25519_pub: kem.x25519_public.to_bytes(),
            mlkem_ek: kem.mlkem_ek_bytes(),
            ed25519_vk: signing.ed25519_vk.to_bytes(),
            mldsa_vk: mldsa_vk_bytes,
            ratchet_pub,
            opk_pubs,
            opk_ids,
        }
    }

    /// SHA-256 fingerprint over all key material for out-of-band verification.
    /// Returns colon-separated groups of 4 hex chars for readability.
    pub fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(self.x25519_pub);
        h.update(&self.mlkem_ek);
        h.update(self.ed25519_vk);
        h.update(&self.mldsa_vk);
        h.update(self.ratchet_pub);
        for opk in &self.opk_pubs {
            h.update(opk);
        }
        let digest = h.finalize();
        digest
            .chunks(2)
            .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
            .collect::<Vec<_>>()
            .join(":")
    }
}

// ─── Hybrid Signature ─────────────────────────────────────────────────────────

/// Both Ed25519 and ML-DSA-65 signatures. BOTH must be valid to accept.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridSignature {
    pub ed25519: Vec<u8>,
    pub mldsa: Vec<u8>,
}

pub fn hybrid_sign(keypair: &HybridSigningKeypair, message: &[u8]) -> HybridSignature {
    use ml_dsa::signature::Signer as MlDsaSigner;

    let ed_sig: Signature = keypair.ed25519_sk.sign(message);

    // ML-DSA signing is deterministic — no RNG needed.
    let dsa_sig = keypair.mldsa_keypair.signing_key().sign(message);

    HybridSignature {
        ed25519: ed_sig.to_bytes().to_vec(),
        // encode() → EncodedSignature<P> which implements AsRef<[u8]>
        mldsa: dsa_sig.encode().to_vec(),
    }
}

pub fn hybrid_verify(
    bundle: &PublicKeyBundle,
    message: &[u8],
    sig: &HybridSignature,
) -> Result<(), CryptoError> {
    // ── Ed25519 verify ────────────────────────────────────────────────────────
    let ed_vk = VerifyingKey::from_bytes(&bundle.ed25519_vk).map_err(|_| CryptoError::SigVerify)?;
    let ed_sig = Signature::from_slice(&sig.ed25519).map_err(|_| CryptoError::SigVerify)?;
    ed_vk
        .verify(message, &ed_sig)
        .map_err(|_| CryptoError::SigVerify)?;

    // ── ML-DSA verify ─────────────────────────────────────────────────────────
    use ml_dsa::signature::Verifier as MlDsaVerifier;

    // Deserialise verifying key: &[u8] → Array<u8, VkSize> → VerifyingKey<MlDsa65>
    // The try_into() target type is inferred from the decode() argument.
    let vk_arr = bundle
        .mldsa_vk
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::SigVerify)?;
    let dsa_vk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(&vk_arr);

    // Deserialise signature — Signature<P> implements TryFrom<&[u8]>
    let dsa_sig: ml_dsa::Signature<ml_dsa::MlDsa65> = sig
        .mldsa
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::SigVerify)?;

    dsa_vk
        .verify(message, &dsa_sig)
        .map_err(|_| CryptoError::SigVerify)?;

    Ok(())
}

// ─── Hybrid KEM Operations ────────────────────────────────────────────────────

/// Ciphertext bundle produced by encapsulation (sent to peer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridKemCiphertext {
    pub mlkem_ct: Vec<u8>, // ML-KEM-768 ciphertext (1088 bytes)
                           // x25519 shared secret is derived from peer's public key + our secret — no ciphertext needed
}

/// Encapsulate: derive shared secret toward `peer_bundle`.
/// Uses our `x25519_secret` for DH and encapsulates to peer's ML-KEM public key.
/// Returns (ciphertext_bundle, shared_secret).
pub fn hybrid_kem_encapsulate(
    peer_bundle: &PublicKeyBundle,
    our_x25519_secret: &StaticSecret,
) -> Result<(HybridKemCiphertext, SymKey), CryptoError> {
    // X25519 DH
    let peer_x25519 = X25519PublicKey::from(peer_bundle.x25519_pub);
    let x25519_ss = our_x25519_secret.diffie_hellman(&peer_x25519);

    // ML-KEM-768 encapsulation
    let peer_ek = EncapsulationKey::<MlKem768Params>::from_bytes(
        peer_bundle
            .mlkem_ek
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::KeyParse)?,
    );
    let (mlkem_ct, mlkem_ss) = peer_ek
        .encapsulate(&mut OsRng)
        .map_err(|_| CryptoError::KemEncap)?;

    // Combine: HKDF(x25519_ss || mlkem_ss)
    let ikm: Vec<u8> = x25519_ss
        .as_bytes()
        .iter()
        .chain(mlkem_ss.iter())
        .copied()
        .collect();
    let mut combined = [0u8; AEAD_KEY_LEN];
    hkdf_expand(&ikm, None, b"op4-hybrid-kem-v1", &mut combined)?;

    Ok((
        HybridKemCiphertext {
            mlkem_ct: mlkem_ct.to_vec(),
        },
        SymKey(combined),
    ))
}

/// Decapsulate: recover shared secret from ciphertext bundle.
pub fn hybrid_kem_decapsulate(
    our_kem: &HybridKemKeypair,
    peer_x25519_pub: &X25519PublicKey,
    ct: &HybridKemCiphertext,
) -> Result<SymKey, CryptoError> {
    // X25519 DH (symmetric — same operation as encapsulate side)
    let x25519_ss = our_kem.x25519_secret.diffie_hellman(peer_x25519_pub);

    // ML-KEM-768 decapsulation
    let mlkem_ct_bytes: &[u8; 1088] = ct
        .mlkem_ct
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::KeyParse)?;
    let mlkem_ss = our_kem
        .mlkem_dk
        .decapsulate(mlkem_ct_bytes.into())
        .map_err(|_| CryptoError::KemDecap)?;

    // Combine identically to encapsulate
    let ikm: Vec<u8> = x25519_ss
        .as_bytes()
        .iter()
        .chain(mlkem_ss.iter())
        .copied()
        .collect();
    let mut combined = [0u8; AEAD_KEY_LEN];
    hkdf_expand(&ikm, None, b"op4-hybrid-kem-v1", &mut combined)?;

    Ok(SymKey(combined))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    // ── HybridKemKeypair ─────────────────────────────────────────────────────

    #[test]
    fn kem_keypair_to_from_bytes_roundtrip() {
        let kp = HybridKemKeypair::generate();
        let bytes = kp.to_bytes();
        assert_eq!(bytes.len(), 2432, "X25519(32) + ML-KEM DK(2400)");
        let kp2 = HybridKemKeypair::from_bytes(&bytes).unwrap();
        assert_eq!(kp.x25519_public.to_bytes(), kp2.x25519_public.to_bytes());
        assert_eq!(kp.mlkem_ek_bytes(), kp2.mlkem_ek_bytes());
    }

    #[test]
    fn kem_keypair_wrong_length_errors() {
        assert!(HybridKemKeypair::from_bytes(&[0u8; 0]).is_err());
        assert!(HybridKemKeypair::from_bytes(&[0u8; 100]).is_err());
        assert!(HybridKemKeypair::from_bytes(&[0u8; 2431]).is_err());
        assert!(HybridKemKeypair::from_bytes(&[0u8; 2433]).is_err());
    }

    // ── HybridSigningKeypair ──────────────────────────────────────────────────

    #[test]
    fn signing_keypair_to_from_bytes_roundtrip() {
        let kp = HybridSigningKeypair::generate();
        let bytes = kp.to_bytes();
        assert_eq!(bytes.len(), 64, "Ed25519 sk(32) + ML-DSA seed(32)");
        let kp2 = HybridSigningKeypair::from_bytes(&bytes).unwrap();
        assert_eq!(kp.ed25519_vk.to_bytes(), kp2.ed25519_vk.to_bytes());
        assert_eq!(kp.mldsa_seed, kp2.mldsa_seed);
    }

    #[test]
    fn signing_keypair_wrong_length_errors() {
        assert!(HybridSigningKeypair::from_bytes(&[0u8; 0]).is_err());
        assert!(HybridSigningKeypair::from_bytes(&[0u8; 32]).is_err());
        assert!(HybridSigningKeypair::from_bytes(&[0u8; 63]).is_err());
        assert!(HybridSigningKeypair::from_bytes(&[0u8; 65]).is_err());
    }

    // ── hybrid_sign / hybrid_verify ───────────────────────────────────────────

    #[test]
    fn sign_verify_roundtrip() {
        let kp = HybridSigningKeypair::generate();
        let kem = HybridKemKeypair::generate();
        let bundle = PublicKeyBundle::from_keypairs(&kem, &kp, [0u8; 32], String::new());
        let sig = hybrid_sign(&kp, b"test message");
        assert!(hybrid_verify(&bundle, b"test message", &sig).is_ok());
    }

    #[test]
    fn sign_verify_tampered_message_fails() {
        let kp = HybridSigningKeypair::generate();
        let kem = HybridKemKeypair::generate();
        let bundle = PublicKeyBundle::from_keypairs(&kem, &kp, [0u8; 32], String::new());
        let sig = hybrid_sign(&kp, b"original");
        assert!(hybrid_verify(&bundle, b"tampered", &sig).is_err());
    }

    #[test]
    fn sign_verify_wrong_bundle_fails() {
        let kp = HybridSigningKeypair::generate();
        let sig = hybrid_sign(&kp, b"message");
        // Verify against a different keypair's bundle
        let other_kp = HybridSigningKeypair::generate();
        let other_kem = HybridKemKeypair::generate();
        let other_bundle =
            PublicKeyBundle::from_keypairs(&other_kem, &other_kp, [0u8; 32], String::new());
        assert!(hybrid_verify(&other_bundle, b"message", &sig).is_err());
    }

    // ── hybrid_kem_encapsulate / decapsulate ──────────────────────────────────

    #[test]
    fn kem_encap_decap_shared_secret_matches() {
        let bob_kem = HybridKemKeypair::generate();
        let bob_signing = HybridSigningKeypair::generate();
        let bob_bundle =
            PublicKeyBundle::from_keypairs(&bob_kem, &bob_signing, [0u8; 32], String::new());

        let alice_ephemeral = StaticSecret::random_from_rng(OsRng);
        let alice_ek_pub = X25519PublicKey::from(&alice_ephemeral);

        let (ct, alice_ss) = hybrid_kem_encapsulate(&bob_bundle, &alice_ephemeral).unwrap();
        let bob_ss = hybrid_kem_decapsulate(&bob_kem, &alice_ek_pub, &ct).unwrap();

        assert_eq!(alice_ss.0, bob_ss.0, "shared secrets must match");
    }

    // ── PublicKeyBundle::fingerprint ──────────────────────────────────────────

    #[test]
    fn fingerprint_is_deterministic() {
        let kem = HybridKemKeypair::generate();
        let signing = HybridSigningKeypair::generate();
        let bundle = PublicKeyBundle::from_keypairs(&kem, &signing, [0u8; 32], "addr".into());
        assert_eq!(bundle.fingerprint(), bundle.fingerprint());
    }

    #[test]
    fn fingerprint_format_sixteen_colon_separated_groups() {
        let kem = HybridKemKeypair::generate();
        let signing = HybridSigningKeypair::generate();
        let bundle = PublicKeyBundle::from_keypairs(&kem, &signing, [0u8; 32], String::new());
        let fp = bundle.fingerprint();
        let parts: Vec<&str> = fp.split(':').collect();
        // SHA-256 is 32 bytes; chunks(2) → 16 groups; each formatted as 4 hex chars
        assert_eq!(
            parts.len(),
            16,
            "fingerprint must have 16 colon-separated groups"
        );
        for part in &parts {
            assert_eq!(part.len(), 4, "each group must be 4 hex chars, got: {part}");
        }
    }

    #[test]
    fn fingerprint_changes_with_different_keys() {
        let kem1 = HybridKemKeypair::generate();
        let signing1 = HybridSigningKeypair::generate();
        let kem2 = HybridKemKeypair::generate();
        let signing2 = HybridSigningKeypair::generate();
        let b1 = PublicKeyBundle::from_keypairs(&kem1, &signing1, [0u8; 32], String::new());
        let b2 = PublicKeyBundle::from_keypairs(&kem2, &signing2, [0u8; 32], String::new());
        assert_ne!(b1.fingerprint(), b2.fingerprint());
    }
}
