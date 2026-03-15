use ml_kem::{
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey},
    EncodedSizeUser, KemCore, MlKem768, MlKem768Params,
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::crypto::primitives::{hkdf_expand, SymKey, AEAD_KEY_LEN};
use crate::error::CryptoError;

// ─── Hybrid KEM Keypair ───────────────────────────────────────────────────────

/// Combined X25519 + ML-KEM-768 keypair for key exchange.
/// Both keys are required; breaking either alone is insufficient.
#[derive(ZeroizeOnDrop)]
pub struct HybridKemKeypair {
    pub x25519_secret: StaticSecret,
    pub x25519_public: X25519PublicKey,
    // ML-KEM keys are not zeroize-on-drop yet in 0.2.x; wrapped in Box to limit scope
    #[zeroize(skip)]
    pub mlkem_dk: Box<DecapsulationKey<MlKem768Params>>,
    #[zeroize(skip)]
    pub mlkem_ek: Box<EncapsulationKey<MlKem768Params>>,
}

impl HybridKemKeypair {
    pub fn generate() -> Self {
        let x25519_secret = StaticSecret::random_from_rng(OsRng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);
        let (mlkem_dk, mlkem_ek) = MlKem768::generate(&mut OsRng);
        Self {
            x25519_secret,
            x25519_public,
            mlkem_dk: Box::new(mlkem_dk),
            mlkem_ek: Box::new(mlkem_ek),
        }
    }

    /// Export the encapsulation (public) key bytes for inclusion in contact codes.
    pub fn mlkem_ek_bytes(&self) -> Vec<u8> {
        self.mlkem_ek.as_bytes().to_vec()
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
#[derive(ZeroizeOnDrop)]
pub struct HybridSigningKeypair {
    pub ed25519_sk: SigningKey,
    #[zeroize(skip)]
    pub ed25519_vk: VerifyingKey,
    #[zeroize(skip)]
    pub mldsa_keypair: Box<ml_dsa::KeyPair<ml_dsa::MlDsa65>>,
}

impl HybridSigningKeypair {
    pub fn generate() -> Self {
        use ml_dsa::KeyGen;
        use hybrid_array::{Array, typenum::U32};

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
        }
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
    pub mlkem_ek: Vec<u8>,    // 1184 bytes for ML-KEM-768
    pub ed25519_vk: [u8; 32],
    pub mldsa_vk: Vec<u8>,   // 1952 bytes for ML-DSA-65
}

impl PublicKeyBundle {
    /// Build a bundle from our keypairs and Nym address.
    pub fn from_keypairs(
        kem: &HybridKemKeypair,
        signing: &HybridSigningKeypair,
        nym_address: String,
    ) -> Self {
        // encode() → EncodedVerifyingKey<P> which implements AsRef<[u8]>.
        let mldsa_vk_bytes: Vec<u8> = signing
            .mldsa_keypair
            .verifying_key()
            .encode()
            .to_vec();
        Self {
            version: 1,
            nym_address,
            x25519_pub: kem.x25519_public.to_bytes(),
            mlkem_ek: kem.mlkem_ek_bytes(),
            ed25519_vk: signing.ed25519_vk.to_bytes(),
            mldsa_vk: mldsa_vk_bytes,
        }
    }

    /// SHA-256 fingerprint over all key material for out-of-band verification.
    /// Returns colon-separated groups of 4 hex chars for readability.
    pub fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&self.x25519_pub);
        h.update(&self.mlkem_ek);
        h.update(&self.ed25519_vk);
        h.update(&self.mldsa_vk);
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
    let ed_sig =
        Signature::from_slice(&sig.ed25519).map_err(|_| CryptoError::SigVerify)?;
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
    let (mlkem_ct, mlkem_ss) = peer_ek.encapsulate(&mut OsRng).map_err(|_| CryptoError::KemEncap)?;

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
