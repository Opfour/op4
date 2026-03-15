use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Key as ChaKey, Nonce as ChaNonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use sha2::Sha256;
use zeroize::ZeroizeOnDrop;

use crate::error::CryptoError;

pub const AEAD_KEY_LEN: usize = 32;
pub const AEAD_NONCE_LEN: usize = 12;
pub const MAC_LEN: usize = 32;

/// A zeroized 32-byte symmetric key.
#[derive(Clone, Debug, ZeroizeOnDrop)]
pub struct SymKey(pub [u8; AEAD_KEY_LEN]);

/// A zeroized 32-byte MAC key.
#[derive(Clone, ZeroizeOnDrop)]
pub struct MacKey(pub [u8; MAC_LEN]);

/// Argon2id parameters for key derivation.
pub struct Argon2Params {
    pub m_cost: u32, // memory in KiB
    pub t_cost: u32, // iterations
    pub p_cost: u32, // parallelism
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_cost: 65536, // 64 MiB
            t_cost: 3,
            p_cost: 4,
        }
    }
}

// ─── HKDF ────────────────────────────────────────────────────────────────────

/// HKDF-SHA256: extract + expand.
/// `salt`: optional; `None` uses HKDF-defined all-zero salt.
/// `out` must be ≤ 255 * 32 bytes.
pub fn hkdf_expand(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let (_, hk) = Hkdf::<Sha256>::extract(salt, ikm);
    hk.expand(info, out).map_err(|_| CryptoError::HkdfExpand)
}

// ─── ChaCha20-Poly1305 AEAD ───────────────────────────────────────────────────

/// Encrypt with additional authenticated data.
/// Output layout: `[12-byte nonce][ciphertext+16-byte tag]`.
/// Nonce is randomly generated per call.
pub fn aead_encrypt(key: &SymKey, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(ChaKey::from_slice(&key.0));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(
            &nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AeadEncrypt)?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt. Input must be `[12-byte nonce][ciphertext+tag]`.
pub fn aead_decrypt(key: &SymKey, nonce_and_ct: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if nonce_and_ct.len() < AEAD_NONCE_LEN + 16 {
        return Err(CryptoError::AeadDecrypt);
    }
    let (nonce_bytes, ct) = nonce_and_ct.split_at(AEAD_NONCE_LEN);
    let nonce = ChaNonce::from_slice(nonce_bytes);
    let cipher = ChaCha20Poly1305::new(ChaKey::from_slice(&key.0));
    cipher
        .decrypt(nonce, chacha20poly1305::aead::Payload { msg: ct, aad })
        .map_err(|_| CryptoError::AeadDecrypt)
}

// ─── Argon2id ────────────────────────────────────────────────────────────────

/// Derive a 32-byte key from a passphrase and salt using Argon2id.
/// `salt` must be 16–32 random bytes.
pub fn argon2id_derive(
    passphrase: &[u8],
    salt: &[u8],
    params: &Argon2Params,
) -> Result<SymKey, CryptoError> {
    let argon2_params = Params::new(
        params.m_cost,
        params.t_cost,
        params.p_cost,
        Some(AEAD_KEY_LEN),
    )
    .map_err(|_| CryptoError::Argon2Params)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut key = [0u8; AEAD_KEY_LEN];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|_| CryptoError::Argon2Hash)?;
    Ok(SymKey(key))
}

// ─── HMAC-SHA256 ─────────────────────────────────────────────────────────────

/// Compute HMAC-SHA256. Returns 32-byte tag.
pub fn hmac_sign(key: &MacKey, data: &[u8]) -> [u8; MAC_LEN] {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&key.0).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Constant-time HMAC verification.
pub fn hmac_verify(key: &MacKey, data: &[u8], tag: &[u8; MAC_LEN]) -> bool {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&key.0).expect("HMAC accepts any key length");
    mac.update(data);
    mac.verify_slice(tag.as_ref()).is_ok()
}

/// Internal: HMAC-SHA256 from raw key bytes (used in ratchet KDF).
pub fn hmac_sign_raw(key: &[u8; 32], data: &[u8]) -> [u8; MAC_LEN] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_roundtrip() {
        let key = SymKey([0x42u8; 32]);
        let plaintext = b"hello op4";
        let aad = b"context";
        let ct = aead_encrypt(&key, plaintext, aad).unwrap();
        let pt = aead_decrypt(&key, &ct, aad).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn aead_wrong_aad_fails() {
        let key = SymKey([0x42u8; 32]);
        let ct = aead_encrypt(&key, b"msg", b"aad").unwrap();
        assert!(aead_decrypt(&key, &ct, b"wrong").is_err());
    }

    #[test]
    fn hmac_sign_verify() {
        let key = MacKey([0x11u8; 32]);
        let tag = hmac_sign(&key, b"data");
        assert!(hmac_verify(&key, b"data", &tag));
        assert!(!hmac_verify(&key, b"other", &tag));
    }

    #[test]
    fn hkdf_deterministic() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        hkdf_expand(b"ikm", Some(b"salt"), b"info", &mut out1).unwrap();
        hkdf_expand(b"ikm", Some(b"salt"), b"info", &mut out2).unwrap();
        assert_eq!(out1, out2);
    }

    #[test]
    fn argon2id_derives_key() {
        let params = Argon2Params {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
        };
        let key = argon2id_derive(b"passphrase", &[0u8; 16], &params).unwrap();
        assert_eq!(key.0.len(), 32);
        // Different passphrase → different key
        let key2 = argon2id_derive(b"other", &[0u8; 16], &params).unwrap();
        assert_ne!(key.0, key2.0);
    }
}
