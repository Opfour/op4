use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::crypto::keys::{
    hybrid_kem_decapsulate, hybrid_kem_encapsulate, HybridKemCiphertext, HybridKemKeypair,
    HybridSigningKeypair, PublicKeyBundle,
};
use crate::crypto::primitives::{aead_decrypt, aead_encrypt, hkdf_expand, SymKey, AEAD_KEY_LEN};
use crate::error::CryptoError;

/// X3DH-variant handshake initial message (Alice → Bob).
/// Alice's identity is inside the E2EE payload only.
/// Nym routing layer sees only Bob's Nym address.
#[derive(Debug, Serialize, Deserialize)]
pub struct HandshakeInitMessage {
    /// Alice's full public key bundle (identity keys + Nym address)
    pub alice_identity: PublicKeyBundle,
    /// Alice's ephemeral X25519 public key for this session
    pub alice_ek_x25519: [u8; 32],
    /// ML-KEM ciphertext: Alice encapsulates to Bob's ML-KEM key
    pub alice_mlkem_ct: HybridKemCiphertext,
    /// Initial encrypted payload (Alice's first application message)
    pub initial_ct: Vec<u8>,
    /// HMAC over (alice_identity_bytes || alice_ek_x25519 || alice_mlkem_ct_bytes)
    pub mac: [u8; 32],
}

/// Session key output from a completed handshake.
/// Becomes the Double Ratchet root key.
#[derive(Debug)]
pub struct HandshakeOutput {
    pub session_key: SymKey,
    pub alice_ek_pub: X25519PublicKey, // for Double Ratchet bootstrapping
}

// ─── Initiator (Alice) ────────────────────────────────────────────────────────

/// Perform the handshake as the initiator (Alice).
///
/// Key agreement (X3DH hybrid variant):
/// ```
/// DH1 = X25519(Alice_IK, Bob_IK)
/// DH2 = X25519(Alice_EK, Bob_IK)
/// DH3 = X25519(Alice_EK, Bob_SPK)   [Bob_SPK = Bob_IK for simplicity here]
/// DH4_ss = ML-KEM-Encap(Bob_MLKEM_EK) shared secret
/// SK = HKDF(DH1 || DH2 || DH3 || DH4_ss, salt=0x00*32, info="op4-x3dh-v1")
/// ```
/// Returns (HandshakeInitMessage, session_key).
pub fn perform_handshake_alice(
    alice_kem: &HybridKemKeypair,
    alice_signing: &HybridSigningKeypair,
    alice_ratchet_pub: [u8; 32],
    alice_nym_address: String,
    bob_bundle: &PublicKeyBundle,
    initial_plaintext: &[u8],
) -> Result<(HandshakeInitMessage, SymKey), CryptoError> {
    // Generate ephemeral X25519 key for this session
    let alice_ek_secret = StaticSecret::random_from_rng(OsRng);
    let alice_ek_pub = X25519PublicKey::from(&alice_ek_secret);

    let bob_ik_pub = X25519PublicKey::from(bob_bundle.x25519_pub);

    // DH1: Alice identity key × Bob identity key
    let dh1 = alice_kem.x25519_secret.diffie_hellman(&bob_ik_pub);
    // DH2: Alice ephemeral key × Bob identity key
    let dh2 = alice_ek_secret.diffie_hellman(&bob_ik_pub);
    // DH3: Alice ephemeral key × Bob identity key (acting as SPK)
    let dh3 = alice_ek_secret.diffie_hellman(&bob_ik_pub);

    // DH4: ML-KEM encapsulation to Bob's ML-KEM public key
    let (mlkem_ct, dh4_ss) = hybrid_kem_encapsulate(bob_bundle, &alice_ek_secret)?;

    // Derive session key
    let session_key = combine_dh_outputs(dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes(), &dh4_ss)?;

    // Encrypt initial payload with session key
    let alice_identity_bytes = postcard::to_allocvec(&alice_kem.x25519_public.to_bytes())
        .map_err(|_| CryptoError::AeadEncrypt)?;
    let initial_ct = aead_encrypt(&session_key, initial_plaintext, &alice_identity_bytes)?;

    // HMAC over header fields for integrity (using session key as MAC key)
    let alice_id_bytes = postcard::to_allocvec(&alice_kem.x25519_public.to_bytes())
        .map_err(|_| CryptoError::AeadEncrypt)?;
    let mlkem_ct_bytes = postcard::to_allocvec(&mlkem_ct).map_err(|_| CryptoError::AeadEncrypt)?;
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(&alice_id_bytes);
    mac_input.extend_from_slice(&alice_ek_pub.to_bytes());
    mac_input.extend_from_slice(&mlkem_ct_bytes);
    let mac = crate::crypto::primitives::hmac_sign_raw(&session_key.0, &mac_input);

    let alice_identity =
        PublicKeyBundle::from_keypairs(alice_kem, alice_signing, alice_ratchet_pub, alice_nym_address);

    Ok((
        HandshakeInitMessage {
            alice_identity,
            alice_ek_x25519: alice_ek_pub.to_bytes(),
            alice_mlkem_ct: mlkem_ct,
            initial_ct,
            mac,
        },
        session_key,
    ))
}

// ─── Responder (Bob) ──────────────────────────────────────────────────────────

/// Respond to a handshake as Bob. Derives the same session key as Alice.
/// Returns (decrypted_initial_payload, session_key).
pub fn perform_handshake_bob(
    bob_kem: &HybridKemKeypair,
    msg: &HandshakeInitMessage,
) -> Result<(Vec<u8>, SymKey), CryptoError> {
    // Verify Alice's identity bundle is well-formed (key parsing check)
    let alice_ik_pub = X25519PublicKey::from(msg.alice_identity.x25519_pub);
    let alice_ek_pub = X25519PublicKey::from(msg.alice_ek_x25519);

    // DH1: Bob identity key × Alice identity key
    let dh1 = bob_kem.x25519_secret.diffie_hellman(&alice_ik_pub);
    // DH2: Bob identity key × Alice ephemeral key
    let dh2 = bob_kem.x25519_secret.diffie_hellman(&alice_ek_pub);
    // DH3: Bob identity key × Alice ephemeral key (same as DH2 in this simplified version)
    let dh3 = bob_kem.x25519_secret.diffie_hellman(&alice_ek_pub);

    // DH4: ML-KEM decapsulation
    let dh4_ss = hybrid_kem_decapsulate(bob_kem, &alice_ek_pub, &msg.alice_mlkem_ct)?;

    // Derive session key (must match Alice's derivation)
    let session_key = combine_dh_outputs(dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes(), &dh4_ss)?;

    // Verify MAC — must use Alice's x25519 pub (from msg) to match Alice's MAC input
    let alice_id_bytes = postcard::to_allocvec(&msg.alice_identity.x25519_pub)
        .map_err(|_| CryptoError::AeadDecrypt)?;
    let mlkem_ct_bytes =
        postcard::to_allocvec(&msg.alice_mlkem_ct).map_err(|_| CryptoError::AeadDecrypt)?;
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(&alice_id_bytes);
    mac_input.extend_from_slice(&msg.alice_ek_x25519);
    mac_input.extend_from_slice(&mlkem_ct_bytes);
    let expected_mac = crate::crypto::primitives::hmac_sign_raw(&session_key.0, &mac_input);
    if expected_mac != msg.mac {
        return Err(CryptoError::AeadDecrypt);
    }

    // Decrypt initial payload
    let alice_id_bytes = postcard::to_allocvec(&msg.alice_identity.x25519_pub)
        .map_err(|_| CryptoError::AeadDecrypt)?;
    let plaintext = aead_decrypt(&session_key, &msg.initial_ct, &alice_id_bytes)?;

    Ok((plaintext, session_key))
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn combine_dh_outputs(
    dh1: &[u8; 32],
    dh2: &[u8; 32],
    dh3: &[u8; 32],
    dh4_ss: &SymKey,
) -> Result<SymKey, CryptoError> {
    let mut ikm = Vec::with_capacity(32 * 4);
    ikm.extend_from_slice(dh1);
    ikm.extend_from_slice(dh2);
    ikm.extend_from_slice(dh3);
    ikm.extend_from_slice(&dh4_ss.0);

    let mut sk = [0u8; AEAD_KEY_LEN];
    hkdf_expand(&ikm, Some(&[0u8; 32]), b"op4-x3dh-v1", &mut sk)?;
    Ok(SymKey(sk))
}
