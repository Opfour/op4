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
    /// 4-byte ID of the one-time prekey used from Bob's bundle (None = no OPK).
    /// ID = first 4 bytes of SHA-256(opk_public_key). Stable across pool mutations.
    #[serde(default)]
    pub opk_id: Option<[u8; 4]>,
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
/// ```text
/// DH1 = X25519(Alice_IK,  Bob_IK)
/// DH2 = X25519(Alice_EK,  Bob_IK)
/// DH3 = X25519(Alice_EK,  Bob_SPK)  [Bob_SPK = Bob.ratchet_pub]
/// DH4_ss = ML-KEM-Encap(Bob_MLKEM_EK) shared secret
/// DH5 = X25519(Alice_EK,  Bob_OPK)  [optional, if Bob has OPKs]
/// SK = HKDF(DH1 || DH2 || DH3 || DH4_ss [|| DH5], salt=0x00*32, info="op4-x3dh-v1")
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

    // DH1: Alice identity key x Bob identity key
    let dh1 = alice_kem.x25519_secret.diffie_hellman(&bob_ik_pub);
    // DH2: Alice ephemeral key x Bob identity key
    let dh2 = alice_ek_secret.diffie_hellman(&bob_ik_pub);
    // DH3: Alice ephemeral key x Bob signed prekey (Bob's dedicated ratchet pub).
    // Falls back to Bob's IK for contacts with pre-ratchet_pub bundles.
    let bob_spk = if bob_bundle.ratchet_pub != [0u8; 32] {
        X25519PublicKey::from(bob_bundle.ratchet_pub)
    } else {
        bob_ik_pub
    };
    let dh3 = alice_ek_secret.diffie_hellman(&bob_spk);

    // DH4: ML-KEM encapsulation to Bob's ML-KEM public key
    let (mlkem_ct, dh4_ss) = hybrid_kem_encapsulate(bob_bundle, &alice_ek_secret)?;

    // DH5: one-time prekey (if Bob's bundle includes OPKs)
    let (opk_id, dh5) = if let Some(opk_pub) = bob_bundle.opk_pubs.first() {
        use sha2::{Digest, Sha256};
        let opk = X25519PublicKey::from(*opk_pub);
        let hash = Sha256::digest(opk_pub);
        let id: [u8; 4] = [hash[0], hash[1], hash[2], hash[3]];
        (Some(id), Some(alice_ek_secret.diffie_hellman(&opk)))
    } else {
        (None, None)
    };

    // Derive session key
    let session_key = combine_dh_outputs(
        dh1.as_bytes(),
        dh2.as_bytes(),
        dh3.as_bytes(),
        &dh4_ss,
        dh5.as_ref().map(|d| d.as_bytes()),
    )?;

    // Build the identity bundle -- used as AAD and MAC input so that
    // ALL identity fields are cryptographically bound to the message.
    let alice_identity = PublicKeyBundle::from_keypairs(
        alice_kem,
        alice_signing,
        alice_ratchet_pub,
        alice_nym_address,
    );

    let alice_id_bytes =
        postcard::to_allocvec(&alice_identity).map_err(|_| CryptoError::Serialize)?;

    // Encrypt initial payload, binding Alice's complete identity as AAD.
    let initial_ct = aead_encrypt(&session_key, initial_plaintext, &alice_id_bytes)?;

    // HMAC over (full_identity_bundle || alice_ek_x25519 || mlkem_ct) using session key.
    let mlkem_ct_bytes = postcard::to_allocvec(&mlkem_ct).map_err(|_| CryptoError::Serialize)?;
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(&alice_id_bytes);
    mac_input.extend_from_slice(&alice_ek_pub.to_bytes());
    mac_input.extend_from_slice(&mlkem_ct_bytes);
    let mac = crate::crypto::primitives::hmac_sign_raw(&session_key.0, &mac_input);

    Ok((
        HandshakeInitMessage {
            alice_identity,
            alice_ek_x25519: alice_ek_pub.to_bytes(),
            alice_mlkem_ct: mlkem_ct,
            initial_ct,
            mac,
            opk_id,
        },
        session_key,
    ))
}

// ─── Responder (Bob) ──────────────────────────────────────────────────────────

/// Respond to a handshake as Bob. Derives the same session key as Alice.
/// Returns (decrypted_initial_payload, session_key, optional OPK ID that was consumed).
///
/// `bob_ratchet_secret` must be the dedicated ratchet X25519 secret from the
/// vault (`identity_ratchet_secret`). It is used for DH3 to match Alice's
/// `DH3 = X25519(Alice_EK, Bob_SPK)` where Bob_SPK = Bob's ratchet public key.
///
/// `bob_opk_secrets` are the one-time prekey secrets corresponding to the
/// public keys in Bob's bundle. If Alice used an OPK, Bob computes DH5 and
/// the caller should delete the consumed secret from the vault via `consume_opk_by_id`.
#[allow(clippy::type_complexity)]
pub fn perform_handshake_bob(
    bob_kem: &HybridKemKeypair,
    bob_ratchet_secret: &StaticSecret,
    bob_opk_secrets: &[[u8; 32]],
    msg: &HandshakeInitMessage,
) -> Result<(Vec<u8>, SymKey, Option<[u8; 4]>), CryptoError> {
    let alice_ik_pub = X25519PublicKey::from(msg.alice_identity.x25519_pub);
    let alice_ek_pub = X25519PublicKey::from(msg.alice_ek_x25519);

    // DH1: Bob identity key x Alice identity key
    let dh1 = bob_kem.x25519_secret.diffie_hellman(&alice_ik_pub);
    // DH2: Bob identity key x Alice ephemeral key
    let dh2 = bob_kem.x25519_secret.diffie_hellman(&alice_ek_pub);
    // DH3: Bob ratchet key x Alice ephemeral key
    let dh3 = bob_ratchet_secret.diffie_hellman(&alice_ek_pub);

    // DH4: ML-KEM decapsulation
    let dh4_ss = hybrid_kem_decapsulate(bob_kem, &alice_ek_pub, &msg.alice_mlkem_ct)?;

    // DH5: one-time prekey (if Alice specified an OPK ID)
    let dh5 = if let Some(ref id) = msg.opk_id {
        use sha2::{Digest, Sha256};
        let found = bob_opk_secrets.iter().find(|s| {
            let pub_key = X25519PublicKey::from(&StaticSecret::from(**s)).to_bytes();
            let hash = Sha256::digest(pub_key);
            &[hash[0], hash[1], hash[2], hash[3]] == id
        });
        if let Some(secret_bytes) = found {
            let opk_secret = StaticSecret::from(*secret_bytes);
            Some(opk_secret.diffie_hellman(&alice_ek_pub))
        } else {
            // Alice referenced an OPK we don't have -- reject
            return Err(CryptoError::KeyParse);
        }
    } else {
        None
    };

    // Derive session key (must match Alice's derivation)
    let session_key = combine_dh_outputs(
        dh1.as_bytes(),
        dh2.as_bytes(),
        dh3.as_bytes(),
        &dh4_ss,
        dh5.as_ref().map(|d| d.as_bytes()),
    )?;

    // Serialize Alice's FULL received identity bundle — this must match Alice's
    // serialization exactly. Any field substituted in transit will produce
    // different bytes and fail either the MAC or AEAD tag check.
    let alice_id_bytes =
        postcard::to_allocvec(&msg.alice_identity).map_err(|_| CryptoError::AeadDecrypt)?;
    let mlkem_ct_bytes =
        postcard::to_allocvec(&msg.alice_mlkem_ct).map_err(|_| CryptoError::AeadDecrypt)?;
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(&alice_id_bytes);
    mac_input.extend_from_slice(&msg.alice_ek_x25519);
    mac_input.extend_from_slice(&mlkem_ct_bytes);

    // Constant-time MAC verification — prevents timing side-channels.
    // Using hmac_verify_raw (backed by subtle::ConstantTimeEq) rather than `!=`.
    if !crate::crypto::primitives::hmac_verify_raw(&session_key.0, &mac_input, &msg.mac) {
        return Err(CryptoError::AeadDecrypt);
    }

    // Decrypt initial payload using the same full-bundle AAD that Alice used.
    let plaintext = aead_decrypt(&session_key, &msg.initial_ct, &alice_id_bytes)?;

    Ok((plaintext, session_key, msg.opk_id))
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn combine_dh_outputs(
    dh1: &[u8; 32],
    dh2: &[u8; 32],
    dh3: &[u8; 32],
    dh4_ss: &SymKey,
    dh5: Option<&[u8; 32]>,
) -> Result<SymKey, CryptoError> {
    let mut ikm = Vec::with_capacity(32 * 5);
    ikm.extend_from_slice(dh1);
    ikm.extend_from_slice(dh2);
    ikm.extend_from_slice(dh3);
    ikm.extend_from_slice(&dh4_ss.0);
    if let Some(dh5_bytes) = dh5 {
        ikm.extend_from_slice(dh5_bytes);
    }

    let mut sk = [0u8; AEAD_KEY_LEN];
    hkdf_expand(&ikm, Some(&[0u8; 32]), b"op4-x3dh-v1", &mut sk)?;
    Ok(SymKey(sk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{HybridKemKeypair, HybridSigningKeypair, PublicKeyBundle};
    use rand::rngs::OsRng;

    /// Build a fresh Bob identity: KEM keypair, signing keypair, ratchet secret,
    /// and a `PublicKeyBundle` with the ratchet public key embedded.
    fn make_bob() -> (
        HybridKemKeypair,
        HybridSigningKeypair,
        StaticSecret,
        PublicKeyBundle,
    ) {
        let kem = HybridKemKeypair::generate();
        let signing = HybridSigningKeypair::generate();
        let ratchet_secret = StaticSecret::random_from_rng(OsRng);
        let ratchet_pub = X25519PublicKey::from(&ratchet_secret).to_bytes();
        let bundle = PublicKeyBundle::from_keypairs(&kem, &signing, ratchet_pub, "bob_addr".into());
        (kem, signing, ratchet_secret, bundle)
    }

    #[test]
    fn session_keys_match_after_handshake() {
        let (bob_kem, _bob_signing, bob_ratchet_secret, bob_bundle) = make_bob();
        let alice_kem = HybridKemKeypair::generate();
        let alice_signing = HybridSigningKeypair::generate();

        let (msg, alice_sk) = perform_handshake_alice(
            &alice_kem,
            &alice_signing,
            [0u8; 32],
            "alice_addr".into(),
            &bob_bundle,
            b"hello bob",
        )
        .unwrap();

        let (plaintext, bob_sk, _) =
            perform_handshake_bob(&bob_kem, &bob_ratchet_secret, &[], &msg).unwrap();

        assert_eq!(alice_sk.0, bob_sk.0, "session keys must match");
        assert_eq!(
            plaintext, b"hello bob",
            "initial plaintext must survive E2EE"
        );
    }

    #[test]
    fn alice_identity_embedded_in_message() {
        let (_bob_kem, _bob_signing, _bob_ratchet_secret, bob_bundle) = make_bob();
        let alice_kem = HybridKemKeypair::generate();
        let alice_signing = HybridSigningKeypair::generate();

        let (msg, _) = perform_handshake_alice(
            &alice_kem,
            &alice_signing,
            [0u8; 32],
            "alice_addr".into(),
            &bob_bundle,
            b"hi",
        )
        .unwrap();

        // Alice's X25519 public key must be in the message
        assert_eq!(
            msg.alice_identity.x25519_pub,
            alice_kem.x25519_public.to_bytes()
        );
        assert_eq!(msg.alice_identity.nym_address, "alice_addr");
    }

    #[test]
    fn tampered_mac_rejected() {
        let (bob_kem, _bob_signing, bob_ratchet_secret, bob_bundle) = make_bob();
        let alice_kem = HybridKemKeypair::generate();
        let alice_signing = HybridSigningKeypair::generate();

        let (mut msg, _) = perform_handshake_alice(
            &alice_kem,
            &alice_signing,
            [0u8; 32],
            "alice_addr".into(),
            &bob_bundle,
            b"hi",
        )
        .unwrap();

        msg.mac[0] ^= 0xff; // flip a bit in the HMAC tag
        assert!(
            perform_handshake_bob(&bob_kem, &bob_ratchet_secret, &[], &msg).is_err(),
            "tampered MAC must be rejected"
        );
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let (bob_kem, _bob_signing, bob_ratchet_secret, bob_bundle) = make_bob();
        let alice_kem = HybridKemKeypair::generate();
        let alice_signing = HybridSigningKeypair::generate();

        let (mut msg, _) = perform_handshake_alice(
            &alice_kem,
            &alice_signing,
            [0u8; 32],
            "alice_addr".into(),
            &bob_bundle,
            b"secret",
        )
        .unwrap();

        // Corrupt the encrypted payload
        if let Some(b) = msg.initial_ct.first_mut() {
            *b ^= 0xff;
        }
        // Either the MAC check or AEAD decryption must reject this
        assert!(perform_handshake_bob(&bob_kem, &bob_ratchet_secret, &[], &msg).is_err());
    }

    #[test]
    fn handshake_with_opk_produces_different_session_key() {
        // Same identities, but Bob has OPKs in one case and not the other.
        let (bob_kem, _bob_signing, bob_ratchet_secret, bob_bundle_no_opk) = make_bob();

        // Generate OPK secrets and build a bundle that includes them.
        let opk_secret = StaticSecret::random_from_rng(OsRng);
        let opk_pub = X25519PublicKey::from(&opk_secret).to_bytes();
        let opk_secrets = vec![opk_secret.to_bytes()];

        let bob_signing = HybridSigningKeypair::generate();
        // Compute the OPK ID for the public key
        let opk_id = {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(opk_pub);
            [hash[0], hash[1], hash[2], hash[3]]
        };
        let bob_bundle_with_opk = PublicKeyBundle::from_keypairs_with_opks(
            &bob_kem,
            &bob_signing,
            X25519PublicKey::from(&bob_ratchet_secret).to_bytes(),
            "bob_addr".into(),
            vec![opk_pub],
            vec![opk_id],
        );

        let alice_kem = HybridKemKeypair::generate();
        let alice_signing = HybridSigningKeypair::generate();

        // Handshake WITHOUT OPK
        let (msg_no_opk, sk_no_opk) = perform_handshake_alice(
            &alice_kem,
            &alice_signing,
            [0u8; 32],
            "alice_addr".into(),
            &bob_bundle_no_opk,
            b"hi",
        )
        .unwrap();
        assert!(msg_no_opk.opk_id.is_none());

        // Handshake WITH OPK (different Alice ephemeral, so keys differ anyway,
        // but we verify OPK ID is set and Bob can complete it)
        let alice_kem2 = HybridKemKeypair::generate();
        let alice_signing2 = HybridSigningKeypair::generate();
        let (msg_with_opk, sk_with_opk) = perform_handshake_alice(
            &alice_kem2,
            &alice_signing2,
            [0u8; 32],
            "alice_addr".into(),
            &bob_bundle_with_opk,
            b"hi",
        )
        .unwrap();
        assert!(msg_with_opk.opk_id.is_some());

        // Bob completes the OPK handshake
        let (pt, bob_sk, consumed_id) =
            perform_handshake_bob(&bob_kem, &bob_ratchet_secret, &opk_secrets, &msg_with_opk)
                .unwrap();
        assert_eq!(pt, b"hi");
        assert_eq!(bob_sk.0, sk_with_opk.0);
        assert!(consumed_id.is_some());

        // Keys must differ from the no-OPK handshake (different ephemerals + OPK)
        assert_ne!(sk_no_opk.0, sk_with_opk.0);
    }

    #[test]
    fn handshake_bob_rejects_invalid_opk_id() {
        let (bob_kem, _bob_signing, bob_ratchet_secret, _bob_bundle) = make_bob();
        let alice_kem = HybridKemKeypair::generate();
        let alice_signing = HybridSigningKeypair::generate();

        let opk_secret = StaticSecret::random_from_rng(OsRng);
        let opk_pub = X25519PublicKey::from(&opk_secret).to_bytes();

        let bob_signing2 = HybridSigningKeypair::generate();
        let bob_bundle = PublicKeyBundle::from_keypairs_with_opks(
            &bob_kem,
            &bob_signing2,
            X25519PublicKey::from(&bob_ratchet_secret).to_bytes(),
            "bob_addr".into(),
            vec![opk_pub],
            vec![[0xAA, 0xBB, 0xCC, 0xDD]], // real ID computed from opk_pub
        );

        let (mut msg, _) = perform_handshake_alice(
            &alice_kem,
            &alice_signing,
            [0u8; 32],
            "alice_addr".into(),
            &bob_bundle,
            b"hi",
        )
        .unwrap();

        // Tamper: set OPK ID to one Bob doesn't have
        msg.opk_id = Some([0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(
            perform_handshake_bob(&bob_kem, &bob_ratchet_secret, &[opk_secret.to_bytes()], &msg)
                .is_err()
        );
    }

    /// Full integration: handshake -> ratchet init -> multi-message bidirectional
    /// exchange -> ratchet advancement -> persistence roundtrip.
    #[test]
    fn handshake_to_ratchet_full_flow() {
        use crate::crypto::ratchet::RatchetState;
        use crate::crypto::primitives::SymKey;

        // ── 1. Generate identities ──────────────────────────────────────
        let (bob_kem, _bob_signing, bob_ratchet_secret, bob_bundle) = make_bob();
        let alice_kem = HybridKemKeypair::generate();
        let alice_signing = HybridSigningKeypair::generate();
        let alice_ratchet_pub = X25519PublicKey::from(&bob_ratchet_secret).to_bytes();

        // ── 2. Alice initiates handshake ────────────────────────────────
        let (hs_msg, alice_sk) = perform_handshake_alice(
            &alice_kem,
            &alice_signing,
            alice_ratchet_pub,
            "alice_addr".into(),
            &bob_bundle,
            b"hello from alice",
        )
        .unwrap();

        // ── 3. Bob completes handshake ──────────────────────────────────
        let (initial_plaintext, bob_sk, _) =
            perform_handshake_bob(&bob_kem, &bob_ratchet_secret, &[], &hs_msg).unwrap();
        assert_eq!(initial_plaintext, b"hello from alice");
        assert_eq!(alice_sk.0, bob_sk.0);

        // ── 4. Initialize Double Ratchets ───────────────────────────────
        let bob_ratchet_pub_key = X25519PublicKey::from(&bob_ratchet_secret);
        let mut alice_ratchet =
            RatchetState::init_alice(alice_sk.0, bob_ratchet_pub_key).unwrap();
        let mut bob_ratchet =
            RatchetState::init_bob(bob_sk.0, bob_ratchet_secret);

        // ── 5. Alice sends multiple messages to Bob ─────────────────────
        for i in 0..5 {
            let msg = format!("alice msg {i}");
            let (header, ct, _mac_key) =
                alice_ratchet.ratchet_encrypt(msg.as_bytes()).unwrap();
            let (pt, _mk) = bob_ratchet.ratchet_decrypt(&header, &ct).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }

        // ── 6. Bob replies (triggers DH ratchet step) ───────────────────
        for i in 0..3 {
            let msg = format!("bob reply {i}");
            let (header, ct, _mac_key) =
                bob_ratchet.ratchet_encrypt(msg.as_bytes()).unwrap();
            let (pt, _mk) = alice_ratchet.ratchet_decrypt(&header, &ct).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }

        // ── 7. Interleaved exchange (multiple ratchet steps) ────────────
        let (h, c, _) = alice_ratchet.ratchet_encrypt(b"ping").unwrap();
        let (pt, _) = bob_ratchet.ratchet_decrypt(&h, &c).unwrap();
        assert_eq!(pt, b"ping");

        let (h, c, _) = bob_ratchet.ratchet_encrypt(b"pong").unwrap();
        let (pt, _) = alice_ratchet.ratchet_decrypt(&h, &c).unwrap();
        assert_eq!(pt, b"pong");

        let (h, c, _) = alice_ratchet.ratchet_encrypt(b"final").unwrap();
        let (pt, _) = bob_ratchet.ratchet_decrypt(&h, &c).unwrap();
        assert_eq!(pt, b"final");

        // ── 8. Persistence roundtrip ────────────────────────────────────
        let key = SymKey([0xABu8; 32]);
        let alice_ct = alice_ratchet.to_encrypted_bytes(&key).unwrap();
        let mut alice_restored =
            RatchetState::from_encrypted_bytes(&key, &alice_ct).unwrap();

        // The restored ratchet must be able to decrypt a new message from Bob.
        let (h, c, _) = bob_ratchet.ratchet_encrypt(b"after restore").unwrap();
        let (pt, _) = alice_restored
            .ratchet_decrypt(&h, &c)
            .expect("restored ratchet must decrypt");
        assert_eq!(pt, b"after restore");
    }
}
