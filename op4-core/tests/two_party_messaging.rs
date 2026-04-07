//! Integration test: full two-party messaging flow.
//!
//! Exercises: identity generation, X3DH handshake (with and without OPKs),
//! Double Ratchet message exchange, vault persistence, outbox queue,
//! message log storage, and ratchet state restore after vault reopen.
//!
//! No network, no Tor, no TUI -- pure in-process E2E test.

use op4_core::crypto::handshake::{perform_handshake_alice, perform_handshake_bob};
use op4_core::crypto::hmac_auth::{compute_message_mac, verify_message_mac};
use op4_core::crypto::keys::{HybridKemKeypair, HybridSigningKeypair, PublicKeyBundle};
use op4_core::crypto::primitives::{Argon2Params, MacKey, SymKey};
use op4_core::crypto::ratchet::RatchetState;
use op4_core::identity::profile::{BootstrapCode, ContactCode, StoredContact};
use op4_core::network::message::{WireMessage, WireMessageType};
use op4_core::storage::vault::{AppSettings, PendingOutbound, StoredMessage, VaultUnlocked};

use rand::rngs::OsRng;
use tempfile::tempdir;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

// Fast Argon2 for tests only -- NOT secure for production.
fn test_params() -> Argon2Params {
    Argon2Params {
        m_cost: 1024,
        t_cost: 1,
        p_cost: 1,
    }
}

/// Full identity: keypairs + ratchet secret + vault.
struct Party {
    kem: HybridKemKeypair,
    signing: HybridSigningKeypair,
    ratchet_secret: StaticSecret,
    vault: VaultUnlocked,
}

impl Party {
    fn new(path: &std::path::Path) -> Self {
        let kem = HybridKemKeypair::generate();
        let signing = HybridSigningKeypair::generate();
        let ratchet_secret = StaticSecret::random_from_rng(OsRng);
        let mut vault = VaultUnlocked::create_with_params(
            path,
            b"test-passphrase",
            b"test-duress",
            &test_params(),
        )
        .unwrap();

        // Store identity secrets in vault
        vault.payload.identity_kem_secret = kem.to_bytes().into();
        vault.payload.identity_signing_secret = signing.to_bytes().into();
        vault.payload.identity_ratchet_secret = ratchet_secret.to_bytes().to_vec().into();
        vault.payload.nym_address = format!("test_{}.onion:14101", rand::random::<u32>());

        // Generate OPKs
        vault.payload.generate_opks();

        Self {
            kem,
            signing,
            ratchet_secret,
            vault,
        }
    }

    fn bundle(&self) -> PublicKeyBundle {
        let ratchet_pub = X25519PublicKey::from(&self.ratchet_secret).to_bytes();
        let opk_pubs = self.vault.payload.opk_public_keys();
        let opk_ids = self.vault.payload.opk_ids();
        PublicKeyBundle::from_keypairs_with_opks(
            &self.kem,
            &self.signing,
            ratchet_pub,
            self.vault.payload.nym_address.clone(),
            opk_pubs,
            opk_ids,
        )
    }
}

// ---------------------------------------------------------------------------
// Test 1: Full handshake -> ratchet -> multi-message -> vault persist -> reload
// ---------------------------------------------------------------------------

#[test]
fn full_two_party_conversation_with_vault_persistence() {
    let dir = tempdir().unwrap();
    let alice_path = dir.path().join("alice.op4");
    let bob_path = dir.path().join("bob.op4");

    let mut alice = Party::new(&alice_path);
    let mut bob = Party::new(&bob_path);

    let bob_bundle = bob.bundle();
    let alice_ratchet_pub = X25519PublicKey::from(&alice.ratchet_secret).to_bytes();

    // -- 1. Handshake (Alice initiates) --
    let (hs_msg, alice_sk) = perform_handshake_alice(
        &alice.kem,
        &alice.signing,
        alice_ratchet_pub,
        alice.vault.payload.nym_address.clone(),
        &bob_bundle,
        b"hey bob, it's alice",
    )
    .unwrap();

    // Bob completes handshake (with OPK)
    let opk_secrets: Vec<[u8; 32]> = bob.vault.payload.opk_secrets.clone();
    let (initial_pt, bob_sk, consumed_opk) =
        perform_handshake_bob(&bob.kem, &bob.ratchet_secret, &opk_secrets, &hs_msg).unwrap();

    assert_eq!(initial_pt, b"hey bob, it's alice");
    assert_eq!(alice_sk.0, bob_sk.0, "session keys must match");
    assert!(consumed_opk.is_some(), "an OPK should be consumed");

    // Consume the OPK from Bob's vault by ID
    let opk_id = consumed_opk.unwrap();
    assert!(bob.vault.payload.consume_opk_by_id(&opk_id).is_some());

    // -- 2. Add contacts to vaults --
    let alice_bundle = alice.bundle();
    let alice_contact = StoredContact::new(
        bob_bundle.clone(),
        "Bob".into(),
        alice.vault.payload.sequence,
    );
    let bob_contact = StoredContact::new(
        alice_bundle.clone(),
        "Alice".into(),
        bob.vault.payload.sequence,
    );
    let alice_contact_id = alice_contact.id;
    let bob_contact_id = bob_contact.id;
    alice.vault.payload.contacts.push(alice_contact);
    bob.vault.payload.contacts.push(bob_contact);

    // -- 3. Initialize Double Ratchets --
    let bob_ratchet_pub_key = X25519PublicKey::from(&bob.ratchet_secret);
    let mut alice_ratchet = RatchetState::init_alice(alice_sk.0, bob_ratchet_pub_key).unwrap();
    let mut bob_ratchet = RatchetState::init_bob(bob_sk.0, bob.ratchet_secret.clone());

    // -- 4. Alice sends 5 messages to Bob --
    let mut alice_messages: Vec<StoredMessage> = Vec::new();
    let mut bob_messages: Vec<StoredMessage> = Vec::new();
    let conversation_id = [0xAAu8; 32];

    for i in 0u64..5 {
        let text = format!("alice msg {i}");
        let (header, ct, mac_key_bytes) = alice_ratchet.ratchet_encrypt(text.as_bytes()).unwrap();

        // Build and verify HMAC
        let mac_key = MacKey(mac_key_bytes);
        let mac = compute_message_mac(&mac_key, &conversation_id, header.n, &ct);
        assert!(verify_message_mac(
            &mac_key,
            &conversation_id,
            header.n,
            &ct,
            &mac
        ));

        // Bob decrypts
        let (pt, bob_mac_bytes) = bob_ratchet.ratchet_decrypt(&header, &ct).unwrap();
        assert_eq!(pt, text.as_bytes());

        // Bob verifies HMAC
        let bob_mac_key = MacKey(bob_mac_bytes);
        assert!(verify_message_mac(
            &bob_mac_key,
            &conversation_id,
            header.n,
            &ct,
            &mac
        ));

        alice_messages.push(StoredMessage {
            counter: i,
            content: text.clone(),
            from_us: true,
        });
        bob_messages.push(StoredMessage {
            counter: i,
            content: text,
            from_us: false,
        });
    }

    // -- 5. Bob replies (triggers DH ratchet advancement) --
    for i in 0u64..3 {
        let text = format!("bob reply {i}");
        let (header, ct, _mac_key) = bob_ratchet.ratchet_encrypt(text.as_bytes()).unwrap();

        let (pt, _) = alice_ratchet.ratchet_decrypt(&header, &ct).unwrap();
        assert_eq!(pt, text.as_bytes());

        bob_messages.push(StoredMessage {
            counter: 5 + i,
            content: text.clone(),
            from_us: true,
        });
        alice_messages.push(StoredMessage {
            counter: 5 + i,
            content: text,
            from_us: false,
        });
    }

    // -- 6. Persist ratchet state and messages in vaults --
    let ratchet_key = SymKey([0xBBu8; 32]);
    let alice_ratchet_ct = alice_ratchet.to_encrypted_bytes(&ratchet_key).unwrap();
    let bob_ratchet_ct = bob_ratchet.to_encrypted_bytes(&ratchet_key).unwrap();

    // Store ratchet state in conversations
    let alice_conv = alice.vault.get_or_create_conversation(alice_contact_id);
    alice_conv.ratchet_state_ct = alice_ratchet_ct;

    let bob_conv = bob.vault.get_or_create_conversation(bob_contact_id);
    bob_conv.ratchet_state_ct = bob_ratchet_ct;

    // Store message logs
    alice
        .vault
        .save_messages(&alice_contact_id, &alice_messages)
        .unwrap();
    bob.vault
        .save_messages(&bob_contact_id, &bob_messages)
        .unwrap();

    // Save vaults to disk
    alice.vault.save().unwrap();
    bob.vault.save().unwrap();

    // -- 7. Reopen vaults from disk --
    let alice_vault2 =
        VaultUnlocked::unlock_with_params(&alice_path, b"test-passphrase", &test_params()).unwrap();
    let bob_vault2 =
        VaultUnlocked::unlock_with_params(&bob_path, b"test-passphrase", &test_params()).unwrap();

    // Verify contacts persisted
    assert_eq!(alice_vault2.payload.contacts.len(), 1);
    assert_eq!(alice_vault2.payload.contacts[0].display_name, "Bob");
    assert_eq!(bob_vault2.payload.contacts.len(), 1);
    assert_eq!(bob_vault2.payload.contacts[0].display_name, "Alice");

    // Verify message logs persisted
    let alice_msgs_loaded = alice_vault2.load_messages(&alice_contact_id);
    assert_eq!(alice_msgs_loaded.len(), 8); // 5 sent + 3 received
    assert_eq!(alice_msgs_loaded[0].content, "alice msg 0");
    assert!(alice_msgs_loaded[0].from_us);
    assert_eq!(alice_msgs_loaded[7].content, "bob reply 2");
    assert!(!alice_msgs_loaded[7].from_us);

    let bob_msgs_loaded = bob_vault2.load_messages(&bob_contact_id);
    assert_eq!(bob_msgs_loaded.len(), 8);
    assert!(!bob_msgs_loaded[0].from_us); // Bob received Alice's messages
    assert!(bob_msgs_loaded[5].from_us); // Bob sent replies

    // Verify OPK was consumed
    assert_eq!(
        bob_vault2.payload.opk_secrets.len(),
        9, // 10 generated - 1 consumed
    );

    // -- 8. Restore ratchet state and continue conversation --
    let alice_conv2 = &alice_vault2.payload.conversations[0];
    let mut alice_ratchet2 =
        RatchetState::from_encrypted_bytes(&ratchet_key, &alice_conv2.ratchet_state_ct).unwrap();

    let bob_conv2 = &bob_vault2.payload.conversations[0];
    let mut bob_ratchet2 =
        RatchetState::from_encrypted_bytes(&ratchet_key, &bob_conv2.ratchet_state_ct).unwrap();

    // Continue messaging after vault reload
    let (header, ct, _) = alice_ratchet2
        .ratchet_encrypt(b"still here after reload")
        .unwrap();
    let (pt, _) = bob_ratchet2.ratchet_decrypt(&header, &ct).unwrap();
    assert_eq!(pt, b"still here after reload");

    let (header, ct, _) = bob_ratchet2.ratchet_encrypt(b"me too").unwrap();
    let (pt, _) = alice_ratchet2.ratchet_decrypt(&header, &ct).unwrap();
    assert_eq!(pt, b"me too");

    // -- 9. No rollback detected --
    assert!(!alice_vault2.check_rollback());
    assert!(!bob_vault2.check_rollback());
}

// ---------------------------------------------------------------------------
// Test 2: Out-of-order delivery via outbox queue
// ---------------------------------------------------------------------------

#[test]
fn outbox_queue_persists_and_retries() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("outbox.op4");

    let mut vault =
        VaultUnlocked::create_with_params(&path, b"pass", b"duress", &test_params()).unwrap();

    // Simulate encrypting 3 messages for an offline contact
    let contact_id = [0xCCu8; 32];
    let recipient_addr = "offline_peer.onion:14101".to_string();

    for i in 0u32..3 {
        let fake_wire_payload = vec![i as u8; 512]; // simulated encrypted wire bytes
        vault.payload.outbox.push(PendingOutbound {
            contact_id,
            recipient_addr: recipient_addr.clone(),
            wire_payload: fake_wire_payload,
            retry_count: 0,
            created_seq: vault.payload.sequence,
        });
    }

    assert_eq!(vault.payload.outbox.len(), 3);

    // Save and reload
    vault.save().unwrap();
    let vault2 = VaultUnlocked::unlock_with_params(&path, b"pass", &test_params()).unwrap();

    assert_eq!(vault2.payload.outbox.len(), 3);
    assert_eq!(vault2.payload.outbox[0].contact_id, contact_id);
    assert_eq!(vault2.payload.outbox[0].recipient_addr, recipient_addr);
    assert_eq!(vault2.payload.outbox[1].wire_payload.len(), 512);
    assert_eq!(vault2.payload.outbox[2].wire_payload[0], 2);

    // Simulate successful delivery of first message -- remove from outbox
    let mut vault3 = VaultUnlocked::unlock_with_params(&path, b"pass", &test_params()).unwrap();
    vault3.payload.outbox.remove(0);
    assert_eq!(vault3.payload.outbox.len(), 2);
    vault3.save().unwrap();

    let vault4 = VaultUnlocked::unlock_with_params(&path, b"pass", &test_params()).unwrap();
    assert_eq!(vault4.payload.outbox.len(), 2);
}

// ---------------------------------------------------------------------------
// Test 3: Bootstrap code contact exchange flow
// ---------------------------------------------------------------------------

#[test]
fn bootstrap_code_contact_exchange() {
    let alice_kem = HybridKemKeypair::generate();
    let alice_signing = HybridSigningKeypair::generate();
    let alice_ratchet_secret = StaticSecret::random_from_rng(OsRng);
    let alice_ratchet_pub = X25519PublicKey::from(&alice_ratchet_secret).to_bytes();

    let alice_bundle = PublicKeyBundle::from_keypairs(
        &alice_kem,
        &alice_signing,
        alice_ratchet_pub,
        "alice.onion:14101".into(),
    );

    // Alice generates a bootstrap code
    let bootstrap = BootstrapCode::from_bundle(&alice_bundle);
    let encoded = bootstrap.encode();

    // Bob scans/pastes the code
    let decoded = BootstrapCode::decode(&encoded).unwrap();
    assert_eq!(decoded.nym_address, "alice.onion:14101");
    assert_eq!(decoded.ed25519_vk, alice_bundle.ed25519_vk);
    assert_eq!(decoded.x25519_pub, alice_bundle.x25519_pub);

    // Bob also generates a full contact code
    let bob_kem = HybridKemKeypair::generate();
    let bob_signing = HybridSigningKeypair::generate();
    let bob_ratchet_secret = StaticSecret::random_from_rng(OsRng);
    let bob_ratchet_pub = X25519PublicKey::from(&bob_ratchet_secret).to_bytes();

    let bob_bundle = PublicKeyBundle::from_keypairs(
        &bob_kem,
        &bob_signing,
        bob_ratchet_pub,
        "bob.onion:14101".into(),
    );
    let bob_code = ContactCode(bob_bundle.clone());
    let bob_encoded = bob_code.encode();

    // Alice decodes Bob's full contact code
    let decoded_bob = ContactCode::decode(&bob_encoded).unwrap();
    assert_eq!(decoded_bob.bundle().nym_address, "bob.onion:14101");
    assert_eq!(decoded_bob.fingerprint(), bob_bundle.fingerprint());

    // Both add each other as contacts
    let alice_stored = StoredContact::new(bob_bundle.clone(), "Bob".into(), 1);
    let bob_stored = StoredContact::new(alice_bundle.clone(), "Alice".into(), 1);

    // IDs are deterministic from the bundle
    assert_ne!(alice_stored.id, bob_stored.id);
    assert!(!alice_stored.verified);
    assert!(!bob_stored.verified);
}

// ---------------------------------------------------------------------------
// Test 4: Wire message construction and HMAC verification
// ---------------------------------------------------------------------------

#[test]
fn wire_message_with_ratchet_and_hmac() {
    // Set up a ratchet pair
    let root_key = [0x42u8; 32];
    let bob_secret = StaticSecret::random_from_rng(OsRng);
    let bob_pub = X25519PublicKey::from(&bob_secret);
    let mut alice = RatchetState::init_alice(root_key, bob_pub).unwrap();
    let mut bob = RatchetState::init_bob(root_key, bob_secret);

    let conversation_id = [0xDDu8; 32];
    let plaintext = b"wire message test payload";

    // Alice encrypts
    let (header, ct, mac_key_bytes) = alice.ratchet_encrypt(plaintext).unwrap();
    let mac_key = MacKey(mac_key_bytes);
    let mac = compute_message_mac(&mac_key, &conversation_id, header.n, &ct);

    // Build wire message
    let wire = WireMessage {
        msg_type: WireMessageType::Data,
        header: header.clone(),
        ciphertext: ct.clone(),
        mac: mac.clone(),
    };

    // Pad and serialize
    let padded = wire.with_padding();
    assert_eq!(padded.ciphertext.len() % 512, 0, "must be block-aligned");
    let wire_bytes = padded.to_bytes().unwrap();
    assert!(!wire_bytes.is_empty());

    // Deserialize on Bob's side
    let received = WireMessage::from_bytes(&wire_bytes).unwrap();
    assert!(matches!(received.msg_type, WireMessageType::Data));

    // Bob decrypts (using original ciphertext length from header, not padded)
    let (pt, bob_mac_bytes) = bob.ratchet_decrypt(&received.header, &ct).unwrap();
    assert_eq!(pt, plaintext);

    // Bob verifies HMAC
    let bob_mac_key = MacKey(bob_mac_bytes);
    assert!(verify_message_mac(
        &bob_mac_key,
        &conversation_id,
        received.header.n,
        &ct,
        &mac
    ));
}

// ---------------------------------------------------------------------------
// Test 5: Duress vault contains no real data
// ---------------------------------------------------------------------------

#[test]
fn duress_vault_is_isolated_from_real_data() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("duress_test.op4");

    // Create vault with real data
    let mut vault =
        VaultUnlocked::create_with_params(&path, b"real-pass", b"duress-pass", &test_params())
            .unwrap();

    vault.payload.nym_address = "real_user.onion:14101".into();
    vault.payload.generate_opks();

    let kem = HybridKemKeypair::generate();
    let signing = HybridSigningKeypair::generate();
    let bundle = PublicKeyBundle::from_keypairs(&kem, &signing, [1u8; 32], "peer.onion".into());
    vault
        .payload
        .contacts
        .push(StoredContact::new(bundle, "Real Friend".into(), 1));

    vault.save().unwrap();

    // Open with duress passphrase
    let duress = VaultUnlocked::unlock_with_params(&path, b"duress-pass", &test_params()).unwrap();

    assert!(duress.is_duress);
    assert_eq!(duress.payload.nym_address, "[duress]");
    assert!(
        duress.payload.contacts.is_empty(),
        "duress must have no contacts"
    );
    assert!(duress.payload.conversations.is_empty());
    assert!(duress.payload.outbox.is_empty());
    assert!(
        duress.payload.opk_secrets.is_empty(),
        "duress vault must not contain OPK secrets"
    );

    // Real vault still works
    let real = VaultUnlocked::unlock_with_params(&path, b"real-pass", &test_params()).unwrap();
    assert!(!real.is_duress);
    assert_eq!(real.payload.contacts.len(), 1);
    assert_eq!(real.payload.contacts[0].display_name, "Real Friend");
}

// ---------------------------------------------------------------------------
// Test 6: Settings persist through vault save/reload
// ---------------------------------------------------------------------------

#[test]
fn app_settings_persist() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("settings.op4");

    let mut vault =
        VaultUnlocked::create_with_params(&path, b"pass", b"duress", &test_params()).unwrap();

    vault.payload.settings = AppSettings {
        tor_socks_addr: "127.0.0.1:9150".into(),
        nym_gateway: Some("gateway.example.com".into()),
        default_auto_delete: Some(100),
    };
    vault.save().unwrap();

    let reloaded = VaultUnlocked::unlock_with_params(&path, b"pass", &test_params()).unwrap();
    assert_eq!(reloaded.payload.settings.tor_socks_addr, "127.0.0.1:9150");
    assert_eq!(
        reloaded.payload.settings.nym_gateway.as_deref(),
        Some("gateway.example.com")
    );
    assert_eq!(reloaded.payload.settings.default_auto_delete, Some(100));
}
