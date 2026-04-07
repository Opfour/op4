use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::ZeroizeOnDrop;

use crate::crypto::primitives::{aead_decrypt, aead_encrypt, hkdf_expand, hmac_sign_raw, SymKey};
use crate::error::CryptoError;

// ─── Serializable Mirror ──────────────────────────────────────────────────────

/// A serializable mirror of `RatchetState`.
/// All secret key material is held as raw `[u8; 32]` arrays so postcard can
/// encode it.  Callers are responsible for zeroizing these bytes after use.
#[derive(Serialize, Deserialize)]
pub struct SerializableRatchetState {
    pub dhs: [u8; 32],
    pub dhs_pub: [u8; 32],
    pub dhr: Option<[u8; 32]>,
    pub rk: [u8; 32],
    pub cks: Option<[u8; 32]>,
    pub ckr: Option<[u8; 32]>,
    pub ns: u64,
    pub nr: u64,
    pub pn: u64,
    /// Total messages received (monotonic, never resets). For skipped key TTL.
    #[serde(default)]
    pub total_recv: u64,
    /// Flattened form of the skipped-key HashMap.
    pub mkskipped: Vec<(SkippedKeyIndex, [u8; 32])>,
}

const MAX_SKIP: u64 = 100;

/// Maximum age of a skipped message key in terms of total messages received.
/// After this many messages have been received since the key was stored,
/// the skipped key is purged (the original message is considered lost).
const SKIPPED_KEY_MAX_AGE: u64 = 500;

// ─── Chain and Message Keys ───────────────────────────────────────────────────

#[derive(Clone, ZeroizeOnDrop)]
pub struct ChainKey(pub [u8; 32]);

#[derive(Clone, ZeroizeOnDrop)]
pub struct MessageKey(pub [u8; 32]);

/// Split a MessageKey into separate AEAD key and MAC key.
/// Uses HKDF with domain separation to produce two independent keys.
pub fn split_message_key(mk: &MessageKey) -> Result<(SymKey, [u8; 32]), CryptoError> {
    let mut out = [0u8; 64];
    hkdf_expand(
        &mk.0,
        Some(&[0u8; 32]),
        b"op4-ratchet-mk-split-v1",
        &mut out,
    )?;
    let mut aead_key = [0u8; 32];
    let mut mac_key = [0u8; 32];
    aead_key.copy_from_slice(&out[..32]);
    mac_key.copy_from_slice(&out[32..]);
    Ok((SymKey(aead_key), mac_key))
}

// ─── KDF Functions ────────────────────────────────────────────────────────────

/// KDF_RK: derive new root key and chain key from (root_key, DH_output).
fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> Result<([u8; 32], ChainKey), CryptoError> {
    let mut out = [0u8; 64];
    hkdf_expand(dh_out, Some(rk), b"op4-ratchet-rk-v1", &mut out)?;
    let mut new_rk = [0u8; 32];
    let mut new_ck = [0u8; 32];
    new_rk.copy_from_slice(&out[..32]);
    new_ck.copy_from_slice(&out[32..]);
    Ok((new_rk, ChainKey(new_ck)))
}

/// KDF_CK: advance a chain key, producing a message key and next chain key.
/// Uses HMAC-SHA256 with constant inputs (0x01 for msg key, 0x02 for next chain key).
fn kdf_ck(ck: &ChainKey) -> (MessageKey, ChainKey) {
    let mk_bytes = hmac_sign_raw(&ck.0, &[0x01]);
    let next_ck_bytes = hmac_sign_raw(&ck.0, &[0x02]);
    (MessageKey(mk_bytes), ChainKey(next_ck_bytes))
}

// ─── Message Header ───────────────────────────────────────────────────────────

/// Ratchet message header. Sent as AEAD additional data (authenticated, not encrypted).
/// Contains NO wall-clock time — only monotonic counters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageHeader {
    pub dh_pub: [u8; 32], // sender's current ratchet X25519 public key
    pub pn: u64,          // previous sending chain message count
    pub n: u64,           // current chain message number (monotonic)
}

// ─── Ratchet State ────────────────────────────────────────────────────────────

/// Index for a skipped message key in the out-of-order buffer.
/// Hash and Eq are based on (dh_ratchet_pub, msg_num) only -- stored_at is metadata.
#[derive(Clone, Serialize, Deserialize)]
pub struct SkippedKeyIndex {
    pub dh_ratchet_pub: [u8; 32],
    pub msg_num: u64,
    /// Total messages received when this key was stored. Used for TTL-based expiry.
    /// Defaults to 0 for backward compatibility with older serialized state.
    #[serde(default)]
    pub stored_at: u64,
}

impl std::hash::Hash for SkippedKeyIndex {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.dh_ratchet_pub.hash(state);
        self.msg_num.hash(state);
    }
}

impl PartialEq for SkippedKeyIndex {
    fn eq(&self, other: &Self) -> bool {
        self.dh_ratchet_pub == other.dh_ratchet_pub && self.msg_num == other.msg_num
    }
}

impl Eq for SkippedKeyIndex {}

/// Full Double Ratchet state for one conversation.
/// Persisted (encrypted) after every send/receive operation.
#[derive(ZeroizeOnDrop)]
pub struct RatchetState {
    dhs: StaticSecret, // our current DH ratchet sending secret
    dhs_pub: X25519PublicKey,
    #[zeroize(skip)]
    dhr: Option<X25519PublicKey>, // remote's current ratchet public key

    rk: [u8; 32], // root key

    cks: Option<ChainKey>, // sending chain key
    ckr: Option<ChainKey>, // receiving chain key

    ns: u64, // monotonic send counter
    nr: u64, // monotonic recv counter
    pn: u64, // previous sending chain length

    /// Total messages received across all DH ratchet steps (never resets).
    /// Used for TTL-based expiry of skipped message keys.
    total_recv: u64,

    // Out-of-order message key buffer (bounded to MAX_SKIP)
    #[zeroize(skip)]
    mkskipped: HashMap<SkippedKeyIndex, MessageKey>,
}

impl RatchetState {
    /// Initialize as the session initiator (Alice).
    pub fn init_alice(
        root_key: [u8; 32],
        bob_ratchet_pub: X25519PublicKey,
    ) -> Result<Self, CryptoError> {
        let dhs = StaticSecret::random_from_rng(OsRng);
        let dhs_pub = X25519PublicKey::from(&dhs);
        let dh_out = dhs.diffie_hellman(&bob_ratchet_pub);
        let (rk, cks) = kdf_rk(&root_key, dh_out.as_bytes())?;
        Ok(Self {
            dhs,
            dhs_pub,
            dhr: Some(bob_ratchet_pub),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            total_recv: 0,
            mkskipped: HashMap::new(),
        })
    }

    /// Initialize as the session responder (Bob).
    pub fn init_bob(root_key: [u8; 32], bob_ratchet_secret: StaticSecret) -> Self {
        let dhs_pub = X25519PublicKey::from(&bob_ratchet_secret);
        Self {
            dhs: bob_ratchet_secret,
            dhs_pub,
            dhr: None,
            rk: root_key,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            total_recv: 0,
            mkskipped: HashMap::new(),
        }
    }

    pub fn our_ratchet_pub(&self) -> [u8; 32] {
        self.dhs_pub.to_bytes()
    }

    // ─── Persistence ──────────────────────────────────────────────────────────

    /// Convert to a serializable mirror struct.
    pub fn to_serializable(&self) -> SerializableRatchetState {
        SerializableRatchetState {
            dhs: self.dhs.to_bytes(),
            dhs_pub: self.dhs_pub.to_bytes(),
            dhr: self.dhr.as_ref().map(|k| k.to_bytes()),
            rk: self.rk,
            cks: self.cks.as_ref().map(|k| k.0),
            ckr: self.ckr.as_ref().map(|k| k.0),
            ns: self.ns,
            nr: self.nr,
            pn: self.pn,
            total_recv: self.total_recv,
            mkskipped: self
                .mkskipped
                .iter()
                .map(|(idx, mk)| (idx.clone(), mk.0))
                .collect(),
        }
    }

    /// Reconstruct from a serializable mirror struct.
    pub fn from_serializable(s: SerializableRatchetState) -> Self {
        Self {
            dhs: StaticSecret::from(s.dhs),
            dhs_pub: X25519PublicKey::from(s.dhs_pub),
            dhr: s.dhr.map(X25519PublicKey::from),
            rk: s.rk,
            cks: s.cks.map(ChainKey),
            ckr: s.ckr.map(ChainKey),
            ns: s.ns,
            nr: s.nr,
            pn: s.pn,
            total_recv: s.total_recv,
            mkskipped: s
                .mkskipped
                .into_iter()
                .map(|(idx, mk)| (idx, MessageKey(mk)))
                .collect(),
        }
    }

    /// Serialize and AEAD-encrypt the ratchet state with a per-conversation key.
    pub fn to_encrypted_bytes(&self, key: &SymKey) -> Result<Vec<u8>, CryptoError> {
        let s = self.to_serializable();
        let plain = postcard::to_allocvec(&s).map_err(|_| CryptoError::Serialize)?;
        aead_encrypt(key, &plain, b"op4-ratchet-v1")
    }

    /// Decrypt and deserialize ratchet state from a per-conversation key.
    pub fn from_encrypted_bytes(key: &SymKey, ct: &[u8]) -> Result<Self, CryptoError> {
        let plain = aead_decrypt(key, ct, b"op4-ratchet-v1")?;
        let s: SerializableRatchetState =
            postcard::from_bytes(&plain).map_err(|_| CryptoError::AeadDecrypt)?;
        Ok(Self::from_serializable(s))
    }

    /// Encrypt a plaintext. Returns (header, ciphertext_with_nonce, mac_key_bytes).
    /// The mac_key is the HMAC key derived from the message key — callers use it
    /// to compute a deniable `MessageMac` over the ciphertext.
    pub fn ratchet_encrypt(
        &mut self,
        plaintext: &[u8],
    ) -> Result<(MessageHeader, Vec<u8>, [u8; 32]), CryptoError> {
        let (mk, new_cks) = kdf_ck(self.cks.as_ref().ok_or(CryptoError::NoChainKey)?);
        self.cks = Some(new_cks);

        let header = MessageHeader {
            dh_pub: self.dhs_pub.to_bytes(),
            pn: self.pn,
            n: self.ns,
        };
        // Monotonically increment — never set from remote data
        self.ns += 1;

        let (aead_key, mac_key_bytes) = split_message_key(&mk)?;
        let aad = postcard::to_allocvec(&header).map_err(|_| CryptoError::Serialize)?;
        let ct = aead_encrypt(&aead_key, plaintext, &aad)?;
        Ok((header, ct, mac_key_bytes))
    }

    /// Decrypt a message. Returns (plaintext, mac_key_bytes).
    /// The mac_key lets callers verify the deniable `MessageMac` that accompanied
    /// the ciphertext. Handles DH ratchet advancement and skipped keys.
    pub fn ratchet_decrypt(
        &mut self,
        header: &MessageHeader,
        ciphertext: &[u8],
    ) -> Result<(Vec<u8>, [u8; 32]), CryptoError> {
        let aad = postcard::to_allocvec(header).map_err(|_| CryptoError::Serialize)?;

        // 1. Check the skipped-message-key buffer first
        let skip_idx = SkippedKeyIndex {
            dh_ratchet_pub: header.dh_pub,
            msg_num: header.n,
            stored_at: 0, // not used for lookup (Hash/Eq ignores stored_at)
        };
        if let Some(mk) = self.mkskipped.remove(&skip_idx) {
            let (aead_key, mac_key_bytes) = split_message_key(&mk)?;
            let pt = aead_decrypt(&aead_key, ciphertext, &aad)?;
            self.total_recv += 1;
            self.purge_expired_skipped_keys();
            return Ok((pt, mac_key_bytes));
        }

        // 2. New DH ratchet key from peer? Advance.
        let peer_pub = X25519PublicKey::from(header.dh_pub);
        let current_dhr = self.dhr.as_ref().map(|k| k.to_bytes());
        if current_dhr != Some(header.dh_pub) {
            self.skip_message_keys(header.pn)?;
            self.dh_ratchet_step(peer_pub)?;
        }

        // 3. Skip within current chain to reach header.n
        self.skip_message_keys(header.n)?;

        // 4. Advance chain and decrypt
        let (mk, new_ckr) = kdf_ck(self.ckr.as_ref().ok_or(CryptoError::NoChainKey)?);
        self.ckr = Some(new_ckr);
        // Monotonically increment — never set from header.n directly
        self.nr += 1;

        let (aead_key, mac_key_bytes) = split_message_key(&mk)?;
        let pt = aead_decrypt(&aead_key, ciphertext, &aad)?;
        self.total_recv += 1;
        self.purge_expired_skipped_keys();
        Ok((pt, mac_key_bytes))
    }

    /// Remove skipped message keys that have exceeded their TTL.
    fn purge_expired_skipped_keys(&mut self) {
        let cutoff = self.total_recv.saturating_sub(SKIPPED_KEY_MAX_AGE);
        self.mkskipped.retain(|idx, _| idx.stored_at >= cutoff);
    }

    /// Buffer skipped message keys up to `until`, bounded by MAX_SKIP.
    fn skip_message_keys(&mut self, until: u64) -> Result<(), CryptoError> {
        if self.nr + MAX_SKIP < until {
            return Err(CryptoError::TooManySkipped);
        }
        while self.nr < until {
            let ck = self.ckr.as_ref().ok_or(CryptoError::NoChainKey)?;
            let (mk, next_ck) = kdf_ck(ck);
            let idx = SkippedKeyIndex {
                dh_ratchet_pub: self.dhr.as_ref().ok_or(CryptoError::NoDhrKey)?.to_bytes(),
                msg_num: self.nr,
                stored_at: self.total_recv,
            };
            self.mkskipped.insert(idx, mk);
            self.ckr = Some(next_ck);
            self.nr += 1;
        }
        Ok(())
    }

    /// Perform a DH ratchet step when a new peer ratchet public key is seen.
    fn dh_ratchet_step(&mut self, peer_pub: X25519PublicKey) -> Result<(), CryptoError> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(peer_pub);

        // Receiving chain: derive from our current DH secret + peer's new pub
        let dh_out = self.dhs.diffie_hellman(&peer_pub);
        let (new_rk, ckr) = kdf_rk(&self.rk, dh_out.as_bytes())?;
        self.rk = new_rk;
        self.ckr = Some(ckr);

        // Generate new DH ratchet keypair for sending
        let new_dhs = StaticSecret::random_from_rng(OsRng);
        let new_dhs_pub = X25519PublicKey::from(&new_dhs);
        let dh_out2 = new_dhs.diffie_hellman(&peer_pub);
        let (new_rk2, cks) = kdf_rk(&self.rk, dh_out2.as_bytes())?;
        self.rk = new_rk2;
        self.cks = Some(cks);
        self.dhs = new_dhs;
        self.dhs_pub = new_dhs_pub;

        Ok(())
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pair() -> (RatchetState, RatchetState) {
        let root_key = [0x42u8; 32];
        let bob_ratchet_secret = StaticSecret::random_from_rng(OsRng);
        let bob_ratchet_pub = X25519PublicKey::from(&bob_ratchet_secret);
        let alice = RatchetState::init_alice(root_key, bob_ratchet_pub).unwrap();
        let bob = RatchetState::init_bob(root_key, bob_ratchet_secret);
        (alice, bob)
    }

    #[test]
    fn basic_roundtrip() {
        let (mut alice, mut bob) = make_pair();
        let msg = b"hello from alice";
        let (hdr, ct, _mac_key) = alice.ratchet_encrypt(msg).unwrap();
        let (pt, _mac_key) = bob.ratchet_decrypt(&hdr, &ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn forward_secrecy_multiple_messages() {
        let (mut alice, mut bob) = make_pair();
        for i in 0u8..10 {
            let msg = vec![i; 16];
            let (hdr, ct, _) = alice.ratchet_encrypt(&msg).unwrap();
            let (pt, _) = bob.ratchet_decrypt(&hdr, &ct).unwrap();
            assert_eq!(pt, msg);
        }
    }

    #[test]
    fn counters_are_monotonic() {
        let (mut alice, _) = make_pair();
        let (hdr1, _, _) = alice.ratchet_encrypt(b"a").unwrap();
        let (hdr2, _, _) = alice.ratchet_encrypt(b"b").unwrap();
        assert!(hdr2.n > hdr1.n);
    }

    #[test]
    fn bidirectional_messaging() {
        // Alice sends, Bob replies, Alice decrypts reply
        let (mut alice, mut bob) = make_pair();

        let (hdr_a, ct_a, _) = alice.ratchet_encrypt(b"alice-to-bob").unwrap();
        let (pt_a, _) = bob.ratchet_decrypt(&hdr_a, &ct_a).unwrap();
        assert_eq!(pt_a, b"alice-to-bob");

        let (hdr_b, ct_b, _) = bob.ratchet_encrypt(b"bob-to-alice").unwrap();
        let (pt_b, _) = alice.ratchet_decrypt(&hdr_b, &ct_b).unwrap();
        assert_eq!(pt_b, b"bob-to-alice");
    }

    #[test]
    fn to_encrypted_bytes_roundtrip() {
        use crate::crypto::primitives::SymKey;

        let (mut alice, _) = make_pair();
        // Send a message so the state is non-trivial (counters advanced)
        let _ = alice.ratchet_encrypt(b"test").unwrap();

        let key = SymKey([0xddu8; 32]);
        let ct = alice.to_encrypted_bytes(&key).unwrap();
        let alice2 = RatchetState::from_encrypted_bytes(&key, &ct).unwrap();

        // Both states should produce identical serializable mirrors
        let s1 = alice.to_serializable();
        let s2 = alice2.to_serializable();
        assert_eq!(s1.dhs, s2.dhs);
        assert_eq!(s1.rk, s2.rk);
        assert_eq!(s1.ns, s2.ns);
        assert_eq!(s1.nr, s2.nr);
        assert_eq!(s1.pn, s2.pn);
    }

    #[test]
    fn to_encrypted_bytes_wrong_key_fails() {
        use crate::crypto::primitives::SymKey;

        let (alice, _) = make_pair();
        let key = SymKey([0x11u8; 32]);
        let ct = alice.to_encrypted_bytes(&key).unwrap();

        let wrong_key = SymKey([0x22u8; 32]);
        assert!(RatchetState::from_encrypted_bytes(&wrong_key, &ct).is_err());
    }

    #[test]
    fn split_message_key_deterministic() {
        let mk = MessageKey([0x55u8; 32]);
        let (aead1, mac1) = split_message_key(&mk).unwrap();
        let (aead2, mac2) = split_message_key(&mk).unwrap();
        assert_eq!(aead1.0, aead2.0);
        assert_eq!(mac1, mac2);
        // AEAD key and MAC key must be different
        assert_ne!(aead1.0, mac1);
    }

    #[test]
    fn out_of_order_messages_decrypt_correctly() {
        let (mut alice, mut bob) = make_pair();

        // Alice sends 3 messages
        let (hdr0, ct0, _) = alice.ratchet_encrypt(b"msg-0").unwrap();
        let (hdr1, ct1, _) = alice.ratchet_encrypt(b"msg-1").unwrap();
        let (hdr2, ct2, _) = alice.ratchet_encrypt(b"msg-2").unwrap();

        // Bob decrypts in reverse order (2, 0, 1)
        let (pt2, _) = bob.ratchet_decrypt(&hdr2, &ct2).unwrap();
        assert_eq!(pt2, b"msg-2");

        let (pt0, _) = bob.ratchet_decrypt(&hdr0, &ct0).unwrap();
        assert_eq!(pt0, b"msg-0");

        let (pt1, _) = bob.ratchet_decrypt(&hdr1, &ct1).unwrap();
        assert_eq!(pt1, b"msg-1");
    }

    #[test]
    fn serializable_roundtrip_preserves_skipped_keys() {
        let (mut alice, mut bob) = make_pair();

        // Alice sends 3, Bob only decrypts the 3rd -- skips 0 and 1
        let (_hdr0, _ct0, _) = alice.ratchet_encrypt(b"skip-0").unwrap();
        let (_hdr1, _ct1, _) = alice.ratchet_encrypt(b"skip-1").unwrap();
        let (hdr2, ct2, _) = alice.ratchet_encrypt(b"take-2").unwrap();
        let (pt, _) = bob.ratchet_decrypt(&hdr2, &ct2).unwrap();
        assert_eq!(pt, b"take-2");

        // Bob should have 2 skipped keys buffered
        let s = bob.to_serializable();
        assert_eq!(s.mkskipped.len(), 2);

        // Roundtrip through serialization
        let bob2 = RatchetState::from_serializable(s);
        let s2 = bob2.to_serializable();
        assert_eq!(s2.mkskipped.len(), 2);
    }

    #[test]
    fn our_ratchet_pub_returns_32_bytes() {
        let (alice, _) = make_pair();
        let pub_key = alice.our_ratchet_pub();
        assert_ne!(pub_key, [0u8; 32]);
    }

    #[test]
    fn kdf_ck_produces_distinct_keys() {
        let ck = ChainKey([0xAAu8; 32]);
        let (mk, next_ck) = kdf_ck(&ck);
        assert_ne!(mk.0, ck.0);
        assert_ne!(next_ck.0, ck.0);
        assert_ne!(mk.0, next_ck.0);
    }

    #[test]
    fn skipped_keys_expire_after_ttl() {
        let (mut alice, mut bob) = make_pair();

        // Alice sends 3 messages; Bob only receives the 3rd (skipping 0 and 1)
        let (hdr0, ct0, _) = alice.ratchet_encrypt(b"msg-0").unwrap();
        let (_hdr1, _ct1, _) = alice.ratchet_encrypt(b"msg-1").unwrap();
        let (hdr2, ct2, _) = alice.ratchet_encrypt(b"msg-2").unwrap();

        let (pt2, _) = bob.ratchet_decrypt(&hdr2, &ct2).unwrap();
        assert_eq!(pt2, b"msg-2");
        // Bob has 2 skipped keys stored
        assert_eq!(bob.mkskipped.len(), 2);

        // Simulate receiving SKIPPED_KEY_MAX_AGE more messages to expire them.
        // We do this by artificially advancing total_recv and purging.
        bob.total_recv += SKIPPED_KEY_MAX_AGE + 1;
        bob.purge_expired_skipped_keys();
        assert_eq!(bob.mkskipped.len(), 0, "skipped keys should be purged after TTL");

        // The expired skipped key should no longer decrypt
        assert!(bob.ratchet_decrypt(&hdr0, &ct0).is_err());
    }

    #[test]
    fn total_recv_increments_on_each_decrypt() {
        let (mut alice, mut bob) = make_pair();
        assert_eq!(bob.total_recv, 0);

        for i in 0..5u8 {
            let (hdr, ct, _) = alice.ratchet_encrypt(&[i]).unwrap();
            bob.ratchet_decrypt(&hdr, &ct).unwrap();
        }
        assert_eq!(bob.total_recv, 5);
    }

    #[test]
    fn kdf_rk_produces_new_root_and_chain() {
        let rk = [0xBBu8; 32];
        let dh = [0xCCu8; 32];
        let (new_rk, new_ck) = kdf_rk(&rk, &dh).unwrap();
        assert_ne!(new_rk, rk);
        assert_ne!(new_ck.0, [0u8; 32]);
    }
}
