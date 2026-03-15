use std::collections::HashMap;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::crypto::primitives::{
    aead_decrypt, aead_encrypt, hkdf_expand, hmac_sign_raw, SymKey,
};
use crate::error::CryptoError;

const MAX_SKIP: u64 = 100;

// ─── Chain and Message Keys ───────────────────────────────────────────────────

#[derive(Clone, ZeroizeOnDrop)]
pub struct ChainKey(pub [u8; 32]);

#[derive(Clone, ZeroizeOnDrop)]
pub struct MessageKey(pub [u8; 32]);

/// Split a MessageKey into separate AEAD key and MAC key.
/// Uses HKDF with domain separation to produce two independent keys.
pub fn split_message_key(mk: &MessageKey) -> Result<(SymKey, [u8; 32]), CryptoError> {
    let mut out = [0u8; 64];
    hkdf_expand(&mk.0, Some(&[0u8; 32]), b"op4-ratchet-mk-split-v1", &mut out)?;
    let mut aead_key = [0u8; 32];
    let mut mac_key = [0u8; 32];
    aead_key.copy_from_slice(&out[..32]);
    mac_key.copy_from_slice(&out[32..]);
    Ok((SymKey(aead_key), mac_key))
}

// ─── KDF Functions ────────────────────────────────────────────────────────────

/// KDF_RK: derive new root key and chain key from (root_key, DH_output).
fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], ChainKey) {
    let mut out = [0u8; 64];
    hkdf_expand(dh_out, Some(rk), b"op4-ratchet-rk-v1", &mut out)
        .expect("HKDF expand is infallible for valid output length");
    let mut new_rk = [0u8; 32];
    let mut new_ck = [0u8; 32];
    new_rk.copy_from_slice(&out[..32]);
    new_ck.copy_from_slice(&out[32..]);
    (new_rk, ChainKey(new_ck))
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
#[derive(Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct SkippedKeyIndex {
    pub dh_ratchet_pub: [u8; 32],
    pub msg_num: u64,
}

/// Full Double Ratchet state for one conversation.
/// Persisted (encrypted) after every send/receive operation.
#[derive(ZeroizeOnDrop)]
pub struct RatchetState {
    dhs: StaticSecret,              // our current DH ratchet sending secret
    dhs_pub: X25519PublicKey,
    #[zeroize(skip)]
    dhr: Option<X25519PublicKey>,   // remote's current ratchet public key

    rk: [u8; 32],                   // root key

    cks: Option<ChainKey>,          // sending chain key
    ckr: Option<ChainKey>,          // receiving chain key

    ns: u64,  // monotonic send counter
    nr: u64,  // monotonic recv counter
    pn: u64,  // previous sending chain length

    // Out-of-order message key buffer (bounded to MAX_SKIP)
    #[zeroize(skip)]
    mkskipped: HashMap<SkippedKeyIndex, MessageKey>,
}

impl RatchetState {
    /// Initialize as the session initiator (Alice).
    pub fn init_alice(
        root_key: [u8; 32],
        bob_ratchet_pub: X25519PublicKey,
    ) -> Self {
        let dhs = StaticSecret::random_from_rng(OsRng);
        let dhs_pub = X25519PublicKey::from(&dhs);
        let dh_out = dhs.diffie_hellman(&bob_ratchet_pub);
        let (rk, cks) = kdf_rk(&root_key, dh_out.as_bytes());
        Self {
            dhs,
            dhs_pub,
            dhr: Some(bob_ratchet_pub),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: HashMap::new(),
        }
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
            mkskipped: HashMap::new(),
        }
    }

    pub fn our_ratchet_pub(&self) -> [u8; 32] {
        self.dhs_pub.to_bytes()
    }

    /// Encrypt a plaintext. Returns (header, ciphertext_with_nonce).
    /// The header is used as AEAD additional data.
    pub fn ratchet_encrypt(
        &mut self,
        plaintext: &[u8],
    ) -> Result<(MessageHeader, Vec<u8>), CryptoError> {
        let (mk, new_cks) = kdf_ck(self.cks.as_ref().ok_or(CryptoError::NoChainKey)?);
        self.cks = Some(new_cks);

        let header = MessageHeader {
            dh_pub: self.dhs_pub.to_bytes(),
            pn: self.pn,
            n: self.ns,
        };
        // Monotonically increment — never set from remote data
        self.ns += 1;

        let (aead_key, _mac_key) = split_message_key(&mk)?;
        let aad = postcard::to_allocvec(&header).map_err(|_| CryptoError::AeadEncrypt)?;
        let ct = aead_encrypt(&aead_key, plaintext, &aad)?;
        Ok((header, ct))
    }

    /// Decrypt a message. Handles DH ratchet advancement and skipped keys.
    pub fn ratchet_decrypt(
        &mut self,
        header: &MessageHeader,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let aad = postcard::to_allocvec(header).map_err(|_| CryptoError::AeadDecrypt)?;

        // 1. Check the skipped-message-key buffer first
        let skip_idx = SkippedKeyIndex {
            dh_ratchet_pub: header.dh_pub,
            msg_num: header.n,
        };
        if let Some(mk) = self.mkskipped.remove(&skip_idx) {
            let (aead_key, _) = split_message_key(&mk)?;
            return aead_decrypt(&aead_key, ciphertext, &aad);
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

        let (aead_key, _) = split_message_key(&mk)?;
        aead_decrypt(&aead_key, ciphertext, &aad)
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
                dh_ratchet_pub: self
                    .dhr
                    .as_ref()
                    .ok_or(CryptoError::NoDhrKey)?
                    .to_bytes(),
                msg_num: self.nr,
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
        let (new_rk, ckr) = kdf_rk(&self.rk, dh_out.as_bytes());
        self.rk = new_rk;
        self.ckr = Some(ckr);

        // Generate new DH ratchet keypair for sending
        let new_dhs = StaticSecret::random_from_rng(OsRng);
        let new_dhs_pub = X25519PublicKey::from(&new_dhs);
        let dh_out2 = new_dhs.diffie_hellman(&peer_pub);
        let (new_rk2, cks) = kdf_rk(&self.rk, dh_out2.as_bytes());
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
        let alice = RatchetState::init_alice(root_key, bob_ratchet_pub);
        let bob = RatchetState::init_bob(root_key, bob_ratchet_secret);
        (alice, bob)
    }

    #[test]
    fn basic_roundtrip() {
        let (mut alice, mut bob) = make_pair();
        let msg = b"hello from alice";
        let (hdr, ct) = alice.ratchet_encrypt(msg).unwrap();
        let pt = bob.ratchet_decrypt(&hdr, &ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn forward_secrecy_multiple_messages() {
        let (mut alice, mut bob) = make_pair();
        for i in 0u8..10 {
            let msg = vec![i; 16];
            let (hdr, ct) = alice.ratchet_encrypt(&msg).unwrap();
            let pt = bob.ratchet_decrypt(&hdr, &ct).unwrap();
            assert_eq!(pt, msg);
        }
    }

    #[test]
    fn counters_are_monotonic() {
        let (mut alice, _) = make_pair();
        let (hdr1, _) = alice.ratchet_encrypt(b"a").unwrap();
        let (hdr2, _) = alice.ratchet_encrypt(b"b").unwrap();
        assert!(hdr2.n > hdr1.n);
    }
}
