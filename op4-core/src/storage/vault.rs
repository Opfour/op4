use std::fs;
use std::path::{Path, PathBuf};

use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::primitives::{
    aead_decrypt, aead_encrypt, argon2id_derive, Argon2Params, SymKey,
};
use crate::error::VaultError;
use crate::identity::profile::StoredContact;

use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

const VAULT_MAGIC: &[u8; 4] = b"OP4V";
/// Number of one-time prekeys to generate per batch.
pub const OPK_BATCH_SIZE: usize = 10;
/// When the OPK pool drops to this size or below, generate a new batch.
pub const OPK_REPLENISH_THRESHOLD: usize = 3;
/// Version 2 adds 8-byte section-length prefix fields to the header so that
/// AEAD decryption operates on the exact ciphertext bytes rather than the
/// padded section.  This fixes duress-passphrase decryption after the first
/// save when the duress payload is smaller than the normal payload.
const VAULT_VERSION: u8 = 2;
const SALT_LEN: usize = 32;

/// A message queued for delivery when the recipient was unreachable.
/// Stores the already-encrypted wire payload so the ratchet state does not
/// need to be re-advanced on retry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingOutbound {
    pub contact_id: [u8; 32],
    pub recipient_addr: String,
    /// Serialised `WireMessage` bytes (encrypted + padded).
    pub wire_payload: Vec<u8>,
    pub retry_count: u32,
    /// Vault sequence counter at the time this entry was created.
    pub created_seq: u64,
}

/// Stored conversation metadata in the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationMeta {
    pub id: [u8; 32],
    pub contact_id: [u8; 32],
    /// Ratchet state, encrypted with per-conversation key derived from master key
    pub ratchet_state_ct: Vec<u8>,
    /// Encrypted message log
    pub message_log_ct: Vec<u8>,
    pub unread_count: u32,
    /// Auto-delete after this many messages (None = keep all)
    pub auto_delete_after: Option<u32>,
}

/// Stored message (inside encrypted message log).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    pub counter: u64, // monotonic, no wall-clock time
    pub content: String,
    pub from_us: bool,
}

/// Application settings stored in the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub tor_socks_addr: String,
    pub nym_gateway: Option<String>,
    pub default_auto_delete: Option<u32>,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            tor_socks_addr: "127.0.0.1:9050".into(),
            nym_gateway: None,
            default_auto_delete: None,
        }
    }
}

/// Decrypted vault payload.
///
/// The three identity-secret fields are wrapped in `Zeroizing<Vec<u8>>` so
/// their bytes are actively overwritten when the vault payload is dropped
/// (e.g. on app exit or after an incorrect passphrase attempt).
/// `Zeroizing<T>` serializes identically to `T`, so existing vault files are
/// fully compatible — no migration required.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct VaultPayload {
    pub nym_address: String,
    /// Our identity KEM keypair bytes (X25519 secret + ML-KEM DK) — zeroized on drop.
    pub identity_kem_secret: Zeroizing<Vec<u8>>,
    /// Our identity signing keypair bytes — zeroized on drop.
    pub identity_signing_secret: Zeroizing<Vec<u8>>,
    /// Dedicated X25519 ratchet secret (separate from the KEM identity key).
    /// Alice uses the corresponding public key from the contact's `PublicKeyBundle`
    /// as Bob's initial ratchet key; Bob uses this secret for `init_bob()`.
    /// Zeroized on drop.
    pub identity_ratchet_secret: Zeroizing<Vec<u8>>,
    pub contacts: Vec<StoredContact>,
    pub conversations: Vec<ConversationMeta>,
    pub settings: AppSettings,
    /// Monotonic sequence counter (incremented each time vault is saved)
    pub sequence: u64,
    /// Messages awaiting delivery (encrypted wire payloads).
    /// Backward-compatible: absent in older vault files, defaults to empty.
    #[serde(default)]
    pub outbox: Vec<PendingOutbound>,
    /// One-time prekey X25519 secrets (32 bytes each). The corresponding public
    /// keys are derived and included in our PublicKeyBundle. Each secret is
    /// deleted after being consumed in a handshake.
    #[serde(default)]
    pub opk_secrets: Vec<[u8; 32]>,
}

impl VaultPayload {
    /// Generate a fresh batch of OPK secrets. Call this during identity
    /// creation and whenever the OPK pool is depleted.
    pub fn generate_opks(&mut self) {
        for _ in 0..OPK_BATCH_SIZE {
            let secret = StaticSecret::random_from_rng(OsRng);
            self.opk_secrets.push(secret.to_bytes());
        }
    }

    /// Derive OPK public keys from the current secrets.
    pub fn opk_public_keys(&self) -> Vec<[u8; 32]> {
        self.opk_secrets
            .iter()
            .map(|s| {
                let secret = StaticSecret::from(*s);
                X25519PublicKey::from(&secret).to_bytes()
            })
            .collect()
    }

    /// Compute the 4-byte OPK ID for a given secret (SHA-256 of the public key, truncated).
    pub fn opk_id_for_secret(secret: &[u8; 32]) -> [u8; 4] {
        use sha2::{Digest, Sha256};
        let public = X25519PublicKey::from(&StaticSecret::from(*secret)).to_bytes();
        let hash = Sha256::digest(public);
        [hash[0], hash[1], hash[2], hash[3]]
    }

    /// Compute OPK IDs for all current secrets (for inclusion in PublicKeyBundle).
    pub fn opk_ids(&self) -> Vec<[u8; 4]> {
        self.opk_secrets
            .iter()
            .map(Self::opk_id_for_secret)
            .collect()
    }

    /// Remove a consumed OPK by its 4-byte ID. Returns the secret if found.
    pub fn consume_opk_by_id(&mut self, id: &[u8; 4]) -> Option<[u8; 32]> {
        let pos = self
            .opk_secrets
            .iter()
            .position(|s| &Self::opk_id_for_secret(s) == id);
        pos.map(|idx| self.opk_secrets.remove(idx))
    }

    /// Check if the OPK pool is at or below the replenishment threshold
    /// and generate a new batch if so. Returns true if new OPKs were generated.
    pub fn replenish_opks_if_needed(&mut self) -> bool {
        if self.opk_secrets.len() <= OPK_REPLENISH_THRESHOLD {
            self.generate_opks();
            true
        } else {
            false
        }
    }
}

/// An unlocked vault with its decrypted payload.
pub struct VaultUnlocked {
    pub payload: VaultPayload,
    pub is_duress: bool,
    path: PathBuf,
    master_key: SymKey,
    duress_salt: [u8; SALT_LEN],
    normal_salt: [u8; SALT_LEN],
    /// Raw encrypted duress section ciphertext (without padding).
    /// Preserved across saves so the duress passphrase keeps working.
    duress_ct: Vec<u8>,
}

impl VaultUnlocked {
    /// Create a new vault with both normal and duress passphrases.
    pub fn create(
        path: &Path,
        normal_passphrase: &[u8],
        duress_passphrase: &[u8],
    ) -> Result<Self, VaultError> {
        Self::create_with_params(
            path,
            normal_passphrase,
            duress_passphrase,
            &Argon2Params::default(),
        )
    }

    /// Create a new vault with explicit Argon2 parameters.
    /// Use `Argon2Params::default()` for production and fast params for tests.
    pub fn create_with_params(
        path: &Path,
        normal_passphrase: &[u8],
        duress_passphrase: &[u8],
        params: &Argon2Params,
    ) -> Result<Self, VaultError> {
        let mut normal_salt = [0u8; SALT_LEN];
        let mut duress_salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut normal_salt);
        OsRng.fill_bytes(&mut duress_salt);

        let normal_key = argon2id_derive(normal_passphrase, &normal_salt, params)?;
        let duress_key = argon2id_derive(duress_passphrase, &duress_salt, params)?;

        let payload = VaultPayload::default();
        let duress_payload = VaultPayload {
            nym_address: "[duress]".into(),
            ..Default::default()
        };

        // Encrypt the duress section once and keep the raw ciphertext for future saves.
        let duress_payload_bytes =
            postcard::to_allocvec(&duress_payload).map_err(|_| VaultError::Corrupt)?;
        let duress_ct = aead_encrypt(&duress_key, &duress_payload_bytes, VAULT_MAGIC)?;

        let vault = VaultUnlocked {
            payload,
            is_duress: false,
            path: path.to_owned(),
            master_key: normal_key,
            duress_salt,
            normal_salt,
            duress_ct: duress_ct.clone(),
        };

        let vault_bytes = build_vault_file(
            &normal_salt,
            &duress_salt,
            &vault.master_key,
            &vault.payload,
            duress_ct,
        )?;
        write_atomic(path, &vault_bytes)?;

        Ok(vault)
    }

    /// Unlock an existing vault. Tries normal key first, then duress key.
    /// Always tries both before returning an error (timing side-channel prevention).
    pub fn unlock(path: &Path, passphrase: &[u8]) -> Result<Self, VaultError> {
        Self::unlock_with_params(path, passphrase, &Argon2Params::default())
    }

    /// Unlock with explicit Argon2 parameters (must match those used at creation).
    pub fn unlock_with_params(
        path: &Path,
        passphrase: &[u8],
        params: &Argon2Params,
    ) -> Result<Self, VaultError> {
        let data = fs::read(path)?;
        let header = parse_header(&data)?;

        let normal_key = argon2id_derive(passphrase, &header.normal_salt, params)?;
        let duress_key = argon2id_derive(passphrase, &header.duress_salt, params)?;

        let normal_result = try_decrypt_section(&data, &normal_key, &header, false);
        let duress_result = try_decrypt_section(&data, &duress_key, &header, true);

        // Extract both raw (pre-padding) ciphertext sections.
        let normal_raw = data
            [header.normal_section_offset..header.normal_section_offset + header.normal_ct_len]
            .to_vec();
        let duress_raw = data
            [header.duress_section_offset..header.duress_section_offset + header.duress_ct_len]
            .to_vec();

        // Evaluate results after both attempts (constant-time).
        if let Ok(payload) = normal_result {
            Ok(VaultUnlocked {
                payload,
                is_duress: false,
                path: path.to_owned(),
                master_key: normal_key,
                duress_salt: header.duress_salt,
                normal_salt: header.normal_salt,
                duress_ct: duress_raw,
            })
        } else if let Ok(payload) = duress_result {
            Ok(VaultUnlocked {
                payload,
                is_duress: true,
                path: path.to_owned(),
                master_key: duress_key,
                duress_salt: header.duress_salt,
                normal_salt: header.normal_salt,
                // In duress mode we store the normal section so it stays intact.
                duress_ct: normal_raw,
            })
        } else {
            Err(VaultError::InvalidPassphrase)
        }
    }

    /// Derive a per-conversation AEAD key from the vault master key.
    ///
    /// Uses HKDF-SHA256 with the master key as IKM and
    /// `"op4-conv-key-v1" || conversation_id` as the info field.
    /// The result is used to encrypt/decrypt `ConversationMeta::ratchet_state_ct`.
    pub fn derive_conversation_key(&self, conversation_id: &[u8; 32]) -> SymKey {
        use crate::crypto::primitives::hkdf_expand;
        use zeroize::Zeroizing;
        let mut info = b"op4-conv-key-v1".to_vec();
        info.extend_from_slice(conversation_id);
        // Wrap in Zeroizing so the raw bytes are overwritten on function exit,
        // even though they are immediately moved into SymKey (which is itself
        // ZeroizeOnDrop). Prevents the intermediate stack buffer from lingering.
        let mut out = Zeroizing::new([0u8; 32]);
        hkdf_expand(&self.master_key.0, None, &info, out.as_mut())
            .expect("HKDF expand is infallible for a 32-byte output");
        SymKey(*out)
    }

    /// Find the index of a `ConversationMeta` whose `contact_id` matches.
    pub fn find_conversation_by_contact(&self, contact_id: &[u8; 32]) -> Option<usize> {
        self.payload
            .conversations
            .iter()
            .position(|c| &c.contact_id == contact_id)
    }

    /// Return a mutable reference to the `ConversationMeta` for `contact_id`,
    /// creating a fresh one if none exists yet.
    pub fn get_or_create_conversation(&mut self, contact_id: [u8; 32]) -> &mut ConversationMeta {
        if self.find_conversation_by_contact(&contact_id).is_none() {
            let mut id = [0u8; 32];
            OsRng.fill_bytes(&mut id);
            self.payload.conversations.push(ConversationMeta {
                id,
                contact_id,
                ratchet_state_ct: Vec::new(),
                message_log_ct: Vec::new(),
                unread_count: 0,
                auto_delete_after: None,
            });
        }
        let idx = self.find_conversation_by_contact(&contact_id).unwrap();
        &mut self.payload.conversations[idx]
    }

    /// Decrypt and return the persisted message log for `contact_id`.
    /// Returns an empty Vec if no messages have been saved yet.
    pub fn load_messages(&self, contact_id: &[u8; 32]) -> Vec<StoredMessage> {
        let conv_idx = match self.find_conversation_by_contact(contact_id) {
            Some(i) => i,
            None => return Vec::new(),
        };
        let ct = &self.payload.conversations[conv_idx].message_log_ct;
        if ct.is_empty() {
            return Vec::new();
        }
        let key = self.derive_conversation_key(contact_id);
        let plain = match aead_decrypt(&key, ct, b"op4-msglog-v1") {
            Ok(p) => p,
            Err(_) => return Vec::new(),
        };
        postcard::from_bytes(&plain).unwrap_or_default()
    }

    /// Encrypt and persist the message log for `contact_id` into the vault.
    /// Call `vault.save()` afterwards to flush to disk.
    pub fn save_messages(
        &mut self,
        contact_id: &[u8; 32],
        messages: &[StoredMessage],
    ) -> Result<(), VaultError> {
        let key = self.derive_conversation_key(contact_id);
        let plain = postcard::to_allocvec(messages).map_err(|_| VaultError::Corrupt)?;
        let ct = aead_encrypt(&key, &plain, b"op4-msglog-v1")?;
        let conv = self.get_or_create_conversation(*contact_id);
        conv.message_log_ct = ct;
        Ok(())
    }

    /// Save the vault atomically (tmp file + rename).
    /// The duress section is preserved unchanged so the duress passphrase
    /// continues to work across saves.
    ///
    /// Increments the sequence counter and writes a rollback-detection marker
    /// file (`<vault_path>.seq`) containing `sequence || HMAC(master_key, sequence)`.
    /// The marker lets `unlock` detect if the vault was replaced with an older copy.
    pub fn save(&mut self) -> Result<(), VaultError> {
        self.payload.sequence += 1;
        let vault_bytes = build_vault_file(
            &self.normal_salt,
            &self.duress_salt,
            &self.master_key,
            &self.payload,
            self.duress_ct.clone(),
        )?;
        write_atomic(&self.path, &vault_bytes)?;
        write_sequence_marker(&self.path, &self.master_key, self.payload.sequence);
        Ok(())
    }

    /// Check if the vault's sequence counter is consistent with the rollback
    /// marker file. Returns `true` if the vault may have been rolled back
    /// (sequence is lower than the marker), `false` if OK or no marker exists.
    pub fn check_rollback(&self) -> bool {
        match read_sequence_marker(&self.path, &self.master_key) {
            Some(marker_seq) => self.payload.sequence < marker_seq,
            None => false, // no marker = first run or marker deleted
        }
    }
}

// ─── Internal Helpers ─────────────────────────────────────────────────────────

struct VaultHeader {
    normal_salt: [u8; SALT_LEN],
    duress_salt: [u8; SALT_LEN],
    /// Byte length of the actual (pre-padding) normal ciphertext.
    normal_ct_len: usize,
    /// Byte length of the actual (pre-padding) duress ciphertext.
    duress_ct_len: usize,
    normal_section_offset: usize,
    duress_section_offset: usize,
}

fn parse_header(data: &[u8]) -> Result<VaultHeader, VaultError> {
    // magic(4) + version(1) + normal_salt(32) + duress_salt(32) + normal_len(4) + duress_len(4)
    let header_len = 4 + 1 + SALT_LEN * 2 + 4 + 4;
    if data.len() < header_len {
        return Err(VaultError::Corrupt);
    }
    if &data[..4] != VAULT_MAGIC {
        return Err(VaultError::InvalidMagic);
    }
    if data[4] != VAULT_VERSION {
        return Err(VaultError::InvalidVersion);
    }
    let mut normal_salt = [0u8; SALT_LEN];
    let mut duress_salt = [0u8; SALT_LEN];
    normal_salt.copy_from_slice(&data[5..5 + SALT_LEN]);
    duress_salt.copy_from_slice(&data[5 + SALT_LEN..5 + SALT_LEN * 2]);

    let len_off = 5 + SALT_LEN * 2;
    let normal_ct_len = u32::from_le_bytes(
        data[len_off..len_off + 4]
            .try_into()
            .map_err(|_| VaultError::Corrupt)?,
    ) as usize;
    let duress_ct_len = u32::from_le_bytes(
        data[len_off + 4..len_off + 8]
            .try_into()
            .map_err(|_| VaultError::Corrupt)?,
    ) as usize;

    let remaining = data.len() - header_len;
    let section_padded_len = remaining / 2;

    if normal_ct_len > section_padded_len || duress_ct_len > section_padded_len {
        return Err(VaultError::Corrupt);
    }

    Ok(VaultHeader {
        normal_salt,
        duress_salt,
        normal_ct_len,
        duress_ct_len,
        normal_section_offset: header_len,
        duress_section_offset: header_len + section_padded_len,
    })
}

fn try_decrypt_section(
    data: &[u8],
    key: &SymKey,
    header: &VaultHeader,
    is_duress: bool,
) -> Result<VaultPayload, VaultError> {
    let (start, ct_len) = if is_duress {
        (header.duress_section_offset, header.duress_ct_len)
    } else {
        (header.normal_section_offset, header.normal_ct_len)
    };
    if ct_len == 0 || start + ct_len > data.len() {
        return Err(VaultError::Corrupt);
    }
    // Slice only the real ciphertext bytes — the padding that follows is ignored.
    let section = &data[start..start + ct_len];
    let plaintext = aead_decrypt(key, section, VAULT_MAGIC)?;
    let payload: VaultPayload =
        postcard::from_bytes(&plaintext).map_err(|_| VaultError::Corrupt)?;
    Ok(payload)
}

/// Build a vault file with a freshly encrypted normal section and the
/// preserved (opaque) duress ciphertext. Both sections are padded to the
/// same length with random bytes so an observer cannot tell which is real.
fn build_vault_file(
    normal_salt: &[u8; SALT_LEN],
    duress_salt: &[u8; SALT_LEN],
    normal_key: &SymKey,
    normal_payload: &VaultPayload,
    duress_ct: Vec<u8>,
) -> Result<Vec<u8>, VaultError> {
    let normal_bytes = postcard::to_allocvec(normal_payload).map_err(|_| VaultError::Corrupt)?;
    let normal_ct = aead_encrypt(normal_key, &normal_bytes, VAULT_MAGIC)?;

    let normal_ct_len = normal_ct.len();
    let duress_ct_len = duress_ct.len();

    // Pad both sections to equal size with random bytes.
    let max_len = normal_ct_len.max(duress_ct_len);
    let mut normal_padded = normal_ct;
    let mut duress_padded = duress_ct;
    if normal_padded.len() < max_len {
        let extra = max_len - normal_padded.len();
        let mut pad = vec![0u8; extra];
        OsRng.fill_bytes(&mut pad);
        normal_padded.extend_from_slice(&pad);
    }
    if duress_padded.len() < max_len {
        let extra = max_len - duress_padded.len();
        let mut pad = vec![0u8; extra];
        OsRng.fill_bytes(&mut pad);
        duress_padded.extend_from_slice(&pad);
    }

    let mut out = Vec::new();
    out.extend_from_slice(VAULT_MAGIC);
    out.push(VAULT_VERSION);
    out.extend_from_slice(normal_salt);
    out.extend_from_slice(duress_salt);
    // Store pre-padding ciphertext lengths so decryption can slice exactly.
    out.extend_from_slice(&(normal_ct_len as u32).to_le_bytes());
    out.extend_from_slice(&(duress_ct_len as u32).to_le_bytes());
    out.extend_from_slice(&normal_padded);
    out.extend_from_slice(&duress_padded);
    Ok(out)
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<(), VaultError> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, data)?;
    {
        let f = fs::File::open(&tmp)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Path of the rollback-detection marker file for a given vault path.
fn seq_marker_path(vault_path: &Path) -> PathBuf {
    vault_path.with_extension("seq")
}

/// Write `sequence (8 bytes LE) || HMAC-SHA256(master_key, sequence)` to the
/// marker file. Best-effort: failure is logged but does not block the save.
fn write_sequence_marker(vault_path: &Path, key: &SymKey, sequence: u64) {
    use crate::crypto::primitives::hmac_sign_raw;
    let seq_bytes = sequence.to_le_bytes();
    let mac = hmac_sign_raw(&key.0, &seq_bytes);
    let mut data = Vec::with_capacity(8 + 32);
    data.extend_from_slice(&seq_bytes);
    data.extend_from_slice(&mac);
    // Best-effort write -- failure doesn't block vault save.
    let _ = fs::write(seq_marker_path(vault_path), &data);
}

/// Read and verify the sequence marker. Returns `Some(sequence)` if the marker
/// exists and has a valid HMAC, `None` if missing, corrupt, or forged.
fn read_sequence_marker(vault_path: &Path, key: &SymKey) -> Option<u64> {
    use crate::crypto::primitives::hmac_verify_raw;
    let data = fs::read(seq_marker_path(vault_path)).ok()?;
    if data.len() != 40 {
        return None; // 8 (seq) + 32 (HMAC)
    }
    let seq_bytes: [u8; 8] = data[..8].try_into().ok()?;
    let mac: [u8; 32] = data[8..40].try_into().ok()?;
    if hmac_verify_raw(&key.0, &seq_bytes, &mac) {
        Some(u64::from_le_bytes(seq_bytes))
    } else {
        None // forged or wrong key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    use crate::crypto::primitives::Argon2Params;

    /// Fast Argon2 params for tests (1 MiB, 1 iteration). Production uses
    /// 64 MiB / 3 iterations. These are NOT secure -- test use only.
    fn test_params() -> Argon2Params {
        Argon2Params {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn create_test_vault(path: &std::path::Path, normal: &[u8], duress: &[u8]) -> VaultUnlocked {
        VaultUnlocked::create_with_params(path, normal, duress, &test_params()).unwrap()
    }

    fn unlock_test_vault(path: &std::path::Path, pass: &[u8]) -> Result<VaultUnlocked, VaultError> {
        VaultUnlocked::unlock_with_params(path, pass, &test_params())
    }

    #[test]
    fn create_and_unlock_normal() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.op4");

        create_test_vault(&path, b"normal-pass", b"duress-pass");
        let v = unlock_test_vault(&path, b"normal-pass").unwrap();

        assert!(!v.is_duress);
        assert!(v.payload.contacts.is_empty());
    }

    #[test]
    fn create_and_unlock_duress() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.op4");

        create_test_vault(&path, b"normal-pass", b"duress-pass");
        let v = unlock_test_vault(&path, b"duress-pass").unwrap();

        assert!(v.is_duress);
        assert_eq!(v.payload.nym_address, "[duress]");
    }

    #[test]
    fn wrong_passphrase_returns_invalid_passphrase() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.op4");

        create_test_vault(&path, b"correct", b"duress");
        let result = unlock_test_vault(&path, b"wrong");

        assert!(matches!(result, Err(VaultError::InvalidPassphrase)));
    }

    #[test]
    fn save_persists_payload_fields() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.op4");

        let mut vault = create_test_vault(&path, b"pass", b"duress");
        vault.payload.nym_address = "onion_addr".into();
        vault.payload.sequence = 42;
        vault.save().unwrap(); // save() auto-increments sequence to 43

        let reloaded = unlock_test_vault(&path, b"pass").unwrap();
        assert_eq!(reloaded.payload.nym_address, "onion_addr");
        assert_eq!(reloaded.payload.sequence, 43);
    }

    #[test]
    fn duress_passphrase_still_works_after_normal_save() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.op4");

        let mut vault = create_test_vault(&path, b"normal", b"duress");
        vault.payload.sequence = 1;
        vault.save().unwrap();

        let dv = unlock_test_vault(&path, b"duress").unwrap();
        assert!(dv.is_duress);
        assert_eq!(dv.payload.nym_address, "[duress]");
    }

    #[test]
    fn vault_file_starts_with_magic_and_version() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.op4");
        create_test_vault(&path, b"pass", b"duress");
        let raw = fs::read(&path).unwrap();
        assert_eq!(&raw[..4], b"OP4V");
        assert_eq!(raw[4], 2, "VAULT_VERSION must be 2");
    }

    #[test]
    fn rollback_detection_catches_stale_vault() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.op4");

        let mut vault = create_test_vault(&path, b"pass", b"duress");
        vault.save().unwrap(); // seq 1
        vault.save().unwrap(); // seq 2

        // Snapshot the vault file at seq 2
        let snapshot = fs::read(&path).unwrap();

        vault.save().unwrap(); // seq 3 -- marker file now says 3

        // Restore the old snapshot (seq 2) -- simulates rollback
        fs::write(&path, &snapshot).unwrap();

        let rolled_back = unlock_test_vault(&path, b"pass").unwrap();
        assert!(
            rolled_back.check_rollback(),
            "vault at seq 2 with marker at seq 3 should be detected as rollback"
        );
    }

    #[test]
    fn no_rollback_on_normal_use() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.op4");

        let mut vault = create_test_vault(&path, b"pass", b"duress");
        vault.save().unwrap();
        vault.save().unwrap();

        let reloaded = unlock_test_vault(&path, b"pass").unwrap();
        assert!(
            !reloaded.check_rollback(),
            "normal save/unlock cycle should not trigger rollback"
        );
    }

    #[test]
    fn corrupt_file_returns_error_without_argon2() {
        // This test does NOT invoke Argon2id: it reads a garbage file and
        // expects parse_header to fail before any KDF work is attempted.
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.op4");
        fs::write(&path, b"not a vault").unwrap();
        let result = VaultUnlocked::unlock(&path, b"any");
        assert!(matches!(
            result,
            Err(VaultError::InvalidMagic) | Err(VaultError::Corrupt)
        ));
    }

    // ── OPK management ───────────────────────────────────────────────────────

    #[test]
    fn generate_opks_creates_batch() {
        let mut payload = VaultPayload::default();
        assert!(payload.opk_secrets.is_empty());
        payload.generate_opks();
        assert_eq!(payload.opk_secrets.len(), OPK_BATCH_SIZE);
    }

    #[test]
    fn opk_public_keys_derive_from_secrets() {
        let mut payload = VaultPayload::default();
        payload.generate_opks();
        let pubs = payload.opk_public_keys();
        assert_eq!(pubs.len(), OPK_BATCH_SIZE);
        // Each public key should be 32 bytes and non-zero
        for pk in &pubs {
            assert_ne!(pk, &[0u8; 32]);
        }
    }

    #[test]
    fn opk_public_keys_match_secrets() {
        let mut payload = VaultPayload::default();
        payload.generate_opks();
        let pubs = payload.opk_public_keys();
        for (secret, expected_pub) in payload.opk_secrets.iter().zip(pubs.iter()) {
            let s = StaticSecret::from(*secret);
            let p = X25519PublicKey::from(&s).to_bytes();
            assert_eq!(&p, expected_pub);
        }
    }

    #[test]
    fn consume_opk_by_id_removes_correct_key() {
        let mut payload = VaultPayload::default();
        payload.generate_opks();
        let target_secret = payload.opk_secrets[0];
        let target_id = VaultPayload::opk_id_for_secret(&target_secret);
        let original_len = payload.opk_secrets.len();

        let removed = payload.consume_opk_by_id(&target_id);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap(), target_secret);
        assert_eq!(payload.opk_secrets.len(), original_len - 1);
        // The removed secret should no longer be in the pool
        assert!(!payload.opk_secrets.contains(&target_secret));
    }

    #[test]
    fn consume_opk_by_id_unknown_returns_none() {
        let mut payload = VaultPayload::default();
        payload.generate_opks();
        let fake_id = [0xFF, 0xFF, 0xFF, 0xFF];
        assert!(payload.consume_opk_by_id(&fake_id).is_none());
        assert_eq!(payload.opk_secrets.len(), OPK_BATCH_SIZE);
    }

    #[test]
    fn opk_ids_match_public_key_hashes() {
        let mut payload = VaultPayload::default();
        payload.generate_opks();
        let ids = payload.opk_ids();
        assert_eq!(ids.len(), OPK_BATCH_SIZE);
        // Each ID should match the hash of the corresponding public key
        for (secret, id) in payload.opk_secrets.iter().zip(ids.iter()) {
            assert_eq!(&VaultPayload::opk_id_for_secret(secret), id);
        }
    }

    #[test]
    fn replenish_opks_generates_new_batch_when_low() {
        let mut payload = VaultPayload::default();
        payload.generate_opks();
        // Drain to threshold
        while payload.opk_secrets.len() > OPK_REPLENISH_THRESHOLD {
            payload.opk_secrets.remove(0);
        }
        assert_eq!(payload.opk_secrets.len(), OPK_REPLENISH_THRESHOLD);
        assert!(payload.replenish_opks_if_needed());
        assert_eq!(
            payload.opk_secrets.len(),
            OPK_REPLENISH_THRESHOLD + OPK_BATCH_SIZE
        );
    }

    #[test]
    fn replenish_opks_does_nothing_when_pool_full() {
        let mut payload = VaultPayload::default();
        payload.generate_opks();
        assert!(!payload.replenish_opks_if_needed());
        assert_eq!(payload.opk_secrets.len(), OPK_BATCH_SIZE);
    }

    // ── AppSettings ──────────────────────────────────────────────────────────

    #[test]
    fn app_settings_default_values() {
        let s = AppSettings::default();
        assert_eq!(s.tor_socks_addr, "127.0.0.1:9050");
        assert!(s.nym_gateway.is_none());
        assert!(s.default_auto_delete.is_none());
    }

    // ── Message persistence ──────────────────────────────────────────────────

    #[test]
    fn save_and_load_messages_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.op4");
        let mut vault = create_test_vault(&path, b"pass", b"duress");

        let contact_id = [0xAAu8; 32];
        let msgs = vec![
            StoredMessage {
                counter: 1,
                content: "hello".into(),
                from_us: true,
            },
            StoredMessage {
                counter: 2,
                content: "world".into(),
                from_us: false,
            },
        ];
        vault.save_messages(&contact_id, &msgs).unwrap();

        let loaded = vault.load_messages(&contact_id);
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].content, "hello");
        assert_eq!(loaded[1].content, "world");
        assert!(loaded[0].from_us);
        assert!(!loaded[1].from_us);
    }

    #[test]
    fn load_messages_returns_empty_for_unknown_contact() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.op4");
        let vault = create_test_vault(&path, b"pass", b"duress");
        let loaded = vault.load_messages(&[0xBBu8; 32]);
        assert!(loaded.is_empty());
    }

    // ── Conversation management ──────────────────────────────────────────────

    #[test]
    fn get_or_create_conversation_creates_on_first_call() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.op4");
        let mut vault = create_test_vault(&path, b"pass", b"duress");

        let cid = [0xCCu8; 32];
        assert!(vault.payload.conversations.is_empty());
        let conv = vault.get_or_create_conversation(cid);
        assert_eq!(conv.contact_id, cid);
        assert_eq!(conv.unread_count, 0);
        assert_eq!(vault.payload.conversations.len(), 1);
    }

    #[test]
    fn get_or_create_conversation_reuses_existing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.op4");
        let mut vault = create_test_vault(&path, b"pass", b"duress");

        let cid = [0xDDu8; 32];
        vault.get_or_create_conversation(cid);
        vault.get_or_create_conversation(cid);
        assert_eq!(vault.payload.conversations.len(), 1);
    }
}
