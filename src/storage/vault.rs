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

const VAULT_MAGIC: &[u8; 4] = b"OP4V";
/// Version 2 adds 8-byte section-length prefix fields to the header so that
/// AEAD decryption operates on the exact ciphertext bytes rather than the
/// padded section.  This fixes duress-passphrase decryption after the first
/// save when the duress payload is smaller than the normal payload.
const VAULT_VERSION: u8 = 2;
const SALT_LEN: usize = 32;

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
        let mut normal_salt = [0u8; SALT_LEN];
        let mut duress_salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut normal_salt);
        OsRng.fill_bytes(&mut duress_salt);

        let params = Argon2Params::default();
        let normal_key = argon2id_derive(normal_passphrase, &normal_salt, &params)?;
        let duress_key = argon2id_derive(duress_passphrase, &duress_salt, &params)?;

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
        let data = fs::read(path)?;
        let header = parse_header(&data)?;

        let params = Argon2Params::default();
        let normal_key = argon2id_derive(passphrase, &header.normal_salt, &params)?;
        let duress_key = argon2id_derive(passphrase, &header.duress_salt, &params)?;

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
    pub fn save(&self) -> Result<(), VaultError> {
        let vault_bytes = build_vault_file(
            &self.normal_salt,
            &self.duress_salt,
            &self.master_key,
            &self.payload,
            self.duress_ct.clone(),
        )?;
        write_atomic(&self.path, &vault_bytes)
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // All vault tests use Argon2id at 64 MiB / 3 iterations (the production
    // default).  Each create+unlock pair takes several seconds.  Run them
    // explicitly with:
    //   cargo test --bin op4 storage::vault -- --include-ignored
    //
    // They are characterisation tests: they document current behaviour without
    // changing it.

    #[test]
    #[ignore = "slow: Argon2id at 64 MiB x 3 iters per call"]
    fn create_and_unlock_normal() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.op4");

        VaultUnlocked::create(&path, b"normal-pass", b"duress-pass").unwrap();
        let v = VaultUnlocked::unlock(&path, b"normal-pass").unwrap();

        assert!(!v.is_duress);
        assert!(v.payload.contacts.is_empty());
    }

    #[test]
    #[ignore = "slow: Argon2id at 64 MiB x 3 iters per call"]
    fn create_and_unlock_duress() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.op4");

        VaultUnlocked::create(&path, b"normal-pass", b"duress-pass").unwrap();
        let v = VaultUnlocked::unlock(&path, b"duress-pass").unwrap();

        assert!(v.is_duress);
        // The duress payload has the sentinel address set in VaultUnlocked::create
        assert_eq!(v.payload.nym_address, "[duress]");
    }

    #[test]
    #[ignore = "slow: Argon2id at 64 MiB x 3 iters per call"]
    fn wrong_passphrase_returns_invalid_passphrase() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.op4");

        VaultUnlocked::create(&path, b"correct", b"duress").unwrap();
        let result = VaultUnlocked::unlock(&path, b"wrong");

        assert!(matches!(result, Err(VaultError::InvalidPassphrase)));
    }

    #[test]
    #[ignore = "slow: Argon2id at 64 MiB x 3 iters per call"]
    fn save_persists_payload_fields() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.op4");

        let mut vault = VaultUnlocked::create(&path, b"pass", b"duress").unwrap();
        vault.payload.nym_address = "onion_addr".into();
        vault.payload.sequence = 42;
        vault.save().unwrap();

        let reloaded = VaultUnlocked::unlock(&path, b"pass").unwrap();
        assert_eq!(reloaded.payload.nym_address, "onion_addr");
        assert_eq!(reloaded.payload.sequence, 42);
    }

    #[test]
    #[ignore = "slow: Argon2id at 64 MiB x 3 iters per call"]
    fn duress_passphrase_still_works_after_normal_save() {
        // Saving with the normal key must not corrupt the duress section
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.op4");

        let mut vault = VaultUnlocked::create(&path, b"normal", b"duress").unwrap();
        vault.payload.sequence = 1;
        vault.save().unwrap();

        let dv = VaultUnlocked::unlock(&path, b"duress").unwrap();
        assert!(dv.is_duress);
        assert_eq!(dv.payload.nym_address, "[duress]");
    }

    #[test]
    #[ignore = "slow: Argon2id at 64 MiB x 3 iters per call"]
    fn vault_file_starts_with_magic_and_version() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.op4");
        VaultUnlocked::create(&path, b"pass", b"duress").unwrap();
        let raw = fs::read(&path).unwrap();
        assert_eq!(&raw[..4], b"OP4V");
        assert_eq!(raw[4], 2, "VAULT_VERSION must be 2");
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
}
