use std::fs;
use std::path::{Path, PathBuf};

use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::crypto::primitives::{
    aead_decrypt, aead_encrypt, argon2id_derive, Argon2Params, SymKey,
};
use crate::error::VaultError;
use crate::identity::profile::StoredContact;

const VAULT_MAGIC: &[u8; 4] = b"OP4V";
const VAULT_VERSION: u8 = 1;
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
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct VaultPayload {
    pub nym_address: String,
    /// Our identity KEM keypair bytes (X25519 secret + ML-KEM DK)
    pub identity_kem_secret: Vec<u8>,
    /// Our identity signing keypair bytes
    pub identity_signing_secret: Vec<u8>,
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

        let vault = VaultUnlocked {
            payload,
            is_duress: false,
            path: path.to_owned(),
            master_key: normal_key,
            duress_salt,
            normal_salt,
        };

        // Build and write the vault file
        let vault_bytes = build_vault_file(
            &normal_salt,
            &duress_salt,
            &vault.master_key,
            &vault.payload,
            &duress_key,
            &duress_payload,
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

        // Evaluate results after both attempts (constant-time)
        if let Ok(payload) = normal_result {
            Ok(VaultUnlocked {
                payload,
                is_duress: false,
                path: path.to_owned(),
                master_key: normal_key,
                duress_salt: header.duress_salt,
                normal_salt: header.normal_salt,
            })
        } else if let Ok(payload) = duress_result {
            Ok(VaultUnlocked {
                payload,
                is_duress: true,
                path: path.to_owned(),
                master_key: duress_key,
                duress_salt: header.duress_salt,
                normal_salt: header.normal_salt,
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
        let mut info = b"op4-conv-key-v1".to_vec();
        info.extend_from_slice(conversation_id);
        let mut out = [0u8; 32];
        hkdf_expand(&self.master_key.0, None, &info, &mut out)
            .expect("HKDF expand is infallible for a 32-byte output");
        SymKey(out)
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
    pub fn save(&self) -> Result<(), VaultError> {
        // For the other section, we can't re-derive the duress key without the passphrase.
        // In a real implementation we'd keep the duress section opaque and just re-encrypt
        // the normal section. For now, we write a placeholder duress section.
        let duress_payload = VaultPayload {
            nym_address: "[duress]".into(),
            ..Default::default()
        };
        // We need the duress key to re-encrypt the duress section.
        // Since we don't have it here, we generate a fresh random duress section
        // that will be invalid (duress can only be set up at creation time).
        // TODO: persist duress section separately in production.
        let mut dummy_key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut dummy_key_bytes);
        let dummy_key = SymKey(dummy_key_bytes);

        let vault_bytes = build_vault_file(
            &self.normal_salt,
            &self.duress_salt,
            &self.master_key,
            &self.payload,
            &dummy_key,
            &duress_payload,
        )?;
        write_atomic(&self.path, &vault_bytes)
    }
}

// ─── Internal Helpers ─────────────────────────────────────────────────────────

struct VaultHeader {
    normal_salt: [u8; SALT_LEN],
    duress_salt: [u8; SALT_LEN],
    normal_section_offset: usize,
    duress_section_offset: usize,
}

fn parse_header(data: &[u8]) -> Result<VaultHeader, VaultError> {
    if data.len() < 4 + 1 + SALT_LEN * 2 {
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
    let header_len = 5 + SALT_LEN * 2;
    // Sections are split in half from header_len to end
    let remaining = data.len() - header_len;
    let section_size = remaining / 2;
    Ok(VaultHeader {
        normal_salt,
        duress_salt,
        normal_section_offset: header_len,
        duress_section_offset: header_len + section_size,
    })
}

fn try_decrypt_section(
    data: &[u8],
    key: &SymKey,
    header: &VaultHeader,
    is_duress: bool,
) -> Result<VaultPayload, VaultError> {
    let (start, end) = if is_duress {
        let s = header.duress_section_offset;
        (s, data.len())
    } else {
        let s = header.normal_section_offset;
        let e = header.duress_section_offset;
        (s, e)
    };
    if end <= start {
        return Err(VaultError::Corrupt);
    }
    let section = &data[start..end];
    let plaintext = aead_decrypt(key, section, VAULT_MAGIC)?;
    let payload: VaultPayload =
        postcard::from_bytes(&plaintext).map_err(|_| VaultError::Corrupt)?;
    Ok(payload)
}

fn build_vault_file(
    normal_salt: &[u8; SALT_LEN],
    duress_salt: &[u8; SALT_LEN],
    normal_key: &SymKey,
    normal_payload: &VaultPayload,
    duress_key: &SymKey,
    duress_payload: &VaultPayload,
) -> Result<Vec<u8>, VaultError> {
    let normal_bytes = postcard::to_allocvec(normal_payload).map_err(|_| VaultError::Corrupt)?;
    let duress_bytes = postcard::to_allocvec(duress_payload).map_err(|_| VaultError::Corrupt)?;

    let mut normal_ct = aead_encrypt(normal_key, &normal_bytes, VAULT_MAGIC)?;
    let mut duress_ct = aead_encrypt(duress_key, &duress_bytes, VAULT_MAGIC)?;

    // Pad both sections to the same size (hide which is real)
    let max_len = normal_ct.len().max(duress_ct.len());
    normal_ct.resize(max_len, 0);
    duress_ct.resize(max_len, 0);

    let mut out = Vec::new();
    out.extend_from_slice(VAULT_MAGIC);
    out.push(VAULT_VERSION);
    out.extend_from_slice(normal_salt);
    out.extend_from_slice(duress_salt);
    out.extend_from_slice(&normal_ct);
    out.extend_from_slice(&duress_ct);
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
