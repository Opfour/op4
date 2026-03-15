use crate::crypto::primitives::{hmac_sign, hmac_verify, MacKey};

/// HMAC-based deniable authentication tag for a wire message.
/// Unlike Ed25519, HMAC is deniable: both parties share the key,
/// so either could have produced the same tag.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MessageMac {
    pub tag: [u8; 32],
}

/// Compute HMAC-SHA256 over (conversation_id || counter_be || ciphertext).
/// `mac_key` is derived from the ratchet message key via HKDF with domain separation.
pub fn compute_message_mac(
    mac_key: &MacKey,
    conversation_id: &[u8; 32],
    counter: u64,
    ciphertext: &[u8],
) -> MessageMac {
    let mut data = Vec::with_capacity(32 + 8 + ciphertext.len());
    data.extend_from_slice(conversation_id);
    data.extend_from_slice(&counter.to_be_bytes());
    data.extend_from_slice(ciphertext);
    MessageMac {
        tag: hmac_sign(mac_key, &data),
    }
}

/// Constant-time verification.
pub fn verify_message_mac(
    mac_key: &MacKey,
    conversation_id: &[u8; 32],
    counter: u64,
    ciphertext: &[u8],
    mac: &MessageMac,
) -> bool {
    let mut data = Vec::with_capacity(32 + 8 + ciphertext.len());
    data.extend_from_slice(conversation_id);
    data.extend_from_slice(&counter.to_be_bytes());
    data.extend_from_slice(ciphertext);
    hmac_verify(mac_key, &data, &mac.tag)
}
