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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::primitives::MacKey;

    fn key() -> MacKey {
        MacKey([0x42u8; 32])
    }
    fn conv_id() -> [u8; 32] {
        [0x01u8; 32]
    }

    #[test]
    fn compute_verify_correct() {
        let mac = compute_message_mac(&key(), &conv_id(), 0, b"ciphertext");
        assert!(verify_message_mac(&key(), &conv_id(), 0, b"ciphertext", &mac));
    }

    #[test]
    fn verify_wrong_key_fails() {
        let mac = compute_message_mac(&key(), &conv_id(), 0, b"ciphertext");
        let other_key = MacKey([0x99u8; 32]);
        assert!(!verify_message_mac(&other_key, &conv_id(), 0, b"ciphertext", &mac));
    }

    #[test]
    fn verify_wrong_counter_fails() {
        let mac = compute_message_mac(&key(), &conv_id(), 0, b"ciphertext");
        assert!(!verify_message_mac(&key(), &conv_id(), 1, b"ciphertext", &mac));
    }

    #[test]
    fn verify_wrong_ciphertext_fails() {
        let mac = compute_message_mac(&key(), &conv_id(), 0, b"ciphertext");
        assert!(!verify_message_mac(&key(), &conv_id(), 0, b"different", &mac));
    }

    #[test]
    fn verify_wrong_conv_id_fails() {
        let mac = compute_message_mac(&key(), &conv_id(), 0, b"ciphertext");
        let other_id = [0x02u8; 32];
        assert!(!verify_message_mac(&key(), &other_id, 0, b"ciphertext", &mac));
    }

    #[test]
    fn tag_is_32_bytes() {
        let mac = compute_message_mac(&key(), &conv_id(), 0, b"payload");
        assert_eq!(mac.tag.len(), 32);
    }
}
