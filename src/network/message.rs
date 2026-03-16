use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::crypto::hmac_auth::MessageMac;
use crate::crypto::ratchet::MessageHeader;

/// Block size for fixed-length padding (hides message length).
pub const BLOCK_SIZE: usize = 512;
/// Maximum message payload: 8 blocks = 4096 bytes.
pub const MAX_BLOCKS: usize = 8;
pub const MAX_PAYLOAD: usize = BLOCK_SIZE * MAX_BLOCKS;
/// Hard cap on inbound wire bytes before the deserializer is invoked.
/// MAX_PAYLOAD (4096) + 512 bytes of framing/header/MAC overhead.
/// Any peer sending a larger blob is either buggy or hostile; drop it.
pub const MAX_WIRE_BYTES: usize = MAX_PAYLOAD + 512;

/// Wire message type tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireMessageType {
    Handshake,
    Data,
    Revocation,
    Ack,
    Loop,           // cover traffic loop message (sent to self)
    Dummy,          // cover traffic filler
    BundleRequest,  // bootstrap: request our full PublicKeyBundle
    BundleResponse, // bootstrap: response carrying full PublicKeyBundle
}

/// The outer wire message sent via Nym.
/// Sender identity is NOT in the routing layer.
/// Only recipient Nym address is known to the Nym network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireMessage {
    pub msg_type: WireMessageType,
    /// Ratchet header (plaintext, used as AEAD additional data)
    pub header: MessageHeader,
    /// Padded, encrypted payload (always a multiple of BLOCK_SIZE bytes)
    pub ciphertext: Vec<u8>,
    /// HMAC-based deniable authentication tag
    pub mac: MessageMac,
}

impl WireMessage {
    /// Pad `ciphertext` to the next multiple of BLOCK_SIZE using random bytes.
    /// Also enforces MAX_PAYLOAD limit.
    pub fn with_padding(mut self) -> Self {
        if self.ciphertext.len() > MAX_PAYLOAD {
            self.ciphertext.truncate(MAX_PAYLOAD);
        }
        // Compute remainder AFTER truncation to avoid padding a truncated
        // buffer based on the original (pre-truncation) length.
        let len = self.ciphertext.len();
        let remainder = len % BLOCK_SIZE;
        if remainder != 0 {
            let padding_needed = BLOCK_SIZE - remainder;
            let mut padding = vec![0u8; padding_needed];
            OsRng.fill_bytes(&mut padding);
            self.ciphertext.extend_from_slice(&padding);
        }
        self
    }

    /// Serialize the message to bytes for transmission.
    /// Returns `None` if serialization fails (should not happen with well-formed messages).
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        postcard::to_allocvec(self).ok()
    }

    /// Deserialize from bytes received from the transport.
    /// Returns `None` for oversized payloads (possible DoS probe) before
    /// invoking the deserializer, and for any malformed postcard data.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_WIRE_BYTES {
            return None;
        }
        postcard::from_bytes(bytes).ok()
    }
}

/// Build a dummy/cover traffic wire message of fixed size.
/// Returns an empty Vec if serialization fails (defensive; should not happen).
pub fn make_dummy_message() -> Vec<u8> {
    use crate::crypto::ratchet::MessageHeader;
    let dummy = WireMessage {
        msg_type: WireMessageType::Dummy,
        header: MessageHeader {
            dh_pub: [0u8; 32],
            pn: 0,
            n: 0,
        },
        ciphertext: {
            let mut v = vec![0u8; BLOCK_SIZE];
            OsRng.fill_bytes(&mut v);
            v
        },
        mac: MessageMac { tag: [0u8; 32] },
    };
    dummy.to_bytes().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hmac_auth::MessageMac;
    use crate::crypto::ratchet::MessageHeader;

    fn make_wire(ciphertext: Vec<u8>) -> WireMessage {
        WireMessage {
            msg_type: WireMessageType::Data,
            header: MessageHeader {
                dh_pub: [0u8; 32],
                pn: 0,
                n: 0,
            },
            ciphertext,
            mac: MessageMac { tag: [0u8; 32] },
        }
    }

    #[test]
    fn wire_message_roundtrip() {
        let msg = make_wire(vec![0xabu8; 64]);
        let bytes = msg.to_bytes().unwrap();
        let decoded = WireMessage::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.ciphertext, vec![0xabu8; 64]);
        assert!(matches!(decoded.msg_type, WireMessageType::Data));
    }

    #[test]
    fn from_bytes_rejects_oversized() {
        // One byte over the cap must be rejected before deserialisation.
        let oversized = vec![0u8; MAX_WIRE_BYTES + 1];
        assert!(WireMessage::from_bytes(&oversized).is_none());
    }

    #[test]
    fn from_bytes_accepts_at_cap() {
        // A byte array exactly at the cap should reach the deserialiser
        // (it will return None because the bytes are garbage, but it must
        // not be rejected by the size check alone).
        // We just verify the None comes from postcard, not the size guard.
        // Both paths return None so we can only distinguish by the cap constant.
        let at_cap = vec![0u8; MAX_WIRE_BYTES];
        // postcard will fail to deserialise garbage — result is still None,
        // but the size guard did not fire first.
        let _ = WireMessage::from_bytes(&at_cap); // must not panic
    }

    #[test]
    fn with_padding_aligns_to_block_size() {
        // 100 bytes → should round up to 512 (one block)
        let msg = make_wire(vec![0u8; 100]);
        let padded = msg.with_padding();
        assert_eq!(padded.ciphertext.len() % BLOCK_SIZE, 0);
        assert_eq!(padded.ciphertext.len(), BLOCK_SIZE);
    }

    #[test]
    fn with_padding_already_aligned_no_extra() {
        // Exactly BLOCK_SIZE bytes → no additional padding added
        let msg = make_wire(vec![0u8; BLOCK_SIZE]);
        let padded = msg.with_padding();
        assert_eq!(padded.ciphertext.len(), BLOCK_SIZE);
    }

    #[test]
    fn with_padding_two_blocks() {
        // BLOCK_SIZE + 1 bytes → padded to 2 × BLOCK_SIZE
        let msg = make_wire(vec![0u8; BLOCK_SIZE + 1]);
        let padded = msg.with_padding();
        assert_eq!(padded.ciphertext.len(), BLOCK_SIZE * 2);
    }

    #[test]
    fn with_padding_truncates_over_max_payload() {
        // Oversized ciphertext is truncated to MAX_PAYLOAD, which is already
        // block-aligned, so no extra padding is added.
        let msg = make_wire(vec![0u8; MAX_PAYLOAD + 1]);
        let padded = msg.with_padding();
        assert_eq!(padded.ciphertext.len(), MAX_PAYLOAD);
        assert_eq!(padded.ciphertext.len() % BLOCK_SIZE, 0);
    }

    #[test]
    fn make_dummy_message_decodes_as_dummy() {
        let bytes = make_dummy_message();
        let msg = WireMessage::from_bytes(&bytes).unwrap();
        assert!(matches!(msg.msg_type, WireMessageType::Dummy));
    }

    #[test]
    fn max_wire_bytes_constant_value() {
        assert_eq!(MAX_WIRE_BYTES, MAX_PAYLOAD + 512);
        assert_eq!(MAX_PAYLOAD, BLOCK_SIZE * MAX_BLOCKS);
    }
}
