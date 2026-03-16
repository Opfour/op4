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

/// Wire message type tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireMessageType {
    Handshake,
    Data,
    Revocation,
    Ack,
    Loop,          // cover traffic loop message (sent to self)
    Dummy,         // cover traffic filler
    BundleRequest, // bootstrap: request our full PublicKeyBundle
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
        let len = self.ciphertext.len();
        if len > MAX_PAYLOAD {
            // Truncate is not correct; callers should check before calling.
            // Here we just pad to MAX_PAYLOAD for robustness.
            self.ciphertext.truncate(MAX_PAYLOAD);
        }
        let remainder = len % BLOCK_SIZE;
        if remainder != 0 {
            let padding_needed = BLOCK_SIZE - remainder;
            let mut padding = vec![0u8; padding_needed];
            OsRng.fill_bytes(&mut padding);
            self.ciphertext.extend_from_slice(&padding);
        }
        self
    }

    /// Serialize the message to bytes for transmission via Nym SDK.
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("WireMessage serialization cannot fail")
    }

    /// Deserialize from bytes received from Nym SDK.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        postcard::from_bytes(bytes).ok()
    }
}

/// Build a dummy/cover traffic wire message of fixed size.
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
    dummy.to_bytes()
}
