pub mod message;

/// A message received from the network transport.
#[derive(Debug)]
pub struct IncomingMessage {
    /// Transport-specific sender tag (unused in Tor transport, reserved).
    pub sender_tag: Option<Vec<u8>>,
    /// Raw payload bytes — a postcard-serialised `WireMessage`.
    pub payload: Vec<u8>,
}

/// Abstract transport trait — implemented by each platform's network backend.
///
/// - **op4-tui**: `NymClient` (Tor control port + SOCKS5 proxy)
/// - **op4-android**: arti-based embedded Tor client
pub trait Transport: Send {
    /// Our reachable address (e.g. `"<onion>.onion:14101"`).
    fn address(&self) -> &str;

    /// Enqueue an encrypted payload for delivery to `recipient_addr`.
    fn send(&self, recipient_addr: &str, payload: Vec<u8>) -> Result<(), crate::error::NetworkError>;

    /// Non-blocking poll for the next inbound message.
    fn try_recv_msg(&mut self) -> Option<IncomingMessage>;

    /// Request a new Tor circuit (SIGNAL NEWNYM or equivalent).
    fn signal_newnym(&self);
}
