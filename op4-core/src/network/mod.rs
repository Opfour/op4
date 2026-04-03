pub mod message;

/// A message received from the network transport.
#[derive(Debug)]
pub struct IncomingMessage {
    /// Transport-specific sender tag (unused in Tor transport, reserved).
    pub sender_tag: Option<Vec<u8>>,
    /// Raw payload bytes -- a postcard-serialised `WireMessage`.
    pub payload: Vec<u8>,
}

/// Abstract transport trait -- implemented by each platform's network backend.
///
/// - **op4-tui**: `NymClient` (Tor control port + SOCKS5 proxy)
/// - **op4-android**: arti-based embedded Tor client
pub trait Transport: Send {
    /// Our reachable address (e.g. `"<onion>.onion:14101"`).
    fn address(&self) -> &str;

    /// Enqueue an encrypted payload for delivery to `recipient_addr`.
    fn send(&self, recipient_addr: &str, payload: Vec<u8>) -> Result<(), crate::error::NetworkError>;

    /// Enqueue a payload and return a oneshot receiver that resolves to `true`
    /// when the TCP connection succeeds or `false` on failure. Callers poll
    /// the receiver non-blockingly to track delivery status.
    fn send_with_confirm(
        &self,
        recipient_addr: &str,
        payload: Vec<u8>,
    ) -> Result<tokio::sync::oneshot::Receiver<bool>, crate::error::NetworkError>;

    /// Non-blocking poll for the next inbound message.
    fn try_recv_msg(&mut self) -> Option<IncomingMessage>;

    /// Request a new Tor circuit (SIGNAL NEWNYM or equivalent).
    fn signal_newnym(&self);

    /// Update the list of contact addresses used for cover traffic distribution.
    /// Default no-op for transports that don't support cover traffic.
    fn set_contact_addrs(&self, _addrs: Vec<String>) {}
}
