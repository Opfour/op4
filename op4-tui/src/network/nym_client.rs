//! Tor hidden-service transport.
//!
//! Replaces the Nym SDK stub with a working network layer.  Architecture:
//!
//! - **Inbound**: `TcpListener` on `127.0.0.1:LISTEN_PORT` exposed by Tor
//!   as a v3 `.onion` hidden service via `ADD_ONION` on the control port.
//! - **Outbound**: each message opens a fresh connection through the Tor
//!   SOCKS5 proxy (`127.0.0.1:9050`) to `<peer>.onion:LISTEN_PORT`.
//! - **Hidden-service key**: deterministically derived from the vault's
//!   identity signing secret AND KEM secret combined via HKDF-SHA256, then
//!   expanded with SHA-512, so the `.onion` address is stable across restarts.
//!   Both secrets must be compromised simultaneously to re-derive the key.
//! - **Cover traffic**: Poisson-distributed dummy messages to self hide
//!   whether any real traffic is flowing.
//!
//! ## Required Tor configuration (`/etc/tor/torrc`)
//! ```text
//! ControlPort 9051
//! CookieAuthentication 1
//! ```
//! The op4 user must be in the `debian-tor` (or `tor`) group so that
//! `/run/tor/control.authcookie` is readable.
//!
//! ## Wire format
//! Each TCP connection carries exactly one message:
//! `[4 bytes BE u32 length][payload bytes]`
//!
//! ## Address format
//! `"<56-char-v3-onion>.onion:LISTEN_PORT"` — stored in
//! `PublicKeyBundle::nym_address` and shared with contacts.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use hkdf::Hkdf;
use rand::Rng;
use sha2::{Digest, Sha256, Sha512};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Semaphore};

use op4_core::error::NetworkError;
use op4_core::network::message::make_dummy_message;
use op4_core::network::{IncomingMessage, Transport};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Inbound hidden-service listener port (localhost only).
pub const LISTEN_PORT: u16 = 14101;

/// Tor control port address (must be enabled in `/etc/tor/torrc`).
const TOR_CONTROL_ADDR: &str = "127.0.0.1:9051";

/// Mean cover-traffic interval in seconds (Poisson process, λ = 1/30 s⁻¹).
const COVER_MEAN_SECS: f64 = 30.0;

/// Maximum concurrent inbound TCP connections (DoS / resource-exhaustion guard).
/// Connections beyond this limit are accepted and immediately dropped.
const MAX_INBOUND_CONNECTIONS: usize = 64;

/// Maximum inbound frame size in bytes (DoS guard).
const MAX_FRAME_BYTES: usize = 65_536;

// ── Public types ──────────────────────────────────────────────────────────────

/// Outbound channel item: (recipient_addr, payload, optional delivery confirmation).
type OutboundItem = (String, Vec<u8>, Option<oneshot::Sender<bool>>);

/// Tor hidden-service transport.
///
/// Keeps the same public interface as the former Nym SDK stub so nothing
/// else in the codebase needs to change.
pub struct NymClient {
    /// Our `.onion` address, e.g. `"abc123...xyz.onion:14101"`.
    /// Share this in your `PublicKeyBundle` so contacts can reach you.
    pub address: String,
    send_tx: mpsc::Sender<OutboundItem>,
    recv_rx: mpsc::UnboundedReceiver<IncomingMessage>,
    /// Sender side of the NEWNYM channel. The background `control_loop` task
    /// owns the Tor control socket and processes signals from this channel.
    newnym_tx: mpsc::Sender<()>,
    /// Contact addresses shared with the cover traffic loop.
    contact_addrs: Arc<Mutex<Vec<String>>>,
}

impl NymClient {
    /// Initialise the Tor transport.
    ///
    /// * `tor_socks_addr` — SOCKS5 proxy, e.g. `"127.0.0.1:9050"`.
    /// * `identity_signing_secret` — Ed25519+ML-DSA signing keypair bytes.
    /// * `identity_kem_secret` — X25519+ML-KEM KEM keypair bytes.
    ///
    /// Both secrets are combined via HKDF before being fed into
    /// `derive_onion_key`, so an attacker needs BOTH to re-derive the
    /// hidden-service key from vault material alone.
    /// If either is empty (first run before keypair generation) a
    /// session-scoped random seed is used; the address changes on the next
    /// restart, but no contacts know it yet so this is safe.
    pub async fn init(
        tor_socks_addr: &str,
        identity_signing_secret: &[u8],
        identity_kem_secret: &[u8],
    ) -> Result<Self, NetworkError> {
        // ── 1. Derive (or randomly seed) the hidden-service key ───────────────
        let hs_ikm: Vec<u8> = if identity_signing_secret.is_empty()
            || identity_kem_secret.is_empty()
        {
            // First run: keypairs not yet generated.  Use a session-scoped
            // random seed.  The address will change on restart once the real
            // keypairs are stored, but no contacts know our address yet.
            use rand::RngCore;
            let mut tmp = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut tmp);
            tmp.to_vec()
        } else {
            // Combine both secrets: HKDF-SHA256(signing||kem, info="op4-hs-ikm-v1") → 32 B.
            // Leaking one key alone is insufficient to re-derive the onion address.
            let mut combined =
                Vec::with_capacity(identity_signing_secret.len() + identity_kem_secret.len());
            combined.extend_from_slice(identity_signing_secret);
            combined.extend_from_slice(identity_kem_secret);
            let hk = Hkdf::<Sha256>::new(None, &combined);
            let mut ikm = [0u8; 32];
            hk.expand(b"op4-hs-ikm-v1", &mut ikm)
                .map_err(|_| NetworkError::NymInit("HKDF failed in hs_ikm derivation".into()))?;
            ikm.to_vec()
        };
        let hs_key = derive_onion_key(&hs_ikm)?;
        let hs_key_b64 = base64_encode_standard(&hs_key);

        // ── 2. Authenticate with the Tor control port ─────────────────────────
        let mut control = TcpStream::connect(TOR_CONTROL_ADDR).await.map_err(|e| {
            NetworkError::NymInit(format!(
                "Cannot connect to Tor control port {TOR_CONTROL_ADDR}: {e}. \
                     Add 'ControlPort 9051' to /etc/tor/torrc and restart Tor."
            ))
        })?;
        tor_authenticate(&mut control).await?;

        // ── 3. Create the v3 hidden service ───────────────────────────────────
        let cmd = format!(
            "ADD_ONION ED25519-V3:{hs_key_b64} Port={LISTEN_PORT},127.0.0.1:{LISTEN_PORT}\r\n"
        );
        control
            .write_all(cmd.as_bytes())
            .await
            .map_err(|e| NetworkError::NymInit(format!("ADD_ONION write: {e}")))?;

        let response = read_tor_response(&mut control).await?;
        let service_id = parse_service_id(&response)?;
        let onion_address = format!("{service_id}.onion:{LISTEN_PORT}");
        eprintln!("[op4] Tor hidden service: {onion_address}");
        eprintln!("[op4] Descriptor propagation takes ~60 s on first use.");

        // ── 4. Bind the inbound listener ──────────────────────────────────────
        let listener = TcpListener::bind(format!("127.0.0.1:{LISTEN_PORT}"))
            .await
            .map_err(|e| {
                NetworkError::NymInit(format!("Cannot bind 127.0.0.1:{LISTEN_PORT}: {e}"))
            })?;

        // ── 5. Channels ───────────────────────────────────────────────────────
        let (recv_tx, recv_rx) = mpsc::unbounded_channel::<IncomingMessage>();
        let (send_tx, send_rx) = mpsc::channel::<OutboundItem>(64);
        let (newnym_tx, newnym_rx) = mpsc::channel::<()>(4);

        // ── 6. Spawn background tasks ─────────────────────────────────────────
        tokio::spawn(inbound_loop(listener, recv_tx));
        tokio::spawn(outbound_loop(send_rx, tor_socks_addr.to_owned()));
        let contact_addrs: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        tokio::spawn(cover_traffic_loop(
            onion_address.clone(),
            send_tx.clone(),
            Arc::clone(&contact_addrs),
        ));
        // The control socket is moved into control_loop, which keeps it alive
        // (Tor removes the hidden service when the control connection closes).
        tokio::spawn(control_loop(control, newnym_rx));

        Ok(NymClient {
            address: onion_address,
            send_tx,
            recv_rx,
            newnym_tx,
            contact_addrs,
        })
    }

    /// Update the list of contact addresses used for cover traffic distribution.
    pub fn set_contact_addrs(&self, addrs: Vec<String>) {
        if let Ok(mut guard) = self.contact_addrs.lock() {
            *guard = addrs;
        }
    }

    /// Enqueue an encrypted wire message for delivery to `recipient_addr`.
    ///
    /// Non-blocking fire-and-forget: returns an error if the outbound queue
    /// is full. No delivery confirmation.
    pub fn send(&self, recipient_addr: &str, payload: Vec<u8>) -> Result<(), NetworkError> {
        self.send_tx
            .try_send((recipient_addr.to_owned(), payload, None))
            .map_err(|e| NetworkError::NymSend(e.to_string()))
    }

    /// Enqueue a message and return a oneshot receiver for delivery status.
    /// Resolves to `true` if the TCP write succeeded, `false` on failure.
    pub fn send_with_confirm(
        &self,
        recipient_addr: &str,
        payload: Vec<u8>,
    ) -> Result<oneshot::Receiver<bool>, NetworkError> {
        let (tx, rx) = oneshot::channel();
        self.send_tx
            .try_send((recipient_addr.to_owned(), payload, Some(tx)))
            .map_err(|e| NetworkError::NymSend(e.to_string()))?;
        Ok(rx)
    }

    /// Non-blocking poll for the next inbound message.
    /// Returns `None` if the receive queue is empty.
    pub fn try_recv_msg(&mut self) -> Option<IncomingMessage> {
        self.recv_rx.try_recv().ok()
    }

    /// Request a new Tor circuit by sending `SIGNAL NEWNYM` to the control
    /// port. Fire-and-forget: the background `control_loop` processes the
    /// signal asynchronously. New circuits become active after ~60 seconds.
    pub fn signal_newnym(&self) {
        self.newnym_tx.try_send(()).ok();
    }
}

impl Transport for NymClient {
    fn address(&self) -> &str {
        &self.address
    }

    fn send(&self, recipient_addr: &str, payload: Vec<u8>) -> Result<(), NetworkError> {
        NymClient::send(self, recipient_addr, payload)
    }

    fn send_with_confirm(
        &self,
        recipient_addr: &str,
        payload: Vec<u8>,
    ) -> Result<oneshot::Receiver<bool>, NetworkError> {
        NymClient::send_with_confirm(self, recipient_addr, payload)
    }

    fn try_recv_msg(&mut self) -> Option<IncomingMessage> {
        NymClient::try_recv_msg(self)
    }

    fn signal_newnym(&self) {
        NymClient::signal_newnym(self);
    }

    fn set_contact_addrs(&self, addrs: Vec<String>) {
        NymClient::set_contact_addrs(self, addrs);
    }
}

// ── Hidden-service key derivation ────────────────────────────────────────────

/// Derive a 64-byte expanded Ed25519 private key for the Tor hidden service
/// from the vault's identity signing secret bytes.
///
/// Derivation:
/// 1. `HKDF-SHA256(ikm, info="op4-onion-key-v1")` → 32-byte seed.
/// 2. `SHA-512(seed)` → 64-byte expanded key.
/// 3. Apply Ed25519 scalar clamping (RFC 8032 §5.1.5).
///
/// The result is passed to Tor's `ADD_ONION ED25519-V3:<base64>` command.
fn derive_onion_key(ikm: &[u8]) -> Result<[u8; 64], NetworkError> {
    // Step 1: HKDF-SHA256 → 32-byte seed
    let mut seed = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(None, ikm);
    hk.expand(b"op4-onion-key-v1", &mut seed)
        .map_err(|_| NetworkError::NymInit("HKDF expand failed in derive_onion_key".into()))?;

    // Step 2: SHA-512(seed) → 64-byte expanded private key
    let digest = Sha512::digest(seed);
    let mut expanded = [0u8; 64];
    expanded.copy_from_slice(&digest);

    // Step 3: clamp the scalar (first 32 bytes) per Ed25519 spec
    expanded[0] &= 248; // clear low 3 bits
    expanded[31] &= 127; // clear top bit
    expanded[31] |= 64; // set second-highest bit

    Ok(expanded)
}

// ── Tor control-port helpers ──────────────────────────────────────────────────

/// Authenticate with the Tor control port using cookie authentication only.
///
/// Reads the cookie path from `PROTOCOLINFO` (falling back to the Debian
/// default `/run/tor/control.authcookie`). Requires `COOKIE` or `SAFECOOKIE`
/// to be advertised; NULL authentication is not accepted as it would allow
/// any local process to control Tor.
async fn tor_authenticate(control: &mut TcpStream) -> Result<(), NetworkError> {
    control
        .write_all(b"PROTOCOLINFO 1\r\n")
        .await
        .map_err(|e| NetworkError::NymInit(format!("PROTOCOLINFO write: {e}")))?;

    let info = read_tor_response(control).await?;

    // Cookie / SafeCookie authentication is required. NULL auth is not
    // accepted: even on localhost an unauthenticated control port lets any
    // local process manipulate Tor, violating defense-in-depth.
    if !info.contains("COOKIE") && !info.contains("SAFECOOKIE") {
        return Err(NetworkError::NymInit(
            "Tor control port does not advertise COOKIE authentication. \
             Ensure /etc/tor/torrc contains 'CookieAuthentication 1' and restart Tor."
                .into(),
        ));
    }

    let cookie_path =
        extract_cookie_path(&info).unwrap_or_else(|| "/run/tor/control.authcookie".into());
    let cookie = tokio::fs::read(&cookie_path).await.map_err(|e| {
        NetworkError::NymInit(format!(
            "Cannot read Tor cookie at '{cookie_path}': {e}. \
             Add yourself to the 'debian-tor' group: sudo adduser $USER debian-tor"
        ))
    })?;

    let hex = bytes_to_hex(&cookie);
    let cmd = format!("AUTHENTICATE {hex}\r\n");
    control
        .write_all(cmd.as_bytes())
        .await
        .map_err(|e| NetworkError::NymInit(format!("AUTHENTICATE write: {e}")))?;
    let resp = read_tor_response(control).await?;
    if !resp.contains("250") {
        return Err(NetworkError::NymInit(
            "Tor cookie authentication rejected. \
             Ensure /etc/tor/torrc contains 'ControlPort 9051' and \
             'CookieAuthentication 1', restart Tor, and add the op4 user \
             to the 'debian-tor' group."
                .into(),
        ));
    }

    Ok(())
}

/// Extract the cookie-file path from a `PROTOCOLINFO` response.
fn extract_cookie_path(info: &str) -> Option<String> {
    let marker = "COOKIEFILE=\"";
    let start = info.find(marker)? + marker.len();
    let end = info[start..].find('"')? + start;
    Some(info[start..end].to_owned())
}

/// Read one `\n`-terminated line from the Tor control socket.
async fn read_tor_line(stream: &mut TcpStream) -> Result<String, NetworkError> {
    let mut line = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|e| NetworkError::NymInit(format!("Tor control read: {e}")))?;
        line.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(String::from_utf8_lossy(&line).into_owned());
        }
        if line.len() > 4096 {
            return Err(NetworkError::NymInit("Tor control line too long".into()));
        }
    }
}

/// Read a complete Tor control response.
///
/// Tor responses end when a line with format `"NNN <text>\r\n"` is received
/// (space at byte-position 3 indicates the final line; dash means continuation).
async fn read_tor_response(stream: &mut TcpStream) -> Result<String, NetworkError> {
    let mut acc = String::new();
    loop {
        let line = read_tor_line(stream).await?;
        acc.push_str(&line);

        // Terminator: "NNN <text>" — digit digit digit SPACE
        let b = line.as_bytes();
        if b.len() >= 4
            && b[3] == b' '
            && b[0].is_ascii_digit()
            && b[1].is_ascii_digit()
            && b[2].is_ascii_digit()
        {
            return Ok(acc);
        }

        if acc.len() > 8192 {
            return Err(NetworkError::NymInit(
                "Tor control response overflow".into(),
            ));
        }
    }
}

/// Parse the `ServiceID` field from an `ADD_ONION` response.
fn parse_service_id(response: &str) -> Result<String, NetworkError> {
    for line in response.lines() {
        if let Some(rest) = line
            .strip_prefix("250-ServiceID=")
            .or_else(|| line.strip_prefix("250 ServiceID="))
        {
            let id = rest.trim().to_owned();
            if !id.is_empty() {
                return Ok(id);
            }
        }
    }
    Err(NetworkError::NymInit(format!(
        "No ServiceID in ADD_ONION response:\n{response}"
    )))
}

// ── SOCKS5 ────────────────────────────────────────────────────────────────────

/// Open a TCP connection to `target` (`host:port`) through the Tor SOCKS5
/// proxy with per-peer stream isolation.
///
/// Uses SOCKS5 username/password authentication (RFC 1929) with the peer's
/// onion address as the username. When Tor is configured with `IsolateSOCKSAuth`
/// (which `scripts/setup-tor.sh` enables), each unique credential gets its own
/// Tor circuit — messages to different peers travel over independent paths.
///
/// Tor accepts username/password auth by default even without `IsolateSOCKSAuth`;
/// in that case the credentials are validated but circuit separation is not applied.
async fn socks5_connect(socks_addr: &str, target: &str) -> std::io::Result<TcpStream> {
    let (host, port_str) = target.rsplit_once(':').ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "target must be host:port")
    })?;
    let port: u16 = port_str.parse().map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid port number")
    })?;

    let mut s = TcpStream::connect(socks_addr).await?;

    // ── Greeting: offer USERNAME/PASSWORD (0x02) for stream isolation ─────────
    s.write_all(&[0x05, 0x01, 0x02]).await?;
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await?;
    if resp[0] != 0x05 || resp[1] != 0x02 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!(
                "SOCKS5: username/password method rejected ({resp:?}). \
                     Ensure Tor is running and accepts SOCKS5 connections."
            ),
        ));
    }

    // ── RFC 1929 sub-negotiation: peer onion address as username ──────────────
    // Tor uses the (username, password) pair as the isolation key when
    // IsolateSOCKSAuth is set on the SocksPort. Each unique pair gets its own
    // circuit, so messages to different peers stay on separate paths.
    let user = target.as_bytes(); // "abc123…xyz.onion:14101"
    if user.len() > 255 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "SOCKS5 isolation username exceeds 255 bytes",
        ));
    }
    let user_len = user.len() as u8;
    let mut auth_msg = vec![0x01, user_len]; // VER=1, ULEN
    auth_msg.extend_from_slice(user);
    auth_msg.push(0x01); // PLEN = 1
    auth_msg.push(0x00); // PASSWD = \x00  (Tor accepts any value)
    s.write_all(&auth_msg).await?;
    let mut auth_resp = [0u8; 2];
    s.read_exact(&mut auth_resp).await?;
    if auth_resp[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("SOCKS5: sub-auth rejected ({auth_resp:?})"),
        ));
    }

    // ── CONNECT request: ATYP=DOMAIN ─────────────────────────────────────────
    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "hostname too long for SOCKS5",
        ));
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8];
    req.extend_from_slice(host_bytes);
    req.push((port >> 8) as u8);
    req.push((port & 0xff) as u8);
    s.write_all(&req).await?;

    // ── CONNECT response ──────────────────────────────────────────────────────
    let mut hdr = [0u8; 4]; // VER REP RSV ATYP
    s.read_exact(&mut hdr).await?;
    if hdr[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("SOCKS5 CONNECT failed: REP=0x{:02x}", hdr[1]),
        ));
    }

    // Drain the bound-address field so the stream is positioned at data.
    match hdr[3] {
        0x01 => {
            let mut b = [0u8; 6]; // IPv4 (4) + port (2)
            s.read_exact(&mut b).await?;
        }
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            let mut b = vec![0u8; l[0] as usize + 2]; // domain + port (2)
            s.read_exact(&mut b).await?;
        }
        0x04 => {
            let mut b = [0u8; 18]; // IPv6 (16) + port (2)
            s.read_exact(&mut b).await?;
        }
        _ => {}
    }

    Ok(s)
}

// ── Frame I/O ─────────────────────────────────────────────────────────────────

/// Write `[4-byte BE u32 length][data]` to `stream`.
async fn write_frame(stream: &mut TcpStream, data: &[u8]) -> std::io::Result<()> {
    stream.write_all(&(data.len() as u32).to_be_bytes()).await?;
    stream.write_all(data).await?;
    stream.flush().await
}

/// Read a length-prefixed frame.  Returns `None` on EOF or oversized frames.
async fn read_frame(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.ok()?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return None; // DoS guard
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await.ok()?;
    Some(payload)
}

// ── Background tasks ──────────────────────────────────────────────────────────

/// Accept inbound TCP connections and push each payload into the receive queue.
///
/// A semaphore caps concurrent in-flight connections at `MAX_INBOUND_CONNECTIONS`.
/// Connections beyond that limit are accepted (so the OS doesn't queue them
/// indefinitely) and then immediately dropped, returning a TCP RST to the peer.
async fn inbound_loop(listener: TcpListener, recv_tx: mpsc::UnboundedSender<IncomingMessage>) {
    let sem = Arc::new(Semaphore::new(MAX_INBOUND_CONNECTIONS));
    loop {
        match listener.accept().await {
            Ok((mut stream, _peer)) => {
                // Try to acquire without blocking — if we're at the limit, drop
                // the connection rather than spawning an unbounded number of tasks.
                let permit = match sem.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        eprintln!(
                            "[op4] inbound connection dropped: \
                             {MAX_INBOUND_CONNECTIONS} concurrent connections limit reached"
                        );
                        drop(stream);
                        continue;
                    }
                };
                let tx = recv_tx.clone();
                tokio::spawn(async move {
                    let _permit = permit; // holds the semaphore slot for the task's lifetime
                    if let Some(payload) = read_frame(&mut stream).await {
                        let _ = tx.send(IncomingMessage {
                            sender_tag: None,
                            payload,
                        });
                    }
                });
            }
            Err(e) => {
                eprintln!("[op4] inbound accept error: {e}");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

/// Drain the outbound send queue, opening a fresh SOCKS5 connection per message.
async fn outbound_loop(mut send_rx: mpsc::Receiver<OutboundItem>, socks_addr: String) {
    while let Some((addr, payload, confirm_tx)) = send_rx.recv().await {
        let socks = socks_addr.clone();
        tokio::spawn(async move {
            let ok = match socks5_connect(&socks, &addr).await {
                Ok(mut stream) => {
                    if let Err(e) = write_frame(&mut stream, &payload).await {
                        eprintln!("[op4] outbound write to {addr}: {e}");
                        false
                    } else {
                        true
                    }
                }
                Err(e) => {
                    eprintln!("[op4] SOCKS5 connect to {addr}: {e}");
                    false
                }
            };
            if let Some(tx) = confirm_tx {
                let _ = tx.send(ok);
            }
        });
    }
}

/// Keep the Tor control connection alive and process NEWNYM requests.
///
/// Owns the control `TcpStream` so the hidden service stays registered for
/// the lifetime of this task. On each received signal, sends `SIGNAL NEWNYM`
/// to rotate the exit circuit. The hidden-service circuit itself is unaffected.
async fn control_loop(mut control: TcpStream, mut newnym_rx: mpsc::Receiver<()>) {
    while let Some(()) = newnym_rx.recv().await {
        if control.write_all(b"SIGNAL NEWNYM\r\n").await.is_ok() {
            // Drain the response (250 OK or error) to keep the stream in sync.
            read_tor_response(&mut control).await.ok();
            eprintln!("[op4] Tor circuit refresh requested (SIGNAL NEWNYM).");
        }
    }
    // Channel closed — NymClient dropped; control socket closes here,
    // which causes Tor to remove the hidden-service descriptor.
}

/// Send Poisson-distributed dummy messages for cover traffic.
///
/// Randomly targets self or a known contact address so that an external
/// observer cannot distinguish real messages from cover by destination alone.
async fn cover_traffic_loop(
    own_address: String,
    send_tx: mpsc::Sender<OutboundItem>,
    contact_addrs: Arc<Mutex<Vec<String>>>,
) {
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::from_entropy();
    loop {
        let interval_secs = sample_exponential(COVER_MEAN_SECS);
        tokio::time::sleep(Duration::from_secs_f64(interval_secs)).await;

        // Pick a target: 50% self, 50% random contact (if any).
        let target = {
            let contacts = contact_addrs.lock().ok();
            let has_contacts = contacts
                .as_ref()
                .is_some_and(|c| !c.is_empty());
            if has_contacts && rng.gen_bool(0.5) {
                let c = contacts.unwrap();
                c[rng.gen_range(0..c.len())].clone()
            } else {
                own_address.clone()
            }
        };

        let _ = send_tx.try_send((target, make_dummy_message(), None));
    }
}

// ── Utilities ─────────────────────────────────────────────────────────────────

/// Standard (padded) Base64 encoding — what Tor's control port expects.
fn base64_encode_standard(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let v = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[((v >> 18) & 0x3f) as usize] as char);
        out.push(T[((v >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[((v >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(v & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Encode bytes as uppercase hexadecimal (used for Tor cookie auth).
fn bytes_to_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02X}")).collect()
}

/// Sample one inter-arrival time from `Exp(1/mean_secs)` via inversion.
fn sample_exponential(mean_secs: f64) -> f64 {
    let u: f64 = rand::thread_rng().gen_range(f64::EPSILON..1.0_f64);
    -mean_secs * u.ln()
}
