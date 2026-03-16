//! Tor hidden-service transport.
//!
//! Replaces the Nym SDK stub with a working network layer.  Architecture:
//!
//! - **Inbound**: `TcpListener` on `127.0.0.1:LISTEN_PORT` exposed by Tor
//!   as a v3 `.onion` hidden service via `ADD_ONION` on the control port.
//! - **Outbound**: each message opens a fresh connection through the Tor
//!   SOCKS5 proxy (`127.0.0.1:9050`) to `<peer>.onion:LISTEN_PORT`.
//! - **Hidden-service key**: deterministically derived from the vault's
//!   identity signing secret via HKDF-SHA256 + SHA-512, so the `.onion`
//!   address is stable across restarts without extra storage.
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

use std::time::Duration;

use hkdf::Hkdf;
use rand::Rng;
use sha2::{Digest, Sha256, Sha512};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::error::NetworkError;
use crate::network::message::make_dummy_message;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Inbound hidden-service listener port (localhost only).
pub const LISTEN_PORT: u16 = 14101;

/// Tor control port address (must be enabled in `/etc/tor/torrc`).
const TOR_CONTROL_ADDR: &str = "127.0.0.1:9051";

/// Mean cover-traffic interval in seconds (Poisson process, λ = 1/30 s⁻¹).
const COVER_MEAN_SECS: f64 = 30.0;

/// Maximum inbound frame size in bytes (DoS guard).
const MAX_FRAME_BYTES: usize = 65_536;

// ── Public types ──────────────────────────────────────────────────────────────

/// A message received from the network.
#[derive(Debug)]
pub struct IncomingMessage {
    /// Unused in the Tor transport (always `None`; reserved for future use).
    pub sender_tag: Option<Vec<u8>>,
    /// Raw payload bytes — a postcard-serialised `WireMessage`.
    pub payload: Vec<u8>,
}

/// Tor hidden-service transport.
///
/// Keeps the same public interface as the former Nym SDK stub so nothing
/// else in the codebase needs to change.
pub struct NymClient {
    /// Our `.onion` address, e.g. `"abc123…xyz.onion:14101"`.
    /// Share this in your `PublicKeyBundle` so contacts can reach you.
    pub address: String,
    send_tx: mpsc::Sender<(String, Vec<u8>)>,
    recv_rx: mpsc::UnboundedReceiver<IncomingMessage>,
    /// Sender side of the NEWNYM channel. The background `control_loop` task
    /// owns the Tor control socket and processes signals from this channel.
    newnym_tx: mpsc::Sender<()>,
}

impl NymClient {
    /// Initialise the Tor transport.
    ///
    /// * `tor_socks_addr` — SOCKS5 proxy, e.g. `"127.0.0.1:9050"`.
    /// * `identity_signing_secret` — raw bytes of the vault's identity
    ///   signing keypair; used as HKDF input so the onion address is stable
    ///   across restarts.  If empty (first run before keypair generation) a
    ///   session-scoped random seed is used instead.
    pub async fn init(
        tor_socks_addr: &str,
        identity_signing_secret: &[u8],
    ) -> Result<Self, NetworkError> {
        // ── 1. Derive (or randomly seed) the hidden-service key ───────────────
        let hs_ikm: Vec<u8> = if identity_signing_secret.is_empty() {
            // First run: keypair not yet generated.  Use a session-scoped
            // random seed.  The address will change on restart once the real
            // keypair is stored, but no contacts know our address yet at that
            // point, so this is safe.
            use rand::RngCore;
            let mut tmp = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut tmp);
            tmp.to_vec()
        } else {
            identity_signing_secret.to_vec()
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
        let (send_tx, send_rx) = mpsc::channel::<(String, Vec<u8>)>(64);
        let (newnym_tx, newnym_rx) = mpsc::channel::<()>(4);

        // ── 6. Spawn background tasks ─────────────────────────────────────────
        tokio::spawn(inbound_loop(listener, recv_tx));
        tokio::spawn(outbound_loop(send_rx, tor_socks_addr.to_owned()));
        tokio::spawn(cover_traffic_loop(onion_address.clone(), send_tx.clone()));
        // The control socket is moved into control_loop, which keeps it alive
        // (Tor removes the hidden service when the control connection closes).
        tokio::spawn(control_loop(control, newnym_rx));

        Ok(NymClient {
            address: onion_address,
            send_tx,
            recv_rx,
            newnym_tx,
        })
    }

    /// Enqueue an encrypted wire message for delivery to `recipient_addr`.
    ///
    /// Non-blocking: returns an error if the outbound queue is full.
    /// The caller may retry; the payload must already be padded and encrypted.
    pub fn send(&self, recipient_addr: &str, payload: Vec<u8>) -> Result<(), NetworkError> {
        self.send_tx
            .try_send((recipient_addr.to_owned(), payload))
            .map_err(|e| NetworkError::NymSend(e.to_string()))
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

/// Authenticate with the Tor control port.
///
/// Tries cookie authentication first (reads the path advertised in
/// `PROTOCOLINFO`, falling back to `/run/tor/control.authcookie`).
/// If the cookie file is not readable, falls back to NULL authentication.
async fn tor_authenticate(control: &mut TcpStream) -> Result<(), NetworkError> {
    control
        .write_all(b"PROTOCOLINFO 1\r\n")
        .await
        .map_err(|e| NetworkError::NymInit(format!("PROTOCOLINFO write: {e}")))?;

    let info = read_tor_response(control).await?;

    let authenticated = if info.contains("COOKIE") || info.contains("SAFECOOKIE") {
        let cookie_path =
            extract_cookie_path(&info).unwrap_or_else(|| "/run/tor/control.authcookie".into());
        if let Ok(cookie) = tokio::fs::read(&cookie_path).await {
            let hex = bytes_to_hex(&cookie);
            let cmd = format!("AUTHENTICATE {hex}\r\n");
            control
                .write_all(cmd.as_bytes())
                .await
                .map_err(|e| NetworkError::NymInit(format!("AUTHENTICATE write: {e}")))?;
            let resp = read_tor_response(control).await?;
            resp.contains("250")
        } else {
            eprintln!(
                "[op4] Warning: cannot read Tor cookie at '{cookie_path}'. \
                 Add yourself to the 'debian-tor' group: sudo adduser $USER debian-tor"
            );
            false
        }
    } else {
        false
    };

    if !authenticated {
        // NULL auth (works when CookieAuthentication is off, e.g. in dev)
        control
            .write_all(b"AUTHENTICATE\r\n")
            .await
            .map_err(|e| NetworkError::NymInit(format!("AUTHENTICATE (null) write: {e}")))?;
        let resp = read_tor_response(control).await?;
        if !resp.contains("250") {
            return Err(NetworkError::NymInit(
                "Tor authentication failed. \
                 Ensure /etc/tor/torrc contains 'ControlPort 9051' and \
                 'CookieAuthentication 1', restart Tor, and add the op4 user \
                 to the 'debian-tor' group."
                    .into(),
            ));
        }
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
/// proxy.  Tor resolves `.onion` names internally — they never leave the
/// Tor network.
async fn socks5_connect(socks_addr: &str, target: &str) -> std::io::Result<TcpStream> {
    let (host, port_str) = target.rsplit_once(':').ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "target must be host:port")
    })?;
    let port: u16 = port_str.parse().map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid port number")
    })?;

    let mut s = TcpStream::connect(socks_addr).await?;

    // ── Greeting: version=5, 1 method, NO_AUTH ────────────────────────────────
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await?;
    if resp[0] != 0x05 || resp[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("SOCKS5: auth method rejected ({resp:?})"),
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
async fn inbound_loop(listener: TcpListener, recv_tx: mpsc::UnboundedSender<IncomingMessage>) {
    loop {
        match listener.accept().await {
            Ok((mut stream, _peer)) => {
                let tx = recv_tx.clone();
                tokio::spawn(async move {
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
async fn outbound_loop(mut send_rx: mpsc::Receiver<(String, Vec<u8>)>, socks_addr: String) {
    while let Some((addr, payload)) = send_rx.recv().await {
        let socks = socks_addr.clone();
        tokio::spawn(async move {
            match socks5_connect(&socks, &addr).await {
                Ok(mut stream) => {
                    if let Err(e) = write_frame(&mut stream, &payload).await {
                        eprintln!("[op4] outbound write to {addr}: {e}");
                    }
                }
                Err(e) => {
                    eprintln!("[op4] SOCKS5 connect to {addr}: {e}");
                }
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
        if control
            .write_all(b"SIGNAL NEWNYM\r\n")
            .await
            .is_ok()
        {
            // Drain the response (250 OK or error) to keep the stream in sync.
            read_tor_response(&mut control).await.ok();
            eprintln!("[op4] Tor circuit refresh requested (SIGNAL NEWNYM).");
        }
    }
    // Channel closed — NymClient dropped; control socket closes here,
    // which causes Tor to remove the hidden-service descriptor.
}

/// Send Poisson-distributed dummy messages to self for cover traffic.
///
/// This ensures that an external observer always sees traffic flowing,
/// making it harder to determine whether real messages are being exchanged.
async fn cover_traffic_loop(own_address: String, send_tx: mpsc::Sender<(String, Vec<u8>)>) {
    loop {
        let interval_secs = sample_exponential(COVER_MEAN_SECS);
        tokio::time::sleep(Duration::from_secs_f64(interval_secs)).await;
        // try_send: drop silently if queue is full (cover traffic is best-effort)
        let _ = send_tx.try_send((own_address.clone(), make_dummy_message()));
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
