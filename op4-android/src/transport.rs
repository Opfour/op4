//! arti-based Tor transport for Android.
//!
//! Replaces the TUI's 600-line control-port / SOCKS5 implementation with
//! ~150 lines of arti API calls. Architecture:
//!
//! - **Inbound**: v3 onion service created via `TorClient::launch_onion_service`.
//!   `RendRequest` → `StreamRequest` → `DataStream` for each connection.
//! - **Outbound**: `TorClient::connect("<onion>.onion:<port>")` opens a
//!   `DataStream` through Tor directly — no SOCKS5 proxy needed.
//! - **Cover traffic**: Poisson-distributed dummy messages to self, same as TUI.
//!
//! ## Key derivation
//! The onion service identity is managed by arti's keystore, which persists
//! keys in the state directory. The service nickname is derived from the
//! vault's identity secrets via HKDF so the same vault always produces the
//! same onion address (after first bootstrap).

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arti_client::{TorClient, config::TorClientConfigBuilder};
use futures::StreamExt;
use safelog::DisplayRedacted;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{OnionServiceConfig, handle_rend_requests};
use tor_rtcompat::PreferredRuntime;

use op4_core::error::NetworkError;
use op4_core::network::{IncomingMessage, Transport};
use op4_core::network::message::make_dummy_message;

/// Listening port advertised in the onion service (same as TUI for compatibility).
const LISTEN_PORT: u16 = 14101;

/// Mean cover-traffic interval in seconds (Poisson process, λ = 1/30 s⁻¹).
const COVER_MEAN_SECS: f64 = 30.0;

/// Maximum inbound frame size in bytes (DoS guard).
const MAX_FRAME_BYTES: usize = 65_536;

/// Outbound channel item: (recipient_addr, payload, optional delivery confirmation).
type OutboundItem = (String, Vec<u8>, Option<oneshot::Sender<bool>>);

/// arti-based Tor transport for Android.
pub struct ArtiTransport {
    /// Our `.onion:port` address.
    address: String,
    send_tx: mpsc::Sender<OutboundItem>,
    recv_rx: mpsc::UnboundedReceiver<IncomingMessage>,
    /// Contact addresses shared with the cover traffic loop.
    contact_addrs: Arc<Mutex<Vec<String>>>,
}

impl ArtiTransport {
    /// Bootstrap the embedded Tor client and create a v3 onion service.
    ///
    /// * `data_dir` — app-private directory for Tor state (e.g. Android internal storage).
    /// * `cache_dir` — app-private directory for Tor cache.
    /// * `service_nickname` — stable nickname for the onion service (derived from vault).
    pub async fn init(
        data_dir: &Path,
        cache_dir: &Path,
        service_nickname: &str,
    ) -> Result<Self, NetworkError> {
        // ── 1. Build arti config pointing to app-private storage ─────────
        let config = TorClientConfigBuilder::from_directories(data_dir, cache_dir)
            .build()
            .map_err(|e| NetworkError::NymInit(format!("arti config: {e}")))?;

        // ── 2. Bootstrap the Tor client ──────────────────────────────────
        log::info!("Bootstrapping embedded Tor client...");
        let client = TorClient::create_bootstrapped(config)
            .await
            .map_err(|e| NetworkError::NymInit(format!("arti bootstrap: {e}")))?;
        log::info!("Tor client bootstrapped.");

        let client = Arc::new(client);

        // ── 3. Create v3 onion service ───────────────────────────────────
        let nickname = service_nickname
            .parse()
            .map_err(|e| NetworkError::NymInit(format!("invalid service nickname: {e}")))?;

        let svc_config = OnionServiceConfig::builder()
            .nickname(nickname)
            .build()
            .map_err(|e| NetworkError::NymInit(format!("onion service config: {e}")))?;

        let (service, rend_stream) = client
            .launch_onion_service(svc_config)
            .map_err(|e| NetworkError::NymInit(format!("launch onion service: {e}")))?
            .ok_or_else(|| NetworkError::NymInit("onion service disabled in config".into()))?;

        // Wait briefly for the onion address to become available.
        let onion_addr = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if let Some(hs_id) = service.onion_address() {
                    return format!(
                        "{}:{LISTEN_PORT}",
                        hs_id.display_unredacted()
                    );
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
        .await
        .map_err(|_| NetworkError::NymInit("timeout waiting for onion address".into()))?;

        log::info!("Onion service ready");
        log::info!("Descriptor propagation takes ~60 s on first use.");

        // ── 4. Channels ──────────────────────────────────────────────────
        let (recv_tx, recv_rx) = mpsc::unbounded_channel::<IncomingMessage>();
        let (send_tx, send_rx) = mpsc::channel::<OutboundItem>(64);

        // ── 5. Spawn background tasks ────────────────────────────────────
        tokio::spawn(inbound_loop(rend_stream, recv_tx));
        tokio::spawn(outbound_loop(send_rx, Arc::clone(&client)));
        let contact_addrs: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        tokio::spawn(cover_traffic_loop(
            onion_addr.clone(),
            send_tx.clone(),
            Arc::clone(&contact_addrs),
        ));

        // Keep the service Arc alive — dropping it removes the onion service.
        tokio::spawn(async move {
            let _keep = service;
            futures::future::pending::<()>().await;
        });

        Ok(ArtiTransport {
            address: onion_addr,
            send_tx,
            recv_rx,
            contact_addrs,
        })
    }
}

impl Transport for ArtiTransport {
    fn address(&self) -> &str {
        &self.address
    }

    fn send(&self, recipient_addr: &str, payload: Vec<u8>) -> Result<(), NetworkError> {
        self.send_tx
            .try_send((recipient_addr.to_owned(), payload, None))
            .map_err(|e| NetworkError::NymSend(e.to_string()))
    }

    fn send_with_confirm(
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

    fn try_recv_msg(&mut self) -> Option<IncomingMessage> {
        self.recv_rx.try_recv().ok()
    }

    fn signal_newnym(&self) {
        // arti manages circuit rotation internally.
        // No explicit SIGNAL NEWNYM needed -- arti rotates circuits based on
        // its own isolation and lifetime policies. This is a no-op on Android.
        log::debug!("signal_newnym: arti manages circuit rotation internally");
    }

    fn set_contact_addrs(&self, addrs: Vec<String>) {
        if let Ok(mut guard) = self.contact_addrs.lock() {
            *guard = addrs;
        }
    }
}

// ── Frame I/O ────────────────────────────────────────────────────────────────

/// Write `[4-byte BE u32 length][data]` — same wire format as TUI.
async fn write_frame<W: AsyncWriteExt + Unpin>(stream: &mut W, data: &[u8]) -> std::io::Result<()> {
    stream.write_all(&(data.len() as u32).to_be_bytes()).await?;
    stream.write_all(data).await?;
    stream.flush().await
}

/// Read a length-prefixed frame. Returns `None` on EOF or oversized frames.
async fn read_frame<R: AsyncReadExt + Unpin>(stream: &mut R) -> Option<Vec<u8>> {
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

// ── Background tasks ─────────────────────────────────────────────────────────

/// Accept inbound connections via the onion service and push payloads into
/// the receive queue. Each `StreamRequest` becomes a `DataStream`.
async fn inbound_loop(
    rend_stream: impl futures::Stream<Item = tor_hsservice::RendRequest> + Unpin,
    recv_tx: mpsc::UnboundedSender<IncomingMessage>,
) {
    let mut stream_requests = handle_rend_requests(rend_stream);

    while let Some(stream_req) = stream_requests.next().await {
        let tx = recv_tx.clone();
        tokio::spawn(async move {
            match stream_req.accept(Connected::new_empty()).await {
                Ok(mut data_stream) => {
                    if let Some(payload) = read_frame(&mut data_stream).await {
                        let _ = tx.send(IncomingMessage {
                            sender_tag: None,
                            payload,
                        });
                    }
                }
                Err(e) => {
                    log::warn!("inbound stream accept error: {e}");
                }
            }
        });
    }
}

/// Drain the outbound send queue, opening a fresh Tor connection per message.
async fn outbound_loop(
    mut send_rx: mpsc::Receiver<OutboundItem>,
    client: Arc<TorClient<PreferredRuntime>>,
) {
    while let Some((addr, payload, confirm_tx)) = send_rx.recv().await {
        let c = Arc::clone(&client);
        tokio::spawn(async move {
            let ok = match c.connect(addr.as_str()).await {
                Ok(mut stream) => {
                    if let Err(e) = write_frame(&mut stream, &payload).await {
                        log::warn!("outbound write failed: {e}");
                        false
                    } else {
                        true
                    }
                }
                Err(e) => {
                    log::warn!("outbound connect failed: {e}");
                    false
                }
            };
            if let Some(tx) = confirm_tx {
                let _ = tx.send(ok);
            }
        });
    }
}

/// Send Poisson-distributed dummy messages for cover traffic.
/// Randomly targets self or a known contact address.
async fn cover_traffic_loop(
    own_address: String,
    send_tx: mpsc::Sender<OutboundItem>,
    contact_addrs: Arc<Mutex<Vec<String>>>,
) {
    use rand::{Rng, SeedableRng};
    let mut rng = rand::rngs::StdRng::from_entropy();
    loop {
        let interval_secs = sample_exponential(COVER_MEAN_SECS);
        tokio::time::sleep(Duration::from_secs_f64(interval_secs)).await;

        let target = {
            let contacts = contact_addrs.lock().ok();
            let has_contacts = contacts.as_ref().is_some_and(|c| !c.is_empty());
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

/// Sample one inter-arrival time from `Exp(1/mean_secs)` via inversion.
fn sample_exponential(mean_secs: f64) -> f64 {
    use rand::Rng;
    let u: f64 = rand::thread_rng().gen_range(f64::EPSILON..1.0_f64);
    -mean_secs * u.ln()
}
