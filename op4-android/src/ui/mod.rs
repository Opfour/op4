mod contacts;
mod conversation;
mod duress;
mod passphrase;
mod qr;
mod settings;

use std::sync::Arc;
use std::time::Duration;

use eframe::egui;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use op4_core::crypto::handshake::{perform_handshake_alice, perform_handshake_bob};
use op4_core::crypto::hmac_auth::{compute_message_mac, verify_message_mac, MessageMac};
use op4_core::crypto::keys::{HybridKemKeypair, HybridSigningKeypair, PublicKeyBundle};
use op4_core::crypto::primitives::MacKey;
use op4_core::crypto::ratchet::{MessageHeader, RatchetState};
use op4_core::identity::profile::{BootstrapCode, ContactCode};
use op4_core::identity::revocation::{RevocationCertificate, RevocationReason};
use op4_core::network::message::{WireMessage, WireMessageType};
use op4_core::network::Transport;
use op4_core::storage::vault::{StoredMessage, VaultUnlocked};

use crate::transport::ArtiTransport;

/// Maximum pending inbound handshakes (same as TUI).
const MAX_PENDING_HANDSHAKES: usize = 10;

// ─── Screen / Tab enums ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Screen {
    Passphrase,
    Main,
    Duress,
    KeyAlert,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Tab {
    Contacts,
    Conversation,
    Settings,
}

#[derive(Debug, Clone, PartialEq)]
enum ContactMode {
    List,
    Fingerprint,
    AddContact,
    ExportCode,
    PendingRequest,
}

#[derive(Debug, Clone, PartialEq)]
enum SettingsEditMode {
    None,
    EditAutoDelete,
    ConfirmRotate,
    ConfirmRevoke,
}

/// Completed handshake from an unknown contact awaiting user acceptance.
struct PendingHandshake {
    bundle: PublicKeyBundle,
    plaintext: Zeroizing<Vec<u8>>,
    session_key_bytes: Zeroizing<[u8; 32]>,
}

// ─── App State ───────────────────────────────────────────────────────────────

pub struct Op4App {
    screen: Screen,
    tab: Tab,
    // Auth
    passphrase_buf: String,
    duress_buf: String,
    is_new_vault: bool,
    vault_path: std::path::PathBuf,
    auth_error: String,
    // Core state (populated after unlock)
    vault: Option<VaultUnlocked>,
    transport: Option<ArtiTransport>,
    tokio_rt: Arc<tokio::runtime::Runtime>,
    data_dir: std::path::PathBuf,
    cache_dir: std::path::PathBuf,
    transport_pending: Option<std::sync::mpsc::Receiver<Result<ArtiTransport, String>>>,
    // Contacts
    selected_contact: usize,
    contact_mode: ContactMode,
    add_contact_buf: String,
    pending_handshakes: Vec<PendingHandshake>,
    pending_name_buf: String,
    export_code: String,
    bootstrap_code: String,
    // Conversation
    draft: String,
    messages: Vec<StoredMessage>,
    loaded_contact_idx: Option<usize>,
    search_query: String,
    search_active: bool,
    // Settings
    settings_edit: SettingsEditMode,
    edit_buf: String,
    // Status
    status: String,
    // QR texture (cached)
    qr_texture: Option<egui::TextureHandle>,
}

impl Op4App {
    pub fn new(
        vault_path: std::path::PathBuf,
        data_dir: std::path::PathBuf,
        cache_dir: std::path::PathBuf,
    ) -> Self {
        let is_new = !vault_path.exists();
        let tokio_rt = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("failed to create tokio runtime"),
        );
        Self {
            screen: Screen::Passphrase,
            tab: Tab::Contacts,
            passphrase_buf: String::new(),
            duress_buf: String::new(),
            is_new_vault: is_new,
            vault_path,
            auth_error: String::new(),
            vault: None,
            transport: None,
            tokio_rt,
            data_dir,
            cache_dir,
            transport_pending: None,
            selected_contact: 0,
            contact_mode: ContactMode::List,
            add_contact_buf: String::new(),
            pending_handshakes: Vec::new(),
            pending_name_buf: String::new(),
            export_code: String::new(),
            bootstrap_code: String::new(),
            draft: String::new(),
            messages: Vec::new(),
            loaded_contact_idx: None,
            search_query: String::new(),
            search_active: false,
            settings_edit: SettingsEditMode::None,
            edit_buf: String::new(),
            status: String::new(),
            qr_texture: None,
        }
    }

    /// Rebuild export and bootstrap codes from vault key material.
    fn refresh_codes(&mut self) {
        if let Some(ref vault) = self.vault {
            if let Some(bundle) = build_our_bundle(vault) {
                self.export_code = ContactCode(bundle.clone()).encode();
                self.bootstrap_code = BootstrapCode::from_bundle(&bundle).encode();
                self.qr_texture = None; // force regeneration
            }
        }
    }

    /// Reload messages for the currently selected contact.
    fn reload_messages(&mut self) {
        if let Some(ref mut vault) = self.vault {
            if let Some(contact) = vault.payload.contacts.get(self.selected_contact) {
                self.messages = vault.load_messages(&contact.id);
                // Clear unread badge
                if let Some(conv_idx) = vault.find_conversation_by_contact(&contact.id) {
                    if vault.payload.conversations[conv_idx].unread_count > 0 {
                        vault.payload.conversations[conv_idx].unread_count = 0;
                        vault.save().ok();
                    }
                }
                self.loaded_contact_idx = Some(self.selected_contact);
            }
        }
    }

    /// Derive a stable service nickname from the vault's identity secrets
    /// and bootstrap the arti transport on the tokio runtime.
    fn start_transport(&mut self) {
        let vault = match self.vault.as_ref() {
            Some(v) => v,
            None => return,
        };

        // Derive a deterministic service nickname from identity KEM secret
        // so the same vault always produces the same onion address.
        let nickname = {
            let hk = Hkdf::<Sha256>::new(None, &vault.payload.identity_kem_secret);
            let mut okm = [0u8; 16];
            hk.expand(b"op4-onion-nickname", &mut okm)
                .expect("16 bytes is valid");
            // arti nicknames must be [a-z0-9_], 1-64 chars
            let hex: String = okm.iter().map(|b| format!("{b:02x}")).collect();
            format!("op4_{hex}")
        };

        let data_dir = self.data_dir.clone();
        let cache_dir = self.cache_dir.clone();
        let rt = Arc::clone(&self.tokio_rt);

        self.status = "Connecting to Tor network...".into();

        // Spawn transport init on a background thread so the UI stays responsive.
        // When it completes, we store the result via a channel.
        let (tx, rx) = std::sync::mpsc::channel::<Result<ArtiTransport, String>>();

        std::thread::spawn(move || {
            let result = rt.block_on(async {
                ArtiTransport::init(&data_dir, &cache_dir, &nickname)
                    .await
                    .map_err(|e| format!("{e:?}"))
            });
            let _ = tx.send(result);
        });

        // Store the receiver so we can poll it in update()
        self.transport_pending = Some(rx);
    }
}

impl eframe::App for Op4App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Check if async transport init has completed
        if let Some(ref rx) = self.transport_pending {
            if let Ok(result) = rx.try_recv() {
                match result {
                    Ok(transport) => {
                        // Set the nym_address so contacts know our onion addr
                        if let Some(ref mut vault) = self.vault {
                            vault.payload.nym_address = transport.address().to_owned();
                            vault.save().ok();
                        }
                        self.status = format!("Connected: {}", transport.address());
                        self.transport = Some(transport);
                        self.refresh_codes();
                    }
                    Err(e) => {
                        self.status = format!("Tor connection failed: {e}");
                    }
                }
                self.transport_pending = None;
            }
        }

        // Poll transport for inbound messages (non-blocking)
        // Collect first to avoid double mutable borrow of self.
        let mut incoming_payloads = Vec::new();
        if let Some(ref mut transport) = self.transport {
            while let Some(incoming) = transport.try_recv_msg() {
                incoming_payloads.push(incoming.payload);
            }
        }
        for payload in &incoming_payloads {
            handle_incoming_message(self, payload);
        }

        // Reload messages if selected contact changed
        if self.screen == Screen::Main && self.tab == Tab::Conversation {
            if Some(self.selected_contact) != self.loaded_contact_idx {
                self.reload_messages();
            }
        }

        // Touch-friendly spacing
        let mut style = (*ctx.style()).clone();
        style.spacing.item_spacing = egui::vec2(8.0, 10.0);
        style.spacing.button_padding = egui::vec2(16.0, 10.0);
        ctx.set_style(style);

        match self.screen.clone() {
            Screen::Passphrase => passphrase::show(self, ctx),
            Screen::Main => {
                self.show_main(ctx);
            }
            Screen::Duress => duress::show(ctx),
            Screen::KeyAlert => {
                // Handled inside contacts when key_alert data is present
                self.show_main(ctx);
            }
        }

        // Request repaint to poll for new messages
        ctx.request_repaint_after(Duration::from_millis(100));
    }
}

impl Op4App {
    fn show_main(&mut self, ctx: &egui::Context) {
        // Top panel: tab bar
        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("op4");
                ui.separator();

                let pending = self.pending_handshakes.len();
                let contacts_label = if pending > 0 {
                    format!("Contacts ({pending})")
                } else {
                    "Contacts".into()
                };

                let total_unread: u32 = self
                    .vault
                    .as_ref()
                    .map(|v| v.payload.conversations.iter().map(|c| c.unread_count).sum())
                    .unwrap_or(0);
                let messages_label = if total_unread > 0 {
                    format!("Messages ({total_unread})")
                } else {
                    "Messages".into()
                };

                if ui
                    .selectable_label(self.tab == Tab::Contacts, contacts_label)
                    .clicked()
                {
                    self.tab = Tab::Contacts;
                }
                if ui
                    .selectable_label(self.tab == Tab::Conversation, messages_label)
                    .clicked()
                {
                    self.tab = Tab::Conversation;
                    self.reload_messages();
                }
                if ui
                    .selectable_label(self.tab == Tab::Settings, "Settings")
                    .clicked()
                {
                    self.tab = Tab::Settings;
                }
            });
        });

        // Bottom panel: status bar
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.label(&self.status);
        });

        // Central panel: active tab content
        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Contacts => contacts::show(self, ui),
            Tab::Conversation => conversation::show(self, ui),
            Tab::Settings => settings::show(self, ui),
        });
    }
}

// ─── Shared helpers (same logic as TUI app.rs) ───────────────────────────────

fn build_our_bundle(vault: &VaultUnlocked) -> Option<PublicKeyBundle> {
    if vault.payload.identity_kem_secret.is_empty()
        || vault.payload.identity_signing_secret.is_empty()
    {
        return None;
    }
    let kem = HybridKemKeypair::from_bytes(&vault.payload.identity_kem_secret).ok()?;
    let signing =
        HybridSigningKeypair::from_bytes(&vault.payload.identity_signing_secret).ok()?;
    let ratchet_pub = if vault.payload.identity_ratchet_secret.len() == 32 {
        let bytes: [u8; 32] = vault.payload.identity_ratchet_secret[..32]
            .try_into()
            .ok()?;
        x25519_dalek::PublicKey::from(&StaticSecret::from(bytes)).to_bytes()
    } else {
        kem.x25519_public.to_bytes()
    };
    Some(PublicKeyBundle::from_keypairs(
        &kem,
        &signing,
        ratchet_pub,
        vault.payload.nym_address.clone(),
    ))
}

fn load_ratchet_secret(vault: &VaultUnlocked) -> Option<StaticSecret> {
    if vault.payload.identity_ratchet_secret.len() == 32 {
        let bytes: [u8; 32] = vault.payload.identity_ratchet_secret[..32]
            .try_into()
            .ok()?;
        Some(StaticSecret::from(bytes))
    } else if vault.payload.identity_kem_secret.len() >= 32 {
        let kem = HybridKemKeypair::from_bytes(&vault.payload.identity_kem_secret).ok()?;
        let bytes = kem.x25519_secret.to_bytes();
        Some(StaticSecret::from(bytes))
    } else {
        None
    }
}

/// Sanitize text for display (strip control chars).
fn sanitize(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .collect()
}

// ─── Send Path ───────────────────────────────────────────────────────────────

fn send_message(app: &mut Op4App, plaintext: &[u8]) {
    let vault = match app.vault.as_mut() {
        Some(v) => v,
        None => return,
    };
    let contact = match vault.payload.contacts.get(app.selected_contact).cloned() {
        Some(c) => c,
        None => {
            app.status = "No contact selected.".into();
            return;
        }
    };
    let contact_id = contact.id;
    let contact_addr = contact.bundle.nym_address.clone();

    if contact_addr.is_empty() {
        app.status = "Contact has no address.".into();
        return;
    }

    let our_kem = match HybridKemKeypair::from_bytes(&vault.payload.identity_kem_secret) {
        Ok(k) => k,
        Err(_) => {
            app.status = "Key error.".into();
            return;
        }
    };

    let conv_key = vault.derive_conversation_key(&contact_id);
    let has_ratchet = vault
        .find_conversation_by_contact(&contact_id)
        .map(|i| !vault.payload.conversations[i].ratchet_state_ct.is_empty())
        .unwrap_or(false);

    let wire_payload: Vec<u8>;

    if has_ratchet {
        let conv_idx = vault.find_conversation_by_contact(&contact_id).unwrap();
        let ratchet_ct = vault.payload.conversations[conv_idx]
            .ratchet_state_ct
            .clone();

        let mut ratchet = match RatchetState::from_encrypted_bytes(&conv_key, &ratchet_ct) {
            Ok(r) => r,
            Err(_) => {
                app.status = "Failed to load ratchet.".into();
                return;
            }
        };
        let (header, ct, mac_key_bytes) = match ratchet.ratchet_encrypt(plaintext) {
            Ok(r) => r,
            Err(_) => {
                app.status = "Encryption failed.".into();
                return;
            }
        };

        let mac = compute_message_mac(&MacKey(mac_key_bytes), &contact_id, header.n, &ct);

        let wire = WireMessage {
            msg_type: WireMessageType::Data,
            header,
            ciphertext: ct,
            mac,
        }
        .with_padding();
        wire_payload = wire.to_bytes().expect("serialization cannot fail");

        if let Ok(new_ct) = ratchet.to_encrypted_bytes(&conv_key) {
            vault.payload.conversations[conv_idx].ratchet_state_ct = new_ct;
        }
    } else {
        let our_signing =
            match HybridSigningKeypair::from_bytes(&vault.payload.identity_signing_secret) {
                Ok(s) => s,
                Err(_) => {
                    app.status = "Key error.".into();
                    return;
                }
            };

        let our_ratchet_pub = if vault.payload.identity_ratchet_secret.len() == 32 {
            let bytes: [u8; 32] = vault.payload.identity_ratchet_secret[..32]
                .try_into()
                .unwrap();
            x25519_dalek::PublicKey::from(&StaticSecret::from(bytes)).to_bytes()
        } else {
            our_kem.x25519_public.to_bytes()
        };

        let (hs_msg, session_key) = match perform_handshake_alice(
            &our_kem,
            &our_signing,
            our_ratchet_pub,
            vault.payload.nym_address.clone(),
            &contact.bundle,
            plaintext,
        ) {
            Ok(r) => r,
            Err(_) => {
                app.status = "Handshake failed.".into();
                return;
            }
        };

        let bob_ratchet_pub = if contact.bundle.ratchet_pub != [0u8; 32] {
            X25519PublicKey::from(contact.bundle.ratchet_pub)
        } else {
            X25519PublicKey::from(contact.bundle.x25519_pub)
        };
        let ratchet = match RatchetState::init_alice(session_key.0, bob_ratchet_pub) {
            Ok(r) => r,
            Err(_) => {
                app.status = "Ratchet init failed.".into();
                return;
            }
        };

        if let Ok(ratchet_ct) = ratchet.to_encrypted_bytes(&conv_key) {
            let conv = vault.get_or_create_conversation(contact_id);
            conv.ratchet_state_ct = ratchet_ct;
        }

        let hs_bytes = postcard::to_allocvec(&hs_msg).expect("serialization cannot fail");
        let wire = WireMessage {
            msg_type: WireMessageType::Handshake,
            header: MessageHeader {
                dh_pub: [0u8; 32],
                pn: 0,
                n: 0,
            },
            ciphertext: hs_bytes,
            mac: MessageMac { tag: [0u8; 32] },
        };
        wire_payload = wire.to_bytes().expect("serialization cannot fail");
    }

    if let Some(ref transport) = app.transport {
        match transport.send(&contact_addr, wire_payload) {
            Ok(()) => {
                let text = sanitize(&String::from_utf8_lossy(plaintext));
                let mut msgs = vault.load_messages(&contact_id);
                let counter = msgs.len() as u64 + 1;
                msgs.push(StoredMessage {
                    counter,
                    content: text,
                    from_us: true,
                });
                vault.save_messages(&contact_id, &msgs).ok();
                app.messages = msgs;
                app.status = "Message sent.".into();
                vault.save().ok();
            }
            Err(e) => {
                app.status = format!("Send failed: {e:?}");
            }
        }
    }
}

// ─── Receive Path ────────────────────────────────────────────────────────────

fn handle_incoming_message(app: &mut Op4App, payload: &[u8]) {
    let wire = match WireMessage::from_bytes(payload) {
        Some(w) => w,
        None => return,
    };

    match wire.msg_type {
        WireMessageType::Dummy | WireMessageType::Loop => {}
        WireMessageType::Handshake => {
            handle_inbound_handshake(app, &wire.ciphertext);
        }
        WireMessageType::Data => {
            handle_inbound_data(app, &wire.header, &wire.ciphertext, &wire.mac);
        }
        WireMessageType::Revocation => {
            handle_inbound_revocation(app, &wire.ciphertext);
        }
        _ => {}
    }
}

fn handle_inbound_handshake(app: &mut Op4App, hs_bytes: &[u8]) {
    if app.pending_handshakes.len() >= MAX_PENDING_HANDSHAKES {
        return;
    }
    let vault = match app.vault.as_ref() {
        Some(v) => v,
        None => return,
    };
    let bob_kem = match HybridKemKeypair::from_bytes(&vault.payload.identity_kem_secret) {
        Ok(k) => k,
        Err(_) => return,
    };
    let bob_ratchet_secret = match load_ratchet_secret(vault) {
        Some(s) => s,
        None => return,
    };
    let hs_msg: op4_core::crypto::handshake::HandshakeInitMessage =
        match postcard::from_bytes(hs_bytes) {
            Ok(m) => m,
            Err(_) => return,
        };
    let (plaintext, session_key) =
        match perform_handshake_bob(&bob_kem, &bob_ratchet_secret, &hs_msg) {
            Ok(r) => r,
            Err(_) => return,
        };

    app.pending_handshakes.push(PendingHandshake {
        bundle: hs_msg.alice_identity,
        plaintext: Zeroizing::new(plaintext),
        session_key_bytes: Zeroizing::new(session_key.0),
    });
    app.status = format!(
        "{} pending contact request(s)",
        app.pending_handshakes.len()
    );
}

fn handle_inbound_data(
    app: &mut Op4App,
    header: &MessageHeader,
    ciphertext: &[u8],
    mac: &MessageMac,
) {
    let vault = match app.vault.as_mut() {
        Some(v) => v,
        None => return,
    };

    // Find which contact sent this by trying each ratchet
    for (idx, contact) in vault.payload.contacts.iter().enumerate() {
        let contact_id = contact.id;
        let conv_key = vault.derive_conversation_key(&contact_id);

        let conv_idx = match vault.find_conversation_by_contact(&contact_id) {
            Some(i) => i,
            None => continue,
        };
        if vault.payload.conversations[conv_idx]
            .ratchet_state_ct
            .is_empty()
        {
            continue;
        }

        let ratchet_ct = vault.payload.conversations[conv_idx]
            .ratchet_state_ct
            .clone();
        let mut ratchet = match RatchetState::from_encrypted_bytes(&conv_key, &ratchet_ct) {
            Ok(r) => r,
            Err(_) => continue,
        };

        let (plaintext, mac_key_bytes) = match ratchet.ratchet_decrypt(header, ciphertext) {
            Ok(r) => r,
            Err(_) => continue,
        };

        // Verify HMAC
        if !verify_message_mac(
            &MacKey(mac_key_bytes),
            &contact_id,
            header.n,
            ciphertext,
            mac,
        ) {
            continue;
        }

        // Persist ratchet
        if let Ok(new_ct) = ratchet.to_encrypted_bytes(&conv_key) {
            vault.payload.conversations[conv_idx].ratchet_state_ct = new_ct;
        }

        // Store message
        let text = sanitize(&String::from_utf8_lossy(&plaintext));
        let mut msgs = vault.load_messages(&contact_id);
        let counter = msgs.len() as u64 + 1;
        msgs.push(StoredMessage {
            counter,
            content: text,
            from_us: false,
        });
        vault.save_messages(&contact_id, &msgs).ok();

        // Update unread count
        vault.payload.conversations[conv_idx].unread_count += 1;

        // If this is the currently viewed conversation, refresh
        if Some(idx) == app.loaded_contact_idx {
            app.messages = msgs;
        }

        vault.save().ok();
        return;
    }
}

fn handle_inbound_revocation(app: &mut Op4App, cert_bytes: &[u8]) {
    let cert: RevocationCertificate = match postcard::from_bytes(cert_bytes) {
        Ok(c) => c,
        Err(_) => return,
    };
    let vault = match app.vault.as_mut() {
        Some(v) => v,
        None => return,
    };

    for contact in vault.payload.contacts.iter_mut() {
        if cert.verify(&contact.bundle).is_ok() {
            match cert.reason {
                RevocationReason::Rotation => {
                    let name = contact.display_name.clone();
                    contact.verified = false;
                    app.status = format!("Key rotated for '{name}' — re-verify fingerprint.");
                    app.screen = Screen::KeyAlert;
                }
                RevocationReason::Retirement | RevocationReason::Compromised => {
                    let name = contact.display_name.clone();
                    app.status = format!("'{name}' has retired their key.");
                }
            }
            vault.save().ok();
            return;
        }
    }
}
