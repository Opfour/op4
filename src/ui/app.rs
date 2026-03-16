use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use ratatui::widgets::ListState;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Tabs},
    Frame, Terminal,
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::crypto::handshake::{
    perform_handshake_alice, perform_handshake_bob, HandshakeInitMessage,
};
use crate::crypto::hmac_auth::{compute_message_mac, verify_message_mac, MessageMac};
use crate::crypto::keys::{HybridKemKeypair, HybridSigningKeypair, PublicKeyBundle};
use crate::crypto::primitives::{aead_decrypt, aead_encrypt, hkdf_expand, MacKey, SymKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;
use crate::crypto::ratchet::{MessageHeader, RatchetState};
use crate::identity::profile::{BootstrapCode, ContactCode, StoredContact};
use crate::identity::revocation::{RevocationCertificate, RevocationReason};
use rand::rngs::OsRng;
use crate::network::message::{WireMessage, WireMessageType};
use crate::network::nym_client::NymClient;
use crate::storage::vault::{StoredMessage, VaultUnlocked};
use crate::ui::{
    contacts::{render_contacts, render_fingerprint_panel, render_key_change_alert},
    conversation::render_conversation,
    duress::render_duress_inbox,
    input::sanitize_for_display,
    qr::{qr_lines, qr_terminal_height, qr_terminal_width},
    settings::render_settings,
};

// ─── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of inbound handshakes queued for user review.
/// Each entry requires an ML-KEM decapsulation (expensive); capping prevents
/// memory exhaustion and CPU amplification from a handshake-flood DoS.
const MAX_PENDING_HANDSHAKES: usize = 10;

// ─── State Types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Tab {
    Contacts,
    Conversation,
    Settings,
}

/// Sub-mode within the Contacts tab.
#[derive(Debug, Clone, PartialEq)]
enum ContactMode {
    List,
    Fingerprint,
    AddContact,
    ExportCode,
    KeyAlert,
    /// Reviewing an inbound contact request from an unknown party.
    PendingRequest,
}

/// Edit/confirmation mode within the Settings tab.
#[derive(Debug, Clone, PartialEq)]
enum SettingsEditMode {
    None,
    EditTorAddr,
    EditAutoDelete,
    ConfirmRotate,
    ConfirmRevoke,
}

/// A completed handshake from an unknown contact awaiting user acceptance.
/// Crypto work is already done; we just need the user to assign a name.
///
/// Both `plaintext` and `session_key_bytes` are wrapped in `Zeroizing` so
/// their bytes are overwritten when the entry is accepted, rejected, or evicted
/// from the queue.
struct PendingHandshake {
    bundle: PublicKeyBundle,
    plaintext: Zeroizing<Vec<u8>>,
    session_key_bytes: Zeroizing<[u8; 32]>,
}

/// Tracks an outstanding BundleRequest we sent after scanning a bootstrap QR.
/// When the peer replies, we match on `ed25519_vk` and verify `fingerprint_prefix`.
struct BootstrapPending {
    ed25519_vk: [u8; 32],
    fingerprint_prefix: [u8; 32],
}

/// Encrypted bundle request payload. Seals the requester's return address and
/// X25519 public key with ephemeral ECDH so Tor relays cannot learn the social graph.
#[derive(Serialize, Deserialize)]
struct SealedBundleRequest {
    ephemeral_pub: [u8; 32],
    ciphertext: Vec<u8>,
}

/// Inner plaintext of an encrypted `BundleRequest`.
#[derive(Serialize, Deserialize)]
struct BundleRequestInner {
    requester_addr: String,
    requester_x25519_pub: [u8; 32],
}

/// Encrypted bundle response payload. Sealed with the requester's X25519 public key.
#[derive(Serialize, Deserialize)]
struct SealedBundleResponse {
    ephemeral_pub: [u8; 32],
    ciphertext: Vec<u8>,
}

struct AppState {
    running: bool,
    tab: Tab,
    // Contacts
    contacts_list: ListState,
    contact_mode: ContactMode,
    add_buf: String,
    export_code: String,
    /// Compact bootstrap code (~170 chars) shown as a QR in the export popup.
    bootstrap_code: String,
    key_alert: Option<(String, String)>, // (contact_name, new_fingerprint)
    // Pending inbound contact requests
    pending_handshakes: Vec<PendingHandshake>,
    pending_name_buf: String,
    // Pending outbound bundle requests (bootstrap QR flow)
    pending_bundle_requests: Vec<BootstrapPending>,
    // Conversation
    draft: String,
    messages: Vec<StoredMessage>,
    active_contact_idx: Option<usize>,
    /// Tracks which contact's messages are currently loaded in `messages`.
    loaded_contact_idx: Option<usize>,
    /// When true, keyboard input goes to `search_query` instead of `draft`.
    search_active: bool,
    /// Filter string for message search; empty = show all messages.
    search_query: String,
    // Settings
    settings_list: ListState,
    settings_edit_mode: SettingsEditMode,
    settings_edit_buf: String,
    // Status bar
    status: String,
}

impl AppState {
    fn new(export_code: String, bootstrap_code: String) -> Self {
        let mut contacts_list = ListState::default();
        contacts_list.select(Some(0));
        let mut settings_list = ListState::default();
        settings_list.select(Some(0));
        Self {
            running: true,
            tab: Tab::Contacts,
            contacts_list,
            contact_mode: ContactMode::List,
            add_buf: String::new(),
            export_code,
            bootstrap_code,
            key_alert: None,
            pending_handshakes: Vec::new(),
            pending_name_buf: String::new(),
            pending_bundle_requests: Vec::new(),
            draft: String::new(),
            messages: Vec::new(),
            active_contact_idx: None,
            loaded_contact_idx: None,
            search_active: false,
            search_query: String::new(),
            settings_list,
            settings_edit_mode: SettingsEditMode::None,
            settings_edit_buf: String::new(),
            status: contacts_help(0),
        }
    }
}

fn contacts_help(pending: usize) -> String {
    if pending > 0 {
        format!(
            "Tab:switch  ↑↓:nav  a:add  e:export  v:verify  d:delete  p:pending({pending})  q:quit"
        )
    } else {
        "Tab:switch  ↑↓:navigate  a:add-contact  e:export-code  v:verify  d:delete  Enter:view  q:quit".into()
    }
}

// ─── Public Entry Points ──────────────────────────────────────────────────────

/// Run the main TUI event loop. Blocks until the user quits.
/// Call from within `tokio::task::block_in_place` so the async runtime
/// can schedule other tasks on other threads while the TUI runs.
pub fn run<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    mut vault: VaultUnlocked,
    nym: &mut NymClient,
) -> crate::error::Result<()> {
    if vault.is_duress {
        return run_duress(terminal);
    }

    let export_code = build_export_code(&vault);
    let bootstrap_code = build_bootstrap_code(&vault);
    let mut app = AppState::new(export_code, bootstrap_code);

    loop {
        // Reload messages if the active contact changed.
        let current_contact = app
            .active_contact_idx
            .or_else(|| app.contacts_list.selected());
        if current_contact != app.loaded_contact_idx {
            if let Some(idx) = current_contact {
                if let Some(contact) = vault.payload.contacts.get(idx) {
                    app.messages = vault.load_messages(&contact.id);
                    // Clear unread badge when the conversation is opened.
                    if let Some(conv_idx) = vault.find_conversation_by_contact(&contact.id) {
                        if vault.payload.conversations[conv_idx].unread_count > 0 {
                            vault.payload.conversations[conv_idx].unread_count = 0;
                            vault.save().ok();
                        }
                    }
                } else {
                    app.messages.clear();
                }
            } else {
                app.messages.clear();
            }
            app.loaded_contact_idx = current_contact;
        }

        terminal
            .draw(|f| draw(f, &mut app, &vault))
            .map_err(|e| crate::error::AppError::Io(std::io::Error::other(e.to_string())))?;

        // Poll for keyboard input with a short timeout.
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                handle_key(&mut app, key, &mut vault, nym);
            }
        }

        // Non-blocking poll for inbound messages.
        while let Some(incoming) = nym.try_recv_msg() {
            handle_incoming_message(&mut app, &mut vault, nym, &incoming.payload);
        }

        if !app.running {
            break;
        }
    }

    vault.save().ok();
    Ok(())
}

/// Reconstruct our full `PublicKeyBundle` from vault key material.
/// Returns `None` when the vault lacks identity keys (first-run not complete).
fn build_our_bundle(vault: &VaultUnlocked) -> Option<PublicKeyBundle> {
    if vault.payload.identity_kem_secret.is_empty()
        || vault.payload.identity_signing_secret.is_empty()
    {
        return None;
    }
    let kem = HybridKemKeypair::from_bytes(&vault.payload.identity_kem_secret).ok()?;
    let signing = HybridSigningKeypair::from_bytes(&vault.payload.identity_signing_secret).ok()?;
    let ratchet_pub = if vault.payload.identity_ratchet_secret.len() == 32 {
        let bytes: [u8; 32] = vault.payload.identity_ratchet_secret[..32].try_into().ok()?;
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

/// Build the full contact code (base58, ~4400 chars) for manual sharing.
fn build_export_code(vault: &VaultUnlocked) -> String {
    match build_our_bundle(vault) {
        Some(bundle) => ContactCode(bundle).encode(),
        None => "[No identity keys — restart op4 to complete first-run setup]".into(),
    }
}

/// Build the compact bootstrap code (base58, ~170 chars) that fits in a QR code.
fn build_bootstrap_code(vault: &VaultUnlocked) -> String {
    match build_our_bundle(vault) {
        Some(bundle) => BootstrapCode::from_bundle(&bundle).encode(),
        None => "[No identity keys]".into(),
    }
}

/// Duress mode: visually identical TUI showing only decoy content.
fn run_duress<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
) -> crate::error::Result<()> {
    loop {
        terminal
            .draw(|f| {
                let area = f.area();
                render_duress_inbox(f, area);
            })
            .map_err(|e| crate::error::AppError::Io(std::io::Error::other(e.to_string())))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') => break,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

// ─── Rendering ────────────────────────────────────────────────────────────────

fn draw(f: &mut Frame, app: &mut AppState, vault: &VaultUnlocked) {
    let area = f.area();

    // Check for key change alert — renders over everything else.
    if app.contact_mode == ContactMode::KeyAlert {
        if let Some((ref name, ref fp)) = app.key_alert.clone() {
            render_key_change_alert(f, name, fp);
            return;
        }
    }

    // Layout: tab bar [3] | content [fill] | status bar [1]
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    draw_tabs(f, app, vault, chunks[0]);

    match app.tab {
        Tab::Contacts => draw_contacts(f, app, vault, chunks[1]),
        Tab::Conversation => draw_conversation(f, app, vault, chunks[1]),
        Tab::Settings => {
            render_settings(
                f,
                &vault.payload.settings,
                &mut app.settings_list,
                chunks[1],
            );
            if app.settings_edit_mode != SettingsEditMode::None {
                draw_settings_edit_popup(f, app, chunks[1]);
            }
        }
    }

    let status = Paragraph::new(app.status.as_str()).style(Style::default().fg(Color::DarkGray));
    f.render_widget(status, chunks[2]);
}

fn draw_tabs(f: &mut Frame, app: &AppState, vault: &VaultUnlocked, area: Rect) {
    let pending = app.pending_handshakes.len();
    let contacts_label = if pending > 0 {
        format!("Contacts [1] ({pending})")
    } else {
        "Contacts [1]".into()
    };
    let total_unread: u32 = vault
        .payload
        .conversations
        .iter()
        .map(|c| c.unread_count)
        .sum();
    let messages_label = if total_unread > 0 {
        format!("Messages [2] ({total_unread})")
    } else {
        "Messages [2]".into()
    };
    let titles = vec![
        Line::from(Span::raw(contacts_label)),
        Line::from(Span::raw(messages_label)),
        Line::from(Span::raw("Settings [3]")),
    ];
    let idx = match app.tab {
        Tab::Contacts => 0,
        Tab::Conversation => 1,
        Tab::Settings => 2,
    };
    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).title("op4"))
        .select(idx)
        .style(Style::default().fg(Color::White))
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(tabs, area);
}

fn draw_contacts(f: &mut Frame, app: &mut AppState, vault: &VaultUnlocked, area: Rect) {
    if app.contact_mode == ContactMode::AddContact {
        draw_add_contact_popup(f, app, area);
        return;
    }
    if app.contact_mode == ContactMode::ExportCode {
        draw_export_code_popup(f, app, area);
        return;
    }
    if app.contact_mode == ContactMode::PendingRequest {
        draw_pending_request_popup(f, app, area);
        return;
    }

    if vault.payload.contacts.is_empty() {
        let pending = app.pending_handshakes.len();
        let msg = if pending > 0 {
            format!(
                "No contacts yet.\n\n\
                 [a]  Add a contact using their contact code\n\
                 [e]  Show your contact code to share with others\n\
                 [p]  Review {pending} pending contact request(s)"
            )
        } else {
            "No contacts yet.\n\n\
             [a]  Add a contact using their contact code\n\
             [e]  Show your contact code to share with others"
                .into()
        };
        let help =
            Paragraph::new(msg).block(Block::default().borders(Borders::ALL).title("Contacts"));
        f.render_widget(help, area);
        return;
    }

    // Split: contact list | detail panel
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(area);

    let unread_counts: Vec<u32> = vault
        .payload
        .contacts
        .iter()
        .map(|c| {
            vault
                .find_conversation_by_contact(&c.id)
                .map(|i| vault.payload.conversations[i].unread_count)
                .unwrap_or(0)
        })
        .collect();
    render_contacts(
        f,
        &vault.payload.contacts,
        &unread_counts,
        &mut app.contacts_list,
        chunks[0],
    );

    if let Some(idx) = app.contacts_list.selected() {
        if let Some(contact) = vault.payload.contacts.get(idx) {
            render_fingerprint_panel(f, contact, chunks[1]);
        }
    }
}

fn draw_add_contact_popup(f: &mut Frame, app: &AppState, area: Rect) {
    let popup = centered_rect(70, 12, area);
    f.render_widget(Clear, popup);
    let content = Paragraph::new(vec![
        Line::from("Paste the contact's contact code below, then press Enter."),
        Line::from("Press Esc to cancel."),
        Line::from(""),
        Line::from(Span::styled(
            app.add_buf.as_str(),
            Style::default().fg(Color::Yellow),
        )),
    ])
    .block(Block::default().borders(Borders::ALL).title("Add Contact"));
    f.render_widget(content, popup);
}

fn draw_export_code_popup(f: &mut Frame, app: &AppState, area: Rect) {
    // Use nearly the full terminal area so the QR has room.
    let popup = centered_rect(96, 96, area);
    f.render_widget(Clear, popup);

    // Inner area (inside the outer border).
    let qr_w = qr_terminal_width(&app.bootstrap_code);
    let qr_h = qr_terminal_height(&app.bootstrap_code);

    // Only show the QR if it fits horizontally and the popup is tall enough.
    let inner_w = popup.width.saturating_sub(2); // subtract border
    let inner_h = popup.height.saturating_sub(2);
    let qr_fits = qr_w > 0 && qr_w <= inner_w && qr_h + 8 <= inner_h;

    if qr_fits {
        // ── Layout: [outer border] / qr / separator / bootstrap text / full code ──

        // Outer block (title + border only — we render content manually inside).
        let outer = Block::default()
            .borders(Borders::ALL)
            .title(" Your Contact Code (Esc to close) ");
        let inner = outer.inner(popup);
        f.render_widget(outer, popup);

        // Split inner area: QR rows | 1 blank | 2 bootstrap text | 1 blank | remaining full code
        let qr_rows = qr_h;
        let constraints = vec![
            Constraint::Length(qr_rows),
            Constraint::Length(1), // spacer
            Constraint::Length(3), // bootstrap code label + value
            Constraint::Length(1), // spacer
            Constraint::Min(3),    // full code
        ];
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(constraints)
            .split(inner);

        // QR code — rendered as a sequence of coloured spans.
        let lines = qr_lines(&app.bootstrap_code);
        let qr_para = Paragraph::new(ratatui::text::Text::from(lines));
        f.render_widget(qr_para, chunks[0]);

        // Bootstrap code (short — fits in a QR code, can be scanned or copy-pasted).
        let bc_text = format!(
            "Bootstrap code (scan QR or share this text):\n{}",
            app.bootstrap_code
        );
        let bc_para = Paragraph::new(bc_text.as_str())
            .style(Style::default().fg(Color::Yellow))
            .wrap(ratatui::widgets::Wrap { trim: false });
        f.render_widget(bc_para, chunks[2]);

        // Full contact code (for contacts who cannot use QR / bootstrap flow).
        let full_text = format!(
            "Full code (manual sharing — paste into Add Contact):\n{}",
            app.export_code
        );
        let full_para = Paragraph::new(full_text.as_str())
            .style(Style::default().fg(Color::DarkGray))
            .wrap(ratatui::widgets::Wrap { trim: false });
        f.render_widget(full_para, chunks[4]);
    } else {
        // ── Fallback: terminal too small for QR — show text codes only. ──────────
        let code_text = format!(
            "Share this code out-of-band (in person, Signal, etc.).\n\
             Never share through an unverified channel.\n\n\
             Bootstrap code (short, fits in a QR code):\n{}\n\n\
             Full contact code (manual sharing):\n{}",
            app.bootstrap_code, app.export_code,
        );
        let block = Paragraph::new(code_text.as_str())
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Your Contact Code (Esc to close) "),
            )
            .wrap(ratatui::widgets::Wrap { trim: false });
        f.render_widget(block, popup);
    }
}

fn draw_pending_request_popup(f: &mut Frame, app: &AppState, area: Rect) {
    let popup = centered_rect(70, 60, area);
    f.render_widget(Clear, popup);

    if let Some(pending) = app.pending_handshakes.first() {
        let fp = pending.bundle.fingerprint();
        let preview = sanitize_for_display(&String::from_utf8_lossy(&pending.plaintext));
        let text = format!(
            "An unknown contact wants to message you.\n\n\
             Their fingerprint:\n{fp}\n\n\
             Their first message:\n\"{preview}\"\n\n\
             Verify this fingerprint out-of-band before accepting.\n\n\
             Enter a name for this contact:\n{}",
            app.pending_name_buf
        );
        let block = Paragraph::new(text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Incoming Contact Request  [Enter:accept  Esc:reject]"),
            )
            .wrap(ratatui::widgets::Wrap { trim: false });
        f.render_widget(block, popup);
    }
}

fn draw_settings_edit_popup(f: &mut Frame, app: &AppState, area: Rect) {
    let popup = centered_rect(60, 40, area);
    f.render_widget(Clear, popup);
    match &app.settings_edit_mode {
        SettingsEditMode::EditTorAddr => {
            let content = Paragraph::new(vec![
                Line::from("Enter new Tor SOCKS5 address (e.g. 127.0.0.1:9050):"),
                Line::from(""),
                Line::from(Span::styled(
                    app.settings_edit_buf.as_str(),
                    Style::default().fg(Color::Yellow),
                )),
                Line::from(""),
                Line::from("Enter:save  Esc:cancel"),
            ])
            .block(Block::default().borders(Borders::ALL).title("Edit Tor SOCKS5 Address"));
            f.render_widget(content, popup);
        }
        SettingsEditMode::EditAutoDelete => {
            let content = Paragraph::new(vec![
                Line::from("Enter message count for auto-delete (blank = disable):"),
                Line::from(""),
                Line::from(Span::styled(
                    app.settings_edit_buf.as_str(),
                    Style::default().fg(Color::Yellow),
                )),
                Line::from(""),
                Line::from("Enter:save  Esc:cancel"),
            ])
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Edit Auto-Delete Threshold"),
            );
            f.render_widget(content, popup);
        }
        SettingsEditMode::ConfirmRotate => {
            let content = Paragraph::new(
                "Rotate your identity keys?\n\n\
                 This generates a new keypair, sends a revocation certificate\n\
                 to all contacts, and invalidates your current contact code.\n\n\
                 y:confirm  Esc/n:cancel",
            )
            .style(Style::default().fg(Color::Yellow))
            .block(Block::default().borders(Borders::ALL).title("Confirm Key Rotation"));
            f.render_widget(content, popup);
        }
        SettingsEditMode::ConfirmRevoke => {
            let content = Paragraph::new(
                "Revoke your current identity key?\n\n\
                 This sends a retirement revocation certificate to all contacts.\n\
                 Use Rotate instead to replace the key with a new one.\n\n\
                 y:confirm  Esc/n:cancel",
            )
            .style(Style::default().fg(Color::Red))
            .block(Block::default().borders(Borders::ALL).title("Confirm Key Revocation"));
            f.render_widget(content, popup);
        }
        SettingsEditMode::None => {}
    }
}

fn draw_conversation(f: &mut Frame, app: &mut AppState, vault: &VaultUnlocked, area: Rect) {
    if vault.payload.contacts.is_empty() {
        let help = Paragraph::new("Add a contact in the Contacts tab first.")
            .block(Block::default().borders(Borders::ALL).title("Messages"));
        f.render_widget(help, area);
        return;
    }

    let idx = app
        .active_contact_idx
        .or_else(|| app.contacts_list.selected())
        .unwrap_or(0);

    if let Some(contact) = vault.payload.contacts.get(idx) {
        render_conversation(f, &contact.display_name, &app.messages, &app.draft, &app.search_query, area);
    } else {
        let help = Paragraph::new("Select a contact in the Contacts tab.")
            .block(Block::default().borders(Borders::ALL).title("Messages"));
        f.render_widget(help, area);
    }
}

// ─── Input Handling ───────────────────────────────────────────────────────────

fn handle_key(
    app: &mut AppState,
    key: crossterm::event::KeyEvent,
    vault: &mut VaultUnlocked,
    nym: &mut NymClient,
) {
    // Global: Ctrl+C always quits
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        app.running = false;
        return;
    }

    // Key alert intercepts everything until dismissed
    if app.contact_mode == ContactMode::KeyAlert {
        handle_key_alert(app, key, vault);
        return;
    }

    match app.tab {
        Tab::Contacts => handle_contacts_key(app, key, vault, nym),
        Tab::Conversation => handle_conversation_key(app, key, vault, nym),
        Tab::Settings => handle_settings_key(app, key, vault, nym),
    }
}

fn handle_key_alert(
    app: &mut AppState,
    key: crossterm::event::KeyEvent,
    vault: &mut VaultUnlocked,
) {
    let contact_idx = app.contacts_list.selected().unwrap_or(0);
    match key.code {
        KeyCode::Char('v') | KeyCode::Char('V') => {
            if let Some(c) = vault.payload.contacts.get_mut(contact_idx) {
                c.verified = true;
                let name = sanitize_for_display(&c.display_name);
                let _ = c;
                vault.save().ok();
                app.status = format!("Key change accepted — '{name}' marked verified.");
            }
            app.key_alert = None;
            app.contact_mode = ContactMode::List;
        }
        KeyCode::Char('r') | KeyCode::Char('R') => {
            vault.payload.contacts.remove(contact_idx);
            vault.save().ok();
            app.contacts_list.select(Some(0));
            app.status = "Contact rejected and removed.".into();
            app.key_alert = None;
            app.contact_mode = ContactMode::List;
        }
        _ => {}
    }
}

fn handle_contacts_key(
    app: &mut AppState,
    key: crossterm::event::KeyEvent,
    vault: &mut VaultUnlocked,
    nym: &mut NymClient,
) {
    let n = vault.payload.contacts.len();
    let pending_count = app.pending_handshakes.len();

    match app.contact_mode {
        ContactMode::List | ContactMode::Fingerprint => match key.code {
            KeyCode::Up => {
                if n > 0 {
                    let i = app.contacts_list.selected().unwrap_or(0);
                    app.contacts_list
                        .select(Some(if i == 0 { n - 1 } else { i - 1 }));
                }
            }
            KeyCode::Down => {
                if n > 0 {
                    let i = app.contacts_list.selected().unwrap_or(0);
                    app.contacts_list.select(Some((i + 1) % n));
                }
            }
            KeyCode::Enter => {
                app.contact_mode = ContactMode::Fingerprint;
                app.status = "v:verify  d:delete  Esc:back".into();
            }
            KeyCode::Esc => {
                app.contact_mode = ContactMode::List;
                app.status = contacts_help(pending_count);
            }
            KeyCode::Char('a') => {
                app.contact_mode = ContactMode::AddContact;
                app.add_buf.clear();
                app.status = "Paste contact code then Enter. Esc to cancel.".into();
            }
            KeyCode::Char('e') => {
                app.contact_mode = ContactMode::ExportCode;
                app.status = "Esc to close.".into();
            }
            KeyCode::Char('p') => {
                if !app.pending_handshakes.is_empty() {
                    app.contact_mode = ContactMode::PendingRequest;
                    app.pending_name_buf.clear();
                    app.status = "Type a name, then Enter to accept. Esc to reject.".into();
                } else {
                    app.status = "No pending contact requests.".into();
                }
            }
            KeyCode::Char('v') => {
                if let Some(idx) = app.contacts_list.selected() {
                    if let Some(c) = vault.payload.contacts.get_mut(idx) {
                        c.verified = true;
                        let name = sanitize_for_display(&c.display_name);
                        let _ = c;
                        vault.save().ok();
                        app.status = format!("'{name}' marked as verified.");
                    }
                }
            }
            KeyCode::Char('d') => {
                if let Some(idx) = app.contacts_list.selected() {
                    if idx < n {
                        vault.payload.contacts.remove(idx);
                        vault.save().ok();
                        let new_n = vault.payload.contacts.len();
                        app.contacts_list.select(if new_n > 0 {
                            Some(idx.min(new_n - 1))
                        } else {
                            None
                        });
                        app.status = "Contact removed.".into();
                    }
                }
            }
            KeyCode::Char('1') => {}
            KeyCode::Char('2') => {
                app.active_contact_idx = app.contacts_list.selected();
                app.tab = Tab::Conversation;
                app.status = "Enter:send  Esc:back  Type to compose".into();
            }
            KeyCode::Char('3') => {
                app.tab = Tab::Settings;
                app.status = "↑↓:navigate  Enter:select  1:contacts  q:quit".into();
            }
            KeyCode::Char('q') => app.running = false,
            _ => {}
        },

        ContactMode::AddContact => match key.code {
            KeyCode::Esc => {
                app.contact_mode = ContactMode::List;
                app.add_buf.clear();
                app.status = contacts_help(pending_count);
            }
            KeyCode::Enter => {
                let code_str = app.add_buf.trim().to_owned();
                app.add_buf.clear();

                if BootstrapCode::is_bootstrap(&code_str) {
                    // ── Bootstrap QR flow: send BundleRequest, await response ────
                    match BootstrapCode::decode(&code_str) {
                        Ok(bc) => {
                            send_bundle_request(app, vault, nym, &bc);
                            app.contact_mode = ContactMode::List;
                            app.status =
                                "Bundle request sent — contact will be added automatically \
                                 when they respond."
                                    .into();
                        }
                        Err(_) => {
                            app.contact_mode = ContactMode::List;
                            app.status = "Invalid bootstrap code — check and try again.".into();
                        }
                    }
                } else {
                    // ── Full contact code: add immediately ───────────────────────
                    match ContactCode::decode(&code_str) {
                        Ok(code) => {
                            let seq = vault.payload.sequence;
                            vault.payload.sequence += 1;
                            let label =
                                format!("Contact {}", vault.payload.contacts.len() + 1);
                            let contact = StoredContact::new(code.0, label, seq);
                            vault.payload.contacts.push(contact);
                            let new_idx = vault.payload.contacts.len() - 1;
                            app.contacts_list.select(Some(new_idx));
                            vault.save().ok();
                            app.contact_mode = ContactMode::List;
                            app.status =
                                "Contact added. Press [v] to verify fingerprint out-of-band."
                                    .into();
                        }
                        Err(_) => {
                            app.contact_mode = ContactMode::List;
                            app.status = "Invalid contact code — check and try again.".into();
                        }
                    }
                }
            }
            KeyCode::Backspace => {
                app.add_buf.pop();
            }
            KeyCode::Char(c) => {
                app.add_buf.push(c);
            }
            _ => {}
        },

        ContactMode::ExportCode | ContactMode::KeyAlert => match key.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                app.contact_mode = ContactMode::List;
                app.status = contacts_help(pending_count);
            }
            _ => {}
        },

        ContactMode::PendingRequest => match key.code {
            KeyCode::Esc => {
                // Reject: discard this pending request.
                if !app.pending_handshakes.is_empty() {
                    app.pending_handshakes.remove(0);
                }
                app.pending_name_buf.clear();
                app.contact_mode = ContactMode::List;
                app.status = contacts_help(app.pending_handshakes.len());
            }
            KeyCode::Enter => {
                accept_pending_handshake(app, vault);
            }
            KeyCode::Backspace => {
                app.pending_name_buf.pop();
            }
            KeyCode::Char(c) => {
                app.pending_name_buf.push(c);
            }
            _ => {}
        },
    }
}

/// Accept the first pending handshake: add the contact, init the ratchet,
/// persist the initial message, and dismiss the popup.
fn accept_pending_handshake(app: &mut AppState, vault: &mut VaultUnlocked) {
    if app.pending_handshakes.is_empty() {
        app.contact_mode = ContactMode::List;
        return;
    }

    let name = app.pending_name_buf.trim().to_owned();
    if name.is_empty() {
        app.status = "Please enter a name for this contact first.".into();
        return;
    }

    let pending = app.pending_handshakes.remove(0);
    app.pending_name_buf.clear();

    // Add the contact.
    let seq = vault.payload.sequence;
    vault.payload.sequence += 1;
    let contact = StoredContact::new(pending.bundle, name.clone(), seq);
    let contact_id = contact.id;
    vault.payload.contacts.push(contact);
    let new_idx = vault.payload.contacts.len() - 1;
    app.contacts_list.select(Some(new_idx));

    // Initialise Bob's ratchet using the dedicated ratchet secret (or KEM fallback).
    let bob_ratchet_secret = match load_ratchet_secret(vault) {
        Some(s) => s,
        None => {
            app.status = "Key error — vault may be corrupt.".into();
            return;
        }
    };
    let ratchet = RatchetState::init_bob(*pending.session_key_bytes, bob_ratchet_secret);
    let conv_key = vault.derive_conversation_key(&contact_id);
    if let Ok(ratchet_ct) = ratchet.to_encrypted_bytes(&conv_key) {
        let conv = vault.get_or_create_conversation(contact_id);
        conv.ratchet_state_ct = ratchet_ct;
    }

    // Persist the initial message.
    let text = sanitize_for_display(&String::from_utf8_lossy(&pending.plaintext));
    let initial_msg = StoredMessage {
        counter: 1,
        content: text.clone(),
        from_us: false,
    };
    vault.save_messages(&contact_id, &[initial_msg]).ok();

    vault.save().ok();
    app.contact_mode = ContactMode::List;
    app.status = format!(
        "Contact '{}' added. Switch to Messages to reply.",
        sanitize_for_display(&name)
    );
    app.status = format!(
        "{} | {} pending request(s) remain",
        app.status,
        app.pending_handshakes.len()
    );
    app.status = contacts_help(app.pending_handshakes.len());
}

fn handle_conversation_key(
    app: &mut AppState,
    key: crossterm::event::KeyEvent,
    vault: &mut VaultUnlocked,
    nym: &mut NymClient,
) {
    // Search mode intercepts all input until the user exits with Esc.
    if app.search_active {
        match key.code {
            KeyCode::Esc => {
                app.search_active = false;
                app.search_query.clear();
                app.status = "Enter:send  Esc:back  Type to compose  /:search".into();
            }
            KeyCode::Backspace => {
                app.search_query.pop();
                let n = app
                    .messages
                    .iter()
                    .filter(|m| m.content.to_lowercase().contains(&app.search_query.to_lowercase()))
                    .count();
                app.status = if app.search_query.is_empty() {
                    "Search: (type to filter, Esc to clear)".into()
                } else {
                    format!("Search: \"{}\"  ({n} match(es))  Esc:clear", app.search_query)
                };
            }
            KeyCode::Char(c) => {
                app.search_query.push(c);
                let n = app
                    .messages
                    .iter()
                    .filter(|m| m.content.to_lowercase().contains(&app.search_query.to_lowercase()))
                    .count();
                app.status =
                    format!("Search: \"{}\"  ({n} match(es))  Esc:clear", app.search_query);
            }
            _ => {}
        }
        return;
    }

    match key.code {
        KeyCode::Esc => {
            if app.draft.is_empty() {
                app.tab = Tab::Contacts;
                app.status = contacts_help(app.pending_handshakes.len());
            } else {
                app.draft.clear();
            }
        }
        KeyCode::Enter => {
            if !app.draft.is_empty() {
                let draft = app.draft.clone();
                app.draft.clear();
                send_message(app, vault, nym, draft.as_bytes());
            }
        }
        KeyCode::Backspace => {
            app.draft.pop();
        }
        KeyCode::Char('/') => {
            // Enter search mode.
            app.search_active = true;
            app.search_query.clear();
            app.status = "Search: (type to filter, Esc to clear)".into();
        }
        KeyCode::Char(c) => {
            app.draft.push(c);
        }
        KeyCode::Tab => {
            if app.draft.is_empty() {
                app.tab = Tab::Settings;
                app.status = "↑↓:navigate  Enter:select  1:contacts  q:quit".into();
            }
        }
        _ => {}
    }
}

fn handle_settings_key(
    app: &mut AppState,
    key: crossterm::event::KeyEvent,
    vault: &mut VaultUnlocked,
    nym: &mut NymClient,
) {
    const NUM_SETTINGS: usize = 7;

    // Active edit/confirm modes intercept all keys.
    match app.settings_edit_mode.clone() {
        SettingsEditMode::EditTorAddr => {
            match key.code {
                KeyCode::Esc => {
                    app.settings_edit_mode = SettingsEditMode::None;
                    app.settings_edit_buf.clear();
                    app.status = "↑↓:navigate  Enter:select  1:contacts  q:quit".into();
                }
                KeyCode::Enter => {
                    let val = app.settings_edit_buf.trim().to_owned();
                    if !val.is_empty() {
                        vault.payload.settings.tor_socks_addr = val;
                        vault.save().ok();
                        app.status = "Tor SOCKS5 address updated. Restart to apply.".into();
                    } else {
                        app.status = "No change — address cannot be empty.".into();
                    }
                    app.settings_edit_mode = SettingsEditMode::None;
                    app.settings_edit_buf.clear();
                }
                KeyCode::Backspace => {
                    app.settings_edit_buf.pop();
                }
                KeyCode::Char(c) => {
                    app.settings_edit_buf.push(c);
                }
                _ => {}
            }
            return;
        }
        SettingsEditMode::EditAutoDelete => {
            match key.code {
                KeyCode::Esc => {
                    app.settings_edit_mode = SettingsEditMode::None;
                    app.settings_edit_buf.clear();
                    app.status = "↑↓:navigate  Enter:select  1:contacts  q:quit".into();
                }
                KeyCode::Enter => {
                    let val = app.settings_edit_buf.trim().to_owned();
                    vault.payload.settings.default_auto_delete = if val.is_empty() {
                        None
                    } else {
                        val.parse::<u32>().ok()
                    };
                    vault.save().ok();
                    app.status = "Auto-delete threshold updated.".into();
                    app.settings_edit_mode = SettingsEditMode::None;
                    app.settings_edit_buf.clear();
                }
                KeyCode::Backspace => {
                    app.settings_edit_buf.pop();
                }
                KeyCode::Char(c) => {
                    app.settings_edit_buf.push(c);
                }
                _ => {}
            }
            return;
        }
        SettingsEditMode::ConfirmRotate => {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    rotate_keys(app, vault, nym);
                }
                _ => {
                    app.status = "Key rotation cancelled.".into();
                }
            }
            app.settings_edit_mode = SettingsEditMode::None;
            return;
        }
        SettingsEditMode::ConfirmRevoke => {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    revoke_key(app, vault, nym);
                }
                _ => {
                    app.status = "Key revocation cancelled.".into();
                }
            }
            app.settings_edit_mode = SettingsEditMode::None;
            return;
        }
        SettingsEditMode::None => {}
    }

    // Normal navigation.
    match key.code {
        KeyCode::Up => {
            let i = app.settings_list.selected().unwrap_or(0);
            app.settings_list
                .select(Some(if i == 0 { NUM_SETTINGS - 1 } else { i - 1 }));
        }
        KeyCode::Down => {
            let i = app.settings_list.selected().unwrap_or(0);
            app.settings_list.select(Some((i + 1) % NUM_SETTINGS));
        }
        KeyCode::Enter => match app.settings_list.selected().unwrap_or(0) {
            0 => {
                // Edit Tor SOCKS5 address
                app.settings_edit_buf = vault.payload.settings.tor_socks_addr.clone();
                app.settings_edit_mode = SettingsEditMode::EditTorAddr;
                app.status = "Edit Tor address. Enter:save  Esc:cancel".into();
            }
            2 => {
                // Edit auto-delete threshold
                app.settings_edit_buf = vault
                    .payload
                    .settings
                    .default_auto_delete
                    .map(|n| n.to_string())
                    .unwrap_or_default();
                app.settings_edit_mode = SettingsEditMode::EditAutoDelete;
                app.status = "Enter count (blank=disable). Enter:save  Esc:cancel".into();
            }
            3 => {
                // Rotate identity keys
                app.settings_edit_mode = SettingsEditMode::ConfirmRotate;
                app.status = "Confirm key rotation? y:yes  Esc/n:cancel".into();
            }
            4 => {
                // Revoke key
                app.settings_edit_mode = SettingsEditMode::ConfirmRevoke;
                app.status = "Confirm key revocation? y:yes  Esc/n:cancel".into();
            }
            5 => {
                // Export contact code
                app.tab = Tab::Contacts;
                app.contact_mode = ContactMode::ExportCode;
                app.status = "Your contact code — press Esc to close.".into();
            }
            6 => {
                // Refresh Tor circuit
                nym.signal_newnym();
                app.status =
                    "SIGNAL NEWNYM sent — new circuits active in ~60 s.".into();
            }
            _ => {}
        },
        KeyCode::Char('1') => {
            app.tab = Tab::Contacts;
            app.status = contacts_help(app.pending_handshakes.len());
        }
        KeyCode::Char('2') => {
            app.tab = Tab::Conversation;
            app.status = "Enter:send  Esc:back  Type to compose".into();
        }
        KeyCode::Char('3') => {}
        KeyCode::Char('q') => app.running = false,
        _ => {}
    }
}

// ─── Send Path ────────────────────────────────────────────────────────────────

/// Encrypt `plaintext` and transmit it to the currently active contact.
///
/// On the first message to a contact, performs the X3DH handshake to
/// establish a shared session key and initialises the Double Ratchet.
/// Subsequent messages use the ratchet directly, with a full HMAC-SHA256
/// deniable authentication tag attached to the wire message.
fn send_message(
    app: &mut AppState,
    vault: &mut VaultUnlocked,
    nym: &mut NymClient,
    plaintext: &[u8],
) {
    // Resolve the active contact.
    let contact_idx = match app
        .active_contact_idx
        .or_else(|| app.contacts_list.selected())
    {
        Some(i) => i,
        None => {
            app.status = "No contact selected.".into();
            return;
        }
    };
    let contact = match vault.payload.contacts.get(contact_idx).cloned() {
        Some(c) => c,
        None => {
            app.status = "Contact not found.".into();
            return;
        }
    };
    let contact_id = contact.id;
    let contact_addr = contact.bundle.nym_address.clone();

    if contact_addr.is_empty() {
        app.status = "Contact has no address — verify their contact code.".into();
        return;
    }

    // Reconstruct our KEM keypair (needed for both handshake and data paths).
    let our_kem = match HybridKemKeypair::from_bytes(&vault.payload.identity_kem_secret) {
        Ok(k) => k,
        Err(_) => {
            app.status = "Key error — vault may be corrupt.".into();
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
        // ── Data message via established ratchet ─────────────────────────────
        let conv_idx = vault.find_conversation_by_contact(&contact_id).unwrap();
        let ratchet_ct = vault.payload.conversations[conv_idx]
            .ratchet_state_ct
            .clone();

        let mut ratchet = match RatchetState::from_encrypted_bytes(&conv_key, &ratchet_ct) {
            Ok(r) => r,
            Err(_) => {
                app.status = "Failed to load ratchet state.".into();
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

        // Compute deniable HMAC-SHA256 over (conv_id || counter || ciphertext).
        let mac = compute_message_mac(&MacKey(mac_key_bytes), &contact_id, header.n, &ct);

        let wire = WireMessage {
            msg_type: WireMessageType::Data,
            header,
            ciphertext: ct,
            mac,
        }
        .with_padding();
        wire_payload = wire.to_bytes().expect("WireMessage serialization cannot fail");

        // Persist the advanced ratchet state.
        if let Ok(new_ct) = ratchet.to_encrypted_bytes(&conv_key) {
            vault.payload.conversations[conv_idx].ratchet_state_ct = new_ct;
        }
    } else {
        // ── Handshake + first message ─────────────────────────────────────────
        let our_signing =
            match HybridSigningKeypair::from_bytes(&vault.payload.identity_signing_secret) {
                Ok(s) => s,
                Err(_) => {
                    app.status = "Key error — vault may be corrupt.".into();
                    return;
                }
            };

        let our_ratchet_pub = if vault.payload.identity_ratchet_secret.len() == 32 {
            let bytes: [u8; 32] = vault.payload.identity_ratchet_secret[..32].try_into().unwrap();
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

        // Initialise Alice's ratchet with Bob's dedicated ratchet pub.
        // Fall back to KEM X25519 pub for contacts with older contact codes.
        let bob_ratchet_pub = if contact.bundle.ratchet_pub != [0u8; 32] {
            X25519PublicKey::from(contact.bundle.ratchet_pub)
        } else {
            X25519PublicKey::from(contact.bundle.x25519_pub)
        };
        let ratchet = match RatchetState::init_alice(session_key.0, bob_ratchet_pub) {
            Ok(r) => r,
            Err(_) => {
                app.status = "Ratchet init failed — contact may be corrupt.".into();
                return;
            }
        };

        // Persist ratchet state.
        if let Ok(ratchet_ct) = ratchet.to_encrypted_bytes(&conv_key) {
            let conv = vault.get_or_create_conversation(contact_id);
            conv.ratchet_state_ct = ratchet_ct;
        }

        // Wrap the HandshakeInitMessage in a WireMessage envelope.
        let hs_bytes =
            postcard::to_allocvec(&hs_msg).expect("HandshakeInitMessage serialization cannot fail");
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
        wire_payload = wire.to_bytes().expect("WireMessage serialization cannot fail");
    }

    // Transmit.
    match nym.send(&contact_addr, wire_payload) {
        Ok(()) => {
            let text = sanitize_for_display(&String::from_utf8_lossy(plaintext));
            // Persist to vault message log.
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

// ─── Receive Path ─────────────────────────────────────────────────────────────

/// Dispatch a raw inbound payload received from the Tor transport.
fn handle_incoming_message(
    app: &mut AppState,
    vault: &mut VaultUnlocked,
    nym: &mut NymClient,
    payload: &[u8],
) {
    let wire = match WireMessage::from_bytes(payload) {
        Some(w) => w,
        None => return, // unparseable — silently drop
    };

    match wire.msg_type {
        // Cover traffic — discard silently.
        WireMessageType::Dummy | WireMessageType::Loop => {}

        WireMessageType::Handshake => {
            handle_inbound_handshake(app, vault, &wire.ciphertext);
        }

        WireMessageType::Data => {
            handle_inbound_data(app, vault, &wire.header, &wire.ciphertext, &wire.mac);
        }

        WireMessageType::BundleRequest => {
            handle_inbound_bundle_request(vault, nym, &wire.ciphertext);
        }

        WireMessageType::BundleResponse => {
            handle_inbound_bundle_response(app, vault, &wire.ciphertext);
        }

        WireMessageType::Revocation => {
            handle_inbound_revocation(app, vault, &wire.ciphertext);
        }

        // Ack — not yet implemented; silently drop.
        _ => {}
    }
}

/// Process an inbound handshake. If the sender is a known contact, complete
/// the session setup immediately. If unknown, store as a pending request for
/// the user to review.
fn handle_inbound_handshake(app: &mut AppState, vault: &mut VaultUnlocked, hs_bytes: &[u8]) {
    let hs_msg: HandshakeInitMessage = match postcard::from_bytes(hs_bytes) {
        Ok(m) => m,
        Err(_) => return,
    };

    // Reconstruct our KEM keypair (needed for both paths).
    let our_kem = match HybridKemKeypair::from_bytes(&vault.payload.identity_kem_secret) {
        Ok(k) => k,
        Err(_) => return,
    };

    // Derive Bob's dedicated ratchet secret (DH3 key) — falls back to KEM
    // identity key for vaults created before the ratchet_pub field was added.
    let bob_ratchet_secret = match load_ratchet_secret(vault) {
        Some(s) => s,
        None => return,
    };

    // Complete the handshake as the responder.
    let (plaintext, session_key) = match perform_handshake_bob(&our_kem, &bob_ratchet_secret, &hs_msg) {
        Ok(r) => r,
        Err(_) => return, // MAC or decryption failure
    };

    // Identify the sender by their Ed25519 verifying key.
    let alice_ed_vk = hs_msg.alice_identity.ed25519_vk;
    let contact_idx = vault
        .payload
        .contacts
        .iter()
        .position(|c| c.bundle.ed25519_vk == alice_ed_vk);

    match contact_idx {
        Some(idx) => {
            // Known contact — set up ratchet and display message immediately.
            let contact_id = vault.payload.contacts[idx].id;
            let ratchet = RatchetState::init_bob(session_key.0, bob_ratchet_secret);
            let conv_key = vault.derive_conversation_key(&contact_id);
            if let Ok(ratchet_ct) = ratchet.to_encrypted_bytes(&conv_key) {
                let conv = vault.get_or_create_conversation(contact_id);
                conv.ratchet_state_ct = ratchet_ct;
            }

            let text = sanitize_for_display(&String::from_utf8_lossy(&plaintext));
            let mut msgs = vault.load_messages(&contact_id);
            let counter = msgs.len() as u64 + 1;
            msgs.push(StoredMessage {
                counter,
                content: text,
                from_us: false,
            });
            vault.save_messages(&contact_id, &msgs).ok();

            // Update in-memory display if this is the active conversation.
            let active_id = app
                .active_contact_idx
                .or_else(|| app.contacts_list.selected())
                .and_then(|i| vault.payload.contacts.get(i))
                .map(|c| c.id);
            if active_id == Some(contact_id) {
                app.messages = msgs;
            } else if let Some(conv_idx) = vault.find_conversation_by_contact(&contact_id) {
                vault.payload.conversations[conv_idx].unread_count += 1;
            }
            vault.save().ok();
        }
        None => {
            // Unknown contact — queue as a pending request for the user to review.
            // Cap the queue to prevent memory exhaustion from a handshake flood.
            // When full, evict the oldest entry (FIFO) to make room for the new one.
            if app.pending_handshakes.len() >= MAX_PENDING_HANDSHAKES {
                app.pending_handshakes.remove(0);
            }
            app.pending_handshakes.push(PendingHandshake {
                bundle: hs_msg.alice_identity,
                plaintext: Zeroizing::new(plaintext),
                session_key_bytes: Zeroizing::new(session_key.0),
            });
            let n = app.pending_handshakes.len();
            app.status =
                format!("{n} pending contact request(s) — press [p] in Contacts to review");
        }
    }
}

/// Try to decrypt an inbound data message against every known ratchet state
/// (sealed-sender: the wire frame carries no sender identity).
/// Verifies the deniable HMAC tag; rejects messages with a bad MAC.
fn handle_inbound_data(
    app: &mut AppState,
    vault: &mut VaultUnlocked,
    header: &MessageHeader,
    ciphertext: &[u8],
    mac: &MessageMac,
) {
    let n_contacts = vault.payload.contacts.len();
    for i in 0..n_contacts {
        let contact_id = vault.payload.contacts[i].id;
        let conv_idx = match vault.find_conversation_by_contact(&contact_id) {
            Some(idx) => idx,
            None => continue,
        };
        let ratchet_ct = vault.payload.conversations[conv_idx]
            .ratchet_state_ct
            .clone();
        if ratchet_ct.is_empty() {
            continue;
        }
        let conv_key = vault.derive_conversation_key(&contact_id);
        let mut ratchet = match RatchetState::from_encrypted_bytes(&conv_key, &ratchet_ct) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let (plaintext, mac_key_bytes) = match ratchet.ratchet_decrypt(header, ciphertext) {
            Ok(r) => r,
            Err(_) => continue,
        };

        // Verify deniable HMAC-SHA256. All peers running op4 v0.1+ send a real
        // MAC derived from the ratchet message key. A zeroed tag is not accepted.
        if !verify_message_mac(&MacKey(mac_key_bytes), &contact_id, header.n, ciphertext, mac) {
            app.status = "Message rejected: HMAC authentication failed.".into();
            return;
        }

        // Persist updated ratchet state.
        if let Ok(new_ct) = ratchet.to_encrypted_bytes(&conv_key) {
            vault.payload.conversations[conv_idx].ratchet_state_ct = new_ct;
        }

        // Persist the message.
        let text = sanitize_for_display(&String::from_utf8_lossy(&plaintext));
        let mut msgs = vault.load_messages(&contact_id);
        let counter = msgs.len() as u64 + 1;
        msgs.push(StoredMessage {
            counter,
            content: text,
            from_us: false,
        });
        vault.save_messages(&contact_id, &msgs).ok();

        // Update in-memory display if this is the active conversation.
        let active_id = app
            .active_contact_idx
            .or_else(|| app.contacts_list.selected())
            .and_then(|idx| vault.payload.contacts.get(idx))
            .map(|c| c.id);
        if active_id == Some(contact_id) {
            app.messages = msgs;
        } else {
            vault.payload.conversations[conv_idx].unread_count += 1;
        }
        vault.save().ok();
        return;
    }
    // No ratchet matched — silently drop (cover traffic or unknown sender).
}

/// Process an inbound revocation certificate.
///
/// Finds the contact by the revoked X25519 key, verifies the hybrid signature
/// against their *current* (known-good) bundle, then either:
/// - updates the contact to the new bundle and triggers a key-change alert, or
/// - removes the contact entirely if no replacement bundle is provided.
///
/// An invalid signature or unknown sender is silently dropped — we never
/// produce an error response that would let an attacker probe our contact list.
fn handle_inbound_revocation(
    app: &mut AppState,
    vault: &mut VaultUnlocked,
    cert_bytes: &[u8],
) {
    let cert: RevocationCertificate = match postcard::from_bytes(cert_bytes) {
        Ok(c) => c,
        Err(_) => return,
    };

    // Locate the contact by the revoked key's X25519 public bytes.
    let contact_idx = vault
        .payload
        .contacts
        .iter()
        .position(|c| c.bundle.x25519_pub == cert.revoked_x25519_pub);
    let contact_idx = match contact_idx {
        Some(i) => i,
        None => return, // Unknown sender — ignore (no oracle leak).
    };

    // Verify the Ed25519+ML-DSA hybrid signature against the *known* bundle.
    // An attacker who does not hold the private signing keys cannot forge this.
    let known_bundle = vault.payload.contacts[contact_idx].bundle.clone();
    if cert.verify(&known_bundle).is_err() {
        return; // Bad signature — drop silently.
    }

    let contact_name = vault.payload.contacts[contact_idx].display_name.clone();

    match cert.new_bundle {
        Some(new_bundle) => {
            // Key rotation: install the new bundle, clear verification status,
            // and raise a key-change alert so the user knows to re-verify OOB.
            let new_fingerprint = new_bundle.fingerprint();
            vault.payload.contacts[contact_idx].bundle = new_bundle;
            vault.payload.contacts[contact_idx].verified = false;
            vault.payload.contacts[contact_idx].last_key_seq += 1;
            app.key_alert = Some((contact_name.clone(), new_fingerprint));
            app.contact_mode = ContactMode::KeyAlert;
            app.tab = Tab::Contacts;
            app.status = format!(
                "⚠ {contact_name} has rotated their key — re-verify fingerprint out-of-band."
            );
        }
        None => {
            // Retirement or compromise with no successor key: remove the contact.
            vault.payload.contacts.remove(contact_idx);
            app.status = format!(
                "Contact '{contact_name}' has revoked their key with no replacement. \
                 They have been removed from your contact list."
            );
        }
    }

    vault.save().ok();
}

// ─── Bootstrap QR / Bundle-Request Flow ───────────────────────────────────────

/// Send a `BundleRequest` wire message to a peer whose bootstrap code we just scanned.
/// Stores the pending request so we can verify the response when it arrives.
fn send_bundle_request(
    app: &mut AppState,
    vault: &VaultUnlocked,
    nym: &mut NymClient,
    bc: &BootstrapCode,
) {
    // Record what fingerprint we expect in the response.
    app.pending_bundle_requests.push(BootstrapPending {
        ed25519_vk: bc.ed25519_vk,
        fingerprint_prefix: bc.fingerprint_prefix,
    });

    let kem = match HybridKemKeypair::from_bytes(&vault.payload.identity_kem_secret) {
        Ok(k) => k,
        Err(_) => return,
    };
    let my_addr = vault.payload.nym_address.clone();
    let my_x25519_pub = kem.x25519_public.to_bytes();

    // Ephemeral ECDH with Bob's x25519_pub → seals our return address and x25519 pub.
    let eph_secret = StaticSecret::random_from_rng(OsRng);
    let eph_pub = X25519PublicKey::from(&eph_secret);
    let bob_x25519 = X25519PublicKey::from(bc.x25519_pub);
    let shared = eph_secret.diffie_hellman(&bob_x25519);

    let mut enc_key = [0u8; 32];
    if hkdf_expand(shared.as_bytes(), Some(eph_pub.as_bytes()), b"op4-bundle-req-v1", &mut enc_key)
        .is_err()
    {
        return;
    }

    let inner = BundleRequestInner { requester_addr: my_addr, requester_x25519_pub: my_x25519_pub };
    let inner_bytes = postcard::to_allocvec(&inner).unwrap_or_default();
    let ct = match aead_encrypt(&SymKey(enc_key), &inner_bytes, eph_pub.as_bytes()) {
        Ok(c) => c,
        Err(_) => return,
    };

    let sealed = SealedBundleRequest { ephemeral_pub: eph_pub.to_bytes(), ciphertext: ct };
    let payload = postcard::to_allocvec(&sealed).unwrap_or_default();
    let wire = WireMessage {
        msg_type: WireMessageType::BundleRequest,
        header: crate::crypto::ratchet::MessageHeader { dh_pub: [0u8; 32], pn: 0, n: 0 },
        ciphertext: payload,
        mac: crate::crypto::hmac_auth::MessageMac { tag: [0u8; 32] },
    };
    nym.send(&bc.nym_address, wire.to_bytes().unwrap_or_default()).ok();
}

/// Handle an inbound `BundleRequest`: decrypt the sealed request, then reply
/// with a sealed `BundleResponse` using the requester's X25519 public key.
fn handle_inbound_bundle_request(
    vault: &VaultUnlocked,
    nym: &mut NymClient,
    request_ciphertext: &[u8],
) {
    // Decrypt the sealed request using our X25519 identity key.
    let kem = match HybridKemKeypair::from_bytes(&vault.payload.identity_kem_secret) {
        Ok(k) => k,
        Err(_) => return,
    };

    let sealed: SealedBundleRequest = match postcard::from_bytes(request_ciphertext) {
        Ok(s) => s,
        Err(_) => return,
    };

    let eph_pub = X25519PublicKey::from(sealed.ephemeral_pub);
    let shared = kem.x25519_secret.diffie_hellman(&eph_pub);

    let mut dec_key = [0u8; 32];
    if hkdf_expand(
        shared.as_bytes(),
        Some(&sealed.ephemeral_pub),
        b"op4-bundle-req-v1",
        &mut dec_key,
    )
    .is_err()
    {
        return;
    }

    let inner_bytes =
        match aead_decrypt(&SymKey(dec_key), &sealed.ciphertext, &sealed.ephemeral_pub) {
            Ok(b) => b,
            Err(_) => return,
        };
    let inner: BundleRequestInner = match postcard::from_bytes(&inner_bytes) {
        Ok(i) => i,
        Err(_) => return,
    };
    if inner.requester_addr.is_empty() {
        return;
    }

    // Build our full bundle.
    let bundle = match build_our_bundle(vault) {
        Some(b) => b,
        None => return,
    };
    let bundle_bytes = postcard::to_allocvec(&bundle).unwrap_or_default();

    // Seal the response with the requester's X25519 public key.
    let resp_eph_secret = StaticSecret::random_from_rng(OsRng);
    let resp_eph_pub = X25519PublicKey::from(&resp_eph_secret);
    let requester_x25519 = X25519PublicKey::from(inner.requester_x25519_pub);
    let resp_shared = resp_eph_secret.diffie_hellman(&requester_x25519);

    let mut resp_key = [0u8; 32];
    if hkdf_expand(
        resp_shared.as_bytes(),
        Some(resp_eph_pub.as_bytes()),
        b"op4-bundle-resp-v1",
        &mut resp_key,
    )
    .is_err()
    {
        return;
    }

    let resp_ct = match aead_encrypt(&SymKey(resp_key), &bundle_bytes, resp_eph_pub.as_bytes()) {
        Ok(c) => c,
        Err(_) => return,
    };

    let sealed_resp =
        SealedBundleResponse { ephemeral_pub: resp_eph_pub.to_bytes(), ciphertext: resp_ct };
    let resp_payload = postcard::to_allocvec(&sealed_resp).unwrap_or_default();

    let wire = WireMessage {
        msg_type: WireMessageType::BundleResponse,
        header: crate::crypto::ratchet::MessageHeader { dh_pub: [0u8; 32], pn: 0, n: 0 },
        ciphertext: resp_payload,
        mac: crate::crypto::hmac_auth::MessageMac { tag: [0u8; 32] },
    };
    nym.send(&inner.requester_addr, wire.to_bytes().unwrap_or_default()).ok();
}

/// Handle an inbound `BundleResponse`: decrypt the sealed response, verify the
/// full 32-byte fingerprint against the pending bootstrap request, then add contact.
fn handle_inbound_bundle_response(
    app: &mut AppState,
    vault: &mut VaultUnlocked,
    ciphertext: &[u8],
) {
    // Decrypt the sealed response using our X25519 identity key.
    let kem = match HybridKemKeypair::from_bytes(&vault.payload.identity_kem_secret) {
        Ok(k) => k,
        Err(_) => return,
    };

    let sealed: SealedBundleResponse = match postcard::from_bytes(ciphertext) {
        Ok(s) => s,
        Err(_) => return,
    };

    let resp_eph_pub = X25519PublicKey::from(sealed.ephemeral_pub);
    let shared = kem.x25519_secret.diffie_hellman(&resp_eph_pub);

    let mut dec_key = [0u8; 32];
    if hkdf_expand(
        shared.as_bytes(),
        Some(&sealed.ephemeral_pub),
        b"op4-bundle-resp-v1",
        &mut dec_key,
    )
    .is_err()
    {
        return;
    }

    let bundle_bytes =
        match aead_decrypt(&SymKey(dec_key), &sealed.ciphertext, &sealed.ephemeral_pub) {
            Ok(b) => b,
            Err(_) => return,
        };

    let bundle: PublicKeyBundle = match postcard::from_bytes(&bundle_bytes) {
        Ok(b) => b,
        Err(_) => return,
    };

    // Compute the SHA-256 fingerprint of the received bundle.
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bundle.x25519_pub);
    h.update(&bundle.mlkem_ek);
    h.update(bundle.ed25519_vk);
    h.update(&bundle.mldsa_vk);
    h.update(bundle.ratchet_pub);
    let digest: [u8; 32] = h.finalize().into();

    // Match against a pending request by ed25519_vk AND full 32-byte fingerprint.
    let pending_idx = app.pending_bundle_requests.iter().position(|p| {
        p.ed25519_vk == bundle.ed25519_vk && p.fingerprint_prefix == digest
    });
    let pending_idx = match pending_idx {
        Some(i) => i,
        None => return, // unexpected response or fingerprint mismatch — drop
    };
    app.pending_bundle_requests.remove(pending_idx);

    // Add the contact with a default name (user can rename later).
    let seq = vault.payload.sequence;
    vault.payload.sequence += 1;
    let label = format!("Contact {}", vault.payload.contacts.len() + 1);
    let contact = StoredContact::new(bundle, label.clone(), seq);
    vault.payload.contacts.push(contact);
    let new_idx = vault.payload.contacts.len() - 1;
    app.contacts_list.select(Some(new_idx));
    vault.save().ok();

    app.status = format!(
        "Contact '{}' added via QR bootstrap. Press [v] to verify fingerprint.",
        sanitize_for_display(&label)
    );
}

// ─── Key Rotation and Revocation ──────────────────────────────────────────────

/// Generate new identity keypairs, broadcast a revocation cert to all contacts,
/// and update the vault. The export code is refreshed in `app.export_code`.
fn rotate_keys(app: &mut AppState, vault: &mut VaultUnlocked, nym: &mut NymClient) {
    let old_signing =
        match HybridSigningKeypair::from_bytes(&vault.payload.identity_signing_secret) {
            Ok(s) => s,
            Err(_) => {
                app.status = "Key rotation failed: cannot load current signing key.".into();
                return;
            }
        };
    let old_kem = match HybridKemKeypair::from_bytes(&vault.payload.identity_kem_secret) {
        Ok(k) => k,
        Err(_) => {
            app.status = "Key rotation failed: cannot load current KEM key.".into();
            return;
        }
    };

    // Build old fingerprint (needed for the revocation cert body).
    let old_ratchet_pub = if vault.payload.identity_ratchet_secret.len() == 32 {
        let b: [u8; 32] = vault.payload.identity_ratchet_secret[..32].try_into().unwrap();
        x25519_dalek::PublicKey::from(&StaticSecret::from(b)).to_bytes()
    } else {
        old_kem.x25519_public.to_bytes()
    };
    let old_bundle = PublicKeyBundle::from_keypairs(
        &old_kem,
        &old_signing,
        old_ratchet_pub,
        String::new(),
    );
    let old_fp = old_bundle.fingerprint();

    // Generate new keypairs.
    let new_kem = HybridKemKeypair::generate();
    let new_signing = HybridSigningKeypair::generate();
    let new_ratchet = StaticSecret::random_from_rng(OsRng);
    let new_ratchet_pub = x25519_dalek::PublicKey::from(&new_ratchet).to_bytes();
    let new_bundle = PublicKeyBundle::from_keypairs(
        &new_kem,
        &new_signing,
        new_ratchet_pub,
        vault.payload.nym_address.clone(),
    );

    // Sign revocation cert with OLD key so contacts can verify it.
    let seq = vault.payload.sequence;
    vault.payload.sequence += 1;
    let cert = RevocationCertificate::create(
        &old_signing,
        old_fp,
        old_kem.x25519_public.to_bytes(),
        RevocationReason::Rotation,
        seq,
        Some(new_bundle),
    );

    // Broadcast to all contacts.
    let cert_bytes = postcard::to_allocvec(&cert).unwrap_or_default();
    let wire = WireMessage {
        msg_type: WireMessageType::Revocation,
        header: MessageHeader {
            dh_pub: [0u8; 32],
            pn: 0,
            n: 0,
        },
        ciphertext: cert_bytes,
        mac: MessageMac { tag: [0u8; 32] },
    };
    let wire_bytes = wire.to_bytes().unwrap_or_default();
    for contact in &vault.payload.contacts {
        if !contact.bundle.nym_address.is_empty() {
            nym.send(&contact.bundle.nym_address, wire_bytes.clone()).ok();
        }
    }

    // Update vault with new keys and refresh export code.
    vault.payload.identity_kem_secret = Zeroizing::new(new_kem.to_bytes());
    vault.payload.identity_signing_secret = Zeroizing::new(new_signing.to_bytes());
    vault.payload.identity_ratchet_secret = Zeroizing::new(new_ratchet.to_bytes().to_vec());
    vault.save().ok();
    app.export_code = build_export_code(vault);
    app.bootstrap_code = build_bootstrap_code(vault);
    app.status =
        "Keys rotated. New contact code ready — share it with contacts via [e] or Settings > 6."
            .into();
}

/// Broadcast a retirement revocation certificate and mark the key as revoked.
/// Does NOT generate a new keypair — use `rotate_keys` for that.
fn revoke_key(app: &mut AppState, vault: &mut VaultUnlocked, nym: &mut NymClient) {
    let old_signing =
        match HybridSigningKeypair::from_bytes(&vault.payload.identity_signing_secret) {
            Ok(s) => s,
            Err(_) => {
                app.status = "Revocation failed: cannot load signing key.".into();
                return;
            }
        };
    let old_kem = match HybridKemKeypair::from_bytes(&vault.payload.identity_kem_secret) {
        Ok(k) => k,
        Err(_) => {
            app.status = "Revocation failed: cannot load KEM key.".into();
            return;
        }
    };

    let old_ratchet_pub = if vault.payload.identity_ratchet_secret.len() == 32 {
        let b: [u8; 32] = vault.payload.identity_ratchet_secret[..32].try_into().unwrap();
        x25519_dalek::PublicKey::from(&StaticSecret::from(b)).to_bytes()
    } else {
        old_kem.x25519_public.to_bytes()
    };
    let old_bundle = PublicKeyBundle::from_keypairs(
        &old_kem,
        &old_signing,
        old_ratchet_pub,
        String::new(),
    );
    let old_fp = old_bundle.fingerprint();

    let seq = vault.payload.sequence;
    vault.payload.sequence += 1;
    let cert = RevocationCertificate::create(
        &old_signing,
        old_fp,
        old_kem.x25519_public.to_bytes(),
        RevocationReason::Retirement,
        seq,
        None,
    );

    let cert_bytes = postcard::to_allocvec(&cert).unwrap_or_default();
    let wire = WireMessage {
        msg_type: WireMessageType::Revocation,
        header: MessageHeader {
            dh_pub: [0u8; 32],
            pn: 0,
            n: 0,
        },
        ciphertext: cert_bytes,
        mac: MessageMac { tag: [0u8; 32] },
    };
    let wire_bytes = wire.to_bytes().unwrap_or_default();
    for contact in &vault.payload.contacts {
        if !contact.bundle.nym_address.is_empty() {
            nym.send(&contact.bundle.nym_address, wire_bytes.clone()).ok();
        }
    }
    vault.save().ok();
    app.status = "Revocation certificate sent to all contacts.".into();
}

// ─── Utilities ────────────────────────────────────────────────────────────────

/// Returns a horizontally and vertically centered Rect.
/// Reconstruct our Bob-side ratchet `StaticSecret` from the vault.
///
/// Prefers the dedicated `identity_ratchet_secret` (32 bytes) stored since
/// first-run. Falls back to the X25519 component of the KEM keypair for
/// vaults created before the ratchet_secret field was introduced.
///
/// Returns `None` only if the vault is corrupt (key bytes malformed).
fn load_ratchet_secret(vault: &VaultUnlocked) -> Option<StaticSecret> {
    if vault.payload.identity_ratchet_secret.len() == 32 {
        let bytes: [u8; 32] = vault.payload.identity_ratchet_secret[..32].try_into().ok()?;
        Some(StaticSecret::from(bytes))
    } else {
        let kem = HybridKemKeypair::from_bytes(&vault.payload.identity_kem_secret).ok()?;
        Some(StaticSecret::from(kem.x25519_secret.to_bytes()))
    }
}

fn centered_rect(pct_x: u16, pct_y: u16, area: Rect) -> Rect {
    let vert = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - pct_y) / 2),
            Constraint::Percentage(pct_y),
            Constraint::Percentage((100 - pct_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - pct_x) / 2),
            Constraint::Percentage(pct_x),
            Constraint::Percentage((100 - pct_x) / 2),
        ])
        .split(vert[1])[1]
}
