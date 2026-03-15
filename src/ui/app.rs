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
use crate::crypto::hmac_auth::MessageMac;
use crate::crypto::keys::{HybridKemKeypair, HybridSigningKeypair, PublicKeyBundle};
use crate::crypto::ratchet::{MessageHeader, RatchetState};
use crate::identity::profile::{ContactCode, StoredContact};
use crate::network::message::{WireMessage, WireMessageType};
use crate::network::nym_client::NymClient;
use crate::storage::vault::{StoredMessage, VaultUnlocked};
use crate::ui::{
    contacts::{render_contacts, render_fingerprint_panel, render_key_change_alert},
    conversation::render_conversation,
    duress::render_duress_inbox,
    input::sanitize_for_display,
    settings::render_settings,
};

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
}

struct AppState {
    running: bool,
    tab: Tab,
    // Contacts
    contacts_list: ListState,
    contact_mode: ContactMode,
    add_buf: String,
    export_code: String,
    key_alert: Option<(String, String)>, // (contact_name, new_fingerprint)
    // Conversation
    draft: String,
    messages: Vec<StoredMessage>,
    active_contact_idx: Option<usize>,
    // Settings
    settings_list: ListState,
    // Status bar
    status: String,
}

impl AppState {
    fn new(export_code: String) -> Self {
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
            key_alert: None,
            draft: String::new(),
            messages: Vec::new(),
            active_contact_idx: None,
            settings_list,
            status: contacts_help(),
        }
    }
}

fn contacts_help() -> String {
    "Tab:switch  ↑↓:navigate  a:add-contact  e:export-code  v:verify  d:delete  Enter:view  q:quit"
        .into()
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
    let mut app = AppState::new(export_code);

    loop {
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
            handle_incoming_message(&mut app, &mut vault, &incoming.payload);
        }

        if !app.running {
            break;
        }
    }

    vault.save().ok();
    Ok(())
}

/// Build the real contact code from vault keypairs, or a descriptive error string.
fn build_export_code(vault: &VaultUnlocked) -> String {
    if vault.payload.identity_kem_secret.is_empty()
        || vault.payload.identity_signing_secret.is_empty()
    {
        return "[No identity keys — restart op4 to complete first-run setup]".into();
    }
    let kem = match HybridKemKeypair::from_bytes(&vault.payload.identity_kem_secret) {
        Ok(k) => k,
        Err(_) => return "[Key decode error — vault may be corrupt]".into(),
    };
    let signing = match HybridSigningKeypair::from_bytes(&vault.payload.identity_signing_secret) {
        Ok(s) => s,
        Err(_) => return "[Key decode error — vault may be corrupt]".into(),
    };
    let bundle = PublicKeyBundle::from_keypairs(&kem, &signing, vault.payload.nym_address.clone());
    ContactCode(bundle).encode()
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

    draw_tabs(f, app, chunks[0]);

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
        }
    }

    let status = Paragraph::new(app.status.as_str()).style(Style::default().fg(Color::DarkGray));
    f.render_widget(status, chunks[2]);
}

fn draw_tabs(f: &mut Frame, app: &AppState, area: Rect) {
    let titles = vec![
        Line::from(Span::raw("Contacts [1]")),
        Line::from(Span::raw("Messages [2]")),
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

    if vault.payload.contacts.is_empty() {
        let help = Paragraph::new(
            "No contacts yet.\n\n\
             [a]  Add a contact using their contact code\n\
             [e]  Show your contact code to share with others",
        )
        .block(Block::default().borders(Borders::ALL).title("Contacts"));
        f.render_widget(help, area);
        return;
    }

    // Split: contact list | detail panel
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(area);

    render_contacts(
        f,
        &vault.payload.contacts,
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
    let popup = centered_rect(80, 50, area);
    f.render_widget(Clear, popup);
    let code_text = format!(
        "Share this code out-of-band (in person, Signal, etc.).\n\
         Never share through an unverified channel.\n\n\
         {}",
        app.export_code
    );
    let block = Paragraph::new(code_text.as_str())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Your Contact Code"),
        )
        .wrap(ratatui::widgets::Wrap { trim: false });
    f.render_widget(block, popup);
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
        render_conversation(f, &contact.display_name, &app.messages, &app.draft, area);
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
        Tab::Contacts => handle_contacts_key(app, key, vault),
        Tab::Conversation => handle_conversation_key(app, key, vault, nym),
        Tab::Settings => handle_settings_key(app, key, vault),
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
) {
    let n = vault.payload.contacts.len();

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
                app.status = contacts_help();
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
                app.status = contacts_help();
            }
            KeyCode::Enter => {
                let code_str = app.add_buf.trim().to_owned();
                app.add_buf.clear();
                match ContactCode::decode(&code_str) {
                    Ok(code) => {
                        let seq = vault.payload.sequence;
                        vault.payload.sequence += 1;
                        let label = format!("Contact {}", vault.payload.contacts.len() + 1);
                        let contact = StoredContact::new(code.0, label, seq);
                        vault.payload.contacts.push(contact);
                        let new_idx = vault.payload.contacts.len() - 1;
                        app.contacts_list.select(Some(new_idx));
                        vault.save().ok();
                        app.contact_mode = ContactMode::List;
                        app.status =
                            "Contact added. Press [v] to verify fingerprint out-of-band.".into();
                    }
                    Err(_) => {
                        app.contact_mode = ContactMode::List;
                        app.status = "Invalid contact code — check and try again.".into();
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
                app.status = contacts_help();
            }
            _ => {}
        },
    }
}

fn handle_conversation_key(
    app: &mut AppState,
    key: crossterm::event::KeyEvent,
    vault: &mut VaultUnlocked,
    nym: &mut NymClient,
) {
    match key.code {
        KeyCode::Esc => {
            if app.draft.is_empty() {
                app.tab = Tab::Contacts;
                app.status = contacts_help();
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
    _vault: &mut VaultUnlocked,
) {
    const NUM_SETTINGS: usize = 6;
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
            5 => {
                // Export contact code
                app.tab = Tab::Contacts;
                app.contact_mode = ContactMode::ExportCode;
                app.status = "Your contact code — press Esc to close.".into();
            }
            _ => {
                app.status = "Setting configuration not yet implemented.".into();
            }
        },
        KeyCode::Char('1') => {
            app.tab = Tab::Contacts;
            app.status = contacts_help();
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
/// Subsequent messages use the ratchet directly.
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
        let (header, ct) = match ratchet.ratchet_encrypt(plaintext) {
            Ok(r) => r,
            Err(_) => {
                app.status = "Encryption failed.".into();
                return;
            }
        };
        let wire = WireMessage {
            msg_type: WireMessageType::Data,
            header,
            ciphertext: ct,
            mac: MessageMac { tag: [0u8; 32] },
        }
        .with_padding();
        wire_payload = wire.to_bytes();

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

        let (hs_msg, session_key) = match perform_handshake_alice(
            &our_kem,
            &our_signing,
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

        // Initialise Alice's ratchet with Bob's identity X25519 pub.
        let bob_ratchet_pub = X25519PublicKey::from(contact.bundle.x25519_pub);
        let ratchet = RatchetState::init_alice(session_key.0, bob_ratchet_pub);

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
        wire_payload = wire.to_bytes();
    }

    // Transmit.
    match nym.send(&contact_addr, wire_payload) {
        Ok(()) => {
            let counter = app.messages.len() as u64 + 1;
            let text = sanitize_for_display(&String::from_utf8_lossy(plaintext));
            app.messages.push(StoredMessage {
                counter,
                content: text,
                from_us: true,
            });
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
fn handle_incoming_message(app: &mut AppState, vault: &mut VaultUnlocked, payload: &[u8]) {
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
            handle_inbound_data(app, vault, &wire.header, &wire.ciphertext);
        }

        // Ack / Revocation — not yet implemented; silently drop.
        _ => {}
    }
}

/// Process an inbound handshake from a known contact (acts as Bob).
fn handle_inbound_handshake(app: &mut AppState, vault: &mut VaultUnlocked, hs_bytes: &[u8]) {
    let hs_msg: HandshakeInitMessage = match postcard::from_bytes(hs_bytes) {
        Ok(m) => m,
        Err(_) => return,
    };

    // Identify the sender by their Ed25519 verifying key.
    let alice_ed_vk = hs_msg.alice_identity.ed25519_vk;
    let contact_idx = match vault
        .payload
        .contacts
        .iter()
        .position(|c| c.bundle.ed25519_vk == alice_ed_vk)
    {
        Some(i) => i,
        None => return, // unknown contact — silently drop
    };
    let contact_id = vault.payload.contacts[contact_idx].id;

    // Reconstruct our KEM keypair.
    let our_kem = match HybridKemKeypair::from_bytes(&vault.payload.identity_kem_secret) {
        Ok(k) => k,
        Err(_) => return,
    };

    // Complete the handshake as the responder.
    let (plaintext, session_key) = match perform_handshake_bob(&our_kem, &hs_msg) {
        Ok(r) => r,
        Err(_) => return, // MAC or decryption failure
    };

    // Initialise Bob's ratchet using our identity X25519 secret.
    let bob_ratchet_secret = StaticSecret::from(our_kem.x25519_secret.to_bytes());
    let ratchet = RatchetState::init_bob(session_key.0, bob_ratchet_secret);

    // Persist ratchet state.
    let conv_key = vault.derive_conversation_key(&contact_id);
    if let Ok(ratchet_ct) = ratchet.to_encrypted_bytes(&conv_key) {
        let conv = vault.get_or_create_conversation(contact_id);
        conv.ratchet_state_ct = ratchet_ct;
    }

    // Display the received message.
    let text = sanitize_for_display(&String::from_utf8_lossy(&plaintext));
    let counter = app.messages.len() as u64 + 1;
    app.messages.push(StoredMessage {
        counter,
        content: text,
        from_us: false,
    });
    vault.save().ok();
}

/// Try to decrypt an inbound data message against every known ratchet state
/// (sealed-sender: the wire frame carries no sender identity).
fn handle_inbound_data(
    app: &mut AppState,
    vault: &mut VaultUnlocked,
    header: &MessageHeader,
    ciphertext: &[u8],
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
        let plaintext = match ratchet.ratchet_decrypt(header, ciphertext) {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Decryption succeeded — persist updated ratchet and display message.
        if let Ok(new_ct) = ratchet.to_encrypted_bytes(&conv_key) {
            vault.payload.conversations[conv_idx].ratchet_state_ct = new_ct;
        }
        let text = sanitize_for_display(&String::from_utf8_lossy(&plaintext));
        let counter = app.messages.len() as u64 + 1;
        app.messages.push(StoredMessage {
            counter,
            content: text,
            from_us: false,
        });
        vault.save().ok();
        return;
    }
    // No ratchet matched — silently drop (cover traffic or unknown sender).
}

// ─── Utilities ────────────────────────────────────────────────────────────────

/// Returns a horizontally and vertically centered Rect.
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
