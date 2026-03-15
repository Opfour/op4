use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Tabs},
    Frame, Terminal,
};
use ratatui::widgets::ListState;

use crate::identity::profile::{ContactCode, StoredContact};
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
    "Tab:switch  ↑↓:navigate  a:add-contact  e:export-code  v:verify  d:delete  Enter:view  q:quit".into()
}

// ─── Public Entry Points ──────────────────────────────────────────────────────

/// Run the main TUI event loop. Blocks until the user quits.
/// Call from within `tokio::task::block_in_place` so the async runtime
/// can schedule other tasks on other threads while the TUI runs.
pub fn run<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    mut vault: VaultUnlocked,
    _nym: &mut NymClient,
) -> crate::error::Result<()> {
    if vault.is_duress {
        return run_duress(terminal);
    }

    // Export code placeholder — real implementation serializes our PublicKeyBundle.
    let export_code =
        "[Your contact code would appear here — share out-of-band with contacts]".to_string();
    let mut app = AppState::new(export_code);

    loop {
        terminal
            .draw(|f| draw(f, &mut app, &vault))
            .map_err(|e| crate::error::AppError::Io(
                std::io::Error::new(std::io::ErrorKind::Other, e.to_string()),
            ))?;

        // Poll for input with a short timeout so we can check for network messages
        // in the future without blocking indefinitely.
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                handle_key(&mut app, key, &mut vault);
            }
        }

        // TODO: poll nym.try_recv_msg() and push to app.messages

        if !app.running {
            break;
        }
    }

    vault.save().ok();
    Ok(())
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
            .map_err(|e| crate::error::AppError::Io(
                std::io::Error::new(std::io::ErrorKind::Other, e.to_string()),
            ))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') => break,
                    KeyCode::Char('c')
                        if key.modifiers.contains(KeyModifiers::CONTROL) =>
                    {
                        break
                    }
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
        .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(1)])
        .split(area);

    draw_tabs(f, app, chunks[0]);

    match app.tab {
        Tab::Contacts => draw_contacts(f, app, vault, chunks[1]),
        Tab::Conversation => draw_conversation(f, app, vault, chunks[1]),
        Tab::Settings => {
            render_settings(f, &vault.payload.settings, &mut app.settings_list, chunks[1]);
        }
    }

    let status = Paragraph::new(app.status.as_str())
        .style(Style::default().fg(Color::DarkGray));
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

    render_contacts(f, &vault.payload.contacts, &mut app.contacts_list, chunks[0]);

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
        .block(Block::default().borders(Borders::ALL).title("Your Contact Code"))
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
        Tab::Conversation => handle_conversation_key(app, key, vault),
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
                // NLL ends the borrow of c here (last use above);
                // vault.save() re-borrows vault immutably without conflict.
                let _ = c;
                vault.save().ok();
                app.status = format!("Key change accepted — '{}' marked verified.", name);
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
                    app.contacts_list.select(Some(if i == 0 { n - 1 } else { i - 1 }));
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
                        let _ = c; // end mutable borrow before vault.save()
                        vault.save().ok();
                        app.status = format!("'{}' marked as verified.", name);
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
    _vault: &mut VaultUnlocked,
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
                let counter = app.messages.len() as u64 + 1;
                let msg = StoredMessage {
                    counter,
                    content: app.draft.clone(),
                    from_us: true,
                };
                app.messages.push(msg);
                app.draft.clear();
                app.status = "Message queued. (Nym send pending full SDK integration)".into();
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
