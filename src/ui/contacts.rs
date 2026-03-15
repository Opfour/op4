use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame,
};

use crate::identity::profile::StoredContact;
use crate::ui::input::sanitize_for_display;

/// Render the contacts list panel.
pub fn render_contacts(
    f: &mut Frame,
    contacts: &[StoredContact],
    list_state: &mut ListState,
    area: ratatui::layout::Rect,
) {
    let items: Vec<ListItem> = contacts
        .iter()
        .map(|c| {
            let name = sanitize_for_display(&c.display_name);
            let verified_indicator = if c.verified {
                Span::styled(" ✓", Style::default().fg(Color::Green))
            } else {
                Span::styled(" ⚠ UNVERIFIED", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
            };
            ListItem::new(Line::from(vec![
                Span::raw(name),
                verified_indicator,
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Contacts"))
        .highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");

    f.render_stateful_widget(list, area, list_state);
}

/// Render the fingerprint verification panel for a selected contact.
/// Shows a prominent warning if the contact has not been verified.
pub fn render_fingerprint_panel(f: &mut Frame, contact: &StoredContact, area: ratatui::layout::Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    // Warning banner for unverified contacts
    if !contact.verified {
        let warning = Paragraph::new(
            "⚠  FINGERPRINT NOT VERIFIED — MITM POSSIBLE. Compare fingerprint out-of-band before trusting.",
        )
        .style(Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::ALL));
        f.render_widget(warning, chunks[0]);
    } else {
        let ok = Paragraph::new("✓  Fingerprint verified")
            .style(Style::default().fg(Color::Green))
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(ok, chunks[0]);
    }

    // Fingerprint display
    let fp = contact.bundle.fingerprint();
    let fp_display = format!(
        "Fingerprint:\n{fp}\n\nVerify this matches your contact's display BEFORE communicating."
    );
    let panel = Paragraph::new(fp_display)
        .block(Block::default().borders(Borders::ALL).title("Key Fingerprint"))
        .wrap(ratatui::widgets::Wrap { trim: false });
    f.render_widget(panel, chunks[1]);
}

/// Render a full-screen red alert when a contact's key has changed.
pub fn render_key_change_alert(f: &mut Frame, contact_name: &str, new_fingerprint: &str) {
    let area = f.area();
    let name = sanitize_for_display(contact_name);
    let fp = sanitize_for_display(new_fingerprint);
    let text = format!(
        "\n\n  ⛔  KEY CHANGE DETECTED\n\n\
         Contact: {name}\n\n\
         Their key has changed. This could indicate a security compromise or device change.\n\n\
         New fingerprint:\n{fp}\n\n\
         Verify this out-of-band before continuing. Press [V] to mark verified, [R] to reject.",
    );
    let alert = Paragraph::new(text)
        .style(Style::default().fg(Color::White).bg(Color::Red).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(alert, area);
}
