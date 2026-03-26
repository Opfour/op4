use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

/// Render the duress inbox — visually identical to the real inbox.
/// Contains plausible decoy conversations only.
/// Called when vault is unlocked with the duress passphrase.
pub fn render_duress_inbox(f: &mut Frame, area: ratatui::layout::Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(area);

    // Fake contact list
    let contacts = vec![
        ListItem::new("Alex"),
        ListItem::new("Sam"),
        ListItem::new("Work Group"),
    ];
    let contact_list = List::new(contacts)
        .block(Block::default().borders(Borders::ALL).title("Contacts"))
        .style(Style::default().fg(Color::White));
    f.render_widget(contact_list, chunks[0]);

    // Fake conversation
    let decoy = Paragraph::new(
        "Alex [#000001]: Hey, are you free tonight?\n\
         You   [#000002]: Yeah, what's up?\n\
         Alex [#000003]: Want to grab dinner?\n\
         You   [#000004]: Sure, sounds good.",
    )
    .block(Block::default().borders(Borders::ALL).title("Alex"))
    .style(Style::default().fg(Color::White));
    f.render_widget(decoy, chunks[1]);
}
