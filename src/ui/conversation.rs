use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

use crate::storage::vault::StoredMessage;
use crate::ui::input::sanitize_for_display;

/// Render the conversation view for a contact.
/// Messages are displayed with monotonic counters only — no wall-clock timestamps.
pub fn render_conversation(
    f: &mut Frame,
    contact_name: &str,
    messages: &[StoredMessage],
    draft: &str,
    area: ratatui::layout::Rect,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(area);

    // Message list
    let items: Vec<ListItem> = messages
        .iter()
        .map(|m| {
            let content = sanitize_for_display(&m.content);
            let (prefix, style) = if m.from_us {
                ("You  ", Style::default().fg(Color::Cyan))
            } else {
                ("Them ", Style::default().fg(Color::White))
            };
            // Counter shown instead of timestamp
            let counter_span =
                Span::styled(format!("[#{:06}] ", m.counter), Style::default().fg(Color::DarkGray));
            let prefix_span = Span::styled(prefix, style.add_modifier(Modifier::BOLD));
            let content_span = Span::styled(content, style);
            ListItem::new(Line::from(vec![counter_span, prefix_span, content_span]))
        })
        .collect();

    let title = format!(" {} ", sanitize_for_display(contact_name));
    let msg_list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title));
    f.render_widget(msg_list, chunks[0]);

    // Input draft area
    let input = Paragraph::new(sanitize_for_display(draft))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Message (Enter to send, Esc to cancel)"),
        );
    f.render_widget(input, chunks[1]);
}
