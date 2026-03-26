use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

use op4_core::storage::vault::StoredMessage;
use crate::ui::input::sanitize_for_display;

/// Render the conversation view for a contact.
///
/// `search_query` filters the visible message list (case-insensitive substring
/// match). Pass an empty string to show all messages.
/// Messages are displayed with monotonic counters only — no wall-clock timestamps.
pub fn render_conversation(
    f: &mut Frame,
    contact_name: &str,
    messages: &[StoredMessage],
    draft: &str,
    search_query: &str,
    area: ratatui::layout::Rect,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(area);

    // Filter messages when a search query is active.
    let query_lower = search_query.to_lowercase();
    let filtered: Vec<&StoredMessage> = if search_query.is_empty() {
        messages.iter().collect()
    } else {
        messages
            .iter()
            .filter(|m| m.content.to_lowercase().contains(&query_lower))
            .collect()
    };

    // Message list
    let items: Vec<ListItem> = filtered
        .iter()
        .map(|m| {
            let content = sanitize_for_display(&m.content);
            let (prefix, style) = if m.from_us {
                ("You  ", Style::default().fg(Color::Cyan))
            } else {
                ("Them ", Style::default().fg(Color::White))
            };
            // Counter shown instead of timestamp
            let counter_span = Span::styled(
                format!("[#{:06}] ", m.counter),
                Style::default().fg(Color::DarkGray),
            );
            let prefix_span = Span::styled(prefix, style.add_modifier(Modifier::BOLD));
            let content_span = Span::styled(content, style);
            ListItem::new(Line::from(vec![counter_span, prefix_span, content_span]))
        })
        .collect();

    // Show search query in title when active.
    let title = if search_query.is_empty() {
        format!(" {} ", sanitize_for_display(contact_name))
    } else {
        format!(
            " {} — search: \"{}\" ({}/{}) ",
            sanitize_for_display(contact_name),
            sanitize_for_display(search_query),
            filtered.len(),
            messages.len()
        )
    };
    let msg_list = List::new(items).block(Block::default().borders(Borders::ALL).title(title));
    f.render_widget(msg_list, chunks[0]);

    // Input draft area (shows search hint when in search mode).
    let draft_title = if search_query.is_empty() {
        "Message (Enter to send, Esc to cancel, /:search)"
    } else {
        "Message  [search active — Esc to clear]"
    };
    let input = Paragraph::new(sanitize_for_display(draft))
        .block(Block::default().borders(Borders::ALL).title(draft_title));
    f.render_widget(input, chunks[1]);
}
