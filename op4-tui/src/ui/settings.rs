use ratatui::{
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, List, ListItem, ListState},
    Frame,
};

use op4_core::storage::vault::AppSettings;

/// Settings menu items.
pub enum SettingsItem {
    TorAddress,
    NymGateway,
    AutoDelete,
    RotateKey,
    RevokeKey,
    ExportContactCode,
    RefreshCircuit,
}

pub fn render_settings(
    f: &mut Frame,
    settings: &AppSettings,
    list_state: &mut ListState,
    area: ratatui::layout::Rect,
) {
    let tor = format!("Tor SOCKS5 address: {}", settings.tor_socks_addr);
    let gateway = format!(
        "Nym gateway: {}",
        settings.nym_gateway.as_deref().unwrap_or("(auto)")
    );
    let auto_del = format!(
        "Auto-delete after: {}",
        settings
            .default_auto_delete
            .map(|n| format!("{n} messages"))
            .unwrap_or_else(|| "disabled".into())
    );

    let items = vec![
        ListItem::new(Line::from(tor)),
        ListItem::new(Line::from(gateway)),
        ListItem::new(Line::from(auto_del)),
        ListItem::new(Line::from("Rotate identity keys")),
        ListItem::new(Line::from("Revoke & announce key change")),
        ListItem::new(Line::from("Export my contact code")),
        ListItem::new(Line::from("Refresh Tor circuit (SIGNAL NEWNYM)")),
    ];

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Settings"))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    f.render_stateful_widget(list, area, list_state);
}
