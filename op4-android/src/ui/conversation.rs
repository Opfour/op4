use eframe::egui;

use super::{sanitize, send_message, Op4App};

pub fn show(app: &mut Op4App, ui: &mut egui::Ui) {
    let vault = match app.vault.as_ref() {
        Some(v) => v,
        None => return,
    };

    if vault.payload.contacts.is_empty() {
        ui.label("Add a contact in the Contacts tab first.");
        return;
    }

    let contact_name = vault
        .payload
        .contacts
        .get(app.selected_contact)
        .map(|c| sanitize(&c.display_name))
        .unwrap_or_else(|| "Unknown".into());

    // Header with contact name
    ui.horizontal(|ui| {
        ui.heading(&contact_name);
        if app.search_active {
            ui.separator();
            ui.label("Search:");
            ui.add(
                egui::TextEdit::singleline(&mut app.search_query)
                    .hint_text("Filter messages...")
                    .desired_width(200.0),
            );
            if ui.button("Clear").clicked() {
                app.search_active = false;
                app.search_query.clear();
            }
        } else if ui.button("Search").clicked() {
            app.search_active = true;
            app.search_query.clear();
        }
    });

    ui.separator();

    // Message area
    let messages = &app.messages;
    let query_lower = app.search_query.to_lowercase();

    egui::ScrollArea::vertical()
        .auto_shrink([false; 2])
        .stick_to_bottom(true)
        .show(ui, |ui| {
            for msg in messages {
                // Filter by search query if active
                if !query_lower.is_empty() && !msg.content.to_lowercase().contains(&query_lower) {
                    continue;
                }

                let text = &msg.content;
                if msg.from_us {
                    // Right-aligned, blue tint
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::TOP), |ui| {
                        let frame = egui::Frame::new()
                            .fill(egui::Color32::from_rgb(30, 60, 100))
                            .corner_radius(8.0)
                            .inner_margin(8.0);
                        frame.show(ui, |ui| {
                            ui.label(egui::RichText::new(text).color(egui::Color32::WHITE));
                        });
                    });
                } else {
                    // Left-aligned, dark gray
                    let frame = egui::Frame::new()
                        .fill(egui::Color32::from_rgb(50, 50, 50))
                        .corner_radius(8.0)
                        .inner_margin(8.0);
                    frame.show(ui, |ui| {
                        ui.label(egui::RichText::new(text).color(egui::Color32::LIGHT_GRAY));
                    });
                }
                ui.add_space(4.0);
            }
        });

    ui.separator();

    // Compose area
    ui.horizontal(|ui| {
        let response = ui.add(
            egui::TextEdit::singleline(&mut app.draft)
                .hint_text("Type a message...")
                .desired_width(ui.available_width() - 80.0),
        );

        let send_clicked = ui
            .add_sized([64.0, 36.0], egui::Button::new("Send"))
            .clicked();

        let enter_pressed = response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

        if (send_clicked || enter_pressed) && !app.draft.is_empty() {
            let draft = app.draft.clone();
            app.draft.clear();
            send_message(app, draft.as_bytes());
            // Re-focus the text field after sending
            response.request_focus();
        }
    });
}
