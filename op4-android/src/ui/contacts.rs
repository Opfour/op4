use eframe::egui;

use op4_core::crypto::ratchet::RatchetState;
use op4_core::identity::profile::{BootstrapCode, ContactCode, StoredContact};

use super::{load_ratchet_secret, sanitize, ContactMode, Op4App, Screen};
use op4_core::storage::vault::StoredMessage;

pub fn show(app: &mut Op4App, ui: &mut egui::Ui) {
    // Key alert takes priority
    if app.screen == Screen::KeyAlert {
        show_key_alert(app, ui);
        return;
    }

    match app.contact_mode.clone() {
        ContactMode::AddContact => show_add_contact(app, ui),
        ContactMode::ExportCode => super::qr::show(app, ui),
        ContactMode::PendingRequest => show_pending_request(app, ui),
        _ => show_contact_list(app, ui),
    }
}

fn show_contact_list(app: &mut Op4App, ui: &mut egui::Ui) {
    if app.vault.is_none() {
        return;
    }

    // Action buttons
    ui.horizontal(|ui| {
        if ui.button("Add Contact").clicked() {
            app.contact_mode = ContactMode::AddContact;
            app.add_contact_buf.clear();
        }
        if ui.button("Export Code").clicked() {
            app.contact_mode = ContactMode::ExportCode;
        }
        let pending = app.pending_handshakes.len();
        if pending > 0 && ui.button(format!("Pending ({pending})")).clicked() {
            app.contact_mode = ContactMode::PendingRequest;
            app.pending_name_buf.clear();
        }
    });

    ui.separator();

    let contacts_empty = app
        .vault
        .as_ref()
        .map(|v| v.payload.contacts.is_empty())
        .unwrap_or(true);

    if contacts_empty {
        ui.label("No contacts yet. Add a contact or share your code.");
        return;
    }

    // Build display data from vault (borrow ends before mutable access)
    let contact_rows: Vec<(usize, String, String, bool)> = {
        let vault = app.vault.as_ref().unwrap();
        vault
            .payload
            .contacts
            .iter()
            .enumerate()
            .map(|(i, contact)| {
                let unread = vault
                    .find_conversation_by_contact(&contact.id)
                    .map(|idx| vault.payload.conversations[idx].unread_count)
                    .unwrap_or(0);

                let mut label = sanitize(&contact.display_name);
                if contact.verified {
                    label.push_str(" \u{2713}");
                } else {
                    label.push_str(" \u{26A0} UNVERIFIED");
                }
                if unread > 0 {
                    label.push_str(&format!(" ({unread})"));
                }
                let fp = contact.bundle.fingerprint();
                (i, label, fp, contact.verified)
            })
            .collect()
    };

    // Contact list
    let show_fp = app.contact_mode == ContactMode::Fingerprint;
    egui::ScrollArea::vertical().show(ui, |ui| {
        for (i, label, fp, verified) in &contact_rows {
            let selected = *i == app.selected_contact;
            let response = ui.selectable_label(selected, label);
            if response.clicked() {
                app.selected_contact = *i;
            }

            if selected && show_fp {
                ui.group(|ui| {
                    if !verified {
                        ui.colored_label(
                            egui::Color32::YELLOW,
                            "\u{26A0} FINGERPRINT NOT VERIFIED \u{2014} MITM POSSIBLE",
                        );
                        ui.label("Compare fingerprint out-of-band before trusting.");
                    } else {
                        ui.colored_label(egui::Color32::GREEN, "\u{2713} Fingerprint verified");
                    }
                    ui.add_space(4.0);
                    ui.monospace(fp);
                });
            }
        }
    });

    // Bottom actions for selected contact
    ui.separator();
    ui.horizontal(|ui| {
        if ui.button("View Fingerprint").clicked() {
            app.contact_mode = if app.contact_mode == ContactMode::Fingerprint {
                ContactMode::List
            } else {
                ContactMode::Fingerprint
            };
        }
        if ui.button("Verify").clicked() {
            let vault = app.vault.as_mut().unwrap();
            if let Some(c) = vault.payload.contacts.get_mut(app.selected_contact) {
                c.verified = true;
                let name = sanitize(&c.display_name);
                vault.save().ok();
                app.status = format!("'{name}' marked as verified.");
            }
        }
        if ui.button("Delete").clicked() {
            let vault = app.vault.as_mut().unwrap();
            if app.selected_contact < vault.payload.contacts.len() {
                vault.payload.contacts.remove(app.selected_contact);
                vault.save().ok();
                let n = vault.payload.contacts.len();
                if n > 0 && app.selected_contact >= n {
                    app.selected_contact = n - 1;
                }
                app.status = "Contact removed.".into();
            }
        }
    });
}

fn show_add_contact(app: &mut Op4App, ui: &mut egui::Ui) {
    ui.heading("Add Contact");
    ui.label("Paste the contact's code below:");
    ui.add_space(8.0);

    ui.add(
        egui::TextEdit::multiline(&mut app.add_contact_buf)
            .hint_text("Contact code or bootstrap code")
            .desired_width(f32::INFINITY)
            .desired_rows(4),
    );

    ui.add_space(8.0);
    ui.horizontal(|ui| {
        if ui.button("Submit").clicked() {
            let code_str = app.add_contact_buf.trim().to_owned();
            app.add_contact_buf.clear();

            if BootstrapCode::is_bootstrap(&code_str) {
                match BootstrapCode::decode(&code_str) {
                    Ok(_bc) => {
                        // TODO: send BundleRequest when transport is wired up
                        app.contact_mode = ContactMode::List;
                        app.status = "Bootstrap code accepted — awaiting response.".into();
                    }
                    Err(_) => {
                        app.status = "Invalid bootstrap code.".into();
                        app.contact_mode = ContactMode::List;
                    }
                }
            } else {
                match ContactCode::decode(&code_str) {
                    Ok(code) => {
                        let vault = app.vault.as_mut().unwrap();
                        let seq = vault.payload.sequence;
                        let label = format!("Contact {}", vault.payload.contacts.len() + 1);
                        let contact = StoredContact::new(code.0, label, seq);
                        vault.payload.contacts.push(contact);
                        let new_idx = vault.payload.contacts.len() - 1;
                        app.selected_contact = new_idx;
                        vault.save().ok();
                        app.contact_mode = ContactMode::List;
                        app.status = "Contact added. Verify fingerprint out-of-band.".into();
                    }
                    Err(_) => {
                        app.status = "Invalid contact code.".into();
                        app.contact_mode = ContactMode::List;
                    }
                }
            }
        }
        if ui.button("Cancel").clicked() {
            app.add_contact_buf.clear();
            app.contact_mode = ContactMode::List;
        }
    });
}

fn show_pending_request(app: &mut Op4App, ui: &mut egui::Ui) {
    ui.heading("Incoming Contact Request");

    if let Some(pending) = app.pending_handshakes.first() {
        let fp = pending.bundle.fingerprint();
        let preview = sanitize(&String::from_utf8_lossy(&pending.plaintext));

        ui.label("An unknown contact wants to message you.");
        ui.add_space(8.0);
        ui.label("Their fingerprint:");
        ui.monospace(&fp);
        ui.add_space(8.0);
        ui.label("Their first message:");
        ui.group(|ui| {
            ui.label(&preview);
        });
        ui.add_space(8.0);
        ui.colored_label(
            egui::Color32::YELLOW,
            "Verify this fingerprint out-of-band before accepting.",
        );
        ui.add_space(8.0);
        ui.label("Enter a name for this contact:");
        ui.add(
            egui::TextEdit::singleline(&mut app.pending_name_buf)
                .hint_text("Contact name")
                .desired_width(300.0),
        );

        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui.button("Accept").clicked() {
                accept_pending(app);
            }
            if ui.button("Reject").clicked() {
                app.pending_handshakes.remove(0);
                app.pending_name_buf.clear();
                app.contact_mode = ContactMode::List;
            }
        });
    } else {
        ui.label("No pending requests.");
        if ui.button("Back").clicked() {
            app.contact_mode = ContactMode::List;
        }
    }
}

fn accept_pending(app: &mut Op4App) {
    let name = app.pending_name_buf.trim().to_owned();
    if name.is_empty() {
        app.status = "Please enter a name.".into();
        return;
    }

    if app.pending_handshakes.is_empty() {
        app.contact_mode = ContactMode::List;
        return;
    }

    let pending = app.pending_handshakes.remove(0);
    app.pending_name_buf.clear();

    let vault = app.vault.as_mut().unwrap();
    let seq = vault.payload.sequence;
    let contact = StoredContact::new(pending.bundle, name.clone(), seq);
    let contact_id = contact.id;
    vault.payload.contacts.push(contact);
    app.selected_contact = vault.payload.contacts.len() - 1;

    // Init Bob's ratchet
    let bob_ratchet_secret = match load_ratchet_secret(vault) {
        Some(s) => s,
        None => {
            app.status = "Key error.".into();
            return;
        }
    };
    let ratchet = RatchetState::init_bob(*pending.session_key_bytes, bob_ratchet_secret);
    let conv_key = vault.derive_conversation_key(&contact_id);
    if let Ok(ratchet_ct) = ratchet.to_encrypted_bytes(&conv_key) {
        let conv = vault.get_or_create_conversation(contact_id);
        conv.ratchet_state_ct = ratchet_ct;
    }

    // Persist initial message
    let text = sanitize(&String::from_utf8_lossy(&pending.plaintext));
    let initial_msg = StoredMessage {
        counter: 1,
        content: text,
        from_us: false,
    };
    vault.save_messages(&contact_id, &[initial_msg]).ok();
    vault.save().ok();

    app.contact_mode = ContactMode::List;
    app.status = format!("Contact '{}' added.", sanitize(&name));
}

fn show_key_alert(app: &mut Op4App, ui: &mut egui::Ui) {
    ui.vertical_centered(|ui| {
        ui.add_space(20.0);
        ui.colored_label(
            egui::Color32::RED,
            egui::RichText::new("\u{26D4} KEY CHANGE DETECTED").size(24.0),
        );
        ui.add_space(12.0);
        ui.label(
            "A contact's key has changed. This could indicate a security \
             compromise or device change.",
        );
        ui.add_space(12.0);
        ui.label("Verify the new fingerprint out-of-band before continuing.");
        ui.add_space(20.0);

        ui.horizontal(|ui| {
            if ui.button("Accept (mark verified)").clicked() {
                let vault = app.vault.as_mut().unwrap();
                if let Some(c) = vault.payload.contacts.get_mut(app.selected_contact) {
                    c.verified = true;
                    vault.save().ok();
                }
                app.screen = Screen::Main;
            }
            if ui.button("Reject (remove contact)").clicked() {
                let vault = app.vault.as_mut().unwrap();
                if app.selected_contact < vault.payload.contacts.len() {
                    vault.payload.contacts.remove(app.selected_contact);
                    vault.save().ok();
                }
                app.screen = Screen::Main;
                app.status = "Contact rejected and removed.".into();
            }
        });
    });
}
