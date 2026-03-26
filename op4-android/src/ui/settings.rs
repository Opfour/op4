use eframe::egui;

use op4_core::network::Transport;

use super::{ContactMode, Op4App, SettingsEditMode};

pub fn show(app: &mut Op4App, ui: &mut egui::Ui) {
    ui.heading("Settings");
    ui.separator();

    let vault = match app.vault.as_ref() {
        Some(v) => v,
        None => return,
    };

    // Auto-delete setting
    let auto_del = vault
        .payload
        .settings
        .default_auto_delete
        .map(|n| format!("{n} messages"))
        .unwrap_or_else(|| "disabled".into());
    ui.horizontal(|ui| {
        ui.label(format!("Auto-delete after: {auto_del}"));
        if ui.button("Edit").clicked() {
            app.edit_buf = vault
                .payload
                .settings
                .default_auto_delete
                .map(|n| n.to_string())
                .unwrap_or_default();
            app.settings_edit = SettingsEditMode::EditAutoDelete;
        }
    });

    ui.separator();

    // Key management
    ui.label("Key Management");
    ui.horizontal(|ui| {
        if ui.button("Rotate Identity Keys").clicked() {
            app.settings_edit = SettingsEditMode::ConfirmRotate;
        }
        if ui.button("Revoke Key").clicked() {
            app.settings_edit = SettingsEditMode::ConfirmRevoke;
        }
    });

    ui.separator();

    // Export contact code
    if ui.button("Export My Contact Code").clicked() {
        app.tab = super::Tab::Contacts;
        app.contact_mode = ContactMode::ExportCode;
    }

    // Refresh Tor circuit
    if ui.button("Refresh Tor Circuit").clicked() {
        if let Some(ref transport) = app.transport {
            transport.signal_newnym();
            app.status = "Circuit refresh requested.".into();
        }
    }

    // Edit / confirm dialogs
    match app.settings_edit.clone() {
        SettingsEditMode::EditAutoDelete => {
            egui::Window::new("Auto-Delete Threshold")
                .collapsible(false)
                .show(ui.ctx(), |ui| {
                    ui.label("Enter message count (blank = disable):");
                    ui.add(
                        egui::TextEdit::singleline(&mut app.edit_buf)
                            .desired_width(100.0),
                    );
                    ui.horizontal(|ui| {
                        if ui.button("Save").clicked() {
                            let vault = app.vault.as_mut().unwrap();
                            vault.payload.settings.default_auto_delete = if app.edit_buf.trim().is_empty() {
                                None
                            } else {
                                app.edit_buf.trim().parse::<u32>().ok()
                            };
                            vault.save().ok();
                            app.settings_edit = SettingsEditMode::None;
                            app.status = "Auto-delete updated.".into();
                        }
                        if ui.button("Cancel").clicked() {
                            app.settings_edit = SettingsEditMode::None;
                        }
                    });
                });
        }
        SettingsEditMode::ConfirmRotate => {
            egui::Window::new("Confirm Key Rotation")
                .collapsible(false)
                .show(ui.ctx(), |ui| {
                    ui.colored_label(
                        egui::Color32::YELLOW,
                        "Rotate your identity keys?\n\n\
                         This generates a new keypair, sends a revocation certificate\n\
                         to all contacts, and invalidates your current contact code.",
                    );
                    ui.horizontal(|ui| {
                        if ui.button("Confirm").clicked() {
                            // TODO: implement key rotation
                            app.settings_edit = SettingsEditMode::None;
                            app.status = "Key rotation not yet implemented on Android.".into();
                        }
                        if ui.button("Cancel").clicked() {
                            app.settings_edit = SettingsEditMode::None;
                        }
                    });
                });
        }
        SettingsEditMode::ConfirmRevoke => {
            egui::Window::new("Confirm Key Revocation")
                .collapsible(false)
                .show(ui.ctx(), |ui| {
                    ui.colored_label(
                        egui::Color32::RED,
                        "Revoke your current identity key?\n\n\
                         This sends a retirement revocation certificate to all contacts.\n\
                         Use Rotate instead to replace the key with a new one.",
                    );
                    ui.horizontal(|ui| {
                        if ui.button("Confirm").clicked() {
                            // TODO: implement key revocation
                            app.settings_edit = SettingsEditMode::None;
                            app.status = "Key revocation not yet implemented on Android.".into();
                        }
                        if ui.button("Cancel").clicked() {
                            app.settings_edit = SettingsEditMode::None;
                        }
                    });
                });
        }
        SettingsEditMode::None => {}
    }
}
