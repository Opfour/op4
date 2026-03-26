use eframe::egui;
use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

use op4_core::crypto::keys::{HybridKemKeypair, HybridSigningKeypair};
use op4_core::storage::vault::VaultUnlocked;

use super::{Op4App, Screen};

/// Passphrase entry screen — unlock existing vault or create new one.
pub fn show(app: &mut Op4App, ctx: &egui::Context) {
    egui::CentralPanel::default().show(ctx, |ui| {
        ui.vertical_centered(|ui| {
            ui.add_space(40.0);
            ui.heading("op4");
            ui.label("Post-quantum encrypted messenger");
            ui.add_space(20.0);

            if app.is_new_vault {
                show_create(app, ui);
            } else {
                show_unlock(app, ui);
            }

            if !app.auth_error.is_empty() {
                ui.add_space(10.0);
                ui.colored_label(egui::Color32::RED, &app.auth_error);
            }
        });
    });
}

fn show_unlock(app: &mut Op4App, ui: &mut egui::Ui) {
    ui.label("Enter passphrase to unlock vault:");
    ui.add_space(8.0);

    let response = ui.add(
        egui::TextEdit::singleline(&mut app.passphrase_buf)
            .password(true)
            .hint_text("Passphrase")
            .desired_width(300.0),
    );

    ui.add_space(12.0);
    let unlock_clicked = ui
        .add_sized([200.0, 44.0], egui::Button::new("Unlock"))
        .clicked();

    // Submit on Enter key
    let enter_pressed = response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

    if unlock_clicked || enter_pressed {
        match VaultUnlocked::unlock(&app.vault_path, app.passphrase_buf.as_bytes()) {
            Ok(vault) => {
                app.passphrase_buf.clear();
                if vault.is_duress {
                    app.vault = Some(vault);
                    app.screen = Screen::Duress;
                } else {
                    app.vault = Some(vault);
                    app.refresh_codes();
                    app.start_transport();
                    app.screen = Screen::Main;
                    app.status = "Vault unlocked.".into();
                }
            }
            Err(op4_core::error::VaultError::InvalidPassphrase) => {
                app.auth_error = "Invalid passphrase.".into();
            }
            Err(e) => {
                app.auth_error = format!("Vault error: {e:?}");
            }
        }
    }

    // Focus the text field on first frame
    if app.passphrase_buf.is_empty() {
        response.request_focus();
    }
}

fn show_create(app: &mut Op4App, ui: &mut egui::Ui) {
    ui.label("No vault found. Create a new one:");
    ui.add_space(8.0);

    ui.label("Passphrase:");
    ui.add(
        egui::TextEdit::singleline(&mut app.passphrase_buf)
            .password(true)
            .hint_text("Choose a strong passphrase")
            .desired_width(300.0),
    );

    // Strength indicator
    if !app.passphrase_buf.is_empty() {
        let estimate = zxcvbn::zxcvbn(&app.passphrase_buf, &[]);
        let (color, label) = match estimate.score() {
            zxcvbn::Score::Zero | zxcvbn::Score::One => (egui::Color32::RED, "Weak"),
            zxcvbn::Score::Two => (egui::Color32::from_rgb(255, 165, 0), "Fair"),
            zxcvbn::Score::Three => (egui::Color32::YELLOW, "Good"),
            zxcvbn::Score::Four => (egui::Color32::GREEN, "Strong"),
            _ => (egui::Color32::GREEN, "Strong"),
        };
        let frac = estimate.score() as u8 as f32 / 4.0;
        ui.horizontal(|ui| {
            let bar = egui::ProgressBar::new(frac).fill(color);
            ui.add_sized([200.0, 16.0], bar);
            ui.colored_label(color, label);
        });
    }

    ui.add_space(8.0);
    ui.label("Duress passphrase (opens decoy vault if coerced):");
    ui.add(
        egui::TextEdit::singleline(&mut app.duress_buf)
            .password(true)
            .hint_text("Duress passphrase")
            .desired_width(300.0),
    );

    ui.add_space(12.0);
    if ui
        .add_sized([200.0, 44.0], egui::Button::new("Create Vault"))
        .clicked()
    {
        if app.passphrase_buf.len() < 8 {
            app.auth_error = "Passphrase must be at least 8 characters.".into();
        } else if app.duress_buf.is_empty() {
            app.auth_error = "Duress passphrase is required.".into();
        } else if app.passphrase_buf == app.duress_buf {
            app.auth_error = "Duress passphrase must differ from main passphrase.".into();
        } else {
            // Create parent directory
            if let Some(parent) = app.vault_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            match VaultUnlocked::create(
                &app.vault_path,
                app.passphrase_buf.as_bytes(),
                app.duress_buf.as_bytes(),
            ) {
                Ok(mut vault) => {
                    app.passphrase_buf.clear();
                    app.duress_buf.clear();

                    // Generate identity keypairs (same as TUI create_new_vault)
                    let kem_keypair = HybridKemKeypair::generate();
                    let signing_keypair = HybridSigningKeypair::generate();
                    let ratchet_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
                    vault.payload.identity_kem_secret =
                        Zeroizing::new(kem_keypair.to_bytes());
                    vault.payload.identity_signing_secret =
                        Zeroizing::new(signing_keypair.to_bytes());
                    vault.payload.identity_ratchet_secret =
                        Zeroizing::new(ratchet_secret.to_bytes().to_vec());
                    vault.save().ok();

                    app.vault = Some(vault);
                    app.refresh_codes();
                    app.start_transport();
                    app.screen = Screen::Main;
                    app.status = "Vault created.".into();
                }
                Err(e) => {
                    app.auth_error = format!("Create failed: {e:?}");
                }
            }
        }
    }
}
