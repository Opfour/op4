use eframe::egui;
use qrcode::QrCode;

use super::{ContactMode, Op4App};

/// Render the export code screen with QR code.
pub fn show(app: &mut Op4App, ui: &mut egui::Ui) {
    ui.heading("Your Contact Code");
    ui.add_space(8.0);

    // Generate and cache QR texture
    if app.qr_texture.is_none() && !app.bootstrap_code.is_empty() {
        if let Some(texture) = generate_qr_texture(ui.ctx(), &app.bootstrap_code) {
            app.qr_texture = Some(texture);
        }
    }

    // Display QR code
    if let Some(ref texture) = app.qr_texture {
        let size = egui::vec2(250.0, 250.0);
        ui.add(egui::Image::new(texture).fit_to_exact_size(size));
    }

    ui.add_space(12.0);

    // Bootstrap code (short, fits in QR)
    ui.label("Bootstrap code (scan QR or copy this):");
    ui.group(|ui| {
        ui.monospace(&app.bootstrap_code);
    });

    ui.add_space(8.0);

    // Full contact code (for manual sharing)
    ui.collapsing("Full contact code (manual sharing)", |ui| {
        ui.monospace(&app.export_code);
    });

    ui.add_space(12.0);
    if ui.button("Close").clicked() {
        app.contact_mode = ContactMode::List;
        app.qr_texture = None;
    }
}

/// Generate a QR code as an egui texture.
fn generate_qr_texture(ctx: &egui::Context, data: &str) -> Option<egui::TextureHandle> {
    let code = QrCode::new(data.as_bytes()).ok()?;
    let module_count = code.width();
    let scale = 4; // pixels per module
    let border = 4 * scale;
    let img_size = module_count * scale + 2 * border;

    let mut pixels = vec![egui::Color32::WHITE; img_size * img_size];

    for y in 0..module_count {
        for x in 0..module_count {
            let color = if code[(x, y)] == qrcode::Color::Dark {
                egui::Color32::BLACK
            } else {
                egui::Color32::WHITE
            };

            for dy in 0..scale {
                for dx in 0..scale {
                    let px = border + x * scale + dx;
                    let py = border + y * scale + dy;
                    pixels[py * img_size + px] = color;
                }
            }
        }
    }

    let image = egui::ColorImage::new([img_size, img_size], pixels);

    Some(ctx.load_texture("qr_code", image, egui::TextureOptions::NEAREST))
}
