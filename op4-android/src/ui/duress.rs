use eframe::egui;

/// Duress mode: visually plausible decoy inbox with no real contacts.
/// Indistinguishable from a new, unused messenger installation.
pub fn show(ctx: &egui::Context) {
    egui::TopBottomPanel::top("duress_tabs").show(ctx, |ui| {
        ui.horizontal(|ui| {
            ui.heading("op4");
            ui.separator();
            let _ = ui.selectable_label(true, "Contacts");
            let _ = ui.selectable_label(false, "Messages");
            let _ = ui.selectable_label(false, "Settings");
        });
    });

    egui::CentralPanel::default().show(ctx, |ui| {
        ui.add_space(40.0);
        ui.vertical_centered(|ui| {
            ui.label("No contacts yet.");
            ui.add_space(12.0);
            ui.label("Add a contact to get started.");
        });
    });
}
