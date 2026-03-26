// op4-android: Android APK with egui UI and arti Tor transport.

pub mod hardening;
pub mod transport;
pub mod ui;

/// Android entry point.
///
/// Called by the android-activity glue crate when the app launches.
/// Sets up hardening, resolves app-private directories, and starts
/// the eframe event loop with the op4 UI.
#[cfg(target_os = "android")]
#[no_mangle]
fn android_main(app: android_activity::AndroidApp) {
    use std::path::PathBuf;

    // 1. Apply security hardening before anything else.
    match hardening::apply_all_android_hardening() {
        Ok(root_status) => {
            if root_status != hardening::RootStatus::NotRooted {
                log::warn!("Device appears rooted — proceed with caution");
            }
        }
        Err(e) => {
            log::error!("Hardening failed: {e}");
            // Fail closed: do not continue if hardening fails.
            return;
        }
    }

    // 2. Resolve app-private directories from the Android context.
    //    android_activity provides internal_data_path and cache_dir.
    let data_dir = app
        .internal_data_path()
        .unwrap_or_else(|| PathBuf::from("/data/data/org.op4.messenger/files"));
    let cache_dir = app
        .external_cache_dir()
        .unwrap_or_else(|| data_dir.join("cache"));

    let vault_path = op4_core::storage::get_vault_path_android(&data_dir);

    // 3. Launch eframe with the op4 UI.
    let options = eframe::NativeOptions {
        renderer: eframe::Renderer::Wgpu,
        ..Default::default()
    };

    eframe::run_native(
        "op4",
        options,
        Box::new(move |_cc| {
            Ok(Box::new(ui::Op4App::new(vault_path, data_dir, cache_dir)))
        }),
    )
    .expect("eframe failed to start");
}
