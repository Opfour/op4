pub mod vault;

use std::io;
use std::path::PathBuf;

/// Platform-aware vault path.
///
/// - **Linux/Desktop**: `$HOME/.local/share/op4/vault.op4`
/// - **Android**: caller must use `AndroidApp::internal_data_path()` and pass it
///   via `get_vault_path_android()` — the generic function is not used on Android.
pub fn get_vault_path() -> io::Result<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    Ok(PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("op4")
        .join("vault.op4"))
}

/// Android vault path — called with the app-private internal data directory.
///
/// Path: `<internal_data_path>/vault.op4`
/// Android enforces per-app file access via UID + SELinux labels.
#[cfg(target_os = "android")]
pub fn get_vault_path_android(internal_data_path: &std::path::Path) -> PathBuf {
    internal_data_path.join("vault.op4")
}
