use std::path::Path;

/// Ensure vault file has restrictive permissions (0600).
///
/// Android's app sandbox already enforces per-UID file access, but
/// explicit chmod prevents accidental exposure if the file is ever
/// moved or the device is accessed via recovery/root.
///
/// Defense-in-depth: even with 0600 bypassed, the vault is still
/// encrypted with Argon2id + ChaCha20-Poly1305.
pub fn restrict_vault_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(metadata) = std::fs::metadata(path) {
        let mut perms = metadata.permissions();
        perms.set_mode(0o600);
        if let Err(e) = std::fs::set_permissions(path, perms) {
            log::warn!("Failed to set vault permissions to 0600: {e}");
        }
    }
}
