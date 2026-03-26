/// Root detection result.
///
/// op4 WARNS but does not refuse to run on rooted devices — the user may
/// have legitimate reasons (e.g. GrapheneOS, which is actually more secure
/// than stock Android).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootStatus {
    NotRooted,
    PossiblyRooted(String),
    Rooted(String),
}

/// Detect if the device is rooted and return a status for the UI to display.
///
/// A rooted device undermines Android's app sandbox. However, op4's vault
/// encryption (Argon2id + ChaCha20-Poly1305) still protects data — an
/// attacker with root access still needs the passphrase.
///
/// Checks:
/// 1. `su` binary in common locations
/// 2. Magisk files
/// 3. System build tags ("test-keys" vs "release-keys")
pub fn check_root_status() -> RootStatus {
    // 1. Check for su binary
    let su_paths = [
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/system/su",
        "/data/local/su",
        "/data/local/bin/su",
    ];
    for path in &su_paths {
        if std::path::Path::new(path).exists() {
            log::warn!("Root detected: su binary found at {path}");
            return RootStatus::Rooted(format!("su binary found at {path}"));
        }
    }

    // 2. Check for Magisk
    let magisk_paths = ["/sbin/.magisk", "/data/adb/magisk"];
    for path in &magisk_paths {
        if std::path::Path::new(path).exists() {
            log::warn!("Root detected: Magisk found at {path}");
            return RootStatus::Rooted(format!("Magisk found at {path}"));
        }
    }

    // 3. Check build tags via /system/build.prop
    if let Ok(props) = std::fs::read_to_string("/system/build.prop") {
        for line in props.lines() {
            if line.starts_with("ro.build.tags=") && line.contains("test-keys") {
                log::warn!("Root indicator: build signed with test-keys");
                return RootStatus::PossiblyRooted("build signed with test-keys".into());
            }
        }
    }

    RootStatus::NotRooted
}
