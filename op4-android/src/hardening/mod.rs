pub mod entropy;
pub mod integrity;
pub mod memory;
pub mod root;
pub mod storage;

use op4_core::error::HardeningError;

/// Full Android hardening startup sequence.
///
/// Must be called BEFORE any secrets are loaded or vault is unlocked.
/// Order matters — see plan Phase 4 startup sequence.
pub fn apply_all_android_hardening() -> Result<RootStatus, HardeningError> {
    // 1. Verify CSPRNG is seeded
    entropy::verify_entropy_source()?;

    // 2. Memory hardening (PR_SET_DUMPABLE, RLIMIT_CORE, NO_NEW_PRIVS)
    memory::apply_android_memory_hardening()?;

    // 3. Runtime integrity (debugger, injection, APK signature)
    integrity::verify_runtime_integrity()?;

    // 4. Root detection (non-fatal — warn only)
    let root_status = root::check_root_status();

    Ok(root_status)
}

pub use root::RootStatus;
