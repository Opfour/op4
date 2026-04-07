use op4_core::error::HardeningError;

/// Runtime integrity checks for the Android build.
///
/// Called at startup before vault unlock. If any check fails, the app
/// refuses to proceed -- an attached debugger or injected framework can
/// read memory and extract vault keys.
pub fn verify_runtime_integrity() -> Result<(), HardeningError> {
    check_no_debugger()?;
    check_no_injection()?;
    Ok(())
}

/// Detect debugger attachment via /proc/self/status TracerPid.
///
/// If TracerPid != 0, a process (debugger, strace, etc.) is attached.
/// This blocks key extraction via ptrace even on rooted devices.
fn check_no_debugger() -> Result<(), HardeningError> {
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|_| HardeningError::IntegrityCheckFailed)?;

    for line in status.lines() {
        if let Some(pid) = line.strip_prefix("TracerPid:\t") {
            if pid.trim() != "0" {
                log::error!("Debugger detected (TracerPid={})", pid.trim());
                return Err(HardeningError::DebuggerDetected);
            }
        }
    }
    Ok(())
}

/// Detect common instrumentation frameworks by scanning /proc/self/maps.
///
/// Checks for:
/// - Frida (dynamic instrumentation toolkit)
/// - Xposed (Android framework hooking)
/// - Substrate (Cydia Substrate)
/// - Gadget (Frida gadget injection)
///
/// These frameworks can hook crypto functions to extract keys or modify
/// behavior at runtime. Detection is best-effort -- a sophisticated
/// attacker can rename libraries, but this raises the bar significantly.
fn check_no_injection() -> Result<(), HardeningError> {
    let maps = std::fs::read_to_string("/proc/self/maps")
        .map_err(|_| HardeningError::IntegrityCheckFailed)?;
    let maps_lower = maps.to_lowercase();

    let suspicious = ["frida", "xposed", "substrate", "gadget"];
    for lib in &suspicious {
        if maps_lower.contains(lib) {
            log::error!("Injection framework detected: {lib}");
            return Err(HardeningError::InjectionDetected);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns true when running under tarpaulin (ptrace-based coverage),
    /// which causes check_no_debugger to detect the tracer.
    fn under_tarpaulin() -> bool {
        std::env::var("TARPAULIN").is_ok() || std::env::var("CARGO_TARPAULIN").is_ok() || {
            // Fallback: check if TracerPid != 0 right now
            std::fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|s| {
                    s.lines()
                        .find(|l| l.starts_with("TracerPid:\t"))
                        .map(|l| l.trim_start_matches("TracerPid:\t").trim() != "0")
                })
                .unwrap_or(false)
        }
    }

    #[test]
    fn no_debugger_on_normal_test_run() {
        if under_tarpaulin() {
            assert!(check_no_debugger().is_err());
            return;
        }
        assert!(check_no_debugger().is_ok());
    }

    #[test]
    fn no_injection_framework_on_desktop() {
        assert!(check_no_injection().is_ok());
    }

    #[test]
    fn verify_runtime_integrity_passes() {
        if under_tarpaulin() {
            assert!(verify_runtime_integrity().is_err());
            return;
        }
        assert!(verify_runtime_integrity().is_ok());
    }
}
