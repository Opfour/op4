use op4_core::error::HardeningError;

/// Runtime integrity checks for the Android build.
///
/// Called at startup before vault unlock. If any check fails, the app
/// refuses to proceed — an attached debugger or injected framework can
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
/// behavior at runtime. Detection is best-effort — a sophisticated
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
