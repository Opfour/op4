use op4_core::error::HardeningError;

/// Android memory hardening — applied at startup before any sensitive allocations.
///
/// Mirrors the Linux build's `apply_memory_hardening()` with Android-specific
/// adjustments:
/// - PR_SET_DUMPABLE = 0: works via NDK bionic libc (same as Linux)
/// - RLIMIT_CORE = 0: works via NDK bionic libc (same as Linux)
/// - mlockall: SKIPPED — Android SELinux policy denies it from app processes.
///   `zeroize` + `ZeroizeOnDrop` on all secret types remains the primary
///   protection against swap exposure. Modern Android devices use encrypted
///   swap, which provides equivalent protection.
/// - PR_SET_NO_NEW_PRIVS: prevents privilege escalation even if exploited.
///   Already implied by Android's zygote seccomp, but explicit is better.
pub fn apply_android_memory_hardening() -> Result<(), HardeningError> {
    // 1. Prevent ptrace attachment and suppress core dumps.
    let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if ret != 0 {
        return Err(HardeningError::PrctlFailed(ret));
    }

    // 2. Belt-and-suspenders: zero RLIMIT_CORE even if PR_SET_DUMPABLE
    //    is somehow bypassed.
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) };
    if ret != 0 {
        return Err(HardeningError::SetrlimitFailed(ret));
    }

    // 3. mlockall — SKIP on Android.
    //    Android's SELinux policy denies mlockall from app processes.
    //    zeroize remains the primary protection against swap exposure.
    //    On devices with encrypted swap (most modern Android), this is
    //    acceptable.
    log::info!("mlockall skipped (Android SELinux denies it); zeroize compensates");

    // 4. Prevent privilege escalation.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        log::warn!("PR_SET_NO_NEW_PRIVS failed (ret={ret}); non-fatal on Android");
    }

    Ok(())
}
