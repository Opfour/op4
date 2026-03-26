use op4_core::error::HardeningError;

/// Apply memory hardening at startup (call before any sensitive allocations).
///
/// 1. Disables ptrace attachment and core dumps via PR_SET_DUMPABLE.
/// 2. Sets RLIMIT_CORE to zero (belt-and-suspenders).
/// 3. Locks memory pages with mlockall (warn-only; containers may deny).
pub fn apply_memory_hardening() -> Result<(), HardeningError> {
    disable_ptrace_and_core_dumps()?;
    lock_memory_pages();
    Ok(())
}

fn disable_ptrace_and_core_dumps() -> Result<(), HardeningError> {
    // PR_SET_DUMPABLE = 0: disable ptrace and core dump generation
    let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if ret != 0 {
        return Err(HardeningError::PrctlFailed(errno()));
    }

    // Belt-and-suspenders: also zero the core dump size limit
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) };
    if ret != 0 {
        return Err(HardeningError::SetrlimitFailed(errno()));
    }

    Ok(())
}

fn lock_memory_pages() {
    // Lock current and future pages into RAM to prevent key material being swapped.
    // EPERM is common in containers — warn but do not abort.
    // zeroize provides the primary protection; mlock is defence-in-depth.
    let ret = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
    if ret != 0 {
        eprintln!(
            "[warn] mlockall failed (errno {}): key pages may be swappable. \
             This is normal in containers.",
            errno()
        );
    }
}

fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}
