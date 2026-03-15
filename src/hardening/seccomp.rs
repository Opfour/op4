use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};
use std::collections::BTreeMap;

use crate::error::HardeningError;

/// Build and install a seccomp-bpf allowlist filter.
///
/// Must be called AFTER:
///   - memory hardening (prctl, setrlimit)
///   - vault unlock (file I/O)
///   - passphrase read (tty I/O)
///   - Nym SDK init (socket setup, DNS, thread spawn)
///   - ratatui terminal setup (ioctl)
///
/// Default action: KillProcess (SIGSYS) for any syscall not in the allowlist.
pub fn install_seccomp_filter() -> Result<(), HardeningError> {
    let filter = build_filter().map_err(HardeningError::SeccompBuild)?;
    seccompiler::apply_filter(&filter).map_err(|e| HardeningError::SeccompInstall(e.to_string()))
}

fn build_filter() -> Result<BpfProgram, String> {
    // Allowlist: empty Vec<SeccompRule> = allow unconditionally
    let allowed: Vec<i64> = vec![
        // Memory management
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mprotect,
        libc::SYS_madvise,
        libc::SYS_brk,
        libc::SYS_mlock,
        libc::SYS_mlockall,
        libc::SYS_memfd_create,
        // File I/O (vault, Nym key storage)
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_openat,
        libc::SYS_close,
        libc::SYS_fstat,
        libc::SYS_stat,
        libc::SYS_lstat,
        libc::SYS_fsync,
        libc::SYS_fdatasync,
        libc::SYS_rename,
        libc::SYS_renameat,
        libc::SYS_unlink,
        libc::SYS_unlinkat,
        libc::SYS_mkdir,
        libc::SYS_mkdirat,
        libc::SYS_lseek,
        libc::SYS_getcwd,
        libc::SYS_getdents64,
        libc::SYS_readlink,
        libc::SYS_readlinkat,
        // Process / threading (Tokio async runtime)
        libc::SYS_futex,
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_set_robust_list,
        libc::SYS_get_robust_list,
        libc::SYS_prctl,
        libc::SYS_arch_prctl,
        libc::SYS_sched_yield,
        libc::SYS_sched_getaffinity,
        // Signals
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_kill,
        libc::SYS_tgkill,
        // Networking (Nym SDK WebSocket, Tor SOCKS5)
        libc::SYS_socket,
        libc::SYS_connect,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_shutdown,
        libc::SYS_poll,
        libc::SYS_ppoll,
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_wait,
        libc::SYS_epoll_pwait,
        libc::SYS_select,
        libc::SYS_pselect6,
        // Time (Tokio timers, Poisson cover traffic)
        libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep,
        libc::SYS_nanosleep,
        libc::SYS_timerfd_create,
        libc::SYS_timerfd_settime,
        libc::SYS_timerfd_gettime,
        // Random (ring, ed25519-dalek, etc.)
        libc::SYS_getrandom,
        // Terminal / TTY (ratatui + crossterm + raw /dev/tty)
        libc::SYS_ioctl,
        // Misc (Rust runtime)
        libc::SYS_getrlimit,
        libc::SYS_setrlimit,
        libc::SYS_uname,
    ];

    let rules_map: BTreeMap<i64, Vec<SeccompRule>> =
        allowed.into_iter().map(|nr| (nr, vec![])).collect();

    let filter: SeccompFilter = SeccompFilter::new(
        rules_map,
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        std::env::consts::ARCH
            .try_into()
            .map_err(|_| "unsupported target architecture".to_string())?,
    )
    .map_err(|e| e.to_string())?;

    let bpf: BpfProgram = filter.try_into().map_err(|e| format!("{e}"))?;
    Ok(bpf)
}
