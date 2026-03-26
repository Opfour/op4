use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};
use std::collections::BTreeMap;

use op4_core::error::HardeningError;

/// Build and install a seccomp-bpf allowlist filter.
///
/// Must be called AFTER:
///   - memory hardening (prctl, setrlimit)
///   - vault unlock (file I/O)
///   - passphrase read (tty I/O)
///   - Nym SDK init (socket setup, DNS, thread spawn)
///   - ratatui terminal setup (ioctl)
///
/// Default action: Trap (SIGSYS) for any syscall not in the allowlist.
/// A SIGSYS handler prints the offending syscall number to stderr before exit,
/// making it easy to identify any remaining missing allowlist entries.
pub fn install_seccomp_filter() -> Result<(), HardeningError> {
    install_sigsys_handler();
    let filter = build_filter().map_err(HardeningError::SeccompBuild)?;
    seccompiler::apply_filter(&filter).map_err(|e| HardeningError::SeccompInstall(e.to_string()))
}

/// Install a SIGSYS signal handler that prints the blocked syscall number.
///
/// seccomp Trap delivers SIGSYS with si_syscall set to the blocked syscall
/// number. The handler writes it to stderr (async-signal-safe path: write(2))
/// then calls _exit so the message is visible before the process ends.
fn install_sigsys_handler() {
    use libc::{SA_SIGINFO, SIGSYS};
    // SAFETY: standard sigaction registration; handler only calls write/_exit.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_flags = SA_SIGINFO;
        sa.sa_sigaction = sigsys_handler as libc::sighandler_t;
        libc::sigaction(SIGSYS, &sa, std::ptr::null_mut());
    }
}

/// SIGSYS handler: writes "[seccomp] blocked syscall NNN\n" to stderr.
/// Must only call async-signal-safe functions.
extern "C" fn sigsys_handler(
    _sig: libc::c_int,
    info: *mut libc::siginfo_t,
    _ctx: *mut libc::c_void,
) {
    // On x86_64 Linux, SIGSYS siginfo_t has si_syscall (i32) at byte offset 24.
    // This is stable kernel ABI (see sigaction(2) / <sys/siginfo.h>).
    // SAFETY: info pointer is valid and aligned when delivered by the kernel.
    #[cfg(target_arch = "x86_64")]
    let nr = unsafe { ((info as *const u8).add(24) as *const i32).read_unaligned() as u64 };
    #[cfg(not(target_arch = "x86_64"))]
    let nr = {
        let _ = info;
        u64::MAX
    };

    let mut buf = [0u8; 64];
    let prefix = b"[seccomp] blocked syscall ";
    let mut pos = 0usize;
    buf[pos..pos + prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    // Write decimal digits without heap allocation (async-signal-safe).
    let mut tmp = [0u8; 20];
    let mut n = nr;
    let mut len = 0usize;
    if n == 0 || n == u64::MAX {
        tmp[0] = b'?';
        len = 1;
    } else {
        while n > 0 {
            tmp[len] = b'0' + (n % 10) as u8;
            n /= 10;
            len += 1;
        }
        tmp[..len].reverse();
    }
    buf[pos..pos + len].copy_from_slice(&tmp[..len]);
    pos += len;
    buf[pos] = b'\n';
    pos += 1;
    // SAFETY: write(2) is async-signal-safe.
    unsafe { libc::write(2, buf.as_ptr() as *const libc::c_void, pos) };
    unsafe { libc::_exit(159) }; // 128 + SIGSYS(31)
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
        libc::SYS_mremap, // allocator resizes large heap mappings on window resize
        libc::SYS_memfd_create,
        // File I/O (vault, Nym key storage)
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,  // scatter-gather read (Tokio I/O)
        libc::SYS_writev, // scatter-gather write (Tokio I/O, WebSocket frames)
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
        libc::SYS_sendmmsg,   // batch socket send (Nym SDK / WebSocket)
        libc::SYS_recvmmsg,   // batch socket recv (Nym SDK / WebSocket)
        libc::SYS_socketpair, // Tokio internal thread wake-up pipe
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
        // File descriptor operations (Tokio O_NONBLOCK / FD_CLOEXEC)
        libc::SYS_fcntl,
        libc::SYS_dup,
        libc::SYS_dup2,
        libc::SYS_dup3,
        // Tokio reactor internals (eventfd + pipe wakeups)
        libc::SYS_eventfd2,
        libc::SYS_pipe2,
        // Thread / signal stack (Rust thread panic handler)
        libc::SYS_sigaltstack,
        // Memory barrier (crossbeam / Tokio lock-free structures)
        libc::SYS_membarrier,
        // glibc 2.35+ registers a restartable-sequence descriptor
        // in every new thread via rseq(2). Without this, any thread
        // spawned after seccomp installation is killed immediately.
        libc::SYS_rseq,
        // Misc (Rust runtime)
        libc::SYS_getrlimit,
        libc::SYS_setrlimit,
        libc::SYS_prlimit64, // modern resource-limit query; glibc pthread_create
        // calls this to check RLIMIT_STACK on thread spawn
        libc::SYS_uname,
    ];

    let rules_map: BTreeMap<i64, Vec<SeccompRule>> =
        allowed.into_iter().map(|nr| (nr, vec![])).collect();

    let filter: SeccompFilter = SeccompFilter::new(
        rules_map,
        SeccompAction::Trap,
        SeccompAction::Allow,
        std::env::consts::ARCH
            .try_into()
            .map_err(|_| "unsupported target architecture".to_string())?,
    )
    .map_err(|e| e.to_string())?;

    let bpf: BpfProgram = filter.try_into().map_err(|e| format!("{e}"))?;
    Ok(bpf)
}
