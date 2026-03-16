# AppArmor profile for op4
# Install: sudo apparmor_parser -r /etc/apparmor.d/op4
# Copy this file to /etc/apparmor.d/op4

#include <tunables/global>

profile op4 /usr/local/bin/op4 {
    #include <abstractions/base>
    #include <abstractions/nameservice>

    # ── Executable ────────────────────────────────────────────────────────
    /usr/local/bin/op4  mr,

    # ── Vault and config storage (private to op4 user) ────────────────────
    owner @{HOME}/.local/share/op4/            rw,
    owner @{HOME}/.local/share/op4/**          rw,
    owner @{HOME}/.local/share/op4/vault.op4   rw,
    owner @{HOME}/.local/share/op4/vault.op4.tmp rw,

    # ── Terminal I/O ──────────────────────────────────────────────────────
    /dev/tty                                   rw,
    /dev/pts/[0-9]*                            rw,

    # ── Tor control port cookie (read-only) ──────────────────────────────
    # Required to authenticate to the Tor control port on startup.
    # The file is owned by the debian-tor group; the running user must be
    # a member of that group (setup.sh handles this automatically).
    /run/tor/                   r,
    /run/tor/control.authcookie r,

    # ── Tor SOCKS5 proxy (loopback only) ─────────────────────────────────
    # op4 connects to Tor at 127.0.0.1:9050 only.
    # No direct internet access — all traffic routes through Tor → Nym.
    network inet  stream,
    network inet6 stream,

    # ── Process control ───────────────────────────────────────────────────
    # Allow reading own process info
    @{PROC}/@{pid}/status  r,
    @{PROC}/@{pid}/maps    r,

    # ── System libraries (read-only) ──────────────────────────────────────
    /usr/lib/**             mr,
    /lib/**                 mr,
    /lib64/**               mr,
    /usr/lib64/**           mr,

    # ── Locale and timezone (read-only, needed by some deps) ─────────────
    /usr/share/locale/**    r,
    /usr/share/zoneinfo/**  r,
    /etc/localtime          r,

    # ── Randomness ───────────────────────────────────────────────────────
    /dev/urandom            r,
    /dev/random             r,

    # ── Explicitly denied ─────────────────────────────────────────────────
    # No access to user home directory content except op4's own data dir.
    deny @{HOME}/.ssh/**    rwklx,
    deny @{HOME}/.gnupg/**  rwklx,
    deny @{HOME}/Documents/ rwklx,
    deny @{HOME}/Downloads/ rwklx,

    # No access to /etc credentials or shadow files
    deny /etc/shadow        rwklx,
    deny /etc/passwd        rwklx,

    # No ptrace / debug capabilities
    deny ptrace,
    deny capability sys_ptrace,
    deny capability sys_admin,
}
