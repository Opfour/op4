# Running op4

---

## Starting the App

op4 takes no command-line arguments and has no flags. Simply run:

```bash
op4
```

Or, if running directly from the build directory:

```bash
./target/release/op4
```

That is the entire invocation. Everything else is configured through the
settings stored inside the encrypted vault.

---

## What Happens on First Start

1. **Memory hardening** is applied immediately — `mlockall` locks all
   pages in RAM (prevents swap), `RLIMIT_CORE` is set to zero (no core
   dumps), and `PR_SET_DUMPABLE` is cleared (no ptrace).

2. **Source hash** is printed to the terminal so you can verify the
   binary matches the published release.

3. **First-run wizard** runs if no vault exists at
   `~/.local/share/op4/vault.op4`. You will be asked to set **two**
   passphrases:
   - **Normal passphrase** — your real inbox.
   - **Duress passphrase** — a decoy inbox that looks identical. Use
     this if you are forced to unlock the app under coercion.

   Both passphrases must be at least 12 characters long and score ≥ 3
   on the zxcvbn strength estimator. The strength check is enforced;
   weak passphrases are rejected.

4. **Vault is created** and encrypted with Argon2id (64 MiB memory,
   3 iterations). This takes a few seconds — this is intentional, as
   it makes brute-force attacks expensive.

5. **Tor transport initialises** — op4 connects to the Tor control port
   at `127.0.0.1:9051`, authenticates, and creates a v3 hidden service
   (`.onion` address) for your inbox. This address is derived
   deterministically from your identity key, so it is the same every
   time you run op4.

6. **seccomp-bpf syscall filter** is installed. After this point, any
   syscall not on the allowlist causes the process to be killed by the
   kernel immediately.

7. **TUI launches.**

---

## What Happens on Subsequent Starts

1. Memory hardening (same as above).
2. Source hash printed.
3. Passphrase prompt — enter your normal or duress passphrase.
   Three incorrect attempts exits the app.
4. Vault is decrypted and loaded.
5. Tor transport initialises (same `.onion` address as before).
6. seccomp filter installed.
7. TUI launches.

---

## Configuration Variables

op4 has no environment variables or command-line flags. All configuration
is stored inside the encrypted vault and survives across restarts.

The following values are set at build time or have hardcoded defaults:

### Hardcoded network addresses

These are compiled into the binary and cannot be changed at runtime
without rebuilding.

| Setting | Value | Source file |
|---|---|---|
| Tor SOCKS5 proxy | `127.0.0.1:9050` | `storage/vault.rs` (default) |
| Tor control port | `127.0.0.1:9051` | `network/nym_client.rs` |
| Inbound listen port | `14101` (localhost only) | `network/nym_client.rs` |

> The SOCKS5 address is stored in the vault's settings field
> (`AppSettings::tor_socks_addr`) and defaults to `127.0.0.1:9050`. In
> a future release this will be editable from the Settings tab.

### Hardcoded crypto parameters

| Parameter | Value |
|---|---|
| Argon2id memory | 64 MiB |
| Argon2id iterations | 3 |
| Argon2id parallelism | 1 |
| AEAD algorithm | ChaCha20-Poly1305 |
| Message block size | 512 bytes |
| Max message size | 4096 bytes (8 blocks) |
| Cover traffic mean interval | 30 seconds (Poisson) |

### Vault path

The vault is always stored at:

```
~/.local/share/op4/vault.op4
```

This path is derived from the `$HOME` environment variable and cannot
be changed at runtime.

---

## Keyboard Reference

op4 is entirely keyboard-driven. The mouse is not used.

### Global (any tab)

| Key | Action |
|---|---|
| `1` | Switch to Contacts tab |
| `2` | Switch to Messages tab |
| `3` | Switch to Settings tab |
| `Tab` | Switch to next tab (when compose field is empty) |
| `Ctrl+C` | Quit immediately |
| `q` | Quit (from Contacts or Settings tab) |

### Contacts tab

| Key | Action |
|---|---|
| `↑` / `↓` | Navigate contact list |
| `Enter` | View contact fingerprint |
| `a` | Add a contact (paste their contact code) |
| `e` | Show your contact code (share this with others) |
| `v` | Mark selected contact as fingerprint-verified |
| `d` | Delete selected contact |
| `Esc` | Go back / cancel current action |

### Add Contact popup

| Key | Action |
|---|---|
| Type | Enter the contact's contact code |
| `Enter` | Confirm and add contact |
| `Esc` | Cancel |
| `Backspace` | Delete last character |

### Messages tab

| Key | Action |
|---|---|
| Type | Compose message |
| `Enter` | Send message |
| `Backspace` | Delete last character |
| `Esc` (empty draft) | Return to Contacts tab |
| `Esc` (non-empty draft) | Clear the draft |

### Settings tab

| Key | Action |
|---|---|
| `↑` / `↓` | Navigate settings list |
| `Enter` | Select / activate setting |
| `1` | Go to Contacts tab |
| `q` | Quit |

### Key change alert (overlays all tabs)

When a contact's key has changed, an alert appears over the screen.

| Key | Action |
|---|---|
| `v` | Accept the new key and re-verify the contact |
| `r` | Reject the key change and remove the contact |

---

## Duress Mode

If you enter your **duress passphrase** at the unlock prompt, op4 opens
a visually identical TUI showing an empty inbox. There is no visible
difference between normal and duress mode from the outside.

In duress mode, `q` or `Ctrl+C` exits the app normally.

---

## Stopping op4

Press `q` from the Contacts or Settings tab, or press `Ctrl+C` from
anywhere. The vault is saved to disk before the process exits.

When the process exits, the Tor control connection is closed and Tor
automatically removes the hidden service. Your `.onion` address is
no longer reachable until you run op4 again.

---

## Errors on Startup

### Tor transport init failed

```
[fatal] Tor transport init failed: NymInit("Cannot connect to Tor control port...")
```

Tor is not running, or `ControlPort 9051` is not enabled. See INSTALL.md.

### Vault error

```
[fatal] Vault error: InvalidPassphrase
```

Wrong passphrase entered three times. Restart and try again.

```
[fatal] Vault error: InvalidVersion
```

The vault was created by a different version of op4. Recreate the vault
or downgrade/upgrade to the matching version.

### seccomp filter install failed

```
[fatal] seccomp filter install failed
```

The kernel does not support seccomp-bpf (requires Linux 3.5+). This
should not happen on any modern distribution.
