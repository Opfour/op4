# op4 — Tester Guide

This guide is for people helping to test op4 before a wider release.
It covers setup, what to test, known issues, and scope.

---

## Prerequisites

You will need:

- **Linux** (Ubuntu 22.04+ or equivalent; tested on x86-64)
- **Rust 1.88.0** — install via [rustup](https://rustup.rs), then run:
  ```
  rustup toolchain install 1.88.0
  ```
- **Tor daemon** running locally with the control port enabled.
  Add to `/etc/tor/torrc` and restart Tor:
  ```
  ControlPort 9051
  CookieAuthentication 1
  ```
  Then add yourself to the `debian-tor` group and log out/in:
  ```
  sudo adduser $USER debian-tor
  ```
- **Two computers** (or two separate user accounts on one machine) to
  test two-party messaging.

---

## Building

```bash
git clone <repo>
cd op4
cargo build
```

The binary is at `target/debug/op4`.

---

## First Run

On first launch op4 will:

1. Create an encrypted vault at `~/.local/share/op4/vault.op4`
2. Ask you to set a **normal passphrase** (≥12 characters, strength ≥ 3)
3. Ask you to set a **duress passphrase** (must differ from normal)
4. Generate all identity keypairs and store them in the vault

**What to verify:**

- [ ] The vault file is created at the expected path
- [ ] Weak passphrases are rejected with a strength meter
- [ ] The normal and duress passphrases must differ
- [ ] The app starts and shows the Contacts tab after setup

---

## Contacts

### Adding a contact

1. On machine A, go to Contacts tab → press `[e]` to export your contact code
2. Copy the displayed code
3. On machine B, press `[a]`, paste the code, press Enter
4. Machine B should show machine A as an unverified contact

**What to verify:**

- [ ] Invalid contact codes are rejected with an error
- [ ] The new contact appears in the list with `⚠ UNVERIFIED` indicator
- [ ] Pressing `[v]` marks the contact as verified (✓ shown)
- [ ] Pressing `[d]` removes the contact

### Fingerprint verification

After adding a contact, compare fingerprints out-of-band:

1. Select the contact, press Enter to show the fingerprint panel
2. Compare the displayed fingerprint with the peer's own fingerprint
3. If they match, press `[v]` to mark as verified

**What to verify:**

- [ ] Fingerprint panel shows the same value on both machines
- [ ] Unverified contacts show a yellow warning banner
- [ ] Verified contacts show a green confirmation

---

## Messaging

### Sending the first message

1. After adding a contact, switch to the Messages tab (`[2]`)
2. Type a message and press Enter

On the first message op4 performs an X3DH-style handshake and starts
the Double Ratchet. Subsequent messages use the ratchet directly.

**What to verify:**

- [ ] The message appears in the conversation view immediately (from_us)
- [ ] The peer receives the message and it appears in their conversation
- [ ] Replying and receiving a reply works correctly
- [ ] The conversation persists after restarting op4

### Message persistence

- [ ] Close op4, reopen it, unlock with your passphrase
- [ ] Messages from the previous session are visible in the conversation

---

## Settings Tab

Navigate to Settings with `[3]` or `Tab`.

| Item | Key | Expected Behaviour |
|---|---|---|
| Tor SOCKS5 address | Enter | Opens text edit popup; save changes to vault |
| Auto-delete threshold | Enter | Opens number edit; blank = disabled |
| Rotate identity keys | Enter | Confirmation popup; `y` generates new keys and broadcasts revocation |
| Revoke & announce | Enter | Confirmation popup; `y` sends retirement revocation to all contacts |
| Export contact code | Enter | Opens contact code popup (same as `[e]` in Contacts) |

**What to verify:**

- [ ] Tor address edit saves correctly and is shown updated in the list
- [ ] Auto-delete edit saves (0 or blank = disabled, number = threshold)
- [ ] Key rotation generates a new contact code (visible via `[e]`)
- [ ] Revocation confirmation can be cancelled with Esc or `n`

---

## Duress Vault

The duress passphrase unlocks a decoy empty inbox that looks identical
to the real vault.

**What to verify:**

- [ ] Unlock with your duress passphrase — the inbox is empty
- [ ] The TUI looks visually identical to the normal inbox
- [ ] After sending messages in the real vault, save, then reopen:
  the duress vault still shows an empty inbox (duress section is preserved)
- [ ] Unlocking with the normal passphrase after duress unlock still works

---

## Network / Tor

**What to verify:**

- [ ] The app connects to Tor on startup (no fatal error)
- [ ] Your Tor hidden service address (`.onion`) appears in your contact code
- [ ] Messages are transmitted and received through Tor (check: no direct
  TCP connections between the two test machines at the OS level)

---

## OS Hardening

These are automatic — just verify no unexpected crashes or warnings.

- [ ] App starts without `mlockall` warning on a non-container system
- [ ] Core dump is disabled (`/proc/$(pidof op4)/coredump_filter` = 0)
- [ ] No crash under normal usage related to seccomp

---

## Known Scope Limitations

These are **not bugs** for this testing round — they are known limitations:

- The Nym gateway field in Settings has no edit popup yet (label only).
- Inbound revocation certificates are received but not yet acted upon
  in the TUI (contacts are not auto-updated on rotation).
- There is no QR code display for contact codes; you must copy the
  Base58 text manually.
- Cover traffic (Poisson dummy messages) is active; you may see Tor
  traffic even when idle — this is intentional.
- The app does not compile on macOS or Windows (Linux-only seccomp/prctl).

---

## Reporting Issues

Please file issues at: https://github.com/Opfour/op4/issues

Include:
- What you did (steps to reproduce)
- What you expected
- What happened instead
- Any error output from the terminal

---

## Quick Reference: Keyboard Shortcuts

| Context | Key | Action |
|---|---|---|
| Any | `Ctrl+C` | Quit |
| Any | `1` / `2` / `3` | Switch to Contacts / Messages / Settings tab |
| Contacts | `a` | Add contact (paste contact code) |
| Contacts | `e` | Export your contact code |
| Contacts | `v` | Mark selected contact as verified |
| Contacts | `d` | Delete selected contact |
| Contacts | `p` | Review pending inbound contact requests |
| Contacts | `↑` / `↓` | Navigate contact list |
| Contacts | Enter | Show fingerprint panel |
| Messages | Type | Compose message |
| Messages | Enter | Send message |
| Messages | Backspace | Delete last char |
| Messages | Esc | Clear draft / return to Contacts |
| Settings | `↑` / `↓` | Navigate settings list |
| Settings | Enter | Edit/activate selected setting |
| Settings edit | Enter | Save change |
| Settings edit | Esc | Cancel |
| Settings confirm | `y` | Confirm (rotate/revoke) |
| Settings confirm | Esc/`n` | Cancel |
| Key alert | `V` | Accept key change (mark verified) |
| Key alert | `R` | Reject contact (remove) |
