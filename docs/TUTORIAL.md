# Tutorial — Connecting to Another Person and Messaging Securely

This tutorial walks through the complete flow of setting up op4 for
two people — call them **Alice** and **Bob** — and having them exchange
their first encrypted message.

Both Alice and Bob must complete every step on their own machines.

---

## Prerequisites

Both Alice and Bob must have:

- op4 built and installed (see INSTALL.md)
- Tor running with `ControlPort 9051` and `CookieAuthentication 1`
- Their user account in the `debian-tor` group

---

## Part 1 — First Run (both Alice and Bob)

### 1.1 — Start op4

```bash
op4
```

The terminal will show the source hash and then ask for a passphrase.
Since no vault exists yet, the first-run wizard starts.

```
=============================================================
  op4 — first-run setup
=============================================================

No vault found at /home/alice/.local/share/op4/vault.op4.
Creating a new encrypted vault.

You will set TWO passphrases:
  Normal passphrase  — unlocks your real contacts and messages.
  Duress passphrase  — unlocks a decoy inbox under coercion.
Both look identical from the outside. Only you know which is which.

Requirements: ≥12 characters, zxcvbn strength score ≥ 3 (Strong).

[1/2] Set your NORMAL passphrase:
```

### 1.2 — Set passphrases

Enter a strong normal passphrase (≥12 characters). The strength meter
will reject weak choices — use a passphrase like a random sequence of
words or a long mixed-character string.

Then set a **different** duress passphrase. It must differ from the
normal passphrase.

```
[2/2] Set your DURESS passphrase:
```

### 1.3 — Vault is created

After both passphrases are accepted, the vault is created and Argon2id
runs (takes a few seconds). Then the TUI launches.

```
Generating vault (Argon2id — this takes a few seconds)...
Vault created: /home/alice/.local/share/op4/vault.op4

Setup complete. Starting op4...
```

### 1.4 — Note your .onion address

When op4 starts, two lines are printed to the terminal (outside the TUI):

```
[op4] Tor hidden service: abc123...xyz.onion:14101
[op4] Descriptor propagation takes ~60 s on first use.
```

This `.onion` address is your **inbox address**. Anyone who knows this
address can send you a message — but only if they also have your
public key (which is part of your contact code, described below).

---

## Part 2 — Exchanging Contact Codes

A **contact code** is a compact, Base58-encoded string that contains your
public keys and your `.onion` address. It is the only thing you need to
share with someone to let them message you.

**Contact codes must be exchanged out-of-band** — meaning through a
channel you already trust. Suitable methods include:

- In person (read it aloud or show a QR code of it)
- Over an already-trusted encrypted channel (Signal, another E2E app)
- Physically written down and handed over

**Do not exchange contact codes over email, SMS, or any unencrypted
channel.** A man-in-the-middle attacker who intercepts and substitutes
the contact code can silently intercept all future messages.

### 2.1 — Show your contact code (Alice)

In the op4 TUI, make sure you are on the **Contacts** tab (press `1`).

Press **`e`** — the "export code" popup appears:

```
┌── Your Contact Code ────────────────────────────────────────────┐
│ Share this code out-of-band (in person, Signal, etc.).          │
│ Never share through an unverified channel.                      │
│                                                                 │
│ <your contact code string appears here>                         │
│                                                                 │
│ Press Esc to close.                                             │
└─────────────────────────────────────────────────────────────────┘
```

Copy or write down the entire contact code string. It is a long
Base58 string (roughly 200–300 characters).

### 2.2 — Share contact codes

Alice sends her contact code to Bob, and Bob sends his contact code to
Alice. Use whichever out-of-band method you trust.

---

## Part 3 — Adding Each Other as Contacts

### 3.1 — Add Bob's contact code (Alice's machine)

In the Contacts tab, press **`a`**. A popup appears:

```
┌── Add Contact ──────────────────────────────────────────────────┐
│ Paste the contact's contact code below, then press Enter.       │
│ Press Esc to cancel.                                            │
│                                                                 │
│ _                                                               │
└─────────────────────────────────────────────────────────────────┘
```

Type or paste Bob's contact code, then press **Enter**.

If the code is valid, Bob is added to Alice's contact list with a
default name (e.g. "Contact 1"). The status bar confirms:

```
Contact added. Press [v] to verify fingerprint out-of-band.
```

### 3.2 — Repeat on Bob's machine

Bob does the same: press `a`, paste Alice's contact code, press Enter.

### 3.3 — Rename contacts (optional, not yet in UI)

Contact renaming will be available in a future release. For now,
contacts are named "Contact 1", "Contact 2", etc.

---

## Part 4 — Verifying Each Other's Fingerprint

This step protects you against a man-in-the-middle attack where someone
substituted a fake contact code during the exchange. It confirms you
actually have each other's genuine keys.

### 4.1 — View the fingerprint (Alice)

In the Contacts tab, select Bob's entry with `↑`/`↓`, then press
**Enter** to open the fingerprint panel. You will see something like:

```
┌── Contact: Contact 1 ───────────────────────────────────────────┐
│                                                                 │
│  Fingerprint:                                                   │
│  a3f8 c2d1 e5b7 9021 43fc ...                                   │
│                                                                 │
│  Verified: No                                                   │
│                                                                 │
│  v:verify   d:delete   Esc:back                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 — Compare fingerprints out-of-band

Alice reads her displayed fingerprint for Bob's entry out loud to Bob
(over a voice call, in person, etc.). Bob simultaneously checks the
fingerprint displayed for Alice's entry on **his** machine.

If the fingerprints match on both sides, you have confirmed there was
no interception. If they do not match, the contact code was tampered
with — delete the contact and exchange codes again through a more
secure channel.

### 4.3 — Mark as verified

Once fingerprints match, press **`v`** on the contact entry. The
status bar shows:

```
'Contact 1' marked as verified.
```

The fingerprint panel now shows "Verified: Yes". Both Alice and Bob
should do this on their respective machines.

> **This step is important.** An unverified contact means you have added
> their keys but have not confirmed those keys actually belong to the
> person you think they do.

---

## Part 5 — Sending a Message

### 5.1 — Open the conversation

From the Contacts tab with a contact selected, press **`2`** to switch
to the Messages tab. The conversation for the selected contact opens.

### 5.2 — Compose and send

Start typing. Your text appears in the compose field at the bottom of
the screen. Press **Enter** to send.

The message is:

1. Encrypted with a per-message key derived from the Double Ratchet.
2. Authenticated with HMAC-SHA256.
3. Padded to the nearest 512-byte boundary to hide its length.
4. Sent through the Tor SOCKS5 proxy to your contact's `.onion:14101`.

### 5.3 — Receiving messages

Inbound messages arrive at your `.onion` address while op4 is running.
The TUI polls for new messages every 100 milliseconds and displays them
in the conversation view as they arrive.

> **op4 must be running to receive messages.** There is no server to
> buffer messages while you are offline. If your contact sends a message
> while op4 is not running, the send will fail on their end and they
> will need to retry when you are online.

### 5.4 — Press Esc to return

Press **Esc** with an empty compose field to return to the Contacts tab.
Press **Esc** with text in the compose field to clear the draft without
sending.

---

## Part 6 — Key Change Alerts

If a contact reinstalls op4 or regenerates their identity keys, their
contact code changes. When you receive a message from a contact whose
keys have changed, op4 shows a full-screen key change alert:

```
┌── Key Change Alert ─────────────────────────────────────────────┐
│                                                                 │
│  Contact 1's signing key has changed.                           │
│                                                                 │
│  New fingerprint:                                               │
│  9c12 a8ef ...                                                  │
│                                                                 │
│  Verify this fingerprint with your contact out-of-band          │
│  before accepting.                                              │
│                                                                 │
│  [v] Accept new key    [r] Reject and remove contact            │
└─────────────────────────────────────────────────────────────────┘
```

- Press **`v`** to accept the new key after verifying the fingerprint
  with your contact through a trusted channel.
- Press **`r`** to reject the key change and remove the contact.

**Never accept a key change without verifying the fingerprint
out-of-band.** A key change alert that you did not expect could indicate
someone else has obtained your contact's device or is attempting an
impersonation attack.

---

## Security Checklist

Before using op4 for sensitive communications, confirm:

- [ ] Both parties have installed from source and verified the build hash
- [ ] Tor is running on both machines
- [ ] Contact codes were exchanged through a trusted out-of-band channel
- [ ] Fingerprints were verified out-of-band (voice, in person)
- [ ] Both contacts show "Verified: Yes" in the fingerprint panel
- [ ] Neither machine has a weak or reused vault passphrase
- [ ] AppArmor profile is loaded (`sudo aa-status | grep op4`)

---

## Operational Security Notes

- **op4 must be running to receive messages.** Plan with your contact
  to have overlapping online windows.
- **The `.onion` address is your inbox.** It changes if you delete your
  vault and start fresh. Notify contacts and re-exchange codes if this
  happens.
- **Tor hidden service descriptor propagation takes approximately
  60 seconds** on first run with a new key. During this time, contacts
  may not be able to reach you yet. This is normal.
- **Cover traffic is always active** while op4 is running. Dummy
  messages are sent to your own `.onion` at random intervals (mean 30 s)
  to prevent a network observer from detecting periods of real activity.
- **Do not use the duress passphrase to access your real messages.**
  The duress vault is independent of the real vault and contains
  no real data.
