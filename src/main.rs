// Suppress dead-code lint crate-wide: most crypto/network functions are
// defined as the foundation and will be wired up as the app grows.
#![allow(dead_code)]

mod crypto;
mod error;
mod hardening;
mod identity;
mod network;
mod storage;
mod ui;

use std::io::{self, stdout};
use std::path::PathBuf;

use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

use crate::crypto::keys::{HybridKemKeypair, HybridSigningKeypair};
use rand::rngs::OsRng;
use x25519_dalek::StaticSecret;
use crate::error::{AppError, VaultError};
use crate::hardening::memory::apply_memory_hardening;
use crate::hardening::seccomp::install_seccomp_filter;
use crate::network::nym_client::NymClient;
use crate::storage::vault::VaultUnlocked;
use crate::ui::passphrase::{prompt_new_passphrase, prompt_unlock_passphrase};
use zeroize::Zeroizing;

/// Source hash generated at build time by build.rs over all src/**/*.rs files.
/// Users can verify this matches the published release hash.
const SOURCE_HASH: &str = env!("OP4_SOURCE_HASH");

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    // ── 0. Non-interactive flags ──────────────────────────────────────────
    // Handle before memory hardening / vault setup so the installer script
    // can extract the embedded source hash without a full Tor connection.
    //   install/setup.sh uses: op4 --print-hash
    if std::env::args().any(|a| a == "--print-hash") {
        println!("{SOURCE_HASH}");
        return;
    }

    // ── 1. Memory hardening ───────────────────────────────────────────────
    // Must be first — before any sensitive allocations.
    // Disables ptrace, zeroes RLIMIT_CORE, locks pages with mlockall.
    if let Err(e) = apply_memory_hardening() {
        eprintln!("[fatal] Memory hardening failed: {e:?}");
        std::process::exit(1);
    }

    // ── 2. Build integrity ────────────────────────────────────────────────
    eprintln!("op4  source hash: {SOURCE_HASH}");
    eprintln!("     Verify this matches the published release hash before trusting this build.");
    eprintln!();

    // ── 3. Determine vault path ───────────────────────────────────────────
    let vault_path = match get_vault_path() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[fatal] Cannot determine vault path: {e}");
            std::process::exit(1);
        }
    };

    // ── 4. Vault unlock or first-run setup ────────────────────────────────
    // All passphrase I/O happens here, in normal terminal mode, before the
    // TUI alternate screen is entered. Passphrase is read from /dev/tty only.
    let mut vault = if vault_path.exists() {
        match unlock_existing_vault(&vault_path) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[fatal] Vault error: {e}");
                std::process::exit(1);
            }
        }
    } else {
        match create_new_vault(&vault_path) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[fatal] First-run setup failed: {e}");
                std::process::exit(1);
            }
        }
    };

    // ── 5. Initialize ratatui terminal ────────────────────────────────────
    let mut terminal = match setup_terminal() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[fatal] Terminal setup failed: {e}");
            std::process::exit(1);
        }
    };

    // ── 6. Initialize Tor hidden-service transport ────────────────────────
    // Connects to the Tor control port, creates a v3 .onion hidden service,
    // and binds the local inbound listener.  All traffic is routed through
    // the Tor SOCKS5 proxy.  Must complete before the seccomp lock.
    let tor_addr = vault.payload.settings.tor_socks_addr.clone();
    let signing_secret = vault.payload.identity_signing_secret.clone();
    let kem_secret = vault.payload.identity_kem_secret.clone();
    let mut nym = match NymClient::init(&tor_addr, &signing_secret, &kem_secret).await {
        Ok(c) => c,
        Err(e) => {
            restore_terminal(&mut terminal);
            eprintln!("[fatal] Tor transport init failed: {e:?}");
            eprintln!();
            eprintln!("  To fix, add these lines to /etc/tor/torrc and restart Tor:");
            eprintln!("    ControlPort 9051");
            eprintln!("    CookieAuthentication 1");
            eprintln!();
            eprintln!("  Then add yourself to the 'debian-tor' group:");
            eprintln!("    sudo adduser $USER debian-tor");
            eprintln!("  (log out and back in for the group change to take effect)");
            std::process::exit(1);
        }
    };
    // Cache the deterministic onion address in the vault for display.
    vault.payload.nym_address = nym.address.clone();

    // ── 7. Seccomp-bpf allowlist ──────────────────────────────────────────
    // Installed LAST — after all setup is complete. Default action: SIGSYS.
    // Any syscall not in the allowlist kills the process immediately.
    if let Err(e) = install_seccomp_filter() {
        restore_terminal(&mut terminal);
        eprintln!("[fatal] seccomp filter install failed: {e:?}");
        std::process::exit(1);
    }

    // ── 8. TUI event loop ─────────────────────────────────────────────────
    // block_in_place: signals tokio to reschedule other async tasks to worker
    // threads while this thread runs the synchronous TUI loop.
    let result = tokio::task::block_in_place(|| ui::app::run(&mut terminal, vault, &mut nym));

    // ── 9. Restore terminal unconditionally ───────────────────────────────
    restore_terminal(&mut terminal);

    if let Err(e) = result {
        eprintln!("[error] {e}");
        std::process::exit(1);
    }
}

// ─── Vault Helpers ────────────────────────────────────────────────────────────

/// Prompt for passphrase and unlock an existing vault. Allows 3 attempts.
fn unlock_existing_vault(vault_path: &std::path::Path) -> Result<VaultUnlocked, AppError> {
    for attempt in 1u8..=3 {
        let passphrase = Zeroizing::new(prompt_unlock_passphrase().map_err(AppError::Io)?);

        match VaultUnlocked::unlock(vault_path, passphrase.as_bytes()) {
            Ok(vault) => return Ok(vault),
            Err(VaultError::InvalidPassphrase) => {
                if attempt < 3 {
                    eprintln!("Incorrect passphrase ({attempt}/3). Try again.");
                } else {
                    eprintln!("3 incorrect attempts. Exiting.");
                    std::process::exit(1);
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    unreachable!()
}

/// First-run wizard: set passphrases and create vault with decoy (duress) section.
fn create_new_vault(vault_path: &std::path::Path) -> Result<VaultUnlocked, AppError> {
    eprintln!("=============================================================");
    eprintln!("  op4 — first-run setup");
    eprintln!("=============================================================");
    eprintln!();
    eprintln!("No vault found at {}.", vault_path.display());
    eprintln!("Creating a new encrypted vault.");
    eprintln!();
    eprintln!("You will set TWO passphrases:");
    eprintln!("  Normal passphrase  — unlocks your real contacts and messages.");
    eprintln!("  Duress passphrase  — unlocks a decoy inbox under coercion.");
    eprintln!("Both look identical from the outside. Only you know which is which.");
    eprintln!();
    eprintln!("Requirements: ≥12 characters, zxcvbn strength score ≥ 3 (Strong).");
    eprintln!();

    // Normal passphrase
    eprintln!("[1/2] Set your NORMAL passphrase:");
    let normal_pp = Zeroizing::new(prompt_new_passphrase().map_err(AppError::Io)?);

    eprintln!();

    // Duress passphrase (must differ from normal)
    eprintln!("[2/2] Set your DURESS passphrase:");
    let duress_pp = loop {
        let pp = Zeroizing::new(prompt_new_passphrase().map_err(AppError::Io)?);
        if pp == normal_pp {
            eprintln!("The duress passphrase must differ from the normal passphrase. Try again.");
        } else {
            break pp;
        }
    };

    // Create vault directory if needed
    if let Some(parent) = vault_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    eprintln!();
    eprintln!("Generating vault (Argon2id — this takes a few seconds)...");

    let mut vault = VaultUnlocked::create(vault_path, normal_pp.as_bytes(), duress_pp.as_bytes())?;

    // Generate identity keypairs and store them in the vault.
    eprintln!("Generating identity keypairs...");
    let kem_keypair = HybridKemKeypair::generate();
    let signing_keypair = HybridSigningKeypair::generate();
    let ratchet_secret = StaticSecret::random_from_rng(OsRng);
    vault.payload.identity_kem_secret = Zeroizing::new(kem_keypair.to_bytes());
    vault.payload.identity_signing_secret = Zeroizing::new(signing_keypair.to_bytes());
    vault.payload.identity_ratchet_secret = Zeroizing::new(ratchet_secret.to_bytes().to_vec());
    vault.save().map_err(AppError::from)?;

    eprintln!("Vault created: {}", vault_path.display());
    eprintln!();
    eprintln!("Setup complete. Starting op4...");
    eprintln!();

    Ok(vault)
}

// ─── Terminal Helpers ─────────────────────────────────────────────────────────

type Term = Terminal<CrosstermBackend<io::Stdout>>;

fn setup_terminal() -> io::Result<Term> {
    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;
    Ok(terminal)
}

/// Restore the terminal to its original state.
/// Called both on clean exit and on all error paths.
fn restore_terminal(terminal: &mut Term) {
    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();
}

// ─── Vault Path ───────────────────────────────────────────────────────────────

fn get_vault_path() -> io::Result<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    Ok(PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("op4")
        .join("vault.op4"))
}
