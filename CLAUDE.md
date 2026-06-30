# op4 -- Secure Terminal Messenger

Rust workspace: terminal-based E2E encrypted messaging over Tor with post-quantum cryptography.

## Workspace Crates

- **op4-core** -- Crypto (Double Ratchet + X25519 + ML-KEM-768), storage, identity, networking
- **op4-tui** -- Terminal UI
- **op4-android** -- Android target (planned)

## Key Directories

- `src/` -- Main binary entry (main.rs)
- `op4-core/` -- Core library: crypto/, identity/, network/, storage/, hardening/
- `op4-tui/` -- TUI frontend
- `scripts/` -- Build and install scripts
- `install/` -- Installation artifacts
- `docs/` -- Documentation and logo

## Commands

```bash
cargo test --workspace          # Run all tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo build --release
```

## Architecture

- Double Ratchet protocol (Signal-style) for message encryption
- Post-quantum: X25519 + ML-KEM-768 hybrid key exchange
- All traffic routed through Tor hidden services (.onion)
- Local encrypted vault storage, no server
- AppArmor profile in apparmor/

## Rules

- Crypto and security code requires 90%+ test coverage
- Never weaken cryptographic defaults
- Test on real Tor connections before releasing
- v0.3.0 shipped; see docs for deferred items (OPKs, build hash, cover traffic)


## Git Recon (run before reading code)

```bash
# Churn hotspots
git log --format=format: --name-only --since="1 year ago" | sort | uniq -c | sort -nr | head -20
# Bus factor
git shortlog -sn --no-merges
# Bug clusters
git log -i -E --grep="fix|bug|broken" --name-only --format= | sort | uniq -c | sort -nr | head -20
# Activity timeline
git log --format='%ad' --date=format:'%Y-%m' | sort | uniq -c
# Crisis patterns
git log --oneline --since="1 year ago" | grep -iE 'revert|hotfix|emergency|rollback'
```
