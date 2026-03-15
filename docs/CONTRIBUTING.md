# Contributing to op4

Thank you for considering a contribution. Because op4 handles sensitive
cryptographic material and user privacy, contributions are held to a
high standard. Please read this document before submitting anything.

---

## What Contributions Are Welcome

- Bug fixes (especially correctness bugs in crypto or vault handling)
- Security hardening improvements
- Documentation improvements and corrections
- Completing items marked TODO in the codebase
- New unit tests and integration tests
- Performance improvements that do not change security properties

## What to Discuss First

Before writing code for a significant new feature or a change to any
cryptographic primitive, open an issue and describe what you want to do
and why. Cryptographic changes require careful review and should not
arrive as surprise pull requests.

---

## Development Setup

```bash
# Clone the repository
git clone <repo-url>
cd op4

# Install the pinned toolchain (automatic via rust-toolchain.toml)
rustup show

# Install cargo-deny for licence and advisory checks
cargo install cargo-deny

# Check for compilation errors
cargo check

# Run tests
cargo test

# Run lints (must pass with zero warnings)
cargo clippy --all-targets -- -D warnings

# Check formatting
cargo fmt --check

# Run all pre-commit checks together
cargo check && cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check
```

---

## Code Standards

### Formatting and lints

- All code must be formatted with `cargo fmt`.
- `cargo clippy --all-targets -- -D warnings` must produce zero
  warnings. Warnings are treated as errors.
- The `#![allow(dead_code)]` crate-level attribute is present during
  development and will be removed once all modules are wired together.

### Security-sensitive code

- Never add cryptographic primitives that are not from the RustCrypto
  ecosystem without a strong justification and explicit maintainer
  approval.
- Never add `unsafe` blocks without a detailed safety comment explaining
  why the invariant holds.
- Never log or print secret key material, passphrases, or vault
  plaintext.
- All new external dependencies must pass `cargo deny check`.

### Error handling

- Use the existing error types in `src/error.rs`.
- Propagate errors with `?`. Do not use `.unwrap()` or `.expect()` in
  production code paths (only in tests and code that provably cannot
  fail, with a comment).

### Memory handling

- Zeroize sensitive values when they are no longer needed. Use the
  `zeroize` crate's `ZeroizeOnDrop` derive or the `Zeroize` trait.
- Do not copy secret key bytes into `String` or other types that do not
  implement `Zeroize`.

---

## Testing

Every bug fix should include a test that fails before the fix and passes
after. New features should include unit tests covering the happy path
and relevant error paths.

Run the full test suite before submitting:

```bash
cargo test
```

---

## Submitting Changes

1. Fork the repository and create a branch named
   `fix/short-description` or `feature/short-description`.
2. Make your changes following the code standards above.
3. Run all checks (fmt, clippy, test).
4. Open a pull request with:
   - A clear description of what the change does and why.
   - A note on any security implications.
   - Reference to the issue it closes (if applicable).

---

## Licence

By submitting a contribution you agree that your work will be released
under the GNU Affero General Public License v3.0, the same licence as
the rest of the project.
