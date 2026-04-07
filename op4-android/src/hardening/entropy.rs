use op4_core::error::HardeningError;

/// Verify entropy source quality on Android.
///
/// op4 relies on getrandom(2) / /dev/urandom for all key generation.
/// The `getrandom` Rust crate automatically uses getrandom(2) on Android.
///
/// This sanity check reads 32 bytes and verifies they are not all zeros,
/// catching broken RNG implementations (rare but catastrophic if missed).
pub fn verify_entropy_source() -> Result<(), HardeningError> {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).map_err(|_| HardeningError::EntropyUnavailable)?;

    // All-zero output from a CSPRNG indicates a broken implementation.
    // Probability of legitimate all-zero: 2^-256 — effectively impossible.
    if buf.iter().all(|&b| b == 0) {
        log::error!("CSPRNG returned all-zero bytes — entropy source is broken");
        return Err(HardeningError::EntropyUnavailable);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_source_works_on_desktop() {
        // getrandom(2) is available on Linux -- should succeed
        assert!(verify_entropy_source().is_ok());
    }
}
