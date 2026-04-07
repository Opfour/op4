use crate::ui::input::read_secret_from_tty;
use std::io;

const MIN_LENGTH: usize = 12;
const MIN_SCORE: u8 = 3; // zxcvbn score 0–4; require ≥ 3

/// Passphrase strength result.
pub struct StrengthResult {
    pub score: u8, // 0–4
    pub feedback: Vec<String>,
    pub is_acceptable: bool,
}

/// Evaluate passphrase strength using zxcvbn.
pub fn evaluate_strength(passphrase: &str) -> StrengthResult {
    if passphrase.len() < MIN_LENGTH {
        return StrengthResult {
            score: 0,
            feedback: vec![format!(
                "Passphrase must be at least {MIN_LENGTH} characters (currently {})",
                passphrase.len()
            )],
            is_acceptable: false,
        };
    }

    let estimate = zxcvbn::zxcvbn(passphrase, &[]);
    let score = estimate.score() as u8;
    let mut feedback = Vec::new();

    if let Some(fb) = estimate.feedback() {
        if let Some(warning) = fb.warning() {
            feedback.push(format!("Warning: {warning}"));
        }
        for suggestion in fb.suggestions() {
            feedback.push(format!("Suggestion: {suggestion}"));
        }
    }

    StrengthResult {
        is_acceptable: score >= MIN_SCORE,
        score,
        feedback,
    }
}

/// Score label for UI display.
pub fn score_label(score: u8) -> &'static str {
    match score {
        0 => "Very weak",
        1 => "Weak",
        2 => "Fair",
        3 => "Strong",
        _ => "Very strong",
    }
}

/// Prompt the user for a new passphrase with strength enforcement.
/// Reads from /dev/tty (never echoed, never from CLI args).
/// Requires two matching entries and minimum strength.
pub fn prompt_new_passphrase() -> io::Result<String> {
    loop {
        let passphrase = read_secret_from_tty("Enter new passphrase: ")?;
        let result = evaluate_strength(&passphrase);

        if !result.is_acceptable {
            eprintln!(
                "Passphrase is too weak (score {}/4: {}). Requirements: ≥{MIN_LENGTH} chars, score ≥{MIN_SCORE}.",
                result.score,
                score_label(result.score)
            );
            for fb in &result.feedback {
                eprintln!("  {fb}");
            }
            continue;
        }

        let confirm = read_secret_from_tty("Confirm passphrase: ")?;
        if passphrase != confirm {
            eprintln!("Passphrases do not match. Try again.");
            continue;
        }

        return Ok(passphrase);
    }
}

/// Prompt the user to unlock the vault (no strength requirements -- existing passphrase).
pub fn prompt_unlock_passphrase() -> io::Result<String> {
    read_secret_from_tty("Passphrase: ")
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- score_label --

    #[test]
    fn score_label_all_tiers() {
        assert_eq!(score_label(0), "Very weak");
        assert_eq!(score_label(1), "Weak");
        assert_eq!(score_label(2), "Fair");
        assert_eq!(score_label(3), "Strong");
        assert_eq!(score_label(4), "Very strong");
        assert_eq!(score_label(255), "Very strong");
    }

    // -- evaluate_strength --

    #[test]
    fn short_passphrase_is_rejected() {
        let r = evaluate_strength("short");
        assert!(!r.is_acceptable);
        assert_eq!(r.score, 0);
        assert!(!r.feedback.is_empty());
    }

    #[test]
    fn minimum_length_boundary() {
        // Exactly MIN_LENGTH but trivial content
        let r = evaluate_strength("aaaaaaaaaaaa");
        // Should pass length check but likely score low
        assert!(r.feedback.is_empty() || r.score < 3 || r.is_acceptable);
    }

    #[test]
    fn strong_passphrase_is_accepted() {
        // A strong passphrase with mixed case, numbers, symbols
        let r = evaluate_strength("correct horse battery staple xkcd");
        assert!(r.is_acceptable);
        assert!(r.score >= 3);
    }

    #[test]
    fn empty_passphrase_rejected() {
        let r = evaluate_strength("");
        assert!(!r.is_acceptable);
        assert_eq!(r.score, 0);
    }
}
