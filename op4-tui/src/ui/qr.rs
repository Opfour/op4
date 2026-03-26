//! Terminal QR code renderer.
//!
//! Converts arbitrary string data into a sequence of ratatui [`Line`]s using
//! Unicode half-block characters (`▀` / `▄` / `█` / space) so that two QR
//! rows fit in one terminal row.  Each dark module is rendered with a black
//! background; each light module with a white background.  Both foreground and
//! background colours are set explicitly so the output is readable regardless
//! of the terminal's colour theme.
//!
//! The quiet zone (2 QR modules on every side) is always included.
//!
//! # Example (approximate output dimensions)
//! A bootstrap code of ~170 bytes encoded as base58 (~170 chars) produces a
//! QR code at error-correction level M, version 7 (45×45 modules).  With a
//! 2-module quiet zone the grid becomes 49×49 modules, rendered as
//! **49 chars wide × 25 terminal rows**.

use ratatui::{
    style::{Color, Style},
    text::{Line, Span},
};

/// Render `data` as a QR code and return the result as ratatui [`Line`]s.
///
/// Returns a single-element error vec when QR generation fails.
/// The quiet zone (2 modules each side) is included.  Uses ECL M for a good
/// balance of size vs. scan reliability.
pub fn qr_lines(data: &str) -> Vec<Line<'static>> {
    let code = match qrcode::QrCode::with_error_correction_level(data, qrcode::EcLevel::M) {
        Ok(c) => c,
        Err(_) => {
            return vec![Line::from(Span::raw(
                "[QR generation failed — data may be too large]",
            ))]
        }
    };

    let w = code.width();
    let dark: Vec<bool> = code
        .into_colors()
        .into_iter()
        .map(|c| matches!(c, qrcode::Color::Dark))
        .collect();

    // 2-module quiet zone on each side (spec recommends 4, but 2 is widely
    // accepted for scanning from screens).
    let qz: usize = 2;
    let total: usize = w + qz * 2;

    // Helper: dark-status of the padded grid (quiet zone = light).
    let get = |row: usize, col: usize| -> bool {
        if row < qz || row >= qz + w || col < qz || col >= qz + w {
            return false; // quiet zone → light
        }
        dark[(row - qz) * w + (col - qz)]
    };

    // Half-block compression: 2 QR rows → 1 terminal row.
    //
    // `▀` = upper half filled by foreground; lower half = background.
    // `▄` = lower half filled by foreground; upper half = background.
    // `█` = fully filled by foreground.
    // ` ` = empty (background only).
    //
    // Colour convention:  dark module → Black;  light module → White.
    //
    // (D, D) → fg=Black  bg=Black  char='█'
    // (D, L) → fg=Black  bg=White  char='▀'  (upper=dark, lower=light)
    // (L, D) → fg=Black  bg=White  char='▄'  (upper=light, lower=dark)
    //              ▄ draws fg in the lower half; bg in the upper half
    // (L, L) → fg=White  bg=White  char=' '

    let out_rows = total.div_ceil(2);
    let mut lines: Vec<Line<'static>> = Vec::with_capacity(out_rows);

    for out_row in 0..out_rows {
        let top_row = out_row * 2;
        let bot_row = out_row * 2 + 1;

        let mut spans: Vec<Span<'static>> = Vec::with_capacity(total);

        for col in 0..total {
            let top = get(top_row, col);
            // When total is odd the last half-row has no bottom partner → light.
            let bot = if bot_row < total {
                get(bot_row, col)
            } else {
                false
            };

            let (ch, fg, bg) = match (top, bot) {
                (true, true) => ('█', Color::Black, Color::Black),
                (true, false) => ('▀', Color::Black, Color::White),
                (false, true) => ('▄', Color::Black, Color::White),
                (false, false) => (' ', Color::White, Color::White),
            };

            spans.push(Span::styled(ch.to_string(), Style::default().fg(fg).bg(bg)));
        }

        lines.push(Line::from(spans));
    }

    lines
}

/// Return the number of terminal **columns** the QR will occupy for `data`
/// (includes 2-module quiet zone on each side).
/// Returns 0 when QR generation would fail.
pub fn qr_terminal_width(data: &str) -> u16 {
    match qrcode::QrCode::with_error_correction_level(data, qrcode::EcLevel::M) {
        Ok(c) => (c.width() + 4) as u16, // +4 = 2 qz left + 2 qz right
        Err(_) => 0,
    }
}

/// Return the number of terminal **rows** the QR will occupy (half-block = ½ height).
/// Returns 0 when QR generation would fail.
pub fn qr_terminal_height(data: &str) -> u16 {
    match qrcode::QrCode::with_error_correction_level(data, qrcode::EcLevel::M) {
        Ok(c) => {
            let total = c.width() + 4;
            total.div_ceil(2) as u16
        }
        Err(_) => 0,
    }
}
