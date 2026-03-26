use std::fs::OpenOptions;
use std::io::{self, Read, Write};

/// Read a line from /dev/tty directly, bypassing the terminal readline stack
/// that logging tools and keyloggers typically hook into.
/// Characters are not echoed to the terminal.
///
/// Used exclusively for passphrase input — no secrets accepted via CLI args.
pub fn read_secret_from_tty(prompt: &str) -> io::Result<String> {
    let mut tty = OpenOptions::new().read(true).write(true).open("/dev/tty")?;

    // Print prompt to tty
    write!(tty, "{prompt}")?;
    tty.flush()?;

    // Disable echo using termios
    use libc::{tcgetattr, tcsetattr, termios, ECHO, TCSANOW};
    let mut old_termios: termios = unsafe { std::mem::zeroed() };
    unsafe {
        use std::os::unix::io::AsRawFd;
        let fd = tty.as_raw_fd();
        if tcgetattr(fd, &mut old_termios) != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut new_termios = old_termios;
        new_termios.c_lflag &= !ECHO;
        tcsetattr(fd, TCSANOW, &new_termios);
    }

    let mut input = String::new();
    let mut buf = [0u8; 1];
    loop {
        match tty.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => {
                if buf[0] == b'\n' || buf[0] == b'\r' {
                    break;
                }
                // Reject non-UTF8 bytes silently (prevents injection via terminal sequences)
                if let Ok(ch) = std::str::from_utf8(&buf) {
                    input.push_str(ch);
                }
            }
            Err(e) => {
                // Restore echo before propagating error
                unsafe {
                    use std::os::unix::io::AsRawFd;
                    tcsetattr(tty.as_raw_fd(), TCSANOW, &old_termios);
                }
                return Err(e);
            }
        }
    }

    // Restore echo
    unsafe {
        use std::os::unix::io::AsRawFd;
        libc::tcsetattr(tty.as_raw_fd(), TCSANOW, &old_termios);
    }

    writeln!(tty)?; // newline after hidden input
    Ok(input)
}

/// Strip ANSI escape sequences from untrusted content before display.
/// Prevents terminal manipulation via crafted message content.
///
/// This is called on ALL incoming message content before rendering in ratatui.
pub fn sanitize_for_display(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            // ESC: skip until sequence terminator
            match chars.peek() {
                Some('[') => {
                    // CSI sequence: ESC [ ... terminator
                    chars.next(); // consume '['
                    for inner in chars.by_ref() {
                        // CSI sequences end with a byte in 0x40–0x7E
                        if ('\x40'..='\x7e').contains(&inner) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    // OSC sequence: ESC ] ... ST or BEL
                    chars.next(); // consume ']'
                    for inner in chars.by_ref() {
                        if inner == '\x07' || inner == '\u{9C}' {
                            break;
                        }
                        if inner == '\x1b' {
                            chars.next(); // consume trailing '\\'
                            break;
                        }
                    }
                }
                _ => {
                    // Other ESC sequences: skip one more char
                    chars.next();
                }
            }
        } else if ch.is_control() && ch != '\n' && ch != '\t' {
            // Drop other control characters (e.g., BEL, BS, FF)
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_csi_sequences() {
        let input = "\x1b[31mred text\x1b[0m";
        assert_eq!(sanitize_for_display(input), "red text");
    }

    #[test]
    fn strips_osc_sequences() {
        let input = "\x1b]0;window title\x07normal";
        assert_eq!(sanitize_for_display(input), "normal");
    }

    #[test]
    fn preserves_normal_text() {
        let input = "hello world\nline two";
        assert_eq!(sanitize_for_display(input), "hello world\nline two");
    }

    #[test]
    fn drops_control_chars() {
        // BEL (\x07) and BS (\x08) are both control chars that get dropped entirely.
        let input = "hello\x07world\x08!";
        assert_eq!(sanitize_for_display(input), "helloworld!");
    }
}
