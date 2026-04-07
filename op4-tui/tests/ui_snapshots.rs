//! TUI snapshot tests using insta + ratatui TestBackend.
//!
//! Renders each UI panel into an in-memory terminal buffer and snapshots
//! the output. Any rendering regression shows up as a diff.

use ratatui::backend::TestBackend;
use ratatui::widgets::ListState;
use ratatui::Terminal;

// -- Helper: render to string -------------------------------------------------

fn render_to_string<F>(width: u16, height: u16, draw_fn: F) -> String
where
    F: FnOnce(&mut ratatui::Frame),
{
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(draw_fn).unwrap();
    // Extract the buffer content as a readable string.
    let buf = terminal.backend().buffer().clone();
    let mut output = String::new();
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            let cell = &buf[(x, y)];
            output.push_str(cell.symbol());
        }
        output.push('\n');
    }
    output
}

// -- Contacts panel -----------------------------------------------------------

#[test]
fn snapshot_contacts_empty() {
    let output = render_to_string(40, 10, |f| {
        let mut state = ListState::default();
        op4_tui::ui::contacts::render_contacts(f, &[], &[], &mut state, f.area());
    });
    insta::assert_snapshot!(output);
}

#[test]
fn snapshot_contacts_with_entries() {
    use op4_core::crypto::keys::{HybridKemKeypair, HybridSigningKeypair, PublicKeyBundle};
    use op4_core::identity::profile::StoredContact;

    let bundles: Vec<PublicKeyBundle> = (0..3)
        .map(|i| {
            let kem = HybridKemKeypair::generate();
            let signing = HybridSigningKeypair::generate();
            PublicKeyBundle::from_keypairs(&kem, &signing, [0u8; 32], format!("addr_{i}"))
        })
        .collect();

    let mut contacts = vec![
        StoredContact::new(bundles[0].clone(), "Alice".into(), 0),
        StoredContact::new(bundles[1].clone(), "Bob".into(), 1),
        StoredContact::new(bundles[2].clone(), "Charlie".into(), 2),
    ];
    contacts[0].verified = true; // Alice is verified

    let unread_counts = vec![0, 3, 0];
    let mut state = ListState::default();
    state.select(Some(1)); // highlight Bob

    let output = render_to_string(50, 12, |f| {
        op4_tui::ui::contacts::render_contacts(f, &contacts, &unread_counts, &mut state, f.area());
    });
    insta::assert_snapshot!(output);
}

// -- Conversation panel -------------------------------------------------------

#[test]
fn snapshot_conversation_with_messages() {
    use op4_core::storage::vault::StoredMessage;

    let messages = vec![
        StoredMessage {
            counter: 1,
            content: "Hey, how are you?".into(),
            from_us: false,
        },
        StoredMessage {
            counter: 2,
            content: "Good, you?".into(),
            from_us: true,
        },
        StoredMessage {
            counter: 3,
            content: "Great, thanks!".into(),
            from_us: false,
        },
    ];

    let output = render_to_string(60, 15, |f| {
        op4_tui::ui::conversation::render_conversation(
            f,
            "Alice",
            &messages,
            "typing a reply...",
            "",
            f.area(),
        );
    });
    insta::assert_snapshot!(output);
}

#[test]
fn snapshot_conversation_with_search() {
    use op4_core::storage::vault::StoredMessage;

    let messages = vec![
        StoredMessage {
            counter: 1,
            content: "Hello world".into(),
            from_us: true,
        },
        StoredMessage {
            counter: 2,
            content: "Goodbye world".into(),
            from_us: false,
        },
        StoredMessage {
            counter: 3,
            content: "Hello again".into(),
            from_us: true,
        },
    ];

    let output = render_to_string(60, 15, |f| {
        op4_tui::ui::conversation::render_conversation(
            f,
            "Bob",
            &messages,
            "",
            "hello", // search active
            f.area(),
        );
    });
    insta::assert_snapshot!(output);
}

// -- Duress inbox -------------------------------------------------------------

#[test]
fn snapshot_duress_inbox() {
    let output = render_to_string(70, 12, |f| {
        op4_tui::ui::duress::render_duress_inbox(f, f.area());
    });
    insta::assert_snapshot!(output);
}

// -- Settings panel -----------------------------------------------------------

#[test]
fn snapshot_settings_default() {
    use op4_core::storage::vault::AppSettings;

    let settings = AppSettings::default();
    let mut state = ListState::default();
    state.select(Some(0));

    let output = render_to_string(50, 14, |f| {
        op4_tui::ui::settings::render_settings(f, &settings, &mut state, f.area());
    });
    insta::assert_snapshot!(output);
}

#[test]
fn snapshot_settings_custom() {
    use op4_core::storage::vault::AppSettings;

    let settings = AppSettings {
        tor_socks_addr: "127.0.0.1:9150".into(),
        nym_gateway: Some("gw.example.com".into()),
        default_auto_delete: Some(50),
    };
    let mut state = ListState::default();

    let output = render_to_string(50, 14, |f| {
        op4_tui::ui::settings::render_settings(f, &settings, &mut state, f.area());
    });
    insta::assert_snapshot!(output);
}

// -- QR code ------------------------------------------------------------------

#[test]
fn snapshot_qr_code() {
    let output = render_to_string(60, 30, |f| {
        let lines = op4_tui::ui::qr::qr_lines("op4b2:test_bootstrap_code_data");
        let paragraph = ratatui::widgets::Paragraph::new(lines);
        f.render_widget(paragraph, f.area());
    });
    insta::assert_snapshot!(output);
}

// -- Fingerprint panel --------------------------------------------------------
// Fingerprint values are non-deterministic (random keypairs), so we assert
// structural properties rather than exact snapshots.

#[test]
fn fingerprint_unverified_shows_warning() {
    use op4_core::crypto::keys::{HybridKemKeypair, HybridSigningKeypair, PublicKeyBundle};
    use op4_core::identity::profile::StoredContact;

    let kem = HybridKemKeypair::generate();
    let signing = HybridSigningKeypair::generate();
    let bundle = PublicKeyBundle::from_keypairs(&kem, &signing, [0u8; 32], "peer.onion".into());
    let contact = StoredContact::new(bundle, "Suspect".into(), 0);

    let output = render_to_string(70, 12, |f| {
        op4_tui::ui::contacts::render_fingerprint_panel(f, &contact, f.area());
    });
    assert!(output.contains("FINGERPRINT NOT VERIFIED"), "unverified must show warning");
    assert!(output.contains("Key Fingerprint"), "must show fingerprint panel");
    assert!(output.contains("Fingerprint:"), "must display fingerprint label");
}

#[test]
fn fingerprint_verified_shows_checkmark() {
    use op4_core::crypto::keys::{HybridKemKeypair, HybridSigningKeypair, PublicKeyBundle};
    use op4_core::identity::profile::StoredContact;

    let kem = HybridKemKeypair::generate();
    let signing = HybridSigningKeypair::generate();
    let bundle = PublicKeyBundle::from_keypairs(&kem, &signing, [0u8; 32], "peer.onion".into());
    let mut contact = StoredContact::new(bundle, "Trusted".into(), 0);
    contact.verified = true;

    let output = render_to_string(70, 12, |f| {
        op4_tui::ui::contacts::render_fingerprint_panel(f, &contact, f.area());
    });
    assert!(output.contains("Fingerprint verified"), "verified must show confirmation");
    assert!(!output.contains("FINGERPRINT NOT VERIFIED"), "must not show warning");
    assert!(output.contains("Key Fingerprint"), "must show fingerprint panel");
}
