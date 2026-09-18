use piui_lib::platform::{finder, opener, trash};
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

fn fixture_root(label: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "piui-platform-ops-{}-{}-{label}",
        std::process::id(),
        NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).expect("platform fixture directory should be created");
    root.canonicalize()
        .expect("platform fixture should resolve canonically")
}

#[test]
fn disclosed_external_urls_are_narrow_and_unambiguous() {
    for accepted in [
        "https://example.test/help",
        "http://127.0.0.1:4312/device-return",
    ] {
        assert_eq!(
            opener::DisclosedExternalUrl::parse(accepted)
                .expect("URL should be accepted")
                .as_str(),
            accepted
        );
    }
    for rejected in [
        "file:///Users/example/.ssh/id_ed25519",
        "javascript:alert(1)",
        "https://user@example.test/private",
        "https://example.test/path with spaces",
        "https://example.test\nhttps://attacker.test",
    ] {
        assert!(opener::DisclosedExternalUrl::parse(rejected).is_err());
    }
}

#[test]
fn finder_targets_must_resolve_inside_the_held_capability() {
    let root = fixture_root("finder");
    let child = root.join("notes.txt");
    fs::write(&child, b"fixture").expect("finder fixture should be written");
    assert_eq!(
        finder::capability_backed_path(&root, &child).expect("child should resolve"),
        child.canonicalize().expect("child should canonicalise")
    );
    assert!(finder::capability_backed_path(&root, std::path::Path::new("/etc/hosts")).is_err());
}

#[test]
fn trash_requires_an_inactive_enumerated_identity_and_fresh_confirmation() {
    let root = fixture_root("trash");
    let source = root.join("session.jsonl");
    let trash_root = root.join("Trash");
    fs::create_dir(&trash_root).expect("trash fixture directory should be created");
    fs::write(&source, b"session fixture").expect("session fixture should be written");
    let confirmation = trash::confirmation(
        "session-01",
        "dev:1:ino:2:size:15",
        "0123456789abcdef0123456789abcdef",
    )
    .expect("confirmation should be created");

    assert!(
        trash::move_enumerated_inactive_session(
            &source,
            &trash_root,
            "session-01",
            "dev:1:ino:2:size:15",
            &confirmation,
            true,
        )
        .is_err()
    );
    assert!(
        trash::move_enumerated_inactive_session(
            &source,
            &trash_root,
            "session-01",
            "changed-identity",
            &confirmation,
            false,
        )
        .is_err()
    );
    let moved = trash::move_enumerated_inactive_session(
        &source,
        &trash_root,
        "session-01",
        "dev:1:ino:2:size:15",
        &confirmation,
        false,
    )
    .expect("fresh inactive session should move");
    assert!(!source.exists());
    assert!(moved.starts_with(&trash_root));
    assert_eq!(
        fs::read(moved).expect("moved fixture should remain intact"),
        b"session fixture"
    );
}
