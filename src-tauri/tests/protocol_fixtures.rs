use piui_lib::protocol::{MAX_LINE_BYTES, ProtocolDecoder};
use serde::Deserialize;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../packages/protocol/fixtures")
}

fn lines(path: &Path) -> Vec<Vec<u8>> {
    let raw = fs::read(path).expect("fixture readable");
    if path.file_name().and_then(|name| name.to_str()) == Some("invalid-oversized.jsonl") {
        let directive: Value = serde_json::from_slice(&raw).expect("directive JSON");
        let bytes = directive["bytes"].as_u64().expect("byte count") as usize;
        return vec![format!("{{\"value\":\"{}\"}}\n", "x".repeat(bytes)).into_bytes()];
    }
    raw.split_inclusive(|byte| *byte == b'\n')
        .map(ToOwned::to_owned)
        .collect()
}

#[test]
fn protocol_fixtures_match_expected_outcomes() {
    let mut entries = fs::read_dir(fixture_root())
        .expect("fixture directory")
        .map(|entry| entry.expect("entry").path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        if path.extension().and_then(|ext| ext.to_str()) != Some("jsonl") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy();
        let expected = name.starts_with("valid-");
        let mut decoder = ProtocolDecoder::default();
        let accepted = lines(&path)
            .into_iter()
            .all(|line| decoder.decode(&line).is_ok());
        assert_eq!(accepted, expected, "fixture {name} outcome differed");
    }
}

#[derive(Deserialize)]
struct DivergenceFixture {
    name: String,
    valid: bool,
    #[serde(default)]
    line: Option<String>,
    #[serde(default)]
    file: Option<String>,
}

#[test]
fn protocol_fixtures_shared_divergence_matches_typescript_verdicts() {
    let fixtures: Vec<DivergenceFixture> = serde_json::from_slice(
        &fs::read(fixture_root().join("divergence-verdicts.json"))
            .expect("divergence fixtures readable"),
    )
    .expect("divergence fixtures valid");
    for fixture in fixtures {
        let bytes = if let Some(file) = fixture.file {
            fs::read(fixture_root().join(file)).expect("referenced fixture readable")
        } else {
            fixture.line.unwrap_or_default().into_bytes()
        };
        let accepted = ProtocolDecoder::default().decode(&bytes).is_ok();
        assert_eq!(
            accepted, fixture.valid,
            "shared fixture {} diverged",
            fixture.name
        );
    }
}

#[test]
fn line_limit_is_exact() {
    let mut decoder = ProtocolDecoder::default();
    assert!(decoder.decode(&vec![b'x'; MAX_LINE_BYTES + 1]).is_err());
}
