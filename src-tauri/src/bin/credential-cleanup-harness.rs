use piui_lib::credentials::KeychainRepository;
use serde::Serialize;
use std::io::{self, Read};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CleanupEvidence {
    schema_version: u8,
    cleanup_succeeded: bool,
    index_absent: bool,
}

fn main() {
    let mut namespace = String::new();
    let passed = io::stdin()
        .take(128)
        .read_to_string(&mut namespace)
        .ok()
        .filter(|_| namespace.ends_with('\n'))
        .and_then(|_| KeychainRepository::for_tests(namespace.trim_end()).ok())
        .and_then(|repository| {
            repository.cleanup_test_repository().ok()?;
            repository
                .test_repository_index_is_absent()
                .ok()
                .filter(|absent| *absent)
        })
        .is_some();
    namespace.clear();
    let evidence = CleanupEvidence {
        schema_version: 1,
        cleanup_succeeded: passed,
        index_absent: passed,
    };
    if let Ok(encoded) = serde_json::to_string(&evidence) {
        println!("{encoded}");
    }
    if !passed {
        std::process::exit(1);
    }
}
