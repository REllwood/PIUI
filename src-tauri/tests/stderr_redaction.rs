use piui_lib::supervisor::StderrRedactor;

#[test]
fn stderr_redaction_removes_credentials_headers_queries_and_personal_paths() {
    let redactor = StderrRedactor::with_home("/Users/tester");
    let source = concat!(
        "Authorization: Bearer header-value ",
        "x-api-key=header-key ",
        "access_token=value-one ",
        "password: value-two ",
        "credential=\"correct horse battery staple\" safe-diagnostic\n",
        "https://user:pass@example.test/path?api_key=query-value&token=query-two\n",
        "/Users/tester/Projects/private/file.txt\n",
        "/Users/another-person/My Projects/client records.txt\n",
        "provider unavailable\n",
    );
    let redacted = redactor.redact(source);
    for secret in [
        "header-value",
        "header-key",
        "value-one",
        "value-two",
        "correct horse battery staple",
        "query-value",
        "query-two",
        "user:pass",
        "tester",
        "another-person",
        "private.txt",
        "My Projects",
        "client records.txt",
    ] {
        assert!(
            !redacted.contains(secret),
            "redactor leaked {secret}: {redacted}"
        );
    }
    assert!(redacted.contains("[redacted]"));
    assert!(redacted.contains("safe-diagnostic"));
    assert!(redacted.contains("provider unavailable"));
    assert!(redacted.contains("<home>") || redacted.contains("<user-path>"));
    assert!(!redacted.contains('\n'));
}

#[test]
fn stderr_redaction_preserves_safe_diagnostics_and_bounds_output() {
    let redactor = StderrRedactor::with_home("/Users/tester");
    assert_eq!(
        redactor.redact("provider unavailable"),
        "provider unavailable"
    );
    assert_eq!(redactor.redact(&"é".repeat(600)).chars().count(), 512);
}
