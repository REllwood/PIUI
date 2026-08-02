use crate::credentials::{CredentialError, IndexMaterial, KeychainRepository, SecretMaterial};
use serde::Serialize;
use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};

const CLEANUP_MODE_ARGUMENT: &str = "--a23-cleanup";
const SEED_MODE_ARGUMENT: &str = "--a23-seed-cleanup-fixture";
const INSPECT_MODE_ARGUMENT: &str = "--a23-inspect-cleanup-fixture";
const A23_NAMESPACE_BYTES: usize = 36;
const A23_NAMESPACE_INPUT_BYTES: usize = A23_NAMESPACE_BYTES + 1;
const FIXTURE_REFERENCE: &str = "credential-00000000000000000000000000000023";
const FIXTURE_LABEL: &str = "PIUI A23 cleanup fixture";
const FIXTURE_SECRET: &[u8] = b"PIUI_A23_DISPOSABLE_CLEANUP_FIXTURE";
const FIXTURE_INDEX: &[u8] = br#"{"version":1,"entries":[{"providerId":"a23.cleanup-fixture","credentialId":"credential-00000000000000000000000000000023","type":"api_key"}],"pending":[]}"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MaintenanceMode {
    Cleanup,
    Seed,
    Inspect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MainAction {
    Continue,
    ExitSuccess,
    ExitFailure(MaintenanceFailureCode),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaintenanceFailureCode {
    Arguments,
    Input,
    Output,
    Repository,
    CleanupOperation,
    CleanupIndexReadback,
    SeedIndexMaterial,
    SeedIndexWrite,
    SeedSecretMaterial,
    SeedSecretCreate,
    SeedSecretReadback,
    SeedLabelReadback,
    SeedIndexReadback,
    InspectIndexReadback,
    InspectSecretReadback,
    InspectLabelReadback,
    Invariant,
}

impl MaintenanceFailureCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Arguments => "arguments",
            Self::Input => "input",
            Self::Output => "output",
            Self::Repository => "repository",
            Self::CleanupOperation => "cleanup-operation",
            Self::CleanupIndexReadback => "cleanup-index-readback",
            Self::SeedIndexMaterial => "seed-index-material",
            Self::SeedIndexWrite => "seed-index-write",
            Self::SeedSecretMaterial => "seed-secret-material",
            Self::SeedSecretCreate => "seed-secret-create",
            Self::SeedSecretReadback => "seed-secret-readback",
            Self::SeedLabelReadback => "seed-label-readback",
            Self::SeedIndexReadback => "seed-index-readback",
            Self::InspectIndexReadback => "inspect-index-readback",
            Self::InspectSecretReadback => "inspect-secret-readback",
            Self::InspectLabelReadback => "inspect-label-readback",
            Self::Invariant => "invariant",
        }
    }

    pub const fn stderr_line(self) -> &'static [u8] {
        match self {
            Self::Arguments => b"A23_MAINTENANCE_FAILURE=arguments\n",
            Self::Input => b"A23_MAINTENANCE_FAILURE=input\n",
            Self::Output => b"A23_MAINTENANCE_FAILURE=output\n",
            Self::Repository => b"A23_MAINTENANCE_FAILURE=repository\n",
            Self::CleanupOperation => b"A23_MAINTENANCE_FAILURE=cleanup-operation\n",
            Self::CleanupIndexReadback => b"A23_MAINTENANCE_FAILURE=cleanup-index-readback\n",
            Self::SeedIndexMaterial => b"A23_MAINTENANCE_FAILURE=seed-index-material\n",
            Self::SeedIndexWrite => b"A23_MAINTENANCE_FAILURE=seed-index-write\n",
            Self::SeedSecretMaterial => b"A23_MAINTENANCE_FAILURE=seed-secret-material\n",
            Self::SeedSecretCreate => b"A23_MAINTENANCE_FAILURE=seed-secret-create\n",
            Self::SeedSecretReadback => b"A23_MAINTENANCE_FAILURE=seed-secret-readback\n",
            Self::SeedLabelReadback => b"A23_MAINTENANCE_FAILURE=seed-label-readback\n",
            Self::SeedIndexReadback => b"A23_MAINTENANCE_FAILURE=seed-index-readback\n",
            Self::InspectIndexReadback => b"A23_MAINTENANCE_FAILURE=inspect-index-readback\n",
            Self::InspectSecretReadback => b"A23_MAINTENANCE_FAILURE=inspect-secret-readback\n",
            Self::InspectLabelReadback => b"A23_MAINTENANCE_FAILURE=inspect-label-readback\n",
            Self::Invariant => b"A23_MAINTENANCE_FAILURE=invariant\n",
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CleanupEvidence {
    schema_version: u8,
    cleanup_succeeded: bool,
    index_absent: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SeedEvidence {
    schema_version: u8,
    fixture_seeded: bool,
    index_present: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InspectEvidence {
    schema_version: u8,
    fixture_absent: bool,
    index_absent: bool,
    secret_absent: bool,
    label_absent: bool,
}

enum Evidence {
    Cleanup(CleanupEvidence),
    Seed(SeedEvidence),
    Inspect(InspectEvidence),
}

impl Evidence {
    fn succeeded(&self) -> bool {
        match self {
            Self::Cleanup(evidence) => evidence.cleanup_succeeded && evidence.index_absent,
            Self::Seed(evidence) => evidence.fixture_seeded && evidence.index_present,
            Self::Inspect(evidence) => {
                evidence.fixture_absent
                    && evidence.index_absent
                    && evidence.secret_absent
                    && evidence.label_absent
            }
        }
    }
}

pub fn run_main_arguments<I, R, W>(arguments: I, input: &mut R, output: &mut W) -> MainAction
where
    I: IntoIterator<Item = OsString>,
    R: Read,
    W: Write,
{
    match parse_reserved_mode(arguments) {
        Ok(None) => MainAction::Continue,
        Ok(Some(mode)) => match run_mode(mode, input, output) {
            Ok(()) => MainAction::ExitSuccess,
            Err(code) => MainAction::ExitFailure(code),
        },
        Err(()) => MainAction::ExitFailure(MaintenanceFailureCode::Arguments),
    }
}

pub fn run_cleanup<R: Read, W: Write>(input: &mut R, output: &mut W) -> bool {
    run_mode(MaintenanceMode::Cleanup, input, output).is_ok()
}

pub(crate) fn valid_a23_namespace(namespace: &str) -> bool {
    namespace.len() == A23_NAMESPACE_BYTES
        && namespace.starts_with("a23-")
        && namespace[4..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_reserved_mode<I>(arguments: I) -> Result<Option<MaintenanceMode>, ()>
where
    I: IntoIterator<Item = OsString>,
{
    let mut arguments = arguments.into_iter();
    if arguments.next().is_none() {
        return Err(());
    }
    let Some(first) = arguments.next() else {
        return Ok(None);
    };
    if let Some(mode) = reserved_mode(first.as_os_str()) {
        return if arguments.next().is_none() {
            Ok(Some(mode))
        } else {
            Err(())
        };
    }
    if arguments.any(|argument| reserved_mode(argument.as_os_str()).is_some()) {
        Err(())
    } else {
        Ok(None)
    }
}

fn reserved_mode(argument: &OsStr) -> Option<MaintenanceMode> {
    if argument == OsStr::new(CLEANUP_MODE_ARGUMENT) {
        Some(MaintenanceMode::Cleanup)
    } else if argument == OsStr::new(SEED_MODE_ARGUMENT) {
        Some(MaintenanceMode::Seed)
    } else if argument == OsStr::new(INSPECT_MODE_ARGUMENT) {
        Some(MaintenanceMode::Inspect)
    } else {
        None
    }
}

fn run_mode<R: Read, W: Write>(
    mode: MaintenanceMode,
    input: &mut R,
    output: &mut W,
) -> Result<(), MaintenanceFailureCode> {
    let execution = match read_namespace(input) {
        Ok(namespace) => execute(mode, &namespace),
        Err(()) => Err(MaintenanceFailureCode::Input),
    };
    let (evidence, failure) = match execution {
        Ok(evidence) => (evidence, None),
        Err(code) => (failed_evidence(mode), Some(code)),
    };
    write_evidence(output, &evidence).map_err(|()| MaintenanceFailureCode::Output)?;
    if let Some(code) = failure {
        return Err(code);
    }
    if evidence.succeeded() {
        Ok(())
    } else {
        Err(MaintenanceFailureCode::Invariant)
    }
}

fn read_namespace<R: Read>(input: &mut R) -> Result<String, ()> {
    let mut bytes = Vec::with_capacity(A23_NAMESPACE_INPUT_BYTES + 1);
    input
        .take((A23_NAMESPACE_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() != A23_NAMESPACE_INPUT_BYTES || bytes.last() != Some(&b'\n') {
        return Err(());
    }
    let namespace = std::str::from_utf8(&bytes[..A23_NAMESPACE_BYTES]).map_err(|_| ())?;
    if valid_a23_namespace(namespace) {
        Ok(namespace.to_owned())
    } else {
        Err(())
    }
}

fn execute(mode: MaintenanceMode, namespace: &str) -> Result<Evidence, MaintenanceFailureCode> {
    match mode {
        MaintenanceMode::Cleanup => cleanup(namespace),
        MaintenanceMode::Seed => seed(namespace),
        MaintenanceMode::Inspect => inspect(namespace),
    }
}

fn cleanup(namespace: &str) -> Result<Evidence, MaintenanceFailureCode> {
    let repository =
        KeychainRepository::for_tests(namespace).map_err(|_| MaintenanceFailureCode::Repository)?;
    repository
        .cleanup_test_repository()
        .map_err(|_| MaintenanceFailureCode::CleanupOperation)?;
    let index_absent = repository
        .test_repository_index_is_absent()
        .map_err(|_| MaintenanceFailureCode::CleanupIndexReadback)?;
    if !index_absent {
        return Err(MaintenanceFailureCode::Invariant);
    }
    Ok(Evidence::Cleanup(CleanupEvidence {
        schema_version: 1,
        cleanup_succeeded: true,
        index_absent: true,
    }))
}

fn seed(namespace: &str) -> Result<Evidence, MaintenanceFailureCode> {
    let repository =
        KeychainRepository::for_tests(namespace).map_err(|_| MaintenanceFailureCode::Repository)?;
    let index = IndexMaterial::new(FIXTURE_INDEX.to_vec())
        .map_err(|_| MaintenanceFailureCode::SeedIndexMaterial)?;
    repository
        .write_index(index)
        .map_err(|_| MaintenanceFailureCode::SeedIndexWrite)?;
    let secret = SecretMaterial::new(FIXTURE_SECRET.to_vec())
        .map_err(|_| MaintenanceFailureCode::SeedSecretMaterial)?;
    repository
        .create_at_reference(FIXTURE_REFERENCE, FIXTURE_LABEL, secret)
        .map_err(|_| MaintenanceFailureCode::SeedSecretCreate)?;

    let secret = repository
        .read(FIXTURE_REFERENCE)
        .map_err(|_| MaintenanceFailureCode::SeedSecretReadback)?;
    if secret.expose() != FIXTURE_SECRET {
        return Err(MaintenanceFailureCode::Invariant);
    }
    let metadata = repository
        .metadata(FIXTURE_REFERENCE)
        .map_err(|_| MaintenanceFailureCode::SeedLabelReadback)?;
    if metadata.account_label != FIXTURE_LABEL {
        return Err(MaintenanceFailureCode::Invariant);
    }
    let index_absent = repository
        .test_repository_index_is_absent()
        .map_err(|_| MaintenanceFailureCode::SeedIndexReadback)?;
    if index_absent {
        return Err(MaintenanceFailureCode::Invariant);
    }

    Ok(Evidence::Seed(SeedEvidence {
        schema_version: 1,
        fixture_seeded: true,
        index_present: true,
    }))
}

fn inspect(namespace: &str) -> Result<Evidence, MaintenanceFailureCode> {
    let repository =
        KeychainRepository::for_tests(namespace).map_err(|_| MaintenanceFailureCode::Repository)?;
    let index_absent = repository
        .test_repository_index_is_absent()
        .map_err(|_| MaintenanceFailureCode::InspectIndexReadback)?;
    let secret_absent = match repository.read(FIXTURE_REFERENCE) {
        Err(error) if error == CredentialError::not_found() => true,
        Err(_) => return Err(MaintenanceFailureCode::InspectSecretReadback),
        Ok(_) => false,
    };
    let label_absent = match repository.metadata(FIXTURE_REFERENCE) {
        Err(error) if error == CredentialError::not_found() => true,
        Err(_) => return Err(MaintenanceFailureCode::InspectLabelReadback),
        Ok(_) => false,
    };
    let evidence = Evidence::Inspect(InspectEvidence {
        schema_version: 1,
        fixture_absent: index_absent && secret_absent && label_absent,
        index_absent,
        secret_absent,
        label_absent,
    });
    if evidence.succeeded() {
        Ok(evidence)
    } else {
        Err(MaintenanceFailureCode::Invariant)
    }
}

fn failed_evidence(mode: MaintenanceMode) -> Evidence {
    match mode {
        MaintenanceMode::Cleanup => Evidence::Cleanup(CleanupEvidence {
            schema_version: 1,
            cleanup_succeeded: false,
            index_absent: false,
        }),
        MaintenanceMode::Seed => Evidence::Seed(SeedEvidence {
            schema_version: 1,
            fixture_seeded: false,
            index_present: false,
        }),
        MaintenanceMode::Inspect => Evidence::Inspect(InspectEvidence {
            schema_version: 1,
            fixture_absent: false,
            index_absent: false,
            secret_absent: false,
            label_absent: false,
        }),
    }
}

fn write_evidence<W: Write>(output: &mut W, evidence: &Evidence) -> Result<(), ()> {
    let encoded = match evidence {
        Evidence::Cleanup(evidence) => serde_json::to_vec(evidence),
        Evidence::Seed(evidence) => serde_json::to_vec(evidence),
        Evidence::Inspect(evidence) => serde_json::to_vec(evidence),
    }
    .map_err(|_| ())?;
    output.write_all(&encoded).map_err(|_| ())?;
    output.write_all(b"\n").map_err(|_| ())?;
    output.flush().map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Error};

    #[test]
    fn reserved_modes_require_an_exact_argument_count_and_position() {
        for (argument, expected) in [
            (CLEANUP_MODE_ARGUMENT, MaintenanceMode::Cleanup),
            (SEED_MODE_ARGUMENT, MaintenanceMode::Seed),
            (INSPECT_MODE_ARGUMENT, MaintenanceMode::Inspect),
        ] {
            assert_eq!(
                parse_reserved_mode([OsString::from("piui"), OsString::from(argument)]),
                Ok(Some(expected))
            );
            assert_eq!(
                parse_reserved_mode([
                    OsString::from("piui"),
                    OsString::from(argument),
                    OsString::from("unexpected"),
                ]),
                Err(())
            );
            assert_eq!(
                parse_reserved_mode([
                    OsString::from("piui"),
                    OsString::from("unexpected"),
                    OsString::from(argument),
                ]),
                Err(())
            );
        }
        assert_eq!(parse_reserved_mode([OsString::from("piui")]), Ok(None));
        assert_eq!(
            parse_reserved_mode([OsString::from("piui"), OsString::from("--ordinary")]),
            Ok(None)
        );
        assert_eq!(parse_reserved_mode(Vec::<OsString>::new()), Err(()));
    }

    #[test]
    fn namespace_input_is_one_exact_bounded_line() {
        let valid = "a23-0123456789abcdefabcdef0123456789";
        assert_eq!(valid.len(), A23_NAMESPACE_BYTES);
        assert_eq!(
            read_namespace(&mut Cursor::new(format!("{valid}\n"))).as_deref(),
            Ok(valid)
        );
        for malformed in [
            valid.to_owned(),
            format!("{valid}\r\n"),
            format!("{valid}\n\n"),
            "a24-0123456789abcdefabcdef0123456789\n".to_owned(),
            "a23-0123456789abcdefABCDEF0123456789\n".to_owned(),
            "a23-0123456789abcdefABCDEFG123456789\n".to_owned(),
        ] {
            assert!(read_namespace(&mut Cursor::new(malformed)).is_err());
        }
    }

    #[test]
    fn failure_codes_have_exact_bounded_secret_free_wire_lines() {
        for (code, expected) in [
            (MaintenanceFailureCode::Arguments, "arguments"),
            (MaintenanceFailureCode::Input, "input"),
            (MaintenanceFailureCode::Output, "output"),
            (MaintenanceFailureCode::Repository, "repository"),
            (
                MaintenanceFailureCode::CleanupOperation,
                "cleanup-operation",
            ),
            (
                MaintenanceFailureCode::CleanupIndexReadback,
                "cleanup-index-readback",
            ),
            (
                MaintenanceFailureCode::SeedIndexMaterial,
                "seed-index-material",
            ),
            (MaintenanceFailureCode::SeedIndexWrite, "seed-index-write"),
            (
                MaintenanceFailureCode::SeedSecretMaterial,
                "seed-secret-material",
            ),
            (
                MaintenanceFailureCode::SeedSecretCreate,
                "seed-secret-create",
            ),
            (
                MaintenanceFailureCode::SeedSecretReadback,
                "seed-secret-readback",
            ),
            (
                MaintenanceFailureCode::SeedLabelReadback,
                "seed-label-readback",
            ),
            (
                MaintenanceFailureCode::SeedIndexReadback,
                "seed-index-readback",
            ),
            (
                MaintenanceFailureCode::InspectIndexReadback,
                "inspect-index-readback",
            ),
            (
                MaintenanceFailureCode::InspectSecretReadback,
                "inspect-secret-readback",
            ),
            (
                MaintenanceFailureCode::InspectLabelReadback,
                "inspect-label-readback",
            ),
            (MaintenanceFailureCode::Invariant, "invariant"),
        ] {
            let line = code.stderr_line();
            assert_eq!(code.as_str(), expected);
            assert_eq!(
                line,
                format!("A23_MAINTENANCE_FAILURE={expected}\n").as_bytes()
            );
            assert!(line.len() <= 64);
            assert_eq!(line.iter().filter(|byte| **byte == b'\n').count(), 1);
            assert!(line.ends_with(b"\n"));
            assert!(
                !line
                    .windows(FIXTURE_REFERENCE.len())
                    .any(|window| window == FIXTURE_REFERENCE.as_bytes())
            );
            assert!(
                !line
                    .windows(FIXTURE_SECRET.len())
                    .any(|window| window == FIXTURE_SECRET)
            );
            assert!(
                !line
                    .windows(FIXTURE_LABEL.len())
                    .any(|window| window == FIXTURE_LABEL.as_bytes())
            );
        }
    }

    #[test]
    fn evidence_outputs_are_fixed_safe_json_lines() {
        for (evidence, expected) in [
            (
                Evidence::Cleanup(CleanupEvidence {
                    schema_version: 1,
                    cleanup_succeeded: true,
                    index_absent: true,
                }),
                b"{\"schemaVersion\":1,\"cleanupSucceeded\":true,\"indexAbsent\":true}\n"
                    .as_slice(),
            ),
            (
                Evidence::Seed(SeedEvidence {
                    schema_version: 1,
                    fixture_seeded: true,
                    index_present: true,
                }),
                b"{\"schemaVersion\":1,\"fixtureSeeded\":true,\"indexPresent\":true}\n"
                    .as_slice(),
            ),
            (
                Evidence::Inspect(InspectEvidence {
                    schema_version: 1,
                    fixture_absent: true,
                    index_absent: true,
                    secret_absent: true,
                    label_absent: true,
                }),
                b"{\"schemaVersion\":1,\"fixtureAbsent\":true,\"indexAbsent\":true,\"secretAbsent\":true,\"labelAbsent\":true}\n"
                    .as_slice(),
            ),
        ] {
            let mut output = Vec::new();
            assert!(write_evidence(&mut output, &evidence).is_ok());
            assert_eq!(output, expected);
            assert!(!output
                .windows(FIXTURE_REFERENCE.len())
                .any(|window| window == FIXTURE_REFERENCE.as_bytes()));
            assert!(!output
                .windows(FIXTURE_SECRET.len())
                .any(|window| window == FIXTURE_SECRET));
            assert!(!output
                .windows(FIXTURE_LABEL.len())
                .any(|window| window == FIXTURE_LABEL.as_bytes()));
        }
    }

    #[test]
    fn fixed_fixture_journal_contains_the_exact_valid_reference() {
        let reference = FIXTURE_REFERENCE
            .strip_prefix("credential-")
            .expect("fixed opaque reference prefix");
        assert_eq!(reference.len(), 32);
        assert!(uuid::Uuid::parse_str(reference).is_ok());

        let document: serde_json::Value =
            serde_json::from_slice(FIXTURE_INDEX).expect("fixed journal JSON");
        assert_eq!(
            document,
            serde_json::json!({
                "version": 1,
                "entries": [{
                    "providerId": "a23.cleanup-fixture",
                    "credentialId": FIXTURE_REFERENCE,
                    "type": "api_key"
                }],
                "pending": []
            })
        );
    }

    #[test]
    fn normal_and_argument_rejected_main_paths_do_not_read_stdin() {
        struct Unreadable;

        impl Read for Unreadable {
            fn read(&mut self, _buffer: &mut [u8]) -> Result<usize, Error> {
                panic!("non-maintenance path read stdin")
            }
        }

        let mut input = Unreadable;
        let mut output = Vec::new();
        assert_eq!(
            run_main_arguments([OsString::from("piui")], &mut input, &mut output),
            MainAction::Continue
        );
        assert_eq!(
            run_main_arguments(
                [
                    OsString::from("piui"),
                    OsString::from(CLEANUP_MODE_ARGUMENT),
                    OsString::from("unexpected"),
                ],
                &mut input,
                &mut output,
            ),
            MainAction::ExitFailure(MaintenanceFailureCode::Arguments)
        );
        assert!(output.is_empty());
    }

    #[test]
    fn invalid_namespace_emits_failure_without_touching_keychain() {
        let mut output = Vec::new();
        assert_eq!(
            run_mode(
                MaintenanceMode::Inspect,
                &mut Cursor::new(b"invalid\n"),
                &mut output,
            ),
            Err(MaintenanceFailureCode::Input)
        );
        assert_eq!(
            output,
            b"{\"schemaVersion\":1,\"fixtureAbsent\":false,\"indexAbsent\":false,\"secretAbsent\":false,\"labelAbsent\":false}\n"
        );
    }

    #[test]
    fn input_and_output_failures_have_fixed_main_action_codes() {
        struct RejectedInput;

        impl Read for RejectedInput {
            fn read(&mut self, _buffer: &mut [u8]) -> Result<usize, Error> {
                Err(Error::other("test input rejection"))
            }
        }

        struct RejectedOutput;

        impl Write for RejectedOutput {
            fn write(&mut self, _buffer: &[u8]) -> Result<usize, Error> {
                Err(Error::other("test output rejection"))
            }

            fn flush(&mut self) -> Result<(), Error> {
                panic!("flush must not run after a rejected write")
            }
        }

        let arguments = [
            OsString::from("piui"),
            OsString::from(INSPECT_MODE_ARGUMENT),
        ];
        let mut input = RejectedInput;
        let mut output = Vec::new();
        assert_eq!(
            run_main_arguments(arguments.clone(), &mut input, &mut output),
            MainAction::ExitFailure(MaintenanceFailureCode::Input)
        );
        assert_eq!(
            output,
            b"{\"schemaVersion\":1,\"fixtureAbsent\":false,\"indexAbsent\":false,\"secretAbsent\":false,\"labelAbsent\":false}\n"
        );

        let mut input = Cursor::new(b"invalid\n");
        let mut output = RejectedOutput;
        assert_eq!(
            run_main_arguments(arguments, &mut input, &mut output),
            MainAction::ExitFailure(MaintenanceFailureCode::Output)
        );
    }
}
