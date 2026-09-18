use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckStatus {
    NotRun,
    Running,
    Pass,
    Warning,
    Fail,
    Offline,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticCheck {
    pub id: &'static str,
    pub label: &'static str,
    pub status: CheckStatus,
    pub detail: String,
    pub recovery: Option<String>,
}

pub fn local_checks(network_available: bool) -> Vec<DiagnosticCheck> {
    let supported_host = cfg!(target_os = "macos") && std::env::consts::ARCH == "aarch64";
    vec![
        DiagnosticCheck {
            id: "host",
            label: "PIUI native host",
            status: if supported_host {
                CheckStatus::Pass
            } else {
                CheckStatus::Fail
            },
            detail: if supported_host {
                "Ready on Apple Silicon macOS.".into()
            } else {
                format!("Unsupported host architecture: {}.", std::env::consts::ARCH)
            },
            recovery: (!supported_host)
                .then(|| "Use the supported Apple Silicon macOS release.".into()),
        },
        DiagnosticCheck {
            id: "sidecar",
            label: "Local Pi helper",
            status: CheckStatus::Pass,
            detail: "Bundled runtime will be validated during the version handshake.".into(),
            recovery: None,
        },
        DiagnosticCheck {
            id: "keychain",
            label: "Credential storage",
            status: CheckStatus::Pass,
            detail: "macOS Keychain is the credential authority.".into(),
            recovery: None,
        },
        DiagnosticCheck {
            id: "network",
            label: "Provider network",
            status: if network_available {
                CheckStatus::NotRun
            } else {
                CheckStatus::Offline
            },
            detail: if network_available {
                "Runs only after a user starts provider sign-in.".into()
            } else {
                "Not run — offline.".into()
            },
            recovery: None,
        },
    ]
}
