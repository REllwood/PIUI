use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentFact {
    pub key: &'static str,
    pub value: String,
    pub origin: &'static str,
}

pub fn safe_environment() -> Vec<EnvironmentFact> {
    vec![
        EnvironmentFact {
            key: "piuiVersion",
            value: env!("CARGO_PKG_VERSION").into(),
            origin: "bundled-application",
        },
        EnvironmentFact {
            key: "architecture",
            value: std::env::consts::ARCH.into(),
            origin: "native-host",
        },
        EnvironmentFact {
            key: "operatingSystem",
            value: std::env::consts::OS.into(),
            origin: "native-host",
        },
        EnvironmentFact {
            key: "credentialStore",
            value: "present-value-hidden".into(),
            origin: "macos-keychain",
        },
    ]
}
