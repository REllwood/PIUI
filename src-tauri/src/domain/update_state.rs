use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpdateStatus {
    Disabled,
    ManualCheck,
    Checking,
    Available,
    Downloading,
    Verifying,
    Ready,
    Installing,
    VerificationFailed,
    InstallFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateState {
    pub status: UpdateStatus,
    pub endpoint: Option<String>,
    pub public_key: Option<String>,
}

impl Default for UpdateState {
    fn default() -> Self {
        Self {
            status: UpdateStatus::Disabled,
            endpoint: None,
            public_key: None,
        }
    }
}

impl UpdateState {
    pub fn activated(&self) -> bool {
        self.endpoint.as_deref().is_some_and(valid_update_endpoint)
            && self.public_key.as_deref().is_some_and(valid_public_key)
    }

    pub fn request_check(&mut self) -> Result<(), String> {
        if !self.activated() {
            self.status = UpdateStatus::Disabled;
            return Err("update-prerequisites-incomplete".into());
        }
        self.status = UpdateStatus::Checking;
        Ok(())
    }

    pub fn verification_failed(&mut self) {
        self.status = UpdateStatus::VerificationFailed;
    }
    pub fn may_install(&self) -> bool {
        self.activated() && self.status == UpdateStatus::Ready
    }
}

pub fn valid_update_endpoint(endpoint: &str) -> bool {
    if endpoint.len() > 2_048 || !endpoint.is_ascii() {
        return false;
    }
    let Ok(parsed) = url::Url::parse(endpoint) else {
        return false;
    };
    parsed.scheme() == "https"
        && parsed.host_str().is_some()
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.fragment().is_none()
}

pub fn valid_public_key(key: &str) -> bool {
    key.len() == 64 && key.bytes().all(|byte| byte.is_ascii_hexdigit())
}
