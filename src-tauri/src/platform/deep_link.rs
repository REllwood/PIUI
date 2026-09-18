use std::collections::HashSet;
use std::sync::Mutex;

#[derive(Default)]
pub struct OAuthReturnRegistry {
    consumed: Mutex<HashSet<String>>,
}

impl OAuthReturnRegistry {
    pub fn consume(&self, expected_state: &str, returned_state: &str) -> Result<(), String> {
        if expected_state != returned_state
            || expected_state.len() < 32
            || expected_state.len() > 128
            || !expected_state
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err("oauth-return-rejected".into());
        }
        let mut consumed = self
            .consumed
            .lock()
            .map_err(|_| "oauth-return-unavailable")?;
        if !consumed.insert(returned_state.into()) {
            return Err("oauth-return-replayed".into());
        }
        Ok(())
    }
}
