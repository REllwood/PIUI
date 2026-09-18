use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Mutex;

#[derive(Debug, Clone)]
pub struct SettingValue {
    pub value: Value,
    pub scope: &'static str,
    pub revision: u64,
}

#[derive(Default)]
pub struct SettingsRegistry {
    values: Mutex<BTreeMap<String, SettingValue>>,
    revision: Mutex<u64>,
}

impl SettingsRegistry {
    pub fn save(
        &self,
        key: String,
        value: Value,
        scope: &'static str,
        expected_revision: u64,
    ) -> Result<SettingValue, String> {
        if !matches!(scope, "global" | "project") || key.is_empty() || key.len() > 128 {
            return Err("setting-invalid".into());
        }
        let mut values = self.values.lock().map_err(|_| "settings-unavailable")?;
        if values.get(&key).map_or(0, |record| record.revision) != expected_revision {
            return Err("setting-save-conflict".into());
        }
        let encoded = serde_json::to_vec(&value).map_err(|_| "setting-invalid")?;
        if encoded.len() > 64 * 1024 {
            return Err("setting-too-large".into());
        }
        let mut revision = self.revision.lock().map_err(|_| "settings-unavailable")?;
        *revision = revision
            .checked_add(1)
            .ok_or("setting-revision-exhausted")?;
        let record = SettingValue {
            value,
            scope,
            revision: *revision,
        };
        values.insert(key, record.clone());
        Ok(record)
    }
}
