use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const CURRENT_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ThemePreference {
    System,
    Light,
    Dark,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppPreferences {
    pub theme: ThemePreference,
    pub advanced_mode: bool,
    #[serde(default = "default_true")]
    pub restore_last_project: bool,
    pub increased_contrast: bool,
    pub reduce_transparency: bool,
    pub reduce_motion: bool,
    pub accessible_transcript: bool,
}

impl Default for AppPreferences {
    fn default() -> Self {
        Self {
            theme: ThemePreference::System,
            advanced_mode: false,
            restore_last_project: true,
            increased_contrast: false,
            reduce_transparency: false,
            reduce_motion: false,
            accessible_transcript: false,
        }
    }
}

const fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OnboardingRecord {
    pub completed_steps: Vec<String>,
    pub finished: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecentWorkspace {
    pub capability_id: String,
    pub display_label: String,
    pub trust_state: String,
    #[serde(default)]
    pub workspace_revision: u64,
    pub last_opened_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowRecord {
    pub width: f64,
    pub height: f64,
    pub maximised: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationData {
    pub version: u16,
    pub preferences: AppPreferences,
    pub onboarding: OnboardingRecord,
    pub recent_workspaces: Vec<RecentWorkspace>,
    pub window: Option<WindowRecord>,
}

impl Default for ApplicationData {
    fn default() -> Self {
        Self {
            version: CURRENT_SCHEMA_VERSION,
            preferences: AppPreferences::default(),
            onboarding: OnboardingRecord {
                completed_steps: Vec::new(),
                finished: false,
            },
            recent_workspaces: Vec::new(),
            window: None,
        }
    }
}

impl ApplicationData {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != CURRENT_SCHEMA_VERSION
            || self.recent_workspaces.len() > 32
            || self.onboarding.completed_steps.len() > 6
            || self.recent_workspaces.iter().any(|workspace| {
                workspace.capability_id.len() > 128
                    || workspace.display_label.chars().count() > 160
                    || !matches!(
                        workspace.trust_state.as_str(),
                        "untrusted" | "trusted" | "revoked"
                    )
            })
            || self.window.as_ref().is_some_and(|window| {
                !window.width.is_finite()
                    || !window.height.is_finite()
                    || !(680.0..=8_192.0).contains(&window.width)
                    || !(560.0..=8_192.0).contains(&window.height)
            })
        {
            return Err("application-data-invalid".into());
        }
        let value = serde_json::to_value(self).map_err(|_| "application-data-invalid")?;
        reject_secret_fields(&value)
    }
}

pub fn reject_secret_fields(value: &Value) -> Result<(), String> {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let normalised = key.to_ascii_lowercase();
                if [
                    "password",
                    "secret",
                    "token",
                    "apikey",
                    "api_key",
                    "authorization",
                    "credential",
                    "refreshtoken",
                    "accesstoken",
                ]
                .iter()
                .any(|forbidden| normalised.contains(forbidden))
                {
                    return Err("application-data-secret-field-rejected".into());
                }
                reject_secret_fields(child)?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for item in items {
                reject_secret_fields(item)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
