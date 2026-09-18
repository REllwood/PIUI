use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderMethod {
    pub id: String,
    pub label: String,
    pub classification: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderView {
    pub id: String,
    pub name: String,
    pub connected: bool,
    pub account_label: Option<String>,
    pub methods: Vec<ProviderMethod>,
    pub model_count: u16,
}

impl ProviderView {
    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty()
            || self.id.len() > 128
            || self.name.chars().count() > 160
            || self.model_count > 512
            || self.methods.is_empty()
            || self.methods.len() > 8
            || self
                .account_label
                .as_ref()
                .is_some_and(|label| label.chars().count() > 160)
        {
            return Err("provider-record-invalid".into());
        }
        if self.methods.iter().any(|method| {
            !matches!(method.id.as_str(), "subscription" | "api-key" | "ambient")
                || !matches!(
                    method.classification.as_str(),
                    "recommended" | "supported" | "fallback"
                )
        }) {
            return Err("provider-method-invalid".into());
        }
        Ok(())
    }
}
