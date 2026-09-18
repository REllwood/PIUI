use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceKind {
    Skill,
    Prompt,
    Theme,
    Extension,
    Package,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceRecord {
    pub id: String,
    pub kind: ResourceKind,
    pub project_owned: bool,
    pub trusted: bool,
    pub enabled: bool,
}

impl ResourceRecord {
    pub fn executable(&self) -> bool {
        matches!(self.kind, ResourceKind::Extension | ResourceKind::Package)
    }
    pub fn may_enable(
        &self,
        workspace_trusted: bool,
        advanced_mode: bool,
        risk_acknowledged: bool,
    ) -> bool {
        (!self.project_owned || workspace_trusted)
            && (!self.executable() || (advanced_mode && self.trusted && risk_acknowledged))
    }
}
