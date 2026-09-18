use super::schema::OnboardingRecord;

const STEPS: [&str; 6] = ["welcome", "check", "import", "connect", "project", "ready"];

pub fn validate_onboarding(record: &OnboardingRecord) -> Result<(), String> {
    if record.completed_steps.len() > STEPS.len() {
        return Err("onboarding-state-invalid".into());
    }
    for (index, completed) in record.completed_steps.iter().enumerate() {
        if STEPS.get(index).copied() != Some(completed.as_str()) {
            return Err("onboarding-state-invalid".into());
        }
    }
    if record.finished && record.completed_steps.len() != STEPS.len() {
        return Err("onboarding-state-invalid".into());
    }
    Ok(())
}
