use super::redact::redact_text;
use std::collections::VecDeque;
use std::sync::Mutex;

const MAX_LOG_LINES: usize = 2_000;

#[derive(Default)]
pub struct SafeLogBuffer {
    lines: Mutex<VecDeque<String>>,
}

impl SafeLogBuffer {
    pub fn push(&self, line: &str) -> Result<(), String> {
        let mut lines = self
            .lines
            .lock()
            .map_err(|_| "diagnostic-log-unavailable")?;
        lines.push_back(redact_text(line));
        while lines.len() > MAX_LOG_LINES {
            lines.pop_front();
        }
        Ok(())
    }

    pub fn snapshot(&self, maximum: usize) -> Result<Vec<String>, String> {
        let lines = self
            .lines
            .lock()
            .map_err(|_| "diagnostic-log-unavailable")?;
        Ok(lines
            .iter()
            .rev()
            .take(maximum.min(MAX_LOG_LINES))
            .rev()
            .cloned()
            .collect())
    }
}
