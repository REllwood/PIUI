use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PerformanceMeasurement {
    pub name: String,
    pub duration_ms: u64,
}

#[derive(Default)]
pub struct PerformanceMarkers {
    active: Mutex<BTreeMap<String, Instant>>,
}

impl PerformanceMarkers {
    pub fn start(&self, name: &str) -> Result<(), String> {
        if name.len() > 80 {
            return Err("performance-marker-invalid".into());
        }
        self.active
            .lock()
            .map_err(|_| "performance-marker-unavailable")?
            .insert(name.into(), Instant::now());
        Ok(())
    }

    pub fn finish(&self, name: &str) -> Result<PerformanceMeasurement, String> {
        let started = self
            .active
            .lock()
            .map_err(|_| "performance-marker-unavailable")?
            .remove(name)
            .ok_or("performance-marker-missing")?;
        Ok(PerformanceMeasurement {
            name: name.into(),
            duration_ms: duration_ms(started.elapsed()),
        })
    }
}

fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}
