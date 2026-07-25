use super::{SidecarStatus, SidecarSupervisor, SupervisorPaths};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub const RESTART_HALTED_REPORT: &str = "PIUI’s local helper stopped repeatedly. Automatic recovery is paused; choose Restart Helper to try again.";

pub struct RestartController {
    attempts: VecDeque<Instant>,
    halted: bool,
    maximum_attempts: usize,
    base_delay: Duration,
    window: Duration,
}

impl Default for RestartController {
    fn default() -> Self {
        Self::new(3, Duration::from_millis(100), Duration::from_secs(60))
    }
}

impl RestartController {
    pub fn new(maximum_attempts: usize, base_delay: Duration, window: Duration) -> Self {
        Self {
            attempts: VecDeque::with_capacity(maximum_attempts),
            halted: false,
            maximum_attempts,
            base_delay,
            window,
        }
    }

    pub fn automatic_restart(
        &mut self,
        supervisor: &mut SidecarSupervisor,
        paths: &SupervisorPaths,
    ) -> Result<SidecarStatus, String> {
        let status = supervisor.status();
        if status.running {
            return Ok(status);
        }
        self.prune(Instant::now());
        if self.halted || self.attempts.len() >= self.maximum_attempts {
            self.halted = true;
            return Err(RESTART_HALTED_REPORT.into());
        }

        let exponent = self.attempts.len().min(16) as u32;
        let multiplier = 1_u32 << exponent;
        let delay = self.base_delay.saturating_mul(multiplier);
        self.attempts.push_back(Instant::now());
        std::thread::sleep(delay);
        supervisor.stop()?;
        supervisor.start(paths).map_err(|_| {
            "PIUI’s local helper could not restart. Open Diagnostics and try again.".into()
        })
    }

    pub fn user_restart(
        &mut self,
        supervisor: &mut SidecarSupervisor,
        paths: &SupervisorPaths,
    ) -> Result<SidecarStatus, String> {
        self.attempts.clear();
        self.halted = false;
        supervisor.stop()?;
        supervisor.start(paths).map_err(|_| {
            "PIUI’s local helper could not restart. Open Diagnostics and try again.".into()
        })
    }

    pub fn is_halted(&self) -> bool {
        self.halted
    }

    pub fn attempt_count(&mut self) -> usize {
        self.prune(Instant::now());
        self.attempts.len()
    }

    fn prune(&mut self, now: Instant) {
        while self
            .attempts
            .front()
            .is_some_and(|attempt| now.saturating_duration_since(*attempt) > self.window)
        {
            self.attempts.pop_front();
        }
        if self.attempts.is_empty() {
            self.halted = false;
        }
    }
}
