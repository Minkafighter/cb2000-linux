//! Per-user brute-force rate limiter for biometric verification.

use std::collections::HashMap;
use std::time::{Duration, Instant};

const MAX_CONSECUTIVE_FAILURES: u32 = 5;
const BASE_LOCKOUT_SECS: u64 = 30;
const MAX_LOCKOUT_SECS: u64 = 300;

#[derive(Debug, Default)]
struct UserLimitState {
    consecutive_failures: u32,
    locked_until: Option<Instant>,
}

/// Tracks consecutive failed verification attempts per Linux user and applies
/// exponential backoff lockouts to mitigate brute-force / spoof retries.
#[derive(Debug, Default)]
pub struct VerifyRateLimiter {
    users: HashMap<String, UserLimitState>,
}

impl VerifyRateLimiter {
    /// Check if `username` is currently allowed to attempt verification.
    /// Returns `Err(remaining_cooldown)` if locked out.
    pub fn check_allowed(&self, username: &str) -> Result<(), Duration> {
        if let Some(st) = self.users.get(username) {
            if let Some(until) = st.locked_until {
                let now = Instant::now();
                if until > now {
                    return Err(until.duration_since(now));
                }
            }
        }
        Ok(())
    }

    /// Record a failed verification attempt and return any newly triggered lockout duration.
    pub fn record_failure(&mut self, username: &str) -> Option<Duration> {
        let st = self.users.entry(username.to_string()).or_default();
        st.consecutive_failures = st.consecutive_failures.saturating_add(1);
        if st.consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
            let exp = (st.consecutive_failures - MAX_CONSECUTIVE_FAILURES).min(4);
            let secs = (BASE_LOCKOUT_SECS.saturating_mul(1u64 << exp)).min(MAX_LOCKOUT_SECS);
            let lockout = Duration::from_secs(secs);
            st.locked_until = Some(Instant::now() + lockout);
            Some(lockout)
        } else {
            None
        }
    }

    /// Reset failure counter upon a cryptographically verified match.
    pub fn record_success(&mut self, username: &str) {
        self.users.remove(username);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locks_out_after_threshold_and_resets_on_success() {
        let mut rl = VerifyRateLimiter::default();
        for _ in 0..4 {
            assert!(rl.record_failure("alice").is_none());
            assert!(rl.check_allowed("alice").is_ok());
        }
        let lockout = rl.record_failure("alice");
        assert!(lockout.is_some());
        assert!(rl.check_allowed("alice").is_err());

        rl.record_success("alice");
        assert!(rl.check_allowed("alice").is_ok());
    }
}
