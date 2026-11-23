//! Exponential reconnect backoff that resets only after a stable connection.

use std::time::Duration;

/// A connection must stay up this long before the backoff resets.
pub const STABLE_UPTIME: Duration = Duration::from_secs(5);

/// Lower bound on the delay, so a zero setting cannot create a hot reconnect loop.
const MIN_DELAY: Duration = Duration::from_millis(100);

/// Doubling delay from `initial` up to `max`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backoff {
    initial: Duration,
    max: Duration,
    attempt: u32,
}

impl Backoff {
    pub fn new(initial: Duration, max: Duration) -> Self {
        let initial = initial.max(MIN_DELAY);
        Self {
            initial,
            max: max.max(initial),
            attempt: 0,
        }
    }

    /// Retries scheduled since the last reset.
    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Counts a retry and returns how long to wait before it.
    pub fn next_delay(&mut self) -> Duration {
        let exponent = self.attempt.min(31);
        self.attempt = self.attempt.saturating_add(1);
        self.initial
            .checked_mul(1u32 << exponent)
            .map_or(self.max, |delay| delay.min(self.max))
    }

    /// Records how long a connection lasted. Only a stable connection resets the backoff.
    pub fn on_disconnected(&mut self, uptime: Duration) {
        if uptime >= STABLE_UPTIME {
            self.reset();
        }
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backoff() -> Backoff {
        Backoff::new(Duration::from_secs(1), Duration::from_secs(8))
    }

    #[test]
    fn backoff_doubles_up_to_the_cap() {
        let mut b = backoff();
        let delays: Vec<u64> = (0..6).map(|_| b.next_delay().as_secs()).collect();
        assert_eq!(delays, [1, 2, 4, 8, 8, 8]);
        assert_eq!(b.attempt(), 6);
    }

    #[test]
    fn backoff_does_not_overflow_after_many_attempts() {
        let mut b = backoff();
        for _ in 0..200 {
            assert!(b.next_delay() <= Duration::from_secs(8));
        }
    }

    #[test]
    fn backoff_keeps_growing_after_a_short_connection() {
        let mut b = backoff();
        b.next_delay();
        b.next_delay();
        b.on_disconnected(STABLE_UPTIME - Duration::from_millis(1));
        assert_eq!(b.attempt(), 2);
        assert_eq!(b.next_delay(), Duration::from_secs(4));
    }

    #[test]
    fn backoff_resets_after_stable_uptime() {
        let mut b = backoff();
        b.next_delay();
        b.next_delay();
        b.on_disconnected(STABLE_UPTIME);
        assert_eq!(b.attempt(), 0);
        assert_eq!(b.next_delay(), Duration::from_secs(1));
    }

    #[test]
    fn backoff_zero_settings_cannot_spin() {
        let mut b = Backoff::new(Duration::ZERO, Duration::ZERO);
        assert_eq!(b.next_delay(), MIN_DELAY);
    }
}
