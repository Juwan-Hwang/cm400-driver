//! CM400 automatic privacy policy + device activity model.
//!
//! Activity is a LIVENESS signal, not a session count. Stable CM400 streaming emits
//! MF-FrameServer Id=10 heartbeats at about 512ms intervals, but the 30-round stop
//! measurement found that 22/24 valid rounds continued heartbeating for >=20s after
//! the probe's stop request. Thus Id=10 does NOT represent immediate stream teardown.
//! The model is deliberately `Unknown | Active | Inactive` — we do NOT claim to count
//! clients/sessions (no evidence Id=10 distinguishes them).
//!
//! `HeartbeatTracker` turns "last heartbeat seen at T" into a state via a
//! recency timeout (timeout = max_observed_interval * safety, supplied by
//! config — never hardcoded in the ETW backend). `decide` is the asymmetric
//! policy (eager UP / conservative DOWN). Both are pure and unit-testable.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Automatic,
    AlwaysOpen,
    AlwaysClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub mode: Mode,
    pub down_grace_ms: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            mode: Mode::Automatic,
            down_grace_ms: 30_000,
        }
    }
}

/// Observed CM400 activity (liveness). `Unknown` = baseline not yet
/// established (e.g. right after start before the first heartbeat); callers
/// must NOT act on Unknown and must NOT persist it as a next-start truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CM400Activity {
    Unknown,
    Inactive,
    Active,
}

/// Recency-based liveness tracker. `Unknown` until the first heartbeat; then
/// `Active` while `now - last_seen <= timeout`, else `Inactive`.
#[derive(Debug, Clone, Copy)]
pub struct HeartbeatTracker {
    last_seen_ms: Option<u64>,
    timeout_ms: u64,
}

impl HeartbeatTracker {
    pub fn new(timeout_ms: u64) -> Self {
        HeartbeatTracker {
            last_seen_ms: None,
            timeout_ms,
        }
    }
    /// Record that a CM400 heartbeat was observed at `now_ms`.
    pub fn note(&mut self, now_ms: u64) {
        self.last_seen_ms = Some(now_ms);
    }
    pub fn state(&self, now_ms: u64) -> CM400Activity {
        match self.last_seen_ms {
            None => CM400Activity::Unknown,
            Some(t) if now_ms.saturating_sub(t) <= self.timeout_ms => CM400Activity::Active,
            Some(_) => CM400Activity::Inactive,
        }
    }
    pub fn age_ms(&self, now_ms: u64) -> Option<u64> {
        self.last_seen_ms.map(|t| now_ms.saturating_sub(t))
    }
    pub fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Raise,
    Retract,
    Hold,
}

/// Pure decision.
/// - `inactive_since_ms`: when CM400 became Inactive (None while Active/Unknown).
pub fn decide(
    policy: &Policy,
    activity: CM400Activity,
    inactive_since_ms: Option<u64>,
    now_ms: u64,
) -> Action {
    match policy.mode {
        Mode::AlwaysClosed => Action::Hold,
        Mode::AlwaysOpen => match activity {
            CM400Activity::Active => Action::Raise,
            _ => Action::Hold,
        },
        Mode::Automatic => match activity {
            CM400Activity::Unknown => Action::Hold,
            CM400Activity::Active => Action::Raise,
            CM400Activity::Inactive => match inactive_since_ms {
                Some(t) if now_ms.saturating_sub(t) >= policy.down_grace_ms => Action::Retract,
                _ => Action::Hold,
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(mode: Mode) -> Policy {
        Policy {
            mode,
            down_grace_ms: 30_000,
        }
    }

    #[test]
    fn automatic_raises_on_active() {
        assert_eq!(
            decide(&p(Mode::Automatic), CM400Activity::Active, None, 1000),
            Action::Raise
        );
    }

    #[test]
    fn automatic_holds_within_grace_then_retracts() {
        let pol = p(Mode::Automatic);
        assert_eq!(
            decide(&pol, CM400Activity::Inactive, Some(5000), 20_000),
            Action::Hold
        );
        assert_eq!(
            decide(&pol, CM400Activity::Inactive, Some(5000), 35_000),
            Action::Retract
        );
    }

    #[test]
    fn automatic_unknown_holds() {
        assert_eq!(
            decide(&p(Mode::Automatic), CM400Activity::Unknown, None, 999_999),
            Action::Hold
        );
    }

    #[test]
    fn always_open_never_retracts() {
        let pol = p(Mode::AlwaysOpen);
        assert_eq!(decide(&pol, CM400Activity::Active, None, 0), Action::Raise);
        assert_eq!(
            decide(&pol, CM400Activity::Inactive, Some(0), 999_999),
            Action::Hold
        );
    }

    #[test]
    fn always_closed_never_raises() {
        let pol = p(Mode::AlwaysClosed);
        assert_eq!(decide(&pol, CM400Activity::Active, None, 0), Action::Hold);
    }

    #[test]
    fn heartbeat_unknown_until_first() {
        let t = HeartbeatTracker::new(3000);
        assert_eq!(t.state(1000), CM400Activity::Unknown);
    }

    #[test]
    fn heartbeat_active_within_timeout_then_inactive() {
        let mut t = HeartbeatTracker::new(3000);
        t.note(1000);
        assert_eq!(t.state(2500), CM400Activity::Active); // age 1500 <= 3000
        assert_eq!(t.state(4000), CM400Activity::Active); // age 3000 == timeout -> still active (<=)
        assert_eq!(t.state(4001), CM400Activity::Inactive); // age 3001 > timeout
    }

    #[test]
    fn heartbeat_refreshes_on_new_beat() {
        let mut t = HeartbeatTracker::new(3000);
        t.note(1000);
        t.note(3500); // new heartbeat resets the clock
        assert_eq!(t.state(5000), CM400Activity::Active); // age from 3500 = 1500
    }
}
