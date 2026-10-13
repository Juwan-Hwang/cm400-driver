//! CM400 motor state model + recovery horizon. No platform, no I/O.
//!
//! Two worlds are kept separate (spec §7 fake-state trap):
//! - `physical`: the real mechanism position, trusted from persistence, never
//!   overwritten by firmware echo.
//! - firmware echo (GET_CUR) is NOT a position and never feeds this model.
//!
//! Because the mechanism self-locks across power loss / re-enumeration, a
//! persisted in-flight transition that is older than the recovery horizon is
//! assumed complete; only a recent interrupted transition is Unknown.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhysicalState {
    Unknown,
    Down,
    Up,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    Idle,
    MovingUp,
    MovingDown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MotorStatus {
    pub physical: PhysicalState,
    pub transition: Transition,
    pub target: Option<PhysicalState>,
    pub started_at_ms: u64,
    pub last_confirmed_at_ms: u64,
}

impl MotorStatus {
    pub fn unknown() -> Self {
        MotorStatus {
            physical: PhysicalState::Unknown,
            transition: Transition::Idle,
            target: None,
            started_at_ms: 0,
            last_confirmed_at_ms: 0,
        }
    }
}

/// Observed max mechanism travel (spec §7: retract 3.1~6.4s). NOT eternal truth;
/// tune from measurements. Do not scatter the literal across code.
pub const T_MAX_OBSERVED_MS: u64 = 6400;
pub const RECOVERY_MARGIN_MS: u64 = 1600;
pub const T_RECOVERY_MS: u64 = T_MAX_OBSERVED_MS + RECOVERY_MARGIN_MS;

/// Resolve a persisted status into a physical state at service start.
/// - Idle transition -> trust the persisted physical state.
/// - In-flight older than the horizon -> assume it completed -> target.
/// - In-flight within the horizon -> genuinely Unknown (needs calibration).
pub fn recover_physical(status: &MotorStatus, now_ms: u64, t_recovery_ms: u64) -> PhysicalState {
    match status.transition {
        Transition::Idle => status.physical,
        Transition::MovingUp | Transition::MovingDown => {
            let elapsed = now_ms.saturating_sub(status.started_at_ms);
            if elapsed > t_recovery_ms {
                status.target.unwrap_or(PhysicalState::Unknown)
            } else {
                PhysicalState::Unknown
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_horizon_is_parametric() {
        assert_eq!(T_RECOVERY_MS, 8000);
    }

    #[test]
    fn idle_trusts_persisted_physical() {
        let s = MotorStatus {
            physical: PhysicalState::Up,
            transition: Transition::Idle,
            target: None,
            started_at_ms: 0,
            last_confirmed_at_ms: 0,
        };
        assert_eq!(
            recover_physical(&s, 999_999, T_RECOVERY_MS),
            PhysicalState::Up
        );
    }

    #[test]
    fn old_inflight_converges_to_target() {
        let s = MotorStatus {
            physical: PhysicalState::Down,
            transition: Transition::MovingUp,
            target: Some(PhysicalState::Up),
            started_at_ms: 0,
            last_confirmed_at_ms: 0,
        };
        // now - started = 9000 > 8000 -> converged to Up, no calibration
        assert_eq!(recover_physical(&s, 9000, T_RECOVERY_MS), PhysicalState::Up);
    }

    #[test]
    fn recent_inflight_is_unknown() {
        let s = MotorStatus {
            physical: PhysicalState::Down,
            transition: Transition::MovingDown,
            target: Some(PhysicalState::Down),
            started_at_ms: 1000,
            last_confirmed_at_ms: 0,
        };
        // elapsed = 5000 <= 8000 -> Unknown (crashed mid-travel)
        assert_eq!(
            recover_physical(&s, 6000, T_RECOVERY_MS),
            PhysicalState::Unknown
        );
    }

    #[test]
    fn boundary_equal_horizon_is_unknown() {
        let s = MotorStatus {
            physical: PhysicalState::Down,
            transition: Transition::MovingUp,
            target: Some(PhysicalState::Up),
            started_at_ms: 0,
            last_confirmed_at_ms: 0,
        };
        // elapsed == horizon is NOT strictly greater -> Unknown
        assert_eq!(
            recover_physical(&s, 8000, T_RECOVERY_MS),
            PhysicalState::Unknown
        );
    }
}
