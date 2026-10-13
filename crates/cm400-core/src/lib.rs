//! CM400 Motor Engine: platform-agnostic orchestration.
//!
//! The engine never talks to a platform directly; it depends on traits
//! (Transport / ActivitySource / Clock / Store) that each OS backend implements.
//! This keeps the whole state machine unit-testable with mocks and shared by
//! Windows / Linux / macOS.
//!
//! Key behaviors encoded from spec + W0:
//! - Open-loop: after issuing SET, mark physical=target once max travel elapsed
//!   (no position feedback; firmware echo is never trusted as position).
//! - Throttle: XU writes >= MIN_WRITE_GAP_MS apart (Option-based so the first
//!   write is allowed at t=0).
//! - Busy: no new move while a transition is in flight.
//! - No-op: never command a move toward the state we already believe we're in.
//! - Unknown activity => hold (never act on an unestablished baseline).
//! - Recovery: on start, resolve persisted status via the recovery horizon.

use cm400_policy::{decide, Action, CM400Activity, Policy};
use cm400_state::{recover_physical, MotorStatus, PhysicalState, Transition, T_RECOVERY_MS};

/// Physical settle assumption for open-loop completion (max observed travel).
pub const MOVEMENT_MAX_MS: u64 = 6400;
/// Minimum gap between two XU writes (spec §12.3).
pub const MIN_WRITE_GAP_MS: u64 = 3000;

/// Ceiling on the retry delay after a failed motor write. Long enough to stop hammering a
/// device that is mid-reset, short enough that a real recovery does not stall for minutes.
pub const WRITE_RETRY_MAX_MS: u64 = 30_000;

/// The motor control channel, as far as the engine is concerned: read one XU value, write one.
///
/// Deliberately `Result<_, ()>`: this is the platform boundary, and each host already reports its own
/// failure detail through the log (`WinUsbTransport` names the Win32 error, the test fakes name the
/// injected fault). Threading a typed error through core would be an API change, not a lint fix, and is
/// tracked separately - which is why this one lint is allowed here rather than silenced at the call
/// sites or across the workspace.
#[allow(clippy::result_unit_err)]
pub trait Transport {
    fn get(&mut self) -> Result<u8, ()>;
    fn set(&mut self, value: u8) -> Result<(), ()>;
}

/// Device-specific CM400 activity source. Backends (Windows FrameServer event
/// log / ETW, Linux PipeWire, macOS CoreMediaIO) implement this; the engine and
/// policy never learn how activity was obtained.
pub trait ActivitySource {
    fn activity(&mut self) -> CM400Activity;

    /// May this reading's `Inactive` skip the down grace?
    ///
    /// The grace exists because a heartbeat's `Inactive` only means "no recent evidence" - it is
    /// silence, and silence can be a slow consumer rather than a stopped stream. A backend that
    /// can name a positive reason (an explicit stop, from a process instance whose identity was
    /// verified, with nothing else left active) does not need to sit out the wait.
    ///
    /// Default `false`, so every backend keeps the shipped protection unless it deliberately
    /// opts in with a reason the operator can read in the log.
    fn fast_retract_allowed(&mut self) -> bool {
        false
    }
}

pub trait Clock {
    fn now_ms(&mut self) -> u64;
}

pub trait Store {
    fn load(&mut self) -> Option<MotorStatus>;
    fn save(&mut self, status: &MotorStatus);
}

pub struct Engine {
    status: MotorStatus,
    policy: Policy,
    inactive_since: Option<u64>,
    last_write_ms: Option<u64>,
    /// How many retractions were issued with the grace waived. Counted because a waiver is a
    /// policy deviation an operator must be able to see, not a silent optimization.
    fast_retracts: u64,
    /// Failed-write pacing, one slot per direction. A failed transfer is not proof that nothing
    /// moved: the request can have been queued and the confirmation lost, so retrying every loop
    /// tick risks exactly the duplicate action we cannot observe. The backoff is kept per target
    /// on purpose - an old failure in one direction must not suppress a newly demanded move the
    /// other way, which is a different control need and the more urgent one.
    write_failures: u32,
    retry_blocked: [Option<u64>; 2],
    retry_streak: [u32; 2],
}

impl Engine {
    pub fn new(policy: Policy) -> Self {
        Engine {
            status: MotorStatus::unknown(),
            policy,
            inactive_since: None,
            last_write_ms: None,
            fast_retracts: 0,
            write_failures: 0,
            retry_blocked: [None, None],
            retry_streak: [0, 0],
        }
    }

    pub fn status(&self) -> MotorStatus {
        self.status
    }

    /// How many retractions were issued with the down grace waived.
    pub fn fast_retracts(&self) -> u64 {
        self.fast_retracts
    }

    /// Consecutive failed motor writes in total. Non-zero means the last known physical position
    /// is whatever was last confirmed, not what was requested.
    pub fn write_failures(&self) -> u32 {
        self.write_failures
    }

    /// Resolve persisted state at startup. Unknown stays Unknown (calibration is
    /// a separate, explicit cm400ctl path, not the resident loop).
    pub fn recover<S: Store>(&mut self, store: &mut S, now_ms: u64) {
        if let Some(s) = store.load() {
            let physical = recover_physical(&s, now_ms, T_RECOVERY_MS);
            self.status = MotorStatus {
                physical,
                transition: Transition::Idle,
                target: None,
                started_at_ms: 0,
                last_confirmed_at_ms: now_ms,
            };
        }
    }

    /// One control-loop tick.
    pub fn tick<A: ActivitySource, C: Clock, T: Transport, S: Store>(
        &mut self,
        activity: &mut A,
        clock: &mut C,
        transport: &mut T,
        store: &mut S,
    ) {
        let now = clock.now_ms();

        // 1) Settle an in-flight transition after max travel (open-loop).
        if self.status.transition != Transition::Idle
            && now.saturating_sub(self.status.started_at_ms) > MOVEMENT_MAX_MS
        {
            if let Some(t) = self.status.target {
                self.status.physical = t;
            }
            self.status.transition = Transition::Idle;
            self.status.target = None;
            self.status.last_confirmed_at_ms = now;
            store.save(&self.status);
        }

        // 2) Track activity edges for the DOWN grace period.
        let act = activity.activity();
        match act {
            CM400Activity::Active => self.inactive_since = None,
            CM400Activity::Inactive => {
                if self.inactive_since.is_none() {
                    self.inactive_since = Some(now);
                }
            }
            CM400Activity::Unknown => {}
        }

        // 3) Decide + act.
        //
        // Waiving the grace is the source's call, and only ever for an `Inactive` reading: an
        // `Unknown` or `Active` reading can never be made to act sooner. Only the wait changes;
        // `mode`, the transport throttle and the settle logic are inherited untouched.
        let fast = act == CM400Activity::Inactive && activity.fast_retract_allowed();
        let pol = if fast {
            Policy {
                down_grace_ms: 0,
                ..self.policy
            }
        } else {
            self.policy
        };
        match decide(&pol, act, self.inactive_since, now) {
            Action::Raise => {
                self.maybe_move(PhysicalState::Up, 1, now, transport, store);
            }
            Action::Retract => {
                // Count only a waiver that actually issued the command. Several ticks in a row
                // can decide `Retract` while the move is already in flight; calling each of
                // those a waived retraction would over-report a speed-up that never happened.
                let wrote = self.maybe_move(PhysicalState::Down, 2, now, transport, store);
                if fast && wrote {
                    self.fast_retracts += 1;
                }
            }
            Action::Hold => {}
        }
    }

    /// Issue the command unless something forbids it. Returns whether a write actually went
    /// out, so callers can count real actions rather than repeated decisions.
    fn maybe_move<T: Transport, S: Store>(
        &mut self,
        want: PhysicalState,
        value: u8,
        now: u64,
        transport: &mut T,
        store: &mut S,
    ) -> bool {
        if self.status.transition != Transition::Idle {
            return false; // busy
        }
        if self.status.physical == want {
            // already there (open-loop target); avoids the fake-state no-op
            return false;
        }
        if let Some(lw) = self.last_write_ms {
            if now.saturating_sub(lw) < MIN_WRITE_GAP_MS {
                return false; // throttle
            }
        }
        // Backoff after a failed write, per direction: doubling from the normal gap, capped, so
        // one lost confirmation cannot turn into hundreds of identical vendor requests - while a
        // demand for the opposite direction stays unblocked.
        let slot = usize::from(want != PhysicalState::Up);
        if let Some(earliest) = self.retry_blocked[slot] {
            if now < earliest {
                return false;
            }
        }
        if transport.set(value).is_ok() {
            self.last_write_ms = Some(now);
            self.write_failures = 0;
            self.retry_blocked[slot] = None;
            self.retry_streak[slot] = 0;
            self.status.transition = match want {
                PhysicalState::Up => Transition::MovingUp,
                PhysicalState::Down => Transition::MovingDown,
                PhysicalState::Unknown => Transition::Idle,
            };
            self.status.target = Some(want);
            self.status.started_at_ms = now;
            store.save(&self.status);
            true
        } else {
            // Nothing was recorded as moved: the status keeps the last position that was
            // actually confirmed, which is the only honest thing to claim here.
            self.write_failures = self.write_failures.saturating_add(1);
            self.retry_streak[slot] = self.retry_streak[slot].saturating_add(1);
            let shift = self.retry_streak[slot].saturating_sub(1).min(4);
            let delay = MIN_WRITE_GAP_MS.saturating_mul(1u64 << shift);
            self.retry_blocked[slot] = Some(now.saturating_add(delay.min(WRITE_RETRY_MAX_MS)));
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cm400_policy::Mode;

    struct Tx {
        sets: Vec<u8>,
    }
    impl Transport for Tx {
        fn get(&mut self) -> Result<u8, ()> {
            Ok(0)
        }
        fn set(&mut self, v: u8) -> Result<(), ()> {
            self.sets.push(v);
            Ok(())
        }
    }
    struct Act(CM400Activity);
    impl ActivitySource for Act {
        fn activity(&mut self) -> CM400Activity {
            self.0
        }
    }
    struct Clk(u64);
    impl Clock for Clk {
        fn now_ms(&mut self) -> u64 {
            self.0
        }
    }
    struct MemStore(Option<MotorStatus>);
    impl Store for MemStore {
        fn load(&mut self) -> Option<MotorStatus> {
            self.0
        }
        fn save(&mut self, s: &MotorStatus) {
            self.0 = Some(*s);
        }
    }

    const ACTIVE: CM400Activity = CM400Activity::Active;

    #[test]
    fn raise_settle_retract_cycle() {
        let mut eng = Engine::new(Policy::default());
        let mut act = Act(ACTIVE);
        let mut clk = Clk(0);
        let mut tx = Tx { sets: Vec::new() };
        let mut store = MemStore(None);

        eng.tick(&mut act, &mut clk, &mut tx, &mut store);
        assert_eq!(tx.sets, vec![1]);
        assert_eq!(eng.status().transition, Transition::MovingUp);

        clk.0 = 7000;
        eng.tick(&mut act, &mut clk, &mut tx, &mut store);
        assert_eq!(eng.status().physical, PhysicalState::Up);
        assert_eq!(eng.status().transition, Transition::Idle);

        act.0 = CM400Activity::Inactive;
        clk.0 = 8000;
        eng.tick(&mut act, &mut clk, &mut tx, &mut store);
        assert_eq!(tx.sets, vec![1]); // within grace -> Hold

        clk.0 = 40_000;
        eng.tick(&mut act, &mut clk, &mut tx, &mut store);
        assert_eq!(tx.sets, vec![1, 2]); // beyond grace -> Retract
        assert_eq!(eng.status().transition, Transition::MovingDown);

        clk.0 = 47_000;
        eng.tick(&mut act, &mut clk, &mut tx, &mut store);
        assert_eq!(eng.status().physical, PhysicalState::Down);
    }

    #[test]
    fn unknown_activity_never_moves() {
        let mut eng = Engine::new(Policy::default());
        let mut act = Act(CM400Activity::Unknown);
        let mut clk = Clk(0);
        let mut tx = Tx { sets: Vec::new() };
        let mut store = MemStore(None);
        eng.tick(&mut act, &mut clk, &mut tx, &mut store);
        assert!(tx.sets.is_empty());
    }

    #[test]
    fn no_redundant_write_when_already_target() {
        let mut eng = Engine::new(Policy::default());
        let mut act = Act(ACTIVE);
        let mut clk = Clk(0);
        let mut tx = Tx { sets: Vec::new() };
        let mut store = MemStore(None);
        eng.tick(&mut act, &mut clk, &mut tx, &mut store);
        clk.0 = 7000;
        eng.tick(&mut act, &mut clk, &mut tx, &mut store);
        clk.0 = 8000;
        eng.tick(&mut act, &mut clk, &mut tx, &mut store);
        assert_eq!(tx.sets, vec![1]); // still active, already Up -> no write
    }

    #[test]
    fn throttle_blocks_rapid_conflicting_write() {
        let mut eng = Engine::new(Policy {
            mode: Mode::Automatic,
            down_grace_ms: 0,
        });
        let mut act = Act(ACTIVE);
        let mut clk = Clk(0);
        let mut tx = Tx { sets: Vec::new() };
        let mut store = MemStore(None);
        eng.tick(&mut act, &mut clk, &mut tx, &mut store);
        assert_eq!(tx.sets, vec![1]);
        act.0 = CM400Activity::Inactive;
        clk.0 = 1000; // busy (MovingUp) -> no second write
        eng.tick(&mut act, &mut clk, &mut tx, &mut store);
        assert_eq!(tx.sets, vec![1]);
    }

    #[test]
    fn recover_converges_old_inflight_without_write() {
        let persisted = MotorStatus {
            physical: PhysicalState::Down,
            transition: Transition::MovingUp,
            target: Some(PhysicalState::Up),
            started_at_ms: 0,
            last_confirmed_at_ms: 0,
        };
        let mut store = MemStore(Some(persisted));
        let mut eng = Engine::new(Policy::default());
        eng.recover(&mut store, 10_000);
        assert_eq!(eng.status().physical, PhysicalState::Up);
    }

    /// A transport whose writes fail a fixed number of times, recording every attempt so the
    /// retry schedule is observable rather than assumed.
    struct Flaky {
        attempts: Vec<u8>,
        fail_first: usize,
    }
    impl Transport for Flaky {
        fn get(&mut self) -> Result<u8, ()> {
            Ok(0)
        }
        fn set(&mut self, v: u8) -> Result<(), ()> {
            self.attempts.push(v);
            if self.attempts.len() <= self.fail_first {
                Err(())
            } else {
                Ok(())
            }
        }
    }

    /// A failed write must not be retried every loop tick, and must not be recorded as a move.
    #[test]
    fn failed_writes_back_off_and_never_fabricate_a_position() {
        let mut eng = Engine::new(Policy {
            mode: Mode::Automatic,
            down_grace_ms: 0,
        });
        let mut act = Act(CM400Activity::Inactive);
        let mut clk = Clk(0);
        let mut tx = Flaky {
            attempts: Vec::new(),
            fail_first: 2,
        };
        let mut store = MemStore(None);

        // 1) fails, and nothing is claimed about the device.
        eng.tick(&mut act, &mut clk, &mut tx, &mut store);
        assert_eq!(tx.attempts, vec![2]);
        assert_eq!(eng.write_failures(), 1);
        assert_eq!(
            eng.status().physical,
            PhysicalState::Unknown,
            "a failed write is not a move"
        );
        assert_eq!(eng.status().transition, Transition::Idle);

        // 2) before the backoff expires there is no second attempt (3 s after the failure).
        clk.0 = 1_000;
        eng.tick(&mut act, &mut clk, &mut tx, &mut store);
        assert_eq!(
            tx.attempts.len(),
            1,
            "backoff, not the loop rate, paces the retry"
        );

        // 3) at 3 s the retry happens and fails again -> the gap doubles to 6 s.
        clk.0 = 3_000;
        eng.tick(&mut act, &mut clk, &mut tx, &mut store);
        assert_eq!(tx.attempts.len(), 2);
        assert_eq!(eng.write_failures(), 2);
        clk.0 = 5_000;
        eng.tick(&mut act, &mut clk, &mut tx, &mut store);
        assert_eq!(
            tx.attempts.len(),
            2,
            "a flat 3 s retry would have fired here"
        );

        // 4) at 9 s the third attempt succeeds; counters clear and the move is recorded.
        clk.0 = 9_000;
        eng.tick(&mut act, &mut clk, &mut tx, &mut store);
        assert_eq!(tx.attempts.len(), 3);
        assert_eq!(eng.write_failures(), 0);
        assert_eq!(eng.status().transition, Transition::MovingDown);
        assert_eq!(eng.status().target, Some(PhysicalState::Down));
    }

    /// An old failure may not silence a new demand in the other direction: the lens being stuck
    /// out while an app waits is worse than one more write attempt.
    #[test]
    fn a_failed_direction_does_not_block_the_opposite_demand() {
        let mut eng = Engine::new(Policy {
            mode: Mode::Automatic,
            down_grace_ms: 0,
        });
        let mut act = Act(CM400Activity::Inactive);
        let mut clk = Clk(0);
        let mut tx = Flaky {
            attempts: Vec::new(),
            fail_first: 1,
        };
        let mut store = MemStore(None);

        // Retract fails and paces itself for 3 s.
        eng.tick(&mut act, &mut clk, &mut tx, &mut store);
        assert_eq!(tx.attempts, vec![2]);
        assert_eq!(eng.write_failures(), 1);

        // A stream starts 1 s later. The raise must go out now, not after the retract backoff.
        act.0 = CM400Activity::Active;
        clk.0 = 1_000;
        eng.tick(&mut act, &mut clk, &mut tx, &mut store);
        assert_eq!(
            tx.attempts,
            vec![2, 1],
            "the new demand was not suppressed by the old failure"
        );
        assert_eq!(
            eng.write_failures(),
            0,
            "a successful write clears the streak"
        );
        assert_eq!(eng.status().transition, Transition::MovingUp);

        // And the position was never invented: only confirmed writes move the recorded state.
        assert_eq!(
            eng.status().physical,
            PhysicalState::Unknown,
            "still travelling; nothing claimed early"
        );
    }

    /// A source that can also say whether this reading may waive the down grace.
    struct Waiving {
        act: CM400Activity,
        waive: bool,
    }
    impl ActivitySource for Waiving {
        fn activity(&mut self) -> CM400Activity {
            self.act
        }
        fn fast_retract_allowed(&mut self) -> bool {
            self.waive
        }
    }

    /// A verified stop retracts on the reading that reports it, without waiting out the grace.
    #[test]
    fn a_waived_grace_retracts_on_the_first_inactive_reading() {
        let mut eng = Engine::new(Policy::default()); // 30 s grace
        let mut act = Waiving {
            act: ACTIVE,
            waive: false,
        };
        let mut clk = Clk(0);
        let mut tx = Tx { sets: Vec::new() };
        let mut store = MemStore(None);
        eng.tick(&mut act, &mut clk, &mut tx, &mut store);
        assert_eq!(tx.sets, vec![1]);
        clk.0 = 7_000;
        eng.tick(&mut act, &mut clk, &mut tx, &mut store); // settle

        // Same moment the stream stops, with the positive reason attached.
        act.act = CM400Activity::Inactive;
        act.waive = true;
        clk.0 = 8_000;
        eng.tick(&mut act, &mut clk, &mut tx, &mut store);
        assert_eq!(tx.sets, vec![1, 2], "retracted without the 30 s wait");
        assert_eq!(eng.fast_retracts(), 1, "and the waiver is counted");

        clk.0 = 15_000;
        eng.tick(&mut act, &mut clk, &mut tx, &mut store);
        assert_eq!(eng.status().physical, PhysicalState::Down);
        assert_eq!(
            eng.fast_retracts(),
            1,
            "the in-flight move was not counted twice"
        );
    }

    /// The waiver must not leak: without it the shipped grace still holds, and it can never
    /// make an `Active` or `Unknown` reading move anything.
    #[test]
    fn the_waiver_changes_only_the_wait_never_the_mode_or_the_other_states() {
        // Waiver off -> the grace is intact.
        let mut eng = Engine::new(Policy::default());
        let mut act = Waiving {
            act: ACTIVE,
            waive: false,
        };
        let mut clk = Clk(0);
        let mut tx = Tx { sets: Vec::new() };
        let mut store = MemStore(None);
        eng.tick(&mut act, &mut clk, &mut tx, &mut store);
        act.act = CM400Activity::Inactive;
        clk.0 = 20_000;
        eng.tick(&mut act, &mut clk, &mut tx, &mut store);
        assert_eq!(tx.sets, vec![1], "silence alone still waits out the grace");
        assert_eq!(eng.fast_retracts(), 0);

        // Waiver on but the reading is Active -> nothing retracts (and nothing is counted).
        let mut eng2 = Engine::new(Policy::default());
        let mut act2 = Waiving {
            act: ACTIVE,
            waive: true,
        };
        let mut clk2 = Clk(0);
        let mut tx2 = Tx { sets: Vec::new() };
        let mut store2 = MemStore(None);
        eng2.tick(&mut act2, &mut clk2, &mut tx2, &mut store2);
        assert_eq!(tx2.sets, vec![1], "an Active reading raises, as always");
        assert_eq!(
            eng2.fast_retracts(),
            0,
            "a waiver is not an instruction to move"
        );

        // Waiver on but the reading is Unknown -> the engine must not act at all.
        let mut eng3 = Engine::new(Policy::default());
        let mut act3 = Waiving {
            act: CM400Activity::Unknown,
            waive: true,
        };
        let mut clk3 = Clk(0);
        let mut tx3 = Tx { sets: Vec::new() };
        let mut store3 = MemStore(None);
        eng3.tick(&mut act3, &mut clk3, &mut tx3, &mut store3);
        assert!(
            tx3.sets.is_empty(),
            "Unknown is never acted on, waived grace or not"
        );

        // Waiver on, but the mode forbids retracting: only the wait was ever in the balance.
        let mut eng4 = Engine::new(Policy {
            mode: Mode::AlwaysOpen,
            down_grace_ms: 30_000,
        });
        let mut act4 = Waiving {
            act: ACTIVE,
            waive: true,
        };
        let mut clk4 = Clk(0);
        let mut tx4 = Tx { sets: Vec::new() };
        let mut store4 = MemStore(None);
        eng4.tick(&mut act4, &mut clk4, &mut tx4, &mut store4);
        act4.act = CM400Activity::Inactive;
        clk4.0 = 5_000;
        eng4.tick(&mut act4, &mut clk4, &mut tx4, &mut store4);
        assert_eq!(
            tx4.sets,
            vec![1],
            "a policy mode is not overridden by a waiver"
        );
        assert_eq!(eng4.fast_retracts(), 0);
    }
}
