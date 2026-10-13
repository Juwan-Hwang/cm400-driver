//! R2: the single arbitration point between the two CM400 activity backends.
//!
//! Everything here is **pure** - no Win32, no COM, no clock, no I/O - so the whole
//! safety argument is unit-testable and reviewable without a device. The platform
//! side (`sam_source.rs`) only parses reports into [`Evidence`] and hands them over;
//! `etw_source.rs` only reports heartbeat arrivals. Neither decides anything.
//!
//! Why a separate arbiter exists: the product loop consumed
//! `HeartbeatTracker::state()` directly, i.e. activity was *defined* as "an Id=10
//! heartbeat arrived recently". Measured, that definition costs a 3s timeout plus a
//! FrameServer teardown tail that ran >=20s in 22 of 24 valid rounds, so the lens
//! could not retract promptly. `IMFSensorActivityMonitor` reports an explicit
//! `streaming=0` for the same process (median 288ms), which is a *positive* stop
//! signal - but it is per-client, and its multi-client semantics are unverified on
//! this rig. So the arbiter's job is to use the positive signal only when it is
//! unambiguous, and to never let the absence of data masquerade as a stop.
//!
//! Invariants, deliberately encoded and tested:
//! - **Only an explicit `streaming=0` for an instance we saw `streaming=1` for, on the
//!   CM400 link, newer than that TRUE, can produce `Idle`.** Empty collections, missing
//!   reports, property failures, silence, or a vanished process never do.
//! - **Identity is (pid, sourced identity value, epoch)**, not pid: a recycled PID is a new
//!   instance, and an identity from a different source is not the same instance either.
//! - **Faults push toward `Active`/`Unknown`, never `Inactive`.**
//! - **Cross-source ordering is semantic, not timestamp arithmetic**: SAM report times and
//!   ETW arrival times are different clock domains and are never compared with each other.
//!
//! Not yet settled (see the maintainer-side release notes (SENSOR-ACTIVITY-INTEGRATION) §4.2/§7): the suppression
//! window needs a measured stop-tail bound. Until that exists it is
//! [`Suppression::Disabled`], and `R2` therefore cannot outrun the heartbeat tail.

use std::collections::HashMap;

use cm400_policy::{CM400Activity, HeartbeatTracker};

/// Design candidate (SENSOR-ACTIVITY-INTEGRATION §4): how long a `Busy` instance may be
/// absent from reports before it degrades to `Lost`. It only ever *removes* the SAM
/// backend's ability to declare a stop; it never produces `Inactive` by itself.
/// Kept as a constant rather than a config key: adding an unreviewed V1 parameter is out
/// of scope, and the value is not load-bearing for safety (larger = more conservative).
pub const LOST_GRACE_MS: u64 = 3_000;

/// A process-instance identity **value, tagged with the source it came from**.
///
/// Two identities are equal only when both the source and the value match. That is not
/// bookkeeping: a creation time and a sequence number are different measurements on different
/// clocks, and a `TRUE` proven under one and a `FALSE` proven under the other must never pair
/// up just because somebody stored both in a `u64` and they happened to be numerically equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IdentityValue {
    /// Unix milliseconds, from `GetProcessTimes`. Has a real unit and a real meaning.
    CreationTime(u64),
    /// `SequenceNumber` from `SystemBasicProcessInformation`: documented as a PID-reuse
    /// detector, **not** a timestamp. Never rendered as `created_ms`.
    SequenceNumber(u64),
}

impl IdentityValue {
    /// Short origin tag for logs, so a line cannot be read as "creation time" by mistake.
    pub fn origin(&self) -> &'static str {
        match self {
            IdentityValue::CreationTime(_) => "creation_time",
            IdentityValue::SequenceNumber(_) => "sequence",
        }
    }

    pub fn raw(&self) -> u64 {
        match self {
            IdentityValue::CreationTime(v) | IdentityValue::SequenceNumber(v) => *v,
        }
    }
}

/// The identity we attach reports to: a pid plus a *sourced* instance value.
///
/// Three separate notions, deliberately not merged:
/// - **identity** (`pid` + `identity`): *which process* a report came from. Only a resolved
///   identity can contribute to `Idle`; `None` means we could not prove it, and a recycled pid
///   could otherwise inherit someone else's stop.
/// - **epoch**: a *generation counter for state churn inside one already-identified instance*
///   (stream closed and reopened by the same process). It exists so a stop and a later start
///   order correctly. It carries **no** identity information and must never be used to bridge
///   two different identities - if identity handling is wrong, a bumping epoch would hide it.
/// - **liveness baseline** (`last_true_ms` / `last_seen_ms` / `last_arrival_ms` per entry):
///   how fresh our observation of that instance is. Freshness is not identity, and silence is
///   not a stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcInstance {
    pub pid: u32,
    pub identity: Option<IdentityValue>,
}

impl ProcInstance {
    pub fn from_creation_time(pid: u32, created_ms: u64) -> Self {
        ProcInstance {
            pid,
            identity: Some(IdentityValue::CreationTime(created_ms)),
        }
    }
    pub fn from_sequence_number(pid: u32, sequence: u64) -> Self {
        ProcInstance {
            pid,
            identity: Some(IdentityValue::SequenceNumber(sequence)),
        }
    }
    pub fn unresolved(pid: u32) -> Self {
        ProcInstance {
            pid,
            identity: None,
        }
    }
    pub fn identity_resolved(&self) -> bool {
        self.identity.is_some()
    }
}

/// Why a report produced nothing usable. All three are **NO DATA** - they are counted for
/// operations and never allowed to move the device state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoMatchKind {
    /// `GetCount()` returned 0.
    EmptyCollection,
    /// Reports exist but none matches the CM400 link.
    NoCm400Report,
    /// `GetSymbolicLink`/`GetStreamingState`/`GetReportTime` failed. Carries the HRESULT.
    PropertyReadFailed(i32),
}

/// An *explicit* backend failure. Silence is not in this list on purpose: the interface is
/// event-driven, so a quiet monitor carries no information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorFaultKind {
    CreateFailed(i32),
    StartFailed(i32),
    PropertyReadFailed(i32),
    ComInitFailed(i32),
    DeviceGone,
    /// The bounded retries ran out; the heartbeat path is the only source until a restart.
    RetriesExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendGoneReason {
    ServiceStop,
    Reenumerated,
    TargetLinkChanged,
}

/// The only thing the arbiter accepts. Both backends produce these; neither decides.
///
/// `Clone` rather than `Copy`: an unmatched report carries the link text, because "which
/// device was this about" is the question a reviewer has to be able to ask of a log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Evidence {
    /// An Id=10 heartbeat for the CM400 arrived at `arrival_ms` (wall clock, our side).
    HeartbeatSeen {
        arrival_ms: u64,
    },
    /// SAM said "this process is streaming" for the CM400 link, at `report_ms`.
    ///
    /// Two stamps travel with one report on purpose, and they are different clocks:
    /// `report_ms` is the system's FILETIME (`GetReportTime`), `arrival_ms` is our wall clock
    /// read **in the callback thread** when the report was delivered. Ordering inside this
    /// source uses `report_ms`; the silence metric uses `arrival_ms`. The two are never
    /// subtracted from each other, and never from the ETW arrival time (design §1).
    PidStreaming {
        inst: ProcInstance,
        report_ms: u64,
        arrival_ms: u64,
    },
    /// SAM said "this process stopped streaming" for the CM400 link, at `report_ms`.
    PidStopped {
        inst: ProcInstance,
        report_ms: u64,
        arrival_ms: u64,
    },
    /// A report set we could not use. Never a stop.
    NoMatchingReport {
        kind: NoMatchKind,
    },
    /// A report whose link is not the CM400's (defence in depth; the source filters first).
    UnmatchedReport {
        link: String,
        pid: u32,
    },
    MonitorFault {
        kind: MonitorFaultKind,
    },
    /// A bounded retry succeeded, so the monitor is explicitly healthy again. Not an
    /// activity claim: it only restores the backend's permission to produce `Idle`.
    MonitorRecovered,
    BackendGone {
        why: BackendGoneReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PidState {
    Busy,
    /// Reached only by an explicit `streaming=0` newer than that instance's TRUE.
    Stopped,
    /// Disappeared without an explicit stop. NOT a stop, and never device-level `Idle`.
    Lost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PidEntry {
    pub inst: ProcInstance,
    pub epoch: u32,
    pub state: PidState,
    pub last_true_ms: u64,
    pub last_stop_ms: u64,
    /// Last time this instance appeared in any CM400 report (absence drives `Busy->Lost`).
    pub last_seen_ms: u64,
    /// Callback-arrival stamp of the last *accepted* report for this instance. Used only to
    /// measure report silence; it never feeds a decision. 0 = never observed.
    pub last_arrival_ms: u64,
}

/// Device-level view of what SAM is saying. `NoData` is the honest "SAM has no usable
/// opinion", and it never erases what the heartbeat path already knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SAMView {
    Busy,
    Idle,
    NoData,
}

/// Which precondition stopped `R2` from being applied. `None` means it was applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blocker {
    None,
    /// SAM has never confirmed a CM400 stream for this generation of reports.
    NeverBusy,
    /// Some instance is still `Busy`.
    StillBusy,
    /// Some instance went missing without an explicit stop.
    UnresolvedInstances,
    /// An instance's identity could not be resolved, so its stop cannot be trusted.
    IdentityUnresolved,
    /// The monitor reported an explicit fault, or was never healthy.
    MonitorUnhealthy,
    /// R2's evidence is complete but no measured stop-tail bound exists yet, so the
    /// suppression window is unset and R2 stays disabled (design §4.2 item 5). This is the
    /// shadow-phase state: SAM can activate early, but cannot accelerate the retraction.
    SuppressionUnset,
    /// R2's evidence is complete, but the stop it wants to act on is not attributable to a
    /// verified process instance (the lifecycle ledger is untrusted, or the report was refused).
    /// The fast path may not declare the device idle on an unidentified stop.
    LedgerUntrusted,
}

/// The suppression window that keeps a *finished* stream's late heartbeats from
/// reactivating the device.
///
/// `Bounded(ms)` may only be built from a measured stop-tail bound; inventing a number here
/// is exactly how a lens gets raised for a stream that never restarted, or left out for one
/// that did. So the default is `Disabled`, which keeps the implementation honest: R2 can
/// report a stop, but until the window is measurable the old heartbeat path resumes as soon
/// as SAM's opinion degrades.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suppression {
    Disabled,
    Bounded(u64),
    /// Stop latch instead of a time window.
    ///
    /// The measured facts are these: a stop report does arrive (269-289 ms after the stream
    /// ended), and the heartbeat tail behind it is not a stable duration (22 of 24 historical
    /// rounds kept beating for at least 20 s; the recent rounds were far shorter). Any fixed
    /// window would therefore be either too short to protect the retraction or a number nobody
    /// measured. So this variant does not mute heartbeats for `ms`; it latches on the accepted
    /// stop and releases only on evidence that a *new* activity cycle really began, or on any
    /// loss of the trust the latch was built on.
    ///
    /// Arming additionally requires the caller to say the stop was attributed by a trusted
    /// lifecycle ledger (`Arbiter::set_ledger_trusted`), so an unidentified `streaming=0` can
    /// never take the fast path.
    Latched,
}

/// Counters for operators and the shadow phase. Nothing here feeds a decision.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Telemetry {
    pub callbacks: u64,
    pub empty_list: u64,
    pub other_device: u64,
    pub property_failures: u64,
    pub stale_stopped: u64,
    /// TRUE reports refused while a stop latch held because their own report time was not newer
    /// than the accepted stop - i.e. an out-of-order duplicate of the generation we just stopped.
    pub stale_starts: u64,
    pub faults: u64,
    pub lost_transitions: u64,
    pub r2_applied: u64,
    pub suppressed_reactivations: u64,
    pub recoveries: u64,
    /// Times the stop latch was armed, and times it was released. A latch that arms but never
    /// releases is a locked-out camera, so the two numbers must move together.
    pub latch_armed: u64,
    pub latch_released: u64,
    /// Longest observed gap between consecutive accepted CM400 reports for one instance,
    /// measured in callback arrivals. Observation only: it decides nothing, but it is the
    /// number that says how often `Busy -> Lost` decay is legitimate during a live stream.
    pub max_report_gap_ms: u64,
    pub conflicts: u64,
}

/// One CM400 stream's worth of arbitration. `now_ms` is supplied by the caller everywhere;
/// the arbiter never reads a clock.
pub struct Arbiter {
    /// Full MI_00 symbolic link of the CM400, compared case-insensitively and in full.
    target_link: String,
    target_link_lower: String,
    hb: HeartbeatTracker,
    lost_grace_ms: u64,
    suppression: Suppression,
    entries: HashMap<ProcInstance, PidEntry>,
    ever_busy: bool,
    sam_healthy: bool,
    /// R2 currently in force (we are reporting Inactive because SAM said so).
    r2_active: bool,
    suppress_until_ms: Option<u64>,
    /// The stop latch (`Suppression::Latched`): armed by an accepted, attributable stop; held
    /// until evidence of a new cycle or a loss of trust releases it.
    stop_latched: bool,
    /// Report time of the stop the latch was armed on. Only a TRUE *newer* than this may open
    /// a new cycle, which is what keeps a late duplicate of an old TRUE from raising the lens.
    latch_stop_report_ms: u64,
    /// Set by the caller: the reports this arbiter is fed were attributed against a trusted
    /// lifecycle ledger. Defaults to false so the fast path is unavailable unless someone
    /// actively establishes that basis.
    ledger_trusted: bool,
    /// Report time of the stop the caller has *attributed*, waiting to authorize a latch. Cleared
    /// when consumed, so one attribution cannot keep the fast path open forever.
    stop_attributed_ms: u64,
    last_latch_release: &'static str,
    blocker: Blocker,
    pub telemetry: Telemetry,
}

impl Arbiter {
    pub fn new(target_link: &str, heartbeat_timeout_ms: u64, suppression: Suppression) -> Self {
        Arbiter {
            target_link: target_link.to_string(),
            target_link_lower: target_link.to_ascii_lowercase(),
            hb: HeartbeatTracker::new(heartbeat_timeout_ms),
            lost_grace_ms: LOST_GRACE_MS,
            suppression,
            entries: HashMap::new(),
            ever_busy: false,
            sam_healthy: true,
            r2_active: false,
            suppress_until_ms: None,
            stop_latched: false,
            latch_stop_report_ms: 0,
            ledger_trusted: false,
            stop_attributed_ms: 0,
            last_latch_release: "never",
            blocker: Blocker::NeverBusy,
            telemetry: Telemetry::default(),
        }
    }

    /// Full, case-insensitive equality. Substring or VID/PID-fragment matching is banned:
    /// a sibling interface of the same physical device would otherwise inherit its state.
    pub fn link_matches(&self, link: &str) -> bool {
        link.to_ascii_lowercase() == self.target_link_lower
    }

    pub fn target_link(&self) -> &str {
        &self.target_link
    }

    pub fn suppression(&self) -> Suppression {
        self.suppression
    }

    /// True while a suppression window is open. Used by the caller to log why heartbeats
    /// are being ignored; the decision itself is made in `activity`.
    pub fn suppression_open(&self, now_ms: u64) -> bool {
        self.suppress_until_ms.map(|t| now_ms < t).unwrap_or(false)
    }

    pub fn blocker(&self) -> Blocker {
        self.blocker
    }

    /// Longest gap seen between two accepted CM400 reports of one instance, in callback
    /// arrivals. Read by the shadow-phase log line; never an input to any decision.
    pub fn max_report_gap_ms(&self) -> u64 {
        self.telemetry.max_report_gap_ms
    }

    /// Every known instance carries an explicit, accepted stop. Absence, a `Lost` registration
    /// and an empty table all fail this: only positive `streaming=0` evidence counts. Freshness is
    /// not judged here - it comes from `note_attributed_stop` being called on the stop this very
    /// poll attributed, so no time bound is smuggled into the rule.
    fn all_stopped(&self) -> bool {
        !self.entries.is_empty() && self.entries.values().all(|e| e.state == PidState::Stopped)
    }

    /// The pending authorization must describe the **newest** accepted stop. Otherwise a stop we
    /// attributed earlier could be consumed by a later stop nobody attributed - e.g. client A
    /// stops (attributed) while B is still busy, B then stops with a report the ledger refused:
    /// the table is fully `Stopped`, but the idle claim would be resting on A's old evidence.
    /// Equality against the newest accepted stop is what closes that hole.
    fn authorization_is_current(&self) -> bool {
        self.stop_attributed_ms != 0
            && self.stop_attributed_ms
                == self
                    .entries
                    .values()
                    .map(|e| e.last_stop_ms)
                    .max()
                    .unwrap_or(0)
    }

    /// Device-level view, computed *with* the clock rather than relying on `expire` having
    /// been called first. A `Busy` entry past its absence grace is already `Lost` here,
    /// so a caller cannot accidentally treat a stale registration as a live client.
    pub fn view(&self, now_ms: u64) -> SAMView {
        if !self.ever_busy {
            return SAMView::NoData;
        }
        if self.entries.is_empty() {
            return SAMView::NoData;
        }
        let effective = |e: &PidEntry| -> PidState {
            if e.state == PidState::Busy
                && now_ms.saturating_sub(e.last_seen_ms) > self.lost_grace_ms
            {
                PidState::Lost
            } else {
                e.state
            }
        };
        if self
            .entries
            .values()
            .any(|e| effective(e) == PidState::Busy)
        {
            return SAMView::Busy;
        }
        if self
            .entries
            .values()
            .all(|e| effective(e) == PidState::Stopped && e.inst.identity_resolved())
        {
            return SAMView::Idle;
        }
        SAMView::NoData
    }

    /// Feed one piece of evidence. No evidence can shorten the policy's down grace: that is
    /// `cm400_policy::decide`'s job and stays there.
    pub fn apply(&mut self, now_ms: u64, ev: Evidence) {
        match ev {
            Evidence::HeartbeatSeen { arrival_ms } => {
                // Arrival time of our own source: same clock domain as the tracker.
                self.hb.note(arrival_ms);
            }
            Evidence::PidStreaming {
                inst,
                report_ms,
                arrival_ms,
            } => self.note_true(inst, report_ms, arrival_ms, now_ms),
            Evidence::PidStopped {
                inst,
                report_ms,
                arrival_ms,
            } => self.note_false(inst, report_ms, arrival_ms, now_ms),
            Evidence::NoMatchingReport { kind } => {
                self.telemetry.callbacks += 1;
                match kind {
                    NoMatchKind::EmptyCollection => self.telemetry.empty_list += 1,
                    NoMatchKind::NoCm400Report => self.telemetry.other_device += 1,
                    NoMatchKind::PropertyReadFailed(_) => self.telemetry.property_failures += 1,
                }
                // Explicitly: no state change, ever.
            }
            Evidence::UnmatchedReport { pid: _, link } => {
                if self.link_matches(&link) {
                    // The source should not have sent this; treat it as a parse fault rather
                    // than silently dropping, because dropping would hide a link bug.
                    self.telemetry.property_failures += 1;
                } else {
                    self.telemetry.other_device += 1;
                }
            }
            Evidence::MonitorFault { .. } => {
                self.telemetry.faults += 1;
                self.sam_healthy = false;
                // Ruling B (2026-10-11): a backend that has failed must not keep suppressing
                // heartbeats. If we lost the monitor we may also miss the report that says
                // "a stream started again", while the tail would keep us pinned to Inactive -
                // worse than losing R2's speed-up. The window goes with it; the heartbeat
                // path takes over immediately.
                // The table is NOT cleared: a Busy entry pinned to Active is the conservative
                // direction, and it still decays to `Lost` below, which lands on NoData.
                self.r2_active = false;
                self.suppress_until_ms = None;
                self.release_latch("monitor fault");
            }
            Evidence::MonitorRecovered => {
                self.telemetry.recoveries += 1;
                self.sam_healthy = true;
                // Nothing else is touched: a healthy monitor is a permission, not evidence.
            }
            Evidence::BackendGone { .. } => {
                // Service stop / re-enumeration: every record we hold describes a stream
                // generation that is over, and none of it may justify a stop decision now.
                // Ruling B: the window is cleared too, so activity decisions genuinely return
                // to the old ETW path instead of staying suppressed by an unattainable signal.
                self.entries.clear();
                self.ever_busy = false;
                self.r2_active = false;
                self.suppress_until_ms = None;
                self.release_latch("backend gone");
                self.blocker = Blocker::NeverBusy;
            }
        }
    }

    /// Record callback silence between two accepted reports of the same instance.
    ///
    /// Both endpoints are our own wall clock read on the callback thread, so this never
    /// compares clock domains. It is observation only: nothing here can change activity state.
    fn observe_liveness(&mut self, e: &mut PidEntry, arrival_ms: u64) {
        if e.last_arrival_ms != 0 && arrival_ms > e.last_arrival_ms {
            let gap = arrival_ms - e.last_arrival_ms;
            if gap > self.telemetry.max_report_gap_ms {
                self.telemetry.max_report_gap_ms = gap;
            }
        }
        e.last_arrival_ms = arrival_ms.max(e.last_arrival_ms);
    }

    fn note_true(&mut self, inst: ProcInstance, report_ms: u64, arrival_ms: u64, now_ms: u64) {
        self.telemetry.callbacks += 1;
        // A streaming claim whose time cannot be placed at all (`report_ms == 0`, the sentinel the
        // source uses for a publisher whose report carries no usable FILETIME - measured with
        // ffmpeg) cannot be ordered against the accepted stop. Dropping it would keep the latch
        // asserting "nothing else is active" while a client says it *is* streaming and we cannot
        // date that claim: absence of orderable evidence is not evidence of absence. So the latch
        // lets go, the idle claim is withdrawn, and the heartbeat path decides again - and it can
        // only be re-armed by a newly attributed stop.
        if self.stop_latched && report_ms == 0 {
            self.release_latch("a streaming claim with no usable time cannot be ordered");
        }
        // Out-of-order protection: reports are delivered in arrival order, and we measured
        // `arrival - report` up to 59.8 s, so a TRUE stamped *before* the accepted stop can still
        // show up afterwards. Acting on it would raise the lens for a stream that already ended,
        // which is the very failure the latch exists to prevent. Symmetric with the `report_ms
        // <= last_true_ms` refusal in `note_false`, and it deliberately refreshes no liveness
        // either: refusing to act on a report and using it to stay "seen" cannot both be true.
        if self.stop_latched && report_ms <= self.latch_stop_report_ms {
            self.telemetry.stale_starts += 1;
            return;
        }
        // The reopen rule: only a TRUE whose own report time is newer than the accepted stop may
        // open a new activity cycle. A heartbeat is never enough, and neither is a late duplicate
        // of a TRUE that belongs to the generation we just stopped.
        if self.stop_latched && report_ms > self.latch_stop_report_ms {
            self.release_latch("newer trusted TRUE after the accepted stop");
        }
        let known = self.entries.get(&inst).copied();
        match known {
            Some(mut e) => {
                if e.state == PidState::Stopped {
                    // A stream generation we already saw end; the wait between that end and
                    // this start is not monitor silence, so only re-baseline.
                    e.last_arrival_ms = arrival_ms;
                } else {
                    // `Busy` or `Lost`: this is exactly the window whose silence matters.
                    self.observe_liveness(&mut e, arrival_ms);
                }
                e.last_seen_ms = now_ms.max(e.last_seen_ms);
                if e.state != PidState::Busy {
                    // Stopped -> Busy or Lost -> Busy is a new stream generation.
                    e.epoch = e.epoch.saturating_add(1);
                    e.state = PidState::Busy;
                    e.last_true_ms = report_ms;
                } else if report_ms > e.last_true_ms {
                    e.last_true_ms = report_ms;
                }
                self.entries.insert(inst, e);
            }
            None => {
                self.entries.insert(
                    inst,
                    PidEntry {
                        inst,
                        epoch: 1,
                        state: PidState::Busy,
                        last_true_ms: report_ms,
                        last_stop_ms: 0,
                        last_seen_ms: now_ms,
                        last_arrival_ms: arrival_ms,
                    },
                );
                self.ever_busy = true;
            }
        }
        // R9: a genuine new stream wins immediately and cancels whatever retraction is still
        // waiting (the engine only issues SET_CUR(2) after the grace, on an Inactive reading).
        self.r2_active = false;
        self.suppress_until_ms = None;
    }

    fn note_false(&mut self, inst: ProcInstance, report_ms: u64, arrival_ms: u64, now_ms: u64) {
        self.telemetry.callbacks += 1;
        let Some(mut e) = self.entries.get(&inst).copied() else {
            // An isolated FALSE: no TRUE ever registered this instance. It cannot tell us the
            // CM400 stopped - it may not even be about the stream we care about. Nothing about
            // the instance is refreshed either.
            self.telemetry.stale_stopped += 1;
            return;
        };
        if e.state == PidState::Stopped {
            // Already stopped by an earlier explicit FALSE. Repeating it proves nothing new and
            // must not extend the instance's liveness.
            self.telemetry.stale_stopped += 1;
            return;
        }
        if report_ms <= e.last_true_ms {
            // Covers both "an old FALSE arrived late" and "a newer TRUE already reopened this
            // instance": within one source, report time is the order, and an older idle claim
            // can never override a newer activity claim (design example B).
            //
            // Deliberately no `last_seen_ms`/`last_arrival_ms` update: a report that failed the
            // ordering check is not evidence that the stream is still there, and refreshing
            // liveness with it would postpone `Busy -> Lost` - repeated stale reports could keep
            // a `Busy` registration alive indefinitely on evidence we just refused to act on.
            self.telemetry.stale_stopped += 1;
            return;
        }
        // Ruling A (2026-10-11): a stop is accepted from `Busy` **or** `Lost`.
        //
        // Silence alone is never a stop - that is what `Busy -> Lost -> NoData` encodes, and it
        // still holds: with no FALSE at all the device never becomes Idle here. But an explicit
        // `streaming=0` for the very same `(pid, created_ms)`, stamped after that instance's
        // newest TRUE, is positive evidence, and refusing it would make R2 fail precisely in the
        // long-session case (the longer a stream runs, the likelier a quiet stretch has already
        // decayed the registration). Identity is the key; the epoch is protected by the
        // `report_ms > last_true_ms` test above, because a reopened instance moved `last_true_ms`
        // past any FALSE that belongs to the previous generation.
        self.observe_liveness(&mut e, arrival_ms);
        e.last_seen_ms = now_ms.max(e.last_seen_ms);
        e.state = PidState::Stopped;
        e.last_stop_ms = report_ms;
        self.entries.insert(inst, e);
    }

    /// `Busy` entries that stopped appearing degrade to `Lost`. Absence is not a stop.
    pub fn expire(&mut self, now_ms: u64) {
        for e in self.entries.values_mut() {
            if e.state == PidState::Busy
                && now_ms.saturating_sub(e.last_seen_ms) > self.lost_grace_ms
            {
                e.state = PidState::Lost;
                self.telemetry.lost_transitions += 1;
            }
        }
    }

    /// The one place the two sources meet. Returns the device-level activity.
    pub fn activity(&mut self, now_ms: u64) -> CM400Activity {
        self.expire(now_ms);
        let view = self.view(now_ms);

        if self.stop_latched {
            // The reopen guard is a state, so it is tested before the idle evaluation rather than
            // as one of its branches: the authorization behind the latch is consumed when it arms,
            // and the instance's own registration may decay afterwards. A live client still
            // outranks it (R1).
            if view == SAMView::Busy {
                self.release_latch("a live client reappeared");
            } else {
                if self.hb.state(now_ms) == CM400Activity::Active {
                    self.telemetry.suppressed_reactivations += 1;
                }
                self.blocker = Blocker::None;
                return CM400Activity::Inactive;
            }
        }

        if view == SAMView::Busy {
            // R1: a live SAM client outranks any staleness in the other source.
            self.blocker = Blocker::StillBusy;
            return CM400Activity::Active;
        }

        // R2's four preconditions (§4.1), evaluated on every reading.
        //
        // For the latch only, `SAM says every instance it knows has stopped` may also count as the
        // idle claim when `view` is `NoData` purely because SAM could not resolve its own
        // creation-time identity - which is the real service context, where that lookup is denied
        // for every report. The identity is then supplied by the lifecycle ledger instead (an
        // attributed stop plus a trusted ledger), and nothing about absence is being read as
        // idleness: `all_stopped` rejects an empty table, a `Lost` entry and a `Busy` entry.
        let latch_idle = matches!(self.suppression, Suppression::Latched)
            && view == SAMView::NoData
            && self.ledger_trusted
            && self.authorization_is_current()
            && self.all_stopped();
        if (view == SAMView::Idle || latch_idle) && self.r2_allowed() {
            match self.suppression {
                Suppression::Disabled => {
                    // Evidence is complete, but the blind period would be unbounded because
                    // no measured tail bound exists. R2 stays off; the heartbeat path decides,
                    // i.e. exactly today's behaviour. Shadow phase asserts this shape.
                    self.blocker = Blocker::SuppressionUnset;
                }
                Suppression::Bounded(ms) => {
                    if !self.r2_active {
                        self.r2_active = true;
                        self.telemetry.r2_applied += 1;
                        self.suppress_until_ms = Some(now_ms.saturating_add(ms));
                    }
                    if self.suppression_open(now_ms) {
                        // R8 lives here: fresh heartbeats belong to the stream that was just
                        // explicitly stopped. Counted when that is actually the case, so the
                        // metric means "the tail was outrun", not "a window existed".
                        if self.hb.state(now_ms) == CM400Activity::Active {
                            self.telemetry.suppressed_reactivations += 1;
                        }
                        self.blocker = Blocker::None;
                        return CM400Activity::Inactive;
                    }
                    // The window elapsed. Recovery is bounded by `ms`, a declared constant,
                    // rather than by a gap that may never appear (§4.2 variant A, disproved).
                    self.blocker = Blocker::None;
                }
                Suppression::Latched => {
                    if !self.ledger_trusted || !self.authorization_is_current() {
                        // Either the lifecycle ledger cannot be trusted, or no `streaming=0` has
                        // been attributed to a verified instance. Refusing here is not a retract:
                        // the heartbeat answers, exactly as it did before R2 existed.
                        self.blocker = Blocker::LedgerUntrusted;
                    } else {
                        // Holding is handled above, before the idle evaluation; reaching here
                        // means this is a fresh authorization.
                        self.r2_active = true;
                        self.stop_latched = true;
                        self.latch_stop_report_ms = self.stop_attributed_ms;
                        // One attributed stop authorizes exactly one latch. Afterwards the fast
                        // path must be re-authorized by a new attributable stop.
                        self.stop_attributed_ms = 0;
                        self.telemetry.r2_applied += 1;
                        self.telemetry.latch_armed += 1;
                        self.blocker = Blocker::None;
                        return CM400Activity::Inactive;
                    }
                }
            }
        } else if view == SAMView::Idle {
            self.blocker = self.idle_blocker();
        } else {
            // NoData must also name its own reason, otherwise the log keeps reporting the
            // blocker of a previous reading.
            self.blocker = self.no_data_blocker();
        }

        // R4 / R5, and the fallback whenever R2 was refused or the window closed. There is
        // deliberately no suppression here: any backend failure clears the window first, so a
        // degraded SAM can never keep heartbeats muted (ruling B).
        if !self.sam_healthy {
            self.blocker = Blocker::MonitorUnhealthy;
        }
        match self.hb.state(now_ms) {
            CM400Activity::Unknown => CM400Activity::Unknown,
            CM400Activity::Active => {
                self.r2_active = false;
                CM400Activity::Active
            }
            CM400Activity::Inactive => CM400Activity::Inactive,
        }
    }

    /// Read-only look at one instance's registration, for the shadow log line. Cannot change
    /// anything: the whole point of shadow is that observation and decision stay separate.
    pub fn peek(&self, inst: ProcInstance) -> Option<PidEntry> {
        self.entries.get(&inst).copied()
    }

    /// Tell the arbiter whether the reports it is being fed were attributed against a trusted
    /// lifecycle ledger. This is a permission for `Suppression::Latched` and nothing else: it
    /// cannot make an unresolved instance resolvable, and it changes no state by itself.
    ///
    /// Losing the permission while a latch holds releases it: a latch built on evidence we no
    /// longer trust must not keep the heartbeats muted (same ruling as a monitor fault).
    pub fn set_ledger_trusted(&mut self, trusted: bool) {
        if !trusted && self.ledger_trusted {
            self.release_latch("lifecycle ledger lost trust");
        }
        self.ledger_trusted = trusted;
    }

    /// The caller has attributed a `streaming=0` report to a verified process instance and
    /// accepted it as the device's stop. Its report time becomes the ordering point for the
    /// reopen rule: only a newer TRUE may start a new activity cycle.
    ///
    /// This is the only way to authorize the fast path. A stop that merely arrived, or one the
    /// ledger refused, never does.
    pub fn note_attributed_stop(&mut self, report_ms: u64) {
        if report_ms == 0 {
            // No usable time to order anything against: authorize nothing.
            return;
        }
        if report_ms > self.stop_attributed_ms {
            self.stop_attributed_ms = report_ms;
        }
    }

    /// `(held, armed_total, released_total, last_release_reason)` for the beat line.
    pub fn latch_state(&self) -> (bool, u64, u64, &'static str) {
        (
            self.stop_latched,
            self.telemetry.latch_armed,
            self.telemetry.latch_released,
            self.last_latch_release,
        )
    }

    /// The only ways out of a held stop latch, all of them evidence-based.
    fn release_latch(&mut self, why: &'static str) {
        if self.stop_latched {
            self.stop_latched = false;
            self.latch_stop_report_ms = 0;
            self.stop_attributed_ms = 0;
            // R2 goes off with the latch, so a later Idle can arm a fresh one for a fresh stop.
            self.r2_active = false;
            self.telemetry.latch_released += 1;
            self.last_latch_release = why;
        }
    }

    /// Shadow-phase logging: would `R2` have been applied right now? Never a decision.
    pub fn r2_would_apply(&mut self, now_ms: u64) -> bool {
        self.expire(now_ms);
        self.view(now_ms) == SAMView::Idle && self.r2_allowed()
    }

    fn r2_allowed(&self) -> bool {
        if !self.sam_healthy {
            return false;
        }
        if self.entries.is_empty() {
            return false;
        }
        match self.suppression {
            // The latch is authorized by an *attributed* stop from a trusted lifecycle ledger,
            // which says more about this instance than SAM's own creation-time identity does -
            // and in the service context that lookup is denied outright, so requiring it here
            // would make the fast path unreachable without adding any safety. Unidentified or
            // unresolved clients still block it through `view`: a Busy entry is `Busy`, and a
            // client that vanished without a stop leaves the view `NoData`, never `Idle`.
            Suppression::Latched => true,
            _ => self.entries.values().all(|e| e.inst.identity_resolved()),
        }
    }

    fn idle_blocker(&self) -> Blocker {
        if !self.sam_healthy {
            Blocker::MonitorUnhealthy
        } else if self.entries.values().any(|e| e.state == PidState::Lost) {
            Blocker::UnresolvedInstances
        } else if self.entries.values().any(|e| !e.inst.identity_resolved()) {
            Blocker::IdentityUnresolved
        } else {
            Blocker::NeverBusy
        }
    }

    fn no_data_blocker(&self) -> Blocker {
        if !self.ever_busy || self.entries.is_empty() {
            Blocker::NeverBusy
        } else if !self.sam_healthy {
            Blocker::MonitorUnhealthy
        } else if self.entries.values().any(|e| e.state != PidState::Stopped) {
            Blocker::UnresolvedInstances
        } else {
            Blocker::IdentityUnresolved
        }
    }

    /// Structured snapshot for the beat line. Deliberately not used by any decision.
    pub fn snapshot(&self, now_ms: u64) -> String {
        let mut ids: Vec<u32> = self.entries.keys().map(|k| k.pid).collect();
        ids.sort_unstable();
        format!(
            "SAM view={:?} instances={:?} blocker={:?} suppress_open={} healthy={} max_report_gap_ms={} telemetry={{ cb={} empty={} other={} propfail={} stale={} lost={} faults={} rec={} r2={} suppressed={} }}",
            self.view(now_ms),
            ids,
            self.blocker,
            self.suppression_open(now_ms),
            self.sam_healthy,
            self.telemetry.max_report_gap_ms,
            self.telemetry.callbacks,
            self.telemetry.empty_list,
            self.telemetry.other_device,
            self.telemetry.property_failures,
            self.telemetry.stale_stopped,
            self.telemetry.lost_transitions,
            self.telemetry.faults,
            self.telemetry.recoveries,
            self.telemetry.r2_applied,
            self.telemetry.suppressed_reactivations,
        )
    }
}

/// Case-insensitive full-link filter used by the source before anything reaches the
/// arbiter. Kept free of COM so it can be tested against real link strings.
pub fn link_is_cm400(target_link: &str, reported: &str) -> bool {
    target_link.eq_ignore_ascii_case(reported)
}

/// Which backend is allowed to answer the policy. Pure, so the rollout gate itself is tested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivityBackend {
    /// Today's shipped behaviour: heartbeat recency only. SAM is not even consulted.
    HeartbeatOnly,
    /// SAM is fed, arbitrated and logged, but the policy still hears the heartbeat answer.
    /// This is the shadow phase the design requires before R2 can be considered.
    SensorShadow,
    /// The arbiter answers, falling back to the heartbeat whenever SAM has no opinion.
    SensorArbitrating,
}

/// The last gate before the policy.
///
/// `SensorArbitrating` still falls back to the heartbeat when the arbiter produced no answer
/// at all (monitor never started, or the control loop has not read a report yet). A missing
/// backend must degrade to today's behaviour, never to a invented state.
pub fn backend_choice(
    backend: ActivityBackend,
    heartbeat: CM400Activity,
    arbitrated: Option<CM400Activity>,
) -> CM400Activity {
    match backend {
        ActivityBackend::HeartbeatOnly | ActivityBackend::SensorShadow => heartbeat,
        ActivityBackend::SensorArbitrating => arbitrated.unwrap_or(heartbeat),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINK: &str = "\\\\?\\usb#vid_0603&pid_8612&mi_00#8&2e26e82&0&0000#{e5323777-f976-4f5b-9b55-b94699c46e44}\\global";
    const OTHER: &str = "\\\\?\\usb#vid_30c9&pid_00c2&mi_00#7&3158ba07&0&0000#{e5323777-f976-4f5b-9b55-b94699c46e44}\\global";
    const HB_TIMEOUT: u64 = 3_000;
    const GRACE: u64 = 3_000;

    fn inst(pid: u32) -> ProcInstance {
        ProcInstance::from_creation_time(pid, 1_000 + pid as u64)
    }

    fn arb() -> Arbiter {
        // No suppression by default: a bounded window needs a measured tail bound.
        Arbiter::new(LINK, HB_TIMEOUT, Suppression::Disabled)
    }

    fn bounded(ms: u64) -> Arbiter {
        Arbiter::new(LINK, HB_TIMEOUT, Suppression::Bounded(ms))
    }

    fn busy(a: &mut Arbiter, at: u64, pid: u32) {
        a.apply(
            at,
            Evidence::PidStreaming {
                inst: inst(pid),
                report_ms: at,
                arrival_ms: at,
            },
        );
    }

    fn stopped(a: &mut Arbiter, at: u64, pid: u32) {
        a.apply(
            at,
            Evidence::PidStopped {
                inst: inst(pid),
                report_ms: at,
                arrival_ms: at,
            },
        );
    }

    /// Explicit control-loop time / report time / callback arrival time, for the tests that
    /// need them to differ (liveness freshness and the silence metric).
    fn true_at(a: &mut Arbiter, now: u64, report_ms: u64, arrival_ms: u64, pid: u32) {
        a.apply(
            now,
            Evidence::PidStreaming {
                inst: inst(pid),
                report_ms,
                arrival_ms,
            },
        );
    }

    fn false_at(a: &mut Arbiter, now: u64, report_ms: u64, arrival_ms: u64, pid: u32) {
        a.apply(
            now,
            Evidence::PidStopped {
                inst: inst(pid),
                report_ms,
                arrival_ms,
            },
        );
    }

    /// A CM400 heartbeat, i.e. the thing whose tail we are trying to stop trusting.
    fn beat(a: &mut Arbiter, at: u64) {
        a.apply(at, Evidence::HeartbeatSeen { arrival_ms: at });
    }

    #[test]
    fn nothing_is_invented_before_any_evidence() {
        let mut a = arb();
        // Unknown, not Inactive: the engine must Hold rather than retract on a fresh start.
        assert_eq!(a.activity(50_000), CM400Activity::Unknown);
        assert_eq!(a.view(50_000), SAMView::NoData);
    }

    #[test]
    fn true_then_false_stops_without_waiting_for_the_heartbeat_tail() {
        let mut a = bounded(25_000);
        busy(&mut a, 1_000, 4994);
        beat(&mut a, 1_500);
        assert_eq!(a.activity(1_600), CM400Activity::Active); // R1

        stopped(&mut a, 5_000, 4994);
        // The tail is still fresh (last beat 1.5s ago, timeout 3s) yet SAM's explicit stop wins.
        assert_eq!(a.activity(5_288), CM400Activity::Inactive); // R2
        assert_eq!(a.blocker(), Blocker::None);
        assert_eq!(a.telemetry.r2_applied, 1);
        assert_eq!(a.view(5_288), SAMView::Idle);
        // 5_288 - 288ms is the measured stop-report latency shape from the 20-round probe.
        assert!(a.suppression_open(25_000), "R2 armed a bounded window");
    }

    /// The gate from design §4.2 item 5: without a measured stop-tail bound, R2 must stay
    /// disabled. SAM may still activate early (R1), but it cannot accelerate a retraction,
    /// so behaviour is identical to the current production build.
    #[test]
    fn with_no_measured_bound_r2_stays_off_and_today_is_unchanged() {
        let mut a = arb(); // Suppression::Disabled
        busy(&mut a, 1_000, 4994);
        beat(&mut a, 4_900);
        // A report during the stream keeps the registration from decaying to `Lost`
        // (the probe measured 8-16 reports per round, so refresh is the normal case).
        busy(&mut a, 4_950, 4994);
        assert_eq!(a.activity(5_000), CM400Activity::Active);
        stopped(&mut a, 5_100, 4994);
        // Evidence is complete, so the shadow view knows R2 *would* apply...
        assert_eq!(a.view(5_200), SAMView::Idle);
        assert!(a.r2_would_apply(5_200));
        // ...but the decision keeps following the heartbeat path, and no window is armed.
        assert_eq!(a.activity(5_200), CM400Activity::Active);
        assert_eq!(a.blocker(), Blocker::SuppressionUnset);
        assert_eq!(
            a.telemetry.r2_applied, 0,
            "R2 must not be applied without a bound"
        );
        assert!(!a.suppression_open(5_200));
        // And the ordinary timeout still ends the stream the way it does today.
        assert_eq!(a.activity(5_100 + HB_TIMEOUT + 1), CM400Activity::Inactive);
    }

    #[test]
    fn an_isolated_false_never_stops_the_device() {
        let mut a = arb();
        beat(&mut a, 1_000);
        a.apply(
            1_100,
            Evidence::PidStopped {
                inst: inst(7777),
                report_ms: 1_100,
                arrival_ms: 1_100,
            },
        );
        // No TRUE was ever seen for 7777: heartbeat path must keep governing.
        assert_eq!(a.activity(1_200), CM400Activity::Active);
        assert_eq!(a.view(1_200), SAMView::NoData);
        assert_eq!(
            a.telemetry.stale_stopped, 1,
            "isolated FALSE is counted, not obeyed"
        );
    }

    #[test]
    fn no_data_shapes_are_never_read_as_stopped() {
        for kind in [
            NoMatchKind::EmptyCollection,
            NoMatchKind::NoCm400Report,
            NoMatchKind::PropertyReadFailed(-2147024809),
        ] {
            let mut a = arb();
            busy(&mut a, 1_000, 4994);
            assert_eq!(a.activity(1_100), CM400Activity::Active);
            a.apply(1_200, Evidence::NoMatchingReport { kind });
            // Still Busy: an empty set is not a stop.
            assert_eq!(a.view(1_300), SAMView::Busy, "{kind:?} degraded the view");
            assert_eq!(
                a.activity(1_300),
                CM400Activity::Active,
                "{kind:?} changed activity"
            );
            // And with no Busy entry either, they must not manufacture Inactive:
            let mut b = arb();
            beat(&mut b, 1_000);
            b.apply(1_100, Evidence::NoMatchingReport { kind });
            assert_eq!(
                b.activity(1_200),
                CM400Activity::Active,
                "{kind:?} invented a stop"
            );
        }
    }

    #[test]
    fn a_wrong_link_is_dropped_and_changes_nothing() {
        let mut a = arb();
        busy(&mut a, 1_000, 4994);
        beat(&mut a, 4_000);
        // The built-in camera's own reports must never touch CM400 state, in either direction.
        assert!(!a.link_matches(OTHER), "link match must be exact");
        assert!(a.link_matches(LINK));
        assert!(
            a.link_matches(&LINK.to_ascii_uppercase()),
            "compare is case-insensitive"
        );
        assert!(!a.link_matches("vid_0603"), "a fragment is not a link");
        a.apply(
            4_100,
            Evidence::UnmatchedReport {
                link: OTHER.to_string(),
                pid: 1,
            },
        );
        a.apply(
            4_200,
            Evidence::PidStopped {
                inst: inst(9999),
                report_ms: 4_200,
                arrival_ms: 4_200,
            },
        );
        assert_eq!(a.activity(4_300), CM400Activity::Active);
        assert_eq!(a.telemetry.other_device, 1);
        assert_eq!(a.telemetry.stale_stopped, 1);
    }

    #[test]
    fn same_pid_with_a_different_creation_time_is_a_different_instance() {
        let mut a = bounded(25_000);
        let old = ProcInstance::from_creation_time(4994, 111);
        let fresh = ProcInstance::from_creation_time(4994, 222);
        a.apply(
            1_000,
            Evidence::PidStreaming {
                inst: old,
                report_ms: 1_000,
                arrival_ms: 1_000,
            },
        );
        // PID recycled: the new instance is a live stream, and the old instance's stop must
        // not be able to idle it.
        a.apply(
            2_000,
            Evidence::PidStreaming {
                inst: fresh,
                report_ms: 2_000,
                arrival_ms: 2_000,
            },
        );
        beat(&mut a, 3_900);
        a.apply(
            3_000,
            Evidence::PidStopped {
                inst: old,
                report_ms: 3_000,
                arrival_ms: 3_000,
            },
        );
        assert_eq!(a.view(3_100), SAMView::Busy);
        assert_eq!(a.activity(3_100), CM400Activity::Active);
        assert_eq!(
            a.telemetry.r2_applied, 0,
            "one live client cannot be idled by a dead one"
        );
        // Only when the new instance is also explicitly stopped does the device idle.
        a.apply(
            4_000,
            Evidence::PidStopped {
                inst: fresh,
                report_ms: 4_000,
                arrival_ms: 4_000,
            },
        );
        assert_eq!(
            a.activity(4_100),
            CM400Activity::Inactive,
            "with the tail still fresh"
        );
    }

    #[test]
    fn an_unresolved_identity_can_never_produce_a_stop() {
        let mut a = bounded(25_000);
        let unknown = ProcInstance::unresolved(4994);
        a.apply(
            1_000,
            Evidence::PidStreaming {
                inst: unknown,
                report_ms: 1_000,
                arrival_ms: 1_000,
            },
        );
        beat(&mut a, 1_900);
        assert_eq!(a.activity(1_100), CM400Activity::Active);
        a.apply(
            2_000,
            Evidence::PidStopped {
                inst: unknown,
                report_ms: 2_000,
                arrival_ms: 2_000,
            },
        );
        // All entries Stopped, but identity is unresolved -> not Idle, and the fresh tail wins.
        assert_eq!(a.view(2_100), SAMView::NoData);
        assert_eq!(a.activity(2_100), CM400Activity::Active);
        assert_eq!(a.telemetry.r2_applied, 0, "R2 must not be applied");
        assert!(
            !a.r2_would_apply(2_100),
            "not even in shadow: an unattributable stop is not a stop"
        );
        assert_eq!(a.blocker(), Blocker::IdentityUnresolved);
    }

    #[test]
    fn a_stale_false_older_than_the_true_is_dropped() {
        let mut a = arb();
        busy(&mut a, 1_000, 4994);
        // FALSE arrives after the TRUE in wall time but carries an older report time.
        a.apply(
            1_200,
            Evidence::PidStopped {
                inst: inst(4994),
                report_ms: 900,
                arrival_ms: 1_200,
            },
        );
        assert_eq!(
            a.view(1_300),
            SAMView::Busy,
            "an older stop cannot override a newer true"
        );
        assert_eq!(a.activity(1_300), CM400Activity::Active);
        assert_eq!(a.telemetry.stale_stopped, 1);
    }

    #[test]
    fn a_second_busy_client_blocks_the_first_clients_stop() {
        let mut a = bounded(25_000);
        busy(&mut a, 1_000, 1111);
        busy(&mut a, 1_100, 2222);
        beat(&mut a, 1_900);
        stopped(&mut a, 2_000, 1111);
        // Multi-client semantics are unverified on this rig, so one remaining client wins.
        assert_eq!(a.view(2_100), SAMView::Busy);
        assert_eq!(a.activity(2_100), CM400Activity::Active);
        assert_eq!(a.blocker(), Blocker::StillBusy);
        assert_eq!(a.telemetry.r2_applied, 0);
        stopped(&mut a, 3_000, 2222);
        assert_eq!(a.activity(3_100), CM400Activity::Inactive);
        assert_eq!(a.telemetry.r2_applied, 1, "R2 waited for every client");
    }

    #[test]
    fn a_missing_client_degrades_to_nodata_and_never_idle() {
        let mut a = bounded(25_000);
        busy(&mut a, 1_000, 1111);
        busy(&mut a, 1_000, 2222);
        stopped(&mut a, 2_000, 1111);
        beat(&mut a, 3_900);
        // 2222 stops appearing in reports. Absence must not become a stop.
        let lost_at = 1_000 + LOST_GRACE_MS + 1;
        assert_eq!(
            a.activity(lost_at),
            CM400Activity::Active,
            "fresh tail keeps it Active (R6)"
        );
        assert_eq!(a.view(lost_at), SAMView::NoData);
        assert_eq!(a.blocker(), Blocker::UnresolvedInstances);
        assert_eq!(a.telemetry.lost_transitions, 1);
        assert!(
            !a.r2_would_apply(lost_at),
            "a disappeared client is not an explicit stop"
        );
        // Once the heartbeat path is also stale, the ordinary timeout decides (R5).
        let late = lost_at + HB_TIMEOUT + 1;
        assert_eq!(a.activity(late), CM400Activity::Inactive);
        assert_eq!(
            a.telemetry.r2_applied, 0,
            "the stop came from the timeout, not from SAM"
        );
    }

    #[test]
    fn late_heartbeats_do_not_reactivate_inside_the_suppression_window() {
        let mut a = bounded(20_000);
        busy(&mut a, 1_000, 4994);
        beat(&mut a, 1_200);
        stopped(&mut a, 5_000, 4994);
        assert_eq!(a.activity(5_100), CM400Activity::Inactive); // R2 arms until 25_100
        assert!(a.suppression_open(6_000));
        assert!(
            !a.suppression_open(25_100),
            "the blind period is bounded by the declared ms"
        );
        // The tail keeps beating. While SAM still reports Idle and the window is open, that
        // must not reactivate the stream, and the suppression has to be *counted*.
        beat(&mut a, 6_000);
        assert_eq!(a.activity(6_100), CM400Activity::Inactive, "R8 held");
        assert!(
            a.telemetry.suppressed_reactivations >= 1,
            "the tail being outrun must be measurable"
        );
    }

    /// Ruling B: once the backend fails, it may no longer mute heartbeats - the window goes,
    /// the old ETW path takes over on the very next reading.
    #[test]
    fn a_backend_failure_releases_the_window_instead_of_extending_it() {
        let mut a = bounded(60_000);
        busy(&mut a, 1_000, 4994);
        stopped(&mut a, 5_000, 4994);
        assert_eq!(a.activity(5_100), CM400Activity::Inactive);
        assert!(
            a.suppression_open(6_000),
            "window armed, would run to 65_100"
        );
        // The monitor reports an explicit fault (not silence).
        a.apply(
            6_000,
            Evidence::MonitorFault {
                kind: MonitorFaultKind::DeviceGone,
            },
        );
        assert!(
            !a.suppression_open(6_100),
            "a failed backend must not keep heartbeats muted"
        );
        // A fresh heartbeat now restores Active exactly as it does today.
        a.apply(6_200, Evidence::HeartbeatSeen { arrival_ms: 6_200 });
        assert_eq!(a.activity(6_300), CM400Activity::Active, "fell back to R4");
        assert_eq!(a.blocker(), Blocker::MonitorUnhealthy);
    }

    /// Ruling B for the stronger case: the backend is gone entirely (re-enumeration), so every
    /// record we hold describes an ended generation *and* the window must not outlive it.
    #[test]
    fn backend_gone_clears_the_table_and_the_armed_window() {
        let mut a = bounded(60_000);
        busy(&mut a, 1_000, 4994);
        stopped(&mut a, 5_000, 4994);
        assert_eq!(a.activity(5_100), CM400Activity::Inactive);
        assert!(a.suppression_open(6_000));
        a.apply(
            6_000,
            Evidence::BackendGone {
                why: BackendGoneReason::Reenumerated,
            },
        );
        assert_eq!(a.view(6_100), SAMView::NoData, "the table was cleared");
        assert!(!a.suppression_open(6_100), "the window was cleared too");
        // Nothing left to re-arm R2 from: the heartbeat path decides, in both directions.
        a.apply(6_200, Evidence::HeartbeatSeen { arrival_ms: 6_200 });
        assert_eq!(
            a.activity(6_300),
            CM400Activity::Active,
            "recovery does not wait for a signal that may never come"
        );
        assert_eq!(
            a.telemetry.r2_applied, 1,
            "only the pre-failure application"
        );
    }

    #[test]
    fn the_old_heartbeat_path_resumes_when_the_window_expires() {
        let mut a = bounded(10_000);
        busy(&mut a, 1_000, 4994);
        beat(&mut a, 4_900);
        stopped(&mut a, 5_000, 4994);
        assert_eq!(a.activity(5_100), CM400Activity::Inactive); // window until 15_100
        beat(&mut a, 5_250);
        assert_eq!(
            a.activity(5_300),
            CM400Activity::Inactive,
            "still inside the window"
        );
        // After the window a fresh heartbeat means Active again: recovery is bounded by a
        // declared constant, not by a gap that may never appear (§4.2 variant A, disproved).
        beat(&mut a, 15_150);
        assert!(!a.suppression_open(15_200));
        assert_eq!(a.activity(15_200), CM400Activity::Active, "R4 restored");
        // And the ordinary timeout still owns the fallback: silence ends the stream as before.
        assert_eq!(a.activity(15_200 + HB_TIMEOUT + 1), CM400Activity::Inactive);
    }

    #[test]
    fn a_new_true_after_the_stop_reactivates_and_cancels_the_pending_retraction() {
        let mut a = bounded(20_000);
        busy(&mut a, 1_000, 4994);
        stopped(&mut a, 5_000, 4994);
        assert_eq!(a.activity(5_100), CM400Activity::Inactive); // R2 would retract after grace
                                                                // Reopen inside the grace: same instance, newer report time -> new epoch, immediate Active.
        busy(&mut a, 6_000, 4994);
        assert_eq!(a.activity(6_100), CM400Activity::Active, "R9");
        assert!(
            !a.suppression_open(6_100),
            "the window must not keep suppressing a live stream"
        );
        let e = a.entries[&inst(4994)];
        assert_eq!(e.epoch, 2, "a reopened stream is a new generation");
        assert_eq!(e.state, PidState::Busy);
    }

    #[test]
    fn an_explicit_monitor_fault_falls_back_without_inventing_a_stop() {
        // A fault is not a stop: even with everything Stopped, R2 is refused, and with no
        // heartbeat history the honest answer is Unknown (never Inactive).
        let mut a = bounded(25_000);
        busy(&mut a, 1_000, 4994);
        stopped(&mut a, 2_000, 4994);
        a.apply(
            2_100,
            Evidence::MonitorFault {
                kind: MonitorFaultKind::StartFailed(-2147024891),
            },
        );
        assert!(!a.r2_allowed());
        assert_eq!(
            a.activity(2_200),
            CM400Activity::Unknown,
            "a fault may only yield Active or Unknown"
        );
        assert_eq!(a.telemetry.r2_applied, 0);
        // With a fresh tail, the same fault keeps the device Active rather than retracting on a
        // broken backend.
        let mut b = bounded(25_000);
        busy(&mut b, 1_000, 4994);
        stopped(&mut b, 2_000, 4994);
        beat(&mut b, 4_900);
        b.apply(
            5_000,
            Evidence::MonitorFault {
                kind: MonitorFaultKind::DeviceGone,
            },
        );
        assert_eq!(b.activity(5_100), CM400Activity::Active);
        assert_eq!(b.blocker(), Blocker::MonitorUnhealthy);
        assert_eq!(b.telemetry.r2_applied, 0, "the fault refused R2");
    }

    #[test]
    fn an_explicit_stop_retracts_once_and_the_window_bounds_reactivation() {
        // Drives the real Engine so the grace and the write throttle are part of the proof,
        // not just asserted in prose.
        use cm400_core::{Engine, Store, Transport};
        use cm400_policy::Policy;
        use cm400_state::MotorStatus;

        struct Tx(Vec<u8>);
        impl Transport for Tx {
            fn get(&mut self) -> Result<u8, ()> {
                Ok(0)
            }
            fn set(&mut self, v: u8) -> Result<(), ()> {
                self.0.push(v);
                Ok(())
            }
        }
        struct Clk(u64);
        impl cm400_core::Clock for Clk {
            fn now_ms(&mut self) -> u64 {
                self.0
            }
        }
        struct Mem(Option<MotorStatus>);
        impl Store for Mem {
            fn load(&mut self) -> Option<MotorStatus> {
                self.0
            }
            fn save(&mut self, s: &MotorStatus) {
                self.0 = Some(*s)
            }
        }

        let mut a = bounded(20_000);
        let mut eng = Engine::new(Policy {
            mode: cm400_policy::Mode::Automatic,
            down_grace_ms: GRACE,
        });
        let mut tx = Tx(Vec::new());
        let mut store = Mem(None);
        let mut clock = Clk(0);
        // When each command left the engine, so the grace and the throttle are checked against
        // real times rather than against a command count.
        let mut at: Vec<u64> = Vec::new();

        // Stream up: SAM TRUE + heartbeats -> one Raise, and the lens settles. SAM keeps
        // reporting while the stream is up, so the registration is refreshed (a silent one
        // decays to `Lost`, which is its own tested case below).
        busy(&mut a, 1_000, 4994);
        for t in (1_000..=7_500u64).step_by(500) {
            if t % 2_000 == 0 {
                busy(&mut a, t, 4994);
            }
            beat(&mut a, t);
            clock.0 = t;
            let act = a.activity(t);
            let before = tx.0.len();
            eng.tick(&mut act_src(act), &mut clock, &mut tx, &mut store);
            if tx.0.len() > before {
                at.push(t);
            }
        }
        assert_eq!(tx.0, vec![1], "one raise while streaming");

        // Stop reported while the tail keeps beating: R2 holds Inactive for the whole window, so
        // exactly one retraction goes out - and never before the existing down grace elapsed.
        stopped(&mut a, 8_000, 4994);
        for t in (8_000..=27_500u64).step_by(500) {
            beat(&mut a, t);
            clock.0 = t;
            let act = a.activity(t);
            let before = tx.0.len();
            eng.tick(&mut act_src(act), &mut clock, &mut tx, &mut store);
            if tx.0.len() > before {
                at.push(t);
                assert!(
                    t >= 8_000 + GRACE,
                    "retract issued before the grace elapsed at t={t}"
                );
            }
        }
        assert_eq!(
            tx.0,
            vec![1, 2],
            "exactly one retraction, no churn while suppressing"
        );

        // Declared consequence of the bounded window: once it expires, heartbeats that are still
        // arriving take the old path again. That is the upper bound of the blind period, not a
        // permanent claim of inactivity - and it is still rate-limited by the write gap.
        for t in (28_100..=31_000u64).step_by(500) {
            beat(&mut a, t);
            clock.0 = t;
            let act = a.activity(t);
            let before = tx.0.len();
            eng.tick(&mut act_src(act), &mut clock, &mut tx, &mut store);
            if tx.0.len() > before {
                at.push(t);
            }
        }
        assert_eq!(at.len(), 3, "raise, retract, re-raise: {at:?}");
        assert!(at[1] >= 8_000 + GRACE, "grace honoured: {at:?}");
        assert!(
            at[2] >= 28_000,
            "reactivation only after the declared window: {at:?}"
        );
        for w in at.windows(2) {
            assert!(
                w[1] - w[0] >= cm400_core::MIN_WRITE_GAP_MS,
                "commands {:?} violate the {}ms write gap",
                at,
                cm400_core::MIN_WRITE_GAP_MS
            );
        }
    }

    /// A registration that stops appearing decays to `Lost`, and an afterwards FALSE
    /// still stops it (ruling A, 2026-10-11). This is the long-session case the whole of R2
    /// exists for: the camera was confirmed streaming, SAM then went quiet as it is allowed
    /// to be, and the stream finally ended with an explicit report.
    #[test]
    fn a_long_quiet_stream_still_stops_on_the_explicit_false() {
        let mut a = bounded(25_000);
        busy(&mut a, 1_000, 4994);
        beat(&mut a, 1_200);
        assert_eq!(a.activity(1_300), CM400Activity::Active);
        // SAM says nothing for longer than the absence grace; the tail is still arriving.
        let late = 1_000 + LOST_GRACE_MS + 500;
        beat(&mut a, late - 100);
        assert_eq!(
            a.activity(late),
            CM400Activity::Active,
            "silence alone is not a stop (R6)"
        );
        assert_eq!(a.view(late), SAMView::NoData);
        assert_eq!(a.telemetry.lost_transitions, 1);
        assert_eq!(a.telemetry.r2_applied, 0, "nothing has been stopped yet");
        // The stream really ends, with an explicit FALSE for the same (pid, created_ms),
        // stamped after its TRUE.
        stopped(&mut a, late + 100, 4994);
        assert_eq!(
            a.view(late + 200),
            SAMView::Idle,
            "Lost -> Stopped is now legal"
        );
        assert_eq!(
            a.telemetry.stale_stopped, 0,
            "and it is not a refused report"
        );
        assert_eq!(
            a.activity(late + 300),
            CM400Activity::Inactive,
            "R2 fires after a long session"
        );
        assert_eq!(a.telemetry.r2_applied, 1);
    }

    /// Ruling A keeps its guard rails: a FALSE that is older than the instance's newest TRUE
    /// is still refused even when the instance is `Lost`.
    #[test]
    fn a_lost_instance_still_needs_a_false_newer_than_its_true() {
        let mut a = bounded(25_000);
        busy(&mut a, 1_000, 4994);
        beat(&mut a, 4_400);
        let lost_at = 1_000 + LOST_GRACE_MS + 500;
        assert_eq!(a.activity(lost_at), CM400Activity::Active);
        assert_eq!(a.view(lost_at), SAMView::NoData, "decayed while quiet");
        // Same instance, FALSE stamped *before* its TRUE: refuses, does not stop.
        a.apply(
            lost_at + 100,
            Evidence::PidStopped {
                inst: inst(4994),
                report_ms: 900,
                arrival_ms: lost_at + 100,
            },
        );
        assert_eq!(a.telemetry.stale_stopped, 1);
        assert_eq!(
            a.view(lost_at + 200),
            SAMView::NoData,
            "a stale FALSE cannot idle the device"
        );
        assert_eq!(a.telemetry.r2_applied, 0);
        // And a FALSE for a *different* creation time (recycled PID) cannot stop this one.
        let other = ProcInstance::from_creation_time(4994, 999_999);
        a.apply(
            lost_at + 300,
            Evidence::PidStopped {
                inst: other,
                report_ms: lost_at + 300,
                arrival_ms: lost_at + 300,
            },
        );
        assert_eq!(
            a.telemetry.stale_stopped, 2,
            "an unknown instance is an isolated FALSE"
        );
        assert_eq!(a.view(lost_at + 400), SAMView::NoData);
    }

    /// Stopping one instance is not stopping the device: while any other instance is `Lost`
    /// the view stays `NoData` and R2 must not fire.
    #[test]
    fn a_stopped_instance_beside_a_lost_one_is_not_idle() {
        let mut a = bounded(25_000);
        busy(&mut a, 1_000, 1111);
        busy(&mut a, 1_000, 2222);
        beat(&mut a, 4_400);
        let lost_at = 1_000 + LOST_GRACE_MS + 500;
        assert_eq!(a.activity(lost_at), CM400Activity::Active);
        // 1111 stops explicitly; 2222 merely went quiet and is Lost.
        stopped(&mut a, lost_at + 100, 1111);
        assert_eq!(
            a.view(lost_at + 200),
            SAMView::NoData,
            "one Lost instance blocks Idle"
        );
        assert_eq!(
            a.activity(lost_at + 300),
            CM400Activity::Active,
            "still Active on the tail"
        );
        assert_eq!(
            a.telemetry.r2_applied, 0,
            "R2 refused while a client is unresolved"
        );
        // 2222 now reports its own explicit stop: the device may idle.
        stopped(&mut a, lost_at + 400, 2222);
        assert_eq!(a.view(lost_at + 500), SAMView::Idle);
        assert_eq!(a.activity(lost_at + 500), CM400Activity::Inactive);
        assert_eq!(a.telemetry.r2_applied, 1);
    }

    /// Silence, decay and a missing monitor must never combine into an Idle claim: without an
    /// explicit FALSE the only way to Inactive is the ordinary heartbeat timeout (the old path).
    #[test]
    fn silence_without_an_explicit_false_never_idles_through_sam() {
        let mut a = bounded(25_000);
        busy(&mut a, 1_000, 4994);
        beat(&mut a, 1_200);
        // No further SAM reports at all, and no further heartbeats either.
        let much_later = 1_000 + 10 * LOST_GRACE_MS;
        assert_eq!(a.view(much_later), SAMView::NoData);
        assert_eq!(
            a.activity(much_later),
            CM400Activity::Inactive,
            "via R5, the heartbeat timeout"
        );
        assert_eq!(a.telemetry.r2_applied, 0, "SAM never claimed the stop");
        assert_eq!(a.telemetry.empty_list, 0);
        assert_eq!(a.blocker(), Blocker::UnresolvedInstances);
        // An empty collection afterwards still cannot be read as confirmation of anything.
        a.apply(
            much_later + 10,
            Evidence::NoMatchingReport {
                kind: NoMatchKind::EmptyCollection,
            },
        );
        assert_eq!(a.view(much_later + 20), SAMView::NoData);
        assert_eq!(a.telemetry.empty_list, 1, "counted, not acted on");
    }

    /// A retry that brings the monitor back restores its *permission* to produce `Idle`, and
    /// nothing else. With no explicit stop behind it, recovery must not fabricate one.
    #[test]
    fn a_recovered_monitor_restores_permission_but_never_invents_evidence() {
        let mut a = bounded(25_000);
        busy(&mut a, 1_000, 4994);
        beat(&mut a, 4_400);
        let lost_at = 1_000 + LOST_GRACE_MS + 500;
        assert_eq!(a.activity(lost_at), CM400Activity::Active);
        a.apply(
            lost_at + 10,
            Evidence::MonitorFault {
                kind: MonitorFaultKind::CreateFailed(-2147024774),
            },
        );
        assert!(
            !a.r2_allowed(),
            "an unhealthy monitor may not idle the device"
        );
        a.apply(lost_at + 20, Evidence::MonitorRecovered);
        assert_eq!(a.telemetry.recoveries, 1);
        assert!(
            a.r2_allowed(),
            "recovery restores the *permission*, which is all it does"
        );
        // ...and permission without evidence is still nothing: the instance is Lost, never
        // Stopped, so the view cannot become Idle and R2 cannot fire.
        assert_eq!(a.view(lost_at + 30), SAMView::NoData);
        assert_eq!(
            a.activity(lost_at + 30),
            CM400Activity::Active,
            "still the fresh tail"
        );
        assert_eq!(
            a.telemetry.r2_applied, 0,
            "recovering a monitor is not a stop report"
        );
        assert!(
            a.snapshot(lost_at + 40).contains("healthy=true"),
            "the log says so"
        );
    }

    /// With a real explicit stop behind it, a fault releases the window (ruling B) and a later
    /// recovery re-arms it - the stop evidence was never withdrawn, only the backend's health.
    #[test]
    fn recovery_rearms_r2_only_on_top_of_existing_explicit_stop() {
        let mut b = bounded(20_000);
        busy(&mut b, 1_000, 4994);
        stopped(&mut b, 5_000, 4994);
        assert_eq!(b.activity(5_100), CM400Activity::Inactive);
        assert!(b.suppression_open(6_000));
        b.apply(
            6_000,
            Evidence::MonitorFault {
                kind: MonitorFaultKind::StartFailed(-2147024770),
            },
        );
        assert!(!b.suppression_open(6_100), "the fault released the window");
        beat(&mut b, 6_200);
        assert_eq!(
            b.activity(6_300),
            CM400Activity::Active,
            "the old path is back in charge"
        );
        b.apply(7_000, Evidence::MonitorRecovered);
        assert_eq!(
            b.activity(7_100),
            CM400Activity::Inactive,
            "R2 re-arms on the same stop"
        );
        assert_eq!(b.telemetry.r2_applied, 2);
    }

    /// A FALSE that fails the ordering check must not keep the registration alive: liveness is
    /// refreshed only by reports we actually accept.
    #[test]
    fn stale_false_does_not_refresh_busy_liveness() {
        let mut a = bounded(25_000);
        true_at(&mut a, 1_000, 1_000, 1_000, 4994);
        beat(&mut a, 1_200);
        assert_eq!(a.view(1_300), SAMView::Busy);
        // Repeated stale FALSEs, each *arriving* before the absence grace would expire. None
        // of them proves the stream is still there, so none may push the deadline out.
        for (i, now) in [2_000u64, 2_600, 3_200, 3_800].into_iter().enumerate() {
            false_at(&mut a, now, 900, now, 4994);
            assert_eq!(a.telemetry.stale_stopped, i as u64 + 1, "refused at {now}");
        }
        // With the bug, the last arrival (3_800) would have kept the entry alive until
        // 3_800 + LOST_GRACE_MS. Timed off the real report it decays right after 1_000 + grace.
        assert_eq!(
            a.view(1_000 + LOST_GRACE_MS + 1),
            SAMView::NoData,
            "decay must be timed off the last accepted report, not off refused ones"
        );
        assert_eq!(
            a.telemetry.lost_transitions, 0,
            "view() is non-mutating; expire() has not run"
        );
        // Let the loop actually tick so the stored state becomes `Lost`; the stop below must
        // then really take the Lost -> Stopped path rather than the Busy one.
        assert_eq!(
            a.activity(1_000 + LOST_GRACE_MS + 1),
            CM400Activity::Active,
            "R6: decayed, but the tail is still fresh"
        );
        assert_eq!(a.telemetry.lost_transitions, 1);
        assert_eq!(a.telemetry.r2_applied, 0);
        assert_eq!(
            a.telemetry.stale_stopped, 4,
            "all four stale reports were refused, not acted on"
        );
        // The valid stop on the now-Lost instance still works (ruling A).
        false_at(&mut a, 5_000, 5_000, 5_000, 4994);
        assert_eq!(a.view(5_100), SAMView::Idle);
        assert_eq!(
            a.activity(5_200),
            CM400Activity::Inactive,
            "Lost -> Stopped still fires R2"
        );
        assert_eq!(a.telemetry.r2_applied, 1);
    }

    /// The silence metric is per instance and per stream generation, measured in callback
    /// arrivals - never by subtracting a SAM report time from an arrival time.
    #[test]
    fn report_gaps_are_measured_per_instance_and_decide_nothing() {
        let mut a = bounded(25_000);
        true_at(&mut a, 1_000, 1_000, 1_000, 1111);
        true_at(&mut a, 4_000, 4_000, 4_000, 1111); // 3_000 ms silent for 1111
        assert_eq!(a.max_report_gap_ms(), 3_000);
        // A second client does not continue 1111's series, and must not inherit its baseline:
        // it arrives long after 1111's last report, which a shared baseline would misread as
        // 8 seconds of monitor silence.
        true_at(&mut a, 4_100, 4_100, 12_000, 2222);
        assert_eq!(
            a.max_report_gap_ms(),
            3_000,
            "a new client must not inherit another's baseline"
        );
        true_at(&mut a, 4_600, 4_600, 12_600, 2222); // 600 ms for 2222, still below the max
        assert_eq!(
            a.max_report_gap_ms(),
            3_000,
            "different clients are not one stream"
        );
        // A refused report must not close a gap either: the next accepted one sees the whole
        // silent stretch, which is the conservative direction for this metric.
        false_at(&mut a, 5_000, 900, 5_000, 1111); // stale -> refused, no observation
        assert_eq!(
            a.max_report_gap_ms(),
            3_000,
            "a refused report is not a report"
        );
        true_at(&mut a, 9_000, 9_000, 9_000, 1111); // 9_000 - 4_000 = 5_000
        assert_eq!(
            a.max_report_gap_ms(),
            5_000,
            "refused reports must not hide silence"
        );
        // An ended stream is not monitor silence: the gap across a generation boundary is not
        // counted, it only re-baselines.
        stopped(&mut a, 9_500, 1111); // valid FALSE; its 500 ms gap changes nothing
        assert_eq!(a.max_report_gap_ms(), 5_000);
        true_at(&mut a, 20_000, 20_000, 20_000, 1111); // 10_500 later, brand new generation
        assert_eq!(
            a.max_report_gap_ms(),
            5_000,
            "a stream gap is not a SAM gap"
        );
        assert!(
            a.snapshot(20_200).contains("max_report_gap_ms=5000"),
            "readable in the beat line"
        );
        // And it decides nothing: real silence plus fresh heartbeats is still Active.
        beat(&mut a, 20_100);
        assert_eq!(a.activity(20_200), CM400Activity::Active);
    }

    /// Adapter so the pure arbiter output can drive `cm400_core::Engine` in tests.
    struct Fixed(CM400Activity);
    impl cm400_core::ActivitySource for Fixed {
        fn activity(&mut self) -> CM400Activity {
            self.0
        }
    }
    fn act_src(a: CM400Activity) -> Fixed {
        Fixed(a)
    }

    /// The rollout gate is itself a safety property: until the reviewer flips the backend,
    /// nothing about SAM may reach the policy.
    #[test]
    fn only_the_arbitrating_backend_can_answer_for_the_device() {
        use CM400Activity::*;
        // Heartbeat says Active, SAM would say Inactive: shadow must not leak it.
        for b in [
            ActivityBackend::HeartbeatOnly,
            ActivityBackend::SensorShadow,
        ] {
            assert_eq!(
                backend_choice(b, Active, Some(Inactive)),
                Active,
                "{b:?} leaked SAM"
            );
        }
        assert_eq!(
            backend_choice(ActivityBackend::SensorArbitrating, Active, Some(Inactive)),
            Inactive,
            "arbitrating is the only mode that can shorten the tail"
        );
        // No arbiter answer at all -> the heartbeat still rules (never an invented state).
        for b in [
            ActivityBackend::HeartbeatOnly,
            ActivityBackend::SensorShadow,
            ActivityBackend::SensorArbitrating,
        ] {
            assert_eq!(
                backend_choice(b, Unknown, None),
                Unknown,
                "{b:?} invented an answer"
            );
            assert_eq!(
                backend_choice(b, Active, None),
                Active,
                "{b:?} lost the fallback"
            );
        }
    }

    #[test]
    fn snapshot_and_helpers_stay_informative_without_becoming_decisions() {
        let mut a = bounded(9_000);
        busy(&mut a, 1_000, 4242);
        let s = a.snapshot(1_100);
        assert!(s.contains("view=Busy"), "{s}");
        assert!(s.contains("instances=[4242]"), "{s}");
        assert!(matches!(a.suppression(), Suppression::Bounded(9_000)));
        assert!(link_is_cm400(LINK, LINK));
        assert!(!link_is_cm400(LINK, OTHER));
    }

    // ---- stop latch (`Suppression::Latched`): reopen protection without a fixed window ----

    fn latched() -> Arbiter {
        Arbiter::new(LINK, HB_TIMEOUT, Suppression::Latched)
    }

    /// A stream that starts and then receives an attributed, accepted stop, with the heartbeat
    /// tail still running - the exact shape that used to raise the lens again.
    fn stopped_once_with_tail(a: &mut Arbiter, pid: u32) {
        busy(a, 1_000, pid);
        stopped(a, 2_000, pid);
        a.note_attributed_stop(2_000);
        a.set_ledger_trusted(true);
        a.apply(2_100, Evidence::HeartbeatSeen { arrival_ms: 2_100 });
    }

    /// 27. An attributed stop retracts immediately, and the residual heartbeat that would have
    ///     re-activated the device is refused.
    #[test]
    fn an_attributed_stop_arms_the_latch_and_the_old_heartbeat_cannot_raise() {
        let mut a = latched();
        stopped_once_with_tail(&mut a, 77);
        // The heartbeat on its own still says Active: this test is about outranking it, not
        // about the heartbeat having gone quiet.
        assert_eq!(a.hb.state(2_200), CM400Activity::Active);
        assert_eq!(
            a.activity(2_200),
            CM400Activity::Inactive,
            "the fast path retracted"
        );
        assert_eq!(a.blocker(), Blocker::None, "R2 was applied, not refused");
        assert_eq!(a.telemetry.latch_armed, 1);
        assert_eq!(a.telemetry.r2_applied, 1);
        assert!(a.latch_state().0, "the latch is held");
    }

    /// 28. The protection is a state, not a countdown: it is still holding 60 s later, long
    ///     after any window we could honestly have measured from the 20 s+ tail.
    #[test]
    fn the_latch_holds_as_long_as_no_new_stream_appeared_instead_of_expiring() {
        let mut a = latched();
        stopped_once_with_tail(&mut a, 77);
        for t in [3_000, 6_000, 21_000, 60_000] {
            a.apply(t, Evidence::HeartbeatSeen { arrival_ms: t });
            assert_eq!(
                a.activity(t + 1),
                CM400Activity::Inactive,
                "late tail at {t} must not raise the lens"
            );
        }
        assert!(
            a.telemetry.suppressed_reactivations >= 3,
            "each reopen refused while holding is counted (the arming reading itself is not one): {}",
            a.telemetry.suppressed_reactivations
        );
        assert_eq!(
            a.telemetry.latch_released, 0,
            "nothing released it - no clock did"
        );
    }

    /// 29. The way out is a genuinely new stream: a newer TRUE opens the next cycle immediately,
    ///     so normal operation is never locked out.
    #[test]
    fn a_newer_true_opens_a_new_cycle_immediately() {
        let mut a = latched();
        stopped_once_with_tail(&mut a, 77);
        assert_eq!(a.activity(2_200), CM400Activity::Inactive);
        a.apply(
            70_000,
            Evidence::PidStreaming {
                inst: inst(77),
                report_ms: 70_000,
                arrival_ms: 70_000,
            },
        );
        let (held, _, released, why) = a.latch_state();
        assert!(!held, "released by evidence");
        assert_eq!(released, 1);
        assert_eq!(why, "newer trusted TRUE after the accepted stop");
        assert_eq!(
            a.activity(70_001),
            CM400Activity::Active,
            "the camera serves the new stream"
        );
    }

    /// 30. A late duplicate of the *previous* stream's TRUE must not be read as a new cycle.
    #[test]
    fn an_old_duplicate_true_arriving_late_does_not_release_the_latch() {
        let mut a = latched();
        stopped_once_with_tail(&mut a, 77);
        // The latch only exists once a reading has applied it - without this call there is
        // nothing held for the out-of-order report to be refused against.
        assert_eq!(a.activity(2_200), CM400Activity::Inactive);
        // Same instance, report time from before the stop, delivered now.
        a.apply(
            30_000,
            Evidence::PidStreaming {
                inst: inst(77),
                report_ms: 1_500,
                arrival_ms: 30_000,
            },
        );
        assert!(a.latch_state().0, "ordering, not arrival, decides");
        assert_eq!(
            a.telemetry.stale_starts, 1,
            "the refused report is counted, not hidden"
        );
        assert_eq!(
            a.peek(inst(77)).map(|e| e.state),
            Some(PidState::Stopped),
            "a refused TRUE must not flip the instance back to Busy"
        );
        // Even though an accepted TRUE made this instance Busy again, the report time said
        // "older than the stop", so the view cannot be trusted as a new cycle either.
        assert_eq!(a.activity(30_001), CM400Activity::Inactive);
        // A report time strictly after the stop does release it - the boundary is the stop's own
        // time, and equal-to-stop is still the old generation.
        a.apply(
            31_000,
            Evidence::PidStreaming {
                inst: inst(77),
                report_ms: 2_000,
                arrival_ms: 31_000,
            },
        );
        assert!(
            a.latch_state().0,
            "report_ms equal to the stop is not newer"
        );
        a.apply(
            32_000,
            Evidence::PidStreaming {
                inst: inst(77),
                report_ms: 2_001,
                arrival_ms: 32_000,
            },
        );
        assert!(
            !a.latch_state().0,
            "the first report after the stop opens the cycle"
        );
    }

    /// 31. No attribution, no fast path. Each missing half of the authorization leaves the
    ///     heartbeat in charge, so a refusal can never itself retract the lens.
    #[test]
    fn an_unattributed_or_untrusted_stop_never_takes_the_fast_path() {
        // Attributed stop, but the ledger is not trusted.
        let mut a = latched();
        busy(&mut a, 1_000, 77);
        stopped(&mut a, 2_000, 77);
        a.note_attributed_stop(2_000);
        a.apply(2_100, Evidence::HeartbeatSeen { arrival_ms: 2_100 });
        assert_eq!(
            a.activity(2_200),
            CM400Activity::Active,
            "no permission given"
        );
        assert_eq!(a.blocker(), Blocker::LedgerUntrusted);
        // Permission given, but this stop was never attributed.
        let mut b = latched();
        b.set_ledger_trusted(true);
        busy(&mut b, 1_000, 77);
        stopped(&mut b, 2_000, 77);
        b.apply(2_100, Evidence::HeartbeatSeen { arrival_ms: 2_100 });
        assert_eq!(
            b.activity(2_200),
            CM400Activity::Active,
            "an unidentified stop is not enough"
        );
        assert_eq!(b.blocker(), Blocker::LedgerUntrusted);
        // An attributed stop with no usable time authorizes nothing either.
        let mut c = latched();
        c.set_ledger_trusted(true);
        busy(&mut c, 1_000, 77);
        stopped(&mut c, 2_000, 77);
        c.note_attributed_stop(0);
        c.apply(2_100, Evidence::HeartbeatSeen { arrival_ms: 2_100 });
        assert_eq!(
            c.activity(2_200),
            CM400Activity::Active,
            "a sentinel time is not evidence"
        );
        assert_eq!(c.telemetry.latch_armed, 0);
    }

    /// 32. A degraded SAM must never keep heartbeats muted: the latch goes, the old path returns,
    ///     and losing the fast path is the only cost.
    #[test]
    fn monitor_fault_and_backend_gone_release_the_latch_instead_of_locking_it() {
        let mut a = latched();
        stopped_once_with_tail(&mut a, 77);
        assert_eq!(a.activity(2_200), CM400Activity::Inactive);
        a.apply(
            3_000,
            Evidence::MonitorFault {
                kind: MonitorFaultKind::PropertyReadFailed(-1),
            },
        );
        let (held, _, released, why) = a.latch_state();
        assert!(!held, "a fault releases");
        assert_eq!(released, 1);
        assert_eq!(why, "monitor fault");
        a.apply(3_100, Evidence::HeartbeatSeen { arrival_ms: 3_100 });
        assert_eq!(
            a.activity(3_200),
            CM400Activity::Active,
            "heartbeats are not muted by a broken monitor"
        );
        // Backend gone: everything we held describes a finished generation.
        let mut b = latched();
        stopped_once_with_tail(&mut b, 77);
        assert_eq!(b.activity(2_200), CM400Activity::Inactive);
        b.apply(
            4_000,
            Evidence::BackendGone {
                why: BackendGoneReason::ServiceStop,
            },
        );
        assert!(!b.latch_state().0);
        assert_eq!(
            b.activity(4_100),
            CM400Activity::Active,
            "the heartbeat path took over"
        );
        // Losing the ledger's trust while held is the third release route.
        let mut c = latched();
        stopped_once_with_tail(&mut c, 77);
        assert_eq!(c.activity(2_200), CM400Activity::Inactive);
        c.set_ledger_trusted(false);
        assert!(
            !c.latch_state().0,
            "a latch built on untrusted evidence is dropped"
        );
        assert_eq!(c.latch_state().3, "lifecycle ledger lost trust");
    }

    /// 33. One attributed stop authorizes exactly one latch: after the cycle it released, the
    ///     fast path needs a newly attributed stop rather than borrowing the old authorization.
    #[test]
    fn one_attribution_authorizes_exactly_one_latch() {
        let mut a = latched();
        stopped_once_with_tail(&mut a, 77);
        assert_eq!(a.activity(2_200), CM400Activity::Inactive);
        // New stream, then it goes quiet in SAM's view without a fresh attributed stop: the
        // latch must not re-arm on the old authorization.
        a.apply(
            5_000,
            Evidence::PidStreaming {
                inst: inst(77),
                report_ms: 5_000,
                arrival_ms: 5_000,
            },
        );
        assert!(!a.latch_state().0);
        stopped(&mut a, 6_000, 77);
        a.apply(6_100, Evidence::HeartbeatSeen { arrival_ms: 6_100 });
        assert_eq!(
            a.activity(6_200),
            CM400Activity::Active,
            "the old authorization was spent"
        );
        assert_eq!(a.telemetry.latch_armed, 1, "and no second latch was armed");
        // A fresh attribution arms again - the mechanism is not one-shot for the process.
        a.note_attributed_stop(6_000);
        assert_eq!(a.activity(6_300), CM400Activity::Inactive);
        assert_eq!(a.telemetry.latch_armed, 2);
    }

    /// 34. Someone else still streaming, or a client that vanished without a stop, keeps the
    ///     fast path away: the latch only speaks for a device SAM says is entirely idle.
    #[test]
    fn another_busy_or_unresolved_client_blocks_the_latch() {
        // Second client still streaming.
        let mut a = latched();
        stopped_once_with_tail(&mut a, 77);
        busy(&mut a, 2_500, 88);
        assert_eq!(
            a.activity(2_600),
            CM400Activity::Active,
            "R1 outranks the latch"
        );
        assert!(!a.latch_state().0, "no latch was ever armed here");
        // A client that disappeared without an explicit stop decays to Lost -> NoData.
        let mut b = latched();
        busy(&mut b, 1_000, 77);
        busy(&mut b, 1_000, 88);
        stopped(&mut b, 2_000, 77);
        b.note_attributed_stop(2_000);
        b.set_ledger_trusted(true);
        b.apply(2_100, Evidence::HeartbeatSeen { arrival_ms: 2_100 });
        // 88 is still Busy at this instant, so no idle claim; after its grace it is Lost, which
        // is a hole in knowledge rather than a stop, and still cannot take the fast path.
        assert_eq!(b.activity(2_200), CM400Activity::Active);
        b.apply(8_900, Evidence::HeartbeatSeen { arrival_ms: 8_900 });
        assert_eq!(
            b.activity(9_000),
            CM400Activity::Active,
            "a Lost client is not an idle device"
        );
        assert_eq!(b.view(9_000), SAMView::NoData);
        assert_eq!(b.telemetry.latch_armed, 0);
    }

    /// 35. The real service shape: SAM cannot resolve its own creation-time identity (every
    ///     report arrives `unresolved`), so its `view` never says `Idle`. The lifecycle ledger's
    ///     attribution can carry that role - and only it. Without attribution nothing moves.
    #[test]
    fn an_unresolved_sam_identity_is_carried_by_the_ledger_attribution_only() {
        let un = |pid: u32| ProcInstance::unresolved(pid);
        let mut a = latched();
        a.apply(
            1_000,
            Evidence::PidStreaming {
                inst: un(77),
                report_ms: 1_000,
                arrival_ms: 1_000,
            },
        );
        a.apply(
            2_000,
            Evidence::PidStopped {
                inst: un(77),
                report_ms: 2_000,
                arrival_ms: 2_000,
            },
        );
        a.apply(2_100, Evidence::HeartbeatSeen { arrival_ms: 2_100 });
        // SAM's own picture cannot call this idle: the identity is unresolved.
        assert_eq!(a.view(2_200), SAMView::NoData);
        assert_eq!(
            a.activity(2_200),
            CM400Activity::Active,
            "no attribution offered, so no fast path"
        );
        // Now the caller says the stop was attributed against a trusted ledger. Same evidence,
        // same clock: only the authorization differs.
        a.set_ledger_trusted(true);
        a.note_attributed_stop(2_000);
        assert_eq!(
            a.activity(2_300),
            CM400Activity::Inactive,
            "the ledger carries the identity SAM could not"
        );
        assert!(a.latch_state().0, "and the reopen guard is holding");
        // It keeps holding through the tail.
        a.apply(9_000, Evidence::HeartbeatSeen { arrival_ms: 9_000 });
        assert_eq!(a.activity(9_100), CM400Activity::Inactive);
        // A newer TRUE still reopens the camera.
        a.apply(
            10_000,
            Evidence::PidStreaming {
                inst: un(77),
                report_ms: 10_000,
                arrival_ms: 10_000,
            },
        );
        assert_eq!(
            a.activity(10_100),
            CM400Activity::Active,
            "normal reopening works"
        );
        // The other side of the same rule: a registration that merely went silent is not an
        // accepted stop, so even attribution must not arm the latch on it.
        let mut b = latched();
        b.apply(
            1_000,
            Evidence::PidStreaming {
                inst: un(88),
                report_ms: 1_000,
                arrival_ms: 1_000,
            },
        );
        b.set_ledger_trusted(true);
        b.note_attributed_stop(1_000);
        b.apply(8_900, Evidence::HeartbeatSeen { arrival_ms: 8_900 });
        assert_eq!(b.view(9_000), SAMView::NoData, "88 decayed to Lost");
        assert_eq!(
            b.activity(9_000),
            CM400Activity::Active,
            "silence is never a stop, attributed or not"
        );
        assert_eq!(b.telemetry.latch_armed, 0);
    }

    /// 36. A pending authorization cannot be inherited by a later, unattributed stop. This is the
    ///     multi-client case in miniature: A's attributed stop must not buy the idle claim after B
    ///     stopped on evidence nobody attributed.
    #[test]
    fn a_stale_authorization_never_covers_a_later_unattributed_stop() {
        let mut a = latched();
        a.set_ledger_trusted(true);
        busy(&mut a, 1_000, 77);
        busy(&mut a, 1_000, 88);
        // A stops and the ledger attributes it; B keeps streaming.
        stopped(&mut a, 2_000, 77);
        a.note_attributed_stop(2_000);
        a.apply(2_100, Evidence::HeartbeatSeen { arrival_ms: 2_100 });
        assert_eq!(
            a.activity(2_200),
            CM400Activity::Active,
            "B is still busy, so no idle claim"
        );
        assert_eq!(a.telemetry.latch_armed, 0);
        // B stops as well, but nobody attributed this one. The table is fully `Stopped` now, and
        // the pending authorization still names A's older stop.
        stopped(&mut a, 3_000, 88);
        a.apply(3_100, Evidence::HeartbeatSeen { arrival_ms: 3_100 });
        assert_eq!(
            a.activity(3_200),
            CM400Activity::Active,
            "A's authorization must not cover B's unattributed stop"
        );
        assert_eq!(a.blocker(), Blocker::LedgerUntrusted);
        assert_eq!(
            a.telemetry.latch_armed, 0,
            "and it did not retract the lens"
        );
        // Attribute B's own stop and the same evidence arms - the refusal was about provenance.
        a.note_attributed_stop(3_000);
        assert_eq!(
            a.activity(3_300),
            CM400Activity::Inactive,
            "the newest accepted stop is now the attributed one"
        );
        assert_eq!(a.telemetry.latch_armed, 1);
    }

    /// 37. A client we cannot date blocks the fast path from the other side. A's attributed stop
    ///     armed the latch; B now claims streaming with an unusable report time. Holding the latch
    ///     would be asserting "nothing else is active" against a client that says it is.
    #[test]
    fn a_streaming_claim_with_no_usable_time_withdraws_the_idle_claim() {
        let mut a = latched();
        stopped_once_with_tail(&mut a, 77);
        assert_eq!(
            a.activity(2_200),
            CM400Activity::Inactive,
            "armed on A's attributed stop"
        );
        // B arrives: unresolved identity, streaming, no usable time (the ffmpeg shape).
        a.apply(
            3_000,
            Evidence::PidStreaming {
                inst: ProcInstance::unresolved(88),
                report_ms: 0,
                arrival_ms: 3_000,
            },
        );
        let (held, _, released, why) = a.latch_state();
        assert!(!held, "the idle claim is withdrawn rather than kept");
        assert_eq!(released, 1);
        assert_eq!(
            why,
            "a streaming claim with no usable time cannot be ordered"
        );
        a.apply(3_100, Evidence::HeartbeatSeen { arrival_ms: 3_100 });
        assert_eq!(
            a.activity(3_200),
            CM400Activity::Active,
            "an undatable streaming claim keeps the lens up"
        );
        // The spent authorization cannot silently re-arm: the fast path is shut until a newly
        // attributed stop arrives.
        assert_eq!(
            a.telemetry.latch_armed, 1,
            "no second latch on the old authorization"
        );
    }

    /// 38. The undatable client was already claiming streaming when A stopped: A's stop alone must
    ///     not retract anything, and the block survives that client going quiet - an unverifiable
    ///     disappearance is `Lost`, never idle.
    #[test]
    fn an_undatable_client_present_at_stop_time_blocks_the_fast_path() {
        let un = |pid: u32| ProcInstance::unresolved(pid);
        let mut a = latched();
        a.set_ledger_trusted(true);
        a.apply(
            1_000,
            Evidence::PidStreaming {
                inst: un(88),
                report_ms: 0,
                arrival_ms: 1_000,
            },
        );
        a.apply(
            1_500,
            Evidence::PidStreaming {
                inst: un(77),
                report_ms: 1_500,
                arrival_ms: 1_500,
            },
        );
        a.apply(
            2_000,
            Evidence::PidStopped {
                inst: un(77),
                report_ms: 2_000,
                arrival_ms: 2_000,
            },
        );
        a.note_attributed_stop(2_000);
        a.apply(2_100, Evidence::HeartbeatSeen { arrival_ms: 2_100 });
        assert_eq!(
            a.activity(2_200),
            CM400Activity::Active,
            "B's claim outranks A's stop (R1)"
        );
        assert_eq!(a.telemetry.latch_armed, 0, "and nothing was armed");
        // B falls silent without any resolvable stop: `Lost`, i.e. a hole in knowledge.
        assert_eq!(a.view(9_000), SAMView::NoData);
        a.apply(8_900, Evidence::HeartbeatSeen { arrival_ms: 8_900 });
        assert_eq!(
            a.activity(9_000),
            CM400Activity::Active,
            "the heartbeat path keeps the floor when SAM cannot confirm idleness"
        );
        assert_eq!(
            a.telemetry.latch_armed, 0,
            "A's authorization never gets a second use"
        );
        // Even a fresh attributed stop for A cannot reopen the fast path while B is unaccounted
        // for: the whole table has to be positively stopped.
        a.note_attributed_stop(2_000);
        assert_eq!(a.activity(9_100), CM400Activity::Active);
        assert_eq!(a.telemetry.latch_armed, 0);
    }
}
