//! Lifecycle-based attribution: can a SAM report be placed inside a *proven* process lifetime?
//!
//! `crate::report_link` showed why a snapshot taken after delivery cannot prove who wrote a
//! report: it only describes who holds the pid *now*. A lifetime is different evidence. If we
//! know instance `A` was created at `t0` and terminated at `t1`, then a report whose own event
//! time falls in `[t0, t1)` belongs to `A` - and a report outside it does not, no matter what
//! the current snapshot says. That is the shape of argument R2 would need.
//!
//! Candidate source, read from **this machine's own provider metadata** (`Get-WinEvent
//! -ListProvider Microsoft-Windows-Kernel-Process`, i.e. the manifest the OS ships, not a blog):
//!
//! ```text
//! Id=1 ProcessStart   v0: ProcessID, CreateTime(FILETIME), ParentProcessID, SessionID, ImageName
//!                 v3/v4: + ProcessSequenceNumber(UInt64), ParentProcessSequenceNumber, ...
//! Id=2 ProcessStop    v0: ProcessID, CreateTime(FILETIME), ExitTime(FILETIME), ExitCode, ...
//!                 v2:   + ProcessSequenceNumber(UInt64)
//! ```
//!
//! Two properties make it interesting: `CreateTime`/`ExitTime` are FILETIME - the same base as
//! `GetReportTime` after our conversion - and the newer versions carry a per-process sequence
//! number, so identity does not depend on the pid alone.
//!
//! What is **not** verified, and this module is written so that it cannot be quietly assumed:
//! - that the event's `ProcessSequenceNumber` is the *same counter* as `SequenceNumber` from
//!   `SystemBasicProcessInformation`. If they differ, a snapshot can never confirm an event, so
//!   `Ledger` cross-checks and refuses on mismatch.
//! - which schema version this build actually emits (v0/v1/v2 of ProcessStart have no sequence
//!   number at all), or whether `LocalService` can consume the provider without a second
//!   real-time session and its own loss surface.
//! - what happened to processes created before we started listening: their birth is `Unknown`,
//!   which is why `Unknown` cannot cover anything.
//!
//! Nothing here is wired into production. It is the testable shape of the argument, so the
//! refusal rules can be proven before any consumer exists.

use crate::report_link::{Denial, Link, Report};
use crate::sam_view::ProcInstance;

/// How the start of a lifetime is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Birth {
    /// A ProcessStart event for this pid and sequence was seen at `at_ms`.
    Event { at_ms: u64, sequence: u64 },
    /// We only know the process existed at `at_ms` (a snapshot). A point of existence is not a
    /// start: it bounds nothing before it.
    SeenAlive { at_ms: u64, sequence: u64 },
    /// Nothing proves where this instance began.
    Unknown,
}

/// How the end of a lifetime is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Death {
    /// A ProcessStop event: the instance ended exactly at `at_ms`.
    Event { at_ms: u64 },
    /// The pid was missing from a snapshot taken at `at_ms`. That only says "gone by `at_ms`",
    /// so the true end time lies somewhere after the last confirmed sighting.
    AbsentAt { at_ms: u64, last_seen_ms: u64 },
    /// Still running as far as we know - which also means we may simply not have looked.
    Unknown,
}

/// One process instance we are tracking a lifetime for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tracked {
    pub pid: u32,
    pub sequence: u64,
    pub birth: Birth,
    pub death: Death,
}

impl Tracked {
    fn inst(&self) -> ProcInstance {
        ProcInstance::from_sequence_number(self.pid, self.sequence)
    }

    /// The start of the interval we can prove, if any.
    fn proven_start(&self) -> Option<u64> {
        match self.birth {
            Birth::Event { at_ms, .. } => Some(at_ms),
            // `SeenAlive` and `Unknown` prove no lower bound: before the sighting, this pid
            // could have been held by an entirely different instance.
            _ => None,
        }
    }

    /// The end of the interval we can prove, if any, and whether it is exact.
    fn proven_end(&self) -> Option<(u64, bool)> {
        match self.death {
            Death::Event { at_ms } => Some((at_ms, true)),
            Death::AbsentAt { .. } => None,
            Death::Unknown => None,
        }
    }
}

/// A hole in our coverage of the lifecycle event stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gap {
    pub from_ms: u64,
    pub to_ms: u64,
}

/// Bounded retention, driven by two measurements rather than a guess:
///
/// * `RETAIN_CLOSED_MS` must comfortably exceed the worst SAM delivery lag we saw - 59.8 s of
///   `arrival - report` over 204 samples. Ten minutes is ~10x that, so pruning cannot be the
///   reason a late report loses its history.
/// * `MAX_TRACKED` bounds both memory and the linear scans `attribute`/`ingest_*` do. Live
///   growth measured ~1.7 records per burst process (a start record that later closes, plus the
///   occasional orphan stop), on top of ~420 pre-existing processes entered as `SeenAlive`.
///   2048 is therefore roughly a thousand processes of history, and keeps the worst-case scan
///   the same order as one TDH decode (~20 us).
pub const RETAIN_CLOSED_MS: u64 = 600_000;
pub const MAX_TRACKED: usize = 2048;

/// The ledger. Pure: the caller supplies events, snapshots and known gaps.
#[derive(Debug, Default)]
pub struct Ledger {
    tracked: Vec<Tracked>,
    gaps: Vec<Gap>,
    /// Sequence values seen in process snapshots, kept separate from event sequences because
    /// the two counters are not yet proven to be the same space.
    snapshot_sequences: Vec<(u64, u64)>,
    /// The instant from which we were actually watching. Reports stamped earlier are refused even
    /// if a later stop event tells us that instance's birth: retroactive knowledge is not
    /// retroactive coverage.
    boundary_ms: Option<u64>,
    /// Set by event loss, an unreadable counter or a stalled collector. While set, nothing in
    /// the ledger may be attributed at all.
    untrusted: Option<&'static str>,
    /// Instances whose continuity was broken by a hole; breaking is not undone by a later clean
    /// counter, only by re-establishing the stream.
    broken: Vec<(u32, u64)>,
    /// Lifetimes already attributed at least once, so "first report of this instance" can be
    /// reported truthfully instead of being hardcoded.
    attributed: Vec<(u32, u64)>,
    /// Counters for the log, so boundedness is observable rather than assumed.
    pruned_closed: u64,
    /// Closed records dropped specifically to make room at the cap. Kept apart from
    /// `pruned_closed` because the two facts mean different things: one is age-based retention
    /// working as designed, the other is pressure, and under pressure the fast path is exactly what
    /// must be seen to have survived.
    closed_reclaimed_on_pressure: u64,
    capacity_resets: u64,
    /// Events dropped because their lifetime provably began before the current observation
    /// boundary, and events dropped for unusable timestamps. Neither may touch `tracked`.
    filtered_before_boundary: u64,
    filtered_invalid: u64,
}

impl Ledger {
    pub fn new() -> Self {
        Ledger::default()
    }

    pub fn add(&mut self, t: Tracked) {
        self.tracked.push(t);
    }

    /// Begin observation: nothing before `at_ms` can be attributed.
    pub fn set_boundary(&mut self, at_ms: u64) {
        self.boundary_ms = Some(at_ms);
    }

    pub fn boundary(&self) -> Option<u64> {
        self.boundary_ms
    }

    /// Decide whether a lifetime may enter the ledger at all.
    ///
    /// After a capacity reset, late ProcessStop records for processes that died *before* the new
    /// boundary are still in the stream. Absorbing them would refill the ledger with history we
    /// deliberately discarded: attribution stays safe because of the boundary, but capacity is
    /// burned and needless further resets follow. Such events are dropped here, before any
    /// mutation of `tracked`, `broken` or `attributed`.
    ///
    /// Equality counts as inside: the boundary is the instant observation began, so a lifetime
    /// stamped exactly at it is not from the discarded world. A zero timestamp is not "the
    /// epoch" either - it is the collector's sentinel for a conversion it could not make, so it
    /// is refused rather than compared.
    fn admits(&mut self, create_ms: u64, exit_ms: Option<u64>) -> bool {
        if create_ms == 0 || exit_ms.map(|e| e < create_ms).unwrap_or(false) {
            self.filtered_invalid += 1;
            return false;
        }
        if let Some(b) = self.boundary_ms {
            if create_ms < b {
                self.filtered_before_boundary += 1;
                return false;
            }
        }
        true
    }

    /// `(dropped_as_pre_boundary, dropped_as_unusable_timestamp)`, for the log.
    pub fn filtered_counts(&self) -> (u64, u64) {
        (self.filtered_before_boundary, self.filtered_invalid)
    }

    /// A ProcessStart we observed. Same pid with a different sequence is a *different* instance:
    /// the previous holder is closed at this birth instant and dropped, so its state can never
    /// be inherited.
    pub fn ingest_start(&mut self, pid: u32, sequence: u64, create_ms: u64) {
        if !self.admits(create_ms, None) {
            return;
        }
        // An observed birth is exactly the re-establishment that clears a previous hole: from
        // this instant on, the stream covers the interval rather than assuming it did.
        self.broken.retain(|x| *x != (pid, sequence));
        if let Some(t) = self
            .tracked
            .iter_mut()
            .find(|t| t.pid == pid && t.sequence == sequence)
        {
            // An event is stronger than "seen alive": it gives the interval a real lower bound.
            t.birth = Birth::Event {
                at_ms: create_ms,
                sequence,
            };
            t.death = Death::Unknown;
            return;
        }
        if let Some(old) = self.tracked.iter().position(|t| t.pid == pid) {
            self.tracked[old].death = Death::Event { at_ms: create_ms };
            self.tracked.remove(old);
        }
        self.tracked.push(Tracked {
            pid,
            sequence,
            birth: Birth::Event {
                at_ms: create_ms,
                sequence,
            },
            death: Death::Unknown,
        });
    }

    /// A ProcessStop carries both the birth and the death instant, so it can complete a lifetime
    /// whose start we missed - for reports from now on, never for the period we were blind.
    pub fn ingest_stop(&mut self, pid: u32, sequence: u64, create_ms: u64, exit_ms: u64) {
        // A stop never rewrites history: if the instance it refers to was born before the
        // boundary, both events are from the discarded world and are dropped together. Note that
        // dropping here cannot make the ledger healthy - trust changes only via the explicit
        // loss/decode/capacity paths.
        if !self.admits(create_ms, Some(exit_ms)) {
            return;
        }
        if let Some(t) = self
            .tracked
            .iter_mut()
            .find(|t| t.pid == pid && t.sequence == sequence)
        {
            t.death = Death::Event { at_ms: exit_ms };
            if !matches!(t.birth, Birth::Event { .. }) {
                t.birth = Birth::Event {
                    at_ms: create_ms,
                    sequence,
                };
            }
            return;
        }
        self.tracked.push(Tracked {
            pid,
            sequence,
            birth: Birth::Event {
                at_ms: create_ms,
                sequence,
            },
            death: Death::Event { at_ms: exit_ms },
        });
    }

    /// A process found alive in a snapshot: it exists at that instant, which bounds nothing below.
    pub fn note_alive(&mut self, pid: u32, sequence: u64, at_ms: u64) {
        if !self.admits(at_ms, None) {
            return;
        }
        if self.tracked.iter().any(|t| t.pid == pid) {
            return;
        }
        self.tracked.push(Tracked {
            pid,
            sequence,
            birth: Birth::SeenAlive { at_ms, sequence },
            death: Death::Unknown,
        });
    }

    /// Event loss, an unreadable counter, or a stalled collector: every still-open lifetime stops
    /// being continuous, because we can no longer claim we saw the whole span.
    pub fn break_trust(&mut self, reason: &'static str) {
        self.untrusted = Some(reason);
        for t in self.tracked.iter() {
            if matches!(t.death, Death::Unknown) && !self.broken.contains(&(t.pid, t.sequence)) {
                self.broken.push((t.pid, t.sequence));
            }
        }
    }

    /// Counters clean again. This re-arms the ledger for *future* observations; intervals already
    /// marked broken stay broken until a fresh start event re-establishes them.
    pub fn restore_trust(&mut self) {
        self.untrusted = None;
    }

    /// Collector recovery is a claim about the future, not about the past.
    ///
    /// Deliberately narrow, in two ways. It clears the collector reasons and nothing else, so a kernel
    /// event loss or a capacity reset cannot be papered over by a healthy-looking sample. And it moves
    /// the observation boundary to `now_ms`, because the collector's counters are cumulative: recovery
    /// is not "the earlier interval was fine all along", it is "the stream can be read again, so
    /// believe intervals from this instant". Lifetimes that were open across the fault were already
    /// marked broken by `break_trust` and stay broken until their own start event is seen.
    pub fn recovered_from_collector_fault(&mut self, baseline_ms: u64) {
        const COLLECTOR_REASONS: [&str; 4] = [
            "collector decode fault",
            "collector queue overflow",
            "collector consumer thread exited",
            // the label a build before this one used, so a long-running process cannot be stuck with a
            // reason that no recovery path names
            "collector decode or transport fault",
        ];
        if self
            .untrusted
            .map(|r| COLLECTOR_REASONS.contains(&r))
            .unwrap_or(false)
        {
            self.untrusted = None;
            self.boundary_ms = Some(baseline_ms);
        }
    }

    /// Re-arm the ledger after a capacity reset, and only after a fresh baseline exists.
    ///
    /// Deliberately narrow: it clears the capacity reason and nothing else, so an event-loss or
    /// decode fault cannot be papered over by a reseed. The dropped history stays dropped - the
    /// new boundary refuses every report stamped before it.
    pub fn recovered_from_capacity_reset(&mut self, baseline_ms: u64) {
        if matches!(self.untrusted, Some("ledger capacity exceeded")) {
            self.untrusted = None;
            self.boundary_ms = Some(baseline_ms);
        }
    }

    pub fn trust_reason(&self) -> Option<&'static str> {
        self.untrusted
    }

    pub fn broken_count(&self) -> usize {
        self.broken.len()
    }

    pub fn open_count(&self) -> usize {
        self.tracked
            .iter()
            .filter(|t| matches!(t.death, Death::Unknown))
            .count()
    }

    pub fn closed_count(&self) -> usize {
        self.tracked
            .iter()
            .filter(|t| matches!(t.death, Death::Event { .. }))
            .count()
    }

    pub fn retention_counters(&self) -> (u64, u64) {
        (self.pruned_closed, self.capacity_resets)
    }

    /// How many closed lifetimes were reclaimed to stay under the cap without resetting the ledger.
    pub fn pressure_reclaims(&self) -> u64 {
        self.closed_reclaimed_on_pressure
    }

    /// How many times the ledger had to invalidate itself entirely.
    pub fn capacity_reset_count(&self) -> u64 {
        self.capacity_resets
    }

    /// Drop closed lifetimes older than `RETAIN_CLOSED_MS`.
    ///
    /// Pruning is safe precisely because a later report for a pruned instance finds *no*
    /// lifetime and is refused (`NoLifetime`); the rules never fall back to "whoever holds the
    /// pid now must be the author".
    pub fn prune_closed(&mut self, now_ms: u64) -> usize {
        let before = self.tracked.len();
        self.tracked.retain(|t| match t.death {
            Death::Event { at_ms } => now_ms.saturating_sub(at_ms) <= RETAIN_CLOSED_MS,
            // Open lifetimes are never pruned here: they are the ones still doing work.
            _ => true,
        });
        let removed = before - self.tracked.len();
        self.pruned_closed += removed as u64;
        removed
    }

    /// Enforce the hard cap, preferring reclaim over invalidation.
    ///
    /// Reaching the cap used to mean dropping everything, and that broke the privacy promise on a
    /// timing accident: a reset moves the observation boundary, the re-seeded entry for a still
    /// running process is only `SeenAlive`, `SeenAlive` proves no lower bound, so the capture that
    /// was in flight at that instant can never have its stop attributed and the fast retract is
    /// lost. Nothing about the process changed; only our bookkeeping did.
    ///
    /// So pressure is resolved against the history whose absence is harmless. A closed record exists
    /// to attribute late reports about a process that already ended; an open one whose start we
    /// actually saw is the proof that the device is still held by a known instance. Dropping the
    /// former refuses such a late report with `NoLifetime` - never by borrowing whoever holds the pid
    /// now - while keeping the latter preserves identity continuity that was already proven rather
    /// than assumed. The observation boundary is deliberately untouched here: coverage of the stream
    /// did not change, so no report becomes newly trustworthy or untrustworthy.
    ///
    /// A reset still happens when there is nothing safe left to reclaim, i.e. open lifetimes alone
    /// exceed the cap, and it keeps its explicit untrusted semantics. Returns `true` only for that
    /// case, so the caller re-snapshots exactly when the ledger really was emptied.
    pub fn enforce_capacity(&mut self, now_ms: u64) -> bool {
        if self.tracked.len() <= MAX_TRACKED {
            return false;
        }
        let reclaimable: Vec<(u8, u64, usize)> = self
            .tracked
            .iter()
            .enumerate()
            .filter_map(|(i, t)| match t.death {
                // Gone, however imprecisely: a report about it is refused either way.
                Death::Event { at_ms } => Some((0u8, at_ms, i)),
                Death::AbsentAt { at_ms, .. } => Some((1u8, at_ms, i)),
                Death::Unknown => None,
            })
            .collect();
        if self.open_count() > MAX_TRACKED {
            self.clear_for_reset(now_ms);
            return true;
        }

        // Oldest endings first, and stop at a low-water mark rather than at the cap: reclaiming one
        // record at a time would put us back under pressure on the next arrival.
        let target = MAX_TRACKED * 3 / 4;
        let mut oldest_first = reclaimable;
        oldest_first.sort();
        let mut drop: Vec<usize> = Vec::new();
        let mut live = self.tracked.len();
        for (_, _, i) in oldest_first {
            if live <= target {
                break;
            }
            drop.push(i);
            live -= 1;
        }
        if drop.is_empty() {
            // Still over the cap with nothing left to reclaim: say so instead of pretending.
            self.clear_for_reset(now_ms);
            return true;
        }
        drop.sort_unstable();
        for i in drop.iter().rev() {
            self.tracked.remove(*i);
        }
        self.closed_reclaimed_on_pressure += drop.len() as u64;
        // The two side tables are keyed by instance; without this they would outlive the records
        // they describe and grow without bound.
        let alive: std::collections::HashSet<(u32, u64)> =
            self.tracked.iter().map(|t| (t.pid, t.sequence)).collect();
        self.attributed.retain(|k| alive.contains(k));
        self.broken.retain(|k| alive.contains(k));
        debug_assert!(
            self.tracked.len() <= MAX_TRACKED,
            "the cap is the point of this function"
        );
        false
    }

    /// Empty the ledger and move the observation boundary to `now_ms`.
    ///
    /// Everything recorded before is unusable from now on, and the new boundary keeps that true
    /// even if the same events are replayed: a lifetime that began before the boundary can never
    /// cover a report at or after it, so dropped history cannot come back through late events.
    pub fn clear_for_reset(&mut self, now_ms: u64) {
        self.tracked.clear();
        self.attributed.clear();
        self.broken.clear();
        self.snapshot_sequences.clear();
        self.boundary_ms = Some(now_ms);
        // Distinct reason from event loss: healthy counters say nothing about pruned history.
        self.untrusted = Some("ledger capacity exceeded");
        self.capacity_resets += 1;
    }

    /// `true` while the ledger may not attribute anything (loss, unreadable counters, decode
    /// fault, or a capacity reset awaiting a fresh baseline).
    pub fn untrusted(&self) -> bool {
        self.untrusted.is_some()
    }

    pub fn tracked_count(&self) -> usize {
        self.tracked.len()
    }

    pub fn add_gap(&mut self, from_ms: u64, to_ms: u64) {
        self.gaps.push(Gap { from_ms, to_ms });
    }

    /// Record a `(at_ms, sequence)` pair observed in a process snapshot.
    pub fn note_snapshot_sequence(&mut self, at_ms: u64, sequence: u64) {
        if at_ms == 0 {
            self.filtered_invalid += 1;
            return;
        }
        if let Some(b) = self.boundary_ms {
            if at_ms < b {
                self.filtered_before_boundary += 1;
                return;
            }
        }
        self.snapshot_sequences.push((at_ms, sequence));
    }

    /// Did any of our lifecycle evidence overlap a coverage hole?
    fn touches_gap(&self, from_ms: u64, to_ms: u64) -> bool {
        self.gaps
            .iter()
            .any(|g| g.from_ms < to_ms && g.to_ms > from_ms)
    }

    /// Attribute `report` by its own event time against known lifetimes.
    ///
    /// The rules, in order, and why each refusal exists:
    /// 1. no candidate covers the instant            -> `StaleSample` (nothing proves this
    ///    instance existed then; a snapshot of the *current* holder is not a substitute)
    /// 2. more than one covers it                    -> `SampleFailed` reused as "ambiguous":
    ///    overlapping lifetimes mean the evidence itself is inconsistent
    /// 3. the covering lifetime straddles a gap      -> coverage refused
    /// 4. the instance was last seen absent, with an unproven death instant inside the
    ///    report's range                            -> `Discontinuous`
    pub fn attribute(&mut self, report: &Report) -> Link {
        // What we compare is the report's own time. Delivery time is irrelevant here: a report
        // that arrives a minute late still describes the instant it was generated.
        let t = report.report_ms;
        if let Some(reason) = self.untrusted {
            return Link::Denied(Denial::LedgerUntrusted(reason));
        }
        // A report with no placeable time cannot be compared against anything, so it is refused
        // before the boundary question is even asked: 0 is the sentinel for "the system gave us
        // an empty or pre-1970 FILETIME", not a claim that the report belongs to 1970.
        if t == 0 {
            return Link::Denied(Denial::UnusableReportTime { pid: report.pid });
        }
        if let Some(b) = self.boundary_ms {
            if t < b {
                return Link::Denied(Denial::BeforeBoundary {
                    boundary_ms: b,
                    report_ms: t,
                });
            }
        }
        let mut covering: Vec<&Tracked> = self
            .tracked
            .iter()
            .filter(|c| c.pid == report.pid)
            .filter(|c| match c.proven_start() {
                Some(start) => t >= start && c.proven_end().is_none_or(|(end, _)| t < end),
                None => false,
            })
            .collect();

        // An unproven death instant: the instance is known gone by `at_ms`, but the report sits
        // after the last confirmed sighting, so we cannot say which side of the death it is on.
        let fuzzy = covering.iter().any(|c| match c.death {
            Death::AbsentAt {
                at_ms,
                last_seen_ms,
            } => t > last_seen_ms && t <= at_ms,
            _ => false,
        });
        if fuzzy {
            covering.retain(|c| !matches!(c.death, Death::AbsentAt { .. }));
        }

        match covering.len() {
            0 if fuzzy => Link::Denied(Denial::Discontinuous { pid: report.pid }),
            0 => {
                // Two different facts, previously collapsed into one misleading label: we have
                // no lifetime for this pid at all (an event that has not arrived yet), versus we
                // have lifetimes and this instant falls outside every one of them.
                if !self.tracked.iter().any(|c| c.pid == report.pid) {
                    return Link::Denied(Denial::NoLifetime { pid: report.pid });
                }
                if self
                    .tracked
                    .iter()
                    .any(|c| c.pid == report.pid && matches!(c.death, Death::AbsentAt { .. }))
                {
                    return Link::Denied(Denial::Discontinuous { pid: report.pid });
                }
                Link::Denied(Denial::OutsideLifetime { pid: report.pid })
            }
            1 => {
                let c = covering[0];
                if self.broken.contains(&(c.pid, c.sequence)) {
                    // This lifetime spans a hole in the event stream: the interval is no longer
                    // continuous evidence, whatever the counters say now.
                    return Link::Denied(Denial::Discontinuous { pid: report.pid });
                }
                let start = c
                    .proven_start()
                    .expect("a covering candidate has a proven start");
                if self.touches_gap(start, t) {
                    // A missed ProcessStart in this window could mean an untracked instance held
                    // the pid. Refuse rather than assume the one we know about.
                    return Link::Denied(Denial::Discontinuous { pid: report.pid });
                }
                if !self.snapshot_sequences.is_empty()
                    && !self
                        .snapshot_sequences
                        .iter()
                        .any(|(_, s)| *s == c.sequence)
                {
                    // We do have snapshot evidence, and it never shows this sequence. Either the
                    // two counters are different spaces or this lifetime is not the current one.
                    return Link::Denied(Denial::IdentityUnavailable);
                }
                let key = (c.pid, c.sequence);
                // `new_instance` means "this is the first report attributed to this lifetime, so
                // the consumer must not graft earlier state onto it". It was previously hardcoded
                // to `true`, which made every line lie about the same thing.
                let is_first = !self.attributed.contains(&key);
                if is_first {
                    self.attributed.push(key);
                }
                Link::Attributed {
                    inst: c.inst(),
                    new_instance: is_first,
                }
            }
            _ => Link::Denied(Denial::Ambiguous {
                pid: report.pid,
                over: covering.len(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report_link::{Denial, Link, Report};

    fn rep(pid: u32, streaming: bool, at: u64) -> Report {
        // arrival is deliberately set far after the report time in most cases: attribution here
        // must not care, because the report's own clock is the evidence.
        Report {
            pid,
            streaming,
            report_ms: at,
            arrival_ms: at + 60_000,
        }
    }

    fn started(pid: u32, seq: u64, at: u64) -> Tracked {
        Tracked {
            pid,
            sequence: seq,
            birth: Birth::Event {
                at_ms: at,
                sequence: seq,
            },
            death: Death::Unknown,
        }
    }

    /// 1 + 4 + 5. The late-report/PID-reuse race, the case the review asks about.
    #[test]
    fn a_late_report_from_the_old_instance_lands_on_the_old_instance() {
        let mut l = Ledger::new();
        l.add(started(4994, 111, 1_000));
        // A exits cleanly at 2_000.
        if let Some(c) = l.tracked.first_mut() {
            c.death = Death::Event { at_ms: 2_000 };
        }
        // B takes the same pid at 2_100 with a different sequence.
        l.add(started(4994, 222, 2_100));
        l.note_snapshot_sequence(2_200, 222);

        // A's TRUE, generated at 1_500, is delivered only now - long after B exists.
        let link = l.attribute(&rep(4994, true, 1_500));
        assert_eq!(
            link,
            Link::Denied(Denial::IdentityUnavailable),
            "we hold snapshot evidence for 222 only, so a lifetime for 111 cannot be confirmed"
        );
        // A stop from A's window behaves the same way: never attributed to B.
        assert_ne!(
            l.attribute(&rep(4994, false, 1_500)).attributed(),
            Some(ProcInstance::from_sequence_number(4994, 222)),
            "the reused pid must not inherit someone else's stop"
        );
        // And B's own report, generated after B started, is about B.
        assert_eq!(
            l.attribute(&rep(4994, true, 2_500)),
            Link::Attributed {
                inst: ProcInstance::from_sequence_number(4994, 222),
                new_instance: true
            }
        );
    }

    /// With both lifetimes confirmed by snapshot evidence, the old report resolves to the old
    /// instance and the new one to the new instance.
    #[test]
    fn confirmed_sequences_separate_the_two_instances_by_report_time() {
        let mut l = Ledger::new();
        l.add(started(4994, 111, 1_000));
        l.tracked[0].death = Death::Event { at_ms: 2_000 };
        l.add(started(4994, 222, 2_100));
        // Both sequences appear in our snapshots: the counter space is consistent.
        l.note_snapshot_sequence(1_500, 111);
        l.note_snapshot_sequence(2_500, 222);
        assert_eq!(
            l.attribute(&rep(4994, true, 1_500)).attributed(),
            Some(ProcInstance::from_sequence_number(4994, 111))
        );
        assert_eq!(
            l.attribute(&rep(4994, false, 2_500)).attributed(),
            Some(ProcInstance::from_sequence_number(4994, 222))
        );
        // A report stamped in the dead zone between the two lifetimes belongs to neither.
        assert!(l.attribute(&rep(4994, false, 2_050)).attributed().is_none());
    }

    /// 5. Birth unknown: no coverage, no guessing from the current holder.
    #[test]
    fn a_process_whose_birth_we_missed_cannot_be_attributed_any_report() {
        let mut l = Ledger::new();
        // We started listening at 5_000 and saw this pid alive then; it existed before that.
        l.add(Tracked {
            pid: 4994,
            sequence: 333,
            birth: Birth::SeenAlive {
                at_ms: 5_000,
                sequence: 333,
            },
            death: Death::Unknown,
        });
        l.note_snapshot_sequence(5_000, 333);
        // A report from 4_000 - before our sighting - cannot be placed.
        assert!(l.attribute(&rep(4994, true, 4_000)).attributed().is_none());
        // And neither can one from 6_000: without a proven start there is no interval at all.
        assert!(l.attribute(&rep(4994, true, 6_000)).attributed().is_none());
        assert_eq!(
            l.tracked_count(),
            1,
            "refusal must not discard the tracking record"
        );
    }

    /// 5. Death only bounded: a report inside the unproven range is refused.
    #[test]
    fn an_unproven_death_instant_refuses_reports_in_the_open_range() {
        let mut l = Ledger::new();
        l.add(started(4994, 777, 1_000));
        l.note_snapshot_sequence(1_000, 777);
        l.note_snapshot_sequence(3_000, 777);
        // Last confirmed sighting 3_000; gone by the snapshot at 9_000.
        l.tracked[0].death = Death::AbsentAt {
            at_ms: 9_000,
            last_seen_ms: 3_000,
        };
        // Before the last sighting: inside the lifetime, attributable.
        assert_eq!(
            l.attribute(&rep(4994, false, 2_500)).attributed(),
            Some(ProcInstance::from_sequence_number(4994, 777))
        );
        // Inside the open range: the death could have happened before or after this report.
        assert!(l.attribute(&rep(4994, false, 5_000)).attributed().is_none());
        assert!(l.attribute(&rep(4994, false, 8_999)).attributed().is_none());
    }

    /// 5. Coverage holes invalidate the interval they touch.
    #[test]
    fn an_event_stream_gap_refuses_attribution() {
        let mut l = Ledger::new();
        l.add(started(4994, 888, 1_000));
        l.note_snapshot_sequence(1_000, 888);
        // We lost lifecycle events between 1_500 and 4_000: an untracked start could hide there.
        l.add_gap(1_500, 4_000);
        assert!(l.attribute(&rep(4994, true, 3_000)).attributed().is_none());
        // A report outside the hole, whose whole span since birth avoids it, still resolves.
        assert_eq!(
            l.attribute(&rep(4994, true, 1_200)).attributed(),
            Some(ProcInstance::from_sequence_number(4994, 888))
        );
    }

    /// Inconsistent evidence: two lifetimes covering the same instant is a refusal, not a pick.
    #[test]
    fn overlapping_lifetimes_are_refused_rather_than_resolved_by_preference() {
        let mut l = Ledger::new();
        l.add(started(4994, 111, 1_000));
        l.add(started(4994, 222, 1_500)); // both "alive", same pid, no end recorded
        l.note_snapshot_sequence(2_000, 111);
        l.note_snapshot_sequence(2_000, 222);
        assert_eq!(
            l.attribute(&rep(4994, true, 2_000)),
            Link::Denied(Denial::Ambiguous { pid: 4994, over: 2 })
        );
    }

    /// A report from a pid nobody ever tracked has no evidence at all.
    #[test]
    fn unknown_pid_has_no_lifetime_and_is_denied() {
        let mut l = Ledger::new();
        l.add(started(111, 1, 1_000));
        assert!(l.attribute(&rep(4994, true, 1_500)).attributed().is_none());
    }

    /// The module's own boundary: two sequence spaces are treated as unproven until shown equal.
    #[test]
    fn snapshot_evidence_for_a_different_sequence_does_not_confirm_an_event_lifetime() {
        let mut l = Ledger::new();
        l.add(started(4994, 111, 1_000));
        // Only the *other* sequence has ever been seen in a snapshot.
        l.note_snapshot_sequence(1_500, 999);
        assert_eq!(
            l.attribute(&rep(4994, true, 1_500)),
            Link::Denied(Denial::IdentityUnavailable)
        );
    }

    /// With no snapshot evidence recorded at all, the event lifetime stands on its own - and the
    /// test states exactly what that does and does not prove.
    #[test]
    fn event_only_evidence_is_accepted_but_is_the_weakest_form() {
        let mut l = Ledger::new();
        l.add(started(4994, 42, 1_000));
        assert_eq!(
            l.attribute(&rep(4994, true, 1_000)),
            Link::Attributed {
                inst: ProcInstance::from_sequence_number(4994, 42),
                new_instance: true
            }
        );
        // Boundary: the birth instant itself is inside the lifetime, one millisecond before is
        // not, so a report cannot be pushed onto a lifetime that had not begun.
        assert!(l.attribute(&rep(4994, true, 999)).attributed().is_none());
    }

    /// 15. Bounded retention: a closed lifetime ages out, and the report that arrives too late
    ///     is refused rather than attributed to whoever holds the pid now.
    #[test]
    fn closed_history_is_pruned_and_the_late_report_is_then_refused() {
        let mut l = Ledger::new();
        l.set_boundary(1_000);
        l.ingest_start(4994, 111, 1_500);
        l.note_snapshot_sequence(1_600, 111);
        l.ingest_stop(4994, 111, 1_500, 2_000);
        // Inside retention: attributable.
        assert_eq!(
            l.attribute(&rep(4994, false, 1_800)).attributed(),
            Some(ProcInstance::from_sequence_number(4994, 111))
        );
        assert_eq!(
            l.prune_closed(2_000 + RETAIN_CLOSED_MS),
            0,
            "nothing is old yet"
        );
        assert_eq!(
            l.prune_closed(2_001 + RETAIN_CLOSED_MS),
            1,
            "the closed lifetime ages out"
        );
        assert_eq!(l.tracked_count(), 0);
        // The same report now finds no history: refused, with the accurate reason.
        assert_eq!(
            l.attribute(&rep(4994, false, 1_800)),
            Link::Denied(Denial::NoLifetime { pid: 4994 })
        );
    }

    /// 16. Hitting the cap must never be a silent partial trim, and the two legitimate outcomes stay
    ///     distinguishable: reclaim proven-dead history (ledger still trusted, counter moves), or
    ///     invalidate completely when only live work is left (untrusted, boundary moved).
    #[test]
    fn capacity_overflow_either_reclaims_the_dead_or_invalidates_explicitly() {
        let mut l = Ledger::new();
        l.set_boundary(1_000);
        for i in 0..MAX_TRACKED {
            // Enough events to exceed the cap; every record is closed so nothing is still in flight.
            l.ingest_start(i as u32 + 1, 7_000 + i as u64, 1_200);
            l.ingest_stop(i as u32 + 1, 7_000 + i as u64, 1_200, 1_300);
        }
        assert!(
            !l.enforce_capacity(5_000),
            "at the limit nothing happens yet"
        );
        l.ingest_start(9_999, 8_888, 5_100);
        assert!(
            l.tracked_count() > MAX_TRACKED,
            "over the cap, which must trigger *some* bounded response"
        );
        assert!(
            !l.enforce_capacity(5_200),
            "nothing here is still running, so history is reclaimed instead of the ledger invalidated"
        );
        assert!(
            l.tracked_count() <= MAX_TRACKED,
            "the cap holds after reclaim: {}",
            l.tracked_count()
        );
        assert!(
            l.pressure_reclaims() > 0,
            "and the reclaim is observable rather than silent"
        );
        assert!(
            !l.untrusted(),
            "reclaiming dead history does not invalidate the observation we still hold"
        );
        assert_eq!(l.capacity_reset_count(), 0, "no reset was needed");
        // The live instance keeps exactly the proof it had: a start event, not a re-seeded sighting.
        assert!(
            l.attribute(&rep(9_999, true, 5_100)).attributed().is_some(),
            "the session in flight is still attributable after a pressure reclaim"
        );
        // An open-heavy ledger has nothing safe to give up, and must say so instead of trimming.
        let mut busy = Ledger::new();
        busy.set_boundary(1_000);
        for i in 0..=MAX_TRACKED {
            busy.ingest_start(i as u32 + 1, 7_000 + i as u64, 1_200); // starts only: all open
        }
        assert!(
            busy.open_count() > MAX_TRACKED,
            "every lifetime is still running: {} open",
            busy.open_count()
        );
        assert!(
            busy.enforce_capacity(5_200),
            "only then does the ledger invalidate itself"
        );
        assert_eq!(busy.tracked_count(), 0, "emptied, not partly trimmed");
        assert_eq!(busy.trust_reason(), Some("ledger capacity exceeded"));
        assert_eq!(busy.boundary(), Some(5_200), "and the boundary moved");
        assert_eq!(busy.capacity_reset_count(), 1);
    }

    /// 17. After a reset, an old instance's late FALSE must not stop the new holder, and a
    ///     re-injected old Start cannot resurrect pruned history.
    #[test]
    fn after_a_reset_neither_a_late_stop_nor_a_replayed_start_restores_history() {
        let mut l = Ledger::new();
        l.set_boundary(1_000);
        l.ingest_start(4994, 111, 1_500);
        l.note_snapshot_sequence(1_600, 111);
        // Reset as if the cap had been hit.
        l.clear_for_reset(9_000);
        assert!(l.untrusted());
        // Replaying the old start cannot be attributed: the boundary moved past it.
        l.restore_trust();
        l.ingest_start(4994, 111, 1_500);
        l.note_snapshot_sequence(9_100, 111);
        assert_eq!(
            l.attribute(&rep(4994, false, 1_800)),
            Link::Denied(Denial::BeforeBoundary {
                boundary_ms: 9_000,
                report_ms: 1_800
            })
        );
        // A genuinely new instance after the boundary works, and is flagged as new.
        l.ingest_start(4994, 222, 9_500);
        l.note_snapshot_sequence(9_600, 222);
        assert_eq!(
            l.attribute(&rep(4994, false, 9_700)).attributed(),
            Some(ProcInstance::from_sequence_number(4994, 222))
        );
    }

    /// 18. `SeenAlive` seeding after a reset must not fabricate a birth bound - and a start event
    ///     from before the reset must not be absorbed to fix that.
    #[test]
    fn reseeded_survivors_get_no_fabricated_birth_bound_and_pre_boundary_starts_are_dropped() {
        let mut l = Ledger::new();
        l.clear_for_reset(10_000);
        l.restore_trust();
        l.note_alive(4994, 555, 10_000);
        l.note_snapshot_sequence(10_000, 555);
        // Existence at one instant bounds nothing below: reports are still refused.
        assert!(l.attribute(&rep(4994, true, 11_000)).attributed().is_none());
        assert!(l.attribute(&rep(4994, false, 9_999)).attributed().is_none());
        // A late Start telling us this survivor was really born at 8_000 cannot help: it is
        // discarded, the record is not upgraded, and the survivor stays unattributable.
        l.ingest_start(4994, 555, 8_000);
        assert_eq!(
            l.attribute(&rep(4994, true, 11_000)).attributed(),
            None,
            "a pre-boundary birth cannot create a usable interval"
        );
        assert_eq!(
            l.filtered_counts(),
            (1, 0),
            "and we can see that it was dropped"
        );
        // Only a lifetime that begins at or after the boundary can be attributed.
        l.ingest_start(7777, 600, 12_000);
        l.note_snapshot_sequence(12_100, 600);
        assert_eq!(
            l.attribute(&rep(7777, true, 12_500)).attributed(),
            Some(ProcInstance::from_sequence_number(7777, 600))
        );
    }

    /// 22. Boundary filtering: pre-boundary Starts and Stops must not touch the ledger at all.
    #[test]
    fn pre_boundary_events_are_dropped_before_any_ledger_mutation() {
        let mut l = Ledger::new();
        l.clear_for_reset(50_000);
        l.restore_trust();
        // Late events about a process that lived and died entirely before the reset.
        l.ingest_start(4994, 111, 10_000);
        l.ingest_stop(4994, 111, 10_000, 12_000);
        assert_eq!(l.tracked_count(), 0, "no refill from discarded history");
        assert_eq!(l.filtered_counts(), (2, 0));
        assert_eq!(
            l.attribute(&rep(4994, false, 11_000)),
            Link::Denied(Denial::BeforeBoundary {
                boundary_ms: 50_000,
                report_ms: 11_000
            })
        );
        // The same old sequence appearing again cannot be smuggled in via a fresh event either.
        l.ingest_stop(4994, 111, 10_000, 60_000);
        assert_eq!(
            l.tracked_count(),
            0,
            "a pre-boundary birth is refused even with a late death"
        );
    }

    /// 23. A report whose time cannot be placed in the unix domain is refused as unusable. It
    ///     must not be read as "before the boundary", and it must not touch the ledger.
    #[test]
    fn a_report_with_no_placeable_time_is_refused_instead_of_being_placed_on_a_side() {
        let mut l = Ledger::new();
        l.set_boundary(1_000);
        l.ingest_start(4994, 111, 1_200);
        l.note_snapshot_sequence(1_300, 111);
        // The same pid does have a covering lifetime, so a boundary-style refusal here would be
        // a mislabel rather than an empty result.
        let zero = Report {
            pid: 4994,
            streaming: true,
            report_ms: 0,
            arrival_ms: 5_000,
        };
        assert_eq!(
            l.attribute(&zero),
            Link::Denied(Denial::UnusableReportTime { pid: 4994 })
        );
        assert_eq!(
            l.filtered_counts(),
            (0, 0),
            "refusal happens in the link layer, not the feed"
        );
        // A report with a real instant at the same moment is still attributable, so the refusal
        // above is about the missing time and not about the ledger having forgotten the pid.
        assert_eq!(
            l.attribute(&rep(4994, true, 1_400)).attributed(),
            Some(ProcInstance::from_sequence_number(4994, 111))
        );
        // And an unusable report never counts as a first frame: the second sight of the real
        // instance is the one that reports new_instance=false.
        assert!(
            matches!(
                l.attribute(&rep(4994, true, 1_400)),
                Link::Attributed {
                    new_instance: false,
                    ..
                }
            ),
            "the unusable report did not consume the first-frame slot"
        );
    }

    /// 24. The boundary comparison is inclusive: the instant observation began belongs to the new
    ///     side, one millisecond earlier belongs to the discarded side.
    #[test]
    fn the_boundary_itself_is_on_the_observed_side() {
        let mut l = Ledger::new();
        l.clear_for_reset(50_000);
        l.restore_trust();
        l.ingest_start(4994, 111, 50_000);
        l.note_snapshot_sequence(50_001, 111);
        assert_eq!(
            l.attribute(&rep(4994, true, 50_000)).attributed(),
            Some(ProcInstance::from_sequence_number(4994, 111)),
            "a lifetime born exactly at the boundary is observed, not discarded"
        );
        assert_eq!(
            l.attribute(&rep(4994, true, 49_999)),
            Link::Denied(Denial::BeforeBoundary {
                boundary_ms: 50_000,
                report_ms: 49_999
            })
        );
        // A birth one millisecond before the boundary is dropped rather than snapped up to it.
        // (Reports are refused in the link layer and do not move the feed counters; this is the
        // ingest side of the same rule.)
        l.ingest_start(8888, 333, 49_999);
        assert_eq!(
            l.filtered_counts(),
            (1, 0),
            "no rounding across the boundary"
        );
        assert_eq!(
            l.tracked_count(),
            1,
            "only the boundary-exact lifetime is held"
        );
    }

    /// 25. After a TTL prune, a reused pid must resolve to the lifetime that exists now, and a
    ///     report belonging to the pruned one can never borrow it back.
    #[test]
    fn a_pruned_history_never_competes_with_the_instance_that_holds_the_pid_now() {
        let mut l = Ledger::new();
        l.set_boundary(1_000);
        l.ingest_start(4994, 111, 1_200);
        l.note_snapshot_sequence(1_300, 111);
        l.ingest_stop(4994, 111, 1_200, 2_000);
        // Well past the retention window: the closed record is reclaimed.
        assert!(l.prune_closed(RETAIN_CLOSED_MS + 10_000) > 0);
        assert_eq!(l.tracked_count(), 0);
        assert_eq!(
            l.attribute(&rep(4994, false, 1_500)),
            Link::Denied(Denial::NoLifetime { pid: 4994 }),
            "the pruned lifetime is gone; the report is refused, not matched by pid alone"
        );
        // The same pid is later taken by a new instance; only that one can be attributed to.
        l.ingest_start(4994, 222, 200_000);
        l.note_snapshot_sequence(200_100, 222);
        assert_eq!(
            l.attribute(&rep(4994, true, 201_000)),
            Link::Attributed {
                inst: ProcInstance::from_sequence_number(4994, 222),
                new_instance: true
            }
        );
        // A late report from the pruned instance is refused on coverage grounds, and cannot be
        // mistaken for the new one just because the pid matches.
        assert_eq!(
            l.attribute(&rep(4994, false, 3_000)),
            Link::Denied(Denial::OutsideLifetime { pid: 4994 })
        );
    }

    /// 25b. A capture that outlives a pressure reclaim keeps its attributed stop - the incident this
    ///      fix exists for. Before it, a session in flight when the cap was reached lost the fast
    ///      path: the reset moved the boundary, the re-seeded entry proved no lower bound, and the
    ///      stop came back `OutsideLifetime` roughly eight seconds later than it should.
    #[test]
    fn an_active_capture_survives_a_capacity_event_and_still_attributes_its_stop() {
        let mut l = Ledger::new();
        l.set_boundary(1_000);
        // The camera process: born by event, still streaming.
        l.ingest_start(32896, 2847, 447_587);
        l.note_snapshot_sequence(447_600, 2847);
        assert_eq!(
            l.attribute(&rep(32896, true, 447_587)).attributed(),
            Some(ProcInstance::from_sequence_number(32896, 2847)),
            "sanity: the running session is attributable before any pressure"
        );
        // Churn: unrelated short-lived processes fill the ledger past the cap while it streams.
        for i in 0..=MAX_TRACKED {
            l.ingest_start(40_000 + i as u32, 90_000 + i as u64, 448_000 + i as u64);
            l.ingest_stop(
                40_000 + i as u32,
                90_000 + i as u64,
                448_000 + i as u64,
                448_100 + i as u64,
            );
        }
        assert!(l.tracked_count() > MAX_TRACKED);
        assert!(
            !l.enforce_capacity(470_000),
            "the camera session is open, so there is something safe to reclaim"
        );
        assert!(!l.untrusted(), "and no invalidation was necessary");
        assert_eq!(l.capacity_reset_count(), 0, "the boundary never moved");
        assert_eq!(
            l.boundary(),
            Some(1_000),
            "the same observation window still covers this session"
        );
        // The stop report of that same session must still be attributable, or the fast retract is lost.
        assert_eq!(
            l.attribute(&rep(32896, false, 470_963)).attributed(),
            Some(ProcInstance::from_sequence_number(32896, 2847)),
            "stop attributed to the session that was in flight across the capacity event"
        );
    }

    /// 25c. What the reclaim does give up, it gives up safely: a late report about a reclaimed
    ///      instance is refused outright, and a new process under the same pid never inherits it.
    #[test]
    fn reclaimed_history_is_refused_and_never_borrowed_by_a_reused_pid() {
        let mut l = Ledger::new();
        l.set_boundary(1_000);
        // A closed session whose record is young enough that only pressure will remove it.
        l.ingest_start(4994, 111, 1_200);
        l.note_snapshot_sequence(1_300, 111);
        l.ingest_stop(4994, 111, 1_200, 1_500);
        assert!(l.attribute(&rep(4994, false, 1_400)).attributed().is_some());
        // Push past the cap with closed churn and let pressure reclaim the oldest endings.
        for i in 0..=MAX_TRACKED {
            l.ingest_start(50_000 + i as u32, 200_000 + i as u64, 1_600 + i as u64);
            l.ingest_stop(
                50_000 + i as u32,
                200_000 + i as u64,
                1_600 + i as u64,
                1_700 + i as u64,
            );
        }
        assert!(
            !l.enforce_capacity(300_000),
            "closed history absorbs the pressure"
        );
        assert_eq!(
            l.attribute(&rep(4994, false, 1_400)),
            Link::Denied(Denial::NoLifetime { pid: 4994 }),
            "the reclaimed lifetime is gone; the report is refused, not guessed"
        );
        // Same pid, new instance: only the new one can be attributed, from its own observed birth.
        l.ingest_start(4994, 222, 301_000);
        l.note_snapshot_sequence(301_100, 222);
        assert_eq!(
            l.attribute(&rep(4994, true, 302_000)).attributed(),
            Some(ProcInstance::from_sequence_number(4994, 222)),
            "identity continuity is not implied by pid equality"
        );
    }

    /// 25d. Boundedness under sustained pressure: repeated overflow must never grow past the cap,
    ///     never lose the live sessions, and never fall back to invalidation while there is dead
    ///     history left to give up.
    #[test]
    fn sustained_pressure_stays_bounded_without_losing_live_sessions_or_trust() {
        let mut l = Ledger::new();
        l.set_boundary(1_000);
        l.ingest_start(7777, 555, 1_100); // one long-running capture, never closed
        l.note_snapshot_sequence(1_150, 555);
        let mut resets_seen = 0;
        for round in 0..6u64 {
            for i in 0..600u32 {
                let at = 2_000 + round * 1_000 + i as u64;
                // A distinct pid per record, not just a distinct sequence: reusing a pid makes
                // ingest_start close and drop the previous holder, which is exactly the mechanism
                // that keeps this ledger small in the first place - and it would quietly prevent
                // the overflow this test exists to exercise.
                let pid: u32 = 60_000 + round as u32 * 1_000 + i;
                l.ingest_start(pid, 400_000 + at, at);
                l.ingest_stop(pid, 400_000 + at, at, at + 10);
            }
            if l.enforce_capacity(9_000 + round) {
                resets_seen += 1;
            }
            assert!(
                l.tracked_count() <= MAX_TRACKED,
                "round {}: bounded at {}",
                round,
                l.tracked_count()
            );
        }
        assert_eq!(
            resets_seen, 0,
            "dead history was available every time, so no reset was needed"
        );
        assert!(
            !l.untrusted(),
            "and the ledger never stopped being able to attribute"
        );
        assert!(
            l.pressure_reclaims() > 0,
            "the reclaims are counted, not silent"
        );
        assert_eq!(
            l.attribute(&rep(7777, false, 9_500)).attributed(),
            Some(ProcInstance::from_sequence_number(7777, 555)),
            "the session that ran through all of it is still attributable"
        );
    }

    /// 26. Dropping old events must never be mistaken for health, and must not undo the reasons
    ///     that are still outstanding.
    #[test]
    fn filtering_never_restores_trust_and_the_three_faults_stay_separate() {
        let mut l = Ledger::new();
        l.set_boundary(1_000);
        l.ingest_start(4994, 111, 1_200);
        l.note_snapshot_sequence(1_300, 111);
        // An unattributable timestamp and an inconsistent pair are refused as invalid, not as
        // pre-boundary, so the two counts cannot blur together.
        l.ingest_start(5555, 222, 0);
        l.ingest_stop(6666, 333, 5_000, 4_000);
        let (old, bad) = l.filtered_counts();
        assert_eq!(
            (old, bad),
            (0, 2),
            "zero timestamp and exit-before-create are 'invalid'"
        );
        // Capacity reset marks the ledger untrusted; filtering then changes nothing about that.
        l.clear_for_reset(9_000);
        l.ingest_start(7777, 444, 1_000);
        assert_eq!(
            l.trust_reason(),
            Some("ledger capacity exceeded"),
            "filtering is not recovery"
        );
        assert!(l.attribute(&rep(7777, true, 9_500)).attributed().is_none());
        // And an event-loss reason is not overwritten by a capacity recovery path.
        l.recovered_from_capacity_reset(9_500);
        l.break_trust("kernel event loss detected");
        l.recovered_from_capacity_reset(9_600);
        assert_eq!(l.trust_reason(), Some("kernel event loss detected"));
        assert_eq!(l.tracked_count(), 0, "still nothing was refilled");
    }

    /// 19. Recovery must not resurrect history: capacity reset, loss counters back to zero, and
    ///     a healthy consumer all leave the old records unusable.
    #[test]
    fn healthy_counters_after_a_reset_do_not_revive_dropped_history() {
        let mut l = Ledger::new();
        l.set_boundary(1_000);
        l.ingest_start(4994, 111, 1_200);
        l.note_snapshot_sequence(1_300, 111);
        l.clear_for_reset(50_000);
        // "Everything looks fine now": trust restored, no loss, consumer alive.
        l.restore_trust();
        assert!(!l.untrusted());
        let r = rep(4994, false, 1_500);
        // The boundary moved past this report, so that is the (more specific, earlier) refusal
        // reason; either way the pre-reset lifetime is gone for good and no zeroed counter
        // brings it back.
        assert_eq!(
            l.attribute(&r),
            Link::Denied(Denial::BeforeBoundary {
                boundary_ms: 50_000,
                report_ms: 1_500
            })
        );
        // And a report *after* the boundary finds no history either.
        assert_eq!(
            l.attribute(&rep(4994, false, 60_000)),
            Link::Denied(Denial::NoLifetime { pid: 4994 })
        );
    }

    /// 21. A capacity reset must be survivable: after a fresh baseline the ledger may attribute
    ///     again, but only for lifetimes observed after the reset.
    #[test]
    fn capacity_reset_recovers_only_for_lifetimes_observed_after_the_new_boundary() {
        let mut l = Ledger::new();
        l.set_boundary(1_000);
        l.ingest_start(4994, 111, 1_200);
        l.note_snapshot_sequence(1_300, 111);
        assert!(l.attribute(&rep(4994, true, 1_500)).attributed().is_some());
        l.clear_for_reset(50_000);
        // Nothing is attributable while the ledger waits for a real baseline.
        assert_eq!(
            l.attribute(&rep(4994, true, 60_000)),
            Link::Denied(Denial::LedgerUntrusted("ledger capacity exceeded"))
        );
        // A fresh snapshot baseline arrives.
        l.recovered_from_capacity_reset(60_000);
        assert!(!l.untrusted());
        assert_eq!(l.boundary(), Some(60_000));
        // Old history is still gone: pre-reset report refused, and so is any old sequence.
        assert_eq!(
            l.attribute(&rep(4994, true, 1_500)),
            Link::Denied(Denial::BeforeBoundary {
                boundary_ms: 60_000,
                report_ms: 1_500
            })
        );
        // A lifetime observed entirely after the reset works again.
        l.ingest_start(7777, 999, 61_000);
        l.note_snapshot_sequence(61_100, 999);
        assert_eq!(
            l.attribute(&rep(7777, false, 62_000)).attributed(),
            Some(ProcInstance::from_sequence_number(7777, 999))
        );
        // Recovery must not clear a different fault reason.
        l.break_trust("kernel event loss detected");
        l.recovered_from_capacity_reset(70_000);
        assert_eq!(l.trust_reason(), Some("kernel event loss detected"));
    }

    /// Once the collector proves it is decoding again, the ledger may attribute - but only from a new
    /// baseline, and never for a lifetime whose interval crossed the untrusted stretch, because that
    /// interval is exactly the one the collector failed to observe.
    #[test]
    fn collector_recovery_rebaselines_without_resurrecting_the_crossing_interval() {
        let mut l = Ledger::new();
        l.set_boundary(1_000);
        l.ingest_start(4994, 777, 1_500);
        l.note_snapshot_sequence(1_600, 777);
        assert_eq!(
            l.attribute(&rep(4994, true, 2_000)).attributed(),
            Some(ProcInstance::from_sequence_number(4994, 777)),
            "sanity: attributable before the fault"
        );

        l.break_trust("collector decode fault");
        assert_eq!(
            l.attribute(&rep(4994, true, 2_500)),
            Link::Denied(Denial::LedgerUntrusted("collector decode fault")),
            "while the collector is untrusted nothing is attributed"
        );
        assert_eq!(
            l.broken_count(),
            1,
            "the open lifetime is marked broken at the fault"
        );

        l.recovered_from_collector_fault(3_000);
        assert_eq!(
            l.trust_reason(),
            None,
            "the fault reason is cleared by its own recovery path"
        );
        assert_eq!(
            l.attribute(&rep(4994, true, 2_500)).attributed(),
            None,
            "a report stamped inside the untrusted stretch still gets nothing, trust or no trust"
        );
        assert_eq!(
            l.attribute(&rep(4994, false, 3_500)).attributed(),
            None,
            "nor may the interval that spanned the fault be closed by a later stop"
        );

        // a lifetime that begins after the new baseline is fully usable again
        l.ingest_start(5050, 888, 3_600);
        l.note_snapshot_sequence(3_700, 888);
        assert_eq!(
            l.attribute(&rep(5050, true, 4_000)).attributed(),
            Some(ProcInstance::from_sequence_number(5050, 888)),
            "new observations after the recovery are attributed normally"
        );
    }

    /// Recovery has to name the fault it recovers from. Otherwise a healthy-looking sample could
    /// clear an event-loss or capacity break too, which is the laundering the design forbids.
    #[test]
    fn collector_recovery_clears_collector_reasons_only() {
        for (reason, should_clear) in [
            ("collector decode fault", true),
            ("collector queue overflow", true),
            ("collector consumer thread exited", true),
            ("collector decode or transport fault", true),
            ("kernel event loss detected", false),
            ("ledger capacity exceeded", false),
            ("loss counters unreadable", false),
        ] {
            let mut l = Ledger::new();
            l.set_boundary(1_000);
            l.break_trust(reason);
            l.recovered_from_collector_fault(9_000);
            if should_clear {
                assert_eq!(l.trust_reason(), None, "{reason} is a collector reason");
            } else {
                assert_eq!(
                    l.trust_reason(),
                    Some(reason),
                    "{reason} must survive collector recovery"
                );
            }
        }
    }

    /// 20. New events after the boundary rebuild usable intervals step by step.
    #[test]
    fn new_lifetimes_after_a_boundary_rebuild_attributable_intervals() {
        let mut l = Ledger::new();
        l.clear_for_reset(20_000);
        l.restore_trust();
        // Snapshot evidence exists (some other process was seen alive), so the cross-source
        // check is live: an unconfirmed sequence must be refused explicitly, not silently used.
        l.note_snapshot_sequence(20_000, 1_000_000);
        l.ingest_start(4994, 909, 21_000);
        assert_eq!(
            l.attribute(&rep(4994, true, 21_500)),
            Link::Denied(Denial::IdentityUnavailable)
        );
        l.note_snapshot_sequence(21_600, 909);
        assert_eq!(
            l.attribute(&rep(4994, true, 21_500)).attributed(),
            Some(ProcInstance::from_sequence_number(4994, 909))
        );
        // Closing it later keeps the interval usable for reports inside the span only.
        l.ingest_stop(4994, 909, 21_000, 22_000);
        assert_eq!(
            l.attribute(&rep(4994, false, 22_500)).attributed(),
            None,
            "a report after death cannot belong to this instance"
        );
    }

    fn rep_at(pid: u32, streaming: bool, at: u64, arrival: u64) -> Report {
        Report {
            pid,
            streaming,
            report_ms: at,
            arrival_ms: arrival,
        }
    }

    /// Reuse plus a broken observation bridge: the old instance's stop, generated inside its own
    /// window but delivered only after the pid changed hands, must be refused and - above all -
    /// must never be pointed at the new instance.
    #[test]
    fn a_reused_pid_with_a_broken_snapshot_bridge_refuses_the_old_stop_forever() {
        let mut l = Ledger::new();
        l.set_boundary(1_000);
        l.ingest_start(4994, 111, 1_500);
        l.note_snapshot_sequence(1_600, 111);
        assert_eq!(
            l.attribute(&rep(4994, true, 2_000)).attributed(),
            Some(ProcInstance::from_sequence_number(4994, 111))
        );
        // The event stream goes quiet and comes back; open lifetimes are now unproven.
        l.break_trust("kernel event loss detected");
        l.restore_trust();
        assert_eq!(
            l.attribute(&rep(4994, true, 2_500)),
            Link::Denied(Denial::Discontinuous { pid: 4994 })
        );
        // During that hole 111 exited and 222 took the pid; the first thing we see again is
        // 222's own start event.
        l.ingest_start(4994, 222, 4_000);
        l.note_snapshot_sequence(4_100, 222);
        // 111's stop, stamped 2_000 but delivered at 4_500: refused, and never 222's.
        let late_old = rep_at(4994, false, 2_000, 4_500);
        assert!(
            l.attribute(&late_old).attributed().is_none(),
            "an orphaned old stop cannot be attributed"
        );
        assert_ne!(
            l.attribute(&late_old).attributed(),
            Some(ProcInstance::from_sequence_number(4994, 222)),
            "the new holder must never inherit the old instance's stop"
        );
        // 222's own reports resolve cleanly to 222, so the refusal is not a blanket outage.
        assert_eq!(
            l.attribute(&rep_at(4994, false, 5_000, 5_100)).attributed(),
            Some(ProcInstance::from_sequence_number(4994, 222))
        );
    }

    /// 12. The observation boundary refuses the past, even when a stop event later reveals that
    ///     very instance's birth instant.
    #[test]
    fn a_stop_event_that_reveals_a_birth_does_not_open_the_period_we_were_blind() {
        let mut l = Ledger::new();
        l.set_boundary(10_000);
        l.note_alive(4994, 555, 10_500);
        // Seen-alive bounds nothing below, so nothing is attributable yet.
        assert!(l.attribute(&rep(4994, true, 11_000)).attributed().is_none());
        // The stop event says it was born at 5_000 - before we started watching. Under the
        // boundary rule that event is discarded outright: a birth from the discarded world may
        // not create a record, even when it arrives together with a death inside our watch.
        l.ingest_stop(4994, 555, 5_000, 12_000);
        assert_eq!(
            l.filtered_counts(),
            (1, 0),
            "the pre-boundary stop was dropped, not absorbed"
        );
        assert_eq!(
            l.attribute(&rep(4994, true, 6_000)),
            Link::Denied(Denial::BeforeBoundary {
                boundary_ms: 10_000,
                report_ms: 6_000
            })
        );
        assert_eq!(
            l.attribute(&rep(4994, false, 9_999)),
            Link::Denied(Denial::BeforeBoundary {
                boundary_ms: 10_000,
                report_ms: 9_999
            })
        );
        // Reports after the boundary find no history either: the seen-alive record still has no
        // lower bound, and the discarded birth did not give it one. The reason reads
        // `OutsideLifetime` rather than `NoLifetime` because a record for the pid does exist - it
        // simply proves nothing about this instant.
        assert_eq!(
            l.attribute(&rep(4994, true, 11_000)),
            Link::Denied(Denial::OutsideLifetime { pid: 4994 })
        );
        // A lifetime that genuinely begins at or after the boundary is still attributable, so the
        // refusal above is about the boundary and not about the ledger being broken.
        l.ingest_start(8888, 600, 10_500);
        l.note_snapshot_sequence(10_600, 600);
        l.ingest_stop(8888, 600, 10_500, 13_000);
        assert_eq!(
            l.attribute(&rep(8888, false, 12_000)).attributed(),
            Some(ProcInstance::from_sequence_number(8888, 600))
        );
    }

    /// 13. Losing lifecycle events is not a detail to log: it voids attribution outright.
    #[test]
    fn event_loss_voids_attribution_until_the_stream_is_reestablished() {
        let mut l = Ledger::new();
        l.set_boundary(1_000);
        l.ingest_start(4994, 777, 1_500);
        l.note_snapshot_sequence(1_600, 777);
        assert_eq!(
            l.attribute(&rep(4994, true, 2_000)).attributed(),
            Some(ProcInstance::from_sequence_number(4994, 777))
        );
        l.break_trust("kernel event loss detected");
        assert_eq!(
            l.attribute(&rep(4994, true, 2_500)),
            Link::Denied(Denial::LedgerUntrusted("kernel event loss detected"))
        );
        assert_eq!(l.broken_count(), 1, "the open lifetime is marked broken");
        // Counters clean again: trust returns, the lifetime that spanned the hole does not.
        l.restore_trust();
        assert_eq!(
            l.attribute(&rep(4994, false, 3_000)),
            Link::Denied(Denial::Discontinuous { pid: 4994 })
        );
        // A fresh start event for the same instance re-establishes continuity.
        l.ingest_start(4994, 777, 3_500);
        assert_eq!(
            l.attribute(&rep(4994, false, 4_000)).attributed(),
            Some(ProcInstance::from_sequence_number(4994, 777))
        );
    }

    /// 14. Reuse closes the old instance, and no evidence crosses that boundary: the old
    ///     instance's late FALSE is refused, and the new holder's reports go to the new instance.
    #[test]
    fn reuse_closes_the_old_instance_without_letting_evidence_cross_the_boundary() {
        let mut l = Ledger::new();
        l.set_boundary(1_000);
        l.ingest_start(4994, 111, 1_500);
        l.note_snapshot_sequence(1_600, 111);
        assert_eq!(
            l.attribute(&rep(4994, true, 2_000)).attributed(),
            Some(ProcInstance::from_sequence_number(4994, 111))
        );
        // The pid is handed to instance 222 at 5_000.
        l.ingest_start(4994, 222, 5_000);
        assert_eq!(l.tracked_count(), 1, "only the current holder is tracked");
        // 111's FALSE, stamped 2_000 but delivered at 6_000, belongs to a record we no longer
        // hold and whose death instant was never observed: refused, never re-pointed at 222.
        // (The label used to be `StaleSample { sample_at_ms: 0 }`, a placeholder that misdescribed
        // the reason. The refusal is unchanged; only the now-accurate name differs.)
        assert_eq!(
            l.attribute(&rep_at(4994, false, 2_000, 6_000)),
            Link::Denied(Denial::OutsideLifetime { pid: 4994 })
        );
        // The new holder's own report resolves to the new instance.
        l.note_snapshot_sequence(6_000, 222);
        assert_eq!(
            l.attribute(&rep_at(4994, false, 5_500, 6_000)).attributed(),
            Some(ProcInstance::from_sequence_number(4994, 222))
        );
    }
}
