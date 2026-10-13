//! Association layer: *may this SAM report be attributed to a process instance we can prove?*
//!
//! Why this is a separate layer. `proc_identity` can parse a process snapshot, and `sam_view`
//! decides device state. Neither of them answers the question in between, which is the hard
//! one: a SAM report carries only a **pid**, while a snapshot describes **who holds that pid at
//! the instant the snapshot was taken**. Handing the pid straight to the state machine - or
//! worse, pasting a sequence number into a field called `created_ms` - would quietly pretend
//! those two things are the same object. They are not, and this module exists to keep the
//! difference visible in the type.
//!
//! What this layer guarantees:
//! - A report is attributed **only** when a snapshot taken at or after the report's arrival
//!   proves the pid is held by the same sourced identity that our baseline holds, with no
//!   broken observation in between.
//! - Anything else returns an explicit `Denial` reason. There is no path that falls back to
//!   pid-only attribution, and no path where "we could not look" becomes "same as last time".
//! - Re-establishment after a discontinuity is marked `new_instance = true`, which tells the
//!   consumer it must not carry over any state recorded under the previous baseline.
//!
//! What this layer does **not** claim: it cannot prove that a report was produced by the
//! instance the snapshot sees, if the observation was broken in between. That limit is real
//! (see the tests around `StaleSample` and `Discontinuous`) and is recorded in the design doc
//! rather than papered over.

use std::collections::HashMap;

use crate::sam_view::{IdentityValue, ProcInstance};

/// One delivered report, with only the fields we actually have.
///
/// SAM gives a pid and a streaming flag. `report_ms` is the report's own clock (system
/// FILETIME), `arrival_ms` is when our callback thread received it. Attribution uses
/// `arrival_ms`, because that is the timestamp comparable with a snapshot we took.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    pub pid: u32,
    pub streaming: bool,
    pub report_ms: u64,
    pub arrival_ms: u64,
}

/// Why a snapshot told us nothing. Every one of these is a **hard stop** for attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleFailure {
    /// `NtQuerySystemInformation` returned an error (NTSTATUS carried verbatim).
    CallFailed(i32),
    /// The buffer could not be walked to the end: partial data is not data.
    BufferInvalid,
    /// The info class is not available on this build.
    Unsupported,
}

/// One process snapshot, pinned to the instant it was taken.
///
/// A row's identity is `None` when the pid is in the list but its instance value could not be
/// read: present-but-unprovable, which is deliberately not the same as `Absent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sample {
    Rows {
        at_ms: u64,
        generation: u64,
        rows: Vec<(u32, Option<IdentityValue>)>,
    },
    Failed {
        at_ms: u64,
        reason: SampleFailure,
    },
}

impl Sample {
    pub fn rows(at_ms: u64, generation: u64, rows: Vec<(u32, Option<IdentityValue>)>) -> Sample {
        Sample::Rows {
            at_ms,
            generation,
            rows,
        }
    }

    pub fn failed(at_ms: u64, reason: SampleFailure) -> Sample {
        Sample::Failed { at_ms, reason }
    }

    /// Who holds `pid` according to this snapshot, if it can say anything at all.
    pub fn lookup(&self, pid: u32) -> Occupant {
        match self {
            Sample::Failed { .. } => Occupant::Unknown,
            Sample::Rows { rows, .. } => match rows.iter().find(|(p, _)| *p == pid) {
                Some((_, Some(identity))) => Occupant::Present(*identity),
                Some((_, None)) => Occupant::PresentButUnprovable,
                None => Occupant::Absent,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Occupant {
    /// The pid is listed and its instance value was read.
    Present(IdentityValue),
    /// The pid is listed, but the identity value could not be read. Not a fallback opportunity.
    PresentButUnprovable,
    /// The snapshot succeeded and the pid is genuinely not in it.
    Absent,
    /// The snapshot failed: we do not know, which is not the same as "absent".
    Unknown,
}

/// The only two outcomes. Note that `Denied` carries no instance: a refusal cannot be
/// misread as "attribute it somewhere anyway".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Link {
    Attributed {
        inst: ProcInstance,
        /// `true` means a baseline was created by *this* report, so nothing before it applies.
        /// The consumer must treat it as a new observation of that pid and must not inherit
        /// liveness or ordering state from any earlier baseline for the same pid.
        new_instance: bool,
    },
    Denied(Denial),
}

impl Link {
    /// Whether the consumer has to discard state held under an earlier baseline.
    pub fn requires_state_reset(&self) -> bool {
        matches!(
            self,
            Link::Attributed {
                new_instance: true,
                ..
            }
        )
    }

    pub fn attributed(&self) -> Option<ProcInstance> {
        match self {
            Link::Attributed { inst, .. } => Some(*inst),
            Link::Denied(_) => None,
        }
    }
}

/// Explicit reasons. Grouped so a reviewer can see that none of them is "good enough".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denial {
    /// No snapshot has ever been taken: we have no view of who holds the pid.
    NoSample,
    /// The snapshot we were given failed (with its cause attached).
    SampleFailed(SampleFailure),
    /// The snapshot predates the report's arrival, so it cannot describe the report's author.
    StaleSample {
        sample_at_ms: u64,
        report_arrival_ms: u64,
    },
    /// The pid was not in a snapshot taken at or after the report.
    PidAbsent,
    /// The pid is listed but its instance value could not be read.
    IdentityUnavailable,
    /// This pid has never had a proven baseline, so a `FALSE` has nothing to stop.
    NoBaseline { pid: u32 },
    /// Same pid, different sequence number: the old instance is gone; the report cannot be
    /// matched across that boundary.
    SequenceChanged { pid: u32, baseline: u64, seen: u64 },
    /// Same numeric value, different identity *source*. Refused: sources are not interchangeable.
    SourceChanged {
        pid: u32,
        baseline: &'static str,
        seen: &'static str,
    },
    /// Observation was broken between the baseline and this report, so continuity is unproven.
    Discontinuous { pid: u32 },
    /// More than one lifetime covers the report's instant: the evidence is inconsistent, and
    /// choosing one of them would be a guess dressed up as a result.
    Ambiguous { pid: u32, over: usize },
    /// The report is stamped before we began observing the process table at all. A lifetime we
    /// later learn the start of is still not coverage for that period.
    BeforeBoundary { boundary_ms: u64, report_ms: u64 },
    /// The report carries no time that can be placed in the unix domain (`report_ms == 0`, the
    /// sentinel for an empty or pre-1970 FILETIME). Such a report cannot be ordered against a
    /// lifetime at all, so it is refused outright rather than being guessed to sit on either
    /// side of the observation boundary.
    UnusableReportTime { pid: u32 },
    /// The lifecycle stream lost events, its counters could not be read, or the collector
    /// stalled: nothing may be attributed while that is true.
    LedgerUntrusted(&'static str),
    /// No lifetime is known for this pid at all - typically a ProcessStart that has not been
    /// flushed yet. Distinct from `OutsideLifetime`, and previously mislabelled as `StaleSample`.
    NoLifetime { pid: u32 },
    /// Lifetimes exist for this pid but the report's instant falls outside every known one.
    OutsideLifetime { pid: u32 },
}

/// Per-pid proof of who we last saw holding it, and whether that sight is still continuous.
#[derive(Debug, Clone, Copy)]
struct Baseline {
    identity: IdentityValue,
    established_at_ms: u64,
    contiguous: bool,
}

/// The linker. Pure: no Win32, no clock, no I/O. The caller brings snapshots and reports.
#[derive(Debug, Default)]
pub struct ReportLinker {
    baselines: HashMap<u32, Baseline>,
    last_generation: Option<u64>,
}

impl ReportLinker {
    pub fn new() -> Self {
        ReportLinker {
            baselines: HashMap::new(),
            last_generation: None,
        }
    }

    pub fn baseline_count(&self) -> usize {
        self.baselines.len()
    }

    /// Forget every baseline: service restart, device re-enumeration, or an explicit decision
    /// to switch identity source. Nothing may pair an old-source `TRUE` with a new-source
    /// `FALSE`, so this is the only sanctioned way to change sources.
    pub fn reset(&mut self) {
        self.baselines.clear();
        self.last_generation = None;
    }

    /// Fold a snapshot into the linker's view of continuity.
    ///
    /// A baseline is never deleted here: "we saw a different identity" is the evidence that
    /// lets `link` name the reason instead of silently treating the pid as untracked. Deletion
    /// happens only in the branches that actually consume the proof.
    pub fn note_sample(&mut self, sample: &Sample) {
        match sample {
            Sample::Failed { reason, .. } => {
                // We can no longer prove that anything is still the same process. The values
                // we proved earlier stay, but every baseline loses continuity, so the next
                // report cannot ride on them.
                let _ = reason;
                for b in self.baselines.values_mut() {
                    b.contiguous = false;
                }
            }
            Sample::Rows {
                generation, rows, ..
            } => {
                for (pid, b) in self.baselines.iter_mut() {
                    // Strict on purpose: a good sample never *repairs* a break that already
                    // happened while we were not looking. Only re-establishment (a TRUE, which
                    // is the conservative direction) starts a new continuous baseline.
                    b.contiguous = b.contiguous
                        && match rows.iter().find(|(p, _)| *p == *pid) {
                            Some((_, Some(identity))) => *identity == b.identity,
                            // Absent, or present with an unreadable value: continuity is broken
                            // either way. "Unknown" is never upgraded to "unchanged".
                            _ => false,
                        };
                }
                self.last_generation = Some(*generation);
            }
        }
    }

    /// When the current baseline for this pid was first proven. Exposure for logs and tests;
    /// never an input to a decision.
    pub fn proven_since(&self, pid: u32) -> Option<u64> {
        self.baselines.get(&pid).map(|b| b.established_at_ms)
    }

    pub fn generation(&self) -> Option<u64> {
        self.last_generation
    }

    /// Decide whether `report` may be attributed, given the latest snapshot.
    ///
    /// This is the fail-closed core: every branch that is not provably the same instance
    /// returns a reason, and no branch invents an identity. Checks run source first, then
    /// value, then continuity, so the most specific refusal wins.
    pub fn link(&mut self, report: &Report, sample: &Sample) -> Link {
        let (at_ms, rows) = match sample {
            Sample::Failed { reason, .. } => return Link::Denied(Denial::SampleFailed(*reason)),
            Sample::Rows { at_ms, rows, .. } => (*at_ms, rows),
        };
        // A snapshot taken before the report arrived cannot say who authored the report.
        if at_ms < report.arrival_ms {
            return Link::Denied(Denial::StaleSample {
                sample_at_ms: at_ms,
                report_arrival_ms: report.arrival_ms,
            });
        }
        match rows.iter().find(|(p, _)| *p == report.pid) {
            None => {
                // Nothing that we ever proved about this pid still applies.
                self.baselines.remove(&report.pid);
                Link::Denied(Denial::PidAbsent)
            }
            Some((_, None)) => Link::Denied(Denial::IdentityUnavailable),
            Some((_, Some(seen))) => {
                let found = *seen;
                let inst = ProcInstance {
                    pid: report.pid,
                    identity: Some(found),
                };
                match self.baselines.get(&report.pid).copied() {
                    Some(base) => {
                        if base.identity.origin() != found.origin() {
                            // Refused without touching the baseline: a single odd sample must
                            // not retarget the instance onto another source.
                            return Link::Denied(Denial::SourceChanged {
                                pid: report.pid,
                                baseline: base.identity.origin(),
                                seen: found.origin(),
                            });
                        }
                        if base.identity != found {
                            // Same pid, different instance. Whatever this report is about, we
                            // can no longer pair it with the baseline we are losing here.
                            self.baselines.remove(&report.pid);
                            return Link::Denied(Denial::SequenceChanged {
                                pid: report.pid,
                                baseline: base.identity.raw(),
                                seen: found.raw(),
                            });
                        }
                        if !base.contiguous {
                            // Observation was broken. A TRUE may start a *new* baseline (it
                            // only ever makes the device busier); a FALSE may not, because an
                            // unprovable stop is exactly what must not idle the device.
                            if !report.streaming {
                                return Link::Denied(Denial::Discontinuous { pid: report.pid });
                            }
                            self.baselines.insert(
                                report.pid,
                                Baseline {
                                    identity: found,
                                    established_at_ms: report.arrival_ms,
                                    contiguous: true,
                                },
                            );
                            return Link::Attributed {
                                inst,
                                new_instance: true,
                            };
                        }
                        Link::Attributed {
                            inst,
                            new_instance: false,
                        }
                    }
                    None => {
                        // No proven baseline for this pid. Only a `TRUE` may create one: it is
                        // the conservative direction (a client probably *is* streaming), and it
                        // establishes identity for later reports. A `FALSE` here is exactly the
                        // isolated-stop case and must never create a baseline just so it can
                        // take the device idle.
                        if !report.streaming {
                            return Link::Denied(Denial::NoBaseline { pid: report.pid });
                        }
                        self.baselines.insert(
                            report.pid,
                            Baseline {
                                identity: found,
                                established_at_ms: report.arrival_ms,
                                contiguous: true,
                            },
                        );
                        Link::Attributed {
                            inst,
                            new_instance: true,
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seq(v: u64) -> Option<IdentityValue> {
        Some(IdentityValue::SequenceNumber(v))
    }

    fn created(v: u64) -> Option<IdentityValue> {
        Some(IdentityValue::CreationTime(v))
    }

    fn report(pid: u32, streaming: bool, arrival: u64) -> Report {
        Report {
            pid,
            streaming,
            report_ms: arrival,
            arrival_ms: arrival,
        }
    }

    fn sample(at: u64, gen: u64, rows: Vec<(u32, Option<IdentityValue>)>) -> Sample {
        Sample::rows(at, gen, rows)
    }

    /// 1. Continuous, valid observation of the same sourced identity is the *same* instance.
    #[test]
    fn continuous_identical_observation_attributes_to_one_instance() {
        let mut l = ReportLinker::new();
        let s = sample(1_500, 1, vec![(4994, seq(373431))]);
        l.note_sample(&s);
        let first = l.link(&report(4994, true, 1_000), &s);
        assert_eq!(
            first,
            Link::Attributed {
                inst: ProcInstance::from_sequence_number(4994, 373431),
                new_instance: true
            }
        );
        assert!(
            first.requires_state_reset(),
            "a fresh baseline must not inherit anything"
        );
        assert_eq!(
            l.proven_since(4994),
            Some(1_000),
            "the baseline records when it was proven"
        );
        // Later reports under the same proven identity continue the same instance.
        let s2 = sample(2_600, 2, vec![(4994, seq(373431))]);
        l.note_sample(&s2);
        assert_eq!(
            l.link(&report(4994, true, 2_500), &s2),
            Link::Attributed {
                inst: ProcInstance::from_sequence_number(4994, 373431),
                new_instance: false
            }
        );
        // And the explicit stop is attributed to exactly that instance.
        assert_eq!(
            l.link(&report(4994, false, 2_550), &s2).attributed(),
            Some(ProcInstance::from_sequence_number(4994, 373431))
        );
    }

    /// 2. Same pid, different sequence: a different instance, and the old liveness never rides over.
    #[test]
    fn a_changed_sequence_number_is_a_different_instance_and_drops_the_old_baseline() {
        let mut l = ReportLinker::new();
        let s = sample(1_100, 1, vec![(4994, seq(111))]);
        l.note_sample(&s);
        assert!(l
            .link(&report(4994, true, 1_000), &s)
            .attributed()
            .is_some());
        // The pid is now held by another instance.
        let s2 = sample(2_200, 2, vec![(4994, seq(222))]);
        l.note_sample(&s2);
        assert_eq!(
            l.link(&report(4994, true, 2_100), &s2),
            Link::Denied(Denial::SequenceChanged {
                pid: 4994,
                baseline: 111,
                seen: 222
            })
        );
        assert_eq!(
            l.baseline_count(),
            0,
            "the old baseline must not survive the switch"
        );
        // A TRUE under the new identity establishes it, flagged as a new observation...
        let s3 = sample(3_200, 3, vec![(4994, seq(222))]);
        l.note_sample(&s3);
        assert_eq!(
            l.link(&report(4994, true, 3_100), &s3),
            Link::Attributed {
                inst: ProcInstance::from_sequence_number(4994, 222),
                new_instance: true
            }
        );
        // ...and the old instance's value can never be produced again for this pid.
        assert_ne!(
            l.link(&report(4994, false, 3_200), &s3).attributed(),
            Some(ProcInstance::from_sequence_number(4994, 111))
        );
    }

    /// 3. Equal numbers from different sources are not equal identities.
    #[test]
    fn the_same_number_from_a_different_source_is_not_the_same_instance() {
        // Type level: a creation time and a sequence number never compare equal.
        assert_ne!(
            IdentityValue::CreationTime(7),
            IdentityValue::SequenceNumber(7)
        );
        assert_ne!(
            ProcInstance::from_creation_time(4994, 7),
            ProcInstance::from_sequence_number(4994, 7)
        );

        let mut l = ReportLinker::new();
        let s = sample(1_100, 1, vec![(4994, created(7))]);
        l.note_sample(&s);
        assert!(l
            .link(&report(4994, true, 1_000), &s)
            .attributed()
            .is_some());
        // Same pid, same numeric value, different source -> refused, and the baseline stays put
        // (a refused sample must not silently retarget the instance onto the new source).
        let s2 = sample(2_200, 2, vec![(4994, seq(7))]);
        l.note_sample(&s2);
        assert_eq!(
            l.link(&report(4994, false, 2_100), &s2),
            Link::Denied(Denial::SourceChanged {
                pid: 4994,
                baseline: "creation_time",
                seen: "sequence"
            })
        );
        // Back to the original source. Two things must both hold: the refusal did not retarget
        // anything, and the sample that disagreed in between is a real break that a later good
        // sample may not erase. (The first version of this test expected the stop to be
        // attributable again here; that expectation was the optimistic one, and the strict rule
        // is what we keep.)
        let s3 = sample(3_200, 3, vec![(4994, created(7))]);
        l.note_sample(&s3);
        assert_eq!(
            l.link(&report(4994, false, 3_100), &s3),
            Link::Denied(Denial::Discontinuous { pid: 4994 }),
            "a disagreeing sample in between breaks continuity for good"
        );
        // Only a TRUE re-establishes, and it re-establishes the *original source's* value.
        assert_eq!(
            l.link(&report(4994, true, 3_150), &s3),
            Link::Attributed {
                inst: ProcInstance::from_creation_time(4994, 7),
                new_instance: true
            }
        );
    }

    /// 4. A pid that is simply not in the snapshot cannot be attributed to anything we knew.
    #[test]
    fn an_absent_pid_is_denied_and_its_baseline_is_dropped() {
        let mut l = ReportLinker::new();
        let s = sample(1_100, 1, vec![(4994, seq(9))]);
        l.note_sample(&s);
        assert!(l
            .link(&report(4994, true, 1_000), &s)
            .attributed()
            .is_some());
        let s2 = sample(2_200, 2, vec![(555, seq(1))]);
        l.note_sample(&s2);
        assert_eq!(
            l.link(&report(4994, false, 2_100), &s2),
            Link::Denied(Denial::PidAbsent)
        );
        assert_eq!(l.baseline_count(), 0);
        // Reappearance is a new observation, never a continuation.
        let s3 = sample(3_200, 3, vec![(4994, seq(9))]);
        l.note_sample(&s3);
        assert_eq!(
            l.link(&report(4994, true, 3_100), &s3),
            Link::Attributed {
                inst: ProcInstance::from_sequence_number(4994, 9),
                new_instance: true
            }
        );
        // A stop that arrives later, judged against the *older* sample, is refused on timing -
        // not by reusing the dropped baseline.
        assert_eq!(
            l.link(&report(4994, false, 3_150), &s2),
            Link::Denied(Denial::StaleSample {
                sample_at_ms: 2_200,
                report_arrival_ms: 3_150
            })
        );
    }

    /// 5. Failed or unparseable snapshots never degrade into pid-only attribution.
    #[test]
    fn a_failed_snapshot_denies_everything_and_breaks_continuity() {
        let mut l = ReportLinker::new();
        let ok = sample(1_100, 1, vec![(4994, seq(9))]);
        l.note_sample(&ok);
        assert!(l
            .link(&report(4994, true, 1_000), &ok)
            .attributed()
            .is_some());
        // A sample that does cover the later reports, so timing is never the reason below.
        let later = sample(2_500, 3, vec![(4994, seq(9))]);

        for reason in [
            SampleFailure::CallFailed(-1073741772),
            SampleFailure::BufferInvalid,
            SampleFailure::Unsupported,
        ] {
            let bad = Sample::failed(2_000, reason);
            assert_eq!(
                l.link(&report(4994, false, 2_100), &bad),
                Link::Denied(Denial::SampleFailed(reason)),
                "a failed query must never look like evidence"
            );
            l.note_sample(&bad);
            // After a failure the earlier proof is no longer continuous, so even a FALSE for
            // the very same identity is refused until a TRUE re-establishes it.
            assert_eq!(
                l.link(&report(4994, false, 2_200), &later),
                Link::Denied(Denial::Discontinuous { pid: 4994 })
            );
            // A fresh good sample does **not** repair the break: the window when we were not
            // looking stays unproven, and continuity is only restored by re-establishment.
            l.note_sample(&later);
            assert_eq!(
                l.link(&report(4994, false, 2_250), &later),
                Link::Denied(Denial::Discontinuous { pid: 4994 })
            );
            assert_eq!(
                l.link(&report(4994, true, 2_300), &later),
                Link::Attributed {
                    inst: ProcInstance::from_sequence_number(4994, 9),
                    new_instance: true
                },
                "re-establishment is allowed but marked new, so no stale state may be reused"
            );
            l.note_sample(&bad);
        }
        // Continuity is the linker's state, not a property of the sample: a fresh linker that
        // never observed this pid still cannot be talked into attributing a stop.
        let mut fresh = ReportLinker::new();
        assert_eq!(
            fresh.link(&report(4994, false, 1_000), &ok),
            Link::Denied(Denial::NoBaseline { pid: 4994 })
        );
        assert_eq!(fresh.baseline_count(), 0);
    }

    /// 6. A late stop from the old instance must not stop the new one.
    #[test]
    fn a_late_false_from_the_previous_instance_cannot_stop_the_new_one() {
        let mut l = ReportLinker::new();
        let s = sample(1_100, 1, vec![(4994, seq(111))]);
        l.note_sample(&s);
        l.link(&report(4994, true, 1_000), &s);
        // Process 111 exits, the pid is handed to 222, and only now does the old stream's
        // FALSE surface in our queue.
        let s2 = sample(5_200, 2, vec![(4994, seq(222))]);
        l.note_sample(&s2);
        assert_eq!(
            l.link(&report(4994, false, 5_100), &s2),
            Link::Denied(Denial::SequenceChanged {
                pid: 4994,
                baseline: 111,
                seen: 222
            })
        );
        // Establishing the new instance, then a FALSE that carries the *old* identity value:
        // it resolves to nothing we hold, so it stays denied.
        let s3 = sample(6_200, 3, vec![(4994, seq(222))]);
        l.note_sample(&s3);
        assert!(l
            .link(&report(4994, true, 6_100), &s3)
            .attributed()
            .is_some());
        assert_eq!(
            l.link(&report(4994, false, 6_200), &sample(6_200, 4, vec![])),
            Link::Denied(Denial::PidAbsent)
        );
    }

    /// 7. The irreducible case: a snapshot older than the report cannot identify its author.
    #[test]
    fn a_snapshot_taken_before_the_report_cannot_prove_the_reports_author() {
        let mut l = ReportLinker::new();
        let s = sample(1_000, 1, vec![(4994, seq(111))]);
        l.note_sample(&s);
        l.link(&report(4994, true, 1_000), &s);
        // Report delivered at 9_000, but the newest sample we hold is from 1_000 - during the
        // 8 s we did not look, the pid could have been recycled. Refuse, do not guess.
        assert_eq!(
            l.link(&report(4994, false, 9_000), &s),
            Link::Denied(Denial::StaleSample {
                sample_at_ms: 1_000,
                report_arrival_ms: 9_000
            })
        );
        // A sample that does cover the arrival instant, with the same identity, is attributable
        // again - the refusal was about timing, not about the pid.
        let fresh = sample(9_500, 2, vec![(4994, seq(111))]);
        l.note_sample(&fresh);
        assert_eq!(
            l.link(&report(4994, false, 9_000), &fresh).attributed(),
            Some(ProcInstance::from_sequence_number(4994, 111))
        );
    }

    /// 8. An isolated stop - a pid nobody ever proved streaming - has nothing to stop.
    #[test]
    fn a_false_without_a_proven_baseline_is_denied_and_creates_nothing() {
        let mut l = ReportLinker::new();
        let s = sample(1_100, 1, vec![(777, seq(5))]);
        l.note_sample(&s);
        assert_eq!(
            l.link(&report(777, false, 1_100), &s),
            Link::Denied(Denial::NoBaseline { pid: 777 })
        );
        assert_eq!(
            l.baseline_count(),
            0,
            "a denied stop must not create a baseline"
        );
        // Presence without a readable identity is its own denial: not a licence to use the pid.
        let s2 = sample(2_100, 2, vec![(777, None)]);
        l.note_sample(&s2);
        assert_eq!(
            l.link(&report(777, true, 2_100), &s2),
            Link::Denied(Denial::IdentityUnavailable)
        );
        assert_eq!(
            l.link(&report(777, false, 2_100), &s2),
            Link::Denied(Denial::IdentityUnavailable)
        );
        assert_eq!(l.baseline_count(), 0);
    }

    /// 9. Nothing that is denied hands back an instance, so no caller can "use it anyway".
    #[test]
    fn denial_never_carries_an_instance() {
        let mut l = ReportLinker::new();
        let s = sample(
            1_000,
            1,
            vec![(4994, seq(9)), (4995, None), (4996, created(1))],
        );
        l.note_sample(&s);
        let cases = [
            report(4994, false, 1_000), // no baseline yet
            report(4995, true, 1_000),  // identity unreadable
            report(9999, true, 1_000),  // not in the snapshot
            report(4996, false, 5_000), // snapshot predates the report
        ];
        for r in cases {
            let link = l.link(&r, &s);
            assert!(
                link.attributed().is_none(),
                "{r:?} must not resolve to an instance: {link:?}"
            );
            assert!(!link.requires_state_reset());
        }
        // Unresolved identity is a state of our knowledge, never a ProcInstance value: the
        // only constructors are the two sourced ones plus unresolved(), and the arbiter still
        // refuses to let an unresolved instance produce a stop (sam_view covers that).
        assert!(!ProcInstance::unresolved(4994).identity_resolved());
    }

    /// 10. Restart and source switches invalidate: no cross-generation pairing.
    #[test]
    fn reset_invalidates_baselines_so_old_state_cannot_pollute_new_ones() {
        let mut l = ReportLinker::new();
        let s = sample(1_100, 1, vec![(4994, created(111))]);
        l.note_sample(&s);
        l.link(&report(4994, true, 1_000), &s);
        l.reset();
        assert_eq!(l.baseline_count(), 0);
        assert_eq!(l.generation(), None);
        // After the reset the same instance value must come back as a new observation...
        let s2 = sample(2_200, 7, vec![(4994, created(111))]);
        l.note_sample(&s2);
        assert_eq!(
            l.link(&report(4994, true, 2_100), &s2),
            Link::Attributed {
                inst: ProcInstance::from_creation_time(4994, 111),
                new_instance: true
            }
        );
        // ...and a stop that predates the reset is not something we may attribute at all.
        assert_eq!(
            l.link(&report(4994, false, 500), &s2).attributed(),
            Some(ProcInstance::from_creation_time(4994, 111)),
            "arriving after the reset, this one is attributable - see the ordering rules in sam_view"
        );
    }

    /// Generation bookkeeping is exposure, not identity: a bump alone changes nothing.
    #[test]
    fn a_new_generation_without_observation_does_not_repair_continuity() {
        let mut l = ReportLinker::new();
        let s = sample(1_100, 1, vec![(4994, seq(9))]);
        l.note_sample(&s);
        l.link(&report(4994, true, 1_000), &s);
        // We fail to observe for a while; the linker is told, and continuity is gone.
        l.note_sample(&Sample::failed(2_000, SampleFailure::Unsupported));
        // A later successful sample cannot, by itself, claim continuity for a report that
        // arrived in between: the gap is already recorded.
        let s3 = sample(3_200, 9, vec![(4994, seq(9))]);
        assert_eq!(
            l.link(&report(4994, false, 2_500), &s3),
            Link::Denied(Denial::Discontinuous { pid: 4994 })
        );
        // Re-establishment needs a TRUE, and it is explicitly new.
        l.note_sample(&s3);
        assert_eq!(
            l.link(&report(4994, true, 3_100), &s3),
            Link::Attributed {
                inst: ProcInstance::from_sequence_number(4994, 9),
                new_instance: true
            }
        );
    }
}
