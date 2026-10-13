//! Read-only sampling of a live ETW session's loss counters.
//!
//! Diagnostics only, and deliberately kept that way:
//!   * the only control code ever passed is `EVENT_TRACE_CONTROL_QUERY` - never STOP,
//!     UPDATE or SET, and no session or consumer is ever created here;
//!   * the single caller is the control loop in `runtime::Runtime::run`, which logs the
//!     result. Nothing in `policy`, `Engine::tick`, `Transport` or `MotorChannel` reads
//!     these numbers, so a loss counter can never move the lens.
//!   * a failed query is reported as unavailable. It is never reported as "zero losses",
//!     and the previous sample is never reused as if it were current.
//!   * log throttling may suppress a *message*. It never suppresses a state transition:
//!     losing trust and dropping the window happen unconditionally.
//!
//! `LossTracker` is a pure state machine so the semantics (reset, invalid interval,
//! throttling, bounded window) are testable without touching ETW at all.

use std::collections::VecDeque;

use windows::core::PCWSTR;
use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::System::Diagnostics::Etw::{
    ControlTraceW, CONTROLTRACE_HANDLE, EVENT_TRACE_CONTROL_QUERY, EVENT_TRACE_PROPERTIES,
};

/// The window is a *time* window, not a bucket count. It is the half-open interval
/// `(now_ms - WINDOW_MS, now_ms]`: a bucket whose age *reaches* 30 minutes is expired by
/// time, not kept and then pushed out by the capacity cap. Expiry runs on every
/// observation, whichever branch that observation takes.
const WINDOW_MS: u64 = 30 * 60 * 1000;
/// How the window is named in a log line. It names a *duration*, never a bucket count:
/// 60 buckets would only happen to be 30 minutes at exactly one sample per 30s, and the
/// cadence we trust is a band, not a constant.
const WINDOW_LABEL: &str = "window30m";
/// A delta may enter the window only when the gap between two successful samples is
/// plausible for the cadence. Outside that band the increment is real but its time span
/// is not a sampling interval, so it must not be presented as a window bucket.
const TRUST_MIN_FACTOR: u64 = 2; // accept dt >= interval/2
const TRUST_MAX_FACTOR: u64 = 2; // accept dt <= interval*2

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LossCounters {
    pub events_lost: u64,
    pub log_buffers_lost: u64,
    pub real_time_buffers_lost: u64,
    pub buffers: u32,
}

/// The scratch-buffer geometry, factored out so the test and the call share one source of
/// truth: capacity (usize-aligned), the struct offset, and the UTF-16 name size including
/// its terminating NUL.
fn scratch_layout(name: &str) -> (usize, usize, usize) {
    let ps = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let nb = (name.encode_utf16().count() + 1) * 2;
    let needed = ps + nb + 8;
    let unit = std::mem::size_of::<usize>();
    (needed.div_ceil(unit) * unit, ps, nb)
}

/// Read one live session's counters by name. `Err(win32_code)` must be logged verbatim.
///
/// The properties buffer has to be allocated together with the trailing session name and
/// `Wnode.BufferSize` has to cover both, or the call fails with ERROR_BAD_LENGTH.
///
/// Backing store is `Vec<usize>`, not `Vec<u8>`: a byte vector carries no alignment
/// guarantee for `EVENT_TRACE_PROPERTIES`, while `usize` is at least as aligned as the
/// struct this platform needs. Capacity is reported to the kernel as the real byte size of
/// the allocation, and `wide` outlives the call (the PCWSTR borrows it).
pub fn session_loss_counters(name: &str) -> Result<LossCounters, u32> {
    unsafe {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let (capacity, ps, nb) = scratch_layout(name);
        debug_assert_eq!(wide.len() * 2, nb, "geometry must match the encoded name");
        let mut backing = vec![0usize; capacity / std::mem::size_of::<usize>()];
        debug_assert_eq!(
            std::mem::size_of_val(backing.as_slice()),
            capacity,
            "reported capacity must be the real allocation size"
        );
        debug_assert_eq!(
            backing.as_ptr() as usize % std::mem::align_of::<EVENT_TRACE_PROPERTIES>(),
            0,
            "usize-aligned storage must satisfy the struct's alignment"
        );
        let raw = backing.as_mut_ptr() as *mut u8;
        let props = raw as *mut EVENT_TRACE_PROPERTIES;
        (*props).Wnode.BufferSize = capacity as u32;
        (*props).LoggerNameOffset = ps as u32;
        std::ptr::copy_nonoverlapping(wide.as_ptr() as *const u8, raw.add(ps), nb);
        let err = ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(wide.as_ptr()),
            props,
            EVENT_TRACE_CONTROL_QUERY,
        );
        if err != WIN32_ERROR(0) {
            return Err(err.0);
        }
        Ok(LossCounters {
            events_lost: (*props).EventsLost as u64,
            log_buffers_lost: (*props).LogBuffersLost as u64,
            real_time_buffers_lost: (*props).RealTimeBuffersLost as u64,
            buffers: (*props).NumberOfBuffers,
        })
    }
}

/// The two cumulative counters that `cum=` does not cover.
///
/// `cum=` has always meant *this session's cumulative `EventsLost`*, and its name and
/// position stay unchanged so existing log parsing keeps working. These two fields make
/// the other cumulative counters of the same successful QUERY equally visible, so a
/// change that happened inside a throttled stretch can still be detected as a net
/// difference between two printed endpoints.
///
/// Only ever called with a value that came out of a successful query: a failed query
/// must not print any counter snapshot.
fn cum_snapshot(c: &LossCounters) -> String {
    format!(
        " cum_log_buffers_lost={} cum_realtime_buffers_lost={}",
        c.log_buffers_lost, c.real_time_buffers_lost
    )
}

pub struct LossTracker {
    interval_ms: u64,
    /// Hard cap on retained buckets: `WINDOW_MS / (interval/2)`, i.e. sized for the fastest
    /// cadence we still trust. With the half-open window a bucket may only be pushed when
    /// `dt >= interval/2`, so a full 30 minutes of the *quickest* trusted sampling fills
    /// exactly this many slots: the cap and the time bound agree at 120, and age - not the
    /// cap - is what retires the boundary bucket. The cap is therefore a memory guard that
    /// normal trusted sampling cannot reach, never the routine eviction path.
    max_buckets: usize,
    quiet_log_ms: u64,
    nonzero_log_ms: u64,
    error_log_ms: u64,
    prev: Option<(u64, LossCounters)>,
    /// Observation is broken: the next successful sample must only re-establish the
    /// baseline. It must NOT produce a window bucket, because the time between the last
    /// good sample and that one was not sampled.
    resync_pending: bool,
    last_quiet: u64,
    last_nonzero: u64,
    last_error: u64,
    /// (sampled_at_ms, events_lost_delta) - time stamped so expiry is real.
    window: VecDeque<(u64, u64)>,
    dropped: u64,
    expired: u64,
}

impl LossTracker {
    pub fn new(interval_ms: u64) -> Self {
        // A trusted gap is at least interval/2, so the fastest admissible cadence sets the
        // bucket cap for a WINDOW_MS span. Never zero, whatever interval_ms is passed in.
        let fastest = (interval_ms / TRUST_MIN_FACTOR).max(1);
        let max_buckets = (WINDOW_MS / fastest).max(1) as usize;
        LossTracker {
            interval_ms,
            max_buckets,
            // "no losses" is also a claim that needs evidence, but it must not be logged
            // every 30 seconds. Keep it well under the invalid-interval threshold below,
            // otherwise a normal quiet stretch would be reported as an unobserved gap.
            quiet_log_ms: 5 * 60 * 1000,
            nonzero_log_ms: 5 * 60 * 1000,
            error_log_ms: 10 * 60 * 1000,
            prev: None,
            resync_pending: false,
            last_quiet: 0,
            last_nonzero: 0,
            last_error: 0,
            window: VecDeque::new(),
            dropped: 0,
            expired: 0,
        }
    }

    pub fn dropped_samples(&self) -> u64 {
        self.dropped
    }

    pub fn expired_buckets(&self) -> u64 {
        self.expired
    }

    pub fn window_len(&self) -> usize {
        self.window.len()
    }

    pub fn window_sum(&self) -> u64 {
        self.window.iter().map(|(_, d)| *d).sum()
    }

    /// Sample time of the oldest bucket still held. Used to show that the window is bounded
    /// by *time*: `now - window_start_ms()` must never exceed `WINDOW_MS`.
    pub fn window_start_ms(&self) -> Option<u64> {
        self.window.front().map(|(at, _)| *at)
    }

    /// Retention cap in buckets, derived from the fastest cadence we still trust.
    pub fn max_buckets(&self) -> usize {
        self.max_buckets
    }

    /// Drop everything the half-open window `(now_ms - WINDOW_MS, now_ms]` excludes, i.e. a
    /// bucket at exactly the 30-minute boundary has aged out. Called on *every* observation,
    /// before any branch decides what to do with the current sample - otherwise a stale
    /// bucket could survive through failure or resync paths and be attributed to "last 30 min".
    fn expire(&mut self, now_ms: u64) {
        let oldest = now_ms.saturating_sub(WINDOW_MS);
        while let Some(&(at, _)) = self.window.front() {
            if at <= oldest {
                self.window.pop_front();
                self.expired += 1;
            } else {
                break;
            }
        }
        self.trim_to_capacity();
    }

    /// Memory bound only. Time expiry is what makes the window a 30-minute window; this only
    /// exists so the deque cannot grow without limit if the semantics above ever change. A
    /// bucket removed here is counted as `dropped`, which is deliberately distinct from
    /// `expired`: the two must never be confused in a log line.
    fn trim_to_capacity(&mut self) {
        while self.window.len() > self.max_buckets {
            self.window.pop_front();
            self.dropped += 1;
        }
    }

    /// `Some(line)` when the caller should log, `None` when it should stay quiet.
    pub fn observe(&mut self, now_ms: u64, sample: Result<LossCounters, u32>) -> Option<String> {
        // Expiry first and unconditionally: no branch - trusted, atypical, failed or
        // re-baselining - may keep a bucket that has already left the 30-minute window.
        self.expire(now_ms);

        let cur = match sample {
            Err(code) => {
                // Observation is broken from here on. Both consequences are unconditional:
                // throttling may hide the message, it may not keep stale buckets alive.
                self.resync_pending = true;
                self.window.clear();
                // The next good sample may only re-establish a baseline; it must not yield
                // a bucket for a span that was never sampled.
                if self.last_error == 0
                    || now_ms.saturating_sub(self.last_error) >= self.error_log_ms
                {
                    self.last_error = now_ms;
                    return Some(format!(
                        "loss unavailable win32={code} (query failed; not treated as zero; window cleared, next sample only re-baselines)"
                    ));
                }
                // Suppressed message, unchanged state: trust is already lost and the
                // window is already empty.
                return None;
            }
            Ok(c) => c,
        };

        let Some((t0, prev)) = self.prev else {
            self.prev = Some((now_ms, cur));
            self.resync_pending = false;
            return Some(format!(
                "loss init cum={} buffers={} (first sample, no interval yet){}",
                cur.events_lost,
                cur.buffers,
                cum_snapshot(&cur)
            ));
        };

        if self.resync_pending {
            self.prev = Some((now_ms, cur));
            self.resync_pending = false;
            return Some(format!(
                "loss resync cum={} buffers={} (baseline re-established; the span since the previous good sample was not sampled and is NOT reported as zero loss){}",
                cur.events_lost, cur.buffers, cum_snapshot(&cur)
            ));
        }

        // A cumulative counter going down is a discontinuity. Whether that is a recreated
        // session or a counter wraparound cannot be told from this API, so we do not guess.
        // This reading is itself valid, so it becomes the baseline immediately - unlike a
        // failed query, which yields no reading at all and therefore needs `resync_pending`.
        if cur.events_lost < prev.events_lost
            || cur.log_buffers_lost < prev.log_buffers_lost
            || cur.real_time_buffers_lost < prev.real_time_buffers_lost
        {
            self.prev = Some((now_ms, cur));
            self.window.clear();
            return Some(format!(
                "loss discontinuity cum={} buffers={} (a cumulative counter went down; cause not determined: could be session recreation or counter wraparound; no negative delta, window cleared){}",
                cur.events_lost, cur.buffers, cum_snapshot(&cur)
            ));
        }

        let dt = now_ms.saturating_sub(t0);
        if dt == 0 || dt > 30 * self.interval_ms {
            self.prev = Some((now_ms, cur));
            self.window.clear();
            return Some(format!(
                "loss cum={} interval=invalid gap={dt}ms (unobserved stretch; window cleared and this sample becomes the new baseline; NOT evidence of zero loss){}",
                cur.events_lost, cum_snapshot(&cur)
            ));
        }

        let d_ev = cur.events_lost - prev.events_lost;
        let d_log = cur.log_buffers_lost - prev.log_buffers_lost;
        let d_rt = cur.real_time_buffers_lost - prev.real_time_buffers_lost;
        self.prev = Some((now_ms, cur));

        // A stretched gap is still real data over a real span, but it is not a sampling
        // interval, so it is reported without becoming a window bucket.
        let trusted =
            dt >= self.interval_ms / TRUST_MIN_FACTOR && dt <= self.interval_ms * TRUST_MAX_FACTOR;
        if !trusted {
            return Some(format!(
                "loss +{d_ev}/+{d_log}/+{d_rt} over {dt}ms cum={} buffers={} {WINDOW_LABEL}= {} (atypical gap: real increment, deliberately not bucketed){}",
                cur.events_lost, cur.buffers, self.window_sum(), cum_snapshot(&cur)
            ));
        }
        // A bucket is (when it was sampled, what it measured), so expiry can be by age and
        // not by count.
        self.window.push_back((now_ms, d_ev));
        self.trim_to_capacity();

        if d_ev == 0 && d_log == 0 && d_rt == 0 {
            if self.last_quiet == 0 || now_ms.saturating_sub(self.last_quiet) >= self.quiet_log_ms {
                self.last_quiet = now_ms;
                return Some(format!(
                    "loss quiet cum={} (+0/+0/+0 over {dt}ms) buffers={} {WINDOW_LABEL}= {}{}",
                    cur.events_lost,
                    cur.buffers,
                    self.window_sum(),
                    cum_snapshot(&cur)
                ));
            }
            return None;
        }

        if self.last_nonzero == 0 || now_ms.saturating_sub(self.last_nonzero) >= self.nonzero_log_ms
        {
            self.last_nonzero = now_ms;
            return Some(format!(
                "loss +{d_ev}/+{d_log}/+{d_rt} over {dt}ms cum={} buffers={} {WINDOW_LABEL}= {} dropped_samples={}{}",
                cur.events_lost,
                cur.buffers,
                self.window_sum(),
                self.dropped,
                cum_snapshot(&cur)
            ));
        }
        // Suppressed by throttling, but the window still recorded it.
        None
    }
}

#[cfg(test)]
mod loss_tests {
    use super::*;

    fn c(ev: u64, log: u64, rt: u64) -> LossCounters {
        LossCounters {
            events_lost: ev,
            log_buffers_lost: log,
            real_time_buffers_lost: rt,
            buffers: 32,
        }
    }
    fn ok(x: LossCounters) -> Result<LossCounters, u32> {
        Ok(x)
    }
    fn err(code: u32) -> Result<LossCounters, u32> {
        Err(code)
    }
    const S: u64 = 30_000;

    /// Advance `n` trusted samples `step` ms apart, each adding one event loss, and return
    /// the new cumulative value.
    ///
    /// Every "the window was cleared" assertion in this module is preceded by this call:
    /// asserting that an empty window became empty proves nothing.
    fn fill(t: &mut LossTracker, from_ms: u64, n: u64, step: u64, mut cum: u64) -> u64 {
        for i in 1..=n {
            cum += 1;
            t.last_nonzero = 0; // defeat the log throttle; these assertions are about state
            t.observe(from_ms + i * step, ok(c(cum, 0, 0)));
        }
        cum
    }

    #[test]
    fn first_sample_has_no_deltas() {
        let mut t = LossTracker::new(S);
        let line = t.observe(1000, ok(c(5034, 0, 0))).unwrap();
        assert!(line.contains("loss init"), "{line}");
        assert!(line.contains("5034"), "{line}");
        assert!(
            !line.contains('+'),
            "first sample must not claim a delta: {line}"
        );
    }

    #[test]
    fn zero_deltas_are_reported_as_quiet_on_a_trusted_cadence_only() {
        let mut t = LossTracker::new(S);
        t.observe(0, ok(c(10, 0, 0)));
        assert!(t
            .observe(S, ok(c(10, 0, 0)))
            .unwrap()
            .contains("loss quiet"));
        // trusted 30s steps stay silent until the 5-minute quiet interval elapses
        for i in 2..=10u64 {
            assert!(
                t.observe(i * S, ok(c(10, 0, 0))).is_none(),
                "quiet must be throttled at sample {i}"
            );
        }
        let l = t.observe(11 * S, ok(c(10, 0, 0))).unwrap();
        assert!(l.contains("loss quiet"), "{l}");
        assert!(
            l.contains("over 30000ms"),
            "quiet speaks about one trusted interval: {l}"
        );
        // a stretched gap is never presented as a normal quiet sample
        let a = t.observe(21 * S, ok(c(10, 0, 0))).unwrap();
        assert!(a.contains("atypical gap"), "{a}");
    }

    #[test]
    fn growing_counters_are_reported_immediately_then_throttled() {
        let mut t = LossTracker::new(S);
        t.observe(0, ok(c(0, 0, 0)));
        let l = t.observe(S, ok(c(7, 0, 2))).unwrap();
        assert!(l.contains("loss +7/+0/+2"), "{l}");
        assert!(l.contains("cum=7"), "{l}");
        assert!(
            t.observe(2 * S, ok(c(9, 0, 2))).is_none(),
            "5 minute throttle"
        );
    }

    #[test]
    fn counter_decrease_is_a_discontinuity_not_a_claimed_restart() {
        let mut t = LossTracker::new(S);
        t.observe(0, ok(c(500, 0, 0)));
        // a window that really holds buckets, so the clearing below is not a no-op
        fill(&mut t, 0, 4, S, 500);
        assert_eq!(t.window.len(), 4, "precondition: the window is populated");
        let l = t.observe(5 * S, ok(c(3, 0, 0))).unwrap();
        assert!(l.contains("loss discontinuity"), "{l}");
        assert!(l.contains("cause not determined"), "{l}");
        assert!(
            !l.to_lowercase().contains("session recreated"),
            "must not guess the cause: {l}"
        );
        assert!(!l.contains('-'), "no negative numbers: {l}");
        assert_eq!(
            t.window.len(),
            0,
            "window must be cleared on a discontinuity"
        );
        // A discontinuity is different from a failed query: this sample *is* a reading, so it
        // becomes the baseline in place and no re-baselining step is owed to the next sample.
        assert!(
            !t.resync_pending,
            "a valid reading re-baselines; only a missing one owes a resync"
        );
        // the sample after a discontinuity is a normal measurement again
        t.last_nonzero = 0; // the window, not the throttle, is what this assertion is about
        let n = t.observe(6 * S, ok(c(4, 0, 0))).unwrap();
        assert!(n.contains("loss +1/+0/+0"), "{n}");
        assert_eq!(t.window.len(), 1, "and it is bucketed normally");
    }

    #[test]
    fn untrustworthy_interval_is_never_reported_as_zero_loss() {
        let mut t = LossTracker::new(S);
        t.observe(0, ok(c(5, 0, 0)));
        // machine slept for an hour: no deltas, and the text says the stretch is unobserved
        let l = t.observe(3_600_000, ok(c(5, 0, 0))).unwrap();
        assert!(l.contains("interval=invalid"), "{l}");
        assert!(
            l.to_lowercase().contains("not evidence of zero loss"),
            "{l}"
        );
        assert!(!l.contains("+0/"), "no fake delta: {l}");
    }

    #[test]
    fn failed_query_is_visible_and_never_feeds_the_window() {
        let mut t = LossTracker::new(S);
        t.observe(0, ok(c(11, 0, 0)));
        // Precondition the review asked for: the window must already contain data, otherwise
        // "a failed sample clears the window" is an assertion about an empty deque.
        fill(&mut t, 0, 4, S, 11);
        assert_eq!(t.window.len(), 4, "precondition: a populated window");
        let l = t.observe(5 * S, err(5)).unwrap();
        assert!(l.contains("loss unavailable win32=5"), "{l}");
        assert!(l.contains("not treated as zero"), "{l}");
        assert_eq!(
            t.window.len(),
            0,
            "a failed sample clears a window that held data"
        );
        assert!(t.resync_pending, "a failed sample marks observation broken");
        assert!(
            t.observe(6 * S, err(5)).is_none(),
            "error must be throttled too"
        );
        assert!(
            t.resync_pending,
            "throttled error must still mark observation broken"
        );
        // The first good sample after a break only re-baselines: the unsampled span must
        // not be smuggled in as one big 30s bucket.
        let r = t.observe(7 * S, ok(c(71, 0, 0))).unwrap();
        assert!(r.contains("loss resync"), "{r}");
        assert!(r.contains("cum=71"), "{r}");
        assert!(!r.contains('+'), "no delta across an unsampled span: {r}");
        assert_eq!(t.window.len(), 0, "resync must not create a bucket");
        // only afterwards do normal buckets resume
        t.last_nonzero = 0;
        let n = t.observe(8 * S, ok(c(73, 0, 0))).unwrap();
        assert!(n.contains("loss +2/+0/+0"), "{n}");
        assert_eq!(t.window.len(), 1);
    }

    /// The exact sequence the review named: after an error has already been logged once, a
    /// second failure arriving inside the 10-minute throttle must still drop the window and
    /// still mark observation broken. Throttling is allowed to hide a message, never to
    /// preserve state that the design says was destroyed.
    #[test]
    fn a_throttled_query_failure_still_clears_a_populated_window() {
        let mut t = LossTracker::new(S);
        t.observe(0, ok(c(0, 0, 0)));
        // 1) ordinary sampling produces buckets
        fill(&mut t, 0, 5, S, 0);
        assert_eq!(t.window.len(), 5, "precondition");
        // 2) a failure that IS logged, and clears
        let f1 = t.observe(6 * S, err(5)).unwrap();
        assert!(f1.contains("loss unavailable win32=5"), "{f1}");
        assert_eq!(t.window.len(), 0);
        // 3) recovery only re-baselines
        let r1 = t.observe(7 * S, ok(c(100, 0, 0))).unwrap();
        assert!(r1.contains("loss resync"), "{r1}");
        assert_eq!(t.window.len(), 0);
        // 4) sampling repopulates the window
        fill(&mut t, 7 * S, 5, S, 100);
        assert_eq!(t.window.len(), 5, "precondition before the second failure");
        // 5) a second failure while the message is still throttled: 13S-6S = 3.5 min < 10 min
        assert!(
            13 * S - 6 * S < t.error_log_ms,
            "this step must sit inside the throttle"
        );
        let second = t.observe(13 * S, err(22));
        assert!(second.is_none(), "the message is throttled");
        assert_eq!(
            t.window.len(),
            0,
            "throttling may hide a message, never a reset"
        );
        assert!(
            t.resync_pending,
            "the second failure still breaks observation"
        );
        // 6) the first good sample only re-baselines: no bucket, no delta
        let r2 = t.observe(14 * S, ok(c(200, 0, 0))).unwrap();
        assert!(r2.contains("loss resync"), "{r2}");
        assert!(
            !r2.contains('+'),
            "no delta across the unsampled span: {r2}"
        );
        assert_eq!(
            t.window.len(),
            0,
            "resync must not resurrect pre-break data"
        );
        // 7) only a later trusted sample counts normally again
        t.last_nonzero = 0;
        let n = t.observe(15 * S, ok(c(207, 0, 0))).unwrap();
        assert!(n.contains("loss +7/+0/+0"), "{n}");
        assert_eq!(t.window.len(), 1);
    }

    /// The window is bounded by *age*, and eviction is counted, never silently kept.
    /// At the nominal 30s cadence a 30-minute span happens to hold about 60 buckets - but
    /// that is a consequence of the arithmetic, not the rule.
    #[test]
    fn window_is_bounded_and_overflow_is_counted_not_stored() {
        let mut t = LossTracker::new(S);
        t.observe(0, ok(c(0, 0, 0)));
        // 70 trusted samples at exactly 30s = 35 minutes of data
        let cum = fill(&mut t, 0, 70, S, 0);
        assert_eq!(cum, 70);
        let now = 70 * S;
        assert_eq!(
            t.window_start_ms(),
            Some(11 * S),
            "the bucket at exactly now-30min has aged out"
        );
        assert!(
            now - t.window_start_ms().unwrap() < WINDOW_MS,
            "the half-open window holds nothing at or before now-30min"
        );
        assert_eq!(
            t.window.len(),
            60,
            "35 minutes of samples must not all stay in a 30-minute window"
        );
        assert_eq!(
            t.expired_buckets(),
            10,
            "the ten oldest left on their own age"
        );
        assert_eq!(
            t.dropped_samples(),
            0,
            "age retired them, the capacity cap never fired"
        );
        assert_eq!(
            t.window_sum(),
            60,
            "one loss per retained bucket; the ten evicted ones are gone"
        );
    }

    /// A trusted gap is a *band*, up to 2x the nominal interval. Sixty samples that are all
    /// 60s apart are therefore all legitimate - and together span an hour. Counting buckets
    /// would have called that "the last 30 minutes"; expiring by age does not.
    #[test]
    fn trusted_but_stretched_samples_cannot_widen_the_window_to_an_hour() {
        let mut t = LossTracker::new(S);
        t.observe(0, ok(c(0, 0, 0)));
        for i in 1..=60u64 {
            t.last_nonzero = 0;
            t.observe(i * 2 * S, ok(c(i, 0, 0))); // dt = 60s: the widest still-trusted gap
        }
        let now = 60 * 2 * S; // one hour after the first interval
        assert_eq!(now, 3_600_000, "the samples really do cover 60 minutes");
        assert!(
            now - t.window_start_ms().unwrap() < WINDOW_MS,
            "nothing at or before now-30min survives the half-open window"
        );
        assert_eq!(
            t.window.len(),
            30,
            "60 trusted buckets are only 30 in a 30-minute window"
        );
        assert_eq!(
            t.expired_buckets(),
            30,
            "age removed them, not the bucket cap"
        );
        assert_eq!(
            t.dropped_samples(),
            0,
            "the cap must not pre-empt a boundary expiry"
        );
        assert_eq!(
            t.window_sum(),
            30,
            "the sum covers the window, not the hour"
        );
    }

    /// At the *fastest* cadence we still trust (interval/2 = 15s), 30 minutes fills exactly
    /// `max_buckets` slots. The cap and the time bound coincide, so the boundary bucket is
    /// retired by age and counted in `expired_buckets` - never taken early by the cap and
    /// mislabelled as `dropped_samples`.
    #[test]
    fn capacity_is_sized_for_the_fastest_trusted_cadence_and_sum_follows_the_window() {
        let mut t = LossTracker::new(S);
        assert_eq!(
            t.max_buckets(),
            (WINDOW_MS / (S / TRUST_MIN_FACTOR)) as usize,
            "120 at a 30s interval"
        );
        assert_ne!(
            t.max_buckets(),
            60,
            "60 would assume every sample is exactly 30s apart"
        );
        let fast = S / TRUST_MIN_FACTOR;
        t.observe(0, ok(c(0, 0, 0)));
        // bucket value == step index, so an eviction is visible in the sum
        let mut cum = 0u64;
        for i in 1..=130u64 {
            t.last_nonzero = 0;
            cum += i;
            t.observe(i * fast, ok(c(cum, 0, 0)));
        }
        let now = 130 * fast; // 32.5 minutes
        assert_eq!(
            t.window.len(),
            t.max_buckets(),
            "a full window at the fastest trusted cadence"
        );
        assert_eq!(
            t.expired_buckets(),
            10,
            "steps 121..130 each aged one boundary bucket out"
        );
        assert_eq!(
            t.dropped_samples(),
            0,
            "time retired them; the cap never fired"
        );
        assert_eq!(t.window_start_ms(), Some(11 * fast));
        assert!(now - t.window_start_ms().unwrap() < WINDOW_MS);
        let expected: u64 = (11..=130).sum();
        assert_eq!(
            t.window_sum(),
            expected,
            "evicted buckets must not be summed"
        );
        assert!(
            t.window_sum() < cum,
            "window total {} differs from cumulative {cum}",
            t.window_sum()
        );
    }

    /// A bucket may only be pushed on a trusted gap (`dt >= interval/2`), so normal sampling
    /// can never fill more than `max_buckets` slots in one window: the cap is a guard against
    /// the deque growing without limit, not the routine eviction path. Forced here directly,
    /// because no admissible observation sequence can reach it.
    #[test]
    fn the_capacity_cap_is_a_memory_guard_and_counts_drops_separately_from_expiry() {
        let mut t = LossTracker::new(S);
        assert_eq!(t.max_buckets(), 120);
        // impossible via observe(): every bucket would need dt >= 15s
        for i in 0..=t.max_buckets() as u64 {
            t.window.push_back((i, 1));
        }
        assert_eq!(
            t.window.len(),
            t.max_buckets() + 1,
            "deliberately over the cap"
        );
        t.trim_to_capacity();
        assert_eq!(
            t.window.len(),
            t.max_buckets(),
            "the guard bounds the deque"
        );
        assert_eq!(t.dropped_samples(), 1, "counted as a capacity drop");
        assert_eq!(t.expired_buckets(), 0, "and not disguised as a time expiry");
        assert_eq!(
            t.window_sum(),
            t.max_buckets() as u64,
            "the evicted bucket left the sum"
        );
    }

    /// No branch - atypical gap, stall, failure or discontinuity - may keep a bucket that
    /// has left the half-open window, nor be "proven" to clear a window that expiry had
    /// already emptied.
    #[test]
    fn expired_data_survives_neither_a_gap_a_failure_nor_a_resync() {
        let fresh = |tr: &LossTracker, now: u64| {
            if let Some(start) = tr.window_start_ms() {
                assert!(
                    now.saturating_sub(start) < WINDOW_MS,
                    "bucket at {start} is at/beyond the edge at {now}"
                );
            }
        };
        let mut t = LossTracker::new(S);
        t.observe(0, ok(c(0, 0, 0)));
        fill(&mut t, 0, 5, S, 0);
        assert_eq!(t.window.len(), 5);
        fresh(&t, 5 * S);

        // atypical gap: reported, not bucketed, and it neither adds nor evicts
        let l = t.observe(8 * S, ok(c(60, 0, 0))).unwrap();
        assert!(l.contains("atypical gap"), "{l}");
        assert_eq!(
            t.window.len(),
            5,
            "an atypical gap leaves the window as it was"
        );
        fresh(&t, 8 * S);

        // stall: nothing has aged out yet, so the clear below destroys live data
        assert!(
            t.window_start_ms().unwrap() + WINDOW_MS > 41 * S,
            "precondition: still inside the window"
        );
        let l = t.observe(41 * S, ok(c(70, 0, 0))).unwrap();
        assert!(l.contains("interval=invalid"), "{l}");
        assert_eq!(t.window.len(), 0, "the stall cleared live buckets");
        fresh(&t, 41 * S);

        // refill, then fail a quarter of an hour later - again with live data to destroy
        fill(&mut t, 41 * S, 4, S, 70);
        assert_eq!(t.window.len(), 4, "precondition before the failure");
        let when = 45 * S + 10 * 60 * 1000;
        assert!(
            t.window_start_ms().unwrap() + WINDOW_MS > when,
            "precondition: not expired at the failure"
        );
        let l = t.observe(when, err(4)).unwrap();
        assert!(l.contains("loss unavailable"), "{l}");
        assert_eq!(
            t.window.len(),
            0,
            "the failure cleared live data, not already-expired data"
        );
        fresh(&t, when);

        // recovery re-baselines, refills, then a discontinuity clears again
        assert!(t
            .observe(when + S, ok(c(200, 0, 0)))
            .unwrap()
            .contains("loss resync"));
        fill(&mut t, when + S, 4, S, 200);
        assert_eq!(t.window.len(), 4, "precondition");
        let l = t.observe(when + 6 * S, ok(c(5, 0, 0))).unwrap();
        assert!(l.contains("loss discontinuity"), "{l}");
        assert_eq!(
            t.window.len(),
            0,
            "a discontinuity clears a populated window too"
        );
        fresh(&t, when + 6 * S);
    }

    /// An observation that produces no bucket must still age the window, or the
    /// `window30m=` total printed on an atypical gap quietly counts stale data.
    #[test]
    fn an_observation_without_a_bucket_still_expires_the_window() {
        let mut t = LossTracker::new(S);
        t.observe(0, ok(c(0, 0, 0)));
        let cum = fill(&mut t, 0, 70, S, 0); // 35 minutes -> 60 buckets retained
        assert_eq!(t.window.len(), 60, "precondition");
        assert_eq!(t.window_sum(), 60);
        // 3 minutes later: an atypical gap, not an invalid one, so it adds no bucket and
        // only age can shrink the window.
        let l = t.observe(73 * S, ok(c(cum + 1, 0, 0))).unwrap();
        assert!(l.contains("atypical gap"), "{l}");
        assert_eq!(
            t.window.len(),
            57,
            "everything at or before now-30min aged out"
        );
        assert_eq!(
            t.expired_buckets(),
            13,
            "ten during the fill, three more now"
        );
        assert_eq!(t.dropped_samples(), 0, "age, not the cap");
        assert!(
            l.contains("window30m= 57"),
            "the printed total is the fresh one: {l}"
        );
    }

    #[test]
    fn stretched_gap_is_reported_but_never_becomes_a_30s_bucket() {
        let mut t = LossTracker::new(S);
        t.observe(0, ok(c(0, 0, 0)));
        fill(&mut t, 0, 3, S, 0); // real buckets to protect, not an empty window
        assert_eq!(t.window.len(), 3, "precondition");
        // 3 minutes: real data over a real span, but still under the 15-minute invalid
        // threshold, so it must be shown as an increment and kept out of the window.
        let l = t.observe(9 * S, ok(c(50, 0, 0))).unwrap();
        assert!(l.contains("loss +47/+0/+0 over 180000ms"), "{l}");
        assert!(l.contains("atypical gap"), "{l}");
        assert_eq!(
            t.window.len(),
            3,
            "an atypical gap must not enter the window"
        );
        // normal cadence afterwards contributes exactly one bucket
        t.last_nonzero = 0;
        let n = t.observe(10 * S, ok(c(51, 0, 0))).unwrap();
        assert!(n.contains("loss +1/"), "{n}");
        assert_eq!(t.window.len(), 4);
    }

    #[test]
    fn long_stall_clears_the_window_instead_of_inventing_deltas() {
        let mut t = LossTracker::new(S);
        t.observe(0, ok(c(1, 0, 0)));
        fill(&mut t, 0, 6, S, 1); // buckets that the stall must actually destroy
        assert_eq!(t.window.len(), 6, "precondition: a populated window");
        // 16 min > the 15 min threshold, yet young enough that expiry has not touched them
        let l = t.observe(38 * S, ok(c(9, 0, 0))).unwrap();
        assert!(l.contains("interval=invalid"), "{l}");
        assert!(l.contains("cum=9"), "{l}");
        assert!(
            !l.contains("loss +"),
            "no delta may be attributed to an unobserved stretch: {l}"
        );
        assert_eq!(
            t.window.len(),
            0,
            "a stall clears a window that really held buckets"
        );
    }

    /// The three cumulative counters must land in their own field, with no swapped mapping.
    /// Distinct values are chosen so that a swap is detectable rather than plausible.
    #[test]
    fn cumulative_snapshot_fields_are_correctly_assigned() {
        let mut t = LossTracker::new(S);
        let l = t.observe(0, ok(c(7, 11, 13))).unwrap();
        assert!(l.contains("loss init"), "{l}");
        assert!(
            l.contains("cum=7"),
            "EventsLost keeps its historical field: {l}"
        );
        assert!(l.contains("cum_log_buffers_lost=11"), "{l}");
        assert!(l.contains("cum_realtime_buffers_lost=13"), "{l}");
        // a swapped pairing would still print *some* number, so forbid it explicitly
        assert!(
            !l.contains("cum_log_buffers_lost=13"),
            "fields must not be swapped: {l}"
        );
        assert!(
            !l.contains("cum_realtime_buffers_lost=11"),
            "fields must not be swapped: {l}"
        );
    }

    /// Every record produced from a successful read carries all three fields; no branch
    /// may print some and omit the others (init / quiet / atypical / invalid / nonzero /
    /// discontinuity / resync).
    #[test]
    fn every_success_line_carries_the_three_cumulative_fields() {
        let mut lines: Vec<String> = Vec::new();
        let mut t = LossTracker::new(S);
        lines.push(t.observe(0, ok(c(1, 2, 3))).unwrap()); // init
        lines.push(t.observe(S, ok(c(1, 2, 3))).unwrap()); // quiet (all deltas zero)
        lines.push(t.observe(7 * S, ok(c(1, 2, 3))).unwrap()); // atypical gap
        let stall = 7 * S + 20 * 60 * 1000;
        lines.push(t.observe(stall, ok(c(1, 2, 3))).unwrap()); // interval=invalid
        t.last_nonzero = 0;
        lines.push(t.observe(stall + S, ok(c(4, 5, 6))).unwrap()); // non-zero delta
        lines.push(t.observe(stall + 2 * S, ok(c(0, 5, 6))).unwrap()); // discontinuity
        assert!(t
            .observe(stall + 3 * S, err(1))
            .unwrap()
            .contains("unavailable"));
        lines.push(t.observe(stall + 4 * S, ok(c(9, 9, 9))).unwrap()); // resync
        assert_eq!(
            lines.len(),
            7,
            "all seven successful branches must be exercised"
        );
        for l in &lines {
            assert!(
                l.contains("cum=")
                    && l.contains("cum_log_buffers_lost=")
                    && l.contains("cum_realtime_buffers_lost="),
                "missing fields: {l}"
            );
        }
    }

    /// Growth of LogBuffersLost / RealTimeBuffersLost must be printed together with the
    /// cumulative value measured at that very read.
    #[test]
    fn buffer_growth_is_reported_with_its_updated_cumulative_values() {
        let mut t = LossTracker::new(S);
        t.observe(0, ok(c(0, 0, 0)));
        let l = t.observe(S, ok(c(0, 4, 0))).unwrap();
        assert!(l.contains("loss +0/+4/+0 over 30000ms"), "{l}");
        assert!(l.contains("cum=0"), "events_lost really is unchanged: {l}");
        assert!(l.contains("cum_log_buffers_lost=4"), "{l}");
        assert!(l.contains("cum_realtime_buffers_lost=0"), "{l}");
        t.last_nonzero = 0;
        let l2 = t.observe(2 * S, ok(c(0, 4, 9))).unwrap();
        assert!(l2.contains("loss +0/+0/+9 over 30000ms"), "{l2}");
        assert!(
            l2.contains("cum_log_buffers_lost=4"),
            "an unchanged counter keeps its value: {l2}"
        );
        assert!(l2.contains("cum_realtime_buffers_lost=9"), "{l2}");
    }

    /// Throttling suppresses messages, not bookkeeping: the next printed record must
    /// carry the newest cumulative values, and the window must have kept accumulating.
    #[test]
    fn throttled_stretch_shows_up_in_the_next_printed_endpoints() {
        let mut t = LossTracker::new(S);
        t.observe(0, ok(c(0, 0, 0)));
        let first = t.observe(S, ok(c(1, 2, 0))).unwrap();
        assert!(first.contains("loss +1/+2/+0"), "{first}");
        assert!(first.contains("cum_log_buffers_lost=2"), "{first}");
        // nine trusted samples, all silenced by the 5-minute throttle, all still counted
        let mut cum_ev = 1u64;
        let mut cum_log = 2u64;
        for k in 2..=10u64 {
            cum_ev += 1;
            cum_log += 3;
            assert!(
                t.observe(k * S, ok(c(cum_ev, cum_log, 0))).is_none(),
                "sample {k} must be throttled"
            );
        }
        // 11*S is the first moment the throttle allows a print (>= 5 min after S)
        let late = t
            .observe(11 * S, ok(c(cum_ev + 1, cum_log + 3, 0)))
            .unwrap();
        assert!(late.contains(&format!("cum={}", cum_ev + 1)), "{late}");
        assert!(
            late.contains(&format!("cum_log_buffers_lost={}", cum_log + 3)),
            "must report the value read now, not S's snapshot: {late}"
        );
        assert!(
            late.contains("window30m= 11"),
            "the window filled while the log was silent: {late}"
        );
    }

    /// A failed query yields no reading, so it must print neither a fake zero nor a stale
    /// snapshot of counters it did not just observe.
    #[test]
    fn failed_query_prints_no_counter_snapshot() {
        let mut t = LossTracker::new(S);
        t.observe(0, ok(c(3, 5, 7)));
        let l = t.observe(S, err(5)).unwrap();
        assert!(l.contains("loss unavailable win32=5"), "{l}");
        assert!(
            !l.contains("cum="),
            "no counter may be quoted from a failed query: {l}"
        );
        assert!(!l.contains("cum_log_buffers_lost"), "{l}");
        assert!(!l.contains("cum_realtime_buffers_lost"), "{l}");
        assert!(
            t.observe(2 * S, err(5)).is_none(),
            "the throttled repeat prints nothing"
        );
    }

    /// Checks the layout arithmetic *and* an actual allocation of that shape: the type
    /// relation alone would not catch a buffer whose real address or byte size is wrong.
    #[test]
    fn scratch_buffer_geometry_is_consistent() {
        use std::mem::{align_of, size_of, size_of_val};
        let name = "CM400-Activity";
        let (capacity, ps, nb) = scratch_layout(name);
        assert_eq!(ps, size_of::<EVENT_TRACE_PROPERTIES>());
        assert_eq!(
            nb,
            (name.encode_utf16().count() + 1) * 2,
            "name size must include the NUL"
        );
        assert!(
            capacity >= ps + nb + 8,
            "capacity must cover the struct plus the name"
        );
        assert_eq!(
            capacity % size_of::<usize>(),
            0,
            "capacity is a whole number of words"
        );
        assert!(
            align_of::<usize>() >= align_of::<EVENT_TRACE_PROPERTIES>(),
            "usize-backed storage cannot be under-aligned for the struct"
        );
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        assert_eq!(
            *wide.last().unwrap(),
            0,
            "the copied region must be NUL-terminated"
        );
        assert_eq!(
            wide.len() * 2,
            nb,
            "geometry must match what the query copies"
        );
        // the same buffer the query builds, checked as a real allocation rather than on paper
        let mut backing = vec![0usize; capacity / size_of::<usize>()];
        assert_eq!(
            size_of_val(backing.as_slice()),
            capacity,
            "reported capacity is the real byte size"
        );
        let props = backing.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        assert_eq!(
            props as usize % align_of::<EVENT_TRACE_PROPERTIES>(),
            0,
            "this address is aligned"
        );
        assert!(
            capacity >= size_of::<EVENT_TRACE_PROPERTIES>(),
            "the struct fits the storage"
        );
        unsafe {
            (*props).Wnode.BufferSize = capacity as u32;
            assert_eq!(
                (*props).Wnode.BufferSize,
                capacity as u32,
                "the field is writable in place"
            );
        }
        // the trailing name region must survive that write: it starts right after the struct
        //
        // `raw` is a **byte** pointer on purpose, exactly as in `session_loss_counters`.
        // It used to be `backing.as_mut_ptr()` (a `*mut usize`), so `raw.add(ps)` advanced by
        // `ps * size_of::<usize>()` bytes - way past this allocation - and the copy below
        // corrupted the heap. Reading back through the same wrong offset hid it: the
        // assertions stayed self-consistent while the process died intermittently
        // (STATUS_ACCESS_VIOLATION / __fastfail) in ~8% of runs.
        let raw = backing.as_mut_ptr() as *mut u8;
        let name_at = unsafe { raw.add(ps) } as usize;
        assert!(
            ps + nb <= capacity,
            "struct offset + name size must fit the allocation: ps={ps} nb={nb} capacity={capacity}"
        );
        unsafe {
            std::ptr::copy_nonoverlapping(wide.as_ptr() as *const u8, raw.add(ps), nb);
        }
        let copied = unsafe { std::slice::from_raw_parts(name_at as *const u16, wide.len()) };
        assert_eq!(
            copied,
            wide.as_slice(),
            "the name must land at LoggerNameOffset, NUL included"
        );
        // A byte-scaled offset is the whole point: the name must begin exactly `ps` bytes in,
        // not one word-array index in. If someone re-types `raw` as `*mut usize`, this fails.
        assert_eq!(
            name_at - (raw as usize),
            ps,
            "the name offset must be measured in bytes"
        );
        // The struct must still be intact after the trailing copy.
        assert_eq!(
            unsafe { (*props).Wnode.BufferSize },
            capacity as u32,
            "the name copy must not clobber the struct"
        );
    }

    #[test]
    fn only_query_is_ever_requested() {
        // Structural guard for the authorisation boundary: this module must never grow a
        // STOP/UPDATE/SET call, a session creation or a second consumer. Checked on the
        // non-test part only, otherwise this very test's literals trip the assertion.
        let src = include_str!("etw_loss.rs");
        let code = src.split("#[cfg(test)]").next().unwrap_or(src);
        assert!(code.contains("EVENT_TRACE_CONTROL_QUERY"));
        assert!(
            !code.contains("EVENT_TRACE_CONTROL_STOP"),
            "sampling must never stop a session"
        );
        assert!(
            !code.contains("EVENT_TRACE_CONTROL_UPDATE"),
            "sampling must never reconfigure a session"
        );
        assert!(
            !code.contains("EVENT_TRACE_CONTROL_FLUSH"),
            "sampling must not force a flush"
        );
        assert!(
            !code.contains("StartTraceW"),
            "loss sampling must never create a session"
        );
        assert!(
            !code.contains("OpenTraceW"),
            "loss sampling must never add a consumer"
        );
        assert!(
            !code.contains("CloseTrace"),
            "loss sampling must not tear anything down"
        );
    }
}
