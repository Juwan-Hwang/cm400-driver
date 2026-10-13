//! Shared CM400 runtime: wires Activity + Motor + Policy + persistence into
//! the platform-agnostic `cm400_core::Engine`. BOTH the console host (2-C1)
//! and the Windows service host (2-C2) call `run_runtime`; hosts own only
//! lifecycle. Core never learns about ETW/WinUSB/Windows.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cm400_core::{ActivitySource, Clock, Engine, Store, Transport};
use cm400_persistence::FileStore;
use cm400_policy::CM400Activity;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, WIN32_ERROR};
use windows::Win32::System::Threading::CreateMutexW;

use crate::config::{BackendChoice, Config};
use crate::etw_loss::{session_loss_counters, LossTracker};
use crate::etw_source::WindowsFrameServerEtwSource;
use crate::kernel_lifecycle::{KernelLifecycle, Loss};
use crate::log;
use crate::proc_lifecycle::Ledger;
use crate::report_link::{Link, Report};
use crate::sam_source::SensorActivitySource;
use crate::sam_view::{
    backend_choice, ActivityBackend, Arbiter, Evidence, PidEntry, ProcInstance, Suppression,
};
use crate::MotorChannel;

/// WIN32: the named object already existed, i.e. somebody else is already us.
const ERROR_ALREADY_EXISTS: u32 = 183;

/// SCM service name, shared by the product host and the console host's guard.
pub const SERVICE_NAME: &str = "CM400Driver";

/// Is the installed service currently up (or coming up / going down)?
///
/// The console host asks this before starting, because it cannot rely on the
/// Global mutex alone: a non-privileged token may fail to create it (measured),
/// and two engines driving one lens is exactly the fault we are guarding against.
/// The SCM, unlike the mutex, always knows who is running.
pub fn service_is_live() -> bool {
    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let Ok(manager) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
    else {
        return false;
    };
    let Ok(service) = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) else {
        return false; // not installed -> nothing to collide with
    };
    matches!(service.query_status(), Ok(status) if status.current_state != ServiceState::Stopped)
}

/// Which host is running. This decides how much exclusivity we are allowed to
/// assume, and the two answers are not interchangeable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Dev host: best-effort mutex, uniquely named ETW session, NEVER takes over
    /// the product logger - so it can run beside the service without stealing it.
    Console,
    /// Product host: machine-wide mutex REQUIRED, fixed-name session + takeover.
    /// Takeover is only safe while that mutex is held, because an ETW session name
    /// does not identify its owner. Measured the hard way: with a session-local
    /// fallback, a second instance stopped the live service's logger.
    Service,
}

/// One driver instance per machine.
///
/// A named mutex is released by the kernel even when the process is killed, which
/// is exactly what makes stale-session takeover safe: only the mutex winner may
/// reclaim a real-time logger it did not create. Dying uncleanly leaks the logger
/// but never the mutex, so the next start wins the lock and cleans up.
pub struct Singleton(HANDLE);

impl Singleton {
    fn acquire(role: Role) -> Result<Singleton, String> {
        // `Global\` needs SeCreateGlobalPrivilege (services have it; a plain user
        // token may not). Only the console host may settle for the session-local
        // namespace, and only because it never touches the product session name.
        let mut names = vec!["Global\\CM400Driver"];
        if matches!(role, Role::Console) {
            names.push("Local\\CM400Driver");
        }
        let mut last_err = String::new();
        for ns in names {
            let wide: Vec<u16> = ns.encode_utf16().chain(std::iter::once(0)).collect();
            match unsafe { CreateMutexW(None, false, PCWSTR(wide.as_ptr())) } {
                Ok(handle) => {
                    if unsafe { GetLastError() } == WIN32_ERROR(ERROR_ALREADY_EXISTS) {
                        unsafe {
                            let _ = CloseHandle(handle);
                        }
                        return Err(format!("another CM400 instance already holds {ns}"));
                    }
                    log(&format!("singleton acquired via {ns}"));
                    return Ok(Singleton(handle));
                }
                Err(e) => last_err = format!("{ns}: {e}"),
            }
        }
        Err(format!("cannot get instance exclusivity ({last_err})"))
    }
}

impl Drop for Singleton {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

pub struct SysClock;
impl Clock for SysClock {
    fn now_ms(&mut self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

/// Runtime-side view of the motor: every command's outcome goes to the log.
/// Observability is a runtime concern; the channel underneath owns no device
/// handle between calls (see `cm400_windows::MotorChannel`).
struct LoggedTransport {
    ch: MotorChannel,
}

impl Transport for LoggedTransport {
    fn get(&mut self) -> Result<u8, ()> {
        self.ch.get().map_err(|_| ())
    }
    fn set(&mut self, value: u8) -> Result<(), ()> {
        let r = self.ch.set(value);
        // The route is logged with every command on purpose: "the lens moved" is not
        // evidence about which interface carried the request, and on this rig both the
        // production GUID and the Zadig fallback resolve to the same hardware.
        let route = match self.ch.last_route() {
            Some((path, via)) => format!(" [via {via} {path}]"),
            None => " [via <unknown>]".to_string(),
        };
        log(&format!(
            "motor SET({}) -> {}{}{}",
            value,
            r.is_ok(),
            match &r {
                Err(e) => format!(" ({e:?})"),
                Ok(()) => String::new(),
            },
            route
        ));
        r.map_err(|_| ())
    }
}

/// Report motor reachability at startup, then release the interface again.
///
/// The engine only touches the device on a non-Hold decision, so without this the
/// log could not answer the acceptance question "can this service account reach
/// MI_02?" - and the answer must not be obtained by sitting on an exclusive DFU
/// interface for the lifetime of the service.
fn probe_motor(transport: &mut LoggedTransport) {
    if !MotorChannel::device_present() {
        log("motor interface: MI_02 not enumerable (unplugged, or WinUSB not bound?)");
        return;
    }
    match transport.ch.probe() {
        Ok(_) => log("motor interface: present, reachable (GET ok; handle released again)"),
        Err(e) => log(&format!(
            "motor interface: present but access FAILED {e:?} (owned by another opener, or account lacks access)"
        )),
    }
}

/// Loss sampling cadence: the loop ticks every 500ms, so 60 ticks is the 30s interval
/// the design asks for. It reuses the existing tick - no extra thread, no extra sleep.
const LOSS_SAMPLE_TICKS: u64 = 60;
const LOSS_SAMPLE_INTERVAL_MS: u64 = 30_000;

/// The activity side of the runtime: the ETW source, plus the R2 arbiter when a backend
/// asks for one.
///
/// The shipped default is [`ActivityBackend::HeartbeatOnly`], which makes this a thin pass-
/// through: the policy sees exactly what it sees today. Flipping the backend is the reviewer's
/// deployment decision, not something an evidence-gathering round does on its own.
pub struct ActivityPipeline {
    etw: WindowsFrameServerEtwSource,
    backend: ActivityBackend,
    /// `None` whenever no arbiter could be built (including a failed link discovery).
    arbiter: Option<Arbiter>,
    sam: Option<SensorActivitySource>,
    /// Heartbeats seen at the last poll, used to turn "the counter moved" into one evidence.
    last_cm400_beats: u64,
    /// Last known count of explicit SAM backend failures, so each new one is logged once.
    last_sam_faults: u64,
    /// Process-lifetime collector (shadow diagnostics only; never an input to a decision).
    lifecycle: Option<KernelLifecycle>,
    ledger: Ledger,
    /// The loss counters seen at the previous check, to notice movement rather than re-read it.
    last_loss: Option<Loss>,
    /// Collector health across beats, so ledger trust is recovered from progress and not from the
    /// absence of new complaints.
    collector_watch: CollectorWatch,
    /// Whether the down-grace waiver is currently announced, so each episode is logged once.
    grace_waived_logged: bool,
    /// Episodes in which a verified stop let the engine retract without waiting out the grace.
    grace_waivers: u64,
}

/// One reduced view of what the lifecycle collector says about itself.
///
/// Deliberately cumulative rather than boolean-flavoured, because that is what the collector keeps:
/// `decode_broken` includes `tally.failed_any()`, and a cumulative counter that has ever been non-zero
/// never returns to false. A trust decision built on "is the flag false again" can then never
/// recover, which is the failure this type exists to avoid: the honest question is whether failures
/// are still being added while successful decodes keep advancing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CollectorSample {
    pub consumer_alive: bool,
    pub queue_lost: bool,
    /// cumulative decode failures of every kind
    pub failures: u64,
    /// cumulative events decoded into a usable start or stop
    pub decoded: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectorTrust {
    /// healthy, or already trusted: nothing to change
    Arm,
    /// stop trusting ledger attributions, with the sub-cause named
    Break(&'static str),
    /// broken, still proving nothing new
    Hold,
    /// deltas show the stream is being decoded again; re-trust from a new baseline
    Recover,
}

/// Tracks collector health across beats so that recovery is a claim about progress, not about
/// silence.
#[derive(Debug, Default)]
pub struct CollectorWatch {
    last: Option<CollectorSample>,
    clean: u8,
    reason: Option<&'static str>,
}

impl CollectorWatch {
    /// Three consecutive progressing samples (about a minute at the current beat spacing). One sample
    /// cannot separate "quiet because broken" from "quiet because nothing is happening"; three where
    /// the decoded counter kept moving can, because a stalled stream would freeze that counter too.
    const NEED: u8 = 3;

    pub fn observe(&mut self, s: CollectorSample) -> CollectorTrust {
        let prev = self.last.replace(s);
        let more_failures = prev.map(|p| s.failures > p.failures).unwrap_or(false);
        let more_decoded = prev.map(|p| s.decoded > p.decoded).unwrap_or(false);
        let queue_newly_lost = s.queue_lost && !prev.map(|p| p.queue_lost).unwrap_or(false);

        if !s.consumer_alive {
            // A consumer thread that exited cannot report the end of its own death: every counter it
            // publishes is frozen where it stopped. Recovery has to wait for a different collector, not
            // for numbers that can no longer move to look better.
            self.clean = 0;
            self.reason = Some("collector consumer thread exited");
            return CollectorTrust::Break("collector consumer thread exited");
        }
        if more_failures || queue_newly_lost {
            self.clean = 0;
            // the sub-causes stay separate: a decoder that cannot parse the payload and a queue that
            // drops events need different follow-up, and one shared label made the log a guess
            let reason = if queue_newly_lost && !more_failures {
                "collector queue overflow"
            } else {
                "collector decode fault"
            };
            self.reason = Some(reason);
            return CollectorTrust::Break(reason);
        }
        if self.reason.is_some() {
            if more_decoded {
                self.clean = self.clean.saturating_add(1);
            } else {
                self.clean = 0;
            }
            if self.clean >= Self::NEED {
                self.clean = 0;
                self.reason = None;
                return CollectorTrust::Recover;
            }
            return CollectorTrust::Hold;
        }
        CollectorTrust::Arm
    }

    pub fn reason(&self) -> Option<&'static str> {
        self.reason
    }

    pub fn streak(&self) -> u8 {
        self.clean
    }
}

impl ActivityPipeline {
    fn heartbeat_only(etw: WindowsFrameServerEtwSource) -> Self {
        let last_cm400_beats = etw.funnel().cm400_heartbeats;
        ActivityPipeline {
            etw,
            backend: ActivityBackend::HeartbeatOnly,
            arbiter: None,
            sam: None,
            last_cm400_beats,
            last_sam_faults: 0,
            lifecycle: None,
            ledger: Ledger::new(),
            last_loss: None,
            collector_watch: CollectorWatch::default(),
            grace_waived_logged: false,
            grace_waivers: 0,
        }
    }

    /// Bring up SAM. Every failure path here leaves the heartbeat in charge; a broken or
    /// missing second backend must never be read as "the camera stopped".
    fn with_backend(
        etw: WindowsFrameServerEtwSource,
        backend: ActivityBackend,
        heartbeat_timeout_ms: u64,
    ) -> Self {
        if backend == ActivityBackend::HeartbeatOnly {
            return Self::heartbeat_only(etw);
        }
        let link = match crate::sam_source::discover_cm400_link() {
            Ok(l) => l,
            Err(e) => {
                log(&format!(
                    "SAM backend requested but the CM400 link could not be resolved (err={e}); \
                     staying on the heartbeat path - no stop signal will be invented"
                ));
                // Read the counter before moving the source into the pipeline.
                let beats = etw.funnel().cm400_heartbeats;
                return ActivityPipeline {
                    etw,
                    backend,
                    arbiter: None,
                    sam: None,
                    last_cm400_beats: beats,
                    last_sam_faults: 0,
                    lifecycle: None,
                    ledger: Ledger::new(),
                    last_loss: None,
                    collector_watch: CollectorWatch::default(),
                    grace_waived_logged: false,
                    grace_waivers: 0,
                };
            }
        };
        log(&format!(
            "SAM backend={backend:?} target link resolved ({} chars, exact match required)",
            link.len()
        ));
        // One-shot availability check of the alternative process-instance identity source, in
        // the real service context. Diagnostic only: whatever it says, the identity rule below
        // stays creation-time based and fail-closed.
        match crate::proc_identity::take() {
            Ok(s) => log(&format!(
                "identity source SystemBasicProcessInformation: ok processes={} return_len={} self_seq_present={} toolhelp={} drift={}+{}",
                s.identities.len(),
                s.return_len,
                s.find(std::process::id()).is_some(),
                s.toolhelp_count,
                s.only_in_snapshot,
                s.only_in_toolhelp
            )),
            Err(e) => log(&format!(
                "identity source SystemBasicProcessInformation: FAILED {e:?} (heartbeat and Shadow behaviour unchanged by this)"
            )),
        }
        let suppression = suppression_for(backend);
        let arbiter = Arbiter::new(&link, heartbeat_timeout_ms, suppression);
        let sam = SensorActivitySource::start(link);
        let last_cm400_beats = etw.funnel().cm400_heartbeats;
        let mut ledger = Ledger::new();
        // The lifecycle collector is brought up last and its failure is harmless: the whole
        // point is that shadow keeps deciding with the heartbeat whatever this backend does.
        let lifecycle = match KernelLifecycle::start() {
            Ok(k) => {
                let b = k.boundary_ms();
                ledger.set_boundary(b);
                // Seed "alive at the boundary" from an independent snapshot. It records
                // existence at one instant and deliberately bounds no interval from below.
                let seeded = match crate::proc_identity::take() {
                    Ok(snap) => {
                        for id in &snap.identities {
                            ledger.note_alive(id.pid, id.sequence, b);
                            // The same snapshot is also the cross-source evidence the ledger
                            // needs before it will trust an event-only lifetime.
                            ledger.note_snapshot_sequence(b, id.sequence);
                        }
                        snap.identities.len()
                    }
                    Err(_) => 0,
                };
                log(&format!(
                    "lifecycle etw: session created by this account, boundary={} live_processes={} (diagnostic only, decisions unchanged)",
                    b, seeded
                ));
                Some(k)
            }
            Err(e) => {
                log(&format!(
                    "lifecycle etw: unavailable err={} (no ledger; heartbeat and shadow unchanged)",
                    e
                ));
                None
            }
        };
        ActivityPipeline {
            etw,
            backend,
            arbiter: Some(arbiter),
            sam: Some(sam),
            last_cm400_beats,
            last_sam_faults: 0,
            lifecycle,
            ledger,
            last_loss: None,
            collector_watch: CollectorWatch::default(),
            grace_waived_logged: false,
            grace_waivers: 0,
        }
    }

    /// Collect this tick's evidence and ask both sources. Returns `(heartbeat, arbitrated)`;
    /// `arbitrated` is `None` when there is no arbiter at all.
    fn poll(&mut self, now_ms: u64) -> (CM400Activity, Option<CM400Activity>) {
        let beats_now = self.etw.funnel().cm400_heartbeats;
        let mut arbitrated = None;
        let evidences: Vec<Evidence> = match self.sam.as_mut() {
            Some(s) => s.drain(),
            None => Vec::new(),
        };
        // Lifetime facts first, and only into the ledger: nothing here reaches the engine.
        if let Some(k) = self.lifecycle.as_mut() {
            for ev in k.drain() {
                if ev.start {
                    self.ledger.ingest_start(ev.pid, ev.sequence, ev.create_ms);
                } else if let Some(exit_ms) = ev.exit_ms {
                    self.ledger
                        .ingest_stop(ev.pid, ev.sequence, ev.create_ms, exit_ms);
                }
            }
            // Sequences the collector saw an independent snapshot agree with.
            for (at, sequence) in crate::kernel_lifecycle::take_confirmations() {
                self.ledger.note_snapshot_sequence(at, sequence);
            }
            // Bounded retention: closed history ages out, and a hard cap invalidates the whole
            // ledger rather than letting it grow forever or silently dropping entries.
            self.ledger.prune_closed(now_ms);
            if self.ledger.enforce_capacity(now_ms) {
                log(&format!(
                    "lifecycle: capacity reset at {} - old history dropped, lifetimes before this instant stay unattributable",
                    now_ms
                ));
                self.reseed_ledger(now_ms);
            }
        }
        // And attribution of each SAM report against proven lifetimes. In shadow this is only
        // recorded; in arbitration it is the sole thing that can authorize the fast path, because
        // a stop we cannot attribute to a verified instance says nothing about the device.
        let mut attributed_stops: Vec<u64> = Vec::new();
        if self.lifecycle.is_some() {
            for ev in &evidences {
                let (pid, streaming, report_ms, arrival_ms) = match ev {
                    Evidence::PidStreaming {
                        inst,
                        report_ms,
                        arrival_ms,
                    } => (inst.pid, true, *report_ms, *arrival_ms),
                    Evidence::PidStopped {
                        inst,
                        report_ms,
                        arrival_ms,
                    } => (inst.pid, false, *report_ms, *arrival_ms),
                    _ => continue,
                };
                let r = Report {
                    pid,
                    streaming,
                    report_ms,
                    arrival_ms,
                };
                match self.ledger.attribute(&r) {
                    Link::Attributed { inst, new_instance } => {
                        if !streaming {
                            attributed_stops.push(report_ms);
                        }
                        log(&format!(
                            "sam attribution: pid={} streaming={} report_ms={} -> instance(pid={}, identity={:?}, epoch_origin=snapshot_confirmed) new_instance={}",
                            pid, streaming, report_ms, inst.pid, inst.identity, new_instance
                        ));
                    }
                    Link::Denied(d) => log(&format!(
                        "sam attribution: pid={} streaming={} report_ms={} -> DENIED {:?}",
                        pid, streaming, report_ms, d
                    )),
                }
            }
        }
        if let Some(a) = self.arbiter.as_mut() {
            // Permission for the stop latch: only a live lifecycle collector with a trusted
            // ledger can say "this stop belongs to a verified instance". Without it the arbiter
            // answers through the heartbeat path, which is today's shipped behaviour.
            let ledger_trusted = self.lifecycle.is_some() && self.ledger.trust_reason().is_none();
            a.set_ledger_trusted(ledger_trusted);
            for ms in attributed_stops {
                a.note_attributed_stop(ms);
            }
            if beats_now != self.last_cm400_beats {
                self.last_cm400_beats = beats_now;
                a.apply(now_ms, Evidence::HeartbeatSeen { arrival_ms: now_ms });
            }
            for ev in &evidences {
                // One line per delivered CM400 report. The shadow phase cannot be judged from
                // aggregates: report counts, per-instance attribution and real callback
                // arrival times are what the stop-latency numbers are built from. The probe
                // measured 8-16 reports per round, so this stays affordable.
                let seen = instance_of(ev).and_then(|i| a.peek(i));
                if let Some(line) = report_line(ev, seen) {
                    log(&line);
                }
            }
            for ev in evidences {
                a.apply(now_ms, ev);
            }
            arbitrated = Some(a.activity(now_ms));
        }
        if let Some((started, faults)) = self.sam_health() {
            if faults != self.last_sam_faults {
                log(&format!(
                    "sam backend fault count {} -> {} (monitor_started={}); explicit fault only, \
                     silence is never a fault - and the heartbeat path stays in charge either way",
                    self.last_sam_faults, faults, started
                ));
                self.last_sam_faults = faults;
            }
        }
        // The heartbeat tracker advances in every backend, so a later flip needs no warm-up.
        let heartbeat = self.etw.activity();
        (heartbeat, arbitrated)
    }

    pub fn backend(&self) -> ActivityBackend {
        self.backend
    }

    pub fn age_ms(&self) -> Option<u64> {
        self.etw.age_ms()
    }

    pub fn provider_enabled(&self) -> bool {
        self.etw.provider_enabled()
    }

    pub fn funnel(&self) -> crate::etw_source::EtwFunnel {
        self.etw.funnel()
    }

    /// SAM's own picture, for the beat line. Never a decision: `backend_choice` already ran.
    /// The latch tail is appended so a reviewer can see whether the reopen guard is holding,
    /// how many times it armed and released, and what released it last.
    pub fn sam_snapshot(&mut self, now_ms: u64) -> Option<String> {
        self.arbiter.as_mut().map(|a| {
            let (held, armed, released, why) = a.latch_state();
            format!(
                "{} latch=held:{}/armed:{}/released:{}/released_by:{}",
                a.snapshot(now_ms),
                held,
                armed,
                released,
                why
            )
        })
    }

    /// Episodes in which a verified stop let the engine retract without the shipped wait.
    pub fn grace_waivers(&self) -> u64 {
        self.grace_waivers
    }

    /// Reports the callback thread posted but the bounded queue could not hold.
    pub fn sam_queue_dropped(&self) -> u64 {
        self.sam.as_ref().map(|s| s.queue_dropped()).unwrap_or(0)
    }

    /// Health of the SAM backend itself, kept separate from the arbiter's view: "the monitor
    /// never came up" must never be readable as "there is no activity".
    pub fn sam_health(&self) -> Option<(bool, u64)> {
        self.sam
            .as_ref()
            .map(|s| (s.monitor_started(), s.monitor_faults()))
    }

    /// Identity-probe totals: (probes attempted, probes that stayed unresolved). Reported so
    /// a claim like "31/31 failed" can be re-derived from the log instead of from a notebook.
    pub fn sam_identity(&self) -> Option<(u64, u64)> {
        self.sam
            .as_ref()
            .map(|_| crate::sam_source::identity_stats())
    }

    /// Longest gap between accepted CM400 reports for one instance, in callback arrivals.
    /// Observation for the shadow phase; it is never an input to a decision.
    pub fn sam_max_report_gap_ms(&self) -> Option<u64> {
        self.arbiter.as_ref().map(|a| a.max_report_gap_ms())
    }

    /// After a capacity reset, re-establish who is alive now. These entries get
    /// `SeenAlive`, which bounds no interval from below: processes born before the new boundary
    /// stay unattributable until their own start/stop events are seen.
    fn reseed_ledger(&mut self, now_ms: u64) {
        if let Ok(snap) = crate::proc_identity::take() {
            for id in &snap.identities {
                self.ledger.note_alive(id.pid, id.sequence, now_ms);
                self.ledger.note_snapshot_sequence(now_ms, id.sequence);
            }
            // A baseline exists, so the ledger may attribute again - but only for lifetimes that
            // begin after this instant. If the snapshot itself failed we stay untrusted: an empty
            // ledger that claims to be healthy is worse than one that admits it cannot see.
            self.ledger.recovered_from_capacity_reset(now_ms);
        }
    }

    /// One beat-line summary of the lifecycle collector, including whether it currently has any
    /// right to be trusted. Reading the counters is part of the contract: a collector that
    /// cannot report its own losses cannot offer intervals anyone should rely on.
    pub fn lifecycle_line(&mut self) -> Option<String> {
        let k = self.lifecycle.as_mut()?;
        match k.loss() {
            Ok(l) => {
                let worse = match self.last_loss {
                    Some(prev) => {
                        l.events_lost > prev.events_lost
                            || l.log_buffers_lost > prev.log_buffers_lost
                            || l.real_time_buffers_lost > prev.real_time_buffers_lost
                    }
                    // The first read is a baseline, not a loss event.
                    None => false,
                };
                if worse {
                    self.ledger.break_trust("kernel event loss detected");
                } else if self.ledger.trust_reason() == Some("kernel event loss detected") {
                    self.ledger.restore_trust();
                }
                self.last_loss = Some(l);
                let (pruned, resets) = self.ledger.retention_counters();
                let (f_old, f_bad) = self.ledger.filtered_counts();
                let (t_empty, t_pre) = crate::sam_source::report_time_stats();
                let h = k.health();
                let c = h.tally;
                let sample = CollectorSample {
                    consumer_alive: h.consumer_alive,
                    queue_lost: h.queue_lost,
                    failures: c.unknown_version
                        + c.tdh_metadata_failed
                        + c.missing_field
                        + c.type_mismatch
                        + c.size_mismatch
                        + c.property_read_failed
                        + c.implausible,
                    decoded: c.ok_start + c.ok_stop,
                };
                // Either the payload did not match what the metadata says, events were dropped inside
                // our own queue, or the consumer thread exited. Unlike the recovery the kernel loss
                // counters get, this one is decided from deltas - see `CollectorWatch`.
                match self.collector_watch.observe(sample) {
                    CollectorTrust::Arm | CollectorTrust::Hold => {}
                    CollectorTrust::Break(reason) => self.ledger.break_trust(reason),
                    CollectorTrust::Recover => {
                        self.ledger.recovered_from_collector_fault(unix_ms())
                    }
                }
                Some(format!(
                    "tracked={} open={} closed={} broken={} pruned={} resets={} filtered_pre_boundary={} filtered_invalid={} sam_time_empty={} sam_time_preepoch={} trusted={} collector_clean={} loss={}/{}/{} buffers={} ok={}/{} unknown_version={} metadata_failed={} missing_field={} type_mismatch={} size_mismatch={} property_read_failed={} implausible={} total={} balanced={} callbacks={} decode_broken={} queue_lost={} consumer_alive={} boundary={}",
                    self.ledger.tracked_count(),
                    self.ledger.open_count(),
                    self.ledger.closed_count(),
                    self.ledger.broken_count(),
                    pruned,
                    resets,
                    f_old,
                    f_bad,
                    t_empty,
                    t_pre,
                    self.ledger.trust_reason().is_none(),
                    self.collector_watch.streak(),
                    l.events_lost,
                    l.log_buffers_lost,
                    l.real_time_buffers_lost,
                    l.buffers,
                    c.ok_start,
                    c.ok_stop,
                    c.unknown_version,
                    c.tdh_metadata_failed,
                    c.missing_field,
                    c.type_mismatch,
                    c.size_mismatch,
                    c.property_read_failed,
                    c.implausible,
                    c.total,
                    c.balanced(),
                    h.callbacks,
                    h.decode_broken,
                    h.queue_lost,
                    h.consumer_alive,
                    self.ledger.boundary().unwrap_or(0)
                ))
            }
            Err(e) => {
                // "Cannot prove we lost nothing" is treated exactly like a loss: the ledger
                // stops being usable for attribution until a read succeeds.
                self.ledger.break_trust("loss counters unreadable");
                Some(format!("loss_query_failed={} trusted=false", e))
            }
        }
    }
}

impl ActivitySource for ActivityPipeline {
    fn activity(&mut self) -> CM400Activity {
        let now = unix_ms();
        let (heartbeat, arbitrated) = self.poll(now);
        backend_choice(self.backend, heartbeat, arbitrated)
    }

    /// The engine asks this once per tick, right after reading activity. Only an `Inactive`
    /// reading can act on it, so this cannot shorten anything else.
    fn fast_retract_allowed(&mut self) -> bool {
        let held = self
            .arbiter
            .as_ref()
            .map(|a| a.latch_state().0)
            .unwrap_or(false);
        let granted = fast_retract_granted(self.backend, held);
        // Announce the edges. A waived wait has to be visible in the log as a decision, not
        // inferred from a faster motor.
        if granted && !self.grace_waived_logged {
            self.grace_waived_logged = true;
            self.grace_waivers += 1;
            log("activity: down grace waived - the idle claim is an attributed stop on a trusted lifecycle ledger, not silence");
        } else if !granted && self.grace_waived_logged {
            self.grace_waived_logged = false;
            log("activity: down grace restored - the stop latch no longer holds");
        }
        granted
    }
}

/// Unix milliseconds, the same wall clock the ETW tracker uses for arrivals.
fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The process instance a delivered report is about, if it is a CM400 report at all.
fn instance_of(ev: &Evidence) -> Option<ProcInstance> {
    match ev {
        Evidence::PidStreaming { inst, .. } | Evidence::PidStopped { inst, .. } => Some(*inst),
        _ => None,
    }
}

/// One observability line per CM400 report.
///
/// Both clocks are printed side by side and deliberately not merged: `report_ms` is the
/// system's FILETIME (ordering inside this source), `arrival_ms` is our own wall clock read
/// on the callback thread (latency and silence measurement). No subtraction happens between
/// them, and neither is compared to the ETW arrival clock.
fn report_line(ev: &Evidence, seen: Option<PidEntry>) -> Option<String> {
    let (streaming, report_ms, arrival_ms, inst) = match ev {
        Evidence::PidStreaming {
            inst,
            report_ms,
            arrival_ms,
        } => (true, *report_ms, *arrival_ms, *inst),
        Evidence::PidStopped {
            inst,
            report_ms,
            arrival_ms,
        } => (false, *report_ms, *arrival_ms, *inst),
        _ => return None,
    };
    Some(format!(
        "sam report: streaming={} pid={} identity={}({}) report_ms={} arrival_ms={} registered={} epoch={}",
        streaming,
        inst.pid,
        inst.identity.map(|v| v.origin()).unwrap_or("unresolved"),
        inst.identity.map(|v| v.raw()).unwrap_or(0),
        report_ms,
        arrival_ms,
        seen.is_some(),
        seen.map(|p| p.epoch).unwrap_or(0)
    ))
}

/// The only way a configuration value can select a backend, and it is a *subset* choice: the
/// role's safety rules stay in `production_backend`, which this can narrow but never widen.
///
/// * the service may run shadow (the shipped default) or arbitration - both keep the heartbeat as
///   fallback, and arbitration additionally cannot act without an attributed stop on a trusted
///   lifecycle ledger;
/// * the console host ignores the choice entirely. It may run beside the service, and a typo in a
///   shared file must not let a second process reach the motor policy;
/// * an unreadable file, a missing key or an invalid value all land on `Shadow` inside
///   `Config` itself, so this function never sees a half-parsed request.
pub fn backend_for(role: Role, choice: BackendChoice) -> ActivityBackend {
    match role {
        Role::Console => ActivityBackend::HeartbeatOnly,
        Role::Service => match choice {
            BackendChoice::Shadow => ActivityBackend::SensorShadow,
            BackendChoice::Arbitrating => ActivityBackend::SensorArbitrating,
        },
    }
}

/// Which suppression mode a backend is allowed to run. Pure, so the rollout gate itself is
/// testable: shadow can never arm the reopen guard (it would be an invisible motor policy), and
/// arbitration can only ever run the state-based latch - not a time window we never measured.
fn suppression_for(backend: ActivityBackend) -> Suppression {
    match backend {
        ActivityBackend::SensorArbitrating => Suppression::Latched,
        ActivityBackend::SensorShadow | ActivityBackend::HeartbeatOnly => Suppression::Disabled,
    }
}

/// The one gate for skipping the down grace.
///
/// Waits exist because an `Inactive` heartbeat reading is silence, not a stop. The only thing
/// that justifies skipping one is a positive, attributable stop whose lifecycle evidence is
/// currently trusted - which is exactly what the stop latch holds, and nothing else:
///
/// * shadow must never waive, because in shadow the arbiter's answer does not reach the policy;
///   waiving there would change motor timing behind a backend documented as observation-only;
/// * the heartbeat backend has no stop claim to waive on;
/// * without a held latch the reading is silence again, so the shipped wait returns unchanged.
pub fn fast_retract_granted(backend: ActivityBackend, stop_latch_held: bool) -> bool {
    matches!(backend, ActivityBackend::SensorArbitrating) && stop_latch_held
}

/// The shipped default backend for a host, decided in code.
///
/// This is the one auditable place the default lives. Arbitration is **not** the default: it is
/// reachable only through an explicit `activity_backend` line in the config file (`backend_for`
/// narrows the role's allowed set to that) or an explicit code path, and it still cannot retract
/// anything without an attributed stop on a trusted lifecycle ledger. The console host is
/// heartbeat-only whatever the file says, because it may run beside the service.
pub fn production_backend(role: Role) -> ActivityBackend {
    match role {
        // Shadow verification: SAM observes and is logged, the heartbeat still decides.
        Role::Service => ActivityBackend::SensorShadow,
        // The console host never adds a second backend: it may run beside a live service,
        // and its purpose is observation through its own session, not product behaviour.
        Role::Console => ActivityBackend::HeartbeatOnly,
    }
}

/// What the policy will actually be fed, for the startup log line. Stated separately from the
/// backend so "SAM is running" can never be misread as "SAM is deciding".
fn decision_source(backend: ActivityBackend) -> &'static str {
    match backend {
        ActivityBackend::HeartbeatOnly => "heartbeat",
        ActivityBackend::SensorShadow => "heartbeat (SAM observes only; cannot move the motor)",
        ActivityBackend::SensorArbitrating => "SAM arbitration with heartbeat fallback",
    }
}

/// The assembled runtime: platform wiring done, loop ready.
///
/// `init` and `run` are split because a Windows service must report `Running` to
/// SCM *after* bring-up and *before* it blocks. Hosts with no supervisor use
/// `run_runtime` (init + run) and never see the difference.
pub struct Runtime {
    /// Kept for the process lifetime: closing it would let a second instance take
    /// over the ETW session while we are still driving the motor.
    _singleton: Singleton,
    store: FileStore,
    clock: SysClock,
    activity: ActivityPipeline,
    transport: LoggedTransport,
    engine: Engine,
    /// Read-only session loss counters. Diagnostics only: nothing below `log` consumes
    /// it, so a loss number can never influence a raise or a retract.
    loss: LossTracker,
}

impl Runtime {
    /// Become the one driver instance, open the ETW session, probe the motor, recover
    /// persisted state, using the backend this host is allowed to use (see
    /// [`production_backend`]: shadow for the service, heartbeat for the console).
    pub fn init(role: Role) -> Result<Self, String> {
        // The runtime switch: `C:\ProgramData\CM400\config.toml` may ask for arbitration without
        // a rebuild. Anything wrong in that file leaves the shipped shadow behaviour (see
        // `Config::parse`), and the outcome is stated in the startup line either way.
        let cfg = Config::load();
        Self::init_with_note(role, backend_for(role, cfg.backend), cfg.backend_note)
    }

    /// Same bring-up, with the backend and the text describing where that choice came from.
    ///
    /// There is deliberately no public "pick a backend" entry point: the experiment that used one
    /// (`--r2-latch-experiment`) is gone, and leaving an interface that bypasses the config would
    /// let a future caller select a backend that the startup line then reports as configured.
    fn init_with_note(
        role: Role,
        backend: ActivityBackend,
        backend_note: &'static str,
    ) -> Result<Self, String> {
        if matches!(role, Role::Console) && service_is_live() {
            return Err(format!(
                "the {SERVICE_NAME} service is live; stop it first (or use cm400ctl to observe)"
            ));
        }
        // Singleton FIRST: the fixed-name session takeover below is only safe for
        // the instance that holds the mutex.
        let _singleton = Singleton::acquire(role)?;
        let cfg = Config::load();
        log(&format!(
            "cm400d starting: role={:?} mode={:?} heartbeat_timeout_ms={} down_grace_ms={} activity_backend={:?} decision_source={} backend_source={}",
            role, cfg.mode, cfg.heartbeat_timeout_ms, cfg.down_grace_ms, backend,
            decision_source(backend), backend_note
        ));

        let mut store = FileStore::new(Config::state_path());
        // The service owns the fixed product session (and may reclaim a stale one);
        // a console host observes through its own session and never steals it.
        let source = match role {
            Role::Service => WindowsFrameServerEtwSource::new(cfg.heartbeat_timeout_ms),
            Role::Console => WindowsFrameServerEtwSource::for_diagnostics(cfg.heartbeat_timeout_ms),
        };
        let activity = match source {
            Ok(a) => ActivityPipeline::with_backend(a, backend, cfg.heartbeat_timeout_ms),
            Err(e) => {
                // Logged, not just returned: a service host has no stderr to read.
                log(&format!(
                    "ETW activity init FAILED role={role:?} err={e} (account lacks the real-time ETW right?)"
                ));
                return Err(format!("ETW activity init failed err={e}"));
            }
        };
        let mut transport = LoggedTransport {
            ch: MotorChannel::new(),
        };
        probe_motor(&mut transport);
        let mut engine = Engine::new(cfg.to_policy());
        let mut clock = SysClock;

        // Recover persisted physical state; activity stays Unknown until first heartbeat.
        engine.recover(&mut store, clock.now_ms());

        // --- startup persistence ---------------------------------------------
        // `recover` deliberately leaves the position Unknown when there is no readable
        // file, because CM400 has no reliable position feedback: "no state file" must
        // never be turned into a silent claim that the lens is Down. What we do at boot
        // is record the honest value, so the file exists and says Unknown.
        let state_path = Config::state_path();
        match store.load() {
            Some(s) => log(&format!(
                "state: restored physical={:?} from {state_path:?}",
                s.physical
            )),
            None => {
                if state_path.exists() {
                    // Corrupt or from an incompatible format: keep the file untouched so
                    // it can be inspected, and do not mint a plausible-looking state.
                    log("state: file EXISTS but is undecodable/incompatible -> physical stays Unknown, file left in place for diagnosis");
                } else {
                    let s = engine.status();
                    store.save(&s);
                    log(&format!(
                        "state: no file at {state_path:?} -> wrote initial record (physical={:?}), no motor command issued",
                        s.physical
                    ));
                }
            }
        }
        log(&format!("recovered status = {:?}", engine.status()));

        Ok(Runtime {
            _singleton,
            store,
            clock,
            activity,
            transport,
            engine,
            loss: LossTracker::new(LOSS_SAMPLE_INTERVAL_MS),
        })
    }

    /// Sample the product session's loss counters. Query is the only operation here;
    /// a failure is logged as unavailable rather than as "no losses".
    fn observe_losses(&mut self) {
        let name = crate::etw_source::SESSION_NAME;
        let sample = session_loss_counters(name);
        let now = self.clock.now_ms();
        if let Some(line) = self.loss.observe(now, sample) {
            log(&format!("{line} (session={name})"));
        }
    }

    /// Control loop until `stop`. Returning drops the activity source, which
    /// tears the ETW session down, and closes WinUSB.
    pub fn run(&mut self, stop: &AtomicBool) -> Result<(), String> {
        let mut last_act = CM400Activity::Unknown;
        let mut last_enabled = false;
        let mut ticks: u64 = 0;
        while !stop.load(Ordering::Relaxed) {
            let a = self.activity.activity();
            if a != last_act {
                log(&format!(
                    "activity {:?} -> {:?} (age={:?}ms)",
                    last_act,
                    a,
                    self.activity.age_ms()
                ));
                last_act = a;
            }
            let enabled = self.activity.provider_enabled();
            if enabled != last_enabled {
                log(&format!("MF-FrameServer provider enabled = {}", enabled));
                last_enabled = enabled;
            }
            // Periodic funnel snapshot: distinguishes "provider off", "no events",
            // "events but no CM400 match", "heartbeat seen but motor idle".
            if ticks.is_multiple_of(20) {
                let now = self.clock.now_ms();
                match self.activity.sam_snapshot(now) {
                    Some(sam) => {
                        let (started, faults) = self.activity.sam_health().unwrap_or((false, 0));
                        let (probes, unresolved) = self.activity.sam_identity().unwrap_or((0, 0));
                        let gap = self.activity.sam_max_report_gap_ms().unwrap_or(0);
                        log(&format!(
                            "beat: activity={:?} funnel={:?} status={:?} sam={} queue_dropped={} monitor_started={} monitor_faults={} sam_max_report_gap_ms={} identity_unresolved={}/{} grace_waived={} fast_retracts={} motor_write_failures={}",
                            a,
                            self.activity.funnel(),
                            self.engine.status(),
                            sam,
                            self.activity.sam_queue_dropped(),
                            started,
                            faults,
                            gap,
                            unresolved,
                            probes,
                            self.activity.grace_waivers(),
                            self.engine.fast_retracts(),
                            self.engine.write_failures()
                        ));
                        if let Some(line) = self.activity.lifecycle_line() {
                            log(&format!("lifecycle: {}", line));
                        }
                    }
                    None => log(&format!(
                        "beat: activity={:?} funnel={:?} status={:?}",
                        a,
                        self.activity.funnel(),
                        self.engine.status()
                    )),
                }
            }
            if ticks.is_multiple_of(LOSS_SAMPLE_TICKS) {
                self.observe_losses();
            }
            self.engine.tick(
                &mut self.activity,
                &mut self.clock,
                &mut self.transport,
                &mut self.store,
            );
            ticks += 1;
            std::thread::sleep(Duration::from_millis(500));
        }

        log("cm400d stopping (activity source will tear down ETW session)");
        Ok(())
    }
}

/// Run the CM400 runtime as a console host (init + run). The service host calls
/// `Runtime::init(Role::Service)` / `run` so it can report Running in between.
pub fn run_runtime(stop: &AtomicBool) -> Result<(), String> {
    let mut rt = Runtime::init(Role::Console)?;
    rt.run(stop)
}

#[cfg(test)]
mod collector_health_transitions {
    use super::*;

    fn sample(
        consumer_alive: bool,
        queue_lost: bool,
        failures: u64,
        decoded: u64,
    ) -> CollectorSample {
        CollectorSample {
            consumer_alive,
            queue_lost,
            failures,
            decoded,
        }
    }

    /// The defect this type exists to close: the collector's failure counters are cumulative, so a
    /// decision built on "is the flag false again" can never recover - one startup-window decode
    /// failure would leave the ledger untrusted for the rest of the process, which silently costs the
    /// SAM-attributed fast retract the waiver it needs. Recovery therefore comes from deltas, and only
    /// from deltas.
    #[test]
    fn a_latched_failure_counter_recovers_only_from_sustained_progress() {
        let mut w = CollectorWatch::default();
        assert_eq!(w.observe(sample(true, false, 0, 100)), CollectorTrust::Arm);

        assert_eq!(
            w.observe(sample(true, false, 3, 101)),
            CollectorTrust::Break("collector decode fault"),
            "a newly added decode failure breaks trust, naming the decode kind"
        );
        assert_eq!(w.reason(), Some("collector decode fault"));

        // silence is not evidence of health: nothing new failed, but nothing new was decoded either
        assert_eq!(w.observe(sample(true, false, 3, 101)), CollectorTrust::Hold);
        assert_eq!(w.streak(), 0, "a stalled sample earns no recovery credit");

        // three uninterrupted progressing samples, with the failure count frozen, do recover
        assert_eq!(w.observe(sample(true, false, 3, 102)), CollectorTrust::Hold);
        assert_eq!(w.observe(sample(true, false, 3, 103)), CollectorTrust::Hold);
        assert_eq!(
            w.observe(sample(true, false, 3, 104)),
            CollectorTrust::Recover
        );
        assert_eq!(w.reason(), None, "recovered, so no reason is outstanding");

        // afterwards a healthy stream changes nothing, and a new failure breaks it again
        assert_eq!(w.observe(sample(true, false, 3, 105)), CollectorTrust::Arm);
        assert_eq!(
            w.observe(sample(true, false, 9, 106)),
            CollectorTrust::Break("collector decode fault")
        );
    }

    /// The streak has to be consecutive, or three samples spread over an hour of intermittent
    /// breakage would read as recovery.
    #[test]
    fn a_fresh_failure_restarts_the_recovery_streak() {
        let mut w = CollectorWatch::default();
        w.observe(sample(true, false, 0, 10));
        w.observe(sample(true, false, 1, 11));
        assert_eq!(w.observe(sample(true, false, 1, 12)), CollectorTrust::Hold);
        assert_eq!(w.observe(sample(true, false, 1, 13)), CollectorTrust::Hold);
        // the failure count moves again mid-streak
        assert_eq!(
            w.observe(sample(true, false, 2, 14)),
            CollectorTrust::Break("collector decode fault")
        );
        assert_eq!(w.streak(), 0);
        // and the count starts over from here
        assert_eq!(w.observe(sample(true, false, 2, 15)), CollectorTrust::Hold);
        assert_eq!(w.observe(sample(true, false, 2, 16)), CollectorTrust::Hold);
        assert_eq!(
            w.observe(sample(true, false, 2, 17)),
            CollectorTrust::Recover
        );
    }

    /// A consumer thread that exited cannot report the end of its own death: every counter it
    /// publishes is frozen where it stopped, which is exactly what a "no new failures plus progress"
    /// rule would mistake for health. So no self-reported progress re-arms the ledger while the
    /// reporter is gone - in practice recovery means a recreated collector (which resets the latches,
    /// see `KernelLifecycle::start`) or a service restart, and intervals that crossed the fault stay
    /// broken either way.
    #[test]
    fn a_dead_consumer_cannot_report_itself_alive_again() {
        let mut w = CollectorWatch::default();
        w.observe(sample(true, false, 0, 10));
        assert_eq!(
            w.observe(sample(false, false, 0, 10)),
            CollectorTrust::Break("collector consumer thread exited"),
            "the exit is its own sub-cause, not a decode fault"
        );
        for i in 0..10 {
            assert_eq!(
                w.observe(sample(false, false, 0, 10 + i)),
                CollectorTrust::Break("collector consumer thread exited"),
                "no amount of self-reported progress re-arms a dead consumer"
            );
        }
        assert_eq!(w.streak(), 0);
        assert_eq!(w.reason(), Some("collector consumer thread exited"));
        // a live consumer reporting again means a new collector exists; it still has to earn the
        // streak from that point: three progressing samples with no new failures
        assert_eq!(w.observe(sample(true, false, 0, 99)), CollectorTrust::Hold);
        assert_eq!(w.observe(sample(true, false, 0, 100)), CollectorTrust::Hold);
        assert_eq!(
            w.observe(sample(true, false, 0, 101)),
            CollectorTrust::Recover
        );
        assert_eq!(w.reason(), None);
    }

    /// Lumping the sub-causes into one label is what made the log line unreadable: three different
    /// failures, one string, no way to tell a decoder bug from a full queue.
    #[test]
    fn queue_and_decode_faults_keep_separate_reasons() {
        let mut w = CollectorWatch::default();
        w.observe(sample(true, false, 0, 5));
        assert_eq!(
            w.observe(sample(true, true, 0, 6)),
            CollectorTrust::Break("collector queue overflow"),
            "queue loss with no new decode failure must not be reported as a decode fault"
        );
        let mut d = CollectorWatch::default();
        d.observe(sample(true, false, 0, 5));
        assert_eq!(
            d.observe(sample(true, false, 1, 6)),
            CollectorTrust::Break("collector decode fault"),
            "a decode failure with no queue loss is the other cause"
        );
    }
}

/// The shadow deployment's isolation, asserted rather than inferred from the pure tests.
///
/// These exist because "the arbiter behaves correctly" does not yet say "the shipped host
/// cannot be steered by it". That is a property of this file's wiring.
#[cfg(test)]
mod shadow_isolation {
    use super::*;
    use crate::sam_view::SAMView;

    /// Config may narrow the role's allowed backends and nothing more.
    #[test]
    fn config_can_only_choose_within_what_the_role_allows() {
        assert_eq!(
            backend_for(Role::Service, BackendChoice::Shadow),
            ActivityBackend::SensorShadow
        );
        assert_eq!(
            backend_for(Role::Service, BackendChoice::Arbitrating),
            ActivityBackend::SensorArbitrating
        );
        // The console host ignores the selection entirely, whichever way it points.
        for c in [BackendChoice::Shadow, BackendChoice::Arbitrating] {
            assert_eq!(
                backend_for(Role::Console, c),
                ActivityBackend::HeartbeatOnly,
                "the console honoured a config selection: {c:?}"
            );
        }
        // With no config at all the service still gets the shipped shadow behaviour.
        assert_eq!(
            backend_for(Role::Service, Config::default().backend),
            production_backend(Role::Service),
            "the config default and the code default must agree"
        );
    }

    const LINK: &str = "\\\\?\\usb#vid_0603&pid_8612&mi_00#8&2e26e82&0&0000#{e5323777-f976-4f5b-9b55-b94699c46e44}\\global";

    #[test]
    fn no_production_entry_point_can_select_arbitration() {
        // Whatever the host role, the production choice is never arbitration.
        for role in [Role::Service, Role::Console] {
            assert_ne!(
                production_backend(role),
                ActivityBackend::SensorArbitrating,
                "{role:?} must not reach arbitration by default"
            );
        }
        // This round's deployment target, stated explicitly so a silent change is a test failure.
        assert_eq!(
            production_backend(Role::Service),
            ActivityBackend::SensorShadow
        );
        // The reopen guard is available to arbitration only. In shadow the arbiter's answer is
        // discarded, so arming a latch there would be an unobservable motor policy.
        assert_eq!(
            suppression_for(ActivityBackend::SensorShadow),
            Suppression::Disabled
        );
        assert_eq!(
            suppression_for(ActivityBackend::HeartbeatOnly),
            Suppression::Disabled,
            "the heartbeat path has no SAM opinion to latch on"
        );
        assert_eq!(
            suppression_for(ActivityBackend::SensorArbitrating),
            Suppression::Latched,
            "and arbitration must never run an unmeasured time window"
        );
        // The console host is untouched: it may run beside the service.
        assert_eq!(
            production_backend(Role::Console),
            ActivityBackend::HeartbeatOnly
        );
        // The down-grace waiver is a property of the arbitration backend holding a verified
        // stop, and of nothing else. Shadow in particular can never change motor timing, since
        // its whole contract is that the policy still hears the heartbeat.
        for held in [true, false] {
            assert!(
                !fast_retract_granted(ActivityBackend::SensorShadow, held),
                "shadow waived the grace with latch_held={held}"
            );
            assert!(
                !fast_retract_granted(ActivityBackend::HeartbeatOnly, held),
                "the heartbeat path has no attributed stop to waive on"
            );
            assert_eq!(
                fast_retract_granted(ActivityBackend::SensorArbitrating, held),
                held,
                "arbitration waives only while the latch holds"
            );
        }
        // And shadow builds an arbiter with no suppression window: R2 cannot be armed at all.
        assert_eq!(
            decision_source(ActivityBackend::SensorShadow)
                .split(' ')
                .next(),
            Some("heartbeat")
        );
    }

    #[test]
    fn shadow_observes_a_real_stop_without_arming_r2_or_feeding_the_policy() {
        // Exactly the arbiter `with_backend` constructs for shadow: Suppression::Disabled.
        let mut a = Arbiter::new(LINK, 3_000, Suppression::Disabled);
        let inst = ProcInstance::from_creation_time(4994, 1);
        a.apply(
            1_000,
            Evidence::PidStreaming {
                inst,
                report_ms: 1_000,
                arrival_ms: 1_000,
            },
        );
        a.apply(1_100, Evidence::HeartbeatSeen { arrival_ms: 1_100 });
        assert_eq!(a.activity(1_200), CM400Activity::Active);

        // A quiet stretch (which shadow must measure), then a genuine explicit stop for the
        // same instance, newer than its TRUE.
        a.apply(
            10_000,
            Evidence::PidStopped {
                inst,
                report_ms: 10_000,
                arrival_ms: 10_000,
            },
        );
        assert_eq!(
            a.view(10_100),
            SAMView::Idle,
            "the stop is registered, ruling A"
        );
        assert_eq!(
            a.max_report_gap_ms(),
            9_000,
            "silence is still measured in callback arrivals"
        );
        assert_eq!(a.telemetry.r2_applied, 0, "shadow must never apply R2");
        let arbitrated = a.activity(10_100);
        assert_eq!(
            arbitrated,
            CM400Activity::Inactive,
            "the arbiter's own answer is Inactive here only because the heartbeat went stale too"
        );

        // The isolation itself: whatever SAM says, shadow hands the policy the heartbeat value.
        for sam_says in [
            CM400Activity::Inactive,
            CM400Activity::Active,
            CM400Activity::Unknown,
        ] {
            for hb in [
                CM400Activity::Inactive,
                CM400Activity::Active,
                CM400Activity::Unknown,
            ] {
                assert_eq!(
                    backend_choice(ActivityBackend::SensorShadow, hb, Some(sam_says)),
                    hb,
                    "shadow leaked SAM (sam={sam_says:?}, heartbeat={hb:?})"
                );
            }
        }
    }

    #[test]
    fn report_lines_keep_the_two_clocks_apart() {
        let ev = Evidence::PidStopped {
            inst: ProcInstance::from_creation_time(4994, 7),
            report_ms: 1_000,
            arrival_ms: 1_300,
        };
        let line = report_line(&ev, None).expect("a CM400 report must be logged");
        assert!(line.contains("report_ms=1000"), "{line}");
        assert!(line.contains("arrival_ms=1300"), "{line}");
        assert!(line.contains("pid=4994"), "{line}");
        assert!(line.contains("identity=creation_time(7)"), "{line}");
        // Non-report evidence must not produce a report line at all.
        assert!(report_line(&Evidence::HeartbeatSeen { arrival_ms: 1 }, None).is_none());
    }
}
