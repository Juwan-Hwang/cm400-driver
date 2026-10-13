//! R2 backend: `IMFSensorActivityMonitor`, the only CM400 signal that reports a stream
//! *ending* rather than merely going quiet.
//!
//! Split of responsibility, and why it is split this way:
//! - [`IdentityResolver`] is pure logic with an injectable creation-time lookup, so the
//!   PID-reuse argument is testable without a process table.
//! - [`SensorActivitySource`] owns the COM lifetime on one dedicated apartment thread and
//!   turns system reports into [`Evidence`]. It decides nothing.
//!
//! Callback rules follow the design (SENSOR-ACTIVITY-INTEGRATION §6.1): the callback only
//! reads fields and posts them to a bounded queue, and always returns `S_OK` - returning a
//! failure would stop FrameServer from delivering reports to *every* subscriber, which is
//! the same class of mistake as leaking an ETW session.
//!
//! Nothing here is wired into the shipped decision path yet: `runtime.rs` keeps
//! `ActivityBackend::HeartbeatOnly` until this passes review. The probe measurements that
//! motivated it (20/20 valid, median 288ms) were taken with the service stopped and with a
//! single client, so multi-client semantics remain unverified; the arbitration rules in
//! `sam_view` are written to be safe under that unknown.

use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use windows::core::{implement, Interface, PWSTR};
use windows::Win32::Foundation::{CloseHandle, GetLastError, FILETIME, HANDLE};
use windows::Win32::Media::MediaFoundation::{
    IMFSensorActivitiesReport, IMFSensorActivitiesReportCallback,
    IMFSensorActivitiesReportCallback_Impl, IMFSensorActivityMonitor, MFCreateAttributes,
    MFCreateSensorActivityMonitor, MFEnumDeviceSources, MFShutdown, MFStartup,
    MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE, MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID,
    MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK, MF_VERSION,
};
use windows::Win32::System::Com::{
    CoInitializeEx, CoTaskMemFree, CoUninitialize, COINIT_APARTMENTTHREADED, COINIT_MULTITHREADED,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::sam_view::{link_is_cm400, Evidence, MonitorFaultKind, NoMatchKind, ProcInstance};

/// The CM400 capture function, as a case-insensitive fragment of the symbolic link.
///
/// Used ONLY to discover which device we mean, exactly like the verified capture probe.
/// Every later comparison is the full string, via [`link_is_cm400`].
const CM400_LINK_FRAGMENT: &str = "vid_0603&pid_8612&mi_00";

/// Bounded because a stalled control loop must never turn evidence accumulation into an
/// out-of-memory service. Dropping the *oldest* evidence is conservative: a lost stop
/// report makes us keep the lens out longer, never retract it sooner.
const QUEUE_CAPACITY: usize = 256;

/// FILETIME (100ns ticks since 1601-01-01) to unix milliseconds.
///
/// Kept as a pure function of the two dwords so the conversion is testable; SAM's report
/// time and our own arrival time are different clocks and are never compared (design §1).
///
/// A `0` return is **not** "the epoch": it is the same sentinel the identity probe already uses
/// (see `ProbeStage::PreEpoch`) - either an uninitialised FILETIME or a pre-1970 stamp that
/// saturating subtraction cannot place in the unix domain. Callers must treat 0 as "no usable
/// time", never as a comparable instant; `proc_lifecycle::Ledger::attribute` does.
pub fn filetime_to_unix_ms(low: u32, high: u32) -> u64 {
    let ticks = ((high as u64) << 32) | low as u64;
    const EPOCH_DIFF_100NS: u64 = 116_444_736_000_000_000;
    ticks
        .saturating_sub(EPOCH_DIFF_100NS)
        .saturating_div(10_000)
}

/// One report row as the system delivered it, before identity resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawReport {
    pub link: String,
    pub pid: u32,
    pub streaming: bool,
    /// Converted from `GetReportTime()`: the system's own clock, used only inside this source.
    pub report_ms: u64,
    /// Our wall clock, read on the callback thread at delivery. This is what the silence metric
    /// uses; the 500 ms control loop must never be passed off as a callback timestamp.
    pub arrival_ms: u64,
}

/// What the worker thread publishes.
struct Sink {
    raw: VecDeque<RawReport>,
    extra: Vec<Evidence>,
    dropped: u64,
}

impl Sink {
    fn new() -> Self {
        Sink {
            raw: VecDeque::new(),
            extra: Vec::new(),
            dropped: 0,
        }
    }
    fn push(&mut self, r: RawReport) {
        if self.raw.len() >= QUEUE_CAPACITY {
            self.raw.pop_front();
            self.dropped += 1;
        }
        self.raw.push_back(r);
    }
    /// Publish a parsed report set. Called with the lock held, and does **no** COM work:
    /// everything here was already read outside the critical section.
    fn publish(&mut self, parsed: Parsed) {
        for r in parsed.rows {
            self.push(r);
        }
        self.extra.extend(parsed.faults);
    }
}

/// One callback invocation, parsed into owned data before anything is shared.
///
/// The reason this exists at all: the callback used to hold the shared mutex across
/// `GetCount`/`GetActivityReport`/`GetSymbolicLink`/`GetProcessActivity`/`GetReportTime`.
/// Those are re-entrant COM calls into FrameServer, `std::sync::Mutex` is not reentrant, and
/// a nested callback on the same thread would self-deadlock. Reading first and publishing
/// afterwards shrinks the critical section to a memcpy.
#[derive(Default)]
struct Parsed {
    rows: Vec<RawReport>,
    faults: Vec<Evidence>,
}

/// Wall clock on the calling (callback) thread, in unix ms.
///
/// One read per `OnActivitiesReport` delivery, stamped onto every row parsed from that report.
/// Same clock domain as the ETW arrival times, and deliberately **not** the same thing as
/// `report_ms`, which comes from the system's FILETIME.
fn callback_clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Reads a `IMFSensorActivitiesReport` collection into owned data.
///
/// Runs on the callback thread but touches no shared state, so it may make as many COM calls
/// as it needs. Every failure shape is recorded as *no data* - with a count, not silently -
/// and a row whose properties could not be read is never published, because a half-read
/// report must not reach the state machine as a valid TRUE/FALSE.
unsafe fn parse_collection(coll: &IMFSensorActivitiesReport, arrival_ms: u64) -> Parsed {
    let mut out = Parsed::default();
    let count = match coll.GetCount() {
        Ok(n) => n,
        Err(e) => {
            out.faults.push(Evidence::NoMatchingReport {
                kind: NoMatchKind::PropertyReadFailed(e.code().0),
            });
            return out;
        }
    };
    if count == 0 {
        // An empty list is the classic false stop: it happens while nothing is streaming
        // and also while *everything* is streaming, so it carries no information about a
        // teardown. Counted, never acted on.
        out.faults.push(Evidence::NoMatchingReport {
            kind: NoMatchKind::EmptyCollection,
        });
        return out;
    }
    let mut useful = 0u32;
    for i in 0..count {
        let report = match coll.GetActivityReport(i) {
            Ok(r) => r,
            Err(e) => {
                out.faults.push(Evidence::NoMatchingReport {
                    kind: NoMatchKind::PropertyReadFailed(e.code().0),
                });
                continue;
            }
        };
        let link = match read_symbolic_link(&report) {
            Some(l) => l,
            None => {
                out.faults.push(Evidence::NoMatchingReport {
                    kind: NoMatchKind::PropertyReadFailed(-1),
                });
                continue;
            }
        };
        let procs = match report.GetProcessCount() {
            Ok(n) => n,
            Err(e) => {
                out.faults.push(Evidence::NoMatchingReport {
                    kind: NoMatchKind::PropertyReadFailed(e.code().0),
                });
                continue;
            }
        };
        for p in 0..procs {
            let act = match report.GetProcessActivity(p) {
                Ok(a) => a,
                Err(e) => {
                    out.faults.push(Evidence::NoMatchingReport {
                        kind: NoMatchKind::PropertyReadFailed(e.code().0),
                    });
                    continue;
                }
            };
            let pid = match act.GetProcessId() {
                Ok(n) => n,
                Err(e) => {
                    out.faults.push(Evidence::NoMatchingReport {
                        kind: NoMatchKind::PropertyReadFailed(e.code().0),
                    });
                    continue;
                }
            };
            // BOOL -> bool. This is the explicit streaming flag: the thing we came for.
            let streaming = match act.GetStreamingState() {
                Ok(b) => b.as_bool(),
                Err(e) => {
                    out.faults.push(Evidence::NoMatchingReport {
                        kind: NoMatchKind::PropertyReadFailed(e.code().0),
                    });
                    continue;
                }
            };
            // `GetReportTime` is load-bearing: the arbiter orders TRUE/FALSE by it. A failure
            // must not become timestamp 0, because 0 would either look like a pre-epoch report
            // or silently win/lose the `report_ms > last_true_ms` comparison at random.
            let ft = match act.GetReportTime() {
                Ok(f) => f,
                Err(e) => {
                    out.faults.push(Evidence::NoMatchingReport {
                        kind: NoMatchKind::PropertyReadFailed(e.code().0),
                    });
                    continue;
                }
            };
            let raw_ticks = ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64;
            let report_ms = filetime_to_unix_ms(ft.dwLowDateTime, ft.dwHighDateTime);
            if report_ms == 0 {
                // Split the two ways a time can be unusable so the log can say which one the
                // system actually handed us, instead of us guessing from the clamped result.
                if raw_ticks == 0 {
                    TIME_RAW_ZERO.fetch_add(1, Ordering::Relaxed);
                } else {
                    TIME_PRE_EPOCH.fetch_add(1, Ordering::Relaxed);
                }
            }
            useful += 1;
            out.rows.push(RawReport {
                link: link.clone(),
                pid,
                streaming,
                report_ms,
                arrival_ms,
            });
        }
    }
    if useful == 0 && out.faults.is_empty() {
        out.faults.push(Evidence::NoMatchingReport {
            kind: NoMatchKind::NoCm400Report,
        });
    }
    out
}

/// `GetSymbolicLink` is a caller-buffered two-call API. Ask for 512 wide chars, and if the
/// device claims it needed more, ask again with room for exactly that.
unsafe fn read_symbolic_link(
    report: &windows::Win32::Media::MediaFoundation::IMFSensorActivityReport,
) -> Option<String> {
    let mut buf = vec![0u16; 512];
    let mut written = 0u32;
    if report.GetSymbolicLink(&mut buf, &mut written).is_err() {
        return None;
    }
    let need = written as usize;
    if need + 1 > buf.len() {
        buf = vec![0u16; need + 1];
        written = 0;
        if report.GetSymbolicLink(&mut buf, &mut written).is_err() {
            return None;
        }
    }
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(String::from_utf16_lossy(&buf[..end]))
}

#[implement(IMFSensorActivitiesReportCallback)]
struct CallbackInner {
    sink: Arc<Mutex<Sink>>,
}

/// Implemented for the identity type the macro generates (`CallbackInner_Impl`), not for
/// `CallbackInner`.
///
/// Worth stating because the macro's own documentation example writes the impl on the user
/// type, and that example is `rust,ignore` - it is not compile-checked. With windows 0.58 +
/// windows-implement 0.58 the vtable is instantiated as `Self` inside the generated identity
/// type, so the `_Impl` bound is required there; writing it on `CallbackInner` fails with
/// "the trait `..._Impl` is not implemented for `CallbackInner_Impl`". Field access goes
/// through the generated `Deref`, so the body still reads the Rust-side struct.
impl IMFSensorActivitiesReportCallback_Impl for CallbackInner_Impl {
    fn OnActivitiesReport(
        &self,
        report: Option<&IMFSensorActivitiesReport>,
    ) -> windows::core::Result<()> {
        // Read first, share second: no COM call happens while the mutex is held, so a
        // re-entrant delivery cannot deadlock against itself.
        let parsed = match report {
            Some(coll) => unsafe { parse_collection(coll, callback_clock_ms()) },
            None => Parsed {
                rows: Vec::new(),
                faults: vec![Evidence::NoMatchingReport {
                    kind: NoMatchKind::EmptyCollection,
                }],
            },
        };
        // A poisoned lock means somebody panicked while publishing; the evidence is still
        // worth keeping, so recover rather than silently drop (same rule as `drain`).
        let mut sink = self.sink.lock().unwrap_or_else(|e| e.into_inner());
        sink.publish(parsed);
        drop(sink);
        // Never propagate a failure into FrameServer's delivery loop.
        Ok(())
    }
}

/// Turns a pid into `(pid, created_ms)`, and knows when to ask again.
///
/// The rule that makes PID reuse safe to talk about: a cached creation time is reused only
/// while that pid is believed to be streaming. Once we have taken the pid out of the live
/// set (explicit stop, or it disappeared), the next TRUE forces a fresh query - which is
/// precisely the window in which the kernel could have handed the pid to another process.
/// If the query fails (exited already, or the account cannot open it) the instance is
/// marked unresolved, and `sam_view` refuses to let an unresolved instance produce a stop.
pub struct IdentityResolver<F: FnMut(u32) -> ProcProbe> {
    cache: HashMap<u32, u64>,
    live: HashSet<u32>,
    lookup: F,
}

impl<F: FnMut(u32) -> ProcProbe> IdentityResolver<F> {
    pub fn new(lookup: F) -> Self {
        IdentityResolver {
            cache: HashMap::new(),
            live: HashSet::new(),
            lookup,
        }
    }

    pub fn resolve(&mut self, pid: u32, streaming: bool) -> ProcInstance {
        // A cached creation time is trusted only while this pid is believed to be streaming.
        // Anything else re-queries - including the "live but no cached value" case, which is
        // what a transient OpenProcess failure leaves behind. Falling back to `unresolved`
        // forever there would be conservative but would also mean the identity never recovers
        // within a long stream.
        let cached = if self.live.contains(&pid) {
            self.cache.get(&pid).copied()
        } else {
            None
        };
        let known = match cached {
            Some(created) => Some(created),
            None => {
                let probe = (self.lookup)(pid);
                match probe.created_ms {
                    Some(created) => {
                        self.cache.insert(pid, created);
                        Some(created)
                    }
                    None => {
                        // Could not confirm it: drop any stale claim so we never attribute a
                        // stop to a creation time we can no longer verify.
                        self.cache.remove(&pid);
                        None
                    }
                }
            }
        };
        if streaming {
            self.live.insert(pid);
        } else {
            self.live.remove(&pid);
        }
        match known {
            // The probe measured a creation time, so the identity is tagged with that source.
            // A sequence number must never arrive through this path.
            Some(created) => ProcInstance::from_creation_time(pid, created),
            None => ProcInstance::unresolved(pid),
        }
    }

    /// A process that is gone can never be "live" again under the same identity.
    pub fn forget(&mut self, pid: u32) {
        self.live.remove(&pid);
    }

    pub fn live_pids(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self.live.iter().copied().collect();
        v.sort_unstable();
        v
    }
}

/// How many identity probes have run, and how many failed to yield a creation time.
/// Process-wide because the beat line reads it from the pipeline while the probes run on the
/// control-loop thread; both are counts of observations, never of decisions.
static IDENTITY_PROBES: AtomicU64 = AtomicU64::new(0);
static IDENTITY_UNRESOLVED: AtomicU64 = AtomicU64::new(0);

/// Reports whose `GetReportTime` succeeded but whose value cannot be placed in the unix domain:
/// a literally empty FILETIME versus a non-zero pre-1970 one. Observation only - the row is still
/// published, and attribution refuses it as `UnusableReportTime` rather than guessing a side.
static TIME_RAW_ZERO: AtomicU64 = AtomicU64::new(0);
static TIME_PRE_EPOCH: AtomicU64 = AtomicU64::new(0);

/// `(empty_filetime, pre_epoch_filetime)` report rows seen since service start.
pub fn report_time_stats() -> (u64, u64) {
    (
        TIME_RAW_ZERO.load(Ordering::Relaxed),
        TIME_PRE_EPOCH.load(Ordering::Relaxed),
    )
}

/// Where the identity probe stopped, the Win32 error at that stage, and whether the process
/// was there at all.
///
/// All three are needed: "could not resolve the creator" collapses four different facts -
/// access denied, process already gone, `GetProcessTimes` refused, timestamp before the epoch
/// - into one line, and only the first two are a security-relevant difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProbeStage {
    Created,
    OpenFailed,
    TimesFailed,
    PreEpoch,
    ProcessGone,
}

impl ProbeStage {
    pub fn code(self) -> u32 {
        match self {
            ProbeStage::Created => 0,
            ProbeStage::OpenFailed => 1,
            ProbeStage::TimesFailed => 2,
            ProbeStage::PreEpoch => 3,
            ProbeStage::ProcessGone => 4,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ProcProbe {
    pub created_ms: Option<u64>,
    pub stage: ProbeStage,
    pub win32: u32,
    pub alive: bool,
}

impl ProcProbe {
    pub fn ok(&self) -> bool {
        self.created_ms.is_some()
    }
}

/// Does this pid exist right now, without needing any access right?
///
/// A failed `OpenProcess` alone cannot tell "denied" from "already exited", and those two
/// lead to opposite conclusions (a permission problem versus a race we should not treat as a
/// fault). The snapshot walk needs no handle to the target, so it works under `LocalService`.
fn process_exists(pid: u32) -> bool {
    unsafe {
        let snap = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut found = false;
        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                if entry.th32ProcessID == pid {
                    found = true;
                    break;
                }
                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
        found
    }
}

/// Production lookup: the creation time of `pid`, or the precise stage where that failed.
fn probe_created_ms(pid: u32) -> ProcProbe {
    unsafe {
        let alive = process_exists(pid);
        let handle: HANDLE = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => h,
            Err(_) => {
                // Read it immediately: any later call would overwrite the code we care about.
                let e = GetLastError().0;
                return ProcProbe {
                    created_ms: None,
                    stage: if alive {
                        ProbeStage::OpenFailed
                    } else {
                        ProbeStage::ProcessGone
                    },
                    win32: e,
                    alive,
                };
            }
        };
        if handle.is_invalid() {
            let e = GetLastError().0;
            return ProcProbe {
                created_ms: None,
                stage: if alive {
                    ProbeStage::OpenFailed
                } else {
                    ProbeStage::ProcessGone
                },
                win32: e,
                alive,
            };
        }
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        let r = GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user);
        let times_err = if r.is_err() { GetLastError().0 } else { 0 };
        let _ = CloseHandle(handle); // never cache a process handle
        if r.is_err() {
            return ProcProbe {
                created_ms: None,
                stage: ProbeStage::TimesFailed,
                win32: times_err,
                alive: true,
            };
        }
        let ms = filetime_to_unix_ms(creation.dwLowDateTime, creation.dwHighDateTime);
        if ms == 0 {
            // A zero result is not "created at the epoch": it is either an uninitialised
            // FILETIME or a pre-1970 stamp. Either way it cannot carry instance identity.
            return ProcProbe {
                created_ms: None,
                stage: ProbeStage::PreEpoch,
                win32: 0,
                alive: true,
            };
        }
        ProcProbe {
            created_ms: Some(ms),
            stage: ProbeStage::Created,
            win32: 0,
            alive: true,
        }
    }
}

/// `probe_created_ms` plus one structured log line per distinct (pid, stage), so the
/// diagnosis is available in the production log without flooding it.
///
/// Runs on the control-loop thread (`drain`), never on the callback thread.
fn probe_and_log(pid: u32) -> ProcProbe {
    use std::collections::{HashMap, HashSet};
    use std::sync::{OnceLock, RwLock};
    static SEEN: OnceLock<RwLock<HashSet<(u32, u32)>>> = OnceLock::new();
    let probe = probe_created_ms(pid);
    IDENTITY_PROBES.fetch_add(1, Ordering::Relaxed);
    if !probe.ok() {
        IDENTITY_UNRESOLVED.fetch_add(1, Ordering::Relaxed);
        let key = (pid, probe.stage.code());
        let seen = SEEN.get_or_init(|| RwLock::new(HashSet::new()));
        let first = {
            let mut g = seen.write().unwrap_or_else(|p| p.into_inner());
            g.insert(key)
        };
        if first {
            crate::log(&format!(
                "sam identity: pid={} stage={:?} win32={} alive={} access=PROCESS_QUERY_LIMITED_INFORMATION(0x{:X}) unresolved={} of {}",
                pid,
                probe.stage,
                probe.win32,
                probe.alive,
                PROCESS_QUERY_LIMITED_INFORMATION.0,
                IDENTITY_UNRESOLVED.load(Ordering::Relaxed),
                IDENTITY_PROBES.load(Ordering::Relaxed)
            ));
        }
        // Cross-check the alternative instance source, which needs no handle to the target.
        // Throttled **per pid** (not globally): a global gate would always sample whichever
        // pid came first in the batch, so "each reported pid has its own instance identity"
        // could never be observed. Log only - it never reaches the arbiter.
        static ALT_LAST: OnceLock<RwLock<HashMap<u32, u64>>> = OnceLock::new();
        let now = callback_clock_ms();
        let due = {
            let m = ALT_LAST.get_or_init(|| RwLock::new(HashMap::new()));
            let mut g = m.write().unwrap_or_else(|p| p.into_inner());
            let prev = g.get(&pid).copied().unwrap_or(0);
            if now.saturating_sub(prev) >= 5_000 {
                g.insert(pid, now);
                true
            } else {
                false
            }
        };
        if due {
            match crate::proc_identity::take() {
                Ok(snap) => match snap.find(pid) {
                    Some(id) => crate::log(&format!(
                        "sam identity(alt=SystemBasicProcessInformation): pid={} present=true sequence={} primary=OpenProcess win32={} processes={} return_len={} toolhelp={} drift={}+{}",
                        pid,
                        id.sequence,
                        probe.win32,
                        snap.identities.len(),
                        snap.return_len,
                        snap.toolhelp_count,
                        snap.only_in_snapshot,
                        snap.only_in_toolhelp
                    )),
                    None => crate::log(&format!(
                        "sam identity(alt=SystemBasicProcessInformation): pid={} present=no-in-snapshot processes={} primary=OpenProcess win32={}",
                        pid,
                        snap.identities.len(),
                        probe.win32
                    )),
                },
                Err(e) => crate::log(&format!(
                    "sam identity(alt=SystemBasicProcessInformation): pid={} unavailable err={:?} primary=OpenProcess win32={}",
                    pid, e, probe.win32
                )),
            }
        }
    }
    probe
}

/// Totals for the beat line: identity probes attempted, and how many stayed unresolved.
/// The denominator matters as much as the failure count, or "31/31" cannot be re-derived.
pub fn identity_stats() -> (u64, u64) {
    (
        IDENTITY_PROBES.load(Ordering::Relaxed),
        IDENTITY_UNRESOLVED.load(Ordering::Relaxed),
    )
}

/// Enumerate MF capture devices and return the CM400's **full** symbolic link.
///
/// Discovery by fragment (identical to the verified capture probe), then every comparison is
/// whole-string: the arbiter must never be handed a substring as its identity.
pub fn discover_cm400_link() -> Result<String, i32> {
    unsafe {
        // A throwaway apartment on the caller's thread, torn down before returning.
        let co = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        if co.is_err() {
            return Err(co.0);
        }
        if MFStartup(MF_VERSION, 0).is_err() {
            CoUninitialize();
            return Err(-1);
        }
        let out = enumerate_link();
        let _ = MFShutdown();
        CoUninitialize();
        out
    }
}

unsafe fn enumerate_link() -> Result<String, i32> {
    let mut attrs_opt: Option<windows::Win32::Media::MediaFoundation::IMFAttributes> = None;
    MFCreateAttributes(&mut attrs_opt, 2).map_err(|e| e.code().0)?;
    let attrs = attrs_opt.ok_or(-1)?;
    attrs
        .SetGUID(
            &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
            &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID,
        )
        .map_err(|e| e.code().0)?;
    let mut devices: *mut Option<windows::Win32::Media::MediaFoundation::IMFActivate> =
        std::ptr::null_mut();
    let mut count = 0u32;
    MFEnumDeviceSources(&attrs, &mut devices, &mut count).map_err(|e| e.code().0)?;
    if devices.is_null() {
        return Err(-2);
    }
    let mut found: Option<String> = None;
    for i in 0..count as usize {
        let act = match (*devices.add(i)).as_ref() {
            Some(a) => a.clone(),
            None => continue,
        };
        let a: windows::Win32::Media::MediaFoundation::IMFAttributes = match act.cast() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let mut pw = PWSTR::null();
        let mut len = 0u32;
        if a.GetAllocatedString(
            &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK,
            &mut pw,
            &mut len,
        )
        .is_err()
            || pw.is_null()
        {
            continue;
        }
        let link = pw.display().to_string();
        CoTaskMemFree(Some(pw.as_ptr() as *const c_void));
        if link.to_ascii_lowercase().contains(CM400_LINK_FRAGMENT) {
            found = Some(link);
            break;
        }
    }
    found.ok_or(-3)
}

/// Attempts allowed after an explicit create/`Start` failure, and the backoff between them.
///
/// Design §5 promises "有限次重试（60s 退避）" but never fixed the count, so 5 is declared here
/// as a **candidate** and reported for review rather than presented as reviewed truth. The
/// backoff is the design's own 60 s.
const MAX_MONITOR_ATTEMPTS: u32 = 5;
const RETRY_BACKOFF_MS: u64 = 60_000;

/// How long a service stop may wait for the monitor thread.
///
/// The thread polls its stop flag every 200 ms, so 2 s is generous for a healthy one. Past
/// that we log the failure and let the thread run out its own COM teardown: releasing
/// `IMFSensorActivityMonitor` / the callback from a different apartment would be a worse bug
/// than a service that stopped slowly, and an unbounded `join()` hands a COM call the power to
/// stall service shutdown.
const SHUTDOWN_WAIT_MS: u64 = 2_000;

/// Push one piece of evidence from the worker thread (never from the callback's critical
/// section, which has its own path through `Sink::publish`).
fn publish(sink: &Arc<Mutex<Sink>>, ev: Evidence) {
    let mut s = sink.lock().unwrap_or_else(|e| e.into_inner());
    s.extra.push(ev);
}

/// Create and start the monitor. Both COM objects are returned so the caller can release them
/// in the required order, on this thread.
unsafe fn attempt_monitor(
    sink: &Arc<Mutex<Sink>>,
) -> Result<(IMFSensorActivityMonitor, IMFSensorActivitiesReportCallback), MonitorFaultKind> {
    let callback: IMFSensorActivitiesReportCallback = CallbackInner { sink: sink.clone() }.into();
    let monitor = match MFCreateSensorActivityMonitor(&callback) {
        Ok(m) => m,
        Err(e) => return Err(MonitorFaultKind::CreateFailed(e.code().0)),
    };
    if let Err(e) = monitor.Start() {
        return Err(MonitorFaultKind::StartFailed(e.code().0));
    }
    Ok((monitor, callback))
}

/// Sleep out the retry backoff in slices, so a service stop is never held for a full minute.
/// `false` means stop was requested and the retry loop must exit.
fn wait_or_stop(stop: &AtomicBool, ms: u64) -> bool {
    let mut left = ms;
    while left > 0 {
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        let slice = left.min(200);
        std::thread::sleep(std::time::Duration::from_millis(slice));
        left -= slice;
    }
    !stop.load(Ordering::Relaxed)
}

/// The monitor, on its own apartment thread.
pub struct SensorActivitySource {
    target_link: String,
    sink: Arc<Mutex<Sink>>,
    stop: Arc<AtomicBool>,
    /// Set by the worker while a started monitor is held, cleared when it tears down. This is
    /// how "the monitor is alive" is reported - not by a forged evidence item.
    started: Arc<AtomicBool>,
    faults: Arc<AtomicU64>,
    worker: Option<JoinHandle<()>>,
    ids: IdentityResolver<Box<dyn FnMut(u32) -> ProcProbe + Send>>,
    drained_dropped: u64,
}

impl SensorActivitySource {
    /// Production constructor. Failures here are *not* fatal to the service: the caller
    /// keeps the heartbeat-only path, which is exactly today's behaviour.
    pub fn start(target_link: String) -> Self {
        Self::with_lookup(target_link, Box::new(probe_and_log))
    }

    fn with_lookup(target_link: String, lookup: Box<dyn FnMut(u32) -> ProcProbe + Send>) -> Self {
        let sink = Arc::new(Mutex::new(Sink::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let started = Arc::new(AtomicBool::new(false));
        let faults = Arc::new(AtomicU64::new(0));
        let worker = {
            let sink = sink.clone();
            let stop = stop.clone();
            let started = started.clone();
            let faults = faults.clone();
            std::thread::spawn(move || run_worker(sink, stop, started, faults))
        };
        SensorActivitySource {
            target_link,
            sink,
            stop,
            started,
            faults,
            worker: Some(worker),
            ids: IdentityResolver::new(lookup),
            drained_dropped: 0,
        }
    }

    /// Pull everything since the last call. Runs on the control-loop thread, never on the
    /// callback thread - that is where `OpenProcess` is allowed to happen.
    pub fn drain(&mut self) -> Vec<Evidence> {
        let (raw, extra, dropped) = {
            let mut s = match self.sink.lock() {
                Ok(s) => s,
                Err(poisoned) => poisoned.into_inner(),
            };
            let raw: Vec<RawReport> = s.raw.drain(..).collect();
            let extra = std::mem::take(&mut s.extra);
            let dropped = std::mem::take(&mut s.dropped);
            (raw, extra, dropped)
        };
        self.drained_dropped = self.drained_dropped.saturating_add(dropped);
        let mut out = extra;
        for r in raw {
            if !link_is_cm400(&self.target_link, &r.link) {
                out.push(Evidence::UnmatchedReport {
                    link: r.link,
                    pid: r.pid,
                });
                continue;
            }
            let inst = self.ids.resolve(r.pid, r.streaming);
            out.push(if r.streaming {
                Evidence::PidStreaming {
                    inst,
                    report_ms: r.report_ms,
                    arrival_ms: r.arrival_ms,
                }
            } else {
                Evidence::PidStopped {
                    inst,
                    report_ms: r.report_ms,
                    arrival_ms: r.arrival_ms,
                }
            });
        }
        out
    }

    pub fn target_link(&self) -> &str {
        &self.target_link
    }

    /// Reports the callback thread posted but the queue could not hold.
    pub fn queue_dropped(&self) -> u64 {
        self.drained_dropped
    }

    /// Is a started monitor currently held by the worker thread? Reported beside the arbiter
    /// snapshot so the shadow phase can tell "healthy and idle" apart from "never came up" -
    /// without forging a `NoMatchingReport`, which would inflate the very counters we read.
    pub fn monitor_started(&self) -> bool {
        self.started.load(Ordering::Relaxed)
    }

    /// Explicit create/`Start` failures seen by this source, retries included.
    pub fn monitor_faults(&self) -> u64 {
        self.faults.load(Ordering::Relaxed)
    }

    /// Ask the worker to tear down and wait for it **with a bound**: `Stop()` and every COM
    /// release happen on the apartment thread that owns them, and service shutdown never blocks
    /// on a COM call. A timeout is logged, not swallowed.
    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let Some(t) = self.worker.take() else { return };
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_millis(SHUTDOWN_WAIT_MS);
        while !t.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        if t.is_finished() {
            let _ = t.join();
        } else {
            // Deliberately detached. The thread still owns its COM apartment; releasing its
            // objects from here would be the worse bug, so we record the failure and let the
            // owner thread finish its own teardown.
            crate::log(&format!(
                "SAM worker thread did not stop within {SHUTDOWN_WAIT_MS}ms; leaving it to finish \
                 its own COM teardown rather than releasing objects across threads"
            ));
            drop(t);
        }
    }
}

impl Drop for SensorActivitySource {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn run_worker(
    sink: Arc<Mutex<Sink>>,
    stop: Arc<AtomicBool>,
    started: Arc<AtomicBool>,
    faults: Arc<AtomicU64>,
) {
    unsafe {
        let co = CoInitializeEx(None, COINIT_MULTITHREADED);
        // S_FALSE means COM was already initialised on this thread, which is still usable.
        if co.is_err() {
            publish(
                &sink,
                Evidence::MonitorFault {
                    kind: MonitorFaultKind::ComInitFailed(co.0),
                },
            );
            return;
        }
        if MFStartup(MF_VERSION, 0).is_err() {
            publish(
                &sink,
                Evidence::MonitorFault {
                    kind: MonitorFaultKind::ComInitFailed(-2),
                },
            );
            CoUninitialize();
            return;
        }

        // Bounded retry (design §5). Each iteration owns its two COM objects and releases
        // them on this thread, in the order: Stop -> monitor -> callback -> MFShutdown ->
        // CoUninitialize. Nothing is released from another thread, and nothing is left to the
        // scope end after CoUninitialize.
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            match attempt_monitor(&sink) {
                Ok((monitor, callback)) => {
                    started.store(true, Ordering::Relaxed);
                    if attempt > 1 {
                        // A bounded retry brought the backend back. That restores its
                        // *permission* to produce Idle and nothing else: no entry, no window.
                        publish(&sink, Evidence::MonitorRecovered);
                        crate::log(&format!("SAM monitor recovered on retry attempt {attempt}"));
                    }
                    while !stop.load(Ordering::Relaxed) {
                        std::thread::sleep(std::time::Duration::from_millis(200));
                    }
                    started.store(false, Ordering::Relaxed);
                    let _ = monitor.Stop();
                    drop(monitor);
                    drop(callback);
                    break;
                }
                Err(kind) => {
                    faults.fetch_add(1, Ordering::Relaxed);
                    publish(&sink, Evidence::MonitorFault { kind });
                    crate::log(&format!(
                        "SAM monitor attempt {attempt}/{MAX_MONITOR_ATTEMPTS} failed: {kind:?}"
                    ));
                    if attempt >= MAX_MONITOR_ATTEMPTS {
                        publish(
                            &sink,
                            Evidence::MonitorFault {
                                kind: MonitorFaultKind::RetriesExhausted,
                            },
                        );
                        crate::log(
                            "SAM monitor retries exhausted; the heartbeat path is the only \
                             activity source until the service restarts",
                        );
                        break;
                    }
                    if !wait_or_stop(&stop, RETRY_BACKOFF_MS) {
                        break;
                    }
                }
            }
        }
        let _ = MFShutdown();
        CoUninitialize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CM400: &str = "\\\\?\\usb#vid_0603&pid_8612&mi_00#8&2e26e82&0&0000#{e5323777-f976-4f5b-9b55-b94699c46e44}\\global";

    #[test]
    fn filetime_conversion_matches_the_1601_epoch() {
        // 2026-10-11T00:00:00Z as FILETIME, checked against the unix value directly.
        let unix_ms = 1_791_657_600_000u64;
        let ticks = unix_ms * 10_000 + 116_444_736_000_000_000;
        let (low, high) = (ticks as u32, (ticks >> 32) as u32);
        assert_eq!(filetime_to_unix_ms(low, high), unix_ms);
        // A pre-1970 FILETIME must not wrap into a giant timestamp.
        assert_eq!(filetime_to_unix_ms(0, 0), 0);
        // Both shapes of "no placeable time" land on the same sentinel 0, and 0 means exactly
        // that: not a report from 1970. `Ledger::attribute` refuses it as `UnusableReportTime`.
        // One day before the epoch, as a non-zero FILETIME, must not sneak through either.
        let pre_epoch = 116_444_736_000_000_000u64 - 86_400_000_000_000;
        assert_eq!(
            filetime_to_unix_ms(pre_epoch as u32, (pre_epoch >> 32) as u32),
            0
        );
        // The first representable unix millisecond is the epoch itself - still 0, still refused.
        assert_eq!(
            filetime_to_unix_ms(
                116_444_736_000_000_000u64 as u32,
                (116_444_736_000_000_000u64 >> 32) as u32
            ),
            0
        );
        // One millisecond later it becomes usable, so the sentinel cannot be reached by a real
        // contemporary report.
        assert_eq!(
            filetime_to_unix_ms(
                (116_444_736_000_000_000u64 + 10_000) as u32,
                ((116_444_736_000_000_000u64 + 10_000) >> 32) as u32
            ),
            1
        );
    }

    #[test]
    fn symbolic_link_comparison_is_whole_string_not_a_fragment() {
        assert!(link_is_cm400(CM400, CM400));
        assert!(link_is_cm400(CM400, &CM400.to_ascii_uppercase()));
        // Same physical device, different function: must not match.
        assert!(!link_is_cm400(
            CM400,
            "\\\\?\\usb#vid_0603&pid_8612&mi_02#8&2e26e82&0&0002#{e5323777-f976-4f5b-9b55-b94699c46e44}\\global"
        ));
        assert!(!link_is_cm400(CM400, "vid_0603&pid_8612&mi_00"));
        // A different instance path on the same interface text: not the same device either.
        assert!(!link_is_cm400(
            CM400,
            "\\\\?\\usb#vid_0603&pid_8612&mi_00#7&deadbeef&0&0000#{e5323777-f976-4f5b-9b55-b94699c46e44}\\global"
        ));
    }

    /// A successful probe, and a denied one. Both are injected: no test below touches real
    /// Win32, so the resolver rules are checked without a process table or a device.
    fn created(ms: u64) -> ProcProbe {
        ProcProbe {
            created_ms: Some(ms),
            stage: ProbeStage::Created,
            win32: 0,
            alive: true,
        }
    }

    fn denied() -> ProcProbe {
        ProcProbe {
            created_ms: None,
            stage: ProbeStage::OpenFailed,
            win32: 5,
            alive: true,
        }
    }

    /// What `counter` hands back: a resolver plus the cell that counts its calls. Named because the
    /// tuple type is long enough that repeating it hid what the two halves were.
    type CounterProbe = (
        IdentityResolver<Box<dyn FnMut(u32) -> ProcProbe>>,
        Arc<std::sync::atomic::AtomicUsize>,
    );

    /// The lookup is counted so "did it ask again" is an observable assertion.
    fn counter(probes: Vec<ProcProbe>) -> CounterProbe {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut seq = probes.into_iter();
        let probe = calls.clone();
        (
            IdentityResolver::new(Box::new(move |_pid| {
                probe.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                seq.next().unwrap_or_else(denied)
            })),
            calls,
        )
    }

    #[test]
    fn identity_is_cached_while_a_stream_is_live_and_requeried_after_it_ends() {
        let (mut ids, calls) = counter(vec![created(500), denied(), created(900)]);
        // First TRUE: resolved from a fresh query.
        let a = ids.resolve(4994, true);
        assert_eq!(a, ProcInstance::from_creation_time(4994, 500));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        // Continued reports of the same live stream reuse the cache: no second query.
        let b = ids.resolve(4994, true);
        assert_eq!(a, b);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        // Explicit FALSE takes it out of the live set...
        let c = ids.resolve(4994, false);
        assert_eq!(
            c.identity,
            Some(crate::sam_view::IdentityValue::CreationTime(500)),
            "a stopped stream keeps its resolved creation time, tagged as such"
        );
        // ...so the next TRUE forces a fresh query, which is where PID reuse would show up.
        // Here the second query fails, then a third returns a different creation time.
        let d = ids.resolve(4994, true);
        assert_eq!(
            d,
            ProcInstance::unresolved(4994),
            "an unopenable pid is unresolved"
        );
        let e = ids.resolve(4994, true);
        assert_eq!(
            e,
            ProcInstance::from_creation_time(4994, 900),
            "a recycled pid yields a new instance"
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[test]
    fn an_unresolved_pid_never_enters_the_live_set_with_a_stale_identity() {
        let (mut ids, _calls) = counter(vec![denied(), created(700)]);
        assert_eq!(ids.resolve(1111, true), ProcInstance::unresolved(1111));
        assert_eq!(
            ids.live_pids(),
            vec![1111],
            "still counted as a live client"
        );
        // forget() is what a confirmed process exit does; the next TRUE re-queries.
        ids.forget(1111);
        assert!(ids.live_pids().is_empty());
        assert_eq!(
            ids.resolve(1111, true),
            ProcInstance::from_creation_time(1111, 700)
        );
    }

    #[test]
    fn an_empty_collection_is_recorded_as_no_data() {
        // Exercises the parsing decision without a device: build a Sink, run the branch that
        // a GetCount()==0 collection would take, and assert what the arbiter would receive.
        let mut sink = Sink::new();
        sink.extra.push(Evidence::NoMatchingReport {
            kind: NoMatchKind::EmptyCollection,
        });
        let ev = std::mem::take(&mut sink.extra);
        assert_eq!(ev.len(), 1);
        // The clock is always supplied by the caller: this module must not own one.
        let t = 1_000u64;
        let mut a = crate::sam_view::Arbiter::new(
            CM400,
            3_000,
            crate::sam_view::Suppression::Bounded(25_000),
        );
        a.apply(
            t,
            Evidence::PidStreaming {
                inst: ProcInstance::from_creation_time(1, 1),
                report_ms: t,
                arrival_ms: t,
            },
        );
        for e in ev {
            a.apply(t, e);
        }
        // Empty list cannot idle a live client.
        assert_eq!(a.view(t), crate::sam_view::SAMView::Busy);
        assert_eq!(a.telemetry.empty_list, 1);
    }

    #[test]
    fn publishing_happens_without_com_and_keeps_the_bound() {
        // Two report sets, the second larger than the queue: the oldest rows go first, the
        // fault items are kept, and nothing in here needs a device.
        let mut sink = Sink::new();
        let mut first = Parsed::default();
        for i in 0..3u32 {
            first.rows.push(RawReport {
                link: CM400.to_string(),
                pid: i,
                streaming: true,
                report_ms: i as u64,
                arrival_ms: 10_000 + i as u64,
            });
        }
        sink.publish(first);
        assert_eq!(sink.raw.len(), 3);
        // Both clocks survive publication: the arbiter orders by `report_ms` and measures
        // silence by `arrival_ms`, so losing either here would break one of them silently.
        assert_eq!(sink.raw.front().unwrap().arrival_ms, 10_000);
        assert_eq!(sink.raw.front().unwrap().report_ms, 0);
        let mut second = Parsed::default();
        second.faults.push(Evidence::NoMatchingReport {
            kind: NoMatchKind::EmptyCollection,
        });
        for i in 0..(QUEUE_CAPACITY as u32 + 2) {
            second.rows.push(RawReport {
                link: CM400.to_string(),
                pid: 100 + i,
                streaming: false,
                report_ms: i as u64,
                arrival_ms: 20_000 + i as u64,
            });
        }
        sink.publish(second);
        // 3 rows from the first batch + (QUEUE_CAPACITY + 2) from the second, against a cap of
        // QUEUE_CAPACITY: exactly the first five ever-pushed rows are gone.
        assert_eq!(sink.raw.len(), QUEUE_CAPACITY, "the queue stays bounded");
        assert_eq!(sink.dropped, 5, "the oldest evidence is what gets dropped");
        assert_eq!(
            sink.raw.front().unwrap().pid,
            102,
            "first two of batch two also went"
        );
        assert_eq!(
            sink.raw.back().unwrap().pid,
            100 + QUEUE_CAPACITY as u32 + 1
        );
        assert_eq!(
            sink.extra.len(),
            1,
            "faults published in the same batch survive"
        );
    }

    #[test]
    fn the_retry_backoff_never_outlives_a_stop_request() {
        // A service stop must not have to wait out the 60s design backoff.
        let stopping = AtomicBool::new(true);
        let t = std::time::Instant::now();
        assert!(
            !wait_or_stop(&stopping, RETRY_BACKOFF_MS),
            "a pending stop aborts the backoff"
        );
        assert!(
            t.elapsed().as_millis() < 500,
            "and it does so promptly, not after 60s"
        );
        // Without a stop request the full wait elapses and the retry may continue.
        let running = AtomicBool::new(false);
        assert!(wait_or_stop(&running, 300), "no stop -> keep retrying");
    }

    #[test]
    fn a_full_queue_drops_the_oldest_evidence_and_counts_it() {
        let mut sink = Sink::new();
        for i in 0..(QUEUE_CAPACITY as u32 + 5) {
            sink.push(RawReport {
                link: CM400.to_string(),
                pid: i,
                streaming: true,
                report_ms: i as u64,
                arrival_ms: i as u64,
            });
        }
        assert_eq!(sink.raw.len(), QUEUE_CAPACITY, "the queue is bounded");
        assert_eq!(sink.dropped, 5);
        // The survivors are the newest ones: losing an old stop report keeps the lens out,
        // which is the conservative direction.
        assert_eq!(sink.raw.front().unwrap().pid, 5);
    }
}
