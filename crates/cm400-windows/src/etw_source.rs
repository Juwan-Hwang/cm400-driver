//! Production CM400 Windows Activity source: real-time ETW consumer of the
//! MF-FrameServer provider.
//!
//! Signal (W0-C2): MF-FrameServer EventId=10 (opcode 1) fires continuously
//! ONLY while CM400 is actively streaming, and its UserData carries the device
//! symbolic link (vid_0603&pid_8612&mi_00). So Activity is a LIVENESS signal:
//! `Active` while a CM400 heartbeat was seen within `timeout_ms`, else
//! `Inactive`; `Unknown` until the first heartbeat after start (no history
//! replay). We do NOT count sessions (no evidence Id=10 distinguishes clients).
//!
//! The EventRecordCallback is kept minimal: compare provider/id/opcode, do an
//! allocation-free byte scan of UserData for the CM400 identity, and bump an
//! atomic liveness counter. All state math happens in `activity()`.
//!
//! MF-FrameServer registers on demand (not while idle), so a worker retries
//! enabling it until success. Drop tears the session down by name (CloseTrace ->
//! join consumer -> ControlTrace STOP), so a service can be restarted without
//! leaking real-time loggers. Requires elevation.

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH};

use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW,
    CONTROLTRACE_HANDLE, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW,
    EVENT_TRACE_LOGFILEW_0, EVENT_TRACE_LOGFILEW_1, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, PROCESSTRACE_HANDLE, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME,
};

use cm400_core::ActivitySource;
use cm400_policy::{CM400Activity, HeartbeatTracker};

const FRAME_SERVER: GUID = GUID::from_u128(0x9E22A3ED_7B32_4B99_B6C2_21DD6ACE01E1);
const ID_HEARTBEAT: u16 = 10;
const OP_START: u8 = 1;

// Allocation-free identity needles (ASCII + UTF-16LE).
const VID_A: &[u8] = b"0603";
const PID_A: &[u8] = b"8612";
const MI_A: &[u8] = b"mi_00";
const MI_A2: &[u8] = b"MI_00";
const VID_U: &[u8] = &[0x30, 0, 0x36, 0, 0x30, 0, 0x33, 0];
const PID_U: &[u8] = &[0x38, 0, 0x36, 0, 0x31, 0, 0x32, 0];
const MI_U: &[u8] = &[0x6d, 0, 0x69, 0, 0x5f, 0, 0x30, 0, 0x30, 0];
const MI_U2: &[u8] = &[0x4d, 0, 0x49, 0, 0x5f, 0, 0x30, 0, 0x30, 0];

static HB_SEQ: AtomicU64 = AtomicU64::new(0);
// Diagnosis funnel: how far events get through the filters. If a field stops
// incrementing, the bottleneck is the NEXT filter, not the device.
static ALL_TOTAL: AtomicU64 = AtomicU64::new(0); // every event delivered to us
static FS_TOTAL: AtomicU64 = AtomicU64::new(0); // all MF-FrameServer events
static HB_TOTAL: AtomicU64 = AtomicU64::new(0); // Id=10/opcode=1, any device
/// 0 while the consumer is still blocked in ProcessTrace; otherwise the WIN32
/// error ProcessTrace returned (a silent consumer exit explains "no events").
static CONSUMER_EXIT: AtomicI64 = AtomicI64::new(0);
static ENABLED: AtomicBool = AtomicBool::new(false);

/// What the real-time consumer actually sees, for operator-visible logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EtwFunnel {
    pub all_events: u64,
    pub frameserver_events: u64,
    pub heartbeats: u64,
    pub cm400_heartbeats: u64,
    pub provider_enabled: bool,
    pub consumer_exit: i64,
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.len() >= needle.len() && hay.windows(needle.len()).any(|w| w == needle)
}

fn is_cm400(d: &[u8]) -> bool {
    let vid = contains(d, VID_A) || contains(d, VID_U);
    let pid = contains(d, PID_A) || contains(d, PID_U);
    let mi = contains(d, MI_A) || contains(d, MI_A2) || contains(d, MI_U) || contains(d, MI_U2);
    vid && pid && mi
}

unsafe extern "system" fn on_event(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    ALL_TOTAL.fetch_add(1, Ordering::Relaxed);
    let r = &*record;
    let h = r.EventHeader;
    if h.ProviderId != FRAME_SERVER {
        return;
    }
    FS_TOTAL.fetch_add(1, Ordering::Relaxed);
    let d = h.EventDescriptor;
    if d.Id != ID_HEARTBEAT || d.Opcode != OP_START {
        return;
    }
    HB_TOTAL.fetch_add(1, Ordering::Relaxed);
    if r.UserData.is_null() || r.UserDataLength == 0 {
        return;
    }
    let data = std::slice::from_raw_parts(r.UserData as *const u8, r.UserDataLength as usize);
    if is_cm400(data) {
        HB_SEQ.fetch_add(1, Ordering::Relaxed);
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub struct WindowsFrameServerEtwSource {
    trace: PROCESSTRACE_HANDLE,
    /// The leaked wide session name. Real-time loggers are stopped BY NAME with an
    /// initialized EVENT_TRACE_PROPERTIES buffer; passing the StartTrace handle
    /// with NULL name/properties fails with ERROR_INVALID_PARAMETER (87) and leaks
    /// the session, which we measured on a service stop.
    name: &'static [u16],
    tracker: HeartbeatTracker,
    last_seq: u64,
    stop: Arc<AtomicBool>,
    /// The thread blocked in ProcessTrace. It must be joined before stopping the
    /// session, or the stop races a live consumer.
    consumer: Option<JoinHandle<()>>,
    enabler: Option<JoinHandle<()>>,
}

/// Product session name: FIXED, so a killed instance cannot leave an ever-growing
/// pile of PID-named real-time loggers behind. Taking one over is only safe
/// because the caller must hold the process singleton first.
pub const SESSION_NAME: &str = "CM400-Activity";
/// WIN32: a real-time session with this name already exists.
const ERROR_ALREADY_EXISTS: u32 = 183;

/// Stop a real-time logger BY NAME. Requires an initialized properties buffer
/// (`Wnode.BufferSize` + `LoggerNameOffset`); the handle + NULL form is rejected
/// with ERROR_INVALID_PARAMETER (87), which silently leaked the logger.
fn stop_session_by_name(name: &[u16]) -> WIN32_ERROR {
    let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let total = props_size + name.len() * 2 + 8;
    let mut buf = vec![0u8; total];
    let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    unsafe {
        (*props).Wnode.BufferSize = total as u32;
        (*props).Wnode.ClientContext = 2;
        (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*props).LoggerNameOffset = props_size as u32;
        let dst = buf.as_mut_ptr().add(props_size) as *mut u16;
        std::ptr::copy_nonoverlapping(name.as_ptr(), dst, name.len());
        ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(name.as_ptr()),
            props,
            EVENT_TRACE_CONTROL_STOP,
        )
    }
}

impl WindowsFrameServerEtwSource {
    /// The product activity source. Callers must own the process singleton first,
    /// otherwise a takeover could stop a live sibling's logger.
    pub fn new(timeout_ms: u64) -> Result<Self, i32> {
        let name = format!("{SESSION_NAME}\0");
        Self::open(&name, timeout_ms, true)
    }

    /// Diagnostics (`cm400ctl activity-watch`): a uniquely named session that
    /// never touches the product logger, so observation can run beside the
    /// service instead of fighting it for the name.
    pub fn for_diagnostics(timeout_ms: u64) -> Result<Self, i32> {
        let name = format!("CM400-Diag-{}\0", std::process::id());
        Self::open(&name, timeout_ms, false)
    }

    fn open(name_nul: &str, timeout_ms: u64, takeover: bool) -> Result<Self, i32> {
        let name_wide: Vec<u16> = name_nul.encode_utf16().collect();
        // Leak the name buffer: it must outlive ProcessTrace (LoggerName points at it).
        let name_leak: &'static mut [u16] = Box::leak(name_wide.into_boxed_slice());

        let session = unsafe {
            let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
            let name_bytes = name_leak.len() * 2;
            let mut buf = vec![0u8; props_size + name_bytes + 8];
            let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
            (*props).Wnode.BufferSize = (props_size + name_bytes + 8) as u32;
            (*props).Wnode.ClientContext = 2;
            (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            (*props).FlushTimer = 1;
            (*props).MinimumBuffers = 32;
            (*props).LoggerNameOffset = props_size as u32;
            let dst = buf.as_mut_ptr().add(props_size) as *mut u16;
            std::ptr::copy_nonoverlapping(name_leak.as_ptr(), dst, name_leak.len());

            let mut h = CONTROLTRACE_HANDLE::default();
            let mut e = StartTraceW(&mut h, PCWSTR(name_leak.as_ptr()), props);
            if e.0 == ERROR_ALREADY_EXISTS && takeover {
                // We hold the singleton, so a logger under our fixed name can only
                // be one a dead instance left behind: reclaim it and retry.
                crate::log("stale ETW session under our name; taking over");
                let _ = stop_session_by_name(name_leak);
                let mut h2 = CONTROLTRACE_HANDLE::default();
                e = StartTraceW(&mut h2, PCWSTR(name_leak.as_ptr()), props);
                h = h2;
            }
            if e != WIN32_ERROR(0) {
                return Err(e.0 as i32);
            }
            h
        };

        let trace = unsafe {
            let mut logfile = EVENT_TRACE_LOGFILEW {
                LoggerName: PWSTR(name_leak.as_mut_ptr()),
                Anonymous1: EVENT_TRACE_LOGFILEW_0 {
                    ProcessTraceMode: PROCESS_TRACE_MODE_REAL_TIME
                        | PROCESS_TRACE_MODE_EVENT_RECORD,
                },
                Anonymous2: EVENT_TRACE_LOGFILEW_1 {
                    EventRecordCallback: Some(on_event),
                },
                ..std::mem::zeroed()
            };
            let th = OpenTraceW(&mut logfile);
            if th.Value == u64::MAX {
                return Err(-1);
            }
            th
        };

        let stop = Arc::new(AtomicBool::new(false));

        // Consumer thread: ProcessTrace blocks until CloseTrace.
        let consumer = {
            let th = trace;
            std::thread::spawn(move || unsafe {
                let err = ProcessTrace(&[th], None, None);
                CONSUMER_EXIT.store(err.0 as i64, Ordering::Relaxed);
            })
        };
        // Enabler thread: MF-FrameServer registers on demand; retry until enabled.
        let enabler = {
            let s = session;
            let stop = stop.clone();
            std::thread::spawn(move || {
                while !ENABLED.load(Ordering::Relaxed) && !stop.load(Ordering::Relaxed) {
                    let e = unsafe {
                        EnableTraceEx2(
                            s,
                            &FRAME_SERVER,
                            1, /*ENABLE_PROVIDER*/
                            5,
                            u64::MAX,
                            0,
                            0,
                            None,
                        )
                    };
                    if e == WIN32_ERROR(0) {
                        ENABLED.store(true, Ordering::Relaxed);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(2000));
                }
            })
        };

        Ok(WindowsFrameServerEtwSource {
            trace,
            name: name_leak,
            tracker: HeartbeatTracker::new(timeout_ms),
            last_seq: 0,
            stop,
            consumer: Some(consumer),
            enabler: Some(enabler),
        })
    }

    /// Debug: age (ms) since the last CM400 heartbeat, if any.
    pub fn age_ms(&self) -> Option<u64> {
        self.tracker.age_ms(now_ms())
    }
    pub fn timeout_ms(&self) -> u64 {
        self.tracker.timeout_ms()
    }
    pub fn provider_enabled(&self) -> bool {
        ENABLED.load(Ordering::Relaxed)
    }

    /// Snapshot of the consume funnel (cumulative counters since start).
    pub fn funnel(&self) -> EtwFunnel {
        EtwFunnel {
            all_events: ALL_TOTAL.load(Ordering::Relaxed),
            frameserver_events: FS_TOTAL.load(Ordering::Relaxed),
            heartbeats: HB_TOTAL.load(Ordering::Relaxed),
            cm400_heartbeats: HB_SEQ.load(Ordering::Relaxed),
            provider_enabled: self.provider_enabled(),
            consumer_exit: CONSUMER_EXIT.load(Ordering::Relaxed),
        }
    }
}

impl ActivitySource for WindowsFrameServerEtwSource {
    fn activity(&mut self) -> CM400Activity {
        let now = now_ms();
        let seq = HB_SEQ.load(Ordering::Relaxed);
        if seq != self.last_seq {
            self.tracker.note(now);
            self.last_seq = seq;
        }
        self.tracker.state(now)
    }
}

impl Drop for WindowsFrameServerEtwSource {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        unsafe {
            let _ = CloseTrace(self.trace);
        }
        if let Some(t) = self.consumer.take() {
            let _ = t.join();
        }
        // Stop by name with a sized properties buffer (handle + NULLs is rejected).
        let r = stop_session_by_name(self.name);
        // Never swallow this: a leaked real-time session is invisible in the log
        // otherwise, and a service gets started/stopped many times.
        if r != WIN32_ERROR(0) {
            crate::log(&format!(
                "ETW session '{}' stop FAILED err={} (logger left running)",
                String::from_utf16_lossy(self.name).trim_end_matches('\0'),
                r.0
            ));
        } else {
            crate::log("ETW real-time session stopped");
        }
        let _ = self.enabler.take();
    }
}
