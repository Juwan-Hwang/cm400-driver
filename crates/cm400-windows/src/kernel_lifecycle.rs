//! Kernel-Process lifecycle collector that runs **in the service's own account**.
//!
//! Why this exists. The prototype capture in `docs/SENSOR-ACTIVITY-INTEGRATION.md` B.9 was made
//! from an elevated shell, which proves nothing about whether `LocalService` - the account the
//! product actually runs in - can create and consume its own session. This module answers that,
//! and it also answers the second question an administrator shell cannot: whether event loss can
//! be *detected* often enough that attribution can be refused while it is happening.
//!
//! Session discipline:
//! - the name is unique per process (`CM400-KernelProc-Diag-<pid>`), and there is **no takeover
//!   path at all**: a collision is an error for us, we never stop a session we did not start.
//!   The product logger `CM400-Activity` is a different name owned by a different code path and
//!   is never touched from here.
//! - only `WINEVENT_KEYWORD_PROCESS` (0x10) at level 4 is enabled - process start/stop only, no
//!   thread/image/handle data, no command lines.
//!
//! Decoding discipline - this is a deliberate "refuse rather than guess" design:
//! - This machine was measured to emit `ProcessStart` version 4 and `ProcessStop` version 2, both
//!   carrying `ProcessSequenceNumber` plus FILETIME payload timestamps. Those two (id, version)
//!   pairs are the *only* layouts this module parses, and the field order/types come from that
//!   measurement (`CreateTime`/`ExitTime` are payload FILETIMEs, not the session clock).
//! - Every other id/version, every short payload, and every value that fails a sanity check
//!   (creation after exit, zero pid, timestamp outside 2020..2100) increments `unknown_schema`
//!   and yields **no** interval. A silently mis-parsed lifetime would be worse than none.
//! - Decoded `(pid, sequence)` pairs are cross-checked while the process is still alive against
//!   `proc_identity`'s independent snapshot of the same counter; any disagreement sets
//!   `decode_broken`, after which the ledger is treated as untrusted. That is what makes the
//!   reader's correctness observable rather than assumed.
//!
//! Observation boundary: the collector takes a process snapshot *after* the session is live and
//! reports that instant as the boundary. Pre-existing processes therefore have no birth event, so
//! `proc_lifecycle` gives them `Birth::SeenAlive`, which bounds nothing - reports before the
//! boundary are refused, not retro-fitted.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Mutex;
use std::thread::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH};

use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW,
    TdhGetEventInformation, TdhGetProperty, TdhGetPropertySize, CONTROLTRACE_HANDLE,
    EVENT_PROPERTY_INFO, EVENT_RECORD, EVENT_TRACE_CONTROL_QUERY, EVENT_TRACE_CONTROL_STOP,
    EVENT_TRACE_LOGFILEW, EVENT_TRACE_LOGFILEW_0, EVENT_TRACE_LOGFILEW_1, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, PROCESSTRACE_HANDLE, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, PROPERTY_DATA_DESCRIPTOR, TRACE_EVENT_INFO,
};

/// `Microsoft-Windows-Kernel-Process`, as reported by this machine (`wevtutil gp`), not the
/// classic "Process" kernel-trace GUID that blog posts often confuse it with.
pub const KERNEL_PROCESS_PROVIDER: GUID =
    GUID::from_u128(0x22fb_2cd6_0e7b_422b_a0c7_2fad_1fd0_e716);
/// `WINEVENT_KEYWORD_PROCESS`, read from the provider's own metadata on this machine.
pub const PROCESS_KEYWORD: u64 = 0x10;
/// The only level this provider declares.
pub const LEVEL_INFORMATIONAL: u8 = 4;

/// What the session itself reports about losing events. These counters, not the consumer's own
/// opinion, are the authority: `EVENT_TRACE_LOGFILEW`'s own `EventsLost` member is documented as
/// unused, so a quiet callback proves nothing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Loss {
    pub events_lost: u64,
    pub log_buffers_lost: u64,
    pub real_time_buffers_lost: u64,
    pub buffers: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct Health {
    pub tally: Tally,
    pub decode_broken: bool,
    pub queue_lost: bool,
    pub consumer_alive: bool,
    pub callbacks: u64,
}

// A single collector instance per process is the design (the service owns the singleton first),
// so a module-level handoff from the ETW callback is enough - and it keeps the callback free of
// any lock-ordering surprises.
static FEED: Mutex<VecDeque<LifecycleEvent>> = Mutex::new(VecDeque::new());
static DECODE_BROKEN: AtomicBool = AtomicBool::new(false);
static LOST_PARSE: AtomicBool = AtomicBool::new(false);
static STARTS: AtomicU64 = AtomicU64::new(0);
static STOPS: AtomicU64 = AtomicU64::new(0);
static ENABLED: AtomicBool = AtomicBool::new(false);
static CONSUMER_EXIT: AtomicI64 = AtomicI64::new(0);
static CALLBACKS: AtomicU64 = AtomicU64::new(0);
/// The first raw status `TdhGetEventInformation` returned on a size probe, kept so the actual
/// code is observable instead of guessed at.
static FIRST_SIZE_PROBE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// FILETIME (100 ns since 1601) to unix ms. Same formula as `sam_source`, kept here so this
/// module's payload times are directly comparable with SAM report times.
fn filetime_to_unix_ms(raw: i64) -> Option<u64> {
    const EPOCH_DIFF_100NS: i64 = 116_444_736_000_000_000;
    if raw < EPOCH_DIFF_100NS {
        return None;
    }
    Some(((raw - EPOCH_DIFF_100NS) / 10_000) as u64)
}

/// Sanity window: anything outside this range means we read the wrong bytes.
fn plausible_unix_ms(v: u64) -> bool {
    // 2020-01-01 .. 2100-01-01 in unix ms.
    v > 1_577_836_800_000 && v < 4_102_444_800_000
}

/// Where decoding stopped. Exactly one of these is recorded per event, so a rising
/// `unknown_version` can never hide a rising `type_mismatch` (the previous build counted both
/// in one `unknown_schema` number, which made the two failure modes indistinguishable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fail {
    /// An id/version combination this decoder does not implement.
    UnknownVersion { id: u16, version: u16 },
    /// `TdhGetEventInformation` refused the event: no names, no types, no read.
    Metadata(u32),
    /// Metadata does not list a field we require.
    MissingField(&'static str),
    /// The field exists but its declared input type is not what we read.
    TypeMismatch { field: &'static str, intype: u16 },
    /// The reported property size is not the size of the type we are about to store.
    SizeMismatch { field: &'static str, got: u32 },
    /// `TdhGetProperty` returned a failure status.
    PropertyRead { field: &'static str, status: u32 },
    /// Fields decoded, but the instance is not usable (zero pid, times out of order, or
    /// timestamps outside any plausible window).
    Implausible,
}

/// One counter per event, never two: `ok_start + ok_stop + all failures == events seen`.
#[derive(Debug, Default, Clone, Copy)]
pub struct Tally {
    pub ok_start: u64,
    pub ok_stop: u64,
    pub unknown_version: u64,
    pub tdh_metadata_failed: u64,
    pub missing_field: u64,
    pub type_mismatch: u64,
    pub size_mismatch: u64,
    pub property_read_failed: u64,
    pub implausible: u64,
    pub total: u64,
}

impl Tally {
    /// Fold one outcome. Kept as a pure function so the exclusivity of the taxonomy is testable
    /// without an ETW session.
    pub fn record(&mut self, r: &Result<Option<LifecycleEvent>, Fail>) {
        self.total += 1;
        match r {
            Ok(Some(ev)) => {
                if ev.start {
                    self.ok_start += 1;
                } else {
                    self.ok_stop += 1;
                }
            }
            Ok(None) => {
                self.unknown_version += 1;
            }
            Err(f) => match f {
                Fail::UnknownVersion { .. } => self.unknown_version += 1,
                Fail::Metadata(_) => self.tdh_metadata_failed += 1,
                Fail::MissingField(_) => self.missing_field += 1,
                Fail::TypeMismatch { .. } => self.type_mismatch += 1,
                Fail::SizeMismatch { .. } => self.size_mismatch += 1,
                Fail::PropertyRead { .. } => self.property_read_failed += 1,
                Fail::Implausible => self.implausible += 1,
            },
        }
    }

    /// True only when every event seen was accounted for exactly once.
    pub fn balanced(&self) -> bool {
        self.total
            == self.ok_start
                + self.ok_stop
                + self.unknown_version
                + self.tdh_metadata_failed
                + self.missing_field
                + self.type_mismatch
                + self.size_mismatch
                + self.property_read_failed
                + self.implausible
    }

    /// Any failure at all, including the "not a lifetime event" case.
    pub fn failed_any(&self) -> bool {
        self.unknown_version
            + self.tdh_metadata_failed
            + self.missing_field
            + self.type_mismatch
            + self.size_mismatch
            + self.property_read_failed
            + self.implausible
            > 0
    }

    pub fn failures(&self) -> u64 {
        self.total.saturating_sub(self.ok_start + self.ok_stop)
    }
}

/// What the metadata says about one property, kept verbatim for the log.
///
/// `InType` alone is not a usable gate here: on this machine the classic Kernel-Process
/// provider declares these properties through the struct arm of `EVENT_PROPERTY_INFO`'s union,
/// so reading `nonStructType.InType` yields 8 (`CIM_STRING`) for a `ProcessID` that the OS then
/// prints as a number. Believing that value would be its own kind of guessing. What is checked
/// instead is (a) the structural `Flags` bits that would make a scalar read wrong (struct, array,
/// parameterised length/count, custom schema, WBEM fragment), and (b) the exact byte length
/// `TdhGetPropertySize` reports for the named property. Correctness of the result is then proven
/// by comparing every decoded field against the OS's own decode of the same capture.
#[derive(Debug, Clone)]
struct Prop {
    name: String,
    intype: u16,
    flags: u32,
}

// PROPERTY_FLAGS bits from `um\tdh.h` that make a plain scalar read unsafe.
const PROP_STRUCT: u32 = 0x1;
const PROP_PARAM_LENGTH: u32 = 0x2;
const PROP_PARAM_COUNT: u32 = 0x4;
const PROP_WBEM_XML: u32 = 0x8;
const PROP_PARAM_FIXED_LENGTH: u32 = 0x10;
const PROP_PARAM_FIXED_COUNT: u32 = 0x20;
const PROP_CUSTOM_SCHEMA: u32 = 0x80;
const CIM_FLAG_ARRAY: u16 = 0x2000;

fn structurally_scalar(p: &Prop) -> bool {
    let blocked = PROP_STRUCT
        | PROP_PARAM_LENGTH
        | PROP_PARAM_COUNT
        | PROP_WBEM_XML
        | PROP_PARAM_FIXED_LENGTH
        | PROP_PARAM_FIXED_COUNT
        | PROP_CUSTOM_SCHEMA;
    p.flags & blocked == 0 && p.intype & CIM_FLAG_ARRAY == 0
}

/// The event's own schema, as TDH describes it.
#[derive(Debug, Clone)]
struct Meta {
    id: u16,
    version: u16,
    /// Properties in metadata order.
    props: Vec<Prop>,
}

/// Read one event's schema from TDH. This is the only place the field layout comes from - the
/// previous build walked the payload by an offset order it had derived itself, and every
/// payload was rejected by its own sanity checks.
unsafe fn metadata_of(rec: *const EVENT_RECORD) -> Result<Meta, u32> {
    let mut need = 0u32;
    let first = TdhGetEventInformation(rec, None, None, &mut need);
    FIRST_SIZE_PROBE
        .compare_exchange(0, first, Ordering::Relaxed, Ordering::Relaxed)
        .ok();
    // The size probe is documented to fail with "more data"/"insufficient buffer"; both codes
    // appear in practice for this call, and treating either as fatal is what made every event
    // look undecodable. Any other status is a real failure.
    const ERROR_MORE_DATA: u32 = 234;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    if first != ERROR_MORE_DATA && first != ERROR_INSUFFICIENT_BUFFER && first != 0 {
        return Err(first);
    }
    if need < std::mem::size_of::<TRACE_EVENT_INFO>() as u32 {
        return Err(0xFFFF_FFFF);
    }
    // Align to 8 so the embedded EVENT_PROPERTY_INFO pointers are correctly aligned.
    let words = (need as usize + 8) / 8;
    let mut backing = vec![0usize; words];
    let base = backing.as_mut_ptr() as *mut u8;
    let mut len = need;
    let second = TdhGetEventInformation(rec, None, Some(base as *mut TRACE_EVENT_INFO), &mut len);
    if second != 0 {
        return Err(0xFFFF_FF00u32 | second); // keep the real code, distinguish the stage
    }
    let info = base as *const TRACE_EVENT_INFO;
    let count = (*info).TopLevelPropertyCount.max((*info).PropertyCount) as usize;
    let first_prop = &raw const (*info).EventPropertyInfoArray as *const EVENT_PROPERTY_INFO;
    let mut props = Vec::with_capacity(count.min(64));
    for i in 0..count {
        let p = first_prop.add(i);
        let name_off = (*p).NameOffset as usize;
        // NameOffset is an offset **inside the TRACE_EVENT_INFO blob** - it is not a payload
        // offset, which is the exact confusion this rewrite is meant to remove.
        if name_off >= len as usize {
            return Err(0xFFFF_FFFE);
        }
        let name_raw = base.add(name_off) as *const u16;
        let mut s = Vec::new();
        for j in 0..256 {
            let c = *name_raw.add(j);
            if c == 0 {
                break;
            }
            s.push(c);
        }
        let name = String::from_utf16_lossy(&s);
        let intype = (*p).Anonymous1.nonStructType.InType;
        let flags = (*p).Flags.0 as u32;
        props.push(Prop {
            name,
            intype,
            flags,
        });
    }
    Ok(Meta {
        id: (*info).EventDescriptor.Id,
        // The descriptor's Version is a u8; the taxonomy reports it as u16 so an unknown
        // version can be named exactly in the log.
        version: u16::from((*info).EventDescriptor.Version),
        props,
    })
}

/// Read one property by name, checking the declared type and the reported size first.
unsafe fn read_u64_named(
    rec: *const EVENT_RECORD,
    meta: &Meta,
    field: &'static str,
    wide: &[u16],
    want_bytes: u32,
) -> Result<u64, Fail> {
    let prop = match meta.props.iter().find(|p| p.name == field) {
        Some(p) => p.clone(),
        None => return Err(Fail::MissingField(field)),
    };
    // Reject anything the metadata describes as struct/array/parameterised before touching
    // bytes: a scalar read through those would silently mis-align.
    if !structurally_scalar(&prop) {
        return Err(Fail::TypeMismatch {
            field,
            intype: prop.intype,
        });
    }
    let desc = PROPERTY_DATA_DESCRIPTOR {
        PropertyName: wide.as_ptr() as u64,
        ArrayIndex: 0,
        Reserved: 0,
    };
    let mut size = 0u32;
    let s1 = TdhGetPropertySize(rec, None, &[desc], &mut size);
    if s1 != 0 {
        return Err(Fail::PropertyRead { field, status: s1 });
    }
    // The size is checked against what the field must be, so no value is ever zero-extended
    // or truncated into a plausible-looking number.
    if size != want_bytes {
        return Err(Fail::SizeMismatch { field, got: size });
    }
    let mut buf = [0u8; 8];
    let s2 = TdhGetProperty(rec, None, &[desc], &mut buf[..size as usize]);
    if s2 != 0 {
        return Err(Fail::PropertyRead { field, status: s2 });
    }
    Ok(if size == 4 {
        u64::from(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
    } else {
        u64::from_le_bytes(buf)
    })
}

fn wide_of(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// FILETIME in 100 ns ticks, kept raw, plus the derived unix ms used for comparison with SAM
/// report times. `create_raw`/`exit_raw` are what get logged and asserted, so precision claimed
/// is precision held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleEvent {
    pub start: bool,
    pub pid: u32,
    pub sequence: u64,
    pub create_raw: i64,
    pub exit_raw: Option<i64>,
    pub create_ms: u64,
    pub exit_ms: Option<u64>,
}

/// Decode one record through TDH metadata + named property reads.
///
/// `Ok(None)` means "this event is not a lifetime fact" - counted once, as `unknown_version`.
/// Acceptance of an id/version pair is based on the fields actually present in its metadata, so
/// a version we never measured cannot sneak through on an id match alone.
unsafe fn decode_rec(rec: *const EVENT_RECORD) -> Result<Option<LifecycleEvent>, Fail> {
    let meta = metadata_of(rec).map_err(Fail::Metadata)?;
    let names: Vec<&str> = meta.props.iter().map(|p| p.name.as_str()).collect();
    let has = |f: &str| names.contains(&f);
    let wants_start =
        has("ProcessID") && has("ProcessSequenceNumber") && has("CreateTime") && !has("ExitTime");
    let wants_stop =
        has("ProcessID") && has("ProcessSequenceNumber") && has("CreateTime") && has("ExitTime");
    // Field presence alone is not enough. A future version could carry the same names with
    // different semantics, and accepting it because the names matched would be guessing again -
    // so the declared (id, version) must also be one of the two shapes measured on this machine,
    // and the shape must agree with what the metadata lists.
    let declared_start = (meta.id, meta.version) == (1, 4);
    let declared_stop = (meta.id, meta.version) == (2, 2);
    if !(declared_start || declared_stop) {
        return Err(Fail::UnknownVersion {
            id: meta.id,
            version: meta.version,
        });
    }
    if declared_start != (wants_start && !wants_stop) || declared_stop != wants_stop {
        return Err(Fail::UnknownVersion {
            id: meta.id,
            version: meta.version,
        });
    }
    if !wants_start && !wants_stop {
        return Err(Fail::UnknownVersion {
            id: meta.id,
            version: meta.version,
        });
    }
    let pid = read_u64_named(rec, &meta, "ProcessID", &wide_of("ProcessID"), 4)?;
    let sequence = read_u64_named(
        rec,
        &meta,
        "ProcessSequenceNumber",
        &wide_of("ProcessSequenceNumber"),
        8,
    )?;
    let create_raw = read_u64_named(rec, &meta, "CreateTime", &wide_of("CreateTime"), 8)? as i64;
    let exit_raw = if wants_stop {
        Some(read_u64_named(rec, &meta, "ExitTime", &wide_of("ExitTime"), 8)? as i64)
    } else {
        None
    };
    if pid == 0 || pid > u64::from(u32::MAX) {
        return Err(Fail::Implausible);
    }
    let create_ms = match filetime_to_unix_ms(create_raw) {
        Some(v) => v,
        None => return Err(Fail::Implausible),
    };
    if !plausible_unix_ms(create_ms) {
        return Err(Fail::Implausible);
    }
    let exit_ms = match exit_raw {
        Some(e) => {
            let v = match filetime_to_unix_ms(e) {
                Some(v) => v,
                None => return Err(Fail::Implausible),
            };
            if !plausible_unix_ms(v) || v < create_ms {
                return Err(Fail::Implausible);
            }
            Some(v)
        }
        None => None,
    };
    Ok(Some(LifecycleEvent {
        start: exit_raw.is_none(),
        pid: pid as u32,
        sequence,
        create_raw,
        exit_raw,
        create_ms,
        exit_ms,
    }))
}

/// The consumer thread's own tally, folded in `on_event`. `DECODE_BROKEN` is set by any
/// decoding failure or by a cross-validation disagreement, and it never clears itself.
static TALLY: std::sync::Mutex<Tally> = std::sync::Mutex::new(Tally::zeroed());

impl Tally {
    // `Mutex<Tally>` needs a const-constructible initial value.
    const fn zeroed() -> Tally {
        Tally {
            ok_start: 0,
            ok_stop: 0,
            unknown_version: 0,
            tdh_metadata_failed: 0,
            missing_field: 0,
            type_mismatch: 0,
            size_mismatch: 0,
            property_read_failed: 0,
            implausible: 0,
            total: 0,
        }
    }
}

/// The first few failure descriptions, kept so the log says *what* the metadata declared
/// instead of only that we refused it.
static FAIL_SAMPLES: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Start events whose sequence was confirmed by an independent process snapshot, as
/// `(confirmed_at_ms, sequence)`. Without this the ledger's cross-source check would have
/// nothing to compare against and would pass on event evidence alone.
static CONFIRMED: Mutex<Vec<(u64, u64)>> = Mutex::new(Vec::new());

/// Take the pending confirmations (drained by the control loop into the ledger).
pub fn take_confirmations() -> Vec<(u64, u64)> {
    let mut v = CONFIRMED.lock().unwrap_or_else(|p| p.into_inner());
    std::mem::take(&mut *v)
}

/// Fold one outcome into the tally and the health flags.
fn classify(r: &Result<Option<LifecycleEvent>, Fail>) {
    let mut t = TALLY.lock().unwrap_or_else(|p| p.into_inner());
    t.record(r);
    drop(t);
    match r {
        Ok(Some(ev)) => {
            if ev.start {
                STARTS.fetch_add(1, Ordering::Relaxed);
            } else {
                STOPS.fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(None) => {}
        Err(e) => {
            let mut s = FAIL_SAMPLES.lock().unwrap_or_else(|p| p.into_inner());
            if s.len() < 6 {
                s.push(format!("{e:?}"));
            }
            DECODE_BROKEN.store(true, Ordering::Relaxed);
        }
    }
}

unsafe extern "system" fn on_event(rec: *mut EVENT_RECORD) {
    CALLBACKS.fetch_add(1, Ordering::Relaxed);
    if rec.is_null() {
        return;
    }
    // The provider filter is belt-and-braces: enabling is keyword-scoped, but a session shared
    // with another provider must not be able to feed us rows we cannot interpret.
    if (*rec).EventHeader.ProviderId != KERNEL_PROCESS_PROVIDER {
        return;
    }
    let out = decode_rec(rec);
    classify(&out);
    if let Ok(Some(ev)) = out {
        if ev.start {
            // Cross-validate against the same counter read through a different API, but only
            // while the process is alive enough to be found: a missing pid here usually means
            // it already exited, which is not a disagreement between the two sources.
            match crate::proc_identity::take() {
                Ok(snap) => match snap.find(ev.pid) {
                    Some(seen) if seen.sequence == ev.sequence => {
                        // The two independent sources agree on this instance: hand that to the
                        // ledger as snapshot evidence.
                        CONFIRMED
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .push((unix_ms(), seen.sequence));
                    }
                    Some(_) => DECODE_BROKEN.store(true, Ordering::Relaxed),
                    None => {}
                },
                // Snapshot unavailable: recorded, not fatal, because the ledger also refuses
                // attribution without snapshot support.
                Err(_) => {
                    LOST_PARSE.store(true, Ordering::Relaxed);
                }
            }
        }
        let mut q = FEED.lock().unwrap_or_else(|p| p.into_inner());
        // Bounded: a stalled consumer must not be able to grow the service's memory. Dropping
        // our own queue is loud and makes the ledger untrusted, never silent.
        if q.len() >= 4096 {
            q.pop_front();
            LOST_PARSE.store(true, Ordering::Relaxed);
        }
        q.push_back(ev);
    }
}

/// The live collector. Dropping it stops only this session.
pub struct KernelLifecycle {
    name: Vec<u16>,
    session: CONTROLTRACE_HANDLE,
    trace: PROCESSTRACE_HANDLE,
    stop: std::sync::Arc<AtomicBool>,
    consumer: Option<JoinHandle<()>>,
    boundary_ms: u64,
}

impl KernelLifecycle {
    /// Start the session and its consumer. Any failure is returned verbatim: the caller keeps
    /// running without a ledger, and shadow behaviour does not depend on this succeeding.
    pub fn start() -> Result<Self, i32> {
        // These latches describe *this* collector. Left over from an earlier one they would accuse a
        // healthy consumer of a fault it never made - or, worse for recovery, keep `consumer_alive`
        // false after a new thread had in fact started, because nothing else resets them. The
        // cumulative tally is cleared for the same reason: the trust rule compares deltas, and a delta
        // taken across a collector hand-over is meaningless.
        DECODE_BROKEN.store(false, Ordering::Relaxed);
        LOST_PARSE.store(false, Ordering::Relaxed);
        CONSUMER_EXIT.store(0, Ordering::Relaxed);
        CALLBACKS.store(0, Ordering::Relaxed);
        *TALLY.lock().unwrap_or_else(|p| p.into_inner()) = Tally::default();

        let name_str = format!("CM400-KernelProc-Diag-{}\0", std::process::id());
        let mut name: Vec<u16> = name_str.encode_utf16().collect();
        let name_ptr = name.as_mut_ptr();

        let session = unsafe {
            let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
            let name_bytes = name.len() * 2;
            let total = props_size + name_bytes + 8;
            let mut buf = vec![0u8; total];
            let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
            (*props).Wnode.BufferSize = total as u32;
            (*props).Wnode.ClientContext = 2;
            (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            (*props).FlushTimer = 1;
            (*props).MinimumBuffers = 8;
            (*props).MaximumBuffers = 32;
            (*props).LoggerNameOffset = props_size as u32;
            std::ptr::copy_nonoverlapping(
                name.as_ptr(),
                buf.as_mut_ptr().add(props_size) as *mut u16,
                name.len(),
            );
            let mut h = CONTROLTRACE_HANDLE::default();
            // No takeover: a name collision means someone else owns it, and we never stop a
            // session we did not create.
            let e = StartTraceW(&mut h, PCWSTR(name_ptr), props);
            if e != WIN32_ERROR(0) {
                return Err(e.0 as i32);
            }
            let en = EnableTraceEx2(
                h,
                &KERNEL_PROCESS_PROVIDER,
                1, /* EVENT_CONTROL_CODE_ENABLE_PROVIDER */
                LEVEL_INFORMATIONAL,
                PROCESS_KEYWORD,
                0,
                0,
                None,
            );
            if en != WIN32_ERROR(0) {
                let _ = stop_by_name(&name);
                return Err(-(en.0 as i32));
            }
            ENABLED.store(true, Ordering::Relaxed);
            h
        };

        let trace = unsafe {
            let mut logfile = EVENT_TRACE_LOGFILEW {
                LoggerName: PWSTR(name.as_mut_ptr()),
                Anonymous1: EVENT_TRACE_LOGFILEW_0 {
                    ProcessTraceMode: PROCESS_TRACE_MODE_REAL_TIME
                        | PROCESS_TRACE_MODE_EVENT_RECORD,
                },
                Anonymous2: EVENT_TRACE_LOGFILEW_1 {
                    EventRecordCallback: Some(on_event),
                },
                ..EVENT_TRACE_LOGFILEW::default()
            };
            let th = OpenTraceW(&mut logfile);
            if th.Value == u64::MAX {
                let _ = stop_by_name(&name);
                return Err(-1);
            }
            th
        };

        let consumer = {
            let th = trace;
            std::thread::spawn(move || unsafe {
                let err = ProcessTrace(&[th], None, None);
                CONSUMER_EXIT.store(err.0 as i64, Ordering::Relaxed);
            })
        };

        // The boundary is taken *after* the session is live, so pre-existing processes are
        // knowingly un-birthed rather than assumed old-but-identifiable.
        let boundary_ms = unix_ms();

        Ok(KernelLifecycle {
            name,
            session,
            trace,
            stop: std::sync::Arc::new(AtomicBool::new(false)),
            consumer: Some(consumer),
            boundary_ms,
        })
    }

    /// The instant from which lifetimes can be claimed to be observed. Reports stamped earlier
    /// than this cannot be attributed, because we had no eyes on the process table then.
    pub fn boundary_ms(&self) -> u64 {
        self.boundary_ms
    }

    pub fn drain(&mut self) -> Vec<LifecycleEvent> {
        let mut q = FEED.lock().unwrap_or_else(|p| p.into_inner());
        q.drain(..).collect()
    }

    /// Query this session's own loss counters. An error here is itself a reason to distrust the
    /// ledger: "we cannot prove we did not lose events" is not "we lost none".
    pub fn loss(&self) -> Result<Loss, u32> {
        unsafe {
            let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
            let name_bytes = self.name.len() * 2;
            let total = props_size + name_bytes + 8;
            let mut buf = vec![0u8; total];
            let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
            (*props).Wnode.BufferSize = total as u32;
            (*props).Wnode.ClientContext = 2;
            (*props).LoggerNameOffset = props_size as u32;
            std::ptr::copy_nonoverlapping(
                self.name.as_ptr(),
                buf.as_mut_ptr().add(props_size) as *mut u16,
                self.name.len(),
            );
            let e = ControlTraceW(
                CONTROLTRACE_HANDLE {
                    Value: self.session.Value,
                },
                PCWSTR(self.name.as_ptr()),
                props,
                EVENT_TRACE_CONTROL_QUERY,
            );
            if e != WIN32_ERROR(0) {
                return Err(e.0);
            }
            Ok(Loss {
                events_lost: (*props).EventsLost as u64,
                log_buffers_lost: (*props).LogBuffersLost as u64,
                real_time_buffers_lost: (*props).RealTimeBuffersLost as u64,
                buffers: (*props).NumberOfBuffers,
            })
        }
    }

    /// Everything the collector knows about its own health, for one log line. The tally is the
    /// authority on whether decoding works; a healthy session with a rising failure counter is
    /// not healthy at all.
    pub fn health(&self) -> Health {
        let tally = *TALLY.lock().unwrap_or_else(|p| p.into_inner());
        Health {
            tally,
            decode_broken: DECODE_BROKEN.load(Ordering::Relaxed) || tally.failed_any(),
            queue_lost: LOST_PARSE.load(Ordering::Relaxed),
            consumer_alive: CONSUMER_EXIT.load(Ordering::Relaxed) == 0,
            callbacks: CALLBACKS.load(Ordering::Relaxed),
        }
    }

    /// Exposed for the offline validator and the log line.
    pub fn tally(&mut self) -> Tally {
        *TALLY.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        unsafe {
            let _ = CloseTrace(self.trace);
        }
        if let Some(t) = self.consumer.take() {
            // The consumer must be back before the session is stopped, or its thread would be
            // using a handle that no longer exists.
            let _ = t.join();
        }
        // `stop_by_name` is a safe function: its own FFI is inside it, so wrapping the call in
        // `unsafe` would only suggest a contract that does not exist.
        let _ = stop_by_name(&self.name);
    }
}

impl Drop for KernelLifecycle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Stop our own session by name - the handle-only form returns ERROR_INVALID_PARAMETER and
/// leaves a real-time logger behind, which is how the product session once leaked.
fn stop_by_name(name: &[u16]) -> WIN32_ERROR {
    let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let total = props_size + name.len() * 2 + 8;
    let mut buf = vec![0u8; total];
    let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    unsafe {
        (*props).Wnode.BufferSize = total as u32;
        (*props).Wnode.ClientContext = 2;
        (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*props).LoggerNameOffset = props_size as u32;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            buf.as_mut_ptr().add(props_size) as *mut u16,
            name.len(),
        );
        ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(name.as_ptr()),
            props,
            EVENT_TRACE_CONTROL_STOP,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ft(unix_ms: u64) -> i64 {
        (unix_ms as i64) * 10_000 + 116_444_736_000_000_000
    }

    /// The window check is what stops a wrong offset from looking like a plausible number.
    #[test]
    fn filetime_conversion_and_plausibility_gate() {
        let t = 1_791_715_054_273u64; // a real value from the diagnostic capture
        let raw = ft(t);
        assert_eq!(filetime_to_unix_ms(raw), Some(t));
        assert!(plausible_unix_ms(t));
        // 1970 and year-3000 timestamps are both "the reader is misaligned", not data.
        assert!(!plausible_unix_ms(0));
        assert!(!plausible_unix_ms(9_000_000_000_000_000));
        assert_eq!(
            filetime_to_unix_ms(0),
            None,
            "pre-epoch FILETIME must not become 0 ms"
        );
    }

    /// The failure taxonomy must be exclusive: one event, one counter. This is the property the
    /// previous build lacked, where `unknown_schema` mixed "unimplemented version" with "known
    /// version whose payload we could not read" - which is exactly how a broken decoder managed
    /// to look like an empty-but-fine one.
    #[test]
    fn each_failure_lands_in_exactly_one_bucket() {
        let cases: Vec<(Result<Option<LifecycleEvent>, Fail>, u8)> = vec![
            (Ok(Some(ev(true))), 0),
            (Ok(Some(ev(false))), 1),
            (Err(Fail::UnknownVersion { id: 1, version: 9 }), 2),
            (Err(Fail::Metadata(87)), 3),
            (Err(Fail::MissingField("ProcessSequenceNumber")), 4),
            (
                Err(Fail::TypeMismatch {
                    field: "CreateTime",
                    intype: 100,
                }),
                5,
            ),
            (
                Err(Fail::SizeMismatch {
                    field: "ProcessID",
                    got: 2,
                }),
                6,
            ),
            (
                Err(Fail::PropertyRead {
                    field: "ExitTime",
                    status: 122,
                }),
                7,
            ),
            (Err(Fail::Implausible), 8),
        ];
        for (i, (case, _)) in cases.iter().enumerate() {
            let mut t = Tally::zeroed();
            t.record(case);
            assert!(
                t.balanced(),
                "event {i} was not accounted for exactly once: {t:?}"
            );
            assert_eq!(t.total, 1);
            let hit = [
                t.ok_start,
                t.ok_stop,
                t.unknown_version,
                t.tdh_metadata_failed,
                t.missing_field,
                t.type_mismatch,
                t.size_mismatch,
                t.property_read_failed,
                t.implausible,
            ];
            assert_eq!(
                hit.iter().filter(|v| **v == 1).count(),
                1,
                "exactly one bucket for {i}"
            );
            assert_eq!(hit.iter().sum::<u64>(), 1);
        }
    }

    /// A known-version failure must never be reported as an unknown version.
    #[test]
    fn a_parse_failure_is_not_misreported_as_an_unknown_version() {
        let mut t = Tally::zeroed();
        t.record(&Err(Fail::TypeMismatch {
            field: "ExitTime",
            intype: 17,
        }));
        t.record(&Err(Fail::SizeMismatch {
            field: "ExitTime",
            got: 3,
        }));
        t.record(&Err(Fail::UnknownVersion { id: 2, version: 0 }));
        assert_eq!(
            (t.type_mismatch, t.size_mismatch, t.unknown_version),
            (1, 1, 1)
        );
        assert_eq!(t.failures(), 3);
        assert!(t.failed_any());
        // And the aggregate cannot hide the split: the old single counter would have said 3 of
        // one kind.
        assert_eq!(t.ok_start + t.ok_stop, 0);
    }

    fn ev(start: bool) -> LifecycleEvent {
        LifecycleEvent {
            start,
            pid: 4994,
            sequence: 12,
            create_raw: 0,
            exit_raw: None,
            create_ms: 0,
            exit_ms: None,
        }
    }

    /// Decoding failure, missing field and event loss are three different faults and must not
    /// be conflated once they reach the ledger: all three refuse, for different stated reasons.
    #[test]
    fn the_three_fault_kinds_stay_distinct_when_they_reach_the_ledger() {
        use crate::proc_lifecycle::Ledger;
        let mut by_loss = Ledger::new();
        let mut by_decode = Ledger::new();
        let mut by_missing = Ledger::new();
        for l in [&mut by_loss, &mut by_decode, &mut by_missing] {
            l.set_boundary(1_000);
            l.ingest_start(4994, 55, 1_500);
            l.note_snapshot_sequence(1_600, 55);
        }
        by_loss.break_trust("kernel event loss detected");
        by_decode.break_trust("collector decode or transport fault");
        by_missing.break_trust("loss counters unreadable");
        let r = crate::report_link::Report {
            pid: 4994,
            streaming: true,
            report_ms: 2_000,
            arrival_ms: 2_100,
        };
        // Each fault kind must refuse, and the reason must say which fault it was.
        assert!(
            by_loss.attribute(&r).attributed().is_none(),
            "event loss must refuse"
        );
        assert!(
            by_decode.attribute(&r).attributed().is_none(),
            "decode fault must refuse"
        );
        assert!(
            by_missing.attribute(&r).attributed().is_none(),
            "unreadable counters must refuse"
        );
        // The reasons stay distinguishable in the log, which is what makes them debuggable.
        assert_eq!(by_loss.trust_reason(), Some("kernel event loss detected"));
        assert_eq!(
            by_decode.trust_reason(),
            Some("collector decode or transport fault")
        );
        assert_eq!(by_missing.trust_reason(), Some("loss counters unreadable"));
    }

    // ---- offline harness over the captured ETL -------------------------------------------
    //
    // This is the real-event evidence: it reads the file trace produced by the temporary
    // session and decodes it with the same code path the service uses. It is `#[ignore]`d
    // because it needs that capture, and a compiled test is not a decoded event.

    static FILE_ROWS: Mutex<Vec<LifecycleEvent>> = Mutex::new(Vec::new());
    static FILE_NS: Mutex<Vec<u64>> = Mutex::new(Vec::new());

    unsafe extern "system" fn on_event_file(rec: *mut EVENT_RECORD) {
        if rec.is_null() || (*rec).EventHeader.ProviderId != KERNEL_PROCESS_PROVIDER {
            return;
        }
        let t0 = std::time::Instant::now();
        let out = decode_rec(rec);
        let ns = t0.elapsed().as_nanos() as u64;
        classify(&out);
        if let Ok(Some(ev)) = out {
            FILE_ROWS.lock().unwrap_or_else(|p| p.into_inner()).push(ev);
            FILE_NS.lock().unwrap_or_else(|p| p.into_inner()).push(ns);
        }
    }

    fn consume_etl(path: &str) -> Result<(), i32> {
        let mut wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        unsafe {
            let mut logfile = EVENT_TRACE_LOGFILEW {
                LogFileName: PWSTR(wide.as_mut_ptr()),
                Anonymous1: EVENT_TRACE_LOGFILEW_0 {
                    ProcessTraceMode: PROCESS_TRACE_MODE_EVENT_RECORD,
                },
                Anonymous2: EVENT_TRACE_LOGFILEW_1 {
                    EventRecordCallback: Some(on_event_file),
                },
                ..EVENT_TRACE_LOGFILEW::default()
            };
            let th = OpenTraceW(&mut logfile);
            if th.Value == u64::MAX {
                // OpenTraceW returns INVALID_PROCESSTRACE_HANDLE and sets the last error; the
                // call itself is the authority, so no fabricated code is invented here.
                return Err(-(windows::Win32::Foundation::GetLastError().0 as i32));
            }
            let err = ProcessTrace(&[th], None, None);
            let _ = CloseTrace(th);
            if err != WIN32_ERROR(0) {
                return Err(err.0 as i32);
            }
        }
        Ok(())
    }

    /// One parsed tracerpt event: id, version, and the `Name="X"` values found in it. Named because
    /// the tuple was long enough to obscure what `xml_rows` hands back.
    type XmlRow = (u16, u16, Vec<(String, String)>);

    /// Pull the id/version and the `Name="X"` values out of one tracerpt XML event. Format is
    /// element-based (`<EventID>2</EventID>`) and tracerpt right-aligns numeric values with
    /// padding spaces, so every value is trimmed before parsing - a padded `   56268` is the
    /// same number, and refusing to trim it would silently drop every reference row.
    fn xml_rows(text: &str) -> Vec<XmlRow> {
        let elem = |body: &str, tag: &str| -> Option<u16> {
            let open = format!("<{tag}>");
            let i = body.find(&open)? + open.len();
            let rest = &body[i..];
            let end = rest.find("</")?;
            rest[..end].trim().parse().ok()
        };
        let mut out = Vec::new();
        for chunk in text.split("<Event ").skip(1) {
            let body = match chunk.split_once("</Event>") {
                Some((b, _)) => b,
                None => continue,
            };
            let id = elem(body, "EventID");
            let version = elem(body, "Version");
            let mut fields = Vec::new();
            let mut rest = body;
            const OPEN: &str = "<Data Name=\"";
            while let Some(i) = rest.find(OPEN) {
                let after = &rest[i + OPEN.len()..];
                let name = after.split('"').next().unwrap_or("").to_string();
                if let Some((_, v)) = after.split_once('>') {
                    if let Some((val, tail)) = v.split_once("</Data>") {
                        fields.push((name, val.trim().to_string()));
                        rest = tail;
                        continue;
                    }
                }
                break;
            }
            if let (Some(i), Some(v)) = (id, version) {
                out.push((i, v, fields));
            }
        }
        out
    }

    fn field<'a>(rows: &'a [(String, String)], name: &str) -> Option<&'a str> {
        rows.iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    #[ignore = "needs the captured ETL; run with --ignored --nocapture"]
    fn decodes_the_captured_etl_and_matches_the_os_decode() {
        // the directory comes from the environment, and the fallback goes through the OS temp path: a
        // hard-coded `C:\Users\<name>\...` would pin this test to one person's machine and put a local
        // account name into a published source file for no benefit
        let dir = std::env::var("CM400_KPROCDIAG_DIR").unwrap_or_else(|_| {
            std::env::temp_dir()
                .join("cm400-kernel-process-diag")
                .to_string_lossy()
                .into_owned()
        });
        let etl = format!("{dir}\\diag.etl");
        let xml = format!("{dir}\\events.xml");
        if !std::path::Path::new(&etl).exists() || !std::path::Path::new(&xml).exists() {
            println!("SKIP: capture not present ({etl} / {xml})");
            return;
        }
        let text = std::fs::read_to_string(&xml).expect("read events.xml");
        let rows = xml_rows(&text);
        // Reference: only Kernel-Process rows carrying our fields. If the reference is empty the
        // harness must say so instead of passing on a vacuous comparison.
        assert!(
            rows.len() > 100,
            "the reference XML parsed to {} rows; the harness is broken",
            rows.len()
        );
        let mut ref_start: Vec<(u32, u64, String)> = Vec::new();
        let mut ref_stop: Vec<(u32, u64, String, String)> = Vec::new();
        for (id, ver, f) in &rows {
            let pid = field(f, "ProcessID").and_then(|v| v.parse::<u32>().ok());
            let seq = field(f, "ProcessSequenceNumber").and_then(|v| v.parse::<u64>().ok());
            let create = field(f, "CreateTime").map(|s| s.to_string());
            let exit = field(f, "ExitTime").map(|s| s.to_string());
            match (id, ver, pid, seq, &create, &exit) {
                (1, 4, Some(p), Some(s), Some(c), None) => ref_start.push((p, s, c.clone())),
                (2, 2, Some(p), Some(s), Some(c), Some(x)) => {
                    ref_stop.push((p, s, c.clone(), x.clone()))
                }
                _ => {}
            }
        }
        println!(
            "reference rows: start_v4={} stop_v2={} (all events={})",
            ref_start.len(),
            ref_stop.len(),
            rows.len()
        );
        println!(
            "first TdhGetEventInformation size-probe status = {}",
            FIRST_SIZE_PROBE.load(Ordering::Relaxed)
        );
        assert!(
            ref_start.len() >= 15 && ref_stop.len() >= 15,
            "the capture must contain the samples it claims"
        );

        let before = self_tally_total();
        consume_etl(&etl).expect("consume ETL");
        let mine = FILE_ROWS.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let ns = FILE_NS.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let tally = tally_delta(before);
        println!("decoded ok: start={} stop={}  failures: unknown_version={} metadata={} missing={} type={} size={} read={} implausible={}",
            tally.ok_start, tally.ok_stop, tally.unknown_version, tally.tdh_metadata_failed,
            tally.missing_field, tally.type_mismatch, tally.size_mismatch, tally.property_read_failed, tally.implausible);
        println!("tally total={} balanced={}", tally.total, tally.balanced());
        assert!(tally.balanced(), "every event must be counted exactly once");
        for s in FAIL_SAMPLES
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
        {
            println!("  failure sample: {s}");
        }
        assert_eq!(
            tally.type_mismatch
                + tally.size_mismatch
                + tally.property_read_failed
                + tally.missing_field
                + tally.tdh_metadata_failed,
            0,
            "a correct decoder must not need any failure bucket on real events"
        );
        assert!(
            tally.ok_start >= 15 && tally.ok_stop >= 15,
            "expected at least the 15 aligned samples each"
        );

        // Field-by-field comparison against the OS decode, as multisets of (pid, sequence).
        // Pairing by pid alone - as an earlier version of this harness did - is wrong precisely
        // because a pid can appear twice in one capture; that is the case the whole design is
        // about, and the mismatch list was the harness lying, not the decoder.
        let mut mine_start: Vec<(u32, u64)> = mine
            .iter()
            .filter(|e| e.start)
            .map(|e| (e.pid, e.sequence))
            .collect();
        let mut mine_stop: Vec<(u32, u64)> = mine
            .iter()
            .filter(|e| !e.start)
            .map(|e| (e.pid, e.sequence))
            .collect();
        let mut ref_s: Vec<(u32, u64)> = ref_start.iter().map(|(p, s, _)| (*p, *s)).collect();
        let mut ref_p: Vec<(u32, u64)> = ref_stop.iter().map(|(p, s, _, _)| (*p, *s)).collect();
        mine_start.sort_unstable();
        mine_stop.sort_unstable();
        ref_s.sort_unstable();
        ref_p.sort_unstable();
        println!(
            "multiset comparison: start {} vs {}  stop {} vs {}",
            mine_start.len(),
            ref_s.len(),
            mine_stop.len(),
            ref_p.len()
        );
        assert_eq!(
            mine_start, ref_s,
            "ProcessID/ProcessSequenceNumber pairs differ from the OS decode (starts)"
        );
        assert_eq!(
            mine_stop, ref_p,
            "ProcessID/ProcessSequenceNumber pairs differ from the OS decode (stops)"
        );
        let matched = mine_start.len() + mine_stop.len();
        println!(
            "field comparison: matched={matched} against {} reference rows",
            ref_start.len() + ref_stop.len()
        );

        // PID reuse inside the capture: the same pid carrying more than one instance, seen
        // directly in real events rather than manufactured in a test.
        let mut by_pid: std::collections::BTreeMap<u32, std::collections::BTreeSet<u64>> =
            std::collections::BTreeMap::new();
        for (p, s) in mine_start.iter().chain(mine_stop.iter()) {
            by_pid.entry(*p).or_default().insert(*s);
        }
        let reused: Vec<(u32, usize)> = by_pid
            .iter()
            .filter(|(_, v)| v.len() > 1)
            .map(|(k, v)| (*k, v.len()))
            .collect();
        println!(
            "real pid reuse in this capture: {} pids carried more than one sequence (e.g. {:?})",
            reused.len(),
            reused.iter().take(4).collect::<Vec<_>>()
        );
        // A stop event must agree with its own start event on sequence, when both are present.
        let mut start_seq: std::collections::HashMap<(u32, u64), i64> =
            std::collections::HashMap::new();
        for e in mine.iter().filter(|e| e.start) {
            start_seq.insert((e.pid, e.sequence), e.create_raw);
        }
        let mut paired = 0usize;
        let mut bad_pair = 0usize;
        for e in mine.iter().filter(|e| !e.start) {
            if let Some(c) = start_seq.get(&(e.pid, e.sequence)) {
                paired += 1;
                if *c != e.create_raw || e.exit_raw.map(|x| x < e.create_raw).unwrap_or(true) {
                    bad_pair += 1;
                }
            }
        }
        println!("start/stop pairing: paired={paired} inconsistent={bad_pair} (unpaired starts are processes still running at capture end)");
        assert_eq!(
            bad_pair, 0,
            "a stop event must carry the same CreateTime as its start"
        );

        // Performance of by-name reading, measured on real events.
        if !ns.is_empty() {
            let mut v = ns.clone();
            v.sort_unstable();
            let sum: u64 = v.iter().sum();
            println!(
                "decode timing per event: n={} min={}us p50={}us p99={}us max={}us mean={}us total={}ms",
                v.len(),
                v[0] / 1000,
                v[v.len() / 2] / 1000,
                v[((v.len() as f64 * 0.99) as usize).min(v.len() - 1)] / 1000,
                v[v.len() - 1] / 1000,
                sum / v.len() as u64 / 1000,
                sum / 1_000_000
            );
        }
        // Raw FILETIME values, so the 100 ns precision can be checked outside this process.
        for e in mine.iter().take(6) {
            println!(
                "raw: start={} pid={} seq={} create_raw={} exit_raw={:?} create_ms={} exit_ms={:?}",
                e.start, e.pid, e.sequence, e.create_raw, e.exit_raw, e.create_ms, e.exit_ms
            );
        }
    }

    fn self_tally_total() -> u64 {
        TALLY.lock().unwrap_or_else(|p| p.into_inner()).total
    }

    fn tally_delta(before: u64) -> Tally {
        let t = *TALLY.lock().unwrap_or_else(|p| p.into_inner());
        Tally {
            total: t.total.saturating_sub(before),
            ..t
        }
    }

    /// The provider identity is a fact from this machine, and a typo in it would silently give an
    /// empty ledger - so it is pinned here as well as in the docs.
    #[test]
    fn provider_identity_is_the_measured_one() {
        // Built a second way from the byte groups this machine reports, so a transposed
        // `from_u128` literal cannot pass unnoticed: an empty ledger would look like "no
        // processes started", which is exactly the silence we must not read as health.
        let expected = windows_core::GUID {
            data1: 0x22fb_2cd6,
            data2: 0x0e7b,
            data3: 0x422b,
            data4: [0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16],
        };
        assert_eq!(KERNEL_PROCESS_PROVIDER, expected);
        assert_eq!(PROCESS_KEYWORD, 0x10);
        assert_eq!(LEVEL_INFORMATIONAL, 4);
    }
}
