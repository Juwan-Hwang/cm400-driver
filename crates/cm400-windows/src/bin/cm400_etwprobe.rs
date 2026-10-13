//! cm400-etwprobe — W0-C2 real-time ETW reconnaissance.
//!
//! Starts a real-time ETW session and, because camera/MF providers register
//! ON-DEMAND (EnableTraceEx2 returns ERROR_NOT_FOUND while idle), a worker
//! thread RETRIES enabling pending providers every 2s. Once a provider is live
//! (e.g. after you open a camera), it gets enabled and its events stream in.
//! For each event it decodes EVENT_HEADER fields and scans UserData for CM400
//! identity (VID 0603 / PID 8612, ASCII + UTF-16LE), printing only matches.
//! Prints a heartbeat (total events) so we can tell if anything flows at all.
//! Runs a fixed duration, then always tears the session down.
//!
//! Must run elevated (real-time consumer needs admin / Performance Log Users).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, QueryAllTracesW,
    StartTraceW, TdhFormatProperty, TdhGetEventInformation, CONTROLTRACE_HANDLE,
    EVENT_PROPERTY_INFO, EVENT_RECORD, EVENT_TRACE_CONTROL_QUERY, EVENT_TRACE_CONTROL_STOP,
    EVENT_TRACE_LOGFILEW, EVENT_TRACE_LOGFILEW_0, EVENT_TRACE_LOGFILEW_1, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, PROCESSTRACE_HANDLE, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, TRACE_EVENT_INFO,
};

/// The CM400 capture function's symbolic link, as parsed from the event's own
/// properties. Exact, case-insensitive comparison - deliberately not a substring
/// search, which previously let another camera's events be counted as ours.
const TARGET_LINK: &str = "\\\\?\\usb#vid_0603&pid_8612&mi_00#8&2e26e82&0&0000#{e5323777-f976-4f5b-9b55-b94699c46e44}\\global";

const PROVIDERS: [GUID; 7] = [
    GUID::from_u128(0x9E22A3ED_7B32_4B99_B6C2_21DD6ACE01E1), // MF-FrameServer
    GUID::from_u128(0xDA1D1DBD_3186_4FA2_BC2D_075EFD9E43E2), // USBVideo
    GUID::from_u128(0xB8197C10_845F_40CA_82AB_9341E98CFC2B), // MFCaptureEngine
    GUID::from_u128(0xBC97B970_D001_482F_8745_B8D7D5759F99), // MF-Platform
    GUID::from_u128(0x9E12CEB1_E3FF_46AD_A0AA_11738B122D20), // WebcamExperience
    GUID::from_u128(0xF404B94E_27E0_4384_BFE8_1D8D390B0AA3), // MF-Performance
    // Positive control, verified with `logman query providers` rather than assumed:
    // Microsoft-Windows-Kernel-Process, WINEVENT_KEYWORD_PROCESS = 0x10, level 4.
    GUID::from_u128(0x22FB2CD6_0E7B_422B_A0C7_2FAD1FD0E716), // MSWin-Kernel-Process
];
const NAMES: [&str; 7] = [
    "MF-FrameServer",
    "USBVideo",
    "MFCaptureEngine",
    "MF-Platform",
    "WebcamExperience",
    "MF-Performance",
    "MSWin-Kernel-Process",
];
/// Keyword mask per provider. The control provider gets ONLY the process keyword: enabling
/// it with every bit set would not be the documented configuration, and a successful
/// EnableTraceEx2 does not by itself mean the events we expect are produced.
const KEYWORDS: [u64; 7] = [
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    0x10,
];

static TOTAL: AtomicU32 = AtomicU32::new(0);
static MATCHES: AtomicU32 = AtomicU32::new(0);
/// (provider, EventId, Opcode, Level) -> count, so a steady-streaming signal can
/// be found from data instead of assumed. Kept per provider to stay readable.
static HIST: Mutex<BTreeMap<(u128, u16, u8, u8), u64>> = Mutex::new(BTreeMap::new());
/// Same table, restricted to events that carry the CM400 identity — the ones we
/// can actually attribute to this device (multi-camera safety).
static HIST_CM400: Mutex<BTreeMap<(u128, u16, u8, u8), u64>> = Mutex::new(BTreeMap::new());
static ENABLED: [AtomicBool; 7] = [
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
];
/// Separate counters, so "no callbacks at all" and "callbacks but none from MF" are two
/// different answers instead of one vague zero.
static KERNPROC: AtomicU32 = AtomicU32::new(0);
static MF_ALL: AtomicU32 = AtomicU32::new(0);
static MF_ID10: AtomicU32 = AtomicU32::new(0);

fn utf16le_bytes(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.len() >= needle.len() && hay.windows(needle.len()).any(|w| w == needle)
}
fn looks_like_cm400(data: &[u8]) -> bool {
    (contains(data, b"0603") || contains(data, &utf16le_bytes("0603")))
        && (contains(data, b"8612") || contains(data, &utf16le_bytes("8612")))
}

/// Walk the event's declared properties and format every one we can.
///
/// Returns (property string, symbolic link if any, struct/array notes). This exists
/// because "the link says CM400" turned out not to identify the device: closing the
/// BUILT-IN camera also produced Id=6/7 carrying the CM400 path, 9.7s after CM400's
/// own shutdown. Only a full attribute dump can show whether any field separates them.
unsafe fn describe(record: *const EVENT_RECORD) -> (String, String) {
    let mut size = 0u32;
    const MORE: u32 = 122;
    let first = TdhGetEventInformation(record, None, None, &mut size);
    if first != MORE && first != 0 {
        return (format!("<tdh-info-failed {first}>"), String::new());
    }
    let need = size as usize;
    if need < std::mem::size_of::<TRACE_EVENT_INFO>() {
        return ("<tdh-size-too-small>".to_string(), String::new());
    }
    let mut buf = vec![0u64; need / 8 + 2];
    let raw = buf.as_mut_ptr() as *mut TRACE_EVENT_INFO;
    if TdhGetEventInformation(record, None, Some(raw), &mut size) != 0 {
        return ("<tdh-second-call-failed>".to_string(), String::new());
    }
    let base = buf.as_ptr() as *const u8;
    let info = &*raw;
    let count = info.PropertyCount as usize;
    let top = info.TopLevelPropertyCount as usize;
    let arr = &info.EventPropertyInfoArray as *const EVENT_PROPERTY_INFO;
    let rec = &*record;
    let ud_len = rec.UserDataLength as usize;
    if rec.UserData.is_null() {
        return ("<no user data>".to_string(), String::new());
    }
    let ud = std::slice::from_raw_parts(rec.UserData as *const u8, ud_len);

    let mut parts: Vec<String> = Vec::new();
    let mut link = String::new();
    let mut cursor = 0usize;
    for i in 0..count {
        let pi = &*arr.add(i);
        let name = if pi.NameOffset != 0 {
            read_wide_at(base.add(pi.NameOffset as usize))
        } else {
            format!("#{i}")
        };
        let non = pi.Anonymous1.nonStructType;
        let mut blen = 0u32;
        let mut consumed = 0u16;
        if cursor >= ud.len() {
            parts.push(format!("{name}=<no data left>"));
            break;
        }
        let rest = &ud[cursor..];
        let ask = TdhFormatProperty(
            base as *const TRACE_EVENT_INFO,
            None,
            8,
            non.InType,
            non.OutType,
            pi.Anonymous3.length,
            rest,
            &mut blen,
            PWSTR::null(),
            &mut consumed,
        );
        if ask != 0 && ask != MORE {
            parts.push(format!("{name}=<fmt-pre-request-failed {ask}>"));
            break;
        }
        let mut value = String::new();
        if blen > 0 {
            let mut wbuf = vec![0u16; (blen as usize) / 2 + 2];
            let mut used = 0u16;
            let rc = TdhFormatProperty(
                base as *const TRACE_EVENT_INFO,
                None,
                8,
                non.InType,
                non.OutType,
                pi.Anonymous3.length,
                rest,
                &mut blen,
                PWSTR(wbuf.as_mut_ptr()),
                &mut used,
            );
            if rc == 0 {
                consumed = used;
                value = String::from_utf16_lossy(&wbuf)
                    .trim_end_matches('\0')
                    .replace('\t', " ");
            } else {
                value = format!("<fmt-failed {rc}>");
            }
        }
        let key: String = name
            .to_ascii_lowercase()
            .chars()
            .filter(|c| *c != '_' && *c != '-')
            .collect();
        if key.contains("symboliclink") && link.is_empty() {
            link = value.clone();
        }
        parts.push(format!("{name}:out{}={value}", non.OutType));
        if consumed == 0 {
            parts.push(format!("{name}=<not consumed, stop>"));
            break;
        }
        cursor += consumed as usize;
    }
    (
        format!(
            "top={top} total={count} consumed={cursor}/{} | {}",
            ud_len,
            parts.join(" ; ")
        ),
        link,
    )
}

unsafe fn read_wide_at(p: *const u8) -> String {
    if p.is_null() {
        return String::new();
    }
    let s = p as *const u16;
    let mut n = 0usize;
    while n < 4096 && *s.add(n) != 0 {
        n += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(s, n))
}

/// Attribute an event by the device path its OWN schema declares.
///
/// Returns (attribution, parsed symbolic link). Anything that cannot be resolved
/// through TDH is reported as `unattributed` rather than guessed: the previous byte
/// scan matched other cameras' events and made the negative control worthless.
unsafe fn tdh_attribution(record: *const EVENT_RECORD) -> (&'static str, String) {
    let mut size = 0u32;
    let first = TdhGetEventInformation(record, None, None, &mut size);
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    if first != ERROR_INSUFFICIENT_BUFFER && first != 0 {
        return ("unattributed", String::new());
    }
    let need = size as usize;
    let min = std::mem::size_of::<TRACE_EVENT_INFO>();
    if need < min {
        return ("unattributed", String::new());
    }
    let mut buf = vec![0u64; need / 8 + 2];
    let raw = buf.as_mut_ptr() as *mut TRACE_EVENT_INFO;
    if TdhGetEventInformation(record, None, Some(raw), &mut size) != 0 {
        return ("unattributed", String::new());
    }
    let base = buf.as_ptr() as *const u8;
    let info = &*raw;
    let count = info.PropertyCount as usize;
    let arr = &info.EventPropertyInfoArray as *const EVENT_PROPERTY_INFO;
    let rec = &*record;
    let ud_len = rec.UserDataLength as usize;
    if rec.UserData.is_null() || ud_len == 0 || count == 0 {
        return ("unattributed", String::new());
    }
    let mut ud = vec![0u8; ud_len];
    std::ptr::copy_nonoverlapping(rec.UserData as *const u8, ud.as_mut_ptr(), ud_len);

    let mut link: Option<String> = None;
    let mut cursor = 0usize;
    for i in 0..count {
        if cursor >= ud_len {
            break;
        }
        let pi = &*arr.add(i);
        let name = if pi.NameOffset != 0 {
            read_wide_at(base.add(pi.NameOffset as usize))
        } else {
            String::new()
        };
        let non = pi.Anonymous1.nonStructType;
        let mut blen = 0u32;
        let mut consumed = 0u16;
        let rest = &ud[cursor..];
        let ask = TdhFormatProperty(
            base as *const TRACE_EVENT_INFO,
            None,
            8,
            non.InType,
            non.OutType,
            pi.Anonymous3.length,
            rest,
            &mut blen,
            PWSTR::null(),
            &mut consumed,
        );
        if ask != 0 && ask != ERROR_INSUFFICIENT_BUFFER {
            break; // schema says we cannot walk further; keep what we already resolved
        }
        let mut value = String::new();
        if blen > 0 {
            let mut wbuf = vec![0u16; (blen as usize) / 2 + 2];
            let mut used = 0u16;
            let rc = TdhFormatProperty(
                base as *const TRACE_EVENT_INFO,
                None,
                8,
                non.InType,
                non.OutType,
                pi.Anonymous3.length,
                rest,
                &mut blen,
                PWSTR(wbuf.as_mut_ptr()),
                &mut used,
            );
            if rc == 0 {
                consumed = used;
                value = String::from_utf16_lossy(&wbuf)
                    .trim_end_matches('\0')
                    .to_string();
            }
        }
        let key: String = name
            .to_ascii_lowercase()
            .chars()
            .filter(|c| *c != '_' && *c != '-')
            .collect();
        if key.contains("symboliclink") && !value.is_empty() && link.is_none() {
            link = Some(value);
        }
        if consumed == 0 {
            break;
        }
        cursor += consumed as usize;
    }

    match link {
        None => ("unattributed", String::new()),
        Some(l) => {
            let same = l.eq_ignore_ascii_case(TARGET_LINK);
            (if same { "cm400" } else { "other" }, l)
        }
    }
}

unsafe extern "system" fn on_event(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    TOTAL.fetch_add(1, Ordering::Relaxed);
    let r = &*record;
    let h = r.EventHeader;
    let d = h.EventDescriptor;
    if h.ProviderId == PROVIDERS[6] {
        KERNPROC.fetch_add(1, Ordering::Relaxed);
    }
    if h.ProviderId == PROVIDERS[0] {
        MF_ALL.fetch_add(1, Ordering::Relaxed);
        if d.Id == 10 {
            MF_ID10.fetch_add(1, Ordering::Relaxed);
        }
    }
    if let Ok(mut hist) = HIST.lock() {
        *hist
            .entry((h.ProviderId.to_u128(), d.Id, d.Opcode, d.Level))
            .or_insert(0) += 1;
    }
    let data = if r.UserData.is_null() || r.UserDataLength == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(r.UserData as *const u8, r.UserDataLength as usize)
    };
    let cm400 = looks_like_cm400(data);

    // Real attribution: TDH-declared properties, not a byte scan. `raw_cm400` is kept
    // only so the difference between the two methods stays visible in the data.
    let (attr, link) = tdh_attribution(r as *const EVENT_RECORD);

    // Full-fidelity trace line for stop-signal discovery: every event from a provider
    // we actually enabled, tagged with whether it carries the CM400 identity. Without
    // this the tool only prints heartbeats, which cannot answer "is there a STOP event".
    let ours = PROVIDERS
        .iter()
        .zip(ENABLED.iter())
        .any(|(p, e)| e.load(Ordering::Relaxed) && *p == h.ProviderId);
    if ours {
        let interesting = matches!(d.Id, 6 | 7 | 10 | 11 | 12 | 19);
        let (attrs, full_link) = if interesting {
            describe(r as *const EVENT_RECORD)
        } else {
            (String::new(), link.clone())
        };
        let hex = if interesting {
            data.iter()
                .take(48)
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join("")
        } else {
            String::new()
        };
        say(&format!(
            "EVT recvms={} ts={} provider={} Id={} Opcode={} Level={} Keyword=0x{:X} pid={} tid={} activity={} attr={} raw_cm400={} len={} link=\"{}\"{}{}",
            std::time::UNIX_EPOCH
                .elapsed()
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            h.TimeStamp,
            h.ProviderId.to_u128(),
            d.Id,
            d.Opcode,
            d.Level,
            d.Keyword,
            h.ProcessId,
            h.ThreadId,
            h.ActivityId.to_u128(),
            attr,
            cm400,
            r.UserDataLength,
            if full_link.is_empty() { link.clone() } else { full_link },
            if interesting { format!(" props=\"{attrs}\"") } else { String::new() },
            if interesting { format!(" payload=\"{hex}\"") } else { String::new() },
        ));
    }
    if attr != "cm400" {
        return;
    }
    if let Ok(mut hist) = HIST_CM400.lock() {
        *hist
            .entry((h.ProviderId.to_u128(), d.Id, d.Opcode, d.Level))
            .or_insert(0) += 1;
    }
    MATCHES.fetch_add(1, Ordering::Relaxed);
    println!(
        "CM400_MATCH  ts={}  provider={:?}  Id={} Opcode={} Level={} Keyword=0x{:X}  pid={} tid={} userLen={}",
        h.TimeStamp, h.ProviderId, d.Id, d.Opcode, d.Level, d.Keyword, h.ProcessId, h.ThreadId,
        r.UserDataLength
    );
}

fn try_enable_pending(session: CONTROLTRACE_HANDLE) {
    unsafe {
        for i in 0..PROVIDERS.len() {
            if ENABLED[i].load(Ordering::Relaxed) {
                continue;
            }
            let e = EnableTraceEx2(
                session,
                &PROVIDERS[i],
                1, /*EVENT_CONTROL_CODE_ENABLE_PROVIDER*/
                5,
                KEYWORDS[i],
                0,
                0,
                None,
            );
            if e == WIN32_ERROR(0) {
                ENABLED[i].store(true, Ordering::Relaxed);
                println!("[+] enabled provider {} ({})", i, NAMES[i]);
            }
        }
    }
}

/// Write to the console AND, when `--out` was given, to a file we flush per line.
/// Redirected stdout is block-buffered and a killed process loses the tail, which
/// previously looked exactly like "the provider sent nothing".
static OUT: Mutex<Option<std::fs::File>> = Mutex::new(None);

fn say(s: &str) {
    println!("{s}");
    if let Ok(mut g) = OUT.lock() {
        if let Some(f) = g.as_mut() {
            use std::io::Write;
            let _ = f.write_all(s.as_bytes());
            let _ = f.write_all(b"\n");
            let _ = f.flush();
        }
    }
}

/// Session admin by exact name. QUERY returns the kernel's own counters; STOP releases
/// the session (and one of the manifest provider's delivery slots). Only names we can
/// prove are ours are ever passed here - everything else is listed, never touched.
fn session_control(name: &str, stop: bool) {
    unsafe {
        let wsz: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let ps = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
        let nb = wsz.len() * 2;
        let mut buf = vec![0u8; ps + nb + 8];
        let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        // STOP/QUERY without a BufferSize covering the name fails with ERROR_BAD_LENGTH,
        // so the struct is allocated together with its trailing logger name.
        (*props).Wnode.BufferSize = (ps + nb + 8) as u32;
        (*props).LoggerNameOffset = ps as u32;
        std::ptr::copy_nonoverlapping(wsz.as_ptr() as *const u8, buf.as_mut_ptr().add(ps), nb);
        let code = if stop {
            EVENT_TRACE_CONTROL_STOP
        } else {
            EVENT_TRACE_CONTROL_QUERY
        };
        let err = ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(wsz.as_ptr()),
            props,
            code,
        );
        if stop {
            println!("stop  {name}: {:?}", err);
            return;
        }
        println!(
            "query {name}: win32={:?} buffers={} eventsLost={} logBuffersLost={} rtBuffersLost={}",
            err,
            (*props).NumberOfBuffers,
            (*props).EventsLost,
            (*props).LogBuffersLost,
            (*props).RealTimeBuffersLost
        );
    }
}

/// Read-only enumeration of trace sessions via QueryAllTracesW. Each properties block
/// must arrive with Wnode.BufferSize already set, which is why the buffers are allocated
/// at full size here. Private logging sessions are NOT returned by this API, so the
/// output is explicitly labelled as not an absolute list.
fn list_sessions(max: usize) {
    unsafe {
        let ps = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
        let pad = 2048usize;
        let mut blocks: Vec<Vec<u8>> = (0..max).map(|_| vec![0u8; ps + pad]).collect();
        let mut ptrs: Vec<*mut EVENT_TRACE_PROPERTIES> = blocks
            .iter_mut()
            .map(|b| {
                let p = b.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
                (*p).Wnode.BufferSize = (ps + pad) as u32;
                p
            })
            .collect();
        let mut count = 0u32;
        // The generated binding derives the array capacity from the slice length and
        // hands back one count, so only two arguments exist here.
        let err = QueryAllTracesW(&mut ptrs, &mut count);
        println!(
            "QueryAllTracesW: win32={:?} count={} (capacity {})",
            err.0, count, max
        );
        println!(
            "  NOTE: private logging sessions are not returned; this is not an absolute list."
        );
        // The reported count's exact meaning is not stated by the binding, so walk the
        // whole capacity and skip empty slots instead of trusting it.
        for (i, p) in ptrs[..max].iter().copied().enumerate() {
            if p.is_null() {
                continue;
            }
            let base = p as *const u8;
            let logger = read_wide_at(base.add((*p).LoggerNameOffset as usize));
            if logger.is_empty() {
                continue;
            }
            let logfile = if (*p).LogFileNameOffset != 0 {
                read_wide_at(base.add((*p).LogFileNameOffset as usize))
            } else {
                String::new()
            };
            println!(
                "  [{i}] name=\"{logger}\" guid={:?} mode=0x{:X} buffers={}/{} sizeKB={} flush={} eventsLost={} logLost={} rtLost={} file=\"{logfile}\"",
                (*p).Wnode.Guid,
                (*p).LogFileMode,
                (*p).NumberOfBuffers,
                (*p).MaximumBuffers,
                (*p).BufferSize,
                (*p).FlushTimer,
                (*p).EventsLost,
                (*p).LogBuffersLost,
                (*p).RealTimeBuffersLost
            );
        }
    }
}

fn fmt_provider(p: u128) -> String {
    PROVIDERS
        .iter()
        .position(|g| g.to_u128() == p)
        .map(|i| NAMES[i].to_string())
        .unwrap_or_else(|| format!("{p:X}"))
}

/// Which (provider, Id, Opcode, Level) triples actually repeat? The steady-use
/// signal has to be picked from this table, not from a guess.
fn print_histograms() {
    print_hist("ALL events", &HIST);
    print_hist("CM400-attributed events", &HIST_CM400);
}

/// One histogram row key: provider GUID, event id, opcode, level.
type HistKey = (u128, u16, u8, u8);

fn print_hist(label: &str, hist: &Mutex<BTreeMap<HistKey, u64>>) {
    let Ok(hist) = hist.lock() else { return };
    let mut rows: Vec<_> = hist.iter().map(|(k, v)| (*k, *v)).collect();
    rows.sort_by_key(|row| std::cmp::Reverse(row.1));
    println!("--- histogram: {label} (top 10 by count) ---");
    for ((p, id, op, lvl), n) in rows.into_iter().take(10) {
        println!(
            "  {n:>8}  {:<16}  Id={id} Opcode={op} Level={lvl}",
            fmt_provider(p)
        );
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("all-sessions") => {
            let n = args
                .get(2)
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(64)
                .min(256);
            list_sessions(n);
            return;
        }
        Some("sessions") => {
            for n in &args[2..] {
                session_control(n, false);
            }
            return;
        }
        Some("stop") => {
            for n in &args[2..] {
                session_control(n, true);
            }
            return;
        }
        _ => {}
    }
    if let Some(pos) = args.iter().position(|a| a == "--out") {
        if let Some(p) = args.get(pos + 1) {
            if let Ok(f) = std::fs::File::create(p) {
                *OUT.lock().unwrap_or_else(|e| e.into_inner()) = Some(f);
            }
        }
    }
    let duration = match args.get(1) {
        None => 180,
        Some(a) => match a.parse::<u64>() {
            Ok(n) => n,
            // A typo used to silently start a 180s recording, which is exactly what
            // happened when `all-sessions` did not exist yet in the running binary.
            Err(_) => {
                eprintln!("unknown first argument {a:?}; expected <seconds> or sessions|stop|all-sessions");
                std::process::exit(1);
            }
        },
    };

    let session = format!("CM400-ETW-Probe-{}\0", std::process::id());
    let session_wide: Vec<u16> = session.encode_utf16().collect();

    let session_handle = unsafe {
        let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
        let name_bytes = session_wide.len() * 2;
        let mut buf = vec![0u8; props_size + name_bytes + 8];
        let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        (*props).Wnode.BufferSize = (props_size + name_bytes + 8) as u32;
        (*props).Wnode.ClientContext = 2;
        (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*props).FlushTimer = 1;
        (*props).MinimumBuffers = 64;
        (*props).LoggerNameOffset = props_size as u32;
        let name_dst = buf.as_mut_ptr().add(props_size) as *mut u16;
        std::ptr::copy_nonoverlapping(session_wide.as_ptr(), name_dst, session_wide.len());

        let mut h = CONTROLTRACE_HANDLE::default();
        let err = StartTraceW(&mut h, PCWSTR(session_wide.as_ptr()), props);
        if err != WIN32_ERROR(0) {
            eprintln!("StartTraceW failed: {:?}", err);
            std::process::exit(2);
        }
        println!("session started: {}", session.trim_end_matches('\0'));
        try_enable_pending(h);
        h
    };

    let trace_handle = unsafe {
        let mut logfile = EVENT_TRACE_LOGFILEW {
            LoggerName: PWSTR(session_wide.as_ptr() as *mut _),
            Anonymous1: EVENT_TRACE_LOGFILEW_0 {
                ProcessTraceMode: PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD,
            },
            Anonymous2: EVENT_TRACE_LOGFILEW_1 {
                EventRecordCallback: Some(on_event),
            },
            ..std::mem::zeroed()
        };
        let th = OpenTraceW(&mut logfile);
        if th.Value == u64::MAX {
            eprintln!("OpenTraceW failed");
            std::process::exit(3);
        }
        th
    };

    // Worker: retry-enable pending providers + heartbeat, then stop ProcessTrace.
    {
        let session = session_handle;
        let thv = trace_handle.Value;
        std::thread::spawn(move || {
            let start = Instant::now();
            let mut last_beat = Instant::now();
            loop {
                std::thread::sleep(Duration::from_millis(2000));
                try_enable_pending(session);
                if last_beat.elapsed() >= Duration::from_secs(10) {
                    println!(
                        "[beat] t={:>3.0}s total={} matches={} kernproc={} mf_all={} mf_id10={} enabled={:?}",
                        start.elapsed().as_secs_f32(),
                        TOTAL.load(Ordering::Relaxed),
                        MATCHES.load(Ordering::Relaxed),
                        KERNPROC.load(Ordering::Relaxed),
                        MF_ALL.load(Ordering::Relaxed),
                        MF_ID10.load(Ordering::Relaxed),
                        ENABLED.iter().map(|a| a.load(Ordering::Relaxed)).collect::<Vec<_>>()
                    );
                    print_histograms();
                    last_beat = Instant::now();
                }
                if start.elapsed() >= Duration::from_secs(duration) {
                    unsafe {
                        let _ = CloseTrace(PROCESSTRACE_HANDLE { Value: thv });
                    }
                    break;
                }
            }
        });
    }

    println!("recording {}s — do the camera sequence now...", duration);
    let pt = unsafe { ProcessTrace(&[trace_handle], None, None) };
    println!("ProcessTrace returned: {:?}", pt);
    let ct = unsafe { CloseTrace(trace_handle) };
    println!("CloseTrace returned: win32={:?}", ct.0);
    // Stop the session by name on every exit path. An un-stopped real-time session
    // survives us: manifest providers deliver to at most 8 sessions, so leaked
    // consumers can leave a fresh session enabled-but-starved (0 callbacks).
    session_control(session.trim_end_matches('\0'), true);
    println!(
        "DONE. total_events={} cm400_matches={} kernproc_events={} mf_all={} mf_id10={}",
        TOTAL.load(Ordering::Relaxed),
        MATCHES.load(Ordering::Relaxed),
        KERNPROC.load(Ordering::Relaxed),
        MF_ALL.load(Ordering::Relaxed),
        MF_ID10.load(Ordering::Relaxed)
    );
    print_histograms();
}
