//! cm400ctl — CM400 diagnostic CLI (NOT a product runtime dependency).
//!
//! Drives the real device through the SAME path the service uses
//! (`cm400_core::Engine` -> `Transport` -> `MotorChannel`), so the shared core is
//! exercised end-to-end and a diagnostic never claims a health the product has.
//!
//! MI_02 is an exclusive interface, and the service no longer holds it between
//! commands - so `status` separates "is the device there" from "can I get it right
//! now", and a failed open is reported as contention rather than as absence.
//! Runs as a normal user (W0-B: no elevation needed for the WinUSB path).

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cm400_core::{ActivitySource, Clock, Engine, Store};
use cm400_persistence::FileStore;
use cm400_policy::{CM400Activity, Mode, Policy};
use cm400_state::{PhysicalState, Transition};
use cm400_windows::config::Config;
use cm400_windows::{MotorChannel, WinUsbTransport, WindowsFrameServerEtwSource};

struct SysClock;
impl Clock for SysClock {
    fn now_ms(&mut self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

struct FixedActivity(CM400Activity);
impl ActivitySource for FixedActivity {
    fn activity(&mut self) -> CM400Activity {
        self.0
    }
}

fn store_path() -> std::path::PathBuf {
    // Same store the resident daemon reads/writes: a manual move must be
    // visible to the daemon's recovery, or the two disagree about the lens.
    Config::state_path()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("status");
    match cmd {
        "status" => status(),
        "raise" => drive(true),
        "retract" => drive(false),
        "activity-watch" => activity_watch(),
        "usbprobe" => usbprobe(),
        other => {
            eprintln!(
                "usage: cm400ctl [status|raise|retract|activity-watch|usbprobe]  (got: {other})"
            );
            std::process::exit(1);
        }
    }
}

/// 2-D gate check: does this firmware carry a Microsoft OS descriptor (1.0 via
/// string index 0xEE, and/or 2.0 via a BOS platform capability) that declares the
/// `WINUSB` compatible ID? If it does, a clean machine can bind the inbox WinUSB
/// driver with NO custom INF - which removes the entire package-signing question.
///
/// Strictly read-only: every request below is a GET_DESCRIPTOR or a vendor IN.
fn usbprobe() {
    let tr = match WinUsbTransport::open() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("open failed: {e:?}");
            std::process::exit(2);
        }
    };

    let mut dd = [0u8; 18];
    match tr.get_descriptor(0x01, 0, 0, &mut dd) {
        Ok(n) => println!(
            "DEVICE   : {n} bytes  bcdUSB=0x{:04x} (BOS needs >=0x0201)  class=0x{:02x}  configs={}",
            u16::from_le_bytes([dd[2], dd[3]]),
            dd[4],
            dd[17]
        ),
        Err(e) => println!("DEVICE   : read failed {e:?}"),
    }

    // Control for the 0xEE result: if a *known* string also fails, then "absent"
    // tells us nothing (WinUSB refusing to relay looks identical to the device not
    // implementing it), and the verdict would have to be downgraded.
    let mut lang = [0u8; 8];
    match tr.get_descriptor(0x03, 0, 0, &mut lang) {
        Ok(n) => println!("LANGID   : {n} bytes read  data={:02x?}", &lang[..n]),
        Err(e) => println!("LANGID   : read failed {e:?}"),
    }
    if dd[14] > 0 {
        let mut s = [0u8; 64];
        match tr.get_descriptor(0x03, dd[14], 0x0409, &mut s) {
            Ok(n) => println!("STRING   : iManufacturer({}) readable, {n} bytes", dd[14]),
            Err(e) => println!("STRING   : iManufacturer({}) FAILED {e:?}", dd[14]),
        }
    }

    // Interface triples decide what a production INF must match on.
    let mut ch = [0u8; 9];
    if tr.get_descriptor(0x02, 0, 0, &mut ch).is_ok() {
        let total = u16::from_le_bytes([ch[2], ch[3]]) as usize;
        let mut cfg = vec![0u8; total.min(1024)];
        match tr.get_descriptor(0x02, 0, 0, &mut cfg) {
            Ok(n) => {
                println!("CONFIG   : {n} bytes (declared {total}) interfaces:");
                dump_interfaces(&cfg[..n]);
            }
            Err(e) => println!("CONFIG   : full read failed {e:?}"),
        }
    } else {
        println!("CONFIG   : header read failed");
    }

    // MS OS 1.0 header: bLength, bDescriptorType(03), then 'MSFT100' + vendor code.
    let mut os1 = [0u8; 16];
    let mut vendor1 = None;
    match tr.get_descriptor(0x03, 0xEE, 0x0409, &mut os1) {
        Ok(n) if n >= 11 => {
            let sig = &os1[4..9];
            println!(
                "OS 1.0   : string 0xEE present ({n} bytes) bLength=0x{:02x} sig={:?} vendorCode=0x{:02x}",
                os1[0],
                String::from_utf8_lossy(sig),
                os1[10]
            );
            if sig == b"MSFT100" {
                vendor1 = Some(os1[10]);
            }
        }
        Ok(n) => println!("OS 1.0   : string 0xEE short read ({n} bytes)"),
        Err(e) => println!("OS 1.0   : string 0xEE absent ({e:?})"),
    }

    // MS OS 2.0 lives behind a BOS platform-capability record.
    let mut vendor2 = None;
    let mut head = [0u8; 4];
    if tr.get_descriptor(0x0F, 0, 0, &mut head).is_ok() {
        let total = u16::from_le_bytes([head[2], head[3]]) as usize;
        let mut bos = vec![0u8; total.clamp(4, 512)];
        match tr.get_descriptor(0x0F, 0, 0, &mut bos) {
            Ok(n) => {
                println!("BOS      : {n} bytes read (declared {total})");
                dump_caps(&bos[..n]);
                vendor2 = ms_os2_vendor_code(&bos[..n]);
                println!(
                    "  MS OS 2.0 platform capability: {}",
                    if vendor2.is_some() {
                        "present"
                    } else {
                        "absent"
                    }
                );
            }
            Err(e) => println!("BOS      : full read failed {e:?}"),
        }
    } else {
        println!("BOS      : not readable (device predates BOS)");
    }

    let mut found = false;
    if let Some(code) = vendor1 {
        let mut set = vec![0u8; 4096];
        match tr.vendor_in(code, 0, 0x0004, &mut set) {
            Ok(n) => found |= report_set("OS 1.0 set", n, &set),
            Err(e) => println!("OS 1.0 set: fetch failed {e:?}"),
        }
    }
    if let Some(code) = vendor2 {
        let mut set = vec![0u8; 4096];
        match tr.vendor_in(code, 0, 0x0007, &mut set) {
            Ok(n) => found |= report_set("OS 2.0 set", n, &set),
            Err(e) => println!("OS 2.0 set: fetch failed {e:?}"),
        }
    }

    println!(
        "\nVERDICT  : MS OS descriptor present = {}   WINUSB compatible ID = {}",
        if vendor1.is_some() || vendor2.is_some() {
            "YES"
        } else {
            "NO"
        },
        if found { "YES" } else { "NO" }
    );
    println!(
        "           => inbox WinUSB without a custom INF: {}",
        if found {
            "POSSIBLE (confirm on a clean machine)"
        } else {
            "NOT POSSIBLE - self-signed INF/CAT route stands"
        }
    );
}

/// Walk a config descriptor blob and report interfaces + IADs. This is what tells
/// us whether MI_02 is a vendor-specific (0xFF) function or, say, DFU (0xFE/01/01),
/// which the INF must match exactly.
fn dump_interfaces(cfg: &[u8]) {
    let mut i = 0usize;
    while i + 2 < cfg.len() {
        let len = cfg[i] as usize;
        let kind = cfg[i + 1];
        if len == 0 || i + len > cfg.len() {
            break;
        }
        match kind {
            0x04 => println!(
                "  IF {:>2} alt={} eps={} class=0x{:02x} sub=0x{:02x} proto=0x{:02x} str={}",
                cfg[i + 2],
                cfg[i + 3],
                cfg[i + 4],
                cfg[i + 5],
                cfg[i + 6],
                cfg[i + 7],
                cfg.get(i + 8).copied().unwrap_or(0)
            ),
            0x0B => println!(
                "  IAD    : firstIF={} count={} class=0x{:02x} sub=0x{:02x} proto=0x{:02x}",
                cfg[i + 2],
                cfg[i + 3],
                cfg[i + 4],
                cfg[i + 5],
                cfg[i + 6]
            ),
            _ => {}
        }
        i += len;
    }
}

/// BOS capability records: [bLength][bDescriptorType=0x10][bCapabilityType]...
fn dump_caps(bos: &[u8]) {
    let mut i = 4usize; // BOS header
    while i + 1 < bos.len() {
        let len = bos[i] as usize;
        if len == 0 || i + len > bos.len() {
            break;
        }
        println!("  cap @i={i} len={len} capabilityType=0x{:02x}", bos[i + 2]);
        i += len;
    }
}

/// Vendor code for the MS OS 2.0 set, from the platform capability whose GUID is
/// D8DD60DF-4589-4CC7-9CC2-CDABCFE9C899 (mixed-endian on the wire).
fn ms_os2_vendor_code(bos: &[u8]) -> Option<u8> {
    const MS_OS20_UUID: [u8; 16] = [
        0xDF, 0x60, 0xDD, 0xD8, 0x89, 0x45, 0xC7, 0x4C, 0x9C, 0xC2, 0xCD, 0xAB, 0xCF, 0xE9, 0xC8,
        0x99,
    ];
    let mut i = 4usize;
    while i + 1 < bos.len() {
        let len = bos[i] as usize;
        if len == 0 || i + len > bos.len() {
            break;
        }
        let rec = &bos[i..i + len];
        // GUID sits at offset 4; vendor code follows GUID(16) + set length(2).
        if rec.get(2) == Some(&0x05) && rec.get(4..20) == Some(&MS_OS20_UUID[..]) {
            return rec.get(22).copied().filter(|&v| v != 0);
        }
        i += len;
    }
    None
}

/// The sets are a sequence of headers/subsets; rather than hand-decode every
/// variant, look for the literal compatible ID and show its surroundings.
fn report_set(label: &str, n: usize, data: &[u8]) -> bool {
    let body = &data[..n];
    match body.windows(6).position(|w| w == b"WINUSB") {
        Some(off) => {
            let lo = off.saturating_sub(16);
            let hi = (off + 16).min(n);
            println!(
                "{label}: {n} bytes, WINUSB @ {off}, context {:02x?}",
                &body[lo..hi]
            );
            true
        }
        None => {
            println!(
                "{label}: {n} bytes, no WINUSB literal (first 64: {:02x?})",
                &body[..64.min(n)]
            );
            false
        }
    }
}

fn status() {
    let mut store = FileStore::new(store_path());
    let persisted = store.load();

    // Four different questions. Collapsing them is what made an exclusive-interface
    // failure look like "no camera attached".
    match cm400_windows::find_motor_interface() {
        Some((_, via)) => println!("device          : present (MI_02 interface found via {via})"),
        None => println!("device          : absent (no MI_02 interface under either GUID)"),
    }
    let mut ch = MotorChannel::new();
    match ch.get() {
        Ok(echo) => println!(
            "motor transport : available (echo={echo} - a state var, NOT physical position)"
        ),
        Err(e) => println!(
            "motor transport : unavailable ({e:?}) - another opener holds MI_02; stop the service to take over"
        ),
    }
    println!("persisted       : {persisted:?}");
}

fn drive(raise: bool) {
    // Safety gate. `XU writes must be >=3s apart` protects the mechanism, and that
    // throttle lives inside one Engine. On-demand access (D7) means a second
    // process can now reach the device, so a manual command could land 0ms after a
    // daemon-issued one - a per-process mutex cannot prevent that. Refuse instead.
    if cm400_windows::runtime::service_is_live() {
        eprintln!(
            "refusing to actuate: the CM400Driver service is running, and a manual SET could violate the >=3s XU write gap.\nstop it first:  sc stop CM400Driver"
        );
        std::process::exit(4);
    }
    let mut store = FileStore::new(store_path());
    let mut clk = SysClock;
    let mut ch = MotorChannel::new();
    if let Err(e) = ch.probe() {
        eprintln!("device not reachable: {e:?}");
        std::process::exit(2);
    }
    // raise -> Automatic (active => eager Raise); retract -> Automatic with 0 grace
    // so a single inactive tick immediately issues Retract.
    let policy = if raise {
        Policy::default()
    } else {
        Policy {
            mode: Mode::Automatic,
            down_grace_ms: 0,
        }
    };
    let mut eng = Engine::new(policy);
    eng.recover(&mut store, clk.now_ms());
    let mut act = FixedActivity(if raise {
        CM400Activity::Active
    } else {
        CM400Activity::Inactive
    });
    let want = if raise {
        PhysicalState::Up
    } else {
        PhysicalState::Down
    };

    let start = Instant::now();
    loop {
        eng.tick(&mut act, &mut clk, &mut ch, &mut store);
        let s = eng.status();
        if s.transition == Transition::Idle && s.physical == want {
            break;
        }
        if start.elapsed() > Duration::from_secs(12) {
            eprintln!("timeout waiting for settle");
            break;
        }
        std::thread::sleep(Duration::from_millis(400));
    }
    println!("final status = {:?}", eng.status());
}

/// Pure observation: prints CM400 activity transitions from the real-time
/// ETW source. Never touches the motor, never captures frames.
fn activity_watch() {
    let timeout_ms = std::env::args()
        .nth(2)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(3000);
    // Unique session name + no takeover: observing must never disturb the running
    // service's fixed-name logger, so both can coexist on the same machine.
    let mut src = match WindowsFrameServerEtwSource::for_diagnostics(timeout_ms) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ETW source init failed (run as admin?) err={}", e);
            std::process::exit(2);
        }
    };
    let mut last = CM400Activity::Unknown;
    let start = Instant::now();
    let mut last_beat = Instant::now();
    println!(
        "watching CM400 activity via ETW (timeout={}ms, Ctrl+C to stop)...",
        timeout_ms
    );
    loop {
        let a = src.activity();
        // Print on every state edge, plus a throttled funnel beat (heartbeats
        // change every ~50ms, so an unconditional beat would flood the console).
        if a != last || last_beat.elapsed() >= Duration::from_secs(2) {
            println!(
                "t+{:>3.0}s  {:?}  age={:?}ms  funnel={:?}",
                start.elapsed().as_secs_f32(),
                a,
                src.age_ms(),
                src.funnel()
            );
            last = a;
            last_beat = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}
