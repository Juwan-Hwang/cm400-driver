//! cm400-capture-probe - command-line Media Foundation capture, no Camera GUI.
//!
//! Why this exists: the service can only infer "the stream stopped" from the
//! ABSENCE of MF-FrameServer heartbeats, which costs a heartbeat timeout plus the
//! reaper tick plus FrameServer's own teardown lag. To find out whether a *positive*
//! stop event exists, the open/stream/shutdown cycle must be reproducible to the
//! millisecond, and clicking a GUI cannot do that.
//!
//! Timeline printed, all relative to process start:
//!   enumerate -> select-by-symbolic-link -> activate -> create source reader ->
//!   FIRST FRAME -> LAST FRAME -> SHUTDOWN request -> Shutdown returned -> dropped
//!
//! Selection is by symbolic link, never "device 0": the CM400 run must match
//! `vid_0603&pid_8612&mi_00`; the built-in-camera control run must be a device that
//! is NOT the CM400, otherwise the negative control proves nothing.
//!
//! This binary touches Media Foundation only. It has no WinUSB path, so it cannot
//! send a motor control transfer even by accident.
use std::ffi::c_void;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use windows::core::{Interface, PWSTR};
use windows::Win32::Media::MediaFoundation::{
    IMFActivate, IMFAttributes, IMFMediaSource, IMFSample, MFCreateAttributes,
    MFCreateSourceReaderFromMediaSource, MFEnumDeviceSources, MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
    MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID,
    MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK, MF_SOURCE_READERF_ENDOFSTREAM,
    MF_SOURCE_READER_FIRST_VIDEO_STREAM,
};
use windows::Win32::System::Com::{CoInitializeEx, CoTaskMemFree, COINIT_APARTMENTTHREADED};

/// The CM400 capture function, as a case-insensitive substring of the symbolic link.
const CM400_LINK: &str = "vid_0603&pid_8612&mi_00";

struct Picked {
    activate: IMFActivate,
    link: String,
}

fn main() {
    let mut argv = std::env::args().skip(1);
    let seconds: u64 = argv
        .next()
        .unwrap_or_else(|| "10".to_string())
        .parse()
        .unwrap_or(10);
    let want = argv.next().unwrap_or_else(|| "cm400".to_string());
    // Optional: append machine-readable wall-clock stamps for the analysis step, which
    // must key off the real streaming interval, not an offset guessed from start time.
    let marks = argv.next().map(std::path::PathBuf::from);

    unsafe {
        // S_OK or S_FALSE both leave COM usable on this thread; MF needs that.
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
    }

    let t0 = Instant::now();
    let unix_ms = |t: Instant| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| {
                d.as_millis() as i64 - t0.elapsed().as_millis() as i64
                    + t.duration_since(t0).as_millis() as i64
            })
            .unwrap_or(0)
    };
    let open_unix = unix_ms(t0);
    let ms = |t: Instant| format!("{:>7}ms", t.duration_since(t0).as_millis());
    println!("mode           : {want}   stream for {seconds}s");

    let device = match unsafe { pick_device(&want) } {
        Ok(d) => d,
        Err(e) => {
            eprintln!("device selection failed: {e}");
            std::process::exit(2);
        }
    };
    println!("{} selected     : {}", ms(t0), device.link);

    let source: IMFMediaSource = match unsafe { device.activate.ActivateObject() } {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ActivateObject failed: {e}");
            std::process::exit(3);
        }
    };
    let at_act = t0.elapsed().as_millis();
    println!("{:>7}ms activated  : media source obtained", at_act);

    let reader = match unsafe { MFCreateSourceReaderFromMediaSource(&source, None) } {
        Ok(r) => r,
        Err(e) => {
            eprintln!("MFCreateSourceReaderFromMediaSource failed: {e}");
            std::process::exit(4);
        }
    };
    println!(
        "{}",
        format_args!("{} reader      : created", ms(Instant::now()))
    );

    // Frames must actually be pulled. Activating without reading is not a streaming
    // session, and FrameServer would have no session to report on.
    let mut frames = 0u64;
    let mut first: Option<Instant> = None;
    let mut last = t0;
    let deadline = t0 + Duration::from_secs(seconds);
    loop {
        if Instant::now() >= deadline {
            break;
        }
        let mut sample: Option<IMFSample> = None;
        let mut actual_stream = 0u32;
        let mut stream_flags = 0u32;
        let mut ts = 0i64;
        match unsafe {
            reader.ReadSample(
                MF_SOURCE_READER_FIRST_VIDEO_STREAM.0 as u32,
                0,
                Some(&mut actual_stream),
                Some(&mut stream_flags),
                Some(&mut ts),
                Some(&mut sample),
            )
        } {
            Ok(()) => {
                if stream_flags & MF_SOURCE_READERF_ENDOFSTREAM.0 as u32 != 0 {
                    println!("{} end of stream", ms(Instant::now()));
                    break;
                }
                if sample.is_some() {
                    frames += 1;
                    last = Instant::now();
                    if first.is_none() {
                        first = Some(last);
                        println!("{} FIRST FRAME", ms(last));
                    }
                }
            }
            Err(e) => {
                println!("{} ReadSample error: {e}", ms(Instant::now()));
                break;
            }
        }
    }

    println!(
        "{} stop reading   : frames={frames}{}",
        ms(Instant::now()),
        if frames == 0 {
            "  <-- ZERO FRAMES: no real stream, any timing here is meaningless"
        } else {
            ""
        }
    );
    if let Some(f) = first {
        println!("{} LAST FRAME    : {}", ms(last), (last - f).as_millis());
    }
    let tstop = Instant::now();
    println!("{} SHUTDOWN requested", ms(tstop));
    let stop_unix = unix_ms(tstop);
    let last_unix = unix_ms(last);
    match unsafe { source.Shutdown() } {
        Ok(()) => println!("{} Shutdown returned", ms(Instant::now())),
        Err(e) => println!("{} Shutdown error: {e}", ms(Instant::now())),
    }
    // Dropping the wrappers releases the COM references (windows-rs Ref owns them),
    // which is what lets FrameServer tear the session down for real.
    drop(reader);
    drop(source);
    drop(device);
    let release_unix = unix_ms(Instant::now());
    println!(
        "{} refs dropped  : reader + source + activate",
        ms(Instant::now())
    );
    if let Some(path) = &marks {
        let line = format!(
            "ROUND\t{want}\t{}\t{}\t{last_unix}\t{stop_unix}\t{release_unix}\t{frames}\n",
            open_unix,
            first.map(unix_ms).unwrap_or(0)
        );
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = f.write_all(line.as_bytes());
        }
    }

    println!(
        "RESULT mode={want} frames={frames} first_ms={} last_ms={} shutdown_ms={}",
        first.map(|f| f.duration_since(t0).as_millis()).unwrap_or(0),
        last.duration_since(t0).as_millis(),
        tstop.duration_since(t0).as_millis(),
    );
    if frames == 0 {
        std::process::exit(5);
    }
}

unsafe fn pick_device(want: &str) -> Result<Picked, String> {
    let mut attrs_opt: Option<IMFAttributes> = None;
    MFCreateAttributes(&mut attrs_opt, 0).map_err(|e| format!("MFCreateAttributes: {e}"))?;
    let attrs = attrs_opt.ok_or_else(|| "MFCreateAttributes returned None".to_string())?;
    attrs
        .SetGUID(
            &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
            &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID,
        )
        .map_err(|e| format!("SetGUID: {e}"))?;

    let mut devices: *mut Option<IMFActivate> = std::ptr::null_mut();
    let mut count = 0u32;
    MFEnumDeviceSources(&attrs, &mut devices, &mut count)
        .map_err(|e| format!("MFEnumDeviceSources: {e}"))?;
    if devices.is_null() || count == 0 {
        return Err("no capture devices found".to_string());
    }

    let mut chosen: Option<Picked> = None;
    for i in 0..count as usize {
        // Clone increments the refcount; the array itself is owned by MF and freed
        // at the end, so this stays valid after the loop.
        let act: IMFActivate = match (*devices.add(i)).as_ref() {
            Some(a) => a.clone(),
            None => continue,
        };
        let a: IMFAttributes = match act.cast() {
            Ok(v) => v,
            Err(e) => {
                println!("  device[{i}]      : <no attributes: {e}>");
                continue;
            }
        };
        let mut pw = PWSTR::null();
        let mut len = 0u32;
        let got = a.GetAllocatedString(
            &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK,
            &mut pw,
            &mut len,
        );
        let link = if got.is_err() || pw.is_null() {
            String::from("(symbolic link unavailable)")
        } else {
            let s = pw.display().to_string();
            CoTaskMemFree(Some(pw.as_ptr() as *const c_void));
            s
        };
        println!("  device[{i}]      : {link}");
        let is_cm400 = link.to_ascii_lowercase().contains(CM400_LINK);
        let take = match want {
            "cm400" => is_cm400,
            "integrated" | "other" => !is_cm400,
            _ => false,
        };
        if take && chosen.is_none() {
            chosen = Some(Picked {
                activate: act,
                link,
            });
        }
    }
    CoTaskMemFree(Some(devices as *const c_void));
    chosen.ok_or_else(|| {
        format!("no device matched mode '{want}' (cm400 means link contains {CM400_LINK})")
    })
}
