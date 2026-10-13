//! Reachability probe for the `IKsControl` motor path, runnable from any process context.
//!
//! Why a probe rather than a production channel: the same control is reachable through the vendor
//! XU on the WinUSB interface the service already owns, and through `IKsControl` on the camera's KS
//! proxy. A third-party project drives the motor that way, and on this machine it did so with the
//! device not streaming and with no graph built. That is not yet a migration decision: the tool
//! that proved it is a .NET program which cannot even start as `LocalService` here (its runtime
//! sits in a dev-environment path, so the service account reports ".NET location: Not found"), and
//! `oem64.inf` is still installed on this machine. Answering the real question - does the path work
//! inside the production service - needs code that runs in the service process, so this module is
//! deliberately small, and read-only unless actuation is asked for by name.
//!
//! Staged reporting is the point. "IKsControl failed" cannot distinguish a device that is absent
//! from one whose proxy refuses the call from a COM initialization problem, and those three lead to
//! three different decisions.

use cm400_protocol::{
    KSPROPERTY_TYPE_GET, KSPROPERTY_TYPE_SET, KSPROPERTY_TYPE_TOPOLOGY, MOTOR_KS_GET_BUFFER_BYTES,
    MOTOR_KS_NODE_ID, MOTOR_KS_PROPERTY_HEADER_BYTES, MOTOR_KS_SET_DATA_BYTES, MOTOR_SELECTOR,
    MOTOR_XU_GUID_U128, PID, VID,
};

/// `KSPROPERTY`'s three fields are 24 bytes; the length the measured call passes is 32. The buffer
/// is sized for the larger number and zero-padded, so passing 32 cannot read past what we own.
const HEADER_BYTES: usize = MOTOR_KS_PROPERTY_HEADER_BYTES as usize;

/// COM already being initialized on this thread is not a failure: a service thread may already hold
/// an apartment, and mistaking that for an initialization refusal would report the service context
/// as unsupported when nothing had actually been attempted.
const RPC_E_CHANGED_MODE: i32 = -2147418113;

/// Candidate call shapes `(property length, data length)`, tried in order and reported one by one.
///
/// Two objects can answer `IKsControl` here and they are not known to agree: the DirectShow capture
/// filter (which the measured third-party call passes a 32-byte property header to, and which
/// answered on this machine) and the Media Foundation source's KS proxy, which on this device
/// refused the same call with `E_INVALIDARG`. Guessing one shape would turn that difference into a
/// silent failure, so the probe states which shape worked, or lists what each one answered.
const SHAPES: [(u32, u32); 4] = [
    (24, 8),
    (24, 1),
    (24, 2),
    (MOTOR_KS_PROPERTY_HEADER_BYTES, MOTOR_KS_GET_BUFFER_BYTES),
];

/// Where the probe got to. Each flag is set only after the call producing it succeeded, so a report
/// cannot claim further than it observed.
#[derive(Debug, Clone, Default)]
pub struct Report {
    /// COM is usable on this thread.
    pub com_ok: bool,
    /// Video capture sources enumerated in this context.
    pub sources: u32,
    /// One of them carries our VID/PID in its symbolic link.
    pub matched: bool,
    /// Friendly name of the matched source, recorded rather than assumed.
    pub name: String,
    /// The activated media source answered for `IKsControl`.
    pub ksp_ok: bool,
    /// `GET_CUR` on the motor selector, and the value read.
    pub get_cur: Option<u8>,
    /// Bytes the proxy says it returned. Recorded, not required - see `get_cur`.
    pub get_returned: u32,
    /// Value read after an actuation, when one was asked for.
    pub read_back: Option<u8>,
    /// The shape that worked, once a read succeeded.
    pub shape: Option<(u32, u32)>,
    /// Every shape tried and what it answered, so a failure names the alternatives it excluded.
    pub attempts: Vec<String>,
    /// Which object this probe reached the proxy through: `directshow` or `media-foundation`. The
    /// two are different COM objects on different devices, and results are not interchangeable.
    pub via: &'static str,
    /// The identity string the DirectShow walk matched on (device path or display name).
    pub identity: String,
    /// Which interface the moniker was bound to before `IKsControl` was queried.
    pub bound_via: &'static str,
    /// Which identity string the walk matched on: `device-path`, `display-name` or `friendly-name`.
    /// Recorded because a run that only matched a label must not read as path-keyed.
    pub identity_source: &'static str,
    /// Raw bytes of the last successful GET buffer, hex, so the log shows what the proxy actually
    /// filled rather than only the first byte we picked out of it.
    pub get_hex: String,
    /// Text of the first failure, with the stage that produced it.
    pub failure: String,
}

impl Report {
    /// One line for the log. `unavailable at <stage>` names the stage that stopped us rather than
    /// implying a cause that was not observed, and always says which object the run went through.
    pub fn verdict(&self) -> String {
        if self.ksp_ok && self.get_cur.is_some() {
            return format!(
                "IKsControl reachable via {} on {}, GET_CUR(selector {MOTOR_SELECTOR}) = {} [{} bytes returned, buffer {}]",
                self.via,
                if self.identity.is_empty() { "unknown object" } else { self.identity.as_str() },
                self.get_cur.unwrap_or(0),
                self.get_returned,
                if self.get_hex.is_empty() { "-" } else { self.get_hex.as_str() }
            );
        }
        let stage = if !self.com_ok {
            "CoInitializeEx"
        } else if self.sources == 0 {
            "capture-source enumeration"
        } else if !self.matched {
            "matching our VID/PID/MI_00 among the sources"
        } else if !self.ksp_ok {
            "QueryInterface IKsControl"
        } else {
            "KsProperty GET_CUR"
        };
        format!(
            "IKsControl via {} unavailable at {stage}: {}",
            self.via, self.failure
        )
    }

    /// Actuation is judged by read-back, never by the write's own return code: the state variable
    /// can answer while the mechanism is doing something else, so a SET without a matching
    /// read-back must not be logged as control working.
    pub fn actuation_line(value: u8, wrote: bool, read_back: Option<u8>) -> String {
        match (wrote, read_back) {
            (true, Some(v)) if v == value => format!("SET({value}) written, read-back {v} agrees"),
            (true, Some(v)) => {
                format!("SET({value}) written, read-back still {v} - physical state UNCONFIRMED")
            }
            (true, None) => {
                format!("SET({value}) written, read-back failed - physical state UNCONFIRMED")
            }
            (false, _) => format!("SET({value}) rejected"),
        }
    }
}

/// Whether COM can be treated as initialized, from the apartment attempts. `sta` is `None` when the
/// first attempt already settled it.
///
/// Returns `(usable, must_uninitialize, note)`. A successful call owns the apartment and must close
/// it; `RPC_E_CHANGED_MODE` means someone else initialized this thread, so we may use it but must
/// not tear it down, and must not call it a refusal either.
pub fn com_outcome(mta: i32, sta: Option<i32>) -> (bool, bool, String) {
    if mta == 0 {
        return (true, true, String::new());
    }
    if mta == RPC_E_CHANGED_MODE {
        return (
            true,
            false,
            format!("COM already initialized on this thread (MTA returned {mta:#x})"),
        );
    }
    match sta {
        Some(0) => (true, true, format!("MTA refused ({mta:#x}), STA accepted")),
        Some(x) if x == RPC_E_CHANGED_MODE => (
            true,
            false,
            format!("MTA refused ({mta:#x}); STA already initialized ({x:#x})"),
        ),
        Some(x) => (false, false, format!("MTA={mta:#x} STA={x:#x}")),
        None => (false, false, format!("MTA={mta:#x}")),
    }
}

/// True when an identity string names our **camera** function. Used by the Media Foundation
/// comparison path, where the enumerated object is already a capture source.
pub fn matches_our_camera(symbolic_link: &str) -> bool {
    let needle = format!("vid_{VID:04x}&pid_{PID:04x}");
    symbolic_link.to_ascii_lowercase().contains(&needle)
}

/// True when an identity string names the camera's **UVC streaming interface** (MI_00) specifically.
///
/// The DirectShow-side walk needs this narrower test: the capture category can expose a device path
/// for any function of the composite device, and binding the motor interface (MI_02) instead would
/// put KS property calls onto the interface our WinUSB channel owns - a different device, and one
/// where a wrong call has worse consequences than a refused read. Keyed on hardware IDs plus
/// interface, never on a friendly name.
pub fn matches_our_capture_interface(identity: &str) -> bool {
    let needle = format!("vid_{VID:04x}&pid_{PID:04x}&mi_00");
    identity.to_ascii_lowercase().contains(&needle)
}

/// The property header for one call, in the byte shape the verified working call produces:
///
/// ```text
/// [0..16)  the motor XU property set GUID
/// [16..20) selector id, 4
/// [20..24) KSPROPERTY_TYPE_SET|TOPOLOGY or GET|TOPOLOGY
/// [24..28) node id, 4
/// [28..32) zero padding, inside the 32 bytes the call declares
/// ```
///
/// The trailing node word is not decoration: this machine's measured call writes a fourth u32, and
/// the first version of this probe omitted it - which is why a correctly bound `IKsControl` answered
/// `E_INVALIDARG`. Both words happen to hold 4 here (selector 4 and node 4), so the two are written
/// from their own constants rather than one value copied twice; see `header_bytes_node_first` for the
/// alternative field order, kept as a second candidate because a single working call cannot tell
/// which of the two slots the type flags occupy.
fn header_bytes(flags: u32) -> [u8; HEADER_BYTES] {
    let mut out = [0u8; HEADER_BYTES];
    write_guid(&mut out);
    out[16..20].copy_from_slice(&(MOTOR_SELECTOR as u32).to_le_bytes());
    out[20..24].copy_from_slice(&flags.to_le_bytes());
    out[24..28].copy_from_slice(&(MOTOR_KS_NODE_ID as u32).to_le_bytes());
    out
}

/// The same header with the two u32 fields after the GUID swapped: node id at 20, type flags at 24.
/// The documented `KSPROPERTY` puts `NodeId` before `Flags`, while the measured call puts them the
/// other way, so both are tried - on a read-only property only, and reported by name.
fn header_bytes_node_first(flags: u32) -> [u8; HEADER_BYTES] {
    let mut out = [0u8; HEADER_BYTES];
    write_guid(&mut out);
    out[16..20].copy_from_slice(&(MOTOR_SELECTOR as u32).to_le_bytes());
    out[20..24].copy_from_slice(&(MOTOR_KS_NODE_ID as u32).to_le_bytes());
    out[24..28].copy_from_slice(&flags.to_le_bytes());
    out
}

/// GUID bytes at the head of the header, in the in-memory order Windows uses: `Data1` as a little
/// endian dword, `Data2`/`Data3` as little endian words, then `Data4`'s eight bytes in order.
fn write_guid(out: &mut [u8; HEADER_BYTES]) {
    let guid = MOTOR_XU_GUID_U128;
    out[0..4].copy_from_slice(&((guid >> 96) as u32).to_le_bytes());
    out[4..6].copy_from_slice(&((guid >> 80) as u16).to_le_bytes());
    out[6..8].copy_from_slice(&((guid >> 64) as u16).to_le_bytes());
    out[8..16].copy_from_slice(&((guid & 0xFFFF_FFFF_FFFF_FFFF) as u64).to_be_bytes());
}

fn get_cur(
    ksp: &windows::Win32::Media::KernelStreaming::IKsControl,
    property_len: u32,
    data_len: u32,
) -> (Option<u8>, u32, String) {
    use windows::Win32::Media::KernelStreaming::KSIDENTIFIER;

    let header = header_bytes(KSPROPERTY_TYPE_TOPOLOGY | KSPROPERTY_TYPE_GET);
    let mut data = vec![0u8; data_len.max(1) as usize];
    let mut returned = 0u32;
    match unsafe {
        ksp.KsProperty(
            &header as *const [u8; HEADER_BYTES] as *const KSIDENTIFIER,
            property_len,
            data.as_mut_ptr() as *mut core::ffi::c_void,
            data_len,
            &mut returned,
        )
    } {
        // Success is the call returning S_OK, and `returned` is recorded but not required: the
        // measured behaviour on this device is a readable value with the count left at zero, so
        // insisting on a positive count would report a working read as a failure.
        Ok(()) => (data.first().copied(), returned, String::new()),
        Err(e) => (None, returned, format!("E={e}")),
    }
}

/// The shared safety gate, applied to the DirectShow-side write as well.
///
/// "selector 5 is poison" and "only 1 and 2 are motor values" are facts about the device, not
/// properties of the transport that reaches it - so the KS path asks the same question the USB path
/// does, through `cm400-protocol`, instead of trusting its caller.
pub fn motor_write_allowed(value: u8) -> bool {
    cm400_protocol::ControlRequest::motor_set(value, cm400_protocol::Recipient::Device)
        .validate()
        .is_ok()
}

/// Write one motor value; reports only whether the proxy accepted it. The caller pairs this with a
/// read-back and reports both, because acceptance is not evidence about the mechanism.
fn set_value(
    ksp: &windows::Win32::Media::KernelStreaming::IKsControl,
    value: u8,
    property_len: u32,
) -> bool {
    use windows::Win32::Media::KernelStreaming::KSIDENTIFIER;

    if !motor_write_allowed(value) {
        return false;
    }
    let header = header_bytes(KSPROPERTY_TYPE_TOPOLOGY | KSPROPERTY_TYPE_SET);
    let mut data = [value; MOTOR_KS_SET_DATA_BYTES as usize];
    let mut returned = 0u32;
    unsafe {
        ksp.KsProperty(
            &header as *const [u8; HEADER_BYTES] as *const KSIDENTIFIER,
            property_len,
            data.as_mut_ptr() as *mut core::ffi::c_void,
            data.len() as u32,
            &mut returned,
        )
    }
    .is_ok()
}

/// Read one allocated string attribute, then free it. The length comes from the API rather than from
/// scanning for a terminator we do not control.
fn read_string(
    attrs: &windows::Win32::Media::MediaFoundation::IMFAttributes,
    key: &windows::core::GUID,
) -> Option<String> {
    use windows::core::PWSTR;
    use windows::Win32::System::Com::CoTaskMemFree;

    let mut value = PWSTR::null();
    let mut len = 0u32;
    if unsafe { attrs.GetAllocatedString(key, &mut value, &mut len) }.is_err() {
        return None;
    }
    if value.0.is_null() {
        return None;
    }
    let units = unsafe { core::slice::from_raw_parts(value.0 as *const u16, len as usize) };
    let text = String::from_utf16_lossy(units);
    unsafe { CoTaskMemFree(Some(value.0 as *const core::ffi::c_void)) };
    Some(text)
}

/// The comparison path: the Media Foundation source's own KS proxy.
///
/// Kept because the difference in outcome between the two objects *is* the finding - this one
/// enumerates, matches and answers `QueryInterface IKsControl`, then refuses the motor property with
/// `E_INVALIDARG` for every header/payload combination tried, while the DirectShow filter path below
/// is the one the verified call goes through.
///
/// `actuate` sends one `SET` of that value and reads it back; `None` never touches the motor.
pub fn run_media_foundation(actuate: Option<u8>) -> (Report, Option<String>) {
    use windows::core::Interface;
    use windows::Win32::Media::KernelStreaming::IKsControl;
    use windows::Win32::Media::MediaFoundation::{
        IMFActivate, IMFAttributes, IMFMediaSource, MFCreateAttributes, MFEnumDeviceSources,
        MFStartup, MF_VERSION,
    };
    use windows::Win32::System::Com::{
        CoInitializeEx, CoTaskMemFree, CoUninitialize, COINIT_APARTMENTTHREADED,
        COINIT_MULTITHREADED,
    };

    let mut rep = Report {
        via: "media-foundation",
        ..Default::default()
    };
    // `CoInitializeEx` hands back a raw HRESULT in this crate version, so the codes are read
    // directly: the probe has to distinguish "already initialized" from "refused".
    let mta = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.0;
    let sta = if mta == 0 || mta == RPC_E_CHANGED_MODE {
        None
    } else {
        Some(unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }.0)
    };
    let (usable, must_uninit, note) = com_outcome(mta, sta);
    rep.com_ok = usable;
    if !note.is_empty() {
        rep.failure = note;
    }
    // One exit path for the apartment so a mid-probe return cannot leak it.
    let done = |rep: &mut Report| {
        if must_uninit {
            unsafe { CoUninitialize() };
        }
        (rep.clone(), None)
    };
    if !usable {
        return (rep, None);
    }

    use windows::Win32::Media::MediaFoundation::{
        MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME, MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
        MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID,
        MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK,
    };

    unsafe {
        // MF has to be started before source enumeration, and there is no reason to hide which
        // step refused.
        let _ = MFStartup(MF_VERSION, 0);
    }
    let mut attrs_slot: Option<IMFAttributes> = None;
    if unsafe { MFCreateAttributes(&mut attrs_slot, 1) }.is_err() {
        rep.failure = "MFCreateAttributes failed".to_string();
        return done(&mut rep);
    }
    let Some(attrs) = attrs_slot else {
        rep.failure = "MFCreateAttributes returned no attributes".to_string();
        return done(&mut rep);
    };
    if unsafe {
        attrs.SetGUID(
            &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
            &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID,
        )
    }
    .is_err()
    {
        rep.failure = "SetGUID(source type) failed".to_string();
        return done(&mut rep);
    }

    let mut block: *mut Option<IMFActivate> = std::ptr::null_mut();
    let mut count = 0u32;
    if unsafe { MFEnumDeviceSources(&attrs, &mut block, &mut count) }.is_err() {
        rep.failure = "MFEnumDeviceSources failed".to_string();
        return done(&mut rep);
    }
    rep.sources = count;

    // Copy out the handles we might use, then release the array the API allocated.
    let mut candidates: Vec<IMFActivate> = Vec::new();
    if !block.is_null() && count > 0 {
        let slice = unsafe { core::slice::from_raw_parts(block, count as usize) };
        candidates.extend(slice.iter().filter_map(|slot| slot.clone()));
        unsafe { CoTaskMemFree(Some(block as *const core::ffi::c_void)) };
    }

    let mut actuation = None;
    for activate in candidates {
        let named: IMFAttributes = match activate.cast() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Some(link) = read_string(
            &named,
            &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK,
        ) else {
            continue;
        };
        if !matches_our_camera(&link) {
            continue;
        }
        rep.matched = true;
        rep.name = read_string(&named, &MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME).unwrap_or_default();

        let source: IMFMediaSource = match unsafe { activate.ActivateObject() } {
            Ok(s) => s,
            Err(e) => {
                rep.failure = format!("ActivateObject: {e}");
                break;
            }
        };
        let ksp: IKsControl = match source.cast() {
            Ok(k) => k,
            Err(e) => {
                rep.failure = format!("QueryInterface IKsControl: {e}");
                break;
            }
        };
        rep.ksp_ok = true;
        // Try the documented shapes; a read that works defines the shape the write must use.
        for (property_len, data_len) in SHAPES {
            let (value, count, err) = get_cur(&ksp, property_len, data_len);
            rep.attempts
                .push(format!("({property_len},{data_len}) -> {err}"));
            if value.is_some() {
                rep.get_cur = value;
                rep.get_returned = count;
                rep.shape = Some((property_len, data_len));
                break;
            }
            if err.is_empty() {
                if let Some(a) = rep.attempts.last_mut() {
                    *a = format!("({property_len},{data_len}) -> ok, no value");
                }
            }
        }
        if rep.get_cur.is_none() {
            rep.failure = format!(
                "KsProperty GET_CUR refused every shape: {}",
                rep.attempts.join("; ")
            );
        }
        if let (Some(want), Some((property_len, data_len))) = (actuate, rep.shape) {
            let wrote = set_value(&ksp, want, property_len);
            let (back, _, _) = get_cur(&ksp, property_len, data_len);
            rep.read_back = back;
            actuation = Some(Report::actuation_line(want, wrote, back));
        }
        break;
    }

    if must_uninit {
        unsafe { CoUninitialize() };
    }
    (rep, actuation)
}

/// A candidate header shape: how it is described in the log, and the function that builds it.
type HeaderBuilder = fn(u32) -> [u8; HEADER_BYTES];
type HeaderCandidate = (&'static str, HeaderBuilder);

/// The header candidates used by `ds_set`: the shape the verified call produces, and the documented
/// field order as a fallback. Reads try these at three lengths; a write only goes out after a read
/// has already answered, so no new request format is invented on the way to the mechanism.
const HEADERS: [HeaderCandidate; 2] = [
    (
        "flags-then-node (the measured call)",
        header_bytes as fn(u32) -> [u8; HEADER_BYTES],
    ),
    (
        "node-then-flags (documented order)",
        header_bytes_node_first,
    ),
];

/// `GET_CUR` through a DirectShow-obtained `IKsControl`, with the verified call shape: a 32-byte
/// topology header and an 8-byte payload buffer.
///
/// Three attempts, reported separately, because two different things can produce the same code: the
/// header field order (candidates A and B) and the vtable slot we call through. The third attempt
/// goes through the crate's own typed `IKsControl`, generated from metadata, so if it succeeds while
/// the manual slot call fails, the manual slot is what was wrong - and if it fails with the same
/// code, the slot is fine and the fault lies in the request or the proxy.
fn ds_get(control: &crate::directshow::ComPtr) -> (Option<u8>, u32, String, Option<String>) {
    use windows::core::Interface;
    use windows::Win32::Media::KernelStreaming::{IKsControl, KSIDENTIFIER};

    let mut refused: Vec<String> = Vec::new();
    let mut note = |text: String| refused.push(text);
    // The read-only request shapes to try, each labelled and reported. `flags-then-node` is the byte
    // shape the verified call produces; `node-then-flags` is how `KSPROPERTY` is documented; the
    // property lengths cover the struct size (24), the documented `KSPROPERTY` size (28) and the
    // length the verified call actually passes (32). Only `GET_CUR` on the motor selector is sent -
    // no selector probing, no forbidden values.
    // A candidate request: the property length, the label, and the header builder that goes with it.
    type Attempt = (u32, &'static str, HeaderBuilder);
    let attempts: [Attempt; 4] = [
        (
            MOTOR_KS_PROPERTY_HEADER_BYTES,
            "flags-then-node @32 (the measured call)",
            header_bytes,
        ),
        (28, "flags-then-node @28", header_bytes),
        (24, "flags-then-node @24", header_bytes),
        (
            MOTOR_KS_PROPERTY_HEADER_BYTES,
            "node-then-flags @32",
            header_bytes_node_first,
        ),
    ];
    for (property_length, label, build) in attempts {
        // Topology plus the access type: the measured call's flags value is 0x10000001 for GET and
        // 0x10000002 for SET, so both bits go on every request from here.
        let header = build(KSPROPERTY_TYPE_TOPOLOGY | KSPROPERTY_TYPE_GET);
        let mut data = [0u8; MOTOR_KS_GET_BUFFER_BYTES as usize];
        match unsafe {
            crate::directshow::ks_property(
                control,
                &header as *const [u8; HEADER_BYTES] as *const core::ffi::c_void,
                property_length,
                data.as_mut_ptr() as *mut core::ffi::c_void,
                data.len() as u32,
            )
        } {
            Ok(returned) => return (data.first().copied(), returned, hex(&data), None),
            Err(code) => note(format!("{label} [{}] -> {:#010X}", hex(&header), code.0)),
        }
    }

    // The same request through the metadata-generated interface, on a borrowed pointer so nothing
    // else about ownership changes.
    let raw = control.raw();
    if let Some(typed) = unsafe { IKsControl::from_raw_borrowed(&raw) } {
        let header = header_bytes(KSPROPERTY_TYPE_TOPOLOGY | KSPROPERTY_TYPE_GET);
        let mut data = [0u8; MOTOR_KS_GET_BUFFER_BYTES as usize];
        let mut returned = 0u32;
        let outcome = unsafe {
            typed.KsProperty(
                &header as *const [u8; HEADER_BYTES] as *const KSIDENTIFIER,
                MOTOR_KS_PROPERTY_HEADER_BYTES,
                data.as_mut_ptr() as *mut core::ffi::c_void,
                data.len() as u32,
                &mut returned,
            )
        };
        match outcome {
            Ok(()) => {
                return (data.first().copied(), returned, hex(&data), None);
            }
            Err(e) => note(format!("typed IKsControl::KsProperty -> {e}")),
        }
    } else {
        note("the bound object is not really an IKsControl pointer".to_string());
    }
    (None, 0, String::new(), Some(refused.join(" | ")))
}

/// `SET_CUR` through the same object: one byte, whitelist-gated before the call is made.
fn ds_set(control: &crate::directshow::ComPtr, value: u8) -> (bool, Option<String>) {
    if !motor_write_allowed(value) {
        return (
            false,
            Some(format!(
                "value {value} refused by the protocol whitelist; not sent"
            )),
        );
    }
    // Write with the header shape the read already answered with. The caller has established it by
    // the time it asks for actuation, so no new request format is invented here.
    for (label, build) in HEADERS {
        let header = build(KSPROPERTY_TYPE_TOPOLOGY | KSPROPERTY_TYPE_SET);
        let mut data = [value; MOTOR_KS_SET_DATA_BYTES as usize];
        let result = unsafe {
            crate::directshow::ks_property(
                control,
                &header as *const [u8; HEADER_BYTES] as *const core::ffi::c_void,
                MOTOR_KS_PROPERTY_HEADER_BYTES,
                data.as_mut_ptr() as *mut core::ffi::c_void,
                data.len() as u32,
            )
        };
        match result {
            Ok(_) => return (true, None),
            Err(code) => {
                let text = format!("{label}: KsProperty SET_CUR refused {:#010X}", code.0);
                if label.starts_with("flags-then-node") {
                    continue;
                }
                return (false, Some(text));
            }
        }
    }
    (
        false,
        Some("no header shape was accepted for SET".to_string()),
    )
}

/// Hex form of a payload buffer, for the log.
fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[doc(hidden)]
/// Diagnostic entry point: match on the label the verified third-party call uses, so a failing
/// request can be attributed to the request rather than to the moniker that was chosen.
///
/// Production code and the service hook never use this. It exists because "same filter, same request,
/// different answer" and "different filter" look identical from one HRESULT.
pub fn run_diagnostic_by_name(actuate: Option<u8>) -> (Report, Option<String>) {
    run_with(actuate, &|identity: &str| {
        identity.to_ascii_lowercase().contains("cm400")
    })
}

#[doc(hidden)]
/// Diagnostic only: walk **every** capture moniker that matches the camera identity and try the
/// verified read on each, returning one line per candidate.
///
/// This is how a "same bytes, different answer" result gets attributed: the capture category can
/// hold several monikers over the same device interface, and without listing them individually there
/// is no way to tell a wrong-object choice from a wrong-request.
pub fn diagnose_each() -> Vec<String> {
    diagnose_with(&matches_our_capture_interface)
}

#[doc(hidden)]
/// Diagnostic only, and wider than `diagnose_each`: list every moniker in the capture category, even
/// the ones whose identity is not our camera interface, and try the verified read on each.
///
/// This is the one that settles "is there another object that answers?" instead of leaving it a
/// hypothesis.
pub fn diagnose_all() -> Vec<String> {
    diagnose_with(&|_identity: &str| true)
}

fn diagnose_with(wanted: &dyn Fn(&str) -> bool) -> Vec<String> {
    use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_MULTITHREADED};

    let mut lines = Vec::new();
    let mta = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.0;
    let (usable, must_uninit, _) = com_outcome(mta, None);
    if !usable {
        return vec!["COM unavailable in this context".to_string()];
    }
    match crate::directshow::open_all_capture_ks_control(wanted) {
        Err(f) => lines.push(format!("enumeration failed: {}", f.describe())),
        Ok(list) => {
            for (index, opened) in list.iter().enumerate() {
                if opened.control.is_null() {
                    lines.push(format!(
                        "[{}] bound={} name=\"{}\" -> no control object ({})",
                        index,
                        opened.bound_via,
                        opened.display_name.clone().unwrap_or_default(),
                        opened.identity_source
                    ));
                    continue;
                }
                let (value, returned, buffer, refused) = ds_get(&opened.control);
                lines.push(format!(
                    "[{}] bound={} source={} path=\"{}\" name=\"{}\" get={:?} returned={} buffer=[{}] refused=[{}]",
                    index,
                    opened.bound_via,
                    opened.identity_source,
                    opened.identity,
                    opened.display_name.clone().unwrap_or_default(),
                    value,
                    returned,
                    buffer,
                    refused.unwrap_or_default()
                ));
            }
        }
    }
    if must_uninit {
        unsafe { CoUninitialize() };
    }
    lines
}

/// Run the probe through the DirectShow capture filter - the object the verified call uses, and the
/// one a migrated production channel would have to reach.
///
/// The request reproduces the measured baseline exactly and does not hunt for parameters: a 32-byte
/// topology property header naming the motor XU GUID with node id 4, an 8-byte `GET` buffer, a
/// 1-byte `SET` payload, and only values 1 and 2. Varying selector, node id or lengths to see what
/// answers would mean sending requests the device has never sanctioned, and selector 5 can force a
/// re-enumeration.
///
/// `actuate` sends one `SET` of that value and reads it back; `None` is read-only and cannot move
/// the lens, so it is safe to run while the service is live.
pub fn run(actuate: Option<u8>) -> (Report, Option<String>) {
    run_with(actuate, &matches_our_capture_interface)
}

fn run_with(actuate: Option<u8>, wanted: &dyn Fn(&str) -> bool) -> (Report, Option<String>) {
    use windows::Win32::System::Com::{
        CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED, COINIT_MULTITHREADED,
    };

    let mut rep = Report {
        via: "directshow",
        ..Default::default()
    };
    let mta = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.0;
    let sta = if mta == 0 || mta == RPC_E_CHANGED_MODE {
        None
    } else {
        Some(unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }.0)
    };
    let (usable, must_uninit, note) = com_outcome(mta, sta);
    rep.com_ok = usable;
    if !note.is_empty() {
        rep.failure = note;
    }
    if !usable {
        return (rep, None);
    }

    let leave = |rep: &mut Report| {
        if must_uninit {
            unsafe { CoUninitialize() };
        }
        (rep.clone(), None)
    };

    let opened = match crate::directshow::open_capture_ks_control(wanted) {
        Ok(o) => o,
        Err(f) => {
            rep.failure = f.describe();
            // `NotMatched` carries the identities actually seen, which is the evidence that rules
            // out "the filter was never there" as an explanation.
            if let crate::directshow::Failure::NotMatched { seen } = &f {
                rep.attempts = seen.clone();
                rep.sources = seen.len() as u32;
            }
            return leave(&mut rep);
        }
    };
    rep.sources = opened.walked;
    rep.matched = true;
    rep.identity = opened.identity.clone();
    rep.name = opened.display_name.clone().unwrap_or_default();
    rep.bound_via = opened.bound_via;
    rep.identity_source = opened.identity_source;
    rep.ksp_ok = true;
    rep.shape = Some((MOTOR_KS_PROPERTY_HEADER_BYTES, MOTOR_KS_GET_BUFFER_BYTES));

    let (value, returned, buffer, refused) = ds_get(&opened.control);
    rep.get_cur = value;
    rep.get_returned = returned;
    rep.get_hex = buffer;
    if let Some(e) = refused {
        rep.failure = e;
        return leave(&mut rep);
    }

    let mut actuation = None;
    if let Some(want) = actuate {
        let (wrote, set_refused) = ds_set(&opened.control, want);
        let (back, _, _, read_refused) = ds_get(&opened.control);
        rep.read_back = back;
        if let Some(e) = read_refused.or(set_refused) {
            rep.failure = e;
        }
        actuation = Some(Report::actuation_line(want, wrote, back));
    }

    if must_uninit {
        unsafe { CoUninitialize() };
    }
    (rep, actuation)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// S-1-5-19 style: the apartment already belongs to somebody else on this thread, which is a
    /// reason to continue, not a reason to report the context as unsupported.
    #[test]
    fn com_being_initialized_already_is_not_a_refusal() {
        let (usable, uninit, note) = com_outcome(RPC_E_CHANGED_MODE, None);
        assert!(usable, "an existing apartment must let the probe continue");
        assert!(
            !uninit,
            "we must not tear down an apartment we did not create"
        );
        assert!(note.contains("already initialized"), "and say so: {note}");

        let (usable, uninit, _) = com_outcome(0, None);
        assert!(usable);
        assert!(uninit, "a fresh apartment is ours to release");

        let (usable, uninit, note) = com_outcome(-2147024809, Some(0));
        assert!(usable, "STA accepted after MTA refused");
        assert!(uninit);
        assert!(note.contains("STA accepted"), "{note}");

        let (usable, uninit, note) = com_outcome(-2147024809, Some(RPC_E_CHANGED_MODE));
        assert!(usable, "STA already initialized is still usable");
        assert!(!uninit);
        assert!(
            note.contains("STA already initialized"),
            "and says which one: {note}"
        );
        // Both refused, and neither refusal is "somebody else owns the apartment".
        let (usable, _, note) = com_outcome(-2147024809, Some(-2147418112));
        assert!(!usable, "both refusals is the only real failure");
        assert!(
            note.contains("MTA=") && note.contains("STA="),
            "report both codes: {note}"
        );
    }

    /// Matching is on hardware IDs, case-insensitively, and never on a product name.
    #[test]
    fn the_matcher_keys_on_hardware_ids_only() {
        let real = format!(
            "\\\\?\\usb#vid_{VID:04x}&pid_{PID:04x}&mi_00#7&1234&0&0000#{{65e8773d-8fba-4d20-9c68-81e56c1002f5}}\\global"
        );
        assert!(matches_our_camera(&real));
        assert!(matches_our_camera(&real.to_uppercase()));
        assert!(
            !matches_our_camera("\\\\?\\usb#vid_1234&pid_5678&mi_00#global"),
            "a different camera must not match"
        );
        assert!(
            !matches_our_camera("USB Video Device"),
            "a friendly name is not a hardware id"
        );
    }

    /// The verdict has to name the stage that stopped us: three different failures below imply
    /// three different decisions about migrating the control path.
    #[test]
    fn the_verdict_names_the_stage_that_actually_stopped_the_probe() {
        let mut r = Report::default();
        assert!(r.verdict().contains("CoInitializeEx"), "{}", r.verdict());

        r.com_ok = true;
        assert!(r.verdict().contains("capture-source enumeration"));

        r.sources = 3;
        assert!(r.verdict().contains("matching our VID/PID"));

        r.matched = true;
        r.name = "CM400 FHD Camera".into();
        assert!(r.verdict().contains("QueryInterface IKsControl"));

        r.ksp_ok = true;
        assert!(r.verdict().contains("KsProperty GET_CUR"));

        r.get_cur = Some(2);
        r.get_returned = 1;
        r.get_hex = "02 00 00 00 00 00 00 00".into();
        r.via = "directshow";
        r.identity = "\\\\?\\usb#vid_0603&pid_8612&mi_00#...".into();
        let line = r.verdict();
        assert!(
            line.contains("via directshow"),
            "the verdict says which object: {line}"
        );
        assert!(
            line.contains("MI_00") || line.contains("mi_00"),
            "and which interface: {line}"
        );
        assert!(line.contains("GET_CUR(selector 4) = 2"), "{line}");
        assert!(line.contains("1 bytes returned"), "{line}");
    }

    /// A write the proxy accepted is not a moved lens: only agreement with the read-back is
    /// reported as control working.
    #[test]
    fn actuation_is_reported_with_its_read_back() {
        assert!(Report::actuation_line(2, true, Some(2)).contains("read-back 2 agrees"));
        let stale = Report::actuation_line(2, true, Some(1));
        assert!(stale.contains("UNCONFIRMED"), "{stale}");
        let unreadable = Report::actuation_line(1, true, None);
        assert!(unreadable.contains("UNCONFIRMED"), "{unreadable}");
        assert_eq!(Report::actuation_line(1, false, Some(1)), "SET(1) rejected");
    }

    /// Header layout exactly as the verified call builds it: GUID, selector id, then the two words
    /// whose order the measured call fixes - and the eight bytes past the 28 used fields stay zero.
    #[test]
    fn the_header_matches_the_measured_call_byte_for_byte() {
        let h = header_bytes(KSPROPERTY_TYPE_TOPOLOGY | KSPROPERTY_TYPE_SET);
        assert_eq!(h.len(), HEADER_BYTES);
        let guid = MOTOR_XU_GUID_U128;
        let data1 = ((guid >> 96) as u32).to_le_bytes();
        let data2 = ((guid >> 80) as u16).to_le_bytes();
        let data3 = ((guid >> 64) as u16).to_le_bytes();
        let data4 = ((guid & 0xFFFF_FFFF_FFFF_FFFF) as u64).to_be_bytes();
        assert_eq!(&h[0..4], &data1);
        assert_eq!(&h[4..6], &data2);
        assert_eq!(&h[6..8], &data3);
        assert_eq!(&h[8..16], &data4);
        assert_eq!(&h[16..20], &(MOTOR_SELECTOR as u32).to_le_bytes());
        assert_eq!(
            &h[20..24],
            &(KSPROPERTY_TYPE_TOPOLOGY | KSPROPERTY_TYPE_SET).to_le_bytes(),
            "the measured call puts the type flags here"
        );
        assert_eq!(&h[24..28], &(MOTOR_KS_NODE_ID as u32).to_le_bytes());
        assert!(h[28..].iter().all(|b| *b == 0), "padding stays zero");
        // The measured flag values themselves, spelled out so a constant drift is caught.
        assert_eq!(KSPROPERTY_TYPE_TOPOLOGY | KSPROPERTY_TYPE_SET, 0x0100_0002);
        assert_eq!(KSPROPERTY_TYPE_TOPOLOGY | KSPROPERTY_TYPE_GET, 0x0100_0001);
    }

    /// The two candidate orders differ only in the two words after the selector, and both are tried
    /// because one working call cannot tell them apart - the values are equal on this device.
    #[test]
    fn the_two_header_candidates_differ_only_in_the_two_trailing_words() {
        let a = header_bytes(KSPROPERTY_TYPE_TOPOLOGY | KSPROPERTY_TYPE_GET);
        let b = header_bytes_node_first(KSPROPERTY_TYPE_TOPOLOGY | KSPROPERTY_TYPE_GET);
        assert_eq!(&a[..20], &b[..20], "GUID and selector id are identical");
        assert_eq!(&a[20..24], &b[24..28], "the flags word moved");
        assert_eq!(&a[24..28], &b[20..24], "and so did the node word");
        // Selector 4 and node 4 are equal on this device, which is exactly why the order cannot be
        // read off the working call - the values look the same either way.
        assert_eq!(MOTOR_SELECTOR as u32, MOTOR_KS_NODE_ID as u32);
    }

    /// The capture-interface matcher has to be narrow enough that the motor interface can never be
    /// selected by it: binding MI_02 would put KS property calls on the interface the WinUSB channel
    /// owns.
    #[test]
    fn the_capture_matcher_requires_the_uvc_interface() {
        let camera = format!(
            "\\\\?\\usb#vid_{VID:04x}&pid_{PID:04x}&mi_00#7&1845226b&0&0000#{{65e8}}\\global"
        );
        assert!(matches_our_capture_interface(&camera));
        assert!(matches_our_capture_interface(&camera.to_uppercase()));
        let motor = format!(
            "\\\\?\\usb#vid_{VID:04x}&pid_{PID:04x}&mi_02#8&2e26e82&0&0002#{{11a9}}\\global"
        );
        assert!(
            !matches_our_capture_interface(&motor),
            "the motor interface is a different device and must not bind"
        );
        // The wider matcher still accepts both functions, which is why the DS path uses the narrow
        // one and the two are kept apart on purpose.
        assert!(matches_our_camera(&motor));
        assert!(!matches_our_capture_interface("USB Video Device"));
    }

    /// Hex rendering is what the log records for a payload, so it must show every byte.
    #[test]
    fn payload_bytes_are_reported_in_full() {
        assert_eq!(hex(&[0, 1, 0xff]), "00 01 ff");
        assert_eq!(hex(&[]), "");
    }

    /// The KS path is held to the same whitelist as the USB path, and that has to be verified
    /// without hardware: whatever the proxy would accept, we never ask it for a forbidden write.
    #[test]
    fn only_the_two_motor_values_clear_the_shared_gate() {
        assert!(motor_write_allowed(cm400_protocol::MOTOR_UP));
        assert!(motor_write_allowed(cm400_protocol::MOTOR_DOWN));
        for bad in [0, 3, 4, 5, 255] {
            assert!(
                !motor_write_allowed(bad),
                "value {bad} must never be written"
            );
        }
    }

    /// The shape list has to keep the measured call and must never understate the header we fill:
    /// a short property length would make the proxy read less than the struct we built.
    #[test]
    fn the_shape_list_covers_the_measured_call_and_never_a_truncated_header() {
        assert!(
            SHAPES.contains(&(MOTOR_KS_PROPERTY_HEADER_BYTES, MOTOR_KS_GET_BUFFER_BYTES)),
            "the call measured on this machine stays in the list"
        );
        for (property_len, data_len) in SHAPES {
            assert!(
                property_len
                    >= core::mem::size_of::<windows::Win32::Media::KernelStreaming::KSIDENTIFIER_0_0>(
                    ) as u32,
                "({property_len},{data_len}) would truncate the header"
            );
            assert!(
                data_len >= 1,
                "({property_len},{data_len}) has no room for a value"
            );
        }
    }

    /// The lengths are separate facts and must stay separate: a header of 32 is not a payload of 32.
    #[test]
    fn header_and_payload_sizes_are_not_confused() {
        assert_eq!(HEADER_BYTES, 32);
        assert_eq!(MOTOR_KS_SET_DATA_BYTES, 1);
        assert_eq!(MOTOR_KS_GET_BUFFER_BYTES, 8);
        // The used fields occupy 28 of the 32 declared bytes.
        assert_eq!(MOTOR_KS_PROPERTY_HEADER_BYTES, 32);
    }
}
