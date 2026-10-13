//! The minimum DirectShow enumeration needed to reach the camera's KS proxy filter.
//!
//! The `windows` crate carries no metadata for these interfaces - `ICreateDevEnum`, `IEnumMoniker`,
//! `IMoniker` and `IPropertyBag` are all absent in 0.58 - so the calls go through the object's
//! vtable by slot index. That is only defensible when the indices are evidence rather than memory,
//! and they are:
//!
//! - `ICreateDevEnum` declares one method after `IUnknown` -> `CreateClassEnumerator` = 3.
//! - `IEnumMoniker` is the `IEnumX` shape -> `Next` = 3.
//! - `IMoniker` derives from `IPersist`, so its own methods follow `GetClassID`, `IsDirty`, `Load`,
//!   `Save`, `GetSizeMax` -> `BindToObject` = 8, `BindToStorage` = 9 ... `GetDisplayName` = 20.
//!   These indices were read off `System.Runtime.InteropServices.ComTypes.IMoniker` on this machine:
//!   a `ComImport` interface must declare its methods in vtable order, and that declaration is what
//!   the working third-party call compiles against.
//! - `IPropertyBag` -> `Read` = 3.
//! - `IKsControl` -> `KsProperty` = 3.
//!
//! A wrong slot would call a different method with our arguments, so every layout assumption that
//! can be checked locally is asserted in the tests at the bottom of this file.

use windows::core::{IUnknown, Interface, GUID, HRESULT};

/// `CLSID_SystemDeviceEnum`.
pub const CLSID_SYSTEM_DEVICE_ENUM: GUID = GUID::from_u128(0x62BE5D10_60EB_11D0_BD3B_00A0C911CE86);
/// `CLSID_VideoInputDeviceCategory` - the filter category that holds capture filters.
pub const CLSID_VIDEO_INPUT_CATEGORY: GUID =
    GUID::from_u128(0x860BB310_5D01_11D0_BD3B_00A0C911CE86);
/// `IID_ICreateDevEnum`.
pub const IID_ICREATE_DEV_ENUM: GUID = GUID::from_u128(0x29840822_5B84_11D0_BD3B_00A0C911CE86);
/// `IID_IBaseFilter`.
pub const IID_IBASE_FILTER: GUID = GUID::from_u128(0x56A86895_0AD4_11CE_B03A_0020AF0BA770);
/// `IID_IKsControl`.
pub const IID_IKS_CONTROL: GUID = GUID::from_u128(0x28F54685_06FD_11D2_B27A_00A0C9223196);
/// `IID_IPropertyBag`, the only way to read the moniker's `DevicePath`.
pub const IID_IPROPERTY_BAG: GUID = GUID::from_u128(0x55272A00_42CB_11CE_8135_00AA004BB851);

const SLOT_QUERY_INTERFACE: usize = 0;
const SLOT_RELEASE: usize = 2;
/// `ICreateDevEnum::CreateClassEnumerator`.
const SLOT_CREATE_CLASS_ENUMERATOR: usize = 3;
/// `IEnumMoniker::Next`.
const SLOT_ENUM_NEXT: usize = 3;
/// `IMoniker::BindToObject`.
const SLOT_BIND_TO_OBJECT: usize = 8;
/// `IMoniker::GetDisplayName`.
const SLOT_GET_DISPLAY_NAME: usize = 20;
/// `IPropertyBag::Read`.
const SLOT_PROPERTY_BAG_READ: usize = 3;
/// `IKsControl::KsProperty`.
const SLOT_KS_PROPERTY: usize = 3;

/// Vtable slot lookup: the first word of a COM object points at its vtable, whose entries are
/// function pointers.
unsafe fn slot(object: *mut core::ffi::c_void, index: usize) -> usize {
    let vtable = *(object as *const *const usize);
    *vtable.add(index)
}

/// A COM reference that this value owns and releases on drop. Deliberately minimal: the probe needs
/// no refcount cleverness, only the guarantee that every failure path still releases.
pub struct ComPtr(*mut core::ffi::c_void);

impl ComPtr {
    /// Adopt a pointer whose reference is already held for us.
    ///
    /// # Safety
    /// `pointer` must be a live COM object pointer that the caller owns, or null.
    pub unsafe fn from_owned(pointer: *mut core::ffi::c_void) -> Self {
        Self(pointer)
    }

    /// Adopt the reference behind a crate COM wrapper, transferring that one reference here instead
    /// of adding another. Forgetting the wrapper is the transfer: nothing else releases it.
    ///
    /// # Safety
    /// `value` must own a live COM reference, and must not be used afterwards.
    pub unsafe fn from_wrapper<T: windows::core::Interface>(value: T) -> Self {
        let raw = value.as_raw();
        core::mem::forget(value);
        Self(raw)
    }

    pub fn raw(&self) -> *mut core::ffi::c_void {
        self.0
    }

    pub fn is_null(&self) -> bool {
        self.0.is_null()
    }

    unsafe fn query(&self, iid: &GUID) -> Result<ComPtr, HRESULT> {
        let mut out: *mut core::ffi::c_void = core::ptr::null_mut();
        let call: unsafe extern "system" fn(
            *mut core::ffi::c_void,
            *const GUID,
            *mut *mut core::ffi::c_void,
        ) -> HRESULT = unsafe { core::mem::transmute(slot(self.0, SLOT_QUERY_INTERFACE)) };
        let code = unsafe { call(self.0, iid, &mut out) };
        if code.is_ok() && !out.is_null() {
            Ok(ComPtr(out))
        } else {
            Err(code)
        }
    }

    /// `ICreateDevEnum::CreateClassEnumerator`. A class with no registered filters returns a null
    /// enumerator with a successful code, which is `Ok(None)` rather than an error.
    unsafe fn create_class_enumerator(&self, class: &GUID) -> Result<Option<ComPtr>, HRESULT> {
        let mut out: *mut core::ffi::c_void = core::ptr::null_mut();
        let call: unsafe extern "system" fn(
            *mut core::ffi::c_void,
            *const GUID,
            *mut *mut core::ffi::c_void,
            u32,
        ) -> HRESULT = unsafe { core::mem::transmute(slot(self.0, SLOT_CREATE_CLASS_ENUMERATOR)) };
        let code = unsafe { call(self.0, class, &mut out, 0) };
        if code.is_err() {
            return Err(code);
        }
        Ok(if out.is_null() {
            None
        } else {
            Some(ComPtr(out))
        })
    }

    /// `IEnumMoniker::Next` for one entry. `Ok(None)` is the end of the list, not a failure.
    unsafe fn next_moniker(&self) -> Result<Option<ComPtr>, HRESULT> {
        let mut out: *mut core::ffi::c_void = core::ptr::null_mut();
        let mut fetched = 0u32;
        let call: unsafe extern "system" fn(
            *mut core::ffi::c_void,
            u32,
            *mut *mut core::ffi::c_void,
            *mut u32,
        ) -> HRESULT = unsafe { core::mem::transmute(slot(self.0, SLOT_ENUM_NEXT)) };
        let code = unsafe { call(self.0, 1, &mut out, &mut fetched) };
        if code.is_err() {
            return Err(code);
        }
        Ok(if out.is_null() || fetched == 0 {
            None
        } else {
            Some(ComPtr(out))
        })
    }

    /// `IMoniker::GetDisplayName`. The buffer is `CoTaskMemAlloc`'d and freed here.
    unsafe fn display_name(&self) -> Result<Option<String>, HRESULT> {
        let mut buffer: *mut u16 = core::ptr::null_mut();
        let call: unsafe extern "system" fn(
            *mut core::ffi::c_void,
            *mut core::ffi::c_void,
            *mut core::ffi::c_void,
            *mut *mut u16,
        ) -> HRESULT = unsafe { core::mem::transmute(slot(self.0, SLOT_GET_DISPLAY_NAME)) };
        let code = unsafe {
            call(
                self.0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut buffer,
            )
        };
        if code.is_err() {
            return Err(code);
        }
        if buffer.is_null() {
            return Ok(None);
        }
        let text = wide_to_string(buffer);
        unsafe {
            windows::Win32::System::Com::CoTaskMemFree(Some(buffer as *const core::ffi::c_void))
        };
        Ok(Some(text))
    }

    /// `IMoniker::BindToObject`, asking for `iid`.
    unsafe fn bind_to_object(&self, iid: &GUID) -> Result<ComPtr, HRESULT> {
        let mut out: *mut core::ffi::c_void = core::ptr::null_mut();
        let call: unsafe extern "system" fn(
            *mut core::ffi::c_void,
            *mut core::ffi::c_void,
            *mut core::ffi::c_void,
            *const GUID,
            *mut *mut core::ffi::c_void,
        ) -> HRESULT = unsafe { core::mem::transmute(slot(self.0, SLOT_BIND_TO_OBJECT)) };
        let code = unsafe {
            call(
                self.0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                iid,
                &mut out,
            )
        };
        if code.is_ok() && !out.is_null() {
            Ok(ComPtr(out))
        } else {
            Err(code)
        }
    }

    /// `IPropertyBag::Read` for a string value.
    ///
    /// The `VARIANT` is the crate's own, so releasing it is handled by code that already knows the
    /// layout: dropping it calls `VariantClear`, which frees the string the bag allocated.
    ///
    /// An empty result is treated as absent rather than as a match. That is not defensive padding:
    /// `BSTR::try_from` on an empty `VARIANT` yields an *empty string*, not an error (asserted in
    /// the tests), so a failed or non-string read would otherwise be handed to the matcher as a
    /// usable identity - and an empty identity matches nothing meaningful anyway.
    unsafe fn bag_read(&self, name: &str) -> Option<String> {
        use windows::core::{BSTR, HSTRING, VARIANT};

        let key = HSTRING::from(name);
        let mut value = VARIANT::new();
        let call: unsafe extern "system" fn(
            *mut core::ffi::c_void,
            *const u16,
            *mut VARIANT,
            *mut core::ffi::c_void,
        ) -> HRESULT = unsafe { core::mem::transmute(slot(self.0, SLOT_PROPERTY_BAG_READ)) };
        let code = unsafe { call(self.0, key.as_ptr(), &mut value, core::ptr::null_mut()) };
        if code.is_err() {
            return None;
        }
        BSTR::try_from(&value)
            .ok()
            .map(|b| b.to_string())
            .filter(|s| !s.is_empty())
    }
}

impl Drop for ComPtr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let call: unsafe extern "system" fn(*mut core::ffi::c_void) -> u32 =
                    core::mem::transmute(slot(self.0, SLOT_RELEASE));
                let _ = call(self.0);
            }
        }
    }
}

/// Read a null-terminated wide string with a hard bound, so a malformed pointer cannot walk off.
/// A null pointer reads as empty: callers treat "no name" as missing information, not as an error.
fn wide_to_string(pointer: *mut u16) -> String {
    const CAP: usize = 4096;
    if pointer.is_null() {
        return String::new();
    }
    let mut units: Vec<u16> = Vec::with_capacity(64);
    for offset in 0..CAP {
        let unit = unsafe { *pointer.add(offset) };
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    String::from_utf16_lossy(&units)
}

/// Which step of the walk failed, with the exact code. Naming the step is the whole point: "COM
/// binding error", "wrong ABI", "no matching device" and "the device refused" lead to different
/// conclusions, and one HRESULT alone cannot tell them apart.
#[derive(Debug)]
pub enum Failure {
    Instantiate(HRESULT),
    CreateEnum(HRESULT),
    EmptyCategory,
    Next(HRESULT),
    NotMatched { seen: Vec<String> },
    Bind(HRESULT),
    NoKsControl(HRESULT),
}

impl Failure {
    pub fn describe(&self) -> String {
        match self {
            Failure::Instantiate(c) => {
                format!(
                    "CoCreateInstance(SystemDeviceEnum)/QI ICreateDevEnum: {:#010X}",
                    c.0
                )
            }
            Failure::CreateEnum(c) => {
                format!("CreateClassEnumerator(video input category): {:#010X}", c.0)
            }
            Failure::EmptyCategory => "the video input category has no filters".to_string(),
            Failure::Next(c) => format!("IEnumMoniker::Next: {:#010X}", c.0),
            Failure::NotMatched { seen } => {
                format!(
                    "no capture moniker matched; {} identity strings were seen",
                    seen.len()
                )
            }
            Failure::Bind(c) => format!("BindToObject(base filter/unknown): {:#010X}", c.0),
            Failure::NoKsControl(c) => {
                format!(
                    "QueryInterface IKsControl on the bound filter: {:#010X}",
                    c.0
                )
            }
        }
    }
}

/// What a successful walk produced: the `IKsControl` object plus the identity it was matched on.
pub struct Opened {
    pub control: ComPtr,
    /// The identity string that matched - a device path or display name, kept for the log.
    pub identity: String,
    pub display_name: Option<String>,
    /// Which interface moniker object we bound before QI'ing `IKsControl`.
    pub bound_via: &'static str,
    /// Which identity string was accepted, so a log can show whether the strict device path matched
    /// or only the looser diagnostic forms did.
    pub identity_source: &'static str,
    /// How many monikers the category handed out before the match. `0` with a failure means the
    /// category was empty; a large number means the walk ran and nothing matched.
    pub walked: u32,
}

/// Pick the identity `wanted` accepts among the three a moniker offers, in preference order:
/// device path, then moniker display name, then friendly name. The path is preferred because it is
/// the only one that carries `MI_xx` - and the accepted source is returned with it, so a run that
/// only matched on a label says so in the log instead of pretending to be path-keyed.
fn pick_candidate(
    candidates: [Option<String>; 3],
    wanted: &dyn Fn(&str) -> bool,
) -> Option<Candidate> {
    const SOURCES: [&str; 3] = ["device-path", "display-name", "friendly-name"];
    SOURCES
        .into_iter()
        .zip(candidates)
        .find_map(|(source, value)| {
            let identity = value?;
            if wanted(&identity) {
                Some(Candidate { identity, source })
            } else {
                None
            }
        })
}

/// The identity strings a moniker offers, with the source each came from.
pub struct Candidate {
    pub identity: String,
    pub source: &'static str,
}

/// Walk the capture category and return **every** filter whose identity `wanted` accepts, in
/// enumeration order, plus any that failed to bind, with the reason.
///
/// This exists because the category can hold more than one moniker for the same device interface - a
/// KS proxy and a software/MF wrapper can share a device path - and "the first one that matched" is
/// not necessarily "the one the verified call bound". Each entry carries its friendly name so the
/// choice is visible rather than assumed.
pub fn open_all_capture_ks_control(wanted: &dyn Fn(&str) -> bool) -> Result<Vec<Opened>, Failure> {
    use windows::core::Interface;
    use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};

    let unknown: IUnknown =
        unsafe { CoCreateInstance(&CLSID_SYSTEM_DEVICE_ENUM, None, CLSCTX_INPROC_SERVER) }
            .map_err(|e| Failure::Instantiate(e.code()))?;
    let dev_enum = unsafe { ComPtr::from_wrapper(unknown) };
    let dev_enum = match unsafe { dev_enum.query(&IID_ICREATE_DEV_ENUM) } {
        Ok(v) => v,
        Err(c) => return Err(Failure::Instantiate(c)),
    };
    let enumerator = match unsafe { dev_enum.create_class_enumerator(&CLSID_VIDEO_INPUT_CATEGORY) }
    {
        Ok(Some(e)) => e,
        Ok(None) => return Err(Failure::EmptyCategory),
        Err(c) => return Err(Failure::CreateEnum(c)),
    };

    let mut opened: Vec<Opened> = Vec::new();
    let mut walked = 0u32;
    loop {
        let moniker = match unsafe { enumerator.next_moniker() } {
            Ok(Some(m)) => m,
            Ok(None) => break,
            Err(c) if walked == 0 => return Err(Failure::Next(c)),
            Err(_) => break,
        };
        walked += 1;
        let display = unsafe { moniker.display_name() }.ok().flatten();
        let bag = unsafe { moniker.query(&IID_IPROPERTY_BAG) }.ok();
        let path = bag
            .as_ref()
            .and_then(|b| unsafe { b.bag_read("DevicePath") });
        let friendly = bag
            .as_ref()
            .and_then(|b| unsafe { b.bag_read("FriendlyName") });
        // Show both label forms in one field: a diagnostic listing has to make clear what each
        // candidate is, and a bare `@device:` string does not.
        let shown = match (&display, &friendly) {
            (Some(d), Some(f)) => Some(format!("{d} | friendly={f}")),
            (Some(d), None) => Some(d.clone()),
            (None, Some(f)) => Some(format!("friendly={f}")),
            (None, None) => None,
        };
        if !path.as_deref().is_some_and(wanted)
            && !display.as_deref().is_some_and(wanted)
            && !friendly.as_deref().is_some_and(wanted)
        {
            continue;
        }
        let source = if path.as_deref().is_some_and(wanted) {
            "device-path"
        } else if display.as_deref().is_some_and(wanted) {
            "display-name"
        } else {
            "friendly-name"
        };
        let identity = path
            .clone()
            .or_else(|| display.clone())
            .or(friendly.clone())
            .unwrap_or_default();
        // Same bind order as the single-match path: the measured GUID first, then plain IUnknown.
        let mut bound = unsafe { moniker.bind_to_object(&IID_IBASE_FILTER) };
        let mut via = "measured-bind-guid";
        if bound.is_err() {
            bound = unsafe { moniker.bind_to_object(&IUnknown::IID) };
            via = "IID_IUnknown";
        }
        let Ok(filter) = bound else {
            opened.push(Opened {
                control: ComPtr(core::ptr::null_mut()),
                identity,
                display_name: shown,
                bound_via: "bind failed",
                walked,
                identity_source: source,
            });
            let _ = via;
            continue;
        };
        let Ok(control) = (unsafe { ks_control_from(&filter) }) else {
            opened.push(Opened {
                control: ComPtr(core::ptr::null_mut()),
                identity,
                display_name: shown,
                bound_via: "no IKsControl",
                walked,
                identity_source: source,
            });
            continue;
        };
        opened.push(Opened {
            control,
            identity,
            display_name: shown,
            bound_via: via,
            walked,
            identity_source: source,
        });
    }
    if opened.is_empty() {
        return Err(Failure::NotMatched { seen: Vec::new() });
    }
    Ok(opened)
}

/// Walk the capture category and pick the filter whose identity `wanted` accepts.
///
/// Both the moniker display name and the property bag's `DevicePath` are consulted, because the
/// display name for some categories is the class-relative form; whichever string matches is
/// recorded, so the log shows the actual interface the handle belongs to.
pub fn open_capture_ks_control(wanted: &dyn Fn(&str) -> bool) -> Result<Opened, Failure> {
    use windows::core::Interface;
    use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};

    let unknown: IUnknown =
        unsafe { CoCreateInstance(&CLSID_SYSTEM_DEVICE_ENUM, None, CLSCTX_INPROC_SERVER) }
            .map_err(|e| Failure::Instantiate(e.code()))?;
    let dev_enum = unsafe { ComPtr::from_wrapper(unknown) };
    let dev_enum = match unsafe { dev_enum.query(&IID_ICREATE_DEV_ENUM) } {
        Ok(v) => v,
        Err(c) => return Err(Failure::Instantiate(c)),
    };
    let enumerator = match unsafe { dev_enum.create_class_enumerator(&CLSID_VIDEO_INPUT_CATEGORY) }
    {
        Ok(Some(e)) => e,
        Ok(None) => return Err(Failure::EmptyCategory),
        Err(c) => return Err(Failure::CreateEnum(c)),
    };

    let mut seen: Vec<String> = Vec::new();
    let mut walked = 0u32;
    loop {
        let moniker = match unsafe { enumerator.next_moniker() } {
            Ok(Some(m)) => m,
            Ok(None) => break,
            Err(c) if seen.is_empty() && walked == 0 => return Err(Failure::Next(c)),
            Err(_) => break,
        };
        walked += 1;
        let display = unsafe { moniker.display_name() }.ok().flatten();
        let bag = unsafe { moniker.query(&IID_IPROPERTY_BAG) }.ok();
        let path = bag
            .as_ref()
            .and_then(|b| unsafe { b.bag_read("DevicePath") });
        // `FriendlyName` is read for one reason: when a run fails, being able to show that the same
        // moniker the verified call selects gives the same answer rules the moniker choice in or out.
        // It is never used for matching by itself.
        let friendly = bag
            .as_ref()
            .and_then(|b| unsafe { b.bag_read("FriendlyName") });
        seen.extend(
            [path.clone(), display.clone(), friendly.clone()]
                .into_iter()
                .flatten(),
        );
        let Some(chosen) = pick_candidate([path, display.clone(), friendly], wanted) else {
            continue;
        };

        // Bind the filter object, then ask it for IKsControl. IBaseFilter first (that is what the
        // measured working call binds), then plain IUnknown in case this proxy answers only that.
        let mut bound = unsafe { moniker.bind_to_object(&IID_IBASE_FILTER) };
        let mut via = "IID_IBaseFilter";
        if bound.is_err() {
            bound = unsafe { moniker.bind_to_object(&IUnknown::IID) };
            via = "IID_IUnknown";
        }
        let filter = bound.map_err(Failure::Bind)?;
        let control = unsafe { ks_control_from(&filter) }.map_err(Failure::NoKsControl)?;
        return Ok(Opened {
            control,
            identity: chosen.identity,
            display_name: display,
            bound_via: via,
            walked,
            identity_source: chosen.source,
        });
    }
    Err(Failure::NotMatched { seen })
}

/// Ask a bound filter object for `IKsControl`, going through its **outer** `IUnknown` first.
///
/// The order is not stylistic. KS proxy filters are aggregates: the outer unknown dispatches to the
/// proxy, which owns the topology node table, while the interface pointer `BindToObject` handed back
/// may belong to the inner object. The verified working call obtains `IUnknown` from the object and
/// then queries `IKsControl` from that, so we do the same, and fall back to a direct query only if
/// even `IUnknown` is refused.
unsafe fn ks_control_from(filter: &ComPtr) -> Result<ComPtr, HRESULT> {
    match unsafe { filter.query(&IUnknown::IID) } {
        Ok(outer) => unsafe { outer.query(&IID_IKS_CONTROL) },
        Err(_) => unsafe { filter.query(&IID_IKS_CONTROL) },
    }
}

/// `IKsControl::KsProperty` on the bound filter.
///
/// # Safety
/// `control` must be a live `IKsControl`; `property` must stay readable for `property_length` bytes
/// and `data` writable for `data_length` bytes.
pub unsafe fn ks_property(
    control: &ComPtr,
    property: *const core::ffi::c_void,
    property_length: u32,
    data: *mut core::ffi::c_void,
    data_length: u32,
) -> Result<u32, HRESULT> {
    let mut returned = 0u32;
    let call: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *const core::ffi::c_void,
        u32,
        *mut core::ffi::c_void,
        u32,
        *mut u32,
    ) -> HRESULT = unsafe { core::mem::transmute(slot(control.raw(), SLOT_KS_PROPERTY)) };
    let code = unsafe {
        call(
            control.raw(),
            property,
            property_length,
            data,
            data_length,
            &mut returned,
        )
    };
    if code.is_ok() {
        Ok(returned)
    } else {
        Err(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The identity choice is where "matched the motor interface" would become a real bug: only the
    /// capture interface is allowed, the device path is preferred, and the accepted source is named.
    #[test]
    fn identity_candidates_prefer_the_device_path() {
        let wanted = |s: &str| s.to_ascii_lowercase().contains("vid_0603&pid_8612&mi_00");
        let path = "\\\\?\\usb#vid_0603&pid_8612&mi_00#7&1845226b&0&0000#{65e8}\\global";
        let display = "@device:pnp:{65e8} CM400";
        let chosen =
            pick_candidate([Some(path.into()), Some(display.into()), None], &wanted).unwrap();
        assert_eq!(
            chosen.source, "device-path",
            "the path wins when both match"
        );
        assert_eq!(chosen.identity, path);
        // Only the display name carries the identity: still used, and reported as such.
        let chosen = pick_candidate([None, Some(path.into()), None], &wanted).unwrap();
        assert_eq!(chosen.source, "display-name");
        // The motor interface must never be selected by a path-keyed matcher.
        let motor = "\\\\?\\usb#vid_0603&pid_8612&mi_02#8&2e26e82&0&0002#{11a9}\\global";
        assert!(pick_candidate([Some(motor.into()), Some(motor.into()), None], &wanted).is_none());
        assert!(pick_candidate([None, None, None], &wanted).is_none());
        // A friendly name alone can be accepted - which is exactly why the source is recorded, and
        // why the production matcher asks for the path.
        let chosen = pick_candidate([None, None, Some(path.into())], &wanted).unwrap();
        assert_eq!(chosen.source, "friendly-name");
    }

    /// The GUIDs handed to `CoCreateInstance`/`QueryInterface` have to be the documented ones: a
    /// typo here shows up as "device not found", which is the most misleading possible failure.
    #[test]
    fn the_interface_identities_are_the_documented_ones() {
        let text = |g: &GUID| {
            let h = format!("{:032x}", g.to_u128());
            format!(
                "{}-{}-{}-{}-{}",
                h[0..8].to_uppercase(),
                h[8..12].to_uppercase(),
                h[12..16].to_uppercase(),
                h[16..20].to_uppercase(),
                h[20..32].to_uppercase()
            )
        };
        assert_eq!(
            text(&CLSID_SYSTEM_DEVICE_ENUM),
            "62BE5D10-60EB-11D0-BD3B-00A0C911CE86"
        );
        assert_eq!(
            text(&CLSID_VIDEO_INPUT_CATEGORY),
            "860BB310-5D01-11D0-BD3B-00A0C911CE86"
        );
        assert_eq!(
            text(&IID_ICREATE_DEV_ENUM),
            "29840822-5B84-11D0-BD3B-00A0C911CE86"
        );
        assert_eq!(
            text(&IID_IBASE_FILTER),
            "56A86895-0AD4-11CE-B03A-0020AF0BA770"
        );
        assert_eq!(
            text(&IID_IKS_CONTROL),
            "28F54685-06FD-11D2-B27A-00A0C9223196"
        );
        assert_eq!(
            text(&IID_IPROPERTY_BAG),
            "55272A00-42CB-11CE-8135-00AA004BB851"
        );
        // Distinctness: two of these sharing a value would be a silent wrong-interface QI.
        let all = [
            CLSID_SYSTEM_DEVICE_ENUM,
            CLSID_VIDEO_INPUT_CATEGORY,
            IID_ICREATE_DEV_ENUM,
            IID_IBASE_FILTER,
            IID_IKS_CONTROL,
            IID_IPROPERTY_BAG,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j {
                    assert_ne!(a.to_u128(), b.to_u128(), "identities {i} and {j} collide");
                }
            }
        }
    }

    /// Slot indices are the load-bearing part of this file. They are asserted here so that editing
    /// one cannot be mistaken for a cosmetic change.
    #[test]
    fn vtable_slots_match_the_documented_layout() {
        assert_eq!(SLOT_QUERY_INTERFACE, 0, "IUnknown QI is always slot 0");
        assert_eq!(SLOT_RELEASE, 2, "IUnknown Release is always slot 2");
        assert_eq!(
            SLOT_CREATE_CLASS_ENUMERATOR, 3,
            "ICreateDevEnum's only method"
        );
        assert_eq!(SLOT_ENUM_NEXT, 3, "IEnumX shape");
        assert_eq!(SLOT_PROPERTY_BAG_READ, 3, "IPropertyBag::Read");
        assert_eq!(SLOT_KS_PROPERTY, 3, "IKsControl::KsProperty");
        assert_eq!(SLOT_BIND_TO_OBJECT, 8, "after IPersist's five methods");
        assert_eq!(SLOT_GET_DISPLAY_NAME, 20, "IMoniker::GetDisplayName");
    }

    /// What `bag_read` depends on, measured rather than assumed: an empty `VARIANT` converts to an
    /// empty `BSTR` successfully, so the code must filter on emptiness - checking for an error alone
    /// would let "no value" through as if it were an identity.
    #[test]
    fn an_empty_variant_yields_an_empty_string_not_an_error() {
        let v = windows::core::VARIANT::new();
        assert!(v.is_empty());
        let converted = windows::core::BSTR::try_from(&v);
        assert!(
            converted.is_ok(),
            "the crate does not reject this conversion"
        );
        assert!(
            converted.unwrap().is_empty(),
            "and the result carries no text"
        );
    }

    /// A wide read stops at the bound instead of walking off when nothing terminates it.
    #[test]
    fn wide_strings_are_read_within_a_bound() {
        let text: Vec<u16> = "abc".encode_utf16().chain([0]).collect();
        assert_eq!(wide_to_string(text.as_ptr() as *mut u16), "abc");
        let unterminated = vec![0x41u16; 5000];
        assert_eq!(
            wide_to_string(unterminated.as_ptr() as *mut u16)
                .chars()
                .count(),
            4096,
            "the bound is the cap, not the allocation"
        );
        assert_eq!(
            wide_to_string(core::ptr::null_mut()).len(),
            0,
            "null reads as empty, not a crash"
        );
    }

    /// The failure text has to name the step, because the codes alone do not.
    #[test]
    fn failures_name_the_step_that_failed() {
        // HRESULT carries a signed i32, so these are the sign-extended forms of the real codes.
        let code = |v: u32| HRESULT(v as i32);
        assert!(Failure::Instantiate(code(0x8004_0154))
            .describe()
            .contains("CoCreateInstance"));
        assert!(Failure::CreateEnum(code(0x8007_0002))
            .describe()
            .contains("CreateClassEnumerator"));
        assert!(Failure::Next(code(0x8000_4001)).describe().contains("Next"));
        assert!(Failure::Bind(code(0x8007_0057))
            .describe()
            .contains("BindToObject"));
        assert!(Failure::NoKsControl(code(0x8000_4002))
            .describe()
            .contains("IKsControl"));
        assert!(Failure::EmptyCategory.describe().contains("no filters"));
        assert!(
            Failure::NotMatched {
                seen: vec!["a".into(), "b".into()]
            }
            .describe()
            .contains("2 identity strings were seen"),
            "a not-matched report has to say how many were looked at"
        );
    }
}
