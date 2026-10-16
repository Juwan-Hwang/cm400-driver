//! CM400 Windows backend: WinUSB motor transport.
//!
//! Implements `cm400_core::Transport` over the real device. All requests are
//! built via `cm400_protocol::ControlRequest`, so the safety whitelist is
//! enforced even at the wire boundary. Discovery targets a stable DeviceInterface
//! GUID (what the production INF will register); it also accepts the GUID Zadig
//! used in the W0-B experiment so 2-A runs against the current rig.
//!
//! W0 facts encoded: reach the XU via device-recipient (0x20/0xA0), wIndex
//! 0x0500; the WinUSB handle MUST be opened with FILE_FLAG_OVERLAPPED or
//! WinUsb_Initialize fails with ERROR_INVALID_HANDLE (6).

pub mod artifact_manifest;
pub mod bundle;
pub mod catalog_trust;
pub mod cert_cleanup;
pub mod config;
pub mod diagnostics;
pub mod directshow;
pub mod etw_loss;
pub mod etw_source;
pub mod iks_probe;
pub mod kernel_lifecycle;
pub mod logging;
pub mod native_trust;
pub mod proc_identity;
pub mod proc_lifecycle;
pub mod report_link;
pub mod runtime;
pub mod sam_source;
pub mod sam_view;
pub mod security;
pub mod trust;
pub mod trust_ownership;

pub use etw_source::WindowsFrameServerEtwSource;

use std::io::Write;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::Config;

/// Timestamped log line for this backend (runtime, activity source, hosts).
///
/// The file under ProgramData is the authoritative sink: a Windows service has no
/// console, and writing to stdout there must be ignored rather than panic. It is
/// also the only place a stopped service's teardown can be observed at all.
pub fn log(msg: &str) {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let line = format!("[t={ms}ms] {msg}");
    let _ = std::io::stdout().write_all(line.as_bytes());
    let _ = std::io::stdout().write_all(b"\n");
    let dir = Config::data_dir().join("logs");
    if std::fs::create_dir_all(&dir).is_ok() {
        // Bounded retention happens here, on the write path, so the cap holds for a service that
        // runs for weeks and not just for one that happens to be restarted.
        let _ = crate::logging::append_line(&dir.join("cm400d.log"), &line);
    }
}

use windows::core::{GUID, PCWSTR};
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInterfaces, SetupDiGetClassDevsW,
    SetupDiGetDeviceInterfaceDetailW, DIGCF_DEVICEINTERFACE, DIGCF_PRESENT,
    SP_DEVICE_INTERFACE_DATA, SP_DEVICE_INTERFACE_DETAIL_DATA_W,
};
use windows::Win32::Devices::Usb::{
    WinUsb_ControlTransfer, WinUsb_Free, WinUsb_GetDescriptor, WinUsb_Initialize,
    WINUSB_INTERFACE_HANDLE, WINUSB_SETUP_PACKET,
};
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, HWND};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, FILE_SHARE_MODE, OPEN_EXISTING,
};

use cm400_core::Transport;
use cm400_protocol::{ControlRequest, Direction, Recipient};

/// Stable interface GUID the production INF registers for MI_02.
pub const CM400_MOTOR_INTERFACE_GUID: GUID =
    GUID::from_u128(0x11a9_c0d3_5f2b_4e7a_9c31_0b6d_2e4f_8a10);

/// GUID Zadig assigned in the W0-B experiment rig (fallback so 2-A runs now).
pub const ZADIG_TEST_INTERFACE_GUID: GUID =
    GUID::from_u128(0xd2dd_2f4c_e5da_4a9f_9ff6_9e8d_708e_4056);

/// Contract tests for the interface GUID.
///
/// They exist because a malformed-but-plausible GUID STRING is invisible to
/// SetupAPI: the value is written to `Device Parameters` without complaint, and
/// WinUSB then simply fails to parse it, so no device interface is ever created.
/// Measured on this rig - `{11a9c0d3-5f2b-4e7a-9c31-0b6d-2e4f-8a10}` (an 8-4-4-4-4-4-4
/// layout) sat in the key the whole time while `SetupDiGetClassDevs` found nothing.
/// The binary constant was correct all along; only the INF text was wrong, which is
/// exactly the kind of split this test is meant to close.
#[cfg(test)]
mod guid_contract {
    use super::{CM400_MOTOR_INTERFACE_GUID, ZADIG_TEST_INTERFACE_GUID};

    /// Registry text form: 8-4-4-4-12 hex digits, braces included.
    fn canonical(value: u128) -> String {
        let hex = format!("{value:032x}");
        format!(
            "{{{}-{}-{}-{}-{}}}",
            &hex[0..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..32]
        )
    }

    fn inf_motor_guid() -> Option<String> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../install/cm400.inf");
        let text = std::fs::read_to_string(path).ok()?;
        for line in text.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("MotorGuid") {
                if let Some((_, value)) = rest.split_once('=') {
                    return Some(value.trim().trim_matches('"').trim().to_string());
                }
            }
        }
        None
    }

    #[test]
    fn canonical_form_is_8_4_4_4_12() {
        let g = canonical(CM400_MOTOR_INTERFACE_GUID.to_u128());
        let inner = g.trim_start_matches('{').trim_end_matches('}');
        let lens: Vec<usize> = inner.split('-').map(str::len).collect();
        assert_eq!(
            lens,
            vec![8usize, 4, 4, 4, 12],
            "text {g} is not registry form"
        );
    }

    #[test]
    fn inf_motor_guid_matches_the_rust_binary_guid() {
        let from_inf = inf_motor_guid().expect("MotorGuid not found in install/cm400.inf");
        let want = canonical(CM400_MOTOR_INTERFACE_GUID.to_u128());
        assert_eq!(
            from_inf.to_ascii_lowercase(),
            want,
            "install/cm400.inf and CM400_MOTOR_INTERFACE_GUID disagree"
        );
    }

    #[test]
    fn both_guids_are_32_hex_digits_once_dashes_are_stripped() {
        for guid in [CM400_MOTOR_INTERFACE_GUID, ZADIG_TEST_INTERFACE_GUID] {
            let text = canonical(guid.to_u128())
                .trim_start_matches('{')
                .trim_end_matches('}')
                .replace('-', "");
            assert_eq!(text.len(), 32, "{text}");
            assert!(text.chars().all(|c| c.is_ascii_hexdigit()), "{text}");
        }
    }
}

const GENERIC_READ_WRITE: u32 = 0x8000_0000 | 0x4000_0000;
const SHARE_READ_WRITE: u32 = 0x0000_0001 | 0x0000_0002;

#[derive(Debug)]
pub enum TransportError {
    NotFound,
    OpenFailed(u32),
    InitFailed(u32),
    Io(u32),
    Protocol(String),
}

fn matches_cm400(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.contains("vid_0603") && p.contains("pid_8612") && p.contains("mi_02")
}

unsafe fn paths_for_guid(guid: &GUID) -> Vec<String> {
    let mut out = Vec::new();
    let hdev = match SetupDiGetClassDevsW(
        Some(guid as *const GUID),
        PCWSTR::null(),
        HWND::default(),
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
    ) {
        Ok(h) => h,
        Err(_) => return out,
    };
    let mut idx = 0u32;
    loop {
        let mut data = SP_DEVICE_INTERFACE_DATA {
            cbSize: std::mem::size_of::<SP_DEVICE_INTERFACE_DATA>() as u32,
            ..Default::default()
        };
        if SetupDiEnumDeviceInterfaces(hdev, None, guid as *const GUID, idx, &mut data).is_err() {
            break;
        }
        idx += 1;
        let mut required = 0u32;
        let _ = SetupDiGetDeviceInterfaceDetailW(hdev, &data, None, 0, Some(&mut required), None);
        if required == 0 {
            continue;
        }
        let mut buf = vec![0u8; required as usize];
        let detail = buf.as_mut_ptr() as *mut SP_DEVICE_INTERFACE_DETAIL_DATA_W;
        (*detail).cbSize = if cfg!(target_pointer_width = "64") {
            8
        } else {
            6
        };
        if SetupDiGetDeviceInterfaceDetailW(hdev, &data, Some(detail), required, None, None).is_ok()
        {
            let wptr = buf.as_ptr().add(4) as *const u16;
            let wlen = (required as usize - 4) / 2;
            let wslice = std::slice::from_raw_parts(wptr, wlen);
            let end = wslice.iter().position(|&c| c == 0).unwrap_or(wslice.len());
            out.push(String::from_utf16_lossy(&wslice[..end]));
        }
    }
    let _ = SetupDiDestroyDeviceInfoList(hdev);
    out
}

/// Find the CM400 MI_02 WinUSB device interface path across candidate GUIDs.
pub fn find_motor_interface_path() -> Option<String> {
    find_motor_interface().map(|(path, _)| path)
}

/// Same discovery, but reporting WHICH registration matched.
///
/// Worth exposing because two GUIDs can match the same hardware: after our own
/// INF is installed, discovery must succeed on the production GUID, and the
/// Zadig/libwdi fallback must visibly stop being the path in use. Without this
/// label a working motor could silently still depend on the test rig.
pub fn find_motor_interface() -> Option<(String, &'static str)> {
    for (label, guid) in [
        (
            "production INF (install/cm400.inf)",
            CM400_MOTOR_INTERFACE_GUID,
        ),
        ("Zadig/libwdi fallback", ZADIG_TEST_INTERFACE_GUID),
    ] {
        if let Some(p) = unsafe { paths_for_guid(&guid) }
            .into_iter()
            .find(|p| matches_cm400(p))
        {
            return Some((p, label));
        }
    }
    None
}

pub struct WinUsbTransport {
    device: HANDLE,
    iface: WINUSB_INTERFACE_HANDLE,
}

impl WinUsbTransport {
    pub fn open() -> Result<Self, TransportError> {
        let path = find_motor_interface_path().ok_or(TransportError::NotFound)?;
        Self::open_path(&path)
    }

    fn open_path(path: &str) -> Result<Self, TransportError> {
        let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        let device = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                GENERIC_READ_WRITE,
                FILE_SHARE_MODE(SHARE_READ_WRITE),
                None,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                HANDLE::default(),
            )
        };
        let device = match device {
            Ok(h) => h,
            Err(_) => return Err(TransportError::OpenFailed(unsafe { GetLastError().0 })),
        };
        let mut iface = WINUSB_INTERFACE_HANDLE::default();
        if unsafe { WinUsb_Initialize(device, &mut iface) }.is_err() {
            let e = unsafe { GetLastError().0 };
            unsafe {
                let _ = CloseHandle(device);
            }
            return Err(TransportError::InitFailed(e));
        }
        Ok(WinUsbTransport { device, iface })
    }

    fn transfer(&self, req: &ControlRequest) -> Result<Option<u8>, TransportError> {
        let setup = req
            .to_setup()
            .map_err(|e| TransportError::Protocol(format!("{:?}", e)))?;
        let packet = WINUSB_SETUP_PACKET {
            RequestType: setup.bm_request_type,
            Request: setup.b_request,
            Value: setup.w_value,
            Index: setup.w_index,
            Length: setup.w_length,
        };
        // For SET (OUT) the data stage must carry the payload value; for GET (IN)
        // the device fills the buffer. Omitting this sends value 0 (a documented
        // no-op per spec §7) -> "API success but nothing moves".
        let mut buf: [u8; 1] = req.data_out().unwrap_or([0u8; 1]);
        let mut xfer = 0u32;
        let ok = unsafe {
            WinUsb_ControlTransfer(
                self.iface,
                packet,
                Some(&mut buf[..]),
                Some(&mut xfer),
                None,
            )
        };
        if ok.is_err() {
            return Err(TransportError::Io(unsafe { GetLastError().0 }));
        }
        Ok(match req.direction {
            Direction::In => Some(buf[0]),
            Direction::Out => None,
        })
    }

    /// Rich get for diagnostics (echo value). Remember: firmware echo is a state
    /// variable, never a physical position.
    pub fn get_echo(&mut self) -> Result<u8, TransportError> {
        self.transfer(&ControlRequest::motor_get(Recipient::Device))
            .map(|v| v.unwrap_or(0))
    }

    /// One motor command. The data stage must carry the value (see `transfer`).
    pub fn set_value(&mut self, value: u8) -> Result<(), TransportError> {
        self.transfer(&ControlRequest::motor_set(value, Recipient::Device))
            .map(|_| ())
    }

    /// Raw GET_DESCRIPTOR, relayed to the device by WinUSB. Diagnostic only
    /// (`cm400ctl usbprobe`); the motor path never needs it.
    pub fn get_descriptor(
        &self,
        kind: u8,
        index: u8,
        lang: u16,
        buf: &mut [u8],
    ) -> Result<usize, TransportError> {
        let mut n = 0u32;
        unsafe { WinUsb_GetDescriptor(self.iface, kind, index, lang, Some(buf), &mut n) }
            .map_err(|_| TransportError::Io(unsafe { GetLastError().0 }))?;
        Ok(n as usize)
    }

    /// Vendor IN control request. Read-only by construction (no OUT data stage,
    /// device recipient), used only to fetch the Microsoft OS descriptor sets.
    pub fn vendor_in(
        &self,
        request: u8,
        value: u16,
        index: u16,
        buf: &mut [u8],
    ) -> Result<usize, TransportError> {
        let packet = WINUSB_SETUP_PACKET {
            RequestType: 0xC0, // device-to-host | vendor request | device recipient
            Request: request,
            Value: value,
            Index: index,
            Length: buf.len() as u16,
        };
        let mut n = 0u32;
        let ok =
            unsafe { WinUsb_ControlTransfer(self.iface, packet, Some(buf), Some(&mut n), None) };
        if ok.is_err() {
            return Err(TransportError::Io(unsafe { GetLastError().0 }));
        }
        Ok(n as usize)
    }
}

impl Drop for WinUsbTransport {
    fn drop(&mut self) {
        unsafe {
            let _ = WinUsb_Free(self.iface);
            let _ = CloseHandle(self.device);
        }
    }
}

/// Motor access that owns nothing between calls.
///
/// Why not hold the handle: MI_02 is an **exclusive interface** (measured - while
/// any handle is open, every other `CreateFile`, elevated included, gets
/// ERROR_ACCESS_DENIED), and it is a DFU function. A resident service that kept it
/// open would permanently lock out the vendor's firmware/DFU tools. So each
/// operation is: discover -> open -> initialize -> transfer -> free -> close.
///
/// The `gate` is not for the engine loop (that already serializes via `&mut self`);
/// it exists because the interface itself cannot be opened twice: any second
/// concurrent user in-process must queue rather than hit ACCESS_DENIED.
/// Two separate concerns stay separate: this mutex = no concurrent USB access;
/// the engine's write throttle = no dangerous mechanical command rate.
pub struct MotorChannel {
    gate: Mutex<()>,
    last_route: Mutex<Option<(String, &'static str)>>,
}

impl MotorChannel {
    pub fn new() -> Self {
        MotorChannel {
            gate: Mutex::new(()),
            last_route: Mutex::new(None),
        }
    }

    /// Which interface the previous operation went through: the symbolic link plus the
    /// label that says whether it is our production GUID or the Zadig/libwdi fallback.
    /// Acceptance requires this per motor action - a lens that moves proves nothing
    /// about WHICH interface the command travelled on, and both GUIDs can resolve to
    /// the same hardware on a development rig.
    pub fn last_route(&self) -> Option<(String, &'static str)> {
        self.last_route
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Acquire the interface, run one operation, release it. A poisoned gate is
    /// unusable device access rather than a reason to deadlock the service.
    fn with<R, F: FnOnce(&mut WinUsbTransport) -> R>(&mut self, f: F) -> Result<R, TransportError> {
        let guard = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        // Recorded with the same lookup WinUsbTransport::open() performs, so this is
        // the interface the handle was actually taken on.
        if let Some(route) = find_motor_interface() {
            *self.last_route.lock().unwrap_or_else(|e| e.into_inner()) = Some(route);
        }
        let mut dev = WinUsbTransport::open()?;
        let out = f(&mut dev);
        // Explicit close before the mutex is released: the next opener (including a
        // vendor tool) must never see the interface still held by us.
        drop(dev);
        drop(guard);
        Ok(out)
    }

    pub fn get(&mut self) -> Result<u8, TransportError> {
        self.with(|d| d.get_echo())?
    }

    pub fn set(&mut self, value: u8) -> Result<(), TransportError> {
        self.with(|d| d.set_value(value))?
    }

    /// Is the motor reachable right now? Opens and closes, so this leaves nothing
    /// locked. `Ok(true)` = interface found and one GET succeeded.
    pub fn probe(&mut self) -> Result<bool, TransportError> {
        self.get().map(|_| true)
    }

    /// Is the device present without claiming it? Checks the device interface only,
    /// never opens a handle - safe to call while something else owns MI_02.
    pub fn device_present() -> bool {
        find_motor_interface_path().is_some()
    }
}

impl Default for MotorChannel {
    fn default() -> Self {
        MotorChannel::new()
    }
}

impl Transport for MotorChannel {
    fn get(&mut self) -> Result<u8, ()> {
        MotorChannel::get(self).map_err(|_| ())
    }
    fn set(&mut self, value: u8) -> Result<(), ()> {
        // The error text is not lost by erasing it here: `Runtime` already logs the failed command
        // with the transport error (measured: `motor SET(1) -> false (NotFound)`), so adding a
        // second line at this boundary would only duplicate it.
        MotorChannel::set(self, value).map_err(|_| ())
    }
}
