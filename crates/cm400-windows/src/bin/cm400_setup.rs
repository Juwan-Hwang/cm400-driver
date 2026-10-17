//! cm400-setup - the Windows installer entry point (Phase 2-D5 prototype).
//!
//! Deliberately a separate binary: driver installation is a one-time, elevated,
//! user-visible act. A LocalService daemon must not repair drivers behind its own
//! back at startup, so this work never belongs in `cm400d`.
//!
//! What this prototype proves is the one link `pnputil` could not deliver:
//!
//! ```text
//! UpdateDriverForPlugAndPlayDevices -> SetupAPI device install
//!     -> DDInstall.HW -> DeviceInterfaceGUIDs -> SetupDi discovery -> WinUSB
//! ```
//!
//! Why pnputil was not enough, measured on this machine: `pnputil /add-driver
//! /install`, and even a forced brand-new device install, configured the driver
//! package (class, service, hardware IDs, winusb.inf Needs chain) but produced NO
//! DDInstall.HW effect - not even for winusb.inf's own `.HW`. The app-side
//! `setupapi.app.log` for that transaction contains only `DIF_REMOVE`, i.e. the
//! SetupAPI device-install stage that applies `.HW` never ran. The boundary of
//! that claim is this machine and this path, not "PnP never executes .HW".
//!
//! Safety: this binary never sends a motor command. It issues at most a GET_CUR.
//! `INSTALLFLAG_FORCE` is deliberately NOT used: forcing can replace a better
//! match with a worse one.

use std::ffi::OsString;
use std::path::PathBuf;

use windows::core::PCWSTR;
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    DiInstallDevice, SetupDiBuildDriverInfoList, SetupDiCallClassInstaller,
    SetupDiDestroyDeviceInfoList, SetupDiDestroyDriverInfoList, SetupDiEnumDeviceInfo,
    SetupDiEnumDriverInfoW, SetupDiGetClassDevsW, SetupDiGetDeviceInstanceIdW,
    SetupDiOpenDevRegKey, SetupDiSetSelectedDriverW, DICS_FLAG_GLOBAL, DIF_INSTALLDEVICE,
    DIGCF_ALLCLASSES, DIGCF_PRESENT, DIREG_DEV, HDEVINFO, SETUP_DI_DRIVER_TYPE, SPDIT_CLASSDRIVER,
    SPDIT_COMPATDRIVER, SP_DEVINFO_DATA, SP_DRVINFO_DATA_V2_W,
};
use windows::Win32::Foundation::{BOOL, HWND};

use cm400_windows::{find_motor_interface, MotorChannel};
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    UpdateDriverForPlugAndPlayDevicesW, UPDATEDRIVERFORPLUGANDPLAYDEVICES_FLAGS,
};

/// The exact function we own. Nothing here matches MI_00/MI_01 (usbvideo).
const MOTOR_HW_ID: &str = "USB\\VID_0603&PID_8612&MI_02";

/// Instance id of the motor function on this rig.
const MOTOR_INSTANCE: &str = "USB\\VID_0603&PID_8612&MI_02\\8&2E26E82&0&0002";

/// Provider string written by our INF; used to pick the driver node explicitly
/// instead of letting PnP re-run best-match selection. Overridable for recovery.
const OUR_PROVIDER: &str = "CM400 Driver";

fn set_provider(over: Option<&str>) {
    if let Some(p) = over {
        println!("provider filter : {p} (explicit node selection)");
        let _ = PROVIDER.set(p.to_string());
    }
}

/// Set once from the command line; no unsafe global needed for a CLI process.
static PROVIDER: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn provider_filter() -> String {
    PROVIDER
        .get()
        .cloned()
        .unwrap_or_else(|| OUR_PROVIDER.to_string())
}

fn from_wide(w: &[u16]) -> String {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end])
}

fn wp(s: &str) -> PCWSTR {
    // Leak: the API keeps no copy, but the pointer must survive the call.
    let v: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    let leaked: &'static mut [u16] = Box::leak(v.into_boxed_slice());
    PCWSTR(leaked.as_mut_ptr() as *const u16)
}

fn main() {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match args.first().and_then(|a| a.to_str()) {
        Some("install-driver") => install_driver(&args[1..]),
        Some("install-device") => {
            // Optional 2nd argument selects the driver node by INF provider, which is
            // how recovery re-binds the libwdi package on purpose: PnP will not
            // downgrade by rank, so an explicit node choice is required.
            set_provider(args.get(2).and_then(|a| a.to_str()));
            install_device(
                args.get(1)
                    .and_then(|a| a.to_str())
                    .unwrap_or(MOTOR_INSTANCE),
                false,
            )
        }
        Some("install-device-dif") => install_device(
            args.get(1)
                .and_then(|a| a.to_str())
                .unwrap_or(MOTOR_INSTANCE),
            true,
        ),
        // Read-only: prints which interface GUID matched, the interface path (which
        // carries the instance id) and a GET_CUR. Used for polling after a DIF
        // install without re-running any installer, and it never actuates.
        Some("probe") => verify(),
        // Writes DeviceInterfaceGUIDs into the device's `Device Parameters` subkey,
        // opened through SetupDiOpenDevRegKey rather than a guessed registry path.
        Some("register-guid") => register_guid(args.get(1).and_then(|a| a.to_str())),
        Some("install") => install_flow(&args[1..]),
        Some("harden-acl") => {
            // Elevated, idempotent repair of the data directory's ACL; prints the verdict.
            if harden_data_acl() {
                std::process::exit(27);
            }
        }
        Some("verify-package") => verify_package_cli(&args[1..]),
        // Read-only, no elevation: says which commit and tree state produced this exact binary. It is a
        // claim the file makes about itself, checked against the release record and the signature - not a
        // proof on its own, which is why the build record also stores the file's SHA-256.
        Some("--version") | Some("version") => {
            println!("cm400-setup {}", env!("CARGO_PKG_VERSION"));
            println!(
                "  commit      : {}",
                option_env!("CM400_GIT_COMMIT").unwrap_or("unknown")
            );
            println!(
                "  describe    : {}",
                option_env!("CM400_GIT_TAG").unwrap_or("unknown")
            );
            println!(
                "  tree state  : {}",
                option_env!("CM400_GIT_DIRTY").unwrap_or("unknown")
            );
            println!(
                "  commit date : {}",
                option_env!("CM400_BUILD_TIME").unwrap_or("unknown")
            );
            println!("  target      : {}", std::env::consts::ARCH);
            println!(
                "  profile     : {}",
                if cfg!(debug_assertions) {
                    "debug"
                } else {
                    "release"
                }
            );
            println!("  publisher   : the Authenticode signature and `cm400-catsig verify` are what attest the");
            println!("                bytes; this listing only states what was compiled.");
        }
        // Read-only: the same reporter the control tool uses, without opening the motor interface. It
        // needs no elevation and stages nothing, so it can be run on a machine nobody has touched yet.
        Some("status") => {
            for line in cm400_windows::diagnostics::status_lines(
                &cm400_windows::config::Config::deployed_daemon_path(),
                false,
            ) {
                println!("{line}");
            }
        }
        // The licence copy has to reach the recipient; in a single-file package that means it is inside.
        Some("--license") | Some("license") => print_license(),
        Some("pinned-identity") => {
            // Read-only, and the reason build scripts stop comparing package files with each other:
            // this is the identity the binary was built to accept.
            println!(
                "sha256_der       : {}",
                cm400_windows::trust::PINNED_SHA256_DER
            );
            println!(
                "sha1_thumbprint  : {}",
                cm400_windows::trust::PINNED_SHA1_THUMBPRINT
            );
            println!(
                "subject          : {}",
                cm400_windows::cert_cleanup::EXPECTED_SUBJECT
            );
        }
        Some("uninstall") => uninstall_gated(&args[1..]),
        // double-clicked, or run with no plan: ask, do not guess
        None => interactive_flow(),
        _ => {
            eprintln!(
                "usage:\n   cm400-setup                        interactive install or maintenance\n  \x20 cm400-setup install   [path\\to\\cm400.inf]\n   cm400-setup uninstall [--yes]\n   cm400-setup status                   (read-only, no elevation needed)\n   cm400-setup harden-acl\n   cm400-setup verify-package  [path\\to\\cm400.inf]\n   cm400-setup --version                   (which commit built this binary)\n   cm400-setup --license\n   cm400-setup pinned-identity\n   cm400-setup install-driver       [path\\to\\cm400.inf]\n   cm400-setup install-device       [device-instance-id] [provider]\n   cm400-setup install-device-dif [device-instance-id]\n   cm400-setup probe\n   cm400-setup register-guid <guid>\n\n\
                 `install` is the product entry point: preflight -> quiesce -> stage + bind ->\n\
                 verify by INTERFACE ENUMERATION (never by an API returning success).\n\
                 It never assumes a third-party rollback package exists, never touches MI_00/MI_01,\n\
                 and sends no motor command. An unrecognised command is not interpreted."
            );
            std::process::exit(1);
        }
    }
}

/// INF to install: explicit argument, else the copy next to this executable
/// (what the shipped installer layout will look like).
fn resolve_inf(arg: Option<&OsString>) -> Result<PathBuf, String> {
    if let Some(p) = arg {
        let path = PathBuf::from(p);
        if path.exists() {
            return Ok(path);
        }
        return Err(format!("INF not found: {}", path.display()));
    }
    let mut exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    exe.pop();
    let cand = exe.join("cm400.inf");
    if cand.exists() {
        return Ok(cand);
    }
    Err("no INF given and none next to the executable".to_string())
}

fn install_driver(rest: &[OsString]) {
    let inf = match resolve_inf(rest.first()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("cm400-setup: {e}");
            std::process::exit(2);
        }
    };
    let inf_str = inf.to_string_lossy().to_string();
    println!("inf            : {inf_str}");
    println!("hardware id    : {MOTOR_HW_ID}");
    println!("install flags  : none (no INSTALLFLAG_FORCE; must be a better match)");

    let mut reboot = BOOL::default();
    let result = unsafe {
        UpdateDriverForPlugAndPlayDevicesW(
            HWND::default(),
            wp(MOTOR_HW_ID),
            wp(&inf_str),
            UPDATEDRIVERFORPLUGANDPLAYDEVICES_FLAGS::default(),
            Some(&mut reboot),
        )
    };
    match result {
        Ok(()) => println!("update driver  : OK (reboot_required={})", reboot.0 != 0),
        Err(e) => {
            // FormatMessage gives the real Win32 text; ERROR_INVALID_MACHINEARCHITECTURE
            // etc. would otherwise be invisible numbers.
            eprintln!("update driver  : FAILED {e}");
            verify();
            std::process::exit(5);
        }
    }
    verify();
}

/// D5-3: run the device-install stage directly, on an explicitly selected driver
/// node. `UpdateDriverForPlugAndPlayDevices` and `pnputil` both stopped at package
/// configuration here; MS documents the device-install call itself as the step that
/// locates DDInstall, processes DDInstall.HW (hardware key) and DDInstall.Services,
/// and registers device interfaces - so this asks that question without a wrapper.
/// D5-4: same selection, but submit the DIF request itself.
/// `DiInstallDevice` is a wrapper; MS documents `SetupDiCallClassInstaller` as the
/// entry that walks class installer -> co-installers -> default handler in order,
/// and `SetupDiInstallDevice` as the DEFAULT HANDLER of `DIF_INSTALLDEVICE`. Our
/// app.log never showed a `DIF_INSTALLDEVICE` transaction, so this asks the
/// narrower question: does the DIF install request produce DDInstall.HW effects?
fn install_device(instance: &str, via_dif: bool) {
    println!("instance       : {instance}");
    println!(
        "selection      : provider == {:?} (no best-match re-derivation)",
        provider_filter()
    );
    println!(
        "install path   : {}",
        if via_dif {
            "SetupDiSetSelectedDriver + SetupDiCallClassInstaller(DIF_INSTALLDEVICE)"
        } else {
            "DiInstallDevice"
        }
    );
    let code = unsafe { run_install_device(instance, via_dif) };
    verify();
    if code != 0 {
        std::process::exit(code);
    }
}

unsafe fn run_install_device(instance: &str, via_dif: bool) -> i32 {
    // SetupDiGetClassDevs requires DIGCF_ALLCLASSES whenever ClassGuid is NULL -
    // without it the call fails with ERROR_INVALID_PARAMETER (measured twice:
    // 0x80070057 with a NULL enumerator, and again with "USB" alone).
    let set = match SetupDiGetClassDevsW(
        None,
        wp("USB"),
        HWND::default(),
        DIGCF_PRESENT | DIGCF_ALLCLASSES,
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("SetupDiGetClassDevs failed: {e}");
            return 6;
        }
    };

    let mut idx = 0u32;
    let mut rc = 7i32;
    let mut done = false;
    while !done {
        let mut di: SP_DEVINFO_DATA = std::mem::zeroed();
        di.cbSize = std::mem::size_of::<SP_DEVINFO_DATA>() as u32;
        if SetupDiEnumDeviceInfo(set, idx, &mut di).is_err() {
            eprintln!("device instance not found among present devices");
            break;
        }
        idx += 1;

        let mut buf = [0u16; 512];
        if SetupDiGetDeviceInstanceIdW(set, &di, Some(&mut buf), None).is_err() {
            continue;
        }
        if !from_wide(&buf).eq_ignore_ascii_case(instance) {
            continue;
        }

        // Drivers installable on this device: pick OUR node explicitly so "best
        // match" is never a variable. The list MUST stay alive until after
        // DiInstallDevice - destroying it first invalidates the node and the call
        // fails with ERROR_INVALID_PARAMETER (measured).
        let mut kind = SPDIT_COMPATDRIVER;
        let mut picked = None;
        if SetupDiBuildDriverInfoList(set, Some(&mut di), kind).is_ok() {
            picked = scan_nodes(set, &di, kind);
        }
        if picked.is_none() {
            let _ = SetupDiDestroyDriverInfoList(set, Some(&di), kind);
            kind = SPDIT_CLASSDRIVER;
            if SetupDiBuildDriverInfoList(set, Some(&mut di), kind).is_ok() {
                picked = scan_nodes(set, &di, kind);
            }
        }
        rc = match picked {
            None => {
                eprintln!(
                    "no driver node with provider {:?} is offered to this device",
                    provider_filter()
                );
                9
            }
            Some(mut dv) => {
                let mut reboot = BOOL(0);
                if via_dif {
                    // Mark our node as the selected driver, then submit the DIF
                    // request. Teardown of the list happens only after this.
                    if let Err(e) = SetupDiSetSelectedDriverW(set, Some(&mut di), Some(&mut dv)) {
                        eprintln!("SetupDiSetSelectedDriver : FAILED {e}");
                        return 11;
                    }
                    match SetupDiCallClassInstaller(DIF_INSTALLDEVICE, set, Some(&di)) {
                        Ok(()) => {
                            println!(
                                "DIF_INSTALLDEVICE: submitted (class installer -> default handler)"
                            );
                            0
                        }
                        Err(e) => {
                            eprintln!("DIF_INSTALLDEVICE: FAILED {e}");
                            12
                        }
                    }
                } else {
                    match DiInstallDevice(
                        HWND::default(),
                        set,
                        &di,
                        Some(&dv),
                        Default::default(),
                        Some(&mut reboot),
                    ) {
                        Ok(()) => {
                            println!("DiInstallDevice  : OK (reboot_required={})", reboot.0 != 0);
                            0
                        }
                        Err(e) => {
                            eprintln!("DiInstallDevice  : FAILED {e}");
                            10
                        }
                    }
                }
            }
        };
        let _ = SetupDiDestroyDriverInfoList(set, Some(&di), kind);
        done = true;
    }
    let _ = SetupDiDestroyDeviceInfoList(set);
    rc
}

/// Enumerate an ALREADY BUILT driver list for our node, printing everything that is
/// offered: that list is itself evidence about whether SetupAPI considers
/// cm400.inf installable on this instance. Does NOT destroy the list - the caller
/// needs it alive for DiInstallDevice.
unsafe fn scan_nodes(
    set: HDEVINFO,
    di: &SP_DEVINFO_DATA,
    kind: SETUP_DI_DRIVER_TYPE,
) -> Option<SP_DRVINFO_DATA_V2_W> {
    let mut i = 0u32;
    let mut hit = None;
    loop {
        let mut dv: SP_DRVINFO_DATA_V2_W = std::mem::zeroed();
        dv.cbSize = std::mem::size_of::<SP_DRVINFO_DATA_V2_W>() as u32;
        if SetupDiEnumDriverInfoW(set, Some(di), kind, i, &mut dv).is_err() {
            break;
        }
        i += 1;
        let provider = from_wide(&dv.ProviderName);
        let desc = from_wide(&dv.Description);
        println!(
            "driver node {i:<2} ({}) : provider={provider:?} desc={desc:?} version={:#x}",
            if kind == SPDIT_COMPATDRIVER {
                "compat"
            } else {
                "class"
            },
            dv.DriverVersion
        );
        if provider == provider_filter() {
            hit = Some(dv);
            break;
        }
    }
    hit
}

/// Post-install assertions, read-only, no motor command.
fn verify() {
    println!("--- verification (no SET_CUR is issued here) ---");
    match find_motor_interface() {
        Some((path, via)) => {
            println!("interface      : FOUND via {via}");
            println!("interface path : {path}");
        }
        None => println!("interface      : NOT FOUND under either GUID"),
    }
    let mut ch = MotorChannel::new();
    match ch.probe() {
        Ok(_) => println!("motor transport: reachable (opened, GET_CUR, closed again)"),
        Err(e) => println!("motor transport: NOT reachable ({e:?})"),
    }
}

// D5-4 follow-up, step 2. On this machine the interface GUID that WinUSB actually
// honours was measured at `...\Device Parameters\DeviceInterfaceGUIDs`, while the
// hardware-key root - the target of `HKR,,` inside DDInstall.HW - holds none, even
// for the working libwdi package whose INF line is character-for-character the same
// shape as ours. So this writes the location that is observably effective, through
// the API that confirms the key instead of a guessed registry path.
fn register_guid(guid_text: Option<&str>) {
    // Canonical 8-4-4-4-12 registry form of CM400_MOTOR_INTERFACE_GUID. The older
    // literal here had the tail split into four groups, which WinUSB cannot parse.
    let text = guid_text.unwrap_or("{11A9C0D3-5F2B-4E7A-9C31-0B6D2E4F8A10}");
    println!("instance       : {MOTOR_INSTANCE}");
    println!("target guid    : {text}");
    let rc = unsafe { write_device_parameters(text) };
    verify();
    if rc != 0 {
        std::process::exit(rc);
    }
}

/// Run a helper program and capture its combined output. `pnputil` and `sc` stay CLI
/// on purpose - they are part of Windows itself and their exit codes are what we
/// assert on. Trust verification is NOT here: it went to native APIs (see
/// `native_trust`) so the installer needs nothing beyond the OS.
fn run(program: &str, args: &[&str]) -> (i32, String) {
    match std::process::Command::new(program).args(args).output() {
        Ok(o) => {
            let mut text = String::from_utf8_lossy(&o.stdout).to_string();
            text.push_str(&String::from_utf8_lossy(&o.stderr));
            (o.status.code().unwrap_or(-1), text)
        }
        Err(e) => (-1, format!("cannot run {program}: {e}")),
    }
}

/// Quote-free path sanity check: our flow must never be pointed at an arbitrary INF.
fn path_ok(p: &std::path::Path) -> bool {
    p.exists()
}

/// Report the trust judgements separately, without installing anything, and exit non-zero when a
/// required one fails.
///
/// The exit code used to be 0 even while the line above it said `FAIL`, because this command exists
/// to show all three answers rather than one. A packaging gate read that 0 and shipped a package it
/// could not verify, so the verdict is now carried by the process result as well as the text.
fn verify_package_cli(rest: &[OsString]) {
    // A single-file installer is its own package. With no argument, unpack what this executable carries
    // into a private directory and run the identical judgements over it - the same code path an install
    // would take, so "verified" means the bytes that would actually have been installed.
    // A bundle has to be unpacked somewhere before it can be judged, and that place is closed to everyone
    // except SYSTEM and Administrators on purpose. So verifying a single-file installer is an elevated
    // action; an ordinary user's check is the published SHA-256 of this one file, compared out of band.
    // `--staged` says the directory being pointed at came out of a bundle, so the host is legitimately
    // absent from it. Without the flag the loose rule applies, and a package directory missing its
    // installer is a real defect - the two must not be conflated by always using the smaller set.
    let wants_staged = rest.iter().any(|a| a.to_str() == Some("--staged"));
    let positional: Vec<&OsString> = rest
        .iter()
        .filter(|a| a.to_str() != Some("--staged"))
        .collect();
    let first = positional.first().copied();
    let staged = match first {
        Some(_) => None,
        None => {
            if !elevated_now() {
                eprintln!("cm400-setup: verifying the payload this file carries needs elevation (the staging directory is deliberately writable only by SYSTEM and Administrators).");
                eprintln!("  as an ordinary user, compare this file's SHA-256 with the value published for the release;");
                eprintln!("  to verify a loose package instead, pass its INF: cm400-setup verify-package <path>\\cm400.inf");
                std::process::exit(20);
            }
            match stage_bundle() {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("cm400-setup: {e}");
                    std::process::exit(30);
                }
            }
        }
    };
    let inf = match (&staged, first) {
        (_, Some(p)) => resolve_inf(Some(p)).unwrap_or_else(|e| {
            eprintln!("cm400-setup: {e}");
            std::process::exit(2);
        }),
        (Some(s), None) => {
            let p = s.dir().join("cm400.inf");
            if !path_ok(&p) {
                eprintln!("cm400-setup: the staged package carries no cm400.inf");
                std::process::exit(21);
            }
            println!(" package        : staged from the bundle carried by this executable");
            p
        }
        (None, None) => resolve_inf(None).unwrap_or_else(|e| {
            eprintln!("cm400-setup: {e}");
            std::process::exit(2);
        }),
    };
    let cat = inf.with_extension("cat");
    let i = inf.to_string_lossy().to_string();
    let c = cat.to_string_lossy().to_string();
    println!("inf            : {i}");
    println!("cat            : {c}");
    let verdict = cm400_windows::native_trust::verify_package(&i, &c);
    match &verdict.signature {
        Ok(()) => println!("1 signature+trust: OK  (WinVerifyTrust verdict; passes for our self-signed catalog only while its certificate is in Local Machine\\Trusted Publishers)"),
        Err(e) => println!("1 signature+trust: FAIL - {e}"),
    }
    match &verdict.membership {
        Ok(()) => println!("2 membership     : OK  (INF digest is a member of this catalog)"),
        Err(e) => println!("2 membership     : FAIL - {e}"),
    }
    println!("3 local trust    : see (1); a cryptically valid signature is NOT the same claim as PnP accepting the package - only pnputil /install or a device install proves that.");

    // 4. identity, when the release ships its public certificate beside the INF. A package whose
    //    files agree with each other but not with the pinned publishing identity is refused here,
    //    which is the check that used to be missing entirely.
    let cer = inf.with_extension("cer");
    let mut identity_failed = false;
    if cer.exists() {
        match cm400_windows::trust::package_identity_gate(&inf, &cat, &cer) {
            Ok(report) => println!(
                "4 identity gate    : OK  (verified signer {} is the pinned publishing identity)",
                report.signer.sha256_der
            ),
            Err(errors) => {
                identity_failed = true;
                for e in errors {
                    println!("4 identity gate    : FAIL - {e}");
                }
            }
        }
    } else {
        println!("4 identity gate    : NOT EVALUATED - no cm400.cer next to the INF; a release that must establish trust ships one.");
    }

    // judgement 5: is the digest list itself inside the signed catalog? A manifest that merely
    // travels along can be rewritten together with the file it is supposed to describe.
    let manifest = inf
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("SHA256SUMS.txt");
    let mut manifest_unattested = false;
    if manifest.exists() {
        match cm400_windows::native_trust::file_catalog_membership(&manifest.to_string_lossy(), &c)
        {
            Ok(()) => {
                println!("5 manifest attested: OK  (SHA256SUMS.txt is a member of this catalog)")
            }
            Err(e) => {
                manifest_unattested = true;
                println!("5 manifest attested: FAIL - {e}");
            }
        }
    } else {
        println!("5 manifest attested: NOT PRESENT - no SHA256SUMS.txt beside the package; `install` requires one whenever it must add trust");
    }

    // judgement 6 separates two claims that were previously collapsed into one exit code: the
    // signature's cryptographic validity and this machine's willingness to trust the signer. A build
    // machine that has not enrolled the release identity is in a different situation from a package
    // whose signature does not verify, and a release gate must not be able to treat those alike by
    // waving through "some non-zero code".
    //
    // The identity gate above is what proves the crypto half: it resolves the signer through
    // `CryptMsgGetAndVerifySigner`, which verifies the signature over the content before naming a
    // signer. So an identity gate that passed while WinVerifyTrust failed can only mean one thing -
    // the certificate chain is not enrolled on this machine.
    let signature_trust_only = verdict.signature.is_err()
        && !identity_failed
        && cer.exists()
        && verdict.membership.is_ok();
    if signature_trust_only {
        println!("6 crypto vs trust : signature verified and signer is the pinned identity; only this machine's trust stores lack the certificate (install establishes that at deploy time)");
    }

    // judgement 7: do the manifest's digests match the bytes actually present? A signed catalog can
    // attest that a manifest was signed without the manifest's own claims agreeing with the files beside
    // it - which is exactly the state a tampered payload with a self-consistent bundle index leaves.
    // Without this line a package could pass 1-6 while the daemon about to be run is not the one anyone
    // signed.
    let pkg_dir = inf
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .to_path_buf();
    let required: &[&str] = if staged.is_some() || wants_staged {
        &cm400_windows::artifact_manifest::REQUIRED_STAGED
    } else {
        &cm400_windows::artifact_manifest::REQUIRED_FILES
    };
    println!(
        " layout         : {}",
        if staged.is_some() || wants_staged {
            "bundled payload (the host is the shipped executable, not a package file)"
        } else {
            "loose package (the installer ships beside its package files)"
        }
    );
    let mut digests_wrong = false;
    if pkg_dir.join("SHA256SUMS.txt").exists() {
        match cm400_windows::artifact_manifest::verify_dir_with(&pkg_dir, required) {
            Ok(r) if r.clean() => println!(
                "7 digests match  : OK  ({} file(s) re-hashed and equal to the manifest)",
                r.checked
            ),
            Ok(r) => {
                digests_wrong = true;
                for p in r.problems {
                    println!("7 digests match  : FAIL - {p}");
                }
            }
            Err(e) => {
                digests_wrong = true;
                println!("7 digests match  : FAIL - {e}");
            }
        }
    } else {
        println!("7 digests match  : NOT PRESENT - no SHA256SUMS.txt beside the package, so nothing was re-hashed");
    }

    let code = if identity_failed {
        31
    } else if manifest_unattested || digests_wrong {
        // both mean the package's own integrity claims do not hold: one code, distinct lines above
        30
    } else if signature_trust_only {
        39
    } else {
        verdict.exit_code()
    };
    if code != 0 {
        eprintln!("verify-package: required judgement failed (exit {code})");
    }
    // a staged copy is this run's temporary, not the operator's; remove it and say so if that fails
    if let Some(s) = &staged {
        if let Err(e) = s.remove() {
            eprintln!("cm400-setup: staging cleanup FAILED: {e}");
            eprintln!("  remove this directory by hand: {}", s.dir().display());
        }
    }
    std::process::exit(code);
}

/// Undo the trust this run added, according to the approved stage table - and report what the stores
/// say afterwards rather than what the removal call returned. Some failures deliberately keep the
/// trust (service registered but not running: retry is the useful next action), so "roll everything
/// back" would be wrong as often as it is right.
fn undo_trust(stage: cm400_windows::trust::Stage, written: &[String]) {
    let to_undo = cm400_windows::trust::rollback_stores(stage, written);
    if to_undo.is_empty() {
        if !written.is_empty() && stage.retains_trust() {
            println!("    trust            : retained for retry ({stage:?} failed after the driver was in place); ownership record kept");
        }
        return;
    }
    match cm400_windows::trust::rollback(&to_undo, cm400_windows::trust::PINNED_SHA1_THUMBPRINT) {
        Ok(leftover) if leftover.is_empty() => {
            println!(
                "    trust            : rolled back and confirmed absent - {}",
                to_undo.join(", ")
            );
            // the record must stop claiming we own a certificate that is no longer there, or a later
            // uninstall would delete one that somebody else installed in the meantime
            report_record_sync(cm400_windows::trust::sync_record_to_reality(&clock(), &[]));
        }
        Ok(leftover) => {
            eprintln!(
                "    trust            : ROLLBACK INCOMPLETE, still trusted: {}",
                leftover.join(", ")
            );
            // present, possibly put here by this run, not confirmed removed: recorded as uncertain so a
            // later cleanup says so instead of skipping the store or blaming an innocent certificate
            report_record_sync(cm400_windows::trust::sync_record_to_reality(
                &clock(),
                &leftover,
            ));
        }
        Err(e) => {
            eprintln!("    trust            : rollback could not be performed ({e})");
            let attempted: Vec<String> = to_undo
                .iter()
                .map(|e| e.split('/').next().unwrap_or(e.as_str()).to_string())
                .collect();
            report_record_sync(cm400_windows::trust::sync_record_to_reality(
                &clock(),
                &attempted,
            ));
        }
    }
}

/// Re-apply the ownership record's own boundary and prove it by reading it back.
///
/// Only meaningful when the file exists; a machine with no record has nothing to protect yet, and the
/// absence is handled by the cleanup decision, not here.
fn enforce_ownership_boundary() -> Result<(), String> {
    let path = cm400_windows::trust_ownership::path();
    if std::fs::metadata(&path).is_err() {
        return Ok(());
    }
    cm400_windows::trust_ownership::enforce_dacl(&path)
}

fn clock() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Say what the ownership record now says, and say it loudly when it could not be written: an install
/// that cannot record its own trust state has to leave the next cleanup in refuse mode, not in a
/// guessed one.
fn report_record_sync(result: Result<cm400_windows::trust_ownership::Record, Vec<String>>) {
    match result {
        Ok(record) => {
            for store in cm400_windows::cert_cleanup::STORES {
                if let Some(state) = record.stores.get(store) {
                    println!("      ownership after rollback {store:<9}= {state:?}");
                }
            }
        }
        Err(errors) => {
            for e in errors {
                eprintln!("      ownership record: {e}");
            }
            eprintln!("      automatic certificate cleanup must be refused until the ownership state can be recorded");
        }
    }
}

/// Deployment protection, measured against a real directory rather than asserted in a comment.
/// The directory under test is a fresh one in `TEMP`; it is handed the same DACL the deploy directory
/// gets, so the property being checked is the plan's effect, not a description of it.
#[cfg(test)]
mod deploy_protection_tests {
    use super::*;

    /// The branch above only exercises whatever this machine happens to carry, so this one manufactures a
    /// foreign explicit write ACE and runs everywhere. An explicit grant to the account running the test
    /// names a trustee the plan does not mention, and `/grant:r` cannot replace it. What must hold either
    /// way: the plan does not report a hardened directory while that trustee can still write it, and it
    /// does not lose the two administrative accesses it exists to establish. Whether the foreign entry is
    /// taken away or the directory is refused depends on the machine, so both outcomes are asserted.
    /// Rewritten after cloud CI, where a runner's own temp named its installing admin and a refuse-only
    /// plan made the installer unable to stage on that machine while still reporting the safe verdict.
    #[test]
    fn a_foreign_explicit_write_ace_is_cleared_or_the_plan_refuses() {
        let dir = std::env::temp_dir().join(format!("cm400-deploy-foreign-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("cm400d.exe"), b"image").unwrap();

        let (code, who) = run("whoami.exe", &[]);
        assert_eq!(
            code, 0,
            "cannot determine the account running this test: {who}"
        );
        let account = who.lines().next().unwrap_or("").trim().to_string();
        assert!(!account.is_empty(), "whoami produced no account name");

        let (code, out) = run(
            "icacls.exe",
            &[
                &dir.to_string_lossy(),
                "/grant",
                &format!("{account}:(OI)(CI)F"),
            ],
        );
        assert_eq!(code, 0, "the foreign ACE could not be created: {out}");

        // if the rule cannot even see the ACE this test just added, the rest would prove nothing
        let before = icacls_report(&dir).expect("the DACL must be readable");
        let stray =
            cm400_windows::security::unexpected_write_grants(&before, &DEPLOY_ALLOWED_WRITERS);
        assert!(
            !stray.is_empty(),
            "the manufactured ACE is invisible to the boundary rule, so this test would prove nothing:\n{before}"
        );

        // The property is that the plan never leaves the directory open to a writer it does not name: it
        // takes that access away, or it refuses. Which one happens depends on whether this machine lets the
        // entry be removed, so both outcomes are asserted on their own terms instead of the test betting on
        // one machine's ACL. Cloud CI is why: a runner's own temp left its installing admin named there, and
        // a plan that could only refuse was safe but unable to install anything.
        let outcome = apply_and_verify(&dir, deploy_dir_grants(&dir));
        let after = icacls_report(&dir).expect("the DACL must be readable after the plan");
        let stray_after =
            cm400_windows::security::unexpected_write_grants(&after, &DEPLOY_ALLOWED_WRITERS);
        match outcome {
            Ok(()) => assert!(
                stray_after.is_empty(),
                "the plan called this directory protected while a writer it does not name still had access:\n{after}"
            ),
            Err(err) => {
                assert!(
                    err.contains("unexpected write principals") || err.contains("cannot take write access away"),
                    "refused for a reason other than the foreign writer: {err}"
                );
                assert!(
                    !stray_after.is_empty(),
                    "the plan refused, yet the boundary now reads as acceptable - refusal and check disagree:\n{after}"
                );
            }
        }
        // and whichever way it went, the access the plan exists to establish is still there
        assert!(
            cm400_windows::security::principal_can_write(&after, "NT AUTHORITY\\SYSTEM", false),
            "SYSTEM lost the access the plan grants:\n{after}"
        );
        assert!(
            cm400_windows::security::principal_can_write(&after, "BUILTIN\\Administrators", false),
            "Administrators lost the access the plan grants:\n{after}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_deploy_directory_plan_leaves_ordinary_users_no_way_to_replace_the_image() {
        let dir = std::env::temp_dir().join(format!("cm400-deploy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // lay the image down first, the way an elevated installer does, then close the boundary
        let file = dir.join("cm400d.exe");
        std::fs::write(&file, b"image").unwrap();

        // What this machine granted here, recorded before anything is asked of it. An unreadable DACL is
        // a failure of this test rather than evidence that nothing is anomalous - "I cannot tell who can
        // write the deployment directory" must never be read as "nobody can". The starting principals
        // are not the branch key, because an inherited foreign ACE is exactly what the plan's
        // `/inheritance:r` clears while an explicit one for a trustee the plan does not name survives;
        // only the second can make the plan fail, and that is where the two paths are told apart.
        let start =
            icacls_report(&dir).expect("the starting DACL of the test directory must be readable");
        let foreign_at_start =
            cm400_windows::security::unexpected_write_grants(&start, &DEPLOY_ALLOWED_WRITERS);
        eprintln!(
            "starting DACL: {} foreign write principal(s){}",
            foreign_at_start.len(),
            if foreign_at_start.is_empty() {
                String::new()
            } else {
                format!(": {}", foreign_at_start.join("; "))
            }
        );

        let unprotected =
            icacls_report(&dir).expect("the DACL of a fresh temp directory is readable");
        // Build the bad state explicitly instead of hoping the machine's defaults are bad: a directory
        // that lets ordinary users create or append children is precisely what must not hold a service
        // image, and the plan's effect can only be measured against it.
        run(
            "icacls.exe",
            &[
                &dir.to_string_lossy(),
                "/grant:r",
                "*S-1-5-32-545:(OI)(CI)(WD,AD,WEA)",
            ],
        );
        let permissive = icacls_report(&dir).unwrap();
        assert!(
            cm400_windows::security::standard_user_can_perturb(&permissive),
            "the baseline should now show child-create rights for Users; it read:\n{permissive}\n(starting point was:\n{unprotected})"
        );
        // and in that state an ordinary user really can drop a file next to the image
        std::fs::write(dir.join("planted-before.exe"), b"x")
            .expect("with the permissive baseline, creating a file must work");

        match apply_and_verify(&dir, deploy_dir_grants(&dir)) {
            Ok(()) => {}
            Err(err) => {
                // The plan could not establish the boundary because some principal the plan does not
                // name kept an explicit write ACE. That refusal is the security property, so assert it
                // rather than letting the outcome depend on the machine - and assert it is a refusal,
                // not a success and not some unrelated failure that would hide a real defect.
                eprintln!("branch: the plan refused this directory - asserting the refusal");
                assert!(
                    err.contains("unexpected write principals"),
                    "the plan failed for a reason other than a surviving foreign writer: {err}"
                );
                // The refusal cannot be mistaken for a completed deployment: reading the boundary back
                // still reports a foreign writer, so no caller may record this path as protected. (The
                // grants that did run are not being asserted away here - what is asserted is that the
                // result is still unacceptable, which is the property that matters to the installer.)
                let after_refusal =
                    icacls_report(&dir).expect("the DACL must still be readable after the refusal");
                assert!(
                    !cm400_windows::security::unexpected_write_grants(
                        &after_refusal,
                        &DEPLOY_ALLOWED_WRITERS
                    )
                    .is_empty(),
                    "the refusal left a DACL the boundary would accept:\n{after_refusal}"
                );
                // and nothing beyond what this test itself wrote appeared in the directory
                let mut entries: Vec<String> = std::fs::read_dir(&dir)
                    .expect("the directory remains listable")
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .collect();
                entries.sort();
                assert_eq!(
                    entries,
                    vec!["cm400d.exe".to_string(), "planted-before.exe".to_string()],
                    "the refused plan must not have staged anything else"
                );
                let _ = std::fs::remove_dir_all(&dir);
                return;
            }
        }
        eprintln!("branch: the plan applied - asserting the boundary it establishes");
        let after = icacls_report(&dir).unwrap();
        assert!(
            !cm400_windows::security::standard_user_can_perturb(&after),
            "after the plan, ordinary users must not create or replace entries here:\n{after}"
        );
        assert!(
            cm400_windows::security::principal_can_write(&after, "NT AUTHORITY\\SYSTEM", false),
            "SYSTEM must still be able to manage it"
        );
        apply_and_verify(&file, daemon_grants(&file)).expect("the file plan must be applicable");
        let file_report = icacls_report(&file).unwrap();
        assert!(
            !cm400_windows::security::standard_user_can_perturb(&file_report),
            "a user-writable service image is local privilege escalation to LocalService:\n{file_report}"
        );
        assert!(
            cm400_windows::security::principal_can_write(
                &file_report,
                "BUILTIN\\Administrators",
                true
            ),
            "administrators must still be able to replace it on upgrade"
        );

        // The property in question, demonstrated by attempting it from this process - but whether this
        // process IS an ordinary user is a fact about the account running the test, not about the boundary.
        // Measured in cloud CI: a runner's test process holds an enabled Administrators group, which is
        // exactly the principal the plan is supposed to grant, so "my write must be refused" was asserting
        // one machine's token. Both cases are checked; neither is skipped.
        if elevated_now() {
            eprintln!(
                "branch: this process is an enabled administrator - the principal the plan grants"
            );
            // so the refusal cannot be demonstrated from here, and the DACL is asserted instead: the two
            // administrators hold the access the plan intends and nobody else holds any
            assert!(
                cm400_windows::security::principal_can_write(&file_report, "BUILTIN\\Administrators", true),
                "an enabled administrator must be able to write the image it is granted:\n{file_report}"
            );
            let stray = cm400_windows::security::unexpected_write_grants(
                &file_report,
                &DEPLOY_ALLOWED_WRITERS,
            );
            assert!(
                stray.is_empty(),
                "the service image names a writer beyond the two administrators:\n  {}",
                stray.join("\n  ")
            );
            // the directory keeps the same boundary, or the image could be swapped by replacing its parent
            let dir_report = icacls_report(&dir).unwrap();
            let stray_dir = cm400_windows::security::unexpected_write_grants(
                &dir_report,
                &DEPLOY_ALLOWED_WRITERS,
            );
            assert!(
                stray_dir.is_empty(),
                "the directory holding the image names a writer beyond the two administrators:\n  {}",
                stray_dir.join("\n  ")
            );
        } else {
            // an un-elevated process is exactly the principal the boundary has to refuse, so a successful
            // write here would mean the service image can be replaced by whoever the service then runs
            let planted = std::fs::write(dir.join("trojan.exe"), b"x").err();
            let overwritten = std::fs::write(&file, b"replaced").err();
            assert!(
                planted.is_some() && overwritten.is_some(),
                "creating {} or replacing {} must be refused to an ordinary user: planted={planted:?}, overwrite={overwritten:?}",
                dir.display(),
                file.display()
            );
            // the file that was already there is beyond this principal's reach in both directions: not
            // writable, and not even readable, because the DACL names only the two administrators and the
            // service account. Asserting the content from here would require an access the boundary is
            // designed to refuse, so the refusal itself is what is checked.
            let peek = std::fs::read(&file).err();
            assert!(
                peek.is_some(),
                "an ordinary user must not be able to read the service image either: {peek:?}"
            );
        }
        // who may write the image: the two administrators, and nobody who runs it. A LocalService that
        // could write its own binary turns any daemon compromise into a persistent one.
        for (trustee, want) in [
            ("NT AUTHORITY\\SYSTEM", true),
            ("BUILTIN\\Administrators", true),
            ("NT AUTHORITY\\LOCAL SERVICE", false),
            ("BUILTIN\\Users", false),
        ] {
            assert_eq!(
                cm400_windows::security::principal_can_write(&file_report, trustee, true),
                want,
                "{trustee} write right on the service image should be {want}:\n{file_report}"
            );
        }
        assert!(
            cm400_windows::security::principal_can_read(
                &file_report,
                "NT AUTHORITY\\LOCAL SERVICE",
                true
            ),
            "the service account still has to be able to load its own image:\n{file_report}"
        );
        // put the tree back the way it was found, or cleanup cannot remove it
        run(
            "icacls.exe",
            &[&dir.to_string_lossy(), "/reset", "/T", "/Q"],
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The upgrade decision, tested without touching a service control manager.
#[cfg(test)]
mod service_plan_tests {
    use super::*;

    const EXE: &str = r"C:\Program Files\CM400\bin\cm400d.exe";
    const WANT: &str = "\"C:\\Program Files\\CM400\\bin\\cm400d.exe\" --service";
    const LS: &str = "NT AUTHORITY\\LocalService";

    fn plan(current: &str, start: &str, account: &str) -> ServicePlan {
        plan_service(true, current, WANT, start, account)
    }

    #[test]
    fn an_unregistered_service_is_created_rather_than_reused() {
        assert_eq!(plan_service(false, "", WANT, "", ""), ServicePlan::Create);
    }

    /// The command line handed to `sc config` has to be exactly the one we intend the SCM to store.
    /// Asserting only the argument count hid a re-quoting bug that appended a stray `"` to the value.
    #[test]
    fn the_bin_path_argument_is_the_command_line_verbatim() {
        match plan(r"E:\old\cm400d.exe --service", "2 AUTO_START", LS) {
            ServicePlan::Reuse { config } => {
                assert_eq!(
                    config,
                    vec!["binPath=".to_string(), WANT.to_string()],
                    "key, then the intended command line unchanged"
                );
                // the value must be valid on its own: a path with spaces, quoted, and one argument
                let (exe, args) =
                    parse_command_line(&config[1]).expect("the emitted value must parse");
                assert_eq!(
                    exe,
                    EXE.to_ascii_lowercase(),
                    "quoted executable path survives"
                );
                assert_eq!(args, "--service", "the flag is still exactly one flag");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_stray_quote_is_not_accepted_as_a_matching_command_line() {
        // this is the shape the buggy construction produced; the comparison must reject it
        let broken = "\"C:\\Program Files\\CM400\\bin\\cm400d.exe\" --service\"";
        assert!(
            !same_command_line(broken, WANT),
            "a trailing quote is a different command line"
        );
        assert!(
            parse_command_line(broken).is_none(),
            "unbalanced quoting is malformed, not equal"
        );
        // and a registered value in that shape triggers a repair rather than a silent reuse
        match plan(broken, "2 AUTO_START", LS) {
            ServicePlan::Reuse { config } => {
                assert_eq!(config.len(), 2, "binPath must be rewritten: {config:?}")
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_existing_service_that_already_matches_needs_no_change() {
        assert_eq!(
            plan(WANT, "2 AUTO_START", LS),
            ServicePlan::Reuse { config: Vec::new() }
        );
        assert_eq!(
            plan(&WANT.to_uppercase(), "2 auto_start", &LS.to_uppercase()),
            ServicePlan::Reuse { config: Vec::new() }
        );
        // a path containing spaces and no quotes is a different command line, not a spelling variant:
        // the SCM would exec `C:\Program`, so it has to be rewritten rather than accepted
        match plan(
            r"C:\Program Files\CM400\bin\cm400d.exe --service",
            "2 AUTO_START",
            LS,
        ) {
            ServicePlan::Reuse { config } => {
                assert_eq!(
                    config,
                    vec!["binPath=".to_string(), WANT.to_string()],
                    "an unquoted path with spaces is not the image we deploy: {config:?}"
                );
            }
            other => panic!("{other:?}"),
        }
        // an unparseable registration is never "equal" to anything, so it gets repaired too
        match plan("", "2 AUTO_START", LS) {
            ServicePlan::Reuse { config } => assert_eq!(config.len(), 2, "{config:?}"),
            other => panic!("{other:?}"),
        }
    }

    /// The account is part of the plan. Reusing a service that runs as LocalSystem would silently
    /// invalidate every ACL assumption the design is built on, so a matching image and start type are
    /// not sufficient conditions for reuse.
    #[test]
    fn a_foreign_account_is_repaired_even_when_image_and_start_type_match() {
        for account in [
            "NT AUTHORITY\\SYSTEM",
            "LocalSystem",
            r".\Administrator",
            "",
        ] {
            match plan(WANT, "2 AUTO_START", account) {
                ServicePlan::Reuse { config } => {
                    assert_eq!(
                        config,
                        vec!["obj=".to_string(), SERVICE_ACCOUNT.to_string()],
                        "account {account:?} must be corrected, and nothing else"
                    );
                }
                other => panic!("{account:?} -> {other:?}"),
            }
        }
    }

    #[test]
    fn image_start_type_and_account_changes_are_combined_in_one_config_call() {
        match plan(
            r"D:\stale\cm400d.exe --service",
            "3 DEMAND_START",
            "NT AUTHORITY\\SYSTEM",
        ) {
            ServicePlan::Reuse { config } => {
                assert_eq!(config.len(), 6, "three key/value pairs: {config:?}");
                assert_eq!(config[0], "binPath=");
                assert_eq!(config[1], WANT);
                assert_eq!(config[2], "start=");
                assert_eq!(config[3], "auto");
                assert_eq!(config[4], "obj=");
                assert_eq!(config[5], LS);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_scm_field_shapes_are_parsed_as_the_scm_prints_them() {
        let qc = "SERVICE_NAME: CM400Driver\r\n    TYPE              : 16 SERVICE_WIN32_OWN_PROCESS\r\n    BINARY_PATH_NAME   : \"C:\\Program Files\\CM400\\bin\\cm400d.exe\" --service\r\n    START_TYPE         : 2 AUTO_START  (AUTOMATIC)\r\n    SERVICE_START_NAME : NT AUTHORITY\\LocalService\r\n";
        assert_eq!(
            service_field(qc, "BINARY_PATH_NAME"),
            "\"C:\\Program Files\\CM400\\bin\\cm400d.exe\" --service"
        );
        assert!(start_type_is_auto(&service_field(qc, "START_TYPE")));
        assert!(account_is_local_service(&service_field(
            qc,
            "SERVICE_START_NAME"
        )));
        assert!(same_command_line(
            &service_field(qc, "BINARY_PATH_NAME"),
            WANT
        ));
        assert!(!account_is_local_service("NT AUTHORITY\\SYSTEM"));
        assert!(!start_type_is_auto("3 DEMAND_START  (MANUAL)"));
    }
}

/// The interaction the real uninstall refused over: two ACL policies applied to the same tree. Each
/// passes on its own, so only a test that runs one after the other can show the composition.
#[cfg(test)]
mod acl_interaction_tests {
    use super::*;

    fn ls_can_write(path: &std::path::Path) -> Option<bool> {
        let report = icacls_report(path).ok()?;
        Some(cm400_windows::security::principal_can_write(
            &report,
            "NT AUTHORITY\\LOCAL SERVICE",
            true,
        ))
    }

    #[test]
    fn data_tree_hardening_widens_the_record_and_the_boundary_check_puts_it_back() {
        use cm400_windows::trust_ownership::{self, Provenance, Record};

        let root = std::env::temp_dir().join(format!("cm400-aclmix-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for dir in cm400_windows::security::data_tree_dirs(&root.to_string_lossy()) {
            std::fs::create_dir_all(dir).unwrap();
        }
        let record = root.join("state").join("trust-ownership.kv");
        let mut rec = Record::new(cm400_windows::trust::PINNED_SHA256_DER, "1");
        for store in cm400_windows::cert_cleanup::STORES {
            rec.stores
                .insert(store.to_string(), Provenance::AddedByInstall);
        }
        std::fs::write(&record, rec.render()).unwrap();

        // step 1: the record gets its own narrow boundary, as the installer publishes it
        trust_ownership::enforce_dacl(&record).expect("the boundary is applicable");
        let after_publish = ls_can_write(&record).expect("the DACL is readable to its owner");
        assert!(
            !after_publish,
            "the record must not be writable by LocalService"
        );

        // step 2: the data-tree pass runs afterwards, exactly as `harden_data_acl` orders it
        for step in cm400_windows::security::data_tree_plan(&root.to_string_lossy()) {
            let refs: Vec<&str> = step.iter().map(String::as_str).collect();
            run("icacls.exe", &refs);
        }
        assert_eq!(
            ls_can_write(&record),
            Some(true),
            "this is the conflict the real uninstall hit: the tree pass resets the record to inherit"
        );

        // step 3: the enforcement the installer now performs at the end of hardening
        cm400_windows::trust_ownership::enforce_dacl(&record)
            .expect("the boundary can be put back");
        assert_eq!(
            ls_can_write(&record),
            Some(false),
            "and verified by reading it back"
        );

        // hand the tree back to the defaults before deleting it: after the plan, only SYSTEM and the
        // service identities may create or remove entries inside, and this process is none of those
        for dir in cm400_windows::security::data_tree_dirs(&root.to_string_lossy()) {
            run("icacls.exe", &[&dir, "/reset", "/T", "/Q"]);
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn only_our_own_widening_may_be_healed() {
        use cm400_windows::security;
        use cm400_windows::trust_ownership::{repair_refusal, Provenance, Record};

        let mut rec = Record::new(cm400_windows::trust::PINNED_SHA256_DER, "1");
        for store in cm400_windows::cert_cleanup::STORES {
            rec.stores
                .insert(store.to_string(), Provenance::AddedByInstall);
        }
        let content = Ok(Some(rec.clone()));
        let observed = vec![
            ("Root".to_string(), true),
            ("TrustedPublisher".to_string(), true),
        ];

        // the exact shape our tree reset leaves behind: everything inherited, tree trustees only
        let ours = "C:\\x: BUILTIN\\Users:(I)(RX)\r\n     NT AUTHORITY\\LOCAL SERVICE:(I)(M)\r\n     BUILTIN\\Administrators:(I)(F)\r\n     NT AUTHORITY\\SYSTEM:(I)(F)\r\n";
        assert_eq!(
            security::ace_groups("(I)(RX)"),
            vec![vec!["I".to_string()], vec!["RX".to_string()]],
            "one group per parenthesised cluster, which is what the shape check below reads"
        );
        assert!(
            repair_refusal(&content, Some(ours), &observed).is_none(),
            "our own hardening is the one thing repair may act on"
        );

        // one explicit foreign grant: someone else touched this file, and repairing would be guessing
        let foreign = "C:\\x: MYCORP\\Bob:(F)\r\n     BUILTIN\\Users:(I)(RX)\r\n     NT AUTHORITY\\LOCAL SERVICE:(I)(M)\r\n     BUILTIN\\Administrators:(I)(F)\r\n     NT AUTHORITY\\SYSTEM:(I)(F)\r\n";
        let why = repair_refusal(&content, Some(foreign), &observed)
            .expect("a foreign explicit ACE must not be healed");
        assert!(why.contains("not the shape"), "{why}");

        // a deny ACE for a tree trustee is also not our shape
        let denied = "C:\\x: BUILTIN\\Users:(I)(DENY)(RX)\r\n     NT AUTHORITY\\LOCAL SERVICE:(I)(M)\r\n     BUILTIN\\Administrators:(I)(F)\r\n     NT AUTHORITY\\SYSTEM:(I)(F)\r\n";
        assert!(
            repair_refusal(&content, Some(denied), &observed).is_some(),
            "deny is not our reset"
        );

        // content that is not the pinned identity is never repairable into trust
        let corrupt = Err("duplicate entry for store Root".to_string());
        assert!(repair_refusal(&corrupt, Some(ours), &observed).is_some());

        // and a record that disagrees with the stores is refused even in the right ACL shape
        let gone = vec![
            ("Root".to_string(), false),
            ("TrustedPublisher".to_string(), true),
        ];
        let why = repair_refusal(&content, Some(ours), &gone)
            .expect("record and machine disagreeing is not a permission question");
        assert!(why.contains("Root"), "{why}");
    }
}

/// D5: the product install flow.
fn install_flow(rest: &[OsString]) {
    // The package is resolved in two steps on purpose: an explicit INF from the operator is honoured
    // immediately, while the default case waits until the bundle this executable carries has been staged
    // into a private directory and digested. Resolving it earlier would point every gate at a directory
    // whose bytes nobody had verified yet.
    let mut inf: PathBuf = match rest.first() {
        Some(p) => resolve_inf(Some(p)).unwrap_or_else(|e| {
            eprintln!("preflight FAIL: {e}");
            std::process::exit(2)
        }),
        None => PathBuf::new(),
    };

    // Elevation check. `net session` is NOT a valid probe: it needs the Server service
    // (LanmanServer) to be running and fails even in an elevated process (measured).
    // Ask instead for exactly the right this installer needs on the SCM, which also
    // proves the service registration step can work.
    println!("[1] preflight");
    let elevated = windows_service::service_manager::ServiceManager::local_computer(
        None::<&str>,
        windows_service::service_manager::ServiceManagerAccess::CONNECT
            | windows_service::service_manager::ServiceManagerAccess::CREATE_SERVICE,
    )
    .is_ok();
    println!(
        "    elevated         : {}",
        if elevated { "yes" } else { "NO (needs admin)" }
    );
    if !elevated {
        eprintln!("    ABORT: driver installation requires elevation");
        std::process::exit(20);
    }
    // [1a] staging happens only in the elevated context, because the directory is deliberately closed to
    // everyone but SYSTEM and Administrators - a run that is not elevated could not write into it, let
    // alone keep another process out of it. `stage_bundle` sweeps first, so leftovers from an aborted run
    // are cleared under the same proofs before this run puts anything down.
    let staged = match stage_bundle() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("    ABORT: {e}");
            eprintln!(" nothing was changed by this run.");
            std::process::exit(30);
        }
    };
    if inf.as_os_str().is_empty() {
        inf = match &staged {
            Some(s) => {
                let p = s.dir().join("cm400.inf");
                if !path_ok(&p) {
                    eprintln!("    ABORT: the staged package carries no cm400.inf");
                    eprintln!(" nothing was changed by this run.");
                    bail(&staged, 21);
                }
                println!("    package        : staged from the bundle carried by this executable");
                p
            }
            None => resolve_inf(None).unwrap_or_else(|e| {
                eprintln!("preflight FAIL: {e}");
                bail(&staged, 2)
            }),
        };
    }
    let cat = inf.with_extension("cat");
    if !path_ok(&inf) || !path_ok(&cat) {
        eprintln!("    ABORT: missing INF or catalog next to it");
        bail(&staged, 21);
    }
    let cer = inf.with_extension("cer");
    let pkg_dir = inf.parent().map(|p| p.to_path_buf()).unwrap_or_default();

    // [1b] whole-package integrity. Verifying only the executable would leave the INF, the catalog
    // and the certificate beside it free to be swapped, and the trust established below would then
    // cover a package nobody checked. A missing manifest is refused whenever a `.cer` is present,
    // because that combination is the release flow that establishes trust.
    if pkg_dir.join("SHA256SUMS.txt").exists() {
        // a staged bundle carries no copy of the host, so the coverage set is the staged one; a loose
        // package still has to speak about the installer file shipped beside its INF
        let required: &[&str] = if staged.is_some() {
            &cm400_windows::artifact_manifest::REQUIRED_STAGED
        } else {
            &cm400_windows::artifact_manifest::REQUIRED_FILES
        };
        match cm400_windows::artifact_manifest::verify_dir_with(&pkg_dir, required) {
            Ok(report) if report.clean() => {
                println!(
                    "    package manifest : {} file(s) verified against SHA256SUMS.txt",
                    report.checked
                )
            }
            Ok(report) => {
                for problem in &report.problems {
                    println!("      manifest problem: {problem}");
                }
                eprintln!("    ABORT: the package does not match its own manifest");
                bail(&staged, 30);
            }
            Err(e) => {
                eprintln!("    ABORT: {e}");
                bail(&staged, 30);
            }
        }
    } else if path_ok(&cer) {
        eprintln!("    ABORT: cm400.cer is present but SHA256SUMS.txt is not; a release that establishes trust ships both");
        bail(&staged, 30);
    } else {
        println!("    package manifest : none beside the package (legacy layout); no trust can be established here");
    }

    // [1c] identity. `catalog_signer` resolves the CMS SignerInfo and verifies the signature, so the
    // comparison below is against whoever actually signed - not against a certificate that merely
    // appears in the message, nor against the shipped `.cer` alone.
    if !path_ok(&cer) {
        eprintln!("    ABORT: cm400.cer is required: the pinned publishing identity must be compared with the certificate that signed this catalog");
        bail(&staged, 21);
    }
    if let Err(e) = cm400_windows::native_trust::catalog_signer(&cat.to_string_lossy()) {
        eprintln!("    ABORT: cannot determine who signed the catalog: {e}");
        bail(&staged, 29);
    }
    if let Err(errors) = cm400_windows::trust::package_identity_gate(&inf, &cat, &cer) {
        for e in errors {
            eprintln!("      identity: {e}");
        }
        eprintln!("    ABORT: this package is not the release identity this installer was built to accept");
        bail(&staged, 31);
    }
    println!("    identity         : OK (verified signer and shipped certificate are the pinned identity)");

    // [1d] trust, with ownership decided and persisted first. Per-store on purpose: `Root` may
    // already hold the certificate while `TrustedPublisher` does not, and one merged verdict would
    // either delete somebody else's entry or leave ours behind.
    let states = match cm400_windows::trust::snapshot_states() {
        Ok(s) => s,
        Err(errors) => {
            for e in errors {
                eprintln!("      trust state: {e}");
            }
            eprintln!("    ABORT: a trust store that cannot be enumerated is not a store we may write into");
            bail(&staged, 32);
        }
    };
    for s in &states {
        println!(
            "    trust in {:<17}: {}",
            s.store,
            if s.present_before {
                "already present; NOT recorded as ours"
            } else {
                "absent; this install will add it"
            }
        );
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    // A record left with widened permissions by this product's own data-tree hardening would otherwise
    // block both directions forever: the install could not trust it, and the uninstall could not clean
    // up by it. Healing is evidence-gated (see `heal_ownership_record`); a refusal is reported and the
    // strict rule below still applies - an unreadable record means nothing is trusted.
    match cm400_windows::trust::heal_ownership_record() {
        Ok(None) => {}
        Ok(Some(cm400_windows::trust_ownership::Repair::Repaired)) => {
            println!("    ownership record : permissions restored to the documented boundary and verified by re-read");
        }
        Ok(Some(cm400_windows::trust_ownership::Repair::Refused(why))) => {
            eprintln!(
                "    ownership record : exists, is not believable, and may not be repaired: {why}"
            );
        }
        // `heal_ownership_record` filters this out at runtime; the type cannot prove it, so the arm
        // exists rather than a catch-all that would also swallow a future variant
        Ok(Some(cm400_windows::trust_ownership::Repair::NotNeeded)) => {}
        Err(errors) => {
            for e in errors {
                eprintln!("      trust state: {e}");
            }
        }
    }
    // Always persisted, even when both stores already trust the certificate. The record - not the
    // store contents - is what a later uninstall relies on, and "no record" is read as the approved
    // `unknown_legacy` case which permits deleting a certificate that predates this product.
    let written: Vec<String> = match cm400_windows::trust::establish_with_ownership(&cer, &now) {
        Ok((established, record)) => {
            println!("    {}", established.describe());
            for store in cm400_windows::cert_cleanup::STORES {
                if let Some(state) = record.stores.get(store) {
                    println!("      ownership {store:<17}= {state:?}");
                }
            }
            established.written().to_vec()
        }
        Err(errors) => {
            for e in errors {
                eprintln!("      trust: {e}");
            }
            eprintln!("    ABORT: local trust for the release identity could not be established and recorded");
            bail(&staged, 33);
        }
    };

    // [1e] the package must now pass the two native checks, as typed results. Reaching here with the
    // identity verified but the signature untrusted is the case the trust write above exists for.
    let verdict =
        cm400_windows::native_trust::verify_package(&inf.to_string_lossy(), &cat.to_string_lossy());
    println!(
        "    catalog signed : {}",
        if verdict.signature.is_ok() {
            "OK"
        } else {
            "FAILED"
        }
    );
    println!(
        "    INF is a member: {}",
        if verdict.membership.is_ok() {
            "OK"
        } else {
            "FAILED"
        }
    );
    if let Err(e) = &verdict.signature {
        eprintln!("      signature/trust error: {e}");
    }
    if let Err(e) = &verdict.membership {
        eprintln!("      membership error     : {e}");
    }
    if !verdict.accepted() {
        undo_trust(cm400_windows::trust::Stage::PackageVerify, &written);
        eprintln!("    ABORT: native trust verification did not pass even after establishing the release identity");
        bail(&staged, 34);
    }

    // [1f] the digest list itself has to be attested. `SHA256SUMS.txt` sitting in the same folder proves
    // nothing, because whoever replaces a file also writes the line describing it; being a member of
    // the catalog whose signer we just matched against the pinned identity is what makes it evidence.
    let manifest = pkg_dir.join("SHA256SUMS.txt");
    if manifest.exists() {
        if let Err(e) = cm400_windows::native_trust::file_catalog_membership(
            &manifest.to_string_lossy(),
            &cat.to_string_lossy(),
        ) {
            undo_trust(cm400_windows::trust::Stage::PackageVerify, &written);
            eprintln!("    ABORT: SHA256SUMS.txt is not a member of the signed catalog, so the package contents are unattested: {e}");
            bail(&staged, 30);
        }
        println!("    manifest signed : OK (SHA256SUMS.txt is a member of the verified catalog)");
    }

    // 2. quiesce: the daemon must be stopped (it is the only other motor writer) and the
    //    lens must be down. A camera app is the user's, so we only report it.
    println!("[2] quiesce");
    let (_, o) = run("sc.exe", &["query", "CM400Driver"]);
    if o.contains("RUNNING") {
        let _ = run("sc.exe", &["stop", "CM400Driver"]);
        println!("    cm400d           : stop requested");
        std::thread::sleep(std::time::Duration::from_secs(4));
    } else {
        println!("    cm400d           : already stopped");
    }

    // 3. stage + bind, choosing the node by OUR provider only.
    println!("[3] stage + install device");
    let (sc, so) = run("pnputil.exe", &["/add-driver", inf.to_str().unwrap_or("")]);
    let published = {
        let t = so.as_str();
        let i = t.find("oem");
        match i {
            Some(i) => {
                let j = t[i..].find(".inf").map(|j| i + j + 4).unwrap_or(t.len());
                t[i..j].to_string()
            }
            None => String::new(),
        }
    };
    println!("    add-driver exit  : {sc}  published: {published}");
    if published.is_empty() {
        undo_trust(cm400_windows::trust::Stage::DriverStage, &written);
        eprintln!("    ABORT: staging produced no package name");
        bail(&staged, 23);
    }
    let code = unsafe { run_install_device(MOTOR_INSTANCE, false) };
    println!("    install rc       : {code}");

    // 4/5. VERIFY BY OUTCOME, not by the API's success. An interface under our own GUID
    // is the only thing that makes this a pass; nothing here falls back to a third-party
    // package, because a clean customer machine does not have one.
    println!("[4] verification (outcome, not return code)");
    std::thread::sleep(std::time::Duration::from_secs(20));
    let (_, dp) = run(
        "reg.exe",
        &[
            "query",
            &format!("HKLM\\SYSTEM\\CurrentControlSet\\Enum\\{MOTOR_INSTANCE}\\Device Parameters"),
            "/v",
            "DeviceInterfaceGUIDs",
        ],
    );
    println!(
        "    Device Parameters: {}",
        dp.lines()
            .find(|l| l.contains("DeviceInterfaceGUIDs"))
            .unwrap_or("(value not present)")
            .trim()
    );
    let found = find_motor_interface();
    match &found {
        Some((path, via)) => {
            println!("    interface        : FOUND via {via}\n                     {path}")
        }
        None => println!("    interface        : NOT FOUND under either GUID"),
    }
    // Match on the prefix: the label is "production INF (install/cm400.inf)", and an
    // exact-match comparison here made a working install report "interface does not
    // exist" and exit 24 - measured.
    let ours_ok = found
        .as_ref()
        .map(|(_, via)| via.starts_with("production INF"))
        .unwrap_or(false);
    if !ours_ok {
        undo_trust(cm400_windows::trust::Stage::InterfaceCheck, &written);
        eprintln!("[5] INSTALL NOT ACCEPTED: our own interface does not exist.");
        eprintln!("    The driver package is staged and the device may even be bound to it; that");
        eprintln!("    is NOT success. Report this as a failure and leave the machine as it is -");
        eprintln!("    no third-party fallback package is created or assumed here.");
        bail(&staged, 24);
    }
    println!("[5] ACCEPTED: interface enumerated through our own GUID.");
    // The image the service will run, in a directory the file's own DACL can protect. Registering
    // `cm400d.exe` from whatever folder the user unpacked would make that folder's write permission
    // equal to code-execution permission as LocalService, and no signature over the driver package
    // covers it.
    let daemon = match deploy_daemon(&daemon_source()) {
        Ok(path) => path,
        Err(e) => {
            // the same stage table as every other pre-registration failure: trust this run added is
            // undone and the ownership record is re-synced, instead of exiting past the cleanup
            undo_trust(cm400_windows::trust::Stage::ServiceRegister, &written);
            eprintln!("    ABORT: the service image could not be deployed safely: {e}");
            eprintln!("         nothing was registered or started from an unverified location");
            bail(&staged, 38);
        }
    };
    service_step(true, &written, &daemon);
}

/// The daemon beside the installer, as shipped.
fn daemon_source() -> std::path::PathBuf {
    let mut p = std::env::current_exe().unwrap_or_default();
    p.pop();
    p.push("cm400d.exe");
    p
}

/// Where the deployed daemon runs from.
const DEPLOY_DIR: &str = r"C:\Program Files\CM400\bin";

/// The daemon's own DACL: writable by SYSTEM and Administrators only. The service account gets read and
/// execute, never write, so a compromised daemon cannot be replaced by the identity that runs it.
fn daemon_grants(path: &std::path::Path) -> Vec<String> {
    grant_argv(
        path,
        &["*S-1-5-18:(F)", "*S-1-5-32-544:(F)", "*S-1-5-19:(RX)"],
    )
}

/// The principals allowed to hold a write-like right on a deployment path: the two accounts that have
/// to be able to manage the image, and nobody who runs it. Named once so a test can measure the rule
/// the installer actually applies instead of restating it and drifting away from it.
const DEPLOY_ALLOWED_WRITERS: [&str; 2] = ["NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators"];

/// The directory needs the same boundary as the file inside it. Restricting only the file's DACL is
/// not enough: delete or replace rights come from the **parent directory**, and `create_dir_all` does
/// not touch the ACL of a directory that already exists. On a clean Windows the default is fine, but
/// an installer may not treat a default as a verified fact about this particular machine.
fn deploy_dir_grants(path: &std::path::Path) -> Vec<String> {
    grant_argv(
        path,
        &[
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            "*S-1-5-19:(OI)(CI)RX",
            "*S-1-5-32-545:(OI)(CI)RX",
        ],
    )
}

/// Only the two administrator principals may write a staging directory. It holds the exact bytes that
/// the catalog gates are about to judge, so an ordinary user must not be able to replace a file inside it
/// or plant a reparse point: a random directory name is not a defence, a DACL that was read back is.
fn staging_grants(path: &std::path::Path) -> Vec<String> {
    grant_argv(path, &["*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"])
}

/// Our own prefix on a staging directory, so a stale one from an aborted run can be recognised without
/// guessing, and nothing that does not carry it is ever touched.
const STAGING_PREFIX: &str = "cm400-stage-";

/// Younger than this, a directory belongs to a run that may still be live, and sweeping it would break
/// somebody else's install rather than clean up after ours.
const STAGING_MIN_AGE_SECS: u64 = 30 * 60;

fn is_reparse(path: &std::path::Path) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        path.symlink_metadata()
            .map(|m| m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
            .unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        false
    }
}

/// The temporary directory this process considers its own, resolved. Without canonicalisation a
/// "leftover" could be pointed at a directory that only looks like a child of TEMP.
fn canonical_temp() -> PathBuf {
    std::fs::canonicalize(std::env::temp_dir()).unwrap_or_else(|_| std::env::temp_dir())
}

/// True only when `path` resolves to a direct child of `parent`. Anything deeper, or redirected by a
/// reparse point, is not the object the cleaner was written for.
fn direct_child_of(path: &std::path::Path, parent: &std::path::Path) -> bool {
    match std::fs::canonicalize(path) {
        Ok(real) => real.parent() == Some(parent),
        Err(_) => false,
    }
}

/// Is somebody actually at a keyboard? A run started by a script, a scheduled task or a `Start-Process`
/// without a console has no input to ask for confirmation from - and a destructive command must then
/// refuse rather than either hang waiting for an answer or proceed without one.
fn interactive_terminal() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal()
}

/// A confirmation that has to be typed. An empty line, EOF, or anything that is not exactly `YES` cancels;
/// there is no default answer and no timeout that accepts one.
fn typed_confirmation(question: &str) -> bool {
    use std::io::Write;
    println!("  {question}");
    print!("  type YES to continue, anything else cancels: ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    match std::io::stdin().read_line(&mut line) {
        Ok(_) => line.trim() == "YES",
        // an unreadable answer is not consent
        Err(_) => false,
    }
}

/// Whether this run can already do the work. The same probe the install flow uses: the right on the
/// service control manager that the flow needs, not `net session`, which is not an elevation test.
fn elevated_now() -> bool {
    windows_service::service_manager::ServiceManager::local_computer(
        None::<&str>,
        windows_service::service_manager::ServiceManagerAccess::CONNECT
            | windows_service::service_manager::ServiceManagerAccess::CREATE_SERVICE,
    )
    .is_ok()
}

/// Ask Windows for one elevation of this same executable, carrying the operation the operator already
/// confirmed. Only the interactive path uses this: a scripted run must keep receiving the existing
/// "requires elevation" refusal instead of opening a consent dialog nobody is watching.
fn relaunch_elevated(operation: &str) -> Result<(), String> {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SHOW_WINDOW_CMD;
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let shown = unsafe {
        ShellExecuteW(
            HWND::default(),
            wp("runas"),
            wp(&exe.to_string_lossy()),
            wp(operation),
            windows::core::PCWSTR::null(),
            SHOW_WINDOW_CMD(1), // SW_SHOWNORMAL, so the consent dialog is the ordinary one
        )
    };
    // the API reports a handle on success and a small negative-form error code otherwise
    if shown.0 as isize > 32 {
        println!("  an elevated window has been started for the {operation} step;");
        println!("  this window is done and changes nothing by itself.");
        Ok(())
    } else {
        Err(format!(
            "the elevation request was refused (code {})",
            shown.0 as isize
        ))
    }
}

/// What `uninstall` will change, stated before asking. An operator cannot confirm something they were
/// never told, and the certificate step in particular must not look like a general cleanup of the
/// machine's trust stores.
fn describe_uninstall_effects() {
    println!("  uninstalling this product will:");
    println!("    - stop and remove the CM400Driver service registration;");
    println!("    - remove the deployed daemon image under C:\\Program Files\\CM400\\bin;");
    println!(
        "    - remove the driver package binding for the motor interface this product installed;"
    );
    println!(
        "    - remove ONLY the certificate whose fingerprint, subject, self-signature and DER"
    );
    println!("      digest all match this release AND which the ownership record says we added;");
    println!("    - leave the data directory and its ACL as they are.");
    println!("  Anything on this machine that is not provably ours is left alone.");
}

/// The destructive command's gate: explicit `--yes` for non-interactive use, a typed YES otherwise, and
/// a refusal when neither is available. It never infers consent from a missing answer.
fn uninstall_gated(args: &[OsString]) {
    let explicit = args.iter().any(|a| a.to_str() == Some("--yes"));
    if explicit {
        println!("  proceeding: the command line carried --yes");
        uninstall_flow();
        return;
    }
    if !interactive_terminal() {
        eprintln!("    ABORT: uninstall needs an explicit confirmation and there is no terminal to ask for it.");
        eprintln!("      run it interactively, or pass --yes when the command is intended.");
        eprintln!("    nothing was changed by this run.");
        std::process::exit(28);
    }
    describe_uninstall_effects();
    if !typed_confirmation("Uninstall CM400 from this machine?") {
        println!("  cancelled; nothing was changed.");
        return;
    }
    uninstall_flow()
}

/// The maintenance menu shown when the product is already present. There is no default action: an
/// unreadable answer, an empty line or an unrecognised choice all cancel, because "pressed nothing" is
/// not an instruction to uninstall somebody's driver.
fn maintenance_menu(partial: Option<&str>) {
    if let Some(why) = partial {
        println!("  the installation is incomplete: {why}");
        println!(
            "  repairing re-runs the installer over what is there; it does not remove anything."
        );
    }
    println!("  choose an operation:");
    println!("    [1] repair or update");
    println!("    [2] uninstall");
    println!("    [3] cancel");
    use std::io::Write;
    print!("  choice: ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let answer = std::io::stdin()
        .read_line(&mut line)
        .map(|_| line.trim().to_string());
    match answer.as_deref() {
        Ok("1") => {
            if !elevated_now() {
                if let Err(e) = relaunch_elevated("install") {
                    eprintln!("    ABORT: {e}");
                    std::process::exit(20);
                }
                return;
            }
            install_flow(&[])
        }
        Ok("2") => uninstall_gated(&[]),
        // every other answer, including a failed read, cancels
        _ => println!("  cancelled; nothing was changed."),
    }
}

/// No arguments means the file was double-clicked. Decide what is installed from observable facts, tell
/// the operator what will happen, and ask - never install, overwrite or uninstall by default.
fn interactive_flow() {
    use cm400_windows::diagnostics::{install_state, InstallState};
    match install_state(&cm400_windows::config::Config::deployed_daemon_path()) {
        InstallState::NotInstalled => {
            println!("CM400 driver is not installed on this machine.");
            println!("  installing will:");
            println!(
                "    - stage this package's driver and bind only the motor interface (MI_02);"
            );
            println!(
                "    - deploy the daemon to C:\\Program Files\\CM400\\bin and register CM400Driver"
            );
            println!("      to run as LocalService with an ACL only SYSTEM and Administrators can write;");
            println!("    - add this release's certificate to the machine's Root and TrustedPublisher stores,");
            println!("      after verifying the catalog signature against the identity built into this file.");
            println!("  UAC will show an unknown publisher: this release is signed with a fixed self-signed");
            println!("  certificate, not one issued by Microsoft.");
            if !typed_confirmation("Proceed with the installation?") {
                println!("  cancelled; nothing was changed.");
                return;
            }
            if !elevated_now() {
                if let Err(e) = relaunch_elevated("install") {
                    eprintln!("    ABORT: {e}");
                    std::process::exit(20);
                }
                return;
            }
            install_flow(&[])
        }
        InstallState::Installed => maintenance_menu(None),
        InstallState::Partial(why) => maintenance_menu(Some(&why)),
    }
}

/// The Apache-2.0 text, carried inside the executable so a single downloaded file can still hand over
/// the licence copy the licence requires.
fn print_license() {
    print!(include_str!("../../../../LICENSE"));
}

/// What is inside a candidate leftover that a staging directory should never hold.
///
/// A staging directory is flat, small, and made only of the payload's own bare file names. Anything
/// else - a subdirectory, a reparse point, a name with a separator or a colon in it, or a pile of
/// entries - means this is not the directory we created, however exactly its DACL, owner and age
/// match. Deciding on the name and the age alone would be deciding on metadata.
fn structure_problems(dir: &std::path::Path) -> Vec<String> {
    let mut problems = Vec::new();
    let read = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) => {
            problems.push(format!("contents cannot be listed: {e}"));
            return problems;
        }
    };
    let mut count = 0usize;
    for entry in read.flatten() {
        count += 1;
        let name = entry.file_name().to_string_lossy().to_string();
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
            || name.contains(':')
            || name.contains('\\')
            || name.contains('/')
        {
            problems.push(format!("{name} is not a bare payload file name"));
        }
        match entry.file_type() {
            Ok(t) if t.is_dir() => problems.push(format!("{name} is a directory")),
            Ok(t) if t.is_symlink() => problems.push(format!("{name} is a symlink")),
            Ok(_) => {}
            Err(e) => problems.push(format!("{name} cannot be inspected: {e}")),
        }
        if is_reparse(&entry.path()) {
            problems.push(format!("{name} is a reparse point"));
        }
    }
    if count > 32 {
        problems.push(format!(
            "{count} entries is more than a staging directory holds"
        ));
    }
    problems
}

/// The facts a sweep decision is made from, all of them gathered rather than assumed.
#[derive(Debug, Clone)]
struct SweepFacts {
    name: String,
    /// None means the age could not be read, which is not permission to delete.
    age_secs: Option<u64>,
    reparse: bool,
    /// The entry must be a direct child of the canonicalised temporary directory this process uses.
    inside_expected_temp: bool,
    /// The owner SID, or None when it could not be read.
    owner_sid: Option<String>,
    /// The DACL as icacls reports it, or None when it could not be read.
    dacl: Option<String>,
    /// The pid our own directory name carries, when the name is the plain `cm400-stage-<pid>` shape.
    owner_pid: Option<u32>,
    /// Whether that pid is still running. None means the machine would not say, which is not a licence.
    pid_alive: Option<bool>,
    /// What the directory holds that a staging directory should not. Empty means the structure is right.
    structure: Vec<String>,
}

/// The package this run unpacked from its own bundle, and the promise that it goes away again.
#[derive(Debug)]
pub struct Staged {
    dir: PathBuf,
}

impl Staged {
    fn create(tag: &str) -> Result<Staged, String> {
        let dir = std::env::temp_dir().join(format!("{STAGING_PREFIX}{tag}"));
        if dir.symlink_metadata().is_ok() {
            return Err(format!(
                "staging directory {} already exists; refusing to reuse it",
                dir.display()
            ));
        }
        std::fs::create_dir(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        if let Err(e) = apply_and_verify(&dir, staging_grants(&dir)) {
            let _ = std::fs::remove_dir(&dir);
            return Err(format!("staging {} is not private: {e}", dir.display()));
        }
        if is_reparse(&dir) {
            let _ = std::fs::remove_dir(&dir);
            return Err(format!(
                "staging {} is a reparse point; refusing to write through it",
                dir.display()
            ));
        }
        Ok(Staged { dir })
    }

    pub fn dir(&self) -> &std::path::Path {
        &self.dir
    }

    /// Remove the directory and prove it is gone. A cleanup that was merely asked for is not a cleanup.
    pub fn remove(&self) -> Result<(), String> {
        if self.dir.symlink_metadata().is_err() {
            return Ok(());
        }
        if is_reparse(&self.dir) {
            return Err(format!(
                "{} is a reparse point; deleting it recursively could follow it somewhere else",
                self.dir.display()
            ));
        }
        std::fs::remove_dir_all(&self.dir)
            .map_err(|e| format!("cannot remove {}: {e}", self.dir.display()))?;
        if self.dir.symlink_metadata().is_ok() {
            return Err(format!(
                "{} still exists after removal was reported successful",
                self.dir.display()
            ));
        }
        Ok(())
    }

    /// SIDs that may own a directory the product created: an elevated interactive install is owned by that
    /// admin's user SID, a run from the service context by SYSTEM, and a scheduled repair by Administrators.
    /// Anywhere else, the directory was not made by us.
    fn owner_is_plausible(owner: Option<&str>, current_user: &str) -> bool {
        // an empty `current_user` means we could not name our own account, which must not become a wildcard
        // match for "owned by nobody"
        matches!(
            owner,
            Some(o) if o == "S-1-5-18" || o == "S-1-5-32-544" || (!current_user.is_empty() && o == current_user)
        )
    }

    /// The pid encoded in a staging directory name, when the name has the plain shape we give it. A name
    /// like `cm400-stage-reuse-1234` (a test's own suffix) yields None on purpose: reading a pid out of
    /// arbitrary text is how a cleaner mistakes somebody else's number for its own.
    fn pid_in_name(name: &str) -> Option<u32> {
        name.strip_prefix(STAGING_PREFIX)
            .and_then(|rest| rest.parse::<u32>().ok())
    }

    /// Is that pid still running? `None` means the machine would not say, which is never permission to
    /// delete. Access denied is read as "alive, and not mine to judge", because a process we cannot open
    /// is more likely somebody's running install than a ghost.
    fn pid_alive(pid: u32) -> Option<bool> {
        use windows::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED};
        use windows::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        // the exit code Windows reports for a process that has not terminated
        const STILL_ACTIVE: u32 = 259;
        unsafe {
            match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Err(e) => {
                    if e.code() == ERROR_ACCESS_DENIED.to_hresult() {
                        None
                    } else {
                        // a pid that cannot be opened for any other reason is not a live process
                        Some(false)
                    }
                }
                Ok(h) => {
                    let mut code = 0u32;
                    let got = GetExitCodeProcess(h, &mut code as *mut u32);
                    let _ = CloseHandle(h);
                    match got {
                        Ok(()) => Some(code == STILL_ACTIVE),
                        Err(_) => None,
                    }
                }
            }
        }
    }

    /// Decide, from gathered facts only. Returns Ok(()) for "this is provably ours and it is stale",
    /// and a reason for every other case so the run can report what it left alone.
    fn sweep_verdict(f: &SweepFacts, current_user: &str) -> Result<(), String> {
        if !f.name.starts_with(STAGING_PREFIX) {
            return Err("not our prefix".to_string());
        }
        // an orphan is a directory whose creating process is demonstrably no longer running. That is a
        // stronger statement than "it is old", and it is why a refused install can stop leaving bytes
        // lying around for half an hour: the next run recognises the pid in the name we chose is dead.
        // Our own pid never counts, and a live one never gets swept on age alone.
        let mine = std::process::id();
        let orphan = matches!(
            (f.owner_pid, f.pid_alive),
            (Some(p), Some(false)) if p != mine
        );
        if f.reparse {
            return Err(
                "it is a reparse point; recursive deletion could follow it elsewhere".to_string(),
            );
        }
        if !f.inside_expected_temp {
            return Err("it is not a direct child of the expected temporary directory".to_string());
        }
        match f.age_secs {
            None => {
                // an unreadable age is survivable only when the run that made the directory is provably
                // gone; otherwise "could not read" would quietly become permission to delete
                if !orphan {
                    return Err(
                        "its age could not be read and its creating run is not known to be gone"
                            .to_string(),
                    );
                }
            }
            Some(a) if a < STAGING_MIN_AGE_SECS && !orphan => {
                return Err(format!("only {a}s old; a live run may still own it"))
            }
            Some(_) => {}
        }
        if !Self::owner_is_plausible(f.owner_sid.as_deref(), current_user) {
            return Err(format!(
                "its owner is {:?}, which cannot have been created by this product",
                f.owner_sid
            ));
        }
        let Some(report) = f.dacl.as_deref() else {
            return Err("its DACL could not be read".to_string());
        };
        // the staging shape is exactly the two administrators, both writable, nobody else able to write,
        // and no ordinary-user ability to create or replace entries
        for trustee in DEPLOY_ALLOWED_WRITERS {
            if !cm400_windows::security::principal_can_write(report, trustee, false) {
                return Err(format!(
                    "{trustee} cannot write it, so this is not the DACL a staging directory gets"
                ));
            }
        }
        let foreign =
            cm400_windows::security::unexpected_write_grants(report, &DEPLOY_ALLOWED_WRITERS);
        if !foreign.is_empty() {
            return Err(format!(
                "its DACL also grants write to {} - an altered boundary, not a leftover of ours",
                foreign.join(", ")
            ));
        }
        if cm400_windows::security::standard_user_can_perturb(report) {
            return Err("ordinary users can still create or replace entries inside it".to_string());
        }
        if !f.structure.is_empty() {
            return Err(format!(
                "its contents are not what a staging directory holds: {}",
                f.structure.join("; ")
            ));
        }
        Ok(())
    }

    /// The directory's owner SID, read from the machine rather than assumed. Needed because the name of a
    /// directory says nothing about who made it.
    fn owner_sid_of(path: &std::path::Path) -> Option<String> {
        use windows::core::{PCWSTR, PWSTR};
        use windows::Win32::Foundation::{LocalFree, HLOCAL, WIN32_ERROR};
        use windows::Win32::Security::Authorization::{
            ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
        };
        use windows::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};
        let wide: Vec<u16> = path
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut owner = PSID(std::ptr::null_mut());
        // the descriptor is an out parameter the API allocates; it is not optional, and it has to be
        // released or every sweep of every leftover leaks one
        let mut descriptor = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        let code = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                Some(&mut owner as *mut PSID),
                None,
                None,
                None,
                &mut descriptor as *mut PSECURITY_DESCRIPTOR,
            )
        };
        if code != WIN32_ERROR(0) {
            return None;
        }
        let mut text = PWSTR::null();
        let converted = unsafe { ConvertSidToStringSidW(owner, &mut text as *mut PWSTR) };
        let sid = if converted.is_ok() {
            unsafe { text.to_string() }.ok()
        } else {
            None
        };
        unsafe {
            // both allocations belong to the API and both have to be handed back
            if !text.0.is_null() {
                let _ = LocalFree(HLOCAL(text.0 as *mut _));
            }
            if !descriptor.0.is_null() {
                let _ = LocalFree(HLOCAL(descriptor.0));
            }
        }
        sid
    }

    /// The SID this process runs as, read from its own access token.
    ///
    /// Deliberately not parsed out of `whoami` output. Measured on this machine: the text form carries the
    /// account and the SID in fields whose labels and separators are localised, and a parser that guessed
    /// at them produced an empty string - which made every owner look foreign and silently disarmed the
    /// sweep while still looking like a conservative refusal. The token answers the question directly.
    ///
    /// Which "current user" this is matters and is stated: it is the identity of THIS process. On an
    /// elevated run that is the account UAC actually started the process as - usually the same user SID as
    /// the interactive login, but not necessarily the same one when elevation was obtained with different
    /// administrator credentials. That case is handled by refusing, not by widening the set: a directory
    /// whose owner this process cannot vouch for stays where it is.
    ///
    /// An empty return value means the token could not be read. `owner_is_plausible` then narrows to the
    /// fixed principals rather than matching anything.
    fn current_user_sid() -> String {
        use windows::core::PWSTR;
        use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
        use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows::Win32::Security::{GetTokenInformation, TokenUser, PSID, TOKEN_QUERY};
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        unsafe {
            let mut token = HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token as *mut HANDLE)
                .is_err()
            {
                return String::new();
            }
            // TOKEN_USER begins with the SID pointer, so the first pointer-sized word of the buffer is
            // the value. Building the struct by hand would tie this to a type whose shape the bindings
            // crate has reshuffled before, and a wrong guess here decides who looks like us.
            let mut needed = 0u32;
            let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed as *mut u32);
            if needed < (std::mem::size_of::<*mut core::ffi::c_void>() * 2) as u32 {
                let _ = CloseHandle(token);
                return String::new();
            }
            let mut buf = vec![0u8; needed as usize];
            let mut used = 0u32;
            let got = GetTokenInformation(
                token,
                TokenUser,
                Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
                buf.len() as u32,
                &mut used as *mut u32,
            );
            let _ = CloseHandle(token);
            if got.is_err()
                || (used as usize) < std::mem::size_of::<*mut core::ffi::c_void>()
                || buf.len() < std::mem::size_of::<*mut core::ffi::c_void>()
            {
                return String::new();
            }
            let owner = PSID(*(buf.as_ptr() as *const *mut core::ffi::c_void));
            if owner.0.is_null() {
                return String::new();
            }
            let mut text = PWSTR::null();
            if ConvertSidToStringSidW(owner, &mut text as *mut PWSTR).is_err() {
                return String::new();
            }
            let sid = text.to_string().unwrap_or_default();
            if !text.0.is_null() {
                let _ = LocalFree(HLOCAL(text.0 as *mut _));
            }
            sid
        }
    }

    /// Sweep before doing anything else. Several failure paths inside the install flow terminate the
    /// process directly, which skips this type's destructor, so a crashed or aborted run would otherwise
    /// leave verified package bytes on disk indefinitely.
    ///
    /// Note what this never does: it does not rewrite a DACL in order to make a deletion succeed. Fixing
    /// up somebody else's boundary to satisfy our cleaner is how a cleanup primitive becomes a weapon.
    fn sweep_stale() {
        let root = std::env::temp_dir();
        let expected = canonical_temp();
        let me = Self::current_user_sid();
        let read = match std::fs::read_dir(&root) {
            Ok(r) => r,
            Err(_) => return,
        };
        for name in read.filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().to_string()))
        {
            if !name.starts_with(STAGING_PREFIX) {
                continue;
            }
            let path = root.join(&name);
            let meta = std::fs::symlink_metadata(&path);
            #[cfg(windows)]
            let reparse = {
                use std::os::windows::fs::MetadataExt;
                const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
                match meta {
                    Ok(ref m) => m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0,
                    // a directory we cannot even stat is not one we should delete
                    Err(_) => true,
                }
            };
            #[cfg(not(windows))]
            let reparse = true;
            let age_secs = std::fs::metadata(&path)
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.elapsed().ok())
                .map(|d| d.as_secs());
            let facts = SweepFacts {
                name: name.clone(),
                age_secs,
                reparse,
                inside_expected_temp: direct_child_of(&path, &expected),
                owner_sid: Self::owner_sid_of(&path),
                dacl: icacls_report(&path).ok(),
                owner_pid: Self::pid_in_name(&name),
                pid_alive: Self::pid_in_name(&name).and_then(Self::pid_alive),
                structure: structure_problems(&path),
            };
            match Self::sweep_verdict(&facts, &me) {
                Ok(()) => {
                    let staged = Staged { dir: path };
                    match staged.remove() {
                        Ok(()) => println!(" swept a stale staging directory: {name}"),
                        Err(e) => {
                            println!(" left a stale staging directory in place ({name}): {e}")
                        }
                    }
                }
                Err(why) => {
                    println!(" left {} in place: {why}", path.display());
                }
            }
        }
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        if let Err(e) = self.remove() {
            // never report a cleanup that did not happen
            eprintln!("cm400-setup: staging cleanup FAILED: {e}");
            eprintln!("  remove this directory by hand: {}", self.dir.display());
        }
    }
}

/// Leave the install flow through one door.
///
/// Every failure after staging has to take this run's private copy with it: the directory holds the exact
/// bytes the gates just judged, and abandoning them is both clutter and a second copy of a driver package
/// lying around where something else could find it. Removal is verified, and a removal that could not be
/// confirmed is named with its path rather than reported as done. The exit code stays the caller's, so
/// cleaning up never changes what a failure reports.
fn bail(staged: &Option<Staged>, code: i32) -> ! {
    if let Some(s) = staged {
        if let Err(e) = s.remove() {
            eprintln!("cm400-setup: staging cleanup FAILED: {e}");
            eprintln!(
                "  this run left its staged package behind at: {}",
                s.dir().display()
            );
            eprintln!("  it is closed to ordinary users; a later run sweeps it once the creating process is gone");
        }
    }
    std::process::exit(code)
}

/// Stage and verify the package this executable carries, if it carries one.
///
/// `Ok(None)` means "no bundle here, use the loose files as before", which is what every pre-rc4 package
/// and every CI script expects - including an explicit INF argument, which always outranks the bundle.
/// A malformed bundle is an error, not a silent fallback: a stripped trailer only downgrades the layout,
/// it does not weaken a single gate, because the loose-file path still demands a catalog that verifies
/// against the pinned identity and a manifest that matches the bytes on disk.
fn stage_bundle() -> Result<Option<Staged>, String> {
    // anyone who is about to use TEMP for a verified copy first clears what an earlier run left there,
    // under the full set of proofs below; this is why the policy lives in the staging entry point rather
    // than only in the install flow
    Staged::sweep_stale();
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let bundle = match cm400_windows::bundle::Bundle::read(&exe) {
        Ok(b) => b,
        Err(e)
            if e.contains("no CM400 bundle trailer")
                || e.contains("smaller than a bundle trailer") =>
        {
            return Ok(None)
        }
        Err(e) => {
            return Err(format!(
                "this executable claims to carry a bundle but it cannot be read: {e}"
            ))
        }
    };
    if !bundle.names().iter().any(|n| n == "cm400.inf") {
        return Err("the bundle carries no cm400.inf".to_string());
    }
    let tag = format!("{}", std::process::id());
    let staged = Staged::create(&tag)?;
    // extract_all digests every member before it writes any of them, and re-hashes what landed
    match bundle.extract_all(&exe, staged.dir()) {
        Ok(files) => {
            println!(
                " staged {} package file(s) into a private directory",
                files.len()
            );
            Ok(Some(staged))
        }
        Err(e) => {
            // `staged` is dropped here, which removes the directory and reports if that failed
            Err(format!(
                "the bundle this executable carries does not verify: {e}"
            ))
        }
    }
}

fn grant_argv(path: &std::path::Path, grants: &[&str]) -> Vec<String> {
    let mut argv = vec![
        path.to_string_lossy().to_string(),
        "/inheritance:r".to_string(),
        "/grant:r".to_string(),
    ];
    argv.extend(grants.iter().map(|g| g.to_string()));
    argv
}

fn icacls_report(path: &std::path::Path) -> Result<String, String> {
    let (code, out) = run("icacls.exe", &[&path.to_string_lossy()]);
    // the exit code is checked inside `dacl_report`'s interpreter, and a failing run yields `Err`
    // rather than the partial text icacls prints while it fails
    cm400_windows::trust_ownership::interpret_icacls_output(code, &out, "", &path.to_string_lossy())
}

/// Apply a grant plan and then read back what the machine actually has, because a DACL that was only
/// asked for is not a DACL that exists.
fn apply_and_verify(path: &std::path::Path, argv: Vec<String>) -> Result<(), String> {
    let refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
    let (code, out) = run("icacls.exe", &refs);
    if code != 0 {
        return Err(format!(
            "icacls refused for {}: {}",
            path.display(),
            out.lines().last().unwrap_or("").trim()
        ));
    }
    let mut report = icacls_report(path)?;
    // A machine whose temp directory hands the installing account an explicit, non-inherited ACE keeps that
    // entry after `/inheritance:r`, which clears inherited entries only. Measured in cloud CI: a runner's own
    // temp left its installing admin named on the staging path, so the boundary rule - correctly - refused a
    // directory the installer had just created. Granting around such an entry would not be hardening, and
    // refusing is safe but not installable, so the plan takes the access away from the principals it does not
    // name and then judges the state that actually resulted. Every check below reads the final DACL; none of
    // them is answered by the DACL as it stood before the removal.
    for _ in 0..3 {
        let stray =
            cm400_windows::security::unexpected_write_grants(&report, &DEPLOY_ALLOWED_WRITERS);
        let mut names: Vec<String> = Vec::new();
        for finding in &stray {
            if let Some((who, _)) = finding.split_once(" holds a write-like right") {
                let who = who.trim();
                if !who.is_empty() && !names.iter().any(|n| n == who) {
                    names.push(who.to_string());
                }
            }
        }
        if names.is_empty() {
            // either nothing foreign is left, or the finding could not be named well enough to remove it;
            // the refusal after the loop treats both honestly rather than assuming the first
            break;
        }
        for who in &names {
            let argv: Vec<String> = vec![
                path.to_string_lossy().to_string(),
                "/remove:g".to_string(),
                who.clone(),
            ];
            let refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
            let (code, out) = run("icacls.exe", &refs);
            if code != 0 {
                return Err(format!(
                    "{}: cannot take write access away from {}: {}",
                    path.display(),
                    who,
                    out.lines().last().unwrap_or("").trim()
                ));
            }
        }
        report = icacls_report(path)?;
    }
    let can = |trustee: &str, file: bool| {
        cm400_windows::security::principal_can_write(&report, trustee, file)
    };
    if !can("NT AUTHORITY\\SYSTEM", !path.is_dir()) {
        return Err(format!("{}: SYSTEM cannot write it", path.display()));
    }
    if !can("BUILTIN\\Administrators", !path.is_dir()) {
        return Err(format!(
            "{}: Administrators cannot write it",
            path.display()
        ));
    }
    // the property that matters for a service image: ordinary users must not be able to create,
    // delete or replace anything here, whatever the inherited defaults were
    if cm400_windows::security::standard_user_can_perturb(&report) {
        return Err(format!(
            "{} is still open to ordinary users creating or replacing entries",
            path.display()
        ));
    }
    // and the deny-list is not the whole answer: a group this machine knows and this installer does
    // not would be invisible to it, as would a report whose ACEs could not be parsed at all. Both are
    // treated as unsafe here, because "I cannot tell who can write the service binary" is not
    // evidence that nobody can.
    let stray = cm400_windows::security::unexpected_write_grants(&report, &DEPLOY_ALLOWED_WRITERS);
    if !stray.is_empty() {
        return Err(format!(
            "{}: unexpected write principals:\n  {}",
            path.display(),
            stray.join("\n  ")
        ));
    }
    Ok(())
}

/// Copy the daemon into `DEPLOY_DIR`, protect the directory and the file, and judge the bytes that
/// actually landed. Returns an error instead of exiting so that the caller can run the stage-appropriate
/// trust rollback and ownership sync - a cleanup that jumps out of the transaction from the middle
/// would leave the record describing a state that no longer exists.
fn deploy_daemon(source: &std::path::Path) -> Result<std::path::PathBuf, String> {
    use cm400_windows::artifact_manifest::sha256_of_file;

    if !source.exists() {
        return Err(format!(
            "no cm400d.exe beside the installer at {}",
            source.display()
        ));
    }
    let dir = std::path::Path::new(DEPLOY_DIR);
    if let Err(e) = std::fs::create_dir_all(dir) {
        return Err(format!("cannot create {}: {e}", dir.display()));
    }
    apply_and_verify(dir, deploy_dir_grants(dir))?;
    let target = dir.join("cm400d.exe");
    if let Err(e) = std::fs::copy(source, &target) {
        // a running service holds its image open; [2] quiesce stops it, so this is some other refusal
        return Err(format!("cannot write {}: {e}", target.display()));
    }
    apply_and_verify(&target, daemon_grants(&target))?;
    match (sha256_of_file(source), sha256_of_file(&target)) {
        (Some(a), Some(b)) if a == b => {
            println!("[6a] daemon image  : deployed to {} (SHA-256 matches the package copy; directory and file DACL verified by re-read)", target.display());
        }
        (Some(_), Some(_)) => {
            return Err(format!(
                "the deployed image at {} does not match {}",
                target.display(),
                source.display()
            ))
        }
        _ => return Err("the deployed image could not be hashed".to_string()),
    }
    Ok(target)
}

/// What the service step must do, decided from what is already registered.
///
/// `sc create` on a name that already exists fails, and treating that as "install incomplete" was
/// wrong in both directions: it reported a hard failure while the existing service could have been
/// reused, and it filed that failure under the stage that *retains* trust. An upgrade of an existing
/// registration is its own path, and it has to end with the image, start type, account and running
/// state verified - not with a create call that cannot succeed.
#[derive(Debug, PartialEq, Eq)]
enum ServicePlan {
    Create,
    /// reuse the registration; `config` holds the `sc config` key/value pairs that must change
    Reuse {
        config: Vec<String>,
    },
}

/// The account the daemon must run as. LocalService is not a cosmetic choice: it is the identity whose
/// access to the data directory and to Performance Log Users the whole ACL design is built around.
const SERVICE_ACCOUNT: &str = "NT AUTHORITY\\LocalService";

/// A `sc qc` field, or empty when absent.
fn service_field(quote: &str, name: &str) -> String {
    quote
        .lines()
        .find(|l| l.trim_start().starts_with(name))
        .and_then(|l| l.split_once(':'))
        .map(|(_, value)| value.trim().to_string())
        .unwrap_or_default()
}

/// Split a service command line into (executable, arguments), rejecting unbalanced quoting.
///
/// This replaces a comparison that stripped every `"` and collapsed whitespace: that comparison could
/// not tell a correct command line from one carrying a stray trailing quote, so the bug it was meant
/// to catch would have been verified as a match. Quoting is part of what is being checked here, so it
/// has to be parsed rather than erased.
fn parse_command_line(text: &str) -> Option<(String, String)> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let (executable, arguments) = if let Some(rest) = text.strip_prefix('"') {
        // a quoted executable path ends at the next quote; anything else is malformed
        let end = rest.find('"')?;
        let path = &rest[..end];
        let tail = rest[end + 1..].trim_start();
        let quotes_after = tail.matches('"').count();
        if quotes_after != 0 {
            return None;
        }
        (path, tail)
    } else {
        let mut parts = text.splitn(2, |c: char| c.is_whitespace());
        let path = parts.next()?;
        if path.contains('"') {
            return None;
        }
        let tail = parts.next().unwrap_or_default().trim();
        // an unquoted command line has no business containing a quote at all: one appearing here means
        // the closing quote landed in the wrong place, which is malformed rather than "a different
        // spelling of the same path"
        if tail.contains('"') {
            return None;
        }
        (path, tail)
    };
    Some((
        executable.to_ascii_lowercase(),
        arguments
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase(),
    ))
}

/// True when both command lines name the same executable with the same arguments.
fn same_command_line(current: &str, want: &str) -> bool {
    match (parse_command_line(current), parse_command_line(want)) {
        (Some(a), Some(b)) => a == b,
        // an unparseable registered image is not "equal to" anything; the caller must fix it
        _ => false,
    }
}

fn plan_service(
    exists: bool,
    current_bin_path: &str,
    want_bin_path: &str,
    current_start_type: &str,
    current_account: &str,
) -> ServicePlan {
    if !exists {
        return ServicePlan::Create;
    }
    let mut config = Vec::new();
    if !same_command_line(current_bin_path, want_bin_path) {
        // pass the command line through as-is: it is already built, and re-wrapping it in quotes
        // produced `"...cm400d.exe" --service"`, which the SCM would have registered verbatim
        config.push("binPath=".to_string());
        config.push(want_bin_path.to_string());
    }
    if !start_type_is_auto(current_start_type) {
        config.push("start=".to_string());
        config.push("auto".to_string());
    }
    if !account_is_local_service(current_account) {
        config.push("obj=".to_string());
        config.push(SERVICE_ACCOUNT.to_string());
    }
    ServicePlan::Reuse { config }
}

/// `sc qc` prints `START_TYPE : 2 AUTO_START`, so the field has to be looked for inside the value
/// rather than compared to it. Exact equality would demand a change on every run and then find the
/// change had no effect, which is how a configuration check becomes noise.
fn start_type_is_auto(value: &str) -> bool {
    value.to_ascii_uppercase().contains("AUTO_START")
}

/// The account the SCM reports for the service.
fn account_is_local_service(value: &str) -> bool {
    value
        .trim_end_matches(|c: char| c.is_whitespace() || c == '\r' || c == '\n')
        .eq_ignore_ascii_case(SERVICE_ACCOUNT)
}

/// Register / remove the daemon service. Part of the installer, not of the daemon:
/// a LocalService process must never install or repair its own service.
///
/// `written` is what this install added to the trust stores, so a failure inside the service step is
/// judged against the approved stage table rather than by whoever wrote the branch: registered-but-
/// not-running keeps trust for a retry, a service that could not be created or configured does not.
/// The image, start type and account are all verified from the SCM's own re-read, never from the
/// result of the call that set them.
fn service_step(install: bool, written: &[String], daemon: &std::path::Path) {
    if !daemon.exists() {
        undo_trust(cm400_windows::trust::Stage::ServiceRegister, written);
        println!("[6] service      : SKIPPED - no cm400d.exe at the deployed location");
        println!("                   an install is not complete without the daemon, so this is a failure:");
        std::process::exit(25);
    }
    if install {
        let bin = format!("\"{}\" --service", daemon.display());
        // is it already registered, and as what?
        let (qc, qco) = run("sc.exe", &["qc", "CM400Driver"]);
        let exists = qc == 0 && qco.contains("CM400Driver");
        let current_bin = service_field(&qco, "BINARY_PATH_NAME");
        let current_start = service_field(&qco, "START_TYPE");
        let current_account = service_field(&qco, "SERVICE_START_NAME");
        let plan = plan_service(exists, &current_bin, &bin, &current_start, &current_account);
        let registered = match &plan {
            ServicePlan::Create => {
                let (c1, o1) = run(
                    "sc.exe",
                    &[
                        "create",
                        "CM400Driver",
                        "binPath=",
                        &bin,
                        "start=",
                        "auto",
                        "obj=",
                        SERVICE_ACCOUNT,
                        "displayName=",
                        "CM400Driver",
                    ],
                );
                println!(
                    "[6] service      : created; exit {c1}  {}",
                    o1.lines().last().unwrap_or("").trim()
                );
                c1 == 0
            }
            ServicePlan::Reuse { config } => {
                if config.is_empty() {
                    println!("[6] service      : reusing the existing registration (image, start type and account already as intended)");
                    true
                } else {
                    let mut args: Vec<String> =
                        vec!["config".to_string(), "CM400Driver".to_string()];
                    args.extend(config.iter().cloned());
                    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                    let (cc, co) = run("sc.exe", &refs);
                    println!("[6] service      : upgrade of the existing registration; `sc config {}` exit {cc} {}",
                        config.join(" "), co.lines().last().unwrap_or("").trim());
                    if cc != 0 {
                        undo_trust(cm400_windows::trust::Stage::ServiceRegister, written);
                        println!("                   the registration could not be brought to the intended configuration");
                        std::process::exit(25);
                    }
                    true
                }
            }
        };
        // whatever the plan did, the state the SCM now reports is the only acceptable evidence, and
        // it has to cover the account as well as the image: an otherwise identical service running as
        // LocalSystem would pass an image-and-RUNNING check while every ACL assumption is wrong
        let (_, after) = run("sc.exe", &["qc", "CM400Driver"]);
        let now_bin = service_field(&after, "BINARY_PATH_NAME");
        let now_start = service_field(&after, "START_TYPE");
        let now_account = service_field(&after, "SERVICE_START_NAME");
        let image_ok = same_command_line(&now_bin, &bin);
        let start_ok = start_type_is_auto(&now_start);
        let account_ok = account_is_local_service(&now_account);
        println!("                 registered image matches deployed: {image_ok} ({now_bin})");
        println!("                 start type auto: {start_ok} ({now_start})");
        println!("                 runs as LocalService: {account_ok} ({now_account})");
        if !(image_ok && start_ok && account_ok) {
            undo_trust(cm400_windows::trust::Stage::ServiceRegister, written);
            println!("[7] the existing registration is not the service this install is for;");
            println!(
                "                   refusing to start an image or account that was not verified"
            );
            std::process::exit(25);
        }
        let (c2, _) = run(
            "sc.exe",
            &[
                "failure",
                "CM400Driver",
                "reset=",
                "86400",
                "actions=",
                "restart/5000/restart/5000/restart/5000",
            ],
        );
        println!("                 failure policy exit {c2}");
        // LocalService needs the Performance Log Users right to run an ETW real-time
        // session, and write access to its own state/log directory. Both are reported,
        // neither is silently assumed.
        let (c3, o3) = run(
            "net.exe",
            &[
                "localgroup",
                "Performance Log Users",
                "/add",
                "NT AUTHORITY\\LocalService",
            ],
        );
        // Measured: adding an existing member returns a non-zero code, so the code alone
        // is not the verdict - confirm membership by listing the group instead.
        let (_, members) = run("net.exe", &["localgroup", "Performance Log Users"]);
        let member = members.to_ascii_uppercase().contains("LOCAL SERVICE");
        println!("                 Performance Log Users: add exit {c3}, member present={member}");
        if !member {
            println!(
                "                   (output was: {})",
                o3.lines().last().unwrap_or("").trim()
            );
        }
        // The data directory is a trust boundary, not scratch space: the daemon reads a backend
        // selection and a persisted motor position from it and treats both as fact. ProgramData
        // hands ordinary users inheritable child-create rights there (measured on this machine as
        // `BUILTIN\Users:(I)(CI)(WD,AD,WEA,WA)`), which is enough to occupy the predictable temp
        // name the atomic state save writes to, so the DACL is replaced here instead of being
        // layered on top of whatever inheritance happens to be in effect.
        let acl_open = harden_data_acl();
        // The data-tree pass resets children to inherit, and the ownership record lives inside that
        // tree, so its narrower boundary is re-applied and verified here. A record that cannot be
        // protected is not a record: it cannot authorize a later cleanup, and trusting the trust we
        // just added on top of it would be exactly the inconsistency that made this uninstall refuse.
        if let Err(e) = enforce_ownership_boundary() {
            undo_trust(cm400_windows::trust::Stage::OwnershipUpdate, written);
            eprintln!("    ABORT: the ownership record's boundary could not be enforced: {e}");
            std::process::exit(35);
        }
        let (c5, o5) = run("sc.exe", &["start", "CM400Driver"]);
        // A service that is still coming up is not a service that failed. Reading `sc query` once,
        // immediately after `sc start`, catches START_PENDING and used to be reported as an
        // incomplete install - measured on this machine as exit 26 while the daemon was Running a
        // second later. Poll instead, and treat only a settled state as an answer: RUNNING is
        // success, two consecutive STOPPED reads mean it really did not come up.
        let mut running = false;
        let mut stopped_reads = 0;
        for _ in 0..30 {
            let (_, q) = run("sc.exe", &["query", "CM400Driver"]);
            if q.contains("RUNNING") {
                running = true;
                break;
            }
            if q.contains("STOPPED") {
                stopped_reads += 1;
                if stopped_reads >= 2 {
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        println!(
            "                 start exit {c5}, {}",
            o5.lines().last().unwrap_or("").trim()
        );
        println!(
            "                 service reached RUNNING={running} (stopped reads {stopped_reads})"
        );
        if !registered || !running {
            println!("[7] DRIVER INSTALLED BUT THE SERVICE IS NOT RUNNING - not reporting a complete install.");
            // Approved retention case: the driver is staged, the interface is bound and the service
            // registration is in place, so the trust stays for a retry - with the ownership record
            // saying so. A registration that could not be created or configured exits above instead.
            undo_trust(cm400_windows::trust::Stage::ServiceRunning, written);
            std::process::exit(26);
        }
        if acl_open {
            // Hardening that failed silently would leave the install looking clean while the
            // trust boundary is still open, so this is a reported failure, not a warning.
            println!("[7] INSTALL INCOMPLETE: ordinary users can still create or replace files the service reads.");
            std::process::exit(27);
        }
        println!("[7] INSTALL COMPLETE: driver bound, own interface enumerated, service running, data ACL closed to ordinary users.");
    }
}

/// Replace the CM400 data tree's DACL with the explicit grant set and judge the result by
/// reading it back. Returns true when a standard user can still perturb anything the service will
/// read next. `icacls` exiting zero is not the verdict - the resulting rights are.
///
/// Used by `install` and reachable on its own (`cm400-setup harden-acl`), because an upgrade or a
/// repair has to fix a directory whose permissions are already wrong: `/inheritance:r` removes
/// the inherited ACE instead of stacking over it, and the children are reset so they pick up the
/// new rights by inheritance.
fn harden_data_acl() -> bool {
    use cm400_windows::security;
    let root = "C:\\ProgramData\\CM400";
    // The directories have to exist before the DACL is set on them: icacls cannot grant on a
    // path that is not there, and LocalService must not have to start before its own tree is
    // laid out.
    for dir in security::data_tree_dirs(root) {
        let _ = std::fs::create_dir_all(&dir);
    }
    for step in security::data_tree_plan(root) {
        let refs: Vec<&str> = step.iter().map(String::as_str).collect();
        let (c, o) = run("icacls.exe", &refs);
        if c != 0 {
            println!(
                "                 icacls {c} for {}: {}",
                step[0],
                o.lines().last().unwrap_or("").trim()
            );
        }
    }
    // The config file is narrowed separately: reading the backend selection is required, changing
    // it from inside the daemon is not. Skipped when absent, which is normal on a fresh install
    // where the config is written afterwards - the next repair pass applies it.
    let config = format!("{root}\\config.toml");
    if std::path::Path::new(&config).exists() {
        let steps = security::config_file_args(&config);
        let refs: Vec<&str> = steps.iter().map(String::as_str).collect();
        let (c, o) = run("icacls.exe", &refs);
        if c != 0 {
            println!(
                "                 icacls {c} for {config}: {}",
                o.lines().last().unwrap_or("").trim()
            );
        }
    }
    // Judge the result, not the exit codes. The write checks are taken on the **directories**, which
    // always exist and whose `(OI)(CI)M` grants are what authorizes the state and log files to be
    // created in the first place - a fresh install has no `state.kv` or `cm400d.log` yet, and
    // checking those files alone reported a good install as failed (measured: exit 27 right after an
    // uninstall had just removed them). When the files do exist, they are checked as well.
    let (_, report) = run("icacls.exe", &[root]);
    let open = security::standard_user_can_perturb(&report);
    let ls = "NT AUTHORITY\\LOCAL SERVICE";
    let state_dir = run("icacls.exe", &["C:\\ProgramData\\CM400\\state"]);
    let logs_dir = run("icacls.exe", &["C:\\ProgramData\\CM400\\logs"]);
    let service_state = run("icacls.exe", &["C:\\ProgramData\\CM400\\state\\state.kv"]);
    let service_log = run("icacls.exe", &["C:\\ProgramData\\CM400\\logs\\cm400d.log"]);
    let dir_allows_state = security::principal_can_write(&state_dir.1, ls, false);
    let dir_allows_log = security::principal_can_write(&logs_dir.1, ls, false);
    let state_file_present =
        std::path::Path::new("C:\\ProgramData\\CM400\\state\\state.kv").exists();
    let log_file_present =
        std::path::Path::new("C:\\ProgramData\\CM400\\logs\\cm400d.log").exists();
    let writes_state = dir_allows_state
        && (!state_file_present || security::principal_can_write(&service_state.1, ls, true));
    let writes_log = dir_allows_log
        && (!log_file_present || security::principal_can_write(&service_log.1, ls, true));
    // The config file has to stay readable (a daemon that cannot read it silently falls back), and
    // must not stay writable (a daemon that can write it can undo its own fail-closed default).
    let (_, config_report) = run("icacls.exe", &[&config]);
    let config_present = std::path::Path::new(&config).exists();
    let reads_config = !config_present
        || security::principal_can_read(&config_report, "NT AUTHORITY\\LOCAL SERVICE", true);
    let writes_config = config_present
        && security::principal_can_write(&config_report, "NT AUTHORITY\\LOCAL SERVICE", true);
    println!(
        "                 data ACL: ordinary-users-can-perturb={open}, service-writes-state={writes_state} (dir {dir_allows_state}, file present {state_file_present}), service-writes-log={writes_log} (dir {dir_allows_log}, file present {log_file_present}), service-reads-config={reads_config}, service-writes-config={writes_config} (want: false, true, true, true, false)"
    );
    if open || !writes_state || !writes_log || !reads_config || writes_config {
        // Show the offending state rather than a bare failure, so the operator can act on it.
        for line in report.lines().take(10) {
            println!("                   {line}");
        }
        println!(
            "                   state.kv: {}",
            service_state.1.lines().next().unwrap_or("").trim()
        );
        println!(
            "                   cm400d.log: {}",
            service_log.1.lines().next().unwrap_or("").trim()
        );
        if config_present {
            println!(
                "                   config.toml: {}",
                config_report.lines().next().unwrap_or("").trim()
            );
        }
    }
    open || !writes_state || !writes_log || !reads_config || writes_config
}

/// What to do with `C:\Program Files\CM400` at uninstall time, decided from evidence.
///
/// Deleting a directory because a `sc delete` returned 0 would be guessing. The directory is ours to
/// remove only when the service that ran from it is provably gone, the image the SCM had registered
/// really was this file (parsed, not substring-matched - `cm400d.exe.bak` contains it as a substring),
/// and nothing we do not recognise is inside.
#[derive(Debug, PartialEq, Eq)]
enum DeployRemoval {
    Remove,
    Keep(String),
}

fn deploy_removal_decision(
    registered_image: Option<&str>,
    service_gone: bool,
    deployed_exe: &std::path::Path,
    relative_files: &[String],
) -> DeployRemoval {
    let Some(image) = registered_image else {
        return DeployRemoval::Keep("the registered service image could not be read".to_string());
    };
    let Some((exe, _args)) = parse_command_line(image) else {
        return DeployRemoval::Keep(format!(
            "the registered image is not a parseable command line ({image:?})"
        ));
    };
    // exact path comparison, case- and separator-insensitive, no substring involved
    let want = deployed_exe
        .to_string_lossy()
        .replace('\\', "")
        .to_ascii_lowercase();
    let have = exe.replace('\\', "").to_ascii_lowercase();
    if have != want {
        return DeployRemoval::Keep(format!(
            "the service ran {image:?}, which is not this product's deployed image; the directory is not ours to delete"
        ));
    }
    if !service_gone {
        return DeployRemoval::Keep(
            "the service registration is still present after the delete attempt".to_string(),
        );
    }
    // the release writes exactly one file here; anything else is somebody else's content, and
    // deleting a directory because it is "probably ours" is how an uninstall eats someone's work
    for entry in relative_files {
        if entry.as_str() != "bin/cm400d.exe" {
            return DeployRemoval::Keep(format!(
                "the deployment directory also holds {entry:?}, which this product did not place there"
            ));
        }
    }
    DeployRemoval::Remove
}

/// What to do with the ownership record once certificate cleanup is over.
///
/// The record is the only thing that lets a later run tell our certificate from somebody else's, so it
/// may be removed only after cleanup actually succeeded: every store enumerated, the pinned identity
/// confirmed gone, and nothing refused. If the certificate is still there - which is exactly the
/// `Preexisting` case - the record is still doing its job and must stay.
#[derive(Debug, PartialEq, Eq)]
enum RecordRemoval {
    Remove,
    Keep(String),
}

fn record_removal_decision(
    refused: &[String],
    enumeration_failed: &[String],
    pinned_still_present: &[String],
) -> RecordRemoval {
    if !refused.is_empty() {
        return RecordRemoval::Keep(format!(
            "certificate cleanup was refused ({})",
            refused.join("; ")
        ));
    }
    if !enumeration_failed.is_empty() {
        return RecordRemoval::Keep(format!(
            "a store could not be enumerated to confirm removal ({}); an unverified state keeps the record",
            enumeration_failed.join("; ")
        ));
    }
    if !pinned_still_present.is_empty() {
        return RecordRemoval::Keep(format!(
            "the pinned identity is still listed in {}; the record is what protects it from a later cleanup",
            pinned_still_present.join(", ")
        ));
    }
    RecordRemoval::Remove
}

/// Every file under `dir`, as `/`-separated paths relative to it, lowercased. An unreadable directory
/// yields an error so the caller keeps the tree rather than concluding it is empty.
fn tree_entries(dir: &std::path::Path) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let read = std::fs::read_dir(&current)
            .map_err(|e| format!("cannot list {}: {e}", current.display()));
        for entry in read? {
            let entry =
                entry.map_err(|e| format!("cannot read an entry of {}: {e}", dir.display()))?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(rel) = path.strip_prefix(dir) {
                out.push(
                    rel.to_string_lossy()
                        .replace('\\', "/")
                        .to_ascii_lowercase(),
                );
            } else {
                // a path outside the root we were asked about: treat as unexpected content
                out.push(
                    path.to_string_lossy()
                        .replace('\\', "/")
                        .to_ascii_lowercase(),
                );
            }
        }
    }
    Ok(out)
}

/// Delete the deployment tree only when the evidence says it is ours and holds nothing else.
///
/// Any refusal is printed with its reason: an uninstall that quietly leaves a directory behind is
/// still an honest one, while one that quietly deletes a directory it assumed was its own is not.
fn remove_deployed_image(registered_image: Option<&str>, service_gone: bool) {
    let deployed = std::path::Path::new(DEPLOY_DIR).join("cm400d.exe");
    let Some(root) = deployed.parent().and_then(|b| b.parent()) else {
        println!("    deployed image   : kept, the deployment path has no usable parent");
        return;
    };
    if !root.exists() {
        println!(
            "    deployed image   : nothing to remove at {}",
            root.display()
        );
        return;
    }
    let entries = match tree_entries(root) {
        Ok(e) => e,
        Err(e) => {
            println!("    deployed image   : kept, the tree could not be inspected: {e}");
            return;
        }
    };
    match deploy_removal_decision(registered_image, service_gone, &deployed, &entries) {
        DeployRemoval::Remove => match std::fs::remove_dir_all(root) {
            Ok(()) if !root.exists() => {
                println!(
                    "    deployed image   : {} removed, absence verified",
                    root.display()
                )
            }
            Ok(()) => println!(
                "    deployed image   : removal reported but {} is still present",
                root.display()
            ),
            Err(e) => println!(
                "    deployed image   : kept, {} could not be removed: {e}",
                root.display()
            ),
        },
        DeployRemoval::Keep(why) => println!("    deployed image   : kept - {why}"),
    }
}

/// The two uninstall-side decisions, asserted as decisions (the real flow also needs an SCM, a driver
/// store and two certificate stores, and a unit test must not touch any of them).
#[cfg(test)]
mod uninstall_decision_tests {
    use super::*;

    const DEPLOYED: &str = r"C:\Program Files\CM400\bin\cm400d.exe";

    fn image_with(path: &str) -> Option<String> {
        Some(format!("\"{path}\" --service"))
    }

    fn deploy(image: Option<String>, gone: bool, files: &[&str]) -> DeployRemoval {
        let entries: Vec<String> = files.iter().map(|f| f.to_string()).collect();
        deploy_removal_decision(
            image.as_deref(),
            gone,
            std::path::Path::new(DEPLOYED),
            &entries,
        )
    }

    #[test]
    fn the_deployed_tree_goes_only_when_every_condition_holds_at_once() {
        assert_eq!(
            deploy(image_with(DEPLOYED), true, &["bin/cm400d.exe"]),
            DeployRemoval::Remove,
            "the registered image is ours, the service is gone, the tree holds only our file"
        );
        assert_eq!(
            deploy(image_with(DEPLOYED), true, &[]),
            DeployRemoval::Remove,
            "an already-empty tree is still ours to remove"
        );
    }

    /// Each missing piece of evidence on its own is enough to keep the directory.
    #[test]
    fn any_missing_evidence_keeps_the_deployed_tree() {
        match deploy(None, true, &["bin/cm400d.exe"]) {
            DeployRemoval::Keep(why) => assert!(why.contains("could not be read"), "{why}"),
            other => panic!("{other:?}"),
        }
        // a *different* image path, even one that contains ours as a substring, is never a match
        for other in [
            r"D:\other\cm400d.exe",
            r"C:\Program Files\CM400\bin\cm400d.exe.bak",
            r"C:\Program Files\CM400\bin2\cm400d.exe",
        ] {
            match deploy(image_with(other), true, &["bin/cm400d.exe"]) {
                DeployRemoval::Keep(why) => {
                    assert!(
                        why.contains("not this product's deployed image"),
                        "{other}: {why}"
                    )
                }
                removed => panic!("{other} must not authorize a removal: {removed:?}"),
            }
        }
        match deploy(image_with(DEPLOYED), false, &["bin/cm400d.exe"]) {
            DeployRemoval::Keep(why) => assert!(why.contains("still present"), "{why}"),
            other => panic!("{other:?}"),
        }
        match deploy(
            image_with(DEPLOYED),
            true,
            &["bin/cm400d.exe", "bin/notes.txt"],
        ) {
            DeployRemoval::Keep(why) => assert!(why.contains("notes.txt"), "{why}"),
            other => panic!("{other:?}"),
        }
        // an unparseable registration is refused rather than compared loosely
        match deploy(
            Some(r#"C:\Program Files\CM400\bin\cm400d.exe" --service""#.to_string()),
            true,
            &["bin/cm400d.exe"],
        ) {
            DeployRemoval::Keep(why) => assert!(why.contains("parseable"), "{why}"),
            other => panic!("{other:?}"),
        }
    }

    fn record(refused: &[&str], failed: &[&str], present: &[&str]) -> RecordRemoval {
        record_removal_decision(
            &refused.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            &failed.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            &present.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
    }

    #[test]
    fn the_record_goes_only_after_cleanup_is_confirmed() {
        assert_eq!(record(&[], &[], &[]), RecordRemoval::Remove);
        // refused cleanup keeps it, with the reason carried through
        match record(&["Root: DACL unreadable"], &[], &[]) {
            RecordRemoval::Keep(why) => assert!(why.contains("refused"), "{why}"),
            other => panic!("{other:?}"),
        }
        // a store that could not be enumerated is not proof of absence
        match record(
            &[],
            &["TrustedPublisher: access denied"],
            &["TrustedPublisher"],
        ) {
            RecordRemoval::Keep(why) => assert!(why.contains("enumerated"), "{why}"),
            other => panic!("{other:?}"),
        }
        // a certificate that is still there means the record is still guarding somebody's trust
        match record(&[], &[], &["Root"]) {
            RecordRemoval::Keep(why) => assert!(why.contains("Root"), "{why}"),
            other => panic!("{other:?}"),
        }
        // refusal outranks everything else, since it also explains the presence
        assert!(matches!(
            record(&["cleanup refused"], &["x"], &["Root"]),
            RecordRemoval::Keep(_)
        ));
    }

    /// The entries helper is the tree's evidence, so "could not read" must not arrive as "empty".
    #[test]
    fn tree_entries_report_an_unreadable_directory_as_an_error() {
        let missing =
            std::env::temp_dir().join(format!("cm400-no-such-tree-{}", std::process::id()));
        let err = tree_entries(&missing)
            .expect_err("a directory that cannot be listed is not an empty one");
        assert!(err.contains("cannot list"), "{err}");

        let dir = std::env::temp_dir().join(format!("cm400-tree-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        std::fs::write(dir.join("bin").join("cm400d.exe"), b"x").unwrap();
        let got = tree_entries(&dir).expect("a real tree can be listed");
        assert_eq!(
            got,
            vec!["bin/cm400d.exe".to_string()],
            "relative, slash-separated, lowercased"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Uninstall, and only uninstall: removes the service registration, the driver package this product
/// published, its deployed image, and the state file. Nothing else is touched: no other device's
/// package, and never MI_00/MI_01 (which stay on their native usbvideo binding by construction - we
/// match our INF's original name, so another vendor's package cannot be selected).
fn uninstall_flow() {
    println!("[1] stop and remove the service");
    // What the SCM currently has registered, read before anything is removed: it is the only evidence
    // that the deployment directory really belonged to this service, and after `sc delete` it is gone.
    let (_, qc_before) = run("sc.exe", &["qc", "CM400Driver"]);
    let registered_image = service_field(&qc_before, "BINARY_PATH_NAME");
    let registered_image = (!registered_image.is_empty()).then_some(registered_image.as_str());
    let _ = run("sc.exe", &["stop", "CM400Driver"]);
    std::thread::sleep(std::time::Duration::from_secs(3));
    let (c, o) = run("sc.exe", &["delete", "CM400Driver"]);
    println!(
        "    sc delete exit   : {c}  {}",
        o.lines().last().unwrap_or("").trim()
    );
    // The exit code is not the fact. `sc delete` can report success while the service is still
    // running and marked for deletion, and deleting the image under it would be deleting a file a live
    // process has open - so ask the SCM whether the registration is actually gone.
    let mut service_gone = false;
    for _ in 0..10 {
        let (qc, _) = run("sc.exe", &["qc", "CM400Driver"]);
        if qc != 0 {
            service_gone = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    println!("    registration gone after delete: {service_gone}");
    remove_deployed_image(registered_image, service_gone);

    println!("[2] remove OUR published driver package only (matched by original name)");
    let (_, all) = run("pnputil.exe", &["/enum-drivers"]);
    // Normalize line endings FIRST: pnputil emits CRLF, so the blank line between
    // packages is "\r\n\r\n" and splitting on "\n\n" never separated anything. That
    // bug made the whole output look like one block containing both our INF and
    // libwdi, so the safety guard excluded every package and nothing was removed
    // (measured: uninstall reported success while oem65.inf stayed in the store).
    let all = all.replace("\r\n", "\n");
    let mut mine: Vec<String> = Vec::new();
    for block in all.split("\n\n") {
        if block.contains("cm400.inf") && !block.contains("libwdi") {
            if let Some(i) = block.find("oem") {
                let j = block[i..]
                    .find(".inf")
                    .map(|j| i + j + 4)
                    .unwrap_or(block.len());
                mine.push(block[i..j].to_string());
            }
        }
    }
    if mine.is_empty() {
        println!("    nothing staged under original name cm400.inf");
    }
    for pkg in mine {
        let (c, o) = run("pnputil.exe", &["/delete-driver", &pkg, "/uninstall"]);
        println!(
            "    delete {pkg}   : exit {c}  {}",
            o.lines().last().unwrap_or("").trim()
        );
    }

    println!("[3] remove state and log files owned by CM400 Driver");
    // The rotated archives belong to the same bounded retention set; leaving them behind would
    // keep files the service created after the product is gone.
    let mut owned: Vec<String> = vec![
        "C:\\ProgramData\\CM400\\state\\state.kv".to_string(),
        "C:\\ProgramData\\CM400\\state\\state.kv.tmp".to_string(),
        "C:\\ProgramData\\CM400\\logs\\cm400d.log".to_string(),
    ];
    for index in 1..=cm400_windows::logging::LOG_KEEP {
        owned.push(format!("C:\\ProgramData\\CM400\\logs\\cm400d.log.{index}"));
    }
    for p in &owned {
        match std::fs::remove_file(p) {
            Ok(()) => println!("    removed {p}"),
            Err(e) if std::path::Path::new(p).exists() => println!("    FAILED to remove {p}: {e}"),
            Err(_) => println!("    not present: {p}"),
        }
    }
    println!("[4] remove this release's own certificate from the local trust stores");
    // Two independent rules apply here, and the second cannot override the first:
    //   - WHICH stores may be touched comes from the ownership record. A certificate that was already
    //     present before this product installed is not ours to delete, and a record that cannot be
    //     believed stops the cleanup rather than being treated as "no record".
    //   - WHICH certificate may be deleted is the pinned publishing identity, checked by DER SHA-256,
    //     SHA-1 handle, subject, self-signed status and store. The fingerprint file that arrives inside
    //     the package folder is never the authorization for a deletion.
    {
        use cm400_windows::cert_cleanup::{self, STORES};
        use cm400_windows::trust::PINNED_SHA1_THUMBPRINT;
        use cm400_windows::trust_ownership::{self, Cleanup};

        let mut refused: Vec<String> = Vec::new();
        // Heal first, on evidence only. This product's own data-tree hardening can leave the record
        // inheriting wider permissions than its boundary, and then the refusal below would be permanent
        // - the certificates we added could never be removed by the mechanism that is supposed to
        // remove them. A refusal to heal is reported and the strict rule stands.
        match cm400_windows::trust::heal_ownership_record() {
            Ok(Some(cm400_windows::trust_ownership::Repair::Repaired)) => {
                println!("    ownership record : permissions healed to the documented boundary before the cleanup decision")
            }
            Ok(Some(cm400_windows::trust_ownership::Repair::Refused(why))) => {
                println!("    ownership record : not believable and not healable: {why}")
            }
            Ok(Some(cm400_windows::trust_ownership::Repair::NotNeeded)) => {}
            Ok(None) => {}
            Err(errors) => {
                for e in errors {
                    println!("    ownership record : {e}");
                }
            }
        }
        match trust_ownership::cleanup_decision(trust_ownership::read_verified()) {
            Cleanup::Refused(reason) => {
                refused.push(reason);
            }
            Cleanup::Nothing(why) => {
                println!("    certificate cleanup: nothing to remove - {why}");
            }
            Cleanup::Targets(stores) => {
                if trust_ownership::read_verified().ok().flatten().is_none() {
                    println!("    ownership=unknown_legacy (no record existed; the approved legacy path applies)");
                }
                for store in &stores {
                    match cert_cleanup::remove_from(store, PINNED_SHA1_THUMBPRINT) {
                        Ok(true) => println!("    removed the pinned release identity from {store}, confirmed absent on re-read"),
                        Ok(false) => println!("    {store}: the pinned identity was not listed there"),
                        Err(e) => refused.push(format!("{store}: {e}")),
                    }
                }
            }
        }

        // Older releases were signed by a per-machine certificate that predates the fixed identity, so
        // a leftover trusted root would otherwise be stranded.
        //
        // The authorization here is the signed catalog, not a text file. The only legacy identity that
        // may be removed is the certificate that actually signed the `cm400.cat` being uninstalled, as
        // resolved by crypt32 - `catalog_signer` verifies the signature before it names a signer, so a
        // certificate that merely appears in the message or merely appears in a file cannot authorize
        // a deletion. No catalog, no verified signature, no legacy cleanup, and that absence is
        // reported instead of being guessed around.
        //
        // A refusal above still stops this entirely.
        if refused.is_empty() {
            let exe = std::env::current_exe().unwrap_or_default();
            let base = exe
                .parent()
                .unwrap_or(std::path::Path::new("."))
                .to_path_buf();
            let cat = base.join("cm400.cat");
            let legacy = match cm400_windows::native_trust::catalog_signer(&cat.to_string_lossy()) {
                Ok(signer) if signer.sha256_der != cm400_windows::trust::PINNED_SHA256_DER => {
                    // the fingerprint artifact is cross-checked, never trusted as the source of a
                    // deletion decision
                    if let Some(named) = cert_cleanup::read_fingerprint(&base) {
                        if named != signer.thumbprint {
                            println!(
                                "    legacy identity : the artifact names {named} but this catalog was signed by {}; acting on the signed identity only",
                                signer.thumbprint
                            );
                        }
                    }
                    println!(
                        "    legacy identity : this package was signed by {} ({}) - not the pinned identity",
                        signer.thumbprint, signer.subject
                    );
                    Some(signer.thumbprint)
                }
                Ok(_) => None,
                Err(e) => {
                    println!(
                        "    legacy identity : nothing cleaned - no signed catalog beside this uninstaller to prove an old identity ({e})"
                    );
                    None
                }
            };
            if let Some(legacy) = legacy {
                for store in STORES {
                    match cert_cleanup::remove_from(store, &legacy) {
                        Ok(true) => println!(
                            "    removed the identity that signed this package from {store}, confirmed absent on re-read"
                        ),
                        Ok(false) => {}
                        Err(e) => refused.push(format!("{store} (legacy {legacy}): {e}")),
                    }
                }
            }
        } else {
            println!("    legacy per-machine cleanup also skipped: the ownership state is not trustworthy");
        }

        // "still listed" and "could not be checked" are different answers, and only the first of them
        // lets the ownership record be retired: an unverified store is a reason to keep the record,
        // not a reason to assume the certificate is gone.
        let mut enum_failed: Vec<String> = Vec::new();
        let still: Vec<String> = STORES
            .iter()
            .filter(|s| match cert_cleanup::find_all_thumbprints(s) {
                Ok(list) => list.iter().any(|t| t == PINNED_SHA1_THUMBPRINT),
                Err(e) => {
                    enum_failed.push(format!("{s}: {e}"));
                    true
                }
            })
            .map(|s| s.to_string())
            .collect();
        println!(
            "    pinned identity still trusted in: {}",
            if still.is_empty() {
                "nowhere".to_string()
            } else {
                still.join(", ")
            }
        );
        // The record exists to make a future cleanup precise. Once this one has actually succeeded it
        // has nothing left to describe, and leaving it behind would let a later install read a stale
        // claim of ownership over a certificate that is no longer trusted.
        match record_removal_decision(&refused, &enum_failed, &still) {
            RecordRemoval::Remove => {
                let target = cm400_windows::trust_ownership::path();
                if target.exists() {
                    match std::fs::remove_file(&target) {
                        // confirmed by absence, not by the call returning
                        Ok(()) if !target.exists() => {
                            println!("    ownership record : removed after confirmed cleanup, absence verified")
                        }
                        Ok(()) => println!(
                            "    ownership record : removal reported but {} is still there",
                            target.display()
                        ),
                        Err(e) => println!(
                            "    ownership record : kept, removal failed for {}: {e}",
                            target.display()
                        ),
                    }
                } else {
                    println!("    ownership record : already absent");
                }
            }
            RecordRemoval::Keep(why) => println!("    ownership record : kept - {why}"),
        }
        if !refused.is_empty() {
            for r in &refused {
                eprintln!("    certificate cleanup REFUSED: {r}");
            }
            println!("    uninstall is NOT complete: no certificate was removed, because its ownership could not be established");
            std::process::exit(37);
        }
    }
    println!("[5] MI_00/MI_01 were never referenced by these steps; a motor-interface");
    println!("    package deletion cannot affect the native UVC binding.");
}

#[cfg(test)]
mod trust_tests {
    // The module moved into the library so the installer and the development harness share it; the
    // tests stay here and now exercise the library's copy, which is the copy that ships.
    use cm400_windows::native_trust::{catalog_signature, inf_catalog_membership};

    fn tmp(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(name);
        p
    }

    /// A file that is not signed at all must fail - a missing signature must never be
    /// reported as "trusted".
    #[test]
    fn unsigned_file_fails() {
        let f = tmp("cm400_test_unsigned.dat");
        std::fs::write(&f, b"not signed").unwrap();
        assert!(catalog_signature(f.to_str().unwrap()).is_err());
        let _ = std::fs::remove_file(&f);
    }

    /// A path that does not exist must fail rather than panic or report success.
    #[test]
    fn missing_file_fails() {
        assert!(catalog_signature("Z:\\nope\\missing.cat").is_err());
        assert!(inf_catalog_membership("Z:\\nope\\missing.inf", "Z:\\nope\\missing.cat").is_err());
    }

    /// A file that exists but is not a catalog must fail the signature check too - a
    /// missing/foreign format can never be reported as "trusted".
    #[test]
    fn non_catalog_file_fails_signature() {
        let inf = manifest_path("../../install/cm400.inf");
        if inf.exists() {
            assert!(catalog_signature(inf.to_str().unwrap()).is_err());
        }
    }

    fn manifest_path(rel: &str) -> std::path::PathBuf {
        let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.push(rel);
        p.canonicalize().unwrap_or(p)
    }

    /// The real pair must verify, and the same INF must NOT verify against a catalog
    /// that is not the one covering it (the INF/CAT mismatch case).
    #[test]
    fn real_pair_is_member_and_foreign_catalog_is_rejected() {
        let inf = manifest_path("../../install/cm400.inf");
        let cat = manifest_path("../../install/cm400.cat");
        if !inf.exists() || !cat.exists() {
            eprintln!("skip: no built catalog next to the INF");
            return;
        }
        let i = inf.to_str().unwrap();
        let c = cat.to_str().unwrap();
        match inf_catalog_membership(i, c) {
            Ok(()) => {}
            Err(e) => panic!("membership against its own catalog must hold: {e}"),
        }
        assert!(inf_catalog_membership(i, "C:\\windows\\inf\\input.inf").is_err());
    }

    /// A catalog covering a DIFFERENT file must not accept this INF: we build a second
    /// catalog only where the tooling is present, so this asserts the negative using the
    /// INF hashed against an unrelated existing catalog file on disk.
    #[test]
    fn foreign_catalog_does_not_accept_our_inf() {
        let inf = manifest_path("../../install/cm400.inf");
        if !inf.exists() {
            return;
        }
        let other = manifest_path("../../install/definitely-not-here.cat");
        assert!(inf_catalog_membership(inf.to_str().unwrap(), other.to_str().unwrap()).is_err());
    }
}

unsafe fn write_device_parameters(guid_text: &str) -> i32 {
    use windows::Win32::System::Registry::{
        RegCloseKey, RegQueryValueExW, RegSetValueExW, KEY_READ, KEY_SET_VALUE, REG_MULTI_SZ,
        REG_VALUE_TYPE,
    };

    // Locate the device through SetupAPI; never hand-assemble a registry path.
    let set = match SetupDiGetClassDevsW(
        None,
        wp("USB"),
        HWND::default(),
        DIGCF_PRESENT | DIGCF_ALLCLASSES,
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("SetupDiGetClassDevs: {e}");
            return 20;
        }
    };
    let mut dev: Option<SP_DEVINFO_DATA> = None;
    let mut i = 0u32;
    while dev.is_none() {
        let mut di: SP_DEVINFO_DATA = std::mem::zeroed();
        di.cbSize = std::mem::size_of::<SP_DEVINFO_DATA>() as u32;
        if SetupDiEnumDeviceInfo(set, i, &mut di).is_err() {
            break;
        }
        i += 1;
        let mut buf = [0u16; 512];
        if SetupDiGetDeviceInstanceIdW(set, &di, Some(&mut buf), None).is_ok()
            && from_wide(&buf).eq_ignore_ascii_case(MOTOR_INSTANCE)
        {
            dev = Some(di);
        }
    }
    let di = match dev {
        Some(d) => d,
        None => {
            let _ = SetupDiDestroyDeviceInfoList(set);
            eprintln!("MI_02 instance is not present");
            return 21;
        }
    };

    let hk = match SetupDiOpenDevRegKey(
        set,
        &di,
        DICS_FLAG_GLOBAL.0,
        0,
        DIREG_DEV,
        (KEY_SET_VALUE | KEY_READ).0,
    ) {
        Ok(k) => k,
        Err(e) => {
            let _ = SetupDiDestroyDeviceInfoList(set);
            eprintln!("SetupDiOpenDevRegKey(DIREG_DEV) failed: {e}");
            return 22;
        }
    };
    println!("hardware key   : opened via SetupDiOpenDevRegKey(DIREG_DEV)");

    // SetupDiOpenDevRegKey(DIREG_DEV) ALREADY returns the `Device Parameters` subkey
    // - measured: creating a "Device Parameters" child of it produced
    // `...\Device Parameters\Device Parameters`, which is why an earlier run seemed
    // to show Windows "reverting" a manual write. It never touched the real key.
    // So the value goes directly into the handle we were given.
    let target = hk;

    // REG_MULTI_SZ needs a double NUL terminator.
    let mut units: Vec<u16> = guid_text.encode_utf16().collect();
    units.push(0);
    units.push(0);
    let mut bytes: Vec<u8> = Vec::with_capacity(units.len() * 2);
    for u in &units {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    let err = RegSetValueExW(
        target,
        wp("DeviceInterfaceGUIDs"),
        0,
        REG_MULTI_SZ,
        Some(&bytes),
    );
    if err.is_err() {
        eprintln!("RegSetValueExW failed: {err:?}");
    } else {
        println!("write          : ok (REG_MULTI_SZ, directly into DIREG_DEV key)");
    }

    // Read back through the same handle: value, type and target must all be verified.
    let mut kind = REG_VALUE_TYPE::default();
    let mut size = 0u32;
    let q = RegQueryValueExW(
        target,
        wp("DeviceInterfaceGUIDs"),
        None::<*const u32>,
        Some(&mut kind),
        None::<*mut u8>,
        Some(&mut size),
    );
    if q.is_ok() && size > 0 {
        let mut raw = vec![0u8; size as usize];
        let mut got = size;
        let q2 = RegQueryValueExW(
            target,
            wp("DeviceInterfaceGUIDs"),
            None::<*const u32>,
            None::<*mut REG_VALUE_TYPE>,
            Some(raw.as_mut_ptr()),
            Some(&mut got),
        );
        if q2.is_ok() {
            let units: Vec<u16> = raw[..got as usize]
                .chunks_exact(2)
                .map(|p| u16::from_le_bytes([p[0], p[1]]))
                .collect();
            let texts: Vec<String> = units
                .split(|&c| c == 0)
                .filter(|s| !s.is_empty())
                .map(String::from_utf16_lossy)
                .collect();
            println!("read back      : type={kind:?} values={}", texts.join(";"));
        } else {
            println!("read back      : FAILED {q2:?}");
        }
    } else {
        println!("read back      : FAILED {q:?}");
    }

    let _ = RegCloseKey(hk);
    let _ = SetupDiDestroyDeviceInfoList(set);
    0
}

// Moved out of main(): the previous edit pasted these items inside the match body.

#[cfg(test)]
mod staging_tests {
    use super::*;

    fn uniq(tag: &str) -> String {
        format!("{}-{}", tag, std::process::id())
    }

    #[test]
    fn a_host_that_carries_no_bundle_falls_back_to_the_loose_layout() {
        // the test binary is not bundled, so this must be a plain "no bundle here" and not an error:
        // every pre-rc4 package and every CI script resolves its package from a directory argument
        assert!(
            stage_bundle()
                .expect("no bundle must not be an error")
                .is_none(),
            "an unbundled host must not invent a staged package"
        );
    }

    /// The DACL a staging directory actually gets, in the shape icacls prints.
    const STAGING_DACL: &str = "C:\\Users\\someone\\AppData\\Local\\Temp\\cm400-stage-1: NT AUTHORITY\\SYSTEM:(OI)(CI)(F)\r\n     BUILTIN\\Administrators:(OI)(CI)(F)\r\n";

    /// One extra trustee in the same printed shape, for the case where the boundary was widened.
    const WIDENED_DACL: &str = "C:\\Users\\someone\\AppData\\Local\\Temp\\cm400-stage-1: NT AUTHORITY\\SYSTEM:(OI)(CI)(F)\r\n     BUILTIN\\Administrators:(OI)(CI)(F)\r\n     MYCORP\\Bob:(OI)(CI)(F)\r\n";

    fn good_facts() -> SweepFacts {
        SweepFacts {
            name: format!("{STAGING_PREFIX}1234"),
            age_secs: Some(STAGING_MIN_AGE_SECS + 10),
            reparse: false,
            inside_expected_temp: true,
            owner_sid: Some("S-1-5-21-1-2-3-1001".to_string()),
            dacl: Some(STAGING_DACL.to_string()),
            owner_pid: None,
            pid_alive: None,
            structure: Vec::new(),
        }
    }

    #[test]
    fn a_dead_creating_process_makes_a_young_leftover_sweepable() {
        // a refused install ends the process without running the destructor's cleanup in every path; the
        // next run should still be able to tell "that pid is gone" from "that run may be live"
        let mut f = good_facts();
        f.name = format!("{STAGING_PREFIX}999998");
        f.age_secs = Some(5);
        f.owner_pid = Some(999_998);
        f.pid_alive = Some(false);
        assert!(
            Staged::sweep_verdict(&f, "S-1-5-21-1-2-3-1001").is_ok(),
            "a provably orphaned directory must not have to sit out the age window: {:?}",
            f
        );
    }

    #[test]
    fn a_live_creating_process_is_never_swept_and_an_unknown_one_neither() {
        let mut alive = good_facts();
        alive.name = format!("{STAGING_PREFIX}999997");
        alive.age_secs = Some(5);
        alive.owner_pid = Some(999_997);
        alive.pid_alive = Some(true);
        assert!(Staged::sweep_verdict(&alive, "S-1-5-21-1-2-3-1001").is_err());
        // the machine would not say: still no licence, even when the age is unreadable too
        let mut unknown = alive.clone();
        unknown.pid_alive = None;
        unknown.age_secs = None;
        let err = Staged::sweep_verdict(&unknown, "S-1-5-21-1-2-3-1001")
            .expect_err("an unknown liveness must not become permission");
        assert!(err.contains("creating run"), "unhelpful: {err}");
    }

    #[test]
    fn our_own_pid_is_never_treated_as_a_dead_one() {
        // impossible in reality, but the rule must not depend on that: our own staging directory belongs to
        // the run that is answering this question
        let mut f = good_facts();
        let me = std::process::id();
        f.name = format!("{STAGING_PREFIX}{me}");
        f.age_secs = None;
        f.owner_pid = Some(me);
        f.pid_alive = Some(false);
        assert!(
            Staged::sweep_verdict(&f, "S-1-5-21-1-2-3-1001").is_err(),
            "our own live directory must never be swept as an orphan"
        );
    }

    #[test]
    fn a_name_that_is_not_a_plain_pid_is_read_by_age_alone() {
        assert_eq!(Staged::pid_in_name("cm400-stage-4321"), Some(4321));
        assert_eq!(Staged::pid_in_name("cm400-stage-reuse-4321"), None);
        assert_eq!(Staged::pid_in_name("cm400-stage-"), None);
    }

    #[test]
    fn this_process_can_name_its_own_sid_without_reading_any_text() {
        // the sweep's owner test depends on this being a real SID, not a parse of localised tool output
        let me = Staged::current_user_sid();
        assert!(
            me.starts_with("S-1-") && me.matches('-').count() >= 3,
            "the token did not yield a SID: {me:?}"
        );
        // and the owner read has to agree with the sweep's rule for something this process created itself.
        // Equality with the token SID is NOT the property, and asserting it was the bug: measured in cloud
        // CI, a runner's directory came back owned by BUILTIN\Administrators rather than by the account that
        // made it - a normal Windows outcome for an administrative token, and still provably this run's own.
        let dir = std::env::temp_dir().join(format!("cm400-ownsid-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let owner = Staged::owner_sid_of(&dir);
        std::fs::remove_dir(&dir).ok();
        let owner =
            owner.unwrap_or_else(|| panic!("the owner of a directory we created is unreadable"));
        assert!(
            owner.starts_with("S-1-"),
            "the owner did not read back as a SID: {owner:?}"
        );
        assert!(
            Staged::owner_is_plausible(Some(owner.as_str()), &me),
            "our own directory is not recognisable as ours: owner {owner:?}, token {me:?}"
        );
    }

    #[test]
    fn an_administrator_that_is_not_us_is_still_foreign() {
        // the UAC-with-different-credentials case: another real admin SID must not become plausible just
        // because it is an administrator
        assert!(!Staged::owner_is_plausible(
            Some("S-1-5-21-999-999-999-500"),
            "S-1-5-21-1-2-3-1001"
        ));
        assert!(Staged::owner_is_plausible(
            Some("S-1-5-32-544"),
            "S-1-5-21-1-2-3-1001"
        ));
    }

    #[test]
    fn an_unexpected_entry_inside_the_directory_ends_the_ownership_claim() {
        let dir = std::env::temp_dir().join(format!("cm400-struct-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(
            structure_problems(&dir).is_empty(),
            "an empty directory is fine"
        );
        std::fs::write(dir.join("cm400d.exe"), b"x").unwrap();
        assert!(
            structure_problems(&dir).is_empty(),
            "a payload file is fine"
        );
        std::fs::create_dir(dir.join("sub")).unwrap();
        let problems = structure_problems(&dir);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("sub") && p.contains("directory")),
            "a subdirectory must end the claim: {problems:?}"
        );
        std::fs::remove_dir_all(dir.join("sub")).ok();
        // legal on Windows but never a name the bundle could carry (a space). A colon would be rejected
        // by the filesystem itself, so writing `weird:name` proves nothing about this rule.
        std::fs::write(dir.join("pay load.exe"), b"x").unwrap();
        let problems = structure_problems(&dir);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("bare payload file name")),
            "a name that is not a bare file must be reported: {problems:?}"
        );
        std::fs::remove_dir_all(&dir).ok();

        // and a directory that fails only on structure is refused even with a perfect DACL, owner and age
        let mut f = good_facts();
        f.structure = vec!["nested is a directory".to_string()];
        let err = Staged::sweep_verdict(&f, "S-1-5-21-1-2-3-1001")
            .expect_err("contents the product would not put there must stop the cleaner");
        assert!(err.contains("contents"), "unhelpful: {err}");
    }

    #[test]
    fn an_unknown_current_sid_makes_every_owner_foreign() {
        // fail closed: not knowing who we are must never turn into "the owner matches us"
        assert!(!Staged::owner_is_plausible(Some(""), ""));
        assert!(
            Staged::owner_is_plausible(Some("S-1-5-18"), ""),
            "SYSTEM is always a plausible creator"
        );
        assert!(Staged::owner_is_plausible(
            Some("S-1-5-21-1-2-3-1001"),
            "S-1-5-21-1-2-3-1001"
        ));
        assert!(!Staged::owner_is_plausible(
            Some("S-1-5-21-9-9-9-1001"),
            "S-1-5-21-1-2-3-1001"
        ));
    }

    #[test]
    fn a_directory_we_can_prove_is_ours_and_stale_is_swept() {
        assert!(
            Staged::sweep_verdict(&good_facts(), "S-1-5-21-1-2-3-1001").is_ok(),
            "the normal leftover case must not be refused, or stale verified bytes pile up in TEMP"
        );
    }

    #[test]
    fn a_forged_name_with_an_unexpected_owner_is_never_swept() {
        let mut f = good_facts();
        f.owner_sid = Some("S-1-5-21-9-9-9-4242".to_string());
        let err = Staged::sweep_verdict(&f, "S-1-5-21-1-2-3-1001")
            .expect_err("a name we recognise is not an ownership proof");
        assert!(err.contains("owner"), "unhelpful: {err}");
        // SYSTEM and Administrators are legitimate owners of a directory the product created
        for sid in ["S-1-5-18", "S-1-5-32-544"] {
            let mut ours = good_facts();
            ours.owner_sid = Some(sid.to_string());
            assert!(Staged::sweep_verdict(&ours, "S-1-5-21-1-2-3-1001").is_ok());
        }
        // and an owner that cannot be read is not a licence to delete either
        let mut unknown = good_facts();
        unknown.owner_sid = None;
        assert!(Staged::sweep_verdict(&unknown, "S-1-5-21-1-2-3-1001").is_err());
    }

    #[test]
    fn a_reparse_point_is_never_swept_recursively() {
        let mut f = good_facts();
        f.reparse = true;
        let err = Staged::sweep_verdict(&f, "S-1-5-21-1-2-3-1001")
            .expect_err("deleting through a reparse point removes what it points at");
        assert!(err.contains("reparse"), "unhelpful: {err}");
    }

    #[test]
    fn an_unreadable_age_is_treated_as_a_live_run() {
        let mut f = good_facts();
        f.age_secs = None;
        assert!(
            Staged::sweep_verdict(&f, "S-1-5-21-1-2-3-1001").is_err(),
            "unknown age must not become permission"
        );
        let mut young = good_facts();
        young.age_secs = Some(STAGING_MIN_AGE_SECS - 1);
        assert!(Staged::sweep_verdict(&young, "S-1-5-21-1-2-3-1001").is_err());
    }

    #[test]
    fn a_directory_outside_the_expected_temp_is_not_swept() {
        let mut f = good_facts();
        f.inside_expected_temp = false;
        let err = Staged::sweep_verdict(&f, "S-1-5-21-1-2-3-1001")
            .expect_err("canonical containment is checked, not assumed from the path string");
        assert!(err.contains("temporary directory"), "unhelpful: {err}");
    }

    #[test]
    fn an_altered_dacl_is_left_alone_instead_of_being_fixed_then_deleted() {
        // a stranger granted write: this is not the boundary a staging directory gets
        let mut f = good_facts();
        f.dacl = Some(WIDENED_DACL.to_string());
        let err = Staged::sweep_verdict(&f, "S-1-5-21-1-2-3-1001")
            .expect_err("a rewritten DACL must stop the cleaner, not be repaired by it");
        assert!(err.contains("DACL"), "unhelpful: {err}");
        // and a DACL that lost the administrators' right, or cannot be read at all
        let mut stripped = good_facts();
        stripped.dacl = Some("C:\\x: NT AUTHORITY\\SYSTEM:(RX)\r\n".to_string());
        assert!(Staged::sweep_verdict(&stripped, "S-1-5-21-1-2-3-1001").is_err());
        let mut unreadable = good_facts();
        unreadable.dacl = None;
        assert!(Staged::sweep_verdict(&unreadable, "S-1-5-21-1-2-3-1001").is_err());
    }

    #[test]
    fn a_name_that_is_not_ours_is_not_even_examined() {
        let mut f = good_facts();
        f.name = "node_modules".to_string();
        assert!(Staged::sweep_verdict(&f, "S-1-5-21-1-2-3-1001").is_err());
        f.name = "cm400-stage-sibling-but-deeper".to_string();
        assert!(
            Staged::sweep_verdict(&f, "S-1-5-21-1-2-3-1001").is_ok(),
            "our prefix still matches"
        );
    }

    #[test]
    fn create_refuses_to_reuse_a_directory_that_already_exists() {
        let tag = uniq("reuse");
        let dir = std::env::temp_dir().join(format!("{STAGING_PREFIX}{tag}"));
        std::fs::create_dir_all(&dir).unwrap();
        let err = Staged::create(&tag)
            .expect_err("reusing a directory would let one run judge another's bytes");
        assert!(err.contains("already exists"), "unhelpful failure: {err}");
        assert!(
            std::fs::remove_dir(&dir).is_ok() || !dir.exists(),
            "test left {} behind",
            dir.display()
        );
    }

    #[test]
    fn a_staged_directory_is_closed_to_everyone_but_the_two_administrators() {
        // measured, and it is the property rather than a limitation: an unelevated run cannot even
        // delete the staging directory it created, so nothing outside SYSTEM and Administrators can
        // replace or remove the bytes the catalog gates are about to judge
        let tag = uniq("dacl");
        let staged =
            Staged::create(&tag).expect("create must succeed on a directory this run owns");
        let report = icacls_report(staged.dir()).expect("the DACL must be readable back");
        assert!(
            !cm400_windows::security::standard_user_can_perturb(&report),
            "ordinary users may perturb the staging directory:\n{report}"
        );
        for trustee in DEPLOY_ALLOWED_WRITERS {
            assert!(
                cm400_windows::security::principal_can_write(&report, trustee, false),
                "{trustee} must be able to manage the staging directory so the elevated installer can clean it up"
            );
        }
        // let this (unelevated) test process take the directory back so the test leaves nothing behind;
        // an installer running elevated already holds what this call only simulates
        let ours = whoami_sid();
        let mut grants = staging_grants(staged.dir());
        if let Some(sid) = ours {
            grants.push(format!("*{sid}:(OI)(CI)F"));
        }
        apply_and_verify(staged.dir(), grants).ok();
        staged.remove().ok();
    }

    fn whoami_sid() -> Option<String> {
        let (code, out) = run("whoami.exe", &["/user", "/sid"]);
        if code != 0 {
            return None;
        }
        out.lines()
            .map(|l| l.trim().to_string())
            .find(|l| l.starts_with("S-1-"))
    }
    #[test]
    fn removal_reports_failure_instead_of_claiming_success() {
        // point it at a regular file: remove_dir_all cannot do that, and the call must say so rather
        // than returning Ok and letting the installer believe the bytes are gone
        let dir = std::env::temp_dir().join(format!("{STAGING_PREFIX}{}", uniq("asfile")));
        std::fs::write(&dir, b"x").unwrap();
        let staged = Staged { dir: dir.clone() };
        assert!(
            staged.remove().is_err(),
            "a path that is not our directory must not be reported as cleaned"
        );
        std::fs::remove_file(&dir).ok();
    }

    #[test]
    fn a_removal_that_cannot_finish_is_reported_and_not_claimed_as_done() {
        // the cleanup path must not turn "I could not delete this" into success; an unelevated process is
        // denied on its own staging directory, which is exactly the state a real abort can leave
        let tag = uniq("leak");
        let staged = Staged::create(&tag).expect("create");
        let dir = staged.dir().to_path_buf();
        let first = staged.remove();
        match first {
            Err(e) => {
                // refused: prove the directory is still there, so the operator can act on the warning
                assert!(
                    dir.exists(),
                    "a refused cleanup must not have half-deleted the directory: {e}"
                );
                let ours = whoami_sid();
                let mut grants = staging_grants(&dir);
                if let Some(sid) = ours {
                    grants.push(format!("*{sid}:(OI)(CI)F"));
                }
                apply_and_verify(&dir, grants).ok();
                std::fs::remove_dir_all(&dir).ok();
            }
            Ok(()) => {
                assert!(!dir.exists(), "removed must mean removed");
            }
        }
    }
}
