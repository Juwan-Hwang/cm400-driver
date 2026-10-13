//! cm400d — CM400 Driver host.
//!
//! 2-C: ONE runtime, two hosts. `--console` is the dev host; `--service` is the
//! product host (SCM + LocalService). Neither holds any product logic — they
//! only translate a lifecycle into `run_runtime(&STOP)`. Everything the driver
//! knows (Activity, Motor, Policy, persistence) lives behind that one call.

use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use cm400_windows::log;
use cm400_windows::runtime::{run_runtime, Role, Runtime, SERVICE_NAME};
use windows::Win32::Foundation::BOOL;
use windows::Win32::System::Console::SetConsoleCtrlHandler;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::{define_windows_service, service_dispatcher};

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

static STOP: AtomicBool = AtomicBool::new(false);

unsafe extern "system" fn on_ctrl(_ctrl_type: u32) -> BOOL {
    STOP.store(true, Ordering::SeqCst);
    true.into()
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    match arg.as_str() {
        "--console" | "" => {
            unsafe {
                let _ = SetConsoleCtrlHandler(Some(on_ctrl), true);
            }
            if let Err(e) = run_runtime(&STOP) {
                eprintln!("cm400d error: {}", e);
                std::process::exit(2);
            }
        }
        "--service" => {
            // Blocking until SCM says the service is done.
            if let Err(e) = service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
                // No console here, so the only way to see this is the log.
                log(&format!(
                    "service_dispatcher::start failed: {e} (is this launched by SCM?)"
                ));
                std::process::exit(3);
            }
        }
        other => {
            eprintln!("usage: cm400d [--console|--service]  (got: {})", other);
            std::process::exit(1);
        }
    }
}

define_windows_service!(ffi_service_main, service_main);

/// Service entry, called by SCM on its own thread with the service arguments.
fn service_main(_args: Vec<OsString>) {
    // Register the control handler first: until we do, SCM cannot ask us to stop.
    // The handler only signals; status reporting stays with `service_main`, which
    // owns the status handle (our drain is <1s, well inside SCM's stop window).
    let handle = match service_control_handler::register(SERVICE_NAME, control_handler) {
        Ok(h) => h,
        Err(e) => {
            log(&format!("service: cannot register control handler: {e}"));
            return;
        }
    };

    // Report StartPending before any real work (SCM requirement), then bring up
    // the shared runtime on this thread.
    report(
        &handle,
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        1,
        Duration::from_secs(20),
    );
    log("service: StartPending reported; initializing runtime");

    // Initialize BEFORE reporting Running: SCM must not claim a half-built
    // driver is working, and a failed init has to end as Stopped, not hang.
    // Role::Service = machine-wide mutex + the fixed ETW session to reclaim.
    // The backend comes from the runtime configuration only: an absent or invalid
    // `activity_backend` stays on the shipped fail-closed Shadow path, and the startup line prints
    // both the backend and where the choice came from, so a deployment cannot claim otherwise.
    //
    // The former `--r2-latch-experiment` argument was removed: `arbitrating` is reachable through
    // the config file now, and a second, older way to select the same backend would only be a
    // stale interface that a deployment could disagree with.
    let mut rt = match Runtime::init(Role::Service) {
        Ok(rt) => rt,
        Err(e) => {
            log(&format!("service: init failed ({e}); reporting Stopped"));
            report(
                &handle,
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                0,
                Duration::from_secs(0),
            );
            return;
        }
    };

    report(
        &handle,
        ServiceState::Running,
        ServiceControlAccept::STOP
            | ServiceControlAccept::SHUTDOWN
            | ServiceControlAccept::PRESHUTDOWN,
        0,
        Duration::from_secs(0),
    );
    log("service: Running");

    // No experimental control path lives here any more. The IKsControl-side probe was removed from
    // the service: migrating to that path was stopped, and a service binary that can be told to move
    // the lens through an unvalidated second channel is an operation surface a release should not
    // carry. The probe itself is not lost - it stays as the standalone `cm400-iks-probe` diagnostic
    // tool, which is excluded from the shipped artifacts by the release manifest rather than by
    // deletion of the evidence.

    if let Err(e) = rt.run(&STOP) {
        log(&format!("service: runtime ended with error: {e}"));
    }
    // Drop the runtime *before* Stopped so the ETW session is really gone
    // (CloseTrace + ControlTrace STOP + WinUSB close) when SCM sees us stopped.
    drop(rt);
    report(
        &handle,
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        0,
        Duration::from_secs(0),
    );
    log("service: Stopped reported");
}

/// STOP/SHUTDOWN/PRESHUTDOWN -> ask the shared runtime to leave its loop, so it
/// can tear the ETW session down itself instead of being killed mid-travel.
fn control_handler(ctrl: ServiceControl) -> ServiceControlHandlerResult {
    match ctrl {
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
            log("service: stop requested; draining runtime");
            STOP.store(true, Ordering::SeqCst);
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    }
}

fn report(
    handle: &ServiceStatusHandle,
    state: ServiceState,
    controls: ServiceControlAccept,
    checkpoint: u32,
    wait_hint: Duration,
) {
    let _ = handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        controls_accepted: controls,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint,
        wait_hint,
        process_id: None,
    });
}
