//! Read-only status reporting, shared by the daemon's control tool and the installer.
//!
//! There is one implementation on purpose. Two binaries that each grew their own idea of "the current
//! state" is how the two sides came to disagree about the lens before, and an installer that guesses at
//! whether the product is installed will act on that guess.
//!
//! Everything here is a read: registry-free, no motor command, no service start or stop, no write to any
//! state file. The optional transport probe is deliberately a separate switch, because opening MI_02 to
//! ask for an echo is a device interaction and the installer's `status` must not perform one.

use crate::config::Config;
use crate::runtime::SERVICE_NAME;
use crate::{find_motor_interface, MotorChannel};
use cm400_core::Store;
use std::path::Path;
use std::process::Command;

/// The deployed daemon image, if the given location exists. Returns the path with its SHA-256, or the
/// reason it could not be read - "absent", "unreadable" and "could not be parsed" are three different
/// answers and must not be collapsed into one, because the installer chooses between install and
/// maintenance on exactly this difference.
pub fn deployed_image(p: &Path) -> (String, String) {
    if !p.exists() {
        return (p.to_string_lossy().to_string(), "ABSENT".to_string());
    }
    let out = Command::new("certutil.exe")
        .args(["-hashfile", &p.to_string_lossy(), "SHA256"])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout).to_string();
            let digest = text
                .lines()
                .map(|l| {
                    l.trim()
                        .chars()
                        .filter(|c| !c.is_whitespace() && *c != ':')
                        .collect::<String>()
                        .to_ascii_uppercase()
                })
                .find(|l| l.len() == 64 && l.chars().all(|c| c.is_ascii_hexdigit()))
                .unwrap_or_else(|| "PARSE_FAILED".to_string());
            (p.to_string_lossy().to_string(), digest)
        }
        Ok(o) => (
            p.to_string_lossy().to_string(),
            format!(
                "UNREADABLE (certutil exit {}: {})",
                o.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&o.stderr).trim()
            ),
        ),
        Err(e) => (
            p.to_string_lossy().to_string(),
            format!("UNREADABLE (cannot run certutil: {e})"),
        ),
    }
}

/// What the service control manager says about our service: state, start type, account and image path.
/// An absent service is reported as ABSENT rather than as "stopped", because the installer's decision
/// between "install" and "maintain" turns on exactly that difference.
pub fn service_facts() -> Vec<(String, String)> {
    service_facts_named(SERVICE_NAME)
}

/// The same report for a service named by the caller. This exists so the "no such service" branch can be
/// tested on a machine that does have CM400 installed: hard-coding the name meant the absent-service path
/// was only ever exercised by a machine nobody could choose, and that is the path that broke in cloud CI.
pub fn service_facts_named(service: &str) -> Vec<(String, String)> {
    let mut facts = Vec::new();
    let out = Command::new("sc.exe").args(["qc", service]).output();
    let (code, text) = match out {
        Ok(o) => (
            o.status.code().unwrap_or(-1),
            format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            ),
        ),
        Err(e) => {
            facts.push((
                "STATE".to_string(),
                format!("UNREADABLE (cannot run sc.exe: {e})"),
            ));
            return facts;
        }
    };
    if code != 0 {
        // Two different questions, two answers. Whether the service is running is not something `sc qc`
        // knows, so a failed configuration read must not stand in for the run state: ask the command that
        // does. The key is the same uppercase one every other path writes - consumers compare these keys
        // case-sensitively, and a lowercase one here made an uninstalled machine report no state at all.
        facts.push(("STATE".to_string(), running_state_named(service)));
        facts.push((
            "CONFIG".to_string(),
            if text.contains("1060") {
                "ABSENT (no such service)".to_string()
            } else {
                format!("UNREADABLE (sc qc exit {code})")
            },
        ));
        return facts;
    }
    for key in [
        "SERVICE_NAME",
        "START_TYPE",
        "SERVICE_START_NAME",
        "BINARY_PATH_NAME",
    ] {
        let value = text
            .lines()
            .find(|l| l.trim_start().starts_with(key))
            .map(|l| {
                l.split_once(':')
                    .map(|(_, v)| v.trim().to_string())
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        facts.push((key.to_string(), value));
    }
    // `sc qc` never reports whether the service is running - measured: its output carries no STATE line at
    // all, because QueryServiceConfig does not know the run state. Asking the wrong command printed an
    // empty field, which a human reads as "stopped". The state comes from `sc query`.
    facts.push(("STATE".to_string(), running_state_named(service)));
    facts
}

/// The run state of this product's service, or the reason it could not be had. Absent and unreadable stay separate answers, so an
/// installer does not offer to uninstall a service nobody has actually seen.
fn running_state_named(service: &str) -> String {
    let out = match Command::new("sc.exe").args(["query", service]).output() {
        Ok(o) => o,
        Err(e) => return format!("UNREADABLE (cannot run sc.exe: {e})"),
    };
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if !out.status.success() {
        return if text.contains("1060") {
            "ABSENT (no such service)".to_string()
        } else {
            format!(
                "UNREADABLE (sc query exit {})",
                out.status.code().unwrap_or(-1)
            )
        };
    }
    text.lines()
        .find(|l| l.trim_start().starts_with("STATE"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_else(|| "UNREADABLE (sc query printed no STATE line)".to_string())
}

/// The lines both tools print. `probe_transport` is opt-in: it opens the motor interface to ask for a
/// state variable echo, which is a device interaction and not needed to answer "is this installed, and
/// what does the daemon think the lens is doing".
pub fn status_lines(deployed: &Path, probe_transport: bool) -> Vec<String> {
    let mut out = Vec::new();
    match find_motor_interface() {
        Some((_, via)) => out.push(format!(
            "device          : present (MI_02 interface found via {via})"
        )),
        None => {
            out.push("device          : absent (no MI_02 interface under either GUID)".to_string())
        }
    }
    for (k, v) in service_facts() {
        out.push(format!("service {k:14}: {v}"));
    }
    let (path, digest) = deployed_image(deployed);
    out.push(format!("deployed image  : {path}"));
    out.push(format!("    sha256        : {digest}"));
    let persisted = cm400_persistence::FileStore::new(Config::state_path()).load();
    out.push(format!("persisted       : {persisted:?}"));
    if probe_transport {
        let mut ch = MotorChannel::new();
        match ch.get() {
            Ok(echo) => out.push(format!(
                "motor transport : available (echo={echo} - a state var, NOT physical position)"
            )),
            Err(e) => out.push(format!(
                "motor transport : unavailable ({e:?}) - another opener holds MI_02; stop the service to take over"
            )),
        }
    }
    out
}

/// Whether the product is present, decided on observable facts and never on a single flag. Both halves
/// are required, because a service that was registered but whose image was deleted is a broken install
/// rather than an installed product - and answering that case wrongly is how a maintenance menu offers
/// the wrong operation.
#[derive(Debug, PartialEq, Eq)]
pub enum InstallState {
    NotInstalled,
    Installed,
    /// Registered but incomplete: needs repair, and must not be treated as a clean install.
    Partial(String),
}

pub fn install_state(deployed: &Path) -> InstallState {
    let facts = service_facts();
    let registered = facts
        .iter()
        .any(|(k, v)| k == "SERVICE_NAME" && !v.is_empty());
    let absent = facts
        .iter()
        .any(|(k, v)| (k == "state" || k == "STATE") && v.starts_with("ABSENT"));
    let unreadable = facts
        .iter()
        .any(|(k, v)| (k == "state" || k == "STATE") && v.starts_with("UNREADABLE"));
    let (img_path, digest) = deployed_image(deployed);
    if unreadable {
        // an answer we could not get is not an answer; guessing "not installed" here would offer an
        // install over a state nobody has read
        return InstallState::Partial(format!(
            "the service database could not be read; refusing to decide ({digest})"
        ));
    }
    match (registered || !absent, digest.as_str()) {
        (true, "ABSENT") => InstallState::Partial(format!(
            "the service is registered but its image is missing at {img_path}"
        )),
        (true, _) => InstallState::Installed,
        (false, "ABSENT") => InstallState::NotInstalled,
        (false, _) => InstallState::Partial(format!(
            "no service is registered, yet a daemon image exists at {img_path}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_service_still_reports_a_state_a_caller_can_read() {
        // This branch used to be reachable only on a machine that happened not to have CM400 installed,
        // which is how it shipped a lowercase key nobody read: cloud CI was the first machine to walk it.
        // Naming a service that cannot exist makes the same path deterministic on every machine.
        let name = format!("CM400-NO-SUCH-SERVICE-{}", std::process::id());
        let facts = service_facts_named(&name);
        let state = facts
            .iter()
            .find(|(k, _)| k == "STATE")
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| panic!("an absent service reported no STATE field: {facts:?}"));
        assert!(
            state.contains("ABSENT") || state.contains("UNREADABLE"),
            "an absent service must not be reported as a running state: {state:?}"
        );
        let config = facts
            .iter()
            .find(|(k, _)| k == "CONFIG")
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| {
                panic!("a failed configuration read reported nothing about it: {facts:?}")
            });
        assert!(
            config.contains("ABSENT"),
            "1060 should be read as no such service, not as a permission problem: {config:?}"
        );
    }

    #[test]
    fn every_reported_key_is_uppercase() {
        // callers look these keys up by exact text, so a key that differs only in case is a key that does
        // not exist - which is precisely the defect that reached a machine without the service installed
        let name = format!("CM400-NO-SUCH-SERVICE-{}", std::process::id());
        for facts in [service_facts(), service_facts_named(&name)] {
            assert!(!facts.is_empty(), "a report with no fields is not a report");
            for (k, _) in &facts {
                assert_eq!(
                    *k,
                    k.to_uppercase(),
                    "fact keys are compared case-sensitively"
                );
            }
        }
    }

    #[test]
    fn service_facts_distinguish_absent_from_unreadable() {
        // whichever way this machine is configured, the reporter must produce an answer in one of the
        // three named shapes and never an empty value that a caller could read as "stopped"
        let facts = service_facts();
        assert!(
            !facts.is_empty(),
            "a query that produced no facts is not a report"
        );
        let state = facts
            .iter()
            .find(|(k, _)| k == "STATE")
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| panic!("the report has no STATE field at all"));
        // tightened on purpose: the previous version of this test accepted an empty STATE value, and an
        // empty value is exactly what asked `sc qc` for a state it never prints - a blank here reads as
        // "stopped" to whoever is deciding whether to install
        assert!(
            !state.is_empty(),
            "an empty STATE field is never an honest answer"
        );
        let recognised = state.contains("RUNNING")
            || state.contains("STOPPED")
            || state.contains("PAUSED")
            || state.contains("ABSENT")
            || state.contains("UNREADABLE");
        assert!(recognised, "unrecognised service state answer: {state:?}");
        // and the installation verdict never calls a machine clean on the strength of a state nobody read
        let state_verdict = install_state(std::path::Path::new(
            r"C:\Program Files\CM400\bin\cm400d.exe",
        ));
        assert!(
            !matches!(state_verdict, InstallState::NotInstalled) || state.contains("ABSENT"),
            "reported NotInstalled while the service state says {state:?}"
        );
    }

    #[test]
    fn a_missing_image_is_reported_absent_not_as_a_failure() {
        // a path that cannot exist on any machine, so the answer under test is the absent branch
        let nowhere =
            std::path::Path::new(r"C:\Program Files\CM400\definitely-not-here\cm400d.exe");
        let (path, digest) = deployed_image(nowhere);
        assert_eq!(
            digest, "ABSENT",
            "{path}: expected the absent answer, got {digest:?}"
        );
        // and a file that exists but is not hashable-by-name must not silently read as absent
        let dir = std::env::temp_dir().join(format!("cm400-digest-{}", std::process::id()));
        std::fs::write(&dir, b"x").unwrap();
        let (_, digest) = deployed_image(&dir);
        assert!(
            digest.len() == 64 || digest.starts_with("UNREADABLE"),
            "an existing path reported as {digest:?}"
        );
        std::fs::remove_file(&dir).ok();
    }

    #[test]
    fn status_lines_always_answer_the_four_questions() {
        let lines = status_lines(
            std::path::Path::new(r"C:\Program Files\CM400\bin\cm400d.exe"),
            false,
        );
        let text = lines.join("\n");
        for needed in ["device", "service", "deployed image", "persisted"] {
            assert!(
                text.contains(needed),
                "status lost the {needed} answer: {text}"
            );
        }
        // the transport probe is opt-in precisely because the installer must not open the device
        assert!(
            !text.contains("motor transport"),
            "status_lines(_, false) must not touch the interface: {text}"
        );
    }
}
