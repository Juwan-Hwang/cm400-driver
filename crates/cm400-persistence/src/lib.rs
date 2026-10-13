//! CM400 motor status persistence. Dependency-free (stable `key=value` text)
//! so the workspace builds offline with no crates.io access.
//!
//! Stores the *persisted physical model* only (never firmware echo). The
//! resident service reloads this at start and runs `cm400_state::recover_physical`
//! on it.

use std::path::PathBuf;

use cm400_core::Store;
use cm400_state::{MotorStatus, PhysicalState, Transition};

fn enc_physical(p: PhysicalState) -> &'static str {
    match p {
        PhysicalState::Up => "up",
        PhysicalState::Down => "down",
        PhysicalState::Unknown => "unknown",
    }
}

fn dec_physical(s: &str) -> Option<PhysicalState> {
    match s {
        "up" => Some(PhysicalState::Up),
        "down" => Some(PhysicalState::Down),
        "unknown" => Some(PhysicalState::Unknown),
        _ => None,
    }
}

fn enc_transition(t: Transition) -> &'static str {
    match t {
        Transition::Idle => "idle",
        Transition::MovingUp => "moving_up",
        Transition::MovingDown => "moving_down",
    }
}

fn dec_transition(s: &str) -> Option<Transition> {
    match s {
        "idle" => Some(Transition::Idle),
        "moving_up" => Some(Transition::MovingUp),
        "moving_down" => Some(Transition::MovingDown),
        _ => None,
    }
}

pub fn encode(s: &MotorStatus) -> String {
    let target = match s.target {
        Some(p) => enc_physical(p).to_string(),
        None => "none".to_string(),
    };
    format!(
        "physical={}\ntransition={}\ntarget={}\nstarted_at_ms={}\nlast_confirmed_at_ms={}\n",
        enc_physical(s.physical),
        enc_transition(s.transition),
        target,
        s.started_at_ms,
        s.last_confirmed_at_ms
    )
}

pub fn decode(text: &str) -> Option<MotorStatus> {
    let mut physical = None;
    let mut transition = None;
    let mut target: Option<Option<PhysicalState>> = None;
    let mut started = None;
    let mut confirmed = None;
    for line in text.lines() {
        let (k, v) = line.split_once('=')?;

        match k {
            "physical" => physical = Some(dec_physical(v)?),
            "transition" => transition = Some(dec_transition(v)?),
            "target" => {
                target = Some(if v == "none" {
                    None
                } else {
                    Some(dec_physical(v)?)
                })
            }
            "started_at_ms" => started = Some(v.parse::<u64>().ok()?),
            "last_confirmed_at_ms" => confirmed = Some(v.parse::<u64>().ok()?),
            _ => {}
        }
    }
    Some(MotorStatus {
        physical: physical?,
        transition: transition?,
        target: target?,
        started_at_ms: started?,
        last_confirmed_at_ms: confirmed?,
    })
}

/// File-backed store implementing the core `Store` trait.
pub struct FileStore {
    pub path: PathBuf,
}

impl FileStore {
    pub fn new(p: impl Into<PathBuf>) -> Self {
        FileStore { path: p.into() }
    }
}

impl Store for FileStore {
    fn load(&mut self) -> Option<MotorStatus> {
        let text = std::fs::read_to_string(&self.path).ok()?;
        decode(&text)
    }
    fn save(&mut self, status: &MotorStatus) {
        // Write-then-rename, not a bare fs::write: a crash mid-write would otherwise
        // leave a truncated file, and a truncated file decodes to None, which silently
        // degrades the next start to "no persisted state". Renaming a finished temp
        // file is the atomic-enough replacement on the same volume.
        let text = encode(status);
        let tmp = {
            let mut p = self.path.clone().into_os_string();
            p.push(".tmp");
            PathBuf::from(p)
        };
        if std::fs::write(&tmp, text).is_err() {
            return; // best effort: a resident service must not die over a persist failure
        }
        if std::fs::rename(&tmp, &self.path).is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_with_target() {
        let s = MotorStatus {
            physical: PhysicalState::Down,
            transition: Transition::MovingUp,
            target: Some(PhysicalState::Up),
            started_at_ms: 1234,
            last_confirmed_at_ms: 5678,
        };
        assert_eq!(decode(&encode(&s)), Some(s));
    }

    #[test]
    fn round_trip_no_target() {
        let s = MotorStatus {
            physical: PhysicalState::Up,
            transition: Transition::Idle,
            target: None,
            started_at_ms: 0,
            last_confirmed_at_ms: 9,
        };
        assert_eq!(decode(&encode(&s)), Some(s));
    }

    #[test]
    fn decode_rejects_garbage() {
        assert_eq!(decode("physical=banana\n"), None);
        assert_eq!(decode("nonsense"), None);
    }

    #[test]
    fn filestore_save_load() {
        let path = std::env::temp_dir().join(format!("cm400_test_{}.kv", std::process::id()));
        let s = MotorStatus {
            physical: PhysicalState::Down,
            transition: Transition::Idle,
            target: None,
            started_at_ms: 42,
            last_confirmed_at_ms: 43,
        };
        let mut store = FileStore::new(&path);
        store.save(&s);
        assert_eq!(store.load(), Some(s));
        let _ = std::fs::remove_file(&path);
    }
}
