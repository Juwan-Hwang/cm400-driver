//! Runtime configuration: mode + timing. Loaded from
//! `C:\ProgramData\CM400\config.toml` (flat `key = value`), falling back to
//! defaults. Kept dependency-free (the subset we use is trivial to parse).

use std::path::PathBuf;

use cm400_policy::{Mode, Policy};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendChoice {
    /// Shipped behaviour: SAM is observed and logged, the heartbeat decides.
    Shadow,
    /// SAM's arbitrated answer drives the policy, with the heartbeat as fallback.
    /// Selectable only by an explicit config line, never by default.
    Arbitrating,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    pub mode: Mode,
    pub heartbeat_timeout_ms: u64,
    pub down_grace_ms: u64,
    pub backend: BackendChoice,
    /// How `backend` was arrived at, for the startup log. Static strings so `Config` can stay
    /// `Copy`; the operator must be able to tell "defaulted" from "configured" from the log.
    pub backend_note: &'static str,
}

impl Default for Config {
    fn default() -> Self {
        // Frozen from W0/2-B measurements: heartbeat interval ~512ms -> 3s timeout is a
        // safe margin. DOWN grace was 30s to absorb the ~20s FrameServer teardown lag.
        // Product decision (2026-10-09): retract as soon as the stream is really gone,
        // so grace is 3s on top of the 3s heartbeat timeout. Consequences, stated
        // honestly: (a) a brief pause while the app stays open now retracts and the next
        // frame re-raises, instead of holding 30s; (b) the teardown lag still bounds
        // close->retract at roughly 20s + 3s + 3s, so "immediate" is measured, not 0.
        Config {
            mode: Mode::Automatic,
            heartbeat_timeout_ms: 3000,
            down_grace_ms: 3_000,
            backend: BackendChoice::Shadow,
            backend_note: "default (no config file)",
        }
    }
}

impl Config {
    pub fn to_policy(&self) -> Policy {
        Policy {
            mode: self.mode,
            down_grace_ms: self.down_grace_ms,
        }
    }

    /// CM400 data dir under ProgramData.
    pub fn data_dir() -> PathBuf {
        let base = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
        let mut p = PathBuf::from(base);
        p.push("CM400");
        p
    }

    /// The single motor-state store. The resident daemon and the diagnostic CLI
    /// MUST share this path: two stores means the daemon recovers a stale (or
    /// Unknown) physical state after a manual `cm400ctl` move.
    pub fn state_path() -> PathBuf {
        let dir = Self::data_dir().join("state");
        let _ = std::fs::create_dir_all(&dir);
        dir.join("state.kv")
    }

    fn config_path() -> PathBuf {
        Self::data_dir().join("config.toml")
    }

    /// Where the deployed daemon runs from. Stated once so that a status reporter cannot drift away from
    /// what the installer actually writes; `cm400_setup` keeps its own constant and a test cross-checks
    /// the two, because a silent disagreement would show up as "installed but not running" reports.
    pub fn deployed_daemon_path() -> PathBuf {
        PathBuf::from(r"C:\Program Files\CM400\bin\cm400d.exe")
    }

    /// Load config, falling back to defaults if the file is absent/unreadable. An unreadable file
    /// is reported as such rather than silently looking like "the operator asked for shadow".
    pub fn load() -> Config {
        let path = Self::config_path();
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(_) => return Config::default(),
        };
        Self::parse(&text)
    }

    /// The whole parser, pure so the fallback rules are testable without touching ProgramData.
    /// Any problem with `activity_backend` leaves the default (`SensorShadow`): a typo in a
    /// rollout switch must never be able to change motor behaviour on its own.
    pub fn parse(text: &str) -> Config {
        let mut c = Config {
            backend_note: "default (key absent)",
            ..Config::default()
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut it = line.splitn(2, '=');
            let k = it.next().unwrap_or("").trim();
            let v = it.next().unwrap_or("").trim().trim_matches('"');
            match k {
                "activity_backend" => {
                    c.backend = match v {
                        "shadow" | "sensor_shadow" => {
                            c.backend_note = "config: shadow";
                            BackendChoice::Shadow
                        }
                        "arbitrating" | "sensor_arbitrating" => {
                            // Saying only where the choice came from: arbitration is the configured mode on
                            // this machine, and an "(experiment)" tag in the startup line would tell an operator
                            // that the running behaviour was provisional when it was chosen deliberately.
                            c.backend_note = "config: arbitrating";
                            BackendChoice::Arbitrating
                        }
                        _ => {
                            // Unreadable/unknown value: keep the shipped default and say so.
                            c.backend_note = "config: invalid activity_backend - staying on shadow";
                            BackendChoice::Shadow
                        }
                    }
                }
                "mode" => {
                    c.mode = match v {
                        "automatic" => Mode::Automatic,
                        "always_open" | "open" => Mode::AlwaysOpen,
                        "always_closed" | "closed" => Mode::AlwaysClosed,
                        _ => c.mode,
                    }
                }
                "heartbeat_timeout_ms" => {
                    if let Ok(n) = v.parse() {
                        c.heartbeat_timeout_ms = n;
                    }
                }
                "down_grace_ms" => {
                    if let Ok(n) = v.parse() {
                        c.down_grace_ms = n;
                    }
                }
                _ => {}
            }
        }
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The parser's outcome for a rejected value, so the assertion below compares whole configs
    /// rather than eyeballing one field.
    fn expected_rejected() -> Config {
        Config {
            backend_note: "config: invalid activity_backend - staying on shadow",
            ..Config::default()
        }
    }

    /// The rollout switch defaults to shadow, and a bad value cannot promote anything.
    #[test]
    fn activity_backend_defaults_and_fails_closed() {
        assert_eq!(
            Config::parse("mode = automatic\n").backend,
            BackendChoice::Shadow
        );
        let missing = Config::parse("");
        assert_eq!(missing.backend_note, "default (key absent)");
        assert_eq!(Config::parse("activity_backend = )"), expected_rejected());
        for bad in [
            "activity_backend = arbitrating2",
            "activity_backend =",
            "activity_backend = \"SENSOR-ARBITRATING\"",
            "activity_backend = heartbeat_only",
        ] {
            let c = Config::parse(bad);
            assert_eq!(
                c.backend,
                BackendChoice::Shadow,
                "`{bad}` must not leave shadow"
            );
            assert!(
                c.backend_note.contains("invalid"),
                "and the log has to say it was rejected: {}",
                c.backend_note
            );
        }
    }

    /// Accepted spellings, including the quoted form the other keys already tolerate.
    #[test]
    fn activity_backend_accepts_only_the_two_allowed_choices() {
        for ok in ["shadow", "sensor_shadow", "\"shadow\""] {
            let c = Config::parse(&format!("activity_backend = {ok}"));
            assert_eq!(c.backend, BackendChoice::Shadow, "{ok}");
        }
        for ok in ["arbitrating", "sensor_arbitrating", "\"arbitrating\""] {
            let c = Config::parse(&format!("activity_backend = {ok}"));
            assert_eq!(c.backend, BackendChoice::Arbitrating, "{ok}");
            assert!(c.backend_note.contains("arbitrating"), "{}", c.backend_note);
            assert!(
                !c.backend_note.contains("experiment"),
                "a configured mode must not be labelled provisional: {}",
                c.backend_note
            );
        }
    }
}
