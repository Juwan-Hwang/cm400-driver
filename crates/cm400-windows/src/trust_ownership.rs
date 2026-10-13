//! Ownership of the trust entries this product adds, recorded so that a later uninstall can tell
//! "the certificate we installed" apart from "a certificate that was already there".
//!
//! Why this needs its own file, its own ACL and its own verification: the record decides whether an
//! administrator's uninstall deletes something from `LocalMachine\Root`. A record the service account
//! could rewrite is an instruction the service could forge, and a record that cannot be parsed is not
//! "no information" - it means the state is no longer trustworthy, so automatic deletion has to stop.
//!
//! The record can only ever *narrow* what gets deleted. The identity requirements (pinned SHA-256 of
//! DER, matching SHA-1 handle, project subject, self-signed, store in `cert_cleanup::STORES`) are
//! checked independently, in `cert_cleanup`/`trust`, and are never relaxed because this file says so.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::cert_cleanup::STORES;
use crate::trust::PINNED_SHA256_DER;

/// How the pinned certificate came to be in one store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Not in the store.
    Absent,
    /// Was already in the store before this product touched it. Never delete it.
    Preexisting,
    /// This product added it, and this product may remove it.
    AddedByInstall,
    /// Trust existed before any ownership record was kept (a release installed by an older build).
    /// Cleanup is allowed for the pinned identity, and the report has to say the ownership is unknown.
    UnknownLegacy,
    /// This transaction said it was about to write the certificate and then wrote it. Persisted
    /// **before** the store is touched, so a process kill, a crash or a power loss in the middle still
    /// leaves a recoverable statement: a store showing the certificate while the record says
    /// `PendingAdd` is ours, not somebody else's pre-existing trust.
    PendingAdd,
}

impl Provenance {
    fn as_str(self) -> &'static str {
        match self {
            Provenance::Absent => "absent",
            Provenance::Preexisting => "preexisting",
            Provenance::AddedByInstall => "added-by-install",
            Provenance::UnknownLegacy => "unknown-legacy",
            Provenance::PendingAdd => "pending-add",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "absent" => Some(Provenance::Absent),
            "preexisting" => Some(Provenance::Preexisting),
            "added-by-install" => Some(Provenance::AddedByInstall),
            "unknown-legacy" => Some(Provenance::UnknownLegacy),
            "pending-add" => Some(Provenance::PendingAdd),
            _ => None,
        }
    }

    /// The only states an uninstall may act on with a clear conscience.
    ///
    /// `PendingAdd` is included deliberately: reaching it means a transaction was interrupted between
    /// promising and finishing, and the certificate may well be in the store. Treating it as
    /// non-removable would strand exactly the trust that a crash produced.
    pub fn removable(self) -> bool {
        matches!(
            self,
            Provenance::AddedByInstall | Provenance::UnknownLegacy | Provenance::PendingAdd
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub sha256_der: String,
    pub stores: BTreeMap<String, Provenance>,
    pub written_at: String,
}

impl Record {
    pub fn new(sha256_der: &str, now: &str) -> Self {
        let mut stores = BTreeMap::new();
        for store in STORES {
            stores.insert(store.to_string(), Provenance::Absent);
        }
        Record {
            sha256_der: sha256_der.to_ascii_uppercase(),
            stores,
            written_at: now.to_string(),
        }
    }

    /// Mark stores this transaction wrote into but could not confirm after a failure.
    ///
    /// Neither existing answer fits. `Absent` would be false (the certificate may be in the store right
    /// now) and would make a later uninstall skip it, stranding trust; `Preexisting` would be a guess
    /// that we are not responsible for it, which is exactly the conclusion a failed cleanup must not
    /// reach quietly. `UnknownLegacy` states what is known: it is present, this product may have put it
    /// there, and any cleanup has to say so.
    pub fn mark_uncertain(&mut self, stores: &[String]) {
        for store in stores {
            if self.stores.contains_key(store) {
                self.stores.insert(store.clone(), Provenance::UnknownLegacy);
            }
        }
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(
            "# CM400 trust ownership record. Read by the installer and the uninstaller to\n",
        );
        out.push_str(
            "# decide which certificate entries this product is allowed to remove. Written by\n",
        );
        out.push_str(
            "# an elevated installer only; the service account has no access to this file.\n",
        );
        out.push_str(&format!("sha256_der = {}\n", self.sha256_der));
        out.push_str(&format!("written_at = {}\n", self.written_at));
        for store in STORES {
            let state = self
                .stores
                .get(store)
                .copied()
                .unwrap_or(Provenance::Absent);
            out.push_str(&format!("{store} = {}\n", state.as_str()));
        }
        out
    }

    /// Strict parse. Anything that does not describe the pinned identity, or that names a store twice
    /// or an unknown store, is treated as corruption - the caller must then refuse to delete.
    pub fn parse(text: &str) -> Result<Record, String> {
        let mut sha = None;
        let mut written_at = None;
        let mut stores: BTreeMap<String, Provenance> = BTreeMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| format!("malformed line {line:?}"))?;
            let (key, value) = (key.trim(), value.trim());
            match key.to_ascii_lowercase().as_str() {
                "sha256_der" => {
                    if sha.is_some() {
                        return Err("duplicate sha256_der".to_string());
                    }
                    if value.len() != 64 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
                        return Err("sha256_der is not a 64-hex digest".to_string());
                    }
                    sha = Some(value.to_ascii_uppercase());
                }
                "written_at" => {
                    if written_at.is_some() {
                        return Err("duplicate written_at".to_string());
                    }
                    written_at = Some(value.to_string());
                }
                other => {
                    if !STORES.iter().any(|s| s.eq_ignore_ascii_case(other)) {
                        return Err(format!(
                            "record names a store this project does not manage: {other}"
                        ));
                    }
                    let name = STORES
                        .iter()
                        .find(|s| s.eq_ignore_ascii_case(other))
                        .unwrap_or(&other)
                        .to_string();
                    let state = Provenance::parse(value)
                        .ok_or_else(|| format!("unknown provenance {value:?} for {name}"))?;
                    if stores.insert(name.clone(), state).is_some() {
                        return Err(format!("duplicate entry for store {name}"));
                    }
                }
            }
        }
        let sha = sha.ok_or_else(|| "record carries no sha256_der".to_string())?;
        if sha != PINNED_SHA256_DER {
            // An attacker who can rewrite this file could otherwise steer an uninstall toward a
            // different certificate; the identity here has to be the one the binary was built for.
            return Err(format!(
                "record names identity {sha}, not the pinned {PINNED_SHA256_DER}"
            ));
        }
        Ok(Record {
            sha256_der: sha,
            stores,
            written_at: written_at.unwrap_or_default(),
        })
    }

    /// Merge what the stores actually contain now with what was recorded before.
    ///
    /// The point of passing the previous record in: an entry we added is still ours. Reading the
    /// store and seeing it present must not reclassify it as somebody else's pre-existing
    /// certificate, or a later uninstall would leave our entry behind forever.
    pub fn plan(previous: Option<&Record>, present: &[(String, bool)]) -> Record {
        let mut out = Record::new(PINNED_SHA256_DER, "");
        for (store, is_present) in present {
            let state = if !is_present {
                Provenance::Absent
            } else {
                match previous.and_then(|r| r.stores.get(store)).copied() {
                    Some(Provenance::AddedByInstall) => Provenance::AddedByInstall,
                    Some(Provenance::UnknownLegacy) => Provenance::UnknownLegacy,
                    // an interrupted transaction promised this write and then died. The certificate is
                    // in the store and it is ours, so it may not be reclassified as pre-existing -
                    // that is the exact confusion the pending marker exists to prevent
                    Some(Provenance::PendingAdd) => Provenance::AddedByInstall,
                    Some(Provenance::Preexisting) => Provenance::Preexisting,
                    // present now but absent in the record: it arrived between the record and now,
                    // by something other than this code path, so it is not ours to delete
                    Some(Provenance::Absent) | None => Provenance::Preexisting,
                }
            };
            out.stores.insert(store.clone(), state);
        }
        out
    }

    /// Mark the stores this call added, and only those.
    pub fn with_added(mut self, written: &[String], now: &str) -> Record {
        for entry in written {
            let store = entry.split('/').next().unwrap_or(entry.as_str());
            if STORES.iter().any(|s| s.eq_ignore_ascii_case(store)) {
                self.stores
                    .insert(store.to_string(), Provenance::AddedByInstall);
            }
        }
        self.written_at = now.to_string();
        self
    }

    /// Declare the intent to add, before anything is written. Persisting this first is what makes a
    /// crash recoverable rather than a silent lie about who put a certificate in a store.
    pub fn mark_pending(&mut self, stores: &[String]) {
        for store in stores {
            if self
                .stores
                .get(store)
                .copied()
                .is_some_and(|state| state == Provenance::Absent)
            {
                self.stores.insert(store.clone(), Provenance::PendingAdd);
            }
        }
    }

    pub fn stores_to_clean(&self) -> Vec<String> {
        self.stores
            .iter()
            .filter(|(_, state)| state.removable())
            .map(|(store, _)| store.clone())
            .collect()
    }
}

/// Which stores an uninstall may remove the pinned certificate from, decided from the record alone.
///
/// `Err` is a real answer and not an inconvenience: a record that exists but cannot be believed means
/// the ownership state is unknown, and the approved policy is to refuse automatic cleanup rather than
/// to treat it as the legacy "no record" case. That distinction is the whole point of the three-state
/// record, so it is expressed in the type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cleanup {
    /// Stores listed as ours (or as `unknown_legacy`), each still subject to the independent identity
    /// checks in `cert_cleanup` before anything is deleted.
    Targets(Vec<String>),
    /// Nothing to do: the certificate was already there before this product, or is not present.
    Nothing(String),
    /// Refuse, with the reason to report verbatim.
    Refused(String),
}

pub fn cleanup_targets(record: Option<&Record>) -> Cleanup {
    let Some(record) = record else {
        // Approved legacy path: a release installed before ownership records existed. Cleanup is
        // still limited to the pinned identity and still re-reads the store afterwards.
        return Cleanup::Targets(STORES.iter().map(|s| s.to_string()).collect());
    };
    let targets: Vec<String> = record.stores_to_clean();
    let preexisting: Vec<String> = record
        .stores
        .iter()
        .filter(|(_, state)| matches!(state, Provenance::Preexisting))
        .map(|(store, _)| store.clone())
        .collect();
    let absent: Vec<String> = record
        .stores
        .iter()
        .filter(|(_, state)| matches!(state, Provenance::Absent))
        .map(|(store, _)| store.clone())
        .collect();
    if !targets.is_empty() {
        Cleanup::Targets(targets)
    } else {
        let mut why = Vec::new();
        if !preexisting.is_empty() {
            why.push(format!(
                "present before this product in {}",
                preexisting.join(", ")
            ));
        }
        if !absent.is_empty() {
            why.push(format!("not present in {}", absent.join(", ")));
        }
        if why.is_empty() {
            why.push("no store is recorded as ours".to_string());
        }
        Cleanup::Nothing(why.join("; "))
    }
}

/// The caller's view of "the record could not be read". Kept separate from `cleanup_targets` so a
/// parse failure cannot be turned into the legacy branch by an accident of control flow.
pub fn cleanup_decision(read: Result<Option<Record>, String>) -> Cleanup {
    match read {
        Ok(record) => cleanup_targets(record.as_ref()),
        Err(reason) => Cleanup::Refused(format!(
            "ownership record exists but cannot be trusted ({reason}); refusing to remove any certificate"
        )),
    }
}

/// Where the record lives. Its own DACL is applied by `write_verified`; it deliberately does not
/// inherit the state directory's grants, which let the service account modify files.
pub fn path() -> PathBuf {
    Path::new(r"C:\ProgramData\CM400\state").join("trust-ownership.kv")
}

/// The exact `icacls` grants this file must carry afterwards. `LOCAL SERVICE` gets nothing at all -
/// it has no reason to read or rewrite a record that controls which certificates an uninstall
/// removes, and letting it write here would let the service decide what an administrator deletes.
pub const GRANTS: [(&str, &str); 2] = [
    ("*S-1-5-18", "(F)"),     // SYSTEM
    ("*S-1-5-32-544", "(F)"), // Administrators
];

/// The trustees that must NOT be able to modify or read it, as SID strings.
pub const MUST_NOT_WRITE: [&str; 2] = ["*S-1-5-19", "*S-1-5-32-545"]; // LOCAL SERVICE, Users

/// What is standing at the record path right now. The three cases must not collapse into each other:
/// turning "exists but cannot be believed" into "does not exist" would move a later uninstall from
/// *refuse to clean* to the `unknown_legacy` branch, which is exactly the protection the design says
/// must stay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Existing {
    /// Nothing there. The legacy-install case, and the only one where publishing creates a record for
    /// the first time.
    Absent,
    /// A record that parses, names the pinned identity and whose ACL is acceptable. Its bytes are kept
    /// so a failed re-publish can put them back.
    Trustworthy { bytes: Vec<u8>, record: Record },
    /// A file is there but cannot be believed: unparsable, wrong identity, or a DACL that does not
    /// match the boundary. Nobody may delete it, and automatic certificate cleanup is refused until a
    /// human decides what it should say.
    Untrusted { reason: String },
    /// The file exists but could not even be read. Treated like `Untrusted`, because "cannot tell" is
    /// not "absent".
    Unreadable { reason: String },
}

impl Existing {
    /// Whether a failed publish may remove what is at `target`. Only ever what this transaction put
    /// there: `Absent` means any file present afterwards is ours, `Trustworthy` means the old bytes
    /// must be restored instead, and the two failure states mean the file is not ours to touch.
    pub fn rollback_action(&self) -> Rollback {
        match self {
            Existing::Absent => Rollback::RemoveOwnPublication,
            Existing::Trustworthy { bytes, .. } => Rollback::Restore(bytes.clone()),
            Existing::Untrusted { .. } | Existing::Unreadable { .. } => Rollback::LeaveAlone,
        }
    }

    /// A publish may only proceed over nothing, or over a record we can still read and believe. A
    /// record we cannot believe is evidence, and silently overwriting it would erase the reason the
    /// next cleanup refused to run.
    pub fn publishable(&self) -> bool {
        matches!(self, Existing::Absent | Existing::Trustworthy { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rollback {
    RemoveOwnPublication,
    Restore(Vec<u8>),
    LeaveAlone,
}

/// Look at the record path without changing anything. `dacl_text` is what `icacls` printed for the
/// file; passing it in keeps this decision testable without a real ACL, while `write_verified` supplies
/// the real one.
pub fn inspect_with(
    exists: bool,
    bytes: Option<Vec<u8>>,
    read_error: Option<String>,
    acl_problems: Vec<String>,
) -> Existing {
    if !exists {
        return Existing::Absent;
    }
    let Some(bytes) = bytes else {
        return Existing::Unreadable {
            reason: read_error.unwrap_or_else(|| "file exists but could not be read".to_string()),
        };
    };
    let text = String::from_utf8_lossy(&bytes).to_string();
    match Record::parse(&text) {
        Ok(record) => {
            if acl_problems.is_empty() {
                Existing::Trustworthy { bytes, record }
            } else {
                Existing::Untrusted {
                    reason: format!(
                        "record parses but its ACL is wrong: {}",
                        acl_problems.join("; ")
                    ),
                }
            }
        }
        Err(reason) => Existing::Untrusted { reason },
    }
}

#[cfg(target_os = "windows")]
pub fn inspect(target: &Path) -> Existing {
    // `Path::exists()` answers "could metadata be read and is it not NotFound?" - it returns false for
    // an access denial too, which would turn an unreadable record into the legacy "no record" branch.
    // Asking for the bytes and reading the error kind is the distinction this design needs.
    let (exists, bytes, read_error) = match std::fs::read(target) {
        Ok(b) => (true, Some(b), None),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (false, None, None),
        Err(e) => (true, None, Some(format!("{}: {e}", target.display()))),
    };
    let acl_problems = if exists {
        match dacl_report(target) {
            Ok(report) => acl_judgements(&report)
                .into_iter()
                .filter(|(_, actual, want)| *actual != *want)
                .map(|(name, actual, want)| format!("{name}: got {actual}, want {want}"))
                .collect(),
            Err(e) => vec![e],
        }
    } else {
        Vec::new()
    };
    inspect_with(exists, bytes, read_error, acl_problems)
}

/// Run the `icacls` steps of `grant_plan` against one path.
///
/// `grant_plan` yields argv whose **first element is the file path** (it is a parameter list for
/// `icacls`, not a command line) - an earlier version skipped element 0 here the way `cert_cleanup`
/// skips a program name, and `icacls` then got a switch with no file to apply it to.
#[cfg(target_os = "windows")]
pub fn apply_grants(path: &Path) -> Result<(), String> {
    for argv in grant_plan(path) {
        let out = std::process::Command::new("icacls.exe")
            .args(&argv)
            .output()
            .map_err(|e| format!("cannot run icacls: {e}"))?;
        if !out.status.success() {
            // Localized failure text arrives in the console codepage, not UTF-8 (measured: the message
            // came back as replacement characters), so the argv is what gets reported.
            return Err(format!(
                "icacls {} failed (exit {})",
                argv.join(" "),
                out.status.code().unwrap_or(-1)
            ));
        }
    }
    Ok(())
}

/// The DACL as the machine reports it.
///
/// A non-zero `icacls` is an error, not a report. The command prints the path and partial lines while
/// failing, so trusting stdout alone can hand a broken ACL query to `acl_judgements`, which then sees
/// fewer ACEs than exist and can read that as "the boundary is tighter than it is" - the exact
/// opposite of fail-closed for a file whose contents decide which certificates get deleted.
#[cfg(target_os = "windows")]
pub fn dacl_report(path: &Path) -> Result<String, String> {
    let out = std::process::Command::new("icacls.exe")
        .arg(path)
        .output()
        .map_err(|e| format!("cannot run icacls against {}: {e}", path.display()))?;
    interpret_icacls_output(
        out.status.code().unwrap_or(-1),
        &String::from_utf8_lossy(&out.stdout),
        &String::from_utf8_lossy(&out.stderr),
        &path.to_string_lossy(),
    )
}

/// Judge an `icacls` run: exit code first, then whether anything readable came back.
///
/// Split out so the refusal can be tested with a synthetic failing run - a real `icacls` failure is
/// usually a permissions story, and the shape of the input that must be refused should not depend on
/// the state of one machine.
pub fn interpret_icacls_output(
    code: i32,
    stdout: &str,
    stderr: &str,
    target: &str,
) -> Result<String, String> {
    if code != 0 {
        let detail = stderr
            .lines()
            .map(str::trim)
            .rfind(|l| !l.is_empty())
            .or_else(|| stdout.lines().map(str::trim).rfind(|l| !l.is_empty()))
            .unwrap_or("(no output)");
        return Err(format!(
            "icacls on {target} exited {code}; refusing to treat its output as an ACL report (last line: {detail})"
        ));
    }
    if !stdout.contains(":(") {
        return Err(format!(
            "icacls on {target} succeeded but reported no access control entries; the permissions are unknown"
        ));
    }
    Ok(stdout.to_string())
}

/// The six judgements this file must satisfy, as `(name, actual, wanted)`. Judged from the DACL text
/// the machine prints, through the same readers the installer uses for its own ACL checks.
#[cfg(target_os = "windows")]
pub fn acl_judgements(report: &str) -> Vec<(String, bool, bool)> {
    use crate::security::{principal_can_read, principal_can_write};
    const LS: &str = "NT AUTHORITY\\LOCAL SERVICE";
    const USERS: &str = "BUILTIN\\Users";
    vec![
        (
            "SYSTEM can write".into(),
            principal_can_write(report, "NT AUTHORITY\\SYSTEM", true),
            true,
        ),
        (
            "Administrators can write".into(),
            principal_can_write(report, "BUILTIN\\Administrators", true),
            true,
        ),
        (
            "LOCAL SERVICE can write".into(),
            principal_can_write(report, LS, true),
            false,
        ),
        (
            "LOCAL SERVICE can read".into(),
            principal_can_read(report, LS, true),
            false,
        ),
        (
            "Users can write".into(),
            principal_can_write(report, USERS, true),
            false,
        ),
        (
            "Users can read".into(),
            principal_can_read(report, USERS, true),
            false,
        ),
    ]
}

/// Write the record, protect it, publish it, then read it back from the published location and require
/// both the content and the DACL to be what was decided. Returns the record as read from disk, so the
/// caller's evidence is the file and not the intention.
///
/// Order is the security property: permissions are applied to the temporary file **before** the rename,
/// because the directory's inherited ACL lets `LOCAL SERVICE` modify anything that lands there. Setting
/// the grants after publishing (measured on this machine) both failed outright - `icacls` cannot be
/// pointed at a file that does not exist yet - and would have left the record world-writable for a
/// moment anyway.
///
/// What a failure is allowed to undo, and what it is not:
///
/// - nothing there before  -> our partial publication is removed, leaving no record
/// - a trustworthy record  -> its previous bytes are put back, so a failed re-publish cannot lose the
///   ownership information an uninstall depends on
/// - an unparsable / wrong-identity / wrong-ACL record -> refused **before** any write: it is evidence,
///   and neither deleting it nor silently replacing it is ours to decide. This is also the case that
///   must never be reported as "no record", because that would send a later cleanup down the
///   `unknown_legacy` path and drop the refuse-to-clean protection.
#[cfg(target_os = "windows")]
pub fn write_verified(record: &Record, now: &str) -> Result<Record, String> {
    write_verified_at(&path(), record, now, true)
}

/// `enforce_acl = false` exists so the transactional behaviour can be unit-tested on an ordinary temp
/// file. `write_verified`, the only function the installer may call, always passes `true`.
#[cfg(target_os = "windows")]
#[doc(hidden)]
pub fn write_verified_at(
    target: &Path,
    record: &Record,
    now: &str,
    enforce_acl: bool,
) -> Result<Record, String> {
    let prior = inspect(target);
    if !prior.publishable() {
        let reason = match &prior {
            Existing::Untrusted { reason } => reason.clone(),
            Existing::Unreadable { reason } => reason.clone(),
            _ => "unexpected state".to_string(),
        };
        return Err(format!(
            "refusing to publish over an ownership record that cannot be believed ({reason}); the existing file is left untouched and automatic certificate cleanup stays refused"
        ));
    }

    let mut record = record.clone();
    record.written_at = now.to_string();
    let text = record.render();

    let outcome = (|| -> Result<Record, String> {
        // one publishing path for both the new record and a restore, so the rollback can never be
        // less careful than the operation it undoes
        publish_bytes(target, text.as_bytes(), enforce_acl)?;

        let read_back = std::fs::read_to_string(target)
            .map_err(|e| format!("record written but cannot be read back: {e}"))?;
        let parsed = Record::parse(&read_back)?;
        if parsed != record {
            return Err("record on disk does not match what was written".to_string());
        }
        if enforce_acl {
            let report = dacl_report(target)?;
            let bad: Vec<String> = acl_judgements(&report)
                .into_iter()
                .filter(|(_, actual, want)| *actual != *want)
                .map(|(name, actual, want)| format!("{name}: got {actual}, want {want}"))
                .collect();
            if !bad.is_empty() {
                return Err(format!("record ACL rejected: {}", bad.join("; ")));
            }
        }
        Ok(parsed)
    })();

    if outcome.is_err() {
        match prior.rollback_action() {
            Rollback::RemoveOwnPublication => {
                // ours, from this transaction, and it did not verify
                let _ = std::fs::remove_file(target);
            }
            Rollback::Restore(bytes) => {
                // restore through the same atomic, permission-carrying path: `std::fs::write` would
                // truncate the live file first, so a crash mid-restore leaves a partial record that
                // then parses as garbage - and a freshly created file would pick up the directory's
                // inherited ACL instead of the restrictive one this record needs
                let want = bytes.clone();
                if let Err(e) = publish_bytes(target, &want, enforce_acl).and_then(|()| {
                    let back = std::fs::read(target)
                        .map_err(|e| format!("cannot read the restored record: {e}"))?;
                    if back != want {
                        return Err(
                            "the restored record does not match the bytes we restored".to_string()
                        );
                    }
                    Ok(())
                }) {
                    // Loudly unrecoverable: the prior record is gone and the new one is unverified.
                    return Err(format!(
                        "{}; AND the previous record could not be restored intact ({e}) - treat the ownership state as unknown and refuse automatic cleanup",
                        outcome.expect_err("the enclosing branch already proved this is an Err")
                    ));
                }
            }
            Rollback::LeaveAlone => {}
        }
    }
    outcome
}

/// The only way anything is written to the record path: sibling temp file, permissions applied before
/// it becomes visible, atomic rename, then a byte-for-byte read-back. Used both for a new record and
/// for restoring a previous one, so the rollback cannot be weaker than the operation it undoes.
#[cfg(target_os = "windows")]
fn publish_bytes(target: &Path, bytes: &[u8], enforce_acl: bool) -> Result<(), String> {
    use std::io::Write;

    let dir = target
        .parent()
        .ok_or_else(|| "record path has no parent directory".to_string())?;
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let name = target
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "trust-ownership.kv".to_string());
    let temp = dir.join(format!("{name}.tmp-{}", std::process::id()));

    let wrote = (|| -> Result<(), String> {
        let mut file = std::fs::File::create(&temp)
            .map_err(|e| format!("cannot write {}: {e}", temp.display()))?;
        file.write_all(bytes)
            .map_err(|e| format!("cannot write {}: {e}", temp.display()))?;
        // Flush before the rename, or a power loss can leave the published name pointing at an
        // unflushed, truncated file.
        file.sync_all()
            .map_err(|e| format!("cannot flush {}: {e}", temp.display()))?;
        if enforce_acl {
            apply_grants(&temp)?;
        }
        std::fs::rename(&temp, target)
            .map_err(|e| format!("cannot publish {}: {e}", target.display()))
    })();
    if wrote.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    wrote
}

/// Non-Windows helper so the module compiles elsewhere too.
#[cfg(not(target_os = "windows"))]
fn publish_bytes(_target: &Path, _bytes: &[u8], _enforce_acl: bool) -> Result<(), String> {
    Err("trust ownership records are Windows-only".to_string())
}

/// Non-Windows stub: this record exists to control Windows certificate stores.
#[cfg(not(target_os = "windows"))]
pub fn write_verified(_record: &Record, _now: &str) -> Result<Record, String> {
    Err("trust ownership records are Windows-only".to_string())
}

/// The `icacls` argument list that puts this file under the two administrators it belongs to, in the
/// shape already proven by `security::config_file_args`: one call, `/inheritance:r` then `/grant:r`
/// followed by one argument per trustee. Measured here: joining the trustees with `;` - the form some
/// other tools use - makes `icacls` fail with exit 87, and directory-style inheritence flags are
/// deliberately absent, because an `(OI)(CI)` ACE on a *file* is inert and an inert grant once left a
/// service unable to write its own log while `icacls` reported success.
pub fn grant_plan(path: &Path) -> Vec<Vec<String>> {
    let target = path.to_string_lossy().to_string();
    let mut argv = vec![target, "/inheritance:r".to_string(), "/grant:r".to_string()];
    for (sid, rights) in GRANTS {
        argv.push(format!("{sid}:{rights}"));
    }
    vec![argv]
}

/// Re-apply this file's own boundary and prove it by reading it back.
///
/// Called at the end of the data-tree hardening, which is what allows this to be a repair rather than
/// a trust decision: the tree pass resets children to inherit from their parent, and that boundary is
/// deliberately **wider** than the one this file needs (the daemon must not be able to rewrite the
/// record that authorizes deleting certificates). Re-applying it does not make a record believable on
/// its own - `read_verified_at` still judges content and permissions at decision time.
#[cfg(target_os = "windows")]
pub fn enforce_dacl(target: &Path) -> Result<(), String> {
    apply_grants(target)?;
    let report = dacl_report(target)?;
    let bad: Vec<String> = acl_judgements(&report)
        .into_iter()
        .filter(|(_, actual, want)| *actual != *want)
        .map(|(name, actual, want)| format!("{name}: got {actual}, want {want}"))
        .collect();
    if bad.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} does not carry the required boundary after being applied: {}",
            target.display(),
            bad.join("; ")
        ))
    }
}

#[cfg(not(target_os = "windows"))]
pub fn enforce_dacl(_target: &Path) -> Result<(), String> {
    Ok(())
}

/// Principals the data tree's own grants produce, and nothing else.
const TREE_TRUSTEES: [&str; 4] = [
    "NT AUTHORITY\\SYSTEM",
    "BUILTIN\\Administrators",
    "NT AUTHORITY\\LOCAL SERVICE",
    "BUILTIN\\Users",
];

/// True when a report shows exactly the shape our own `data_tree_plan` reset leaves behind: every ACE
/// inherited, only the tree's own trustees, and nothing explicit or denying.
///
/// That shape is the evidence that the widened permissions were produced by this product's installer
/// rather than by somebody else. A single explicit ACE, a trustee the tree never grants, or a deny
/// entry means "something else touched this file", and the answer to that is refusal, not repair.
#[cfg(target_os = "windows")]
fn looks_like_our_tree_reset(report: &str) -> bool {
    let mut saw_ace = false;
    for line in report.lines() {
        let mut cursor = 0usize;
        while let Some(offset) = line[cursor..].find(":(") {
            let at = cursor + offset;
            let before = line[..at].to_ascii_lowercase();
            let groups = crate::security::ace_groups(&line[at + 1..]);
            cursor = at + 1;
            if groups.is_empty() {
                continue;
            }
            saw_ace = true;
            let tokens: Vec<String> = groups.iter().flatten().cloned().collect();
            if tokens.iter().any(|t| t.eq_ignore_ascii_case("DENY")) {
                return false;
            }
            if !tokens.iter().any(|t| t == "I") {
                return false; // explicit ACE: not what inheritance reset leaves
            }
            if !TREE_TRUSTEES
                .iter()
                .any(|t| before.contains(&t.to_ascii_lowercase()))
            {
                return false;
            }
        }
    }
    saw_ace
}

#[cfg(not(target_os = "windows"))]
fn looks_like_our_tree_reset(_report: &str) -> bool {
    false
}

/// The evidence chain, as a function of what was observed rather than of side effects, so that every
/// refusal can be asserted without touching a certificate store.
///
/// `None` means repairing the file's DACL is justified; `Some(reason)` says why it is not. Repair is
/// never allowed on a record whose content is not the pinned identity, whose permissions do not look
/// like our own reset, or whose per-store claims disagree with the stores - because in those cases the
/// record would no longer be evidence of anything, and "cannot be trusted" must not be turned into
/// "trusted" by the act of trying to fix it.
#[cfg(target_os = "windows")]
pub fn repair_refusal(
    content: &Result<Option<Record>, String>,
    report: Option<&str>,
    observed: &[(String, bool)],
) -> Option<String> {
    let record = match content {
        Ok(Some(r)) => r,
        Ok(None) => return Some("there is no record to repair".to_string()),
        Err(e) => {
            return Some(format!(
                "the record's content is not a pinned identity ({e})"
            ))
        }
    };
    let Some(report) = report else {
        return Some(
            "its DACL could not be read, so nothing can be concluded about it".to_string(),
        );
    };
    if !looks_like_our_tree_reset(report) {
        return Some(
            "the permissions are not the shape this product's own data-tree pass produces (inherited \
             entries for the tree's trustees only); repairing them would be guessing who widened them"
                .to_string(),
        );
    }
    use Provenance::{AddedByInstall, PendingAdd};
    for (store, claim) in &record.stores {
        if matches!(claim, AddedByInstall | PendingAdd) {
            let present = observed.iter().any(|(s, p)| s == store && *p);
            if !present {
                return Some(format!(
                    "{store}: the record claims {claim:?} yet the pinned certificate is not listed there, so record and machine disagree"
                ));
            }
        }
    }
    None
}

/// Outcome of the guarded repair attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Repair {
    /// the record already satisfies content and boundary; nothing to do
    NotNeeded,
    /// permissions were restored to the documented boundary and verified by re-read
    Repaired,
    /// refused, with the reason to report verbatim
    Refused(String),
}

/// Attempt the repair on one path, gathering the evidence through the same readers the uninstaller
/// uses. A refusal is the normal answer whenever anything is not exactly as expected.
#[cfg(target_os = "windows")]
pub fn guarded_repair_at(target: &Path, observed: &[(String, bool)]) -> Repair {
    // already believable means there is nothing to heal
    if read_verified_at(target).is_ok() {
        return Repair::NotNeeded;
    }
    let content = read_content_at(target);
    let report = dacl_report(target).ok();
    if let Some(reason) = repair_refusal(&content, report.as_deref(), observed) {
        return Repair::Refused(reason);
    }
    match enforce_dacl(target) {
        Ok(()) => match read_verified_at(target) {
            Ok(Some(_)) => Repair::Repaired,
            Ok(None) => Repair::Refused("the record vanished during the repair".to_string()),
            Err(e) => Repair::Refused(format!(
                "permissions were applied but still do not satisfy the boundary ({e})"
            )),
        },
        Err(e) => Repair::Refused(e),
    }
}

/// The same, for the default location.
#[cfg(target_os = "windows")]
pub fn guarded_repair(observed: &[(String, bool)]) -> Repair {
    guarded_repair_at(&path(), observed)
}

/// Read the record and refuse to believe it unless **both** its content and its actual DACL are what
/// this boundary requires.
///
/// Content alone is not enough: the record decides which certificates an uninstall deletes, so a
/// file that parses perfectly but has been opened up to ordinary users or to the service account is
/// not evidence of anything - whoever widened it could point the uninstall at a certificate that was
/// already there. `Err` here means "do not clean up automatically", and it must never be collapsed
/// into `Ok(None)`, because `Ok(None)` is the legacy branch that *permits* cleanup.
#[cfg(target_os = "windows")]
pub fn read_verified() -> Result<Option<Record>, String> {
    read_verified_at(&path())
}

#[cfg(target_os = "windows")]
pub fn read_verified_at(target: &Path) -> Result<Option<Record>, String> {
    let Some(record) = read_content_at(target)? else {
        return Ok(None);
    };
    match dacl_report(target) {
        Ok(report) => {
            let bad: Vec<String> = acl_judgements(&report)
                .into_iter()
                .filter(|(_, actual, want)| *actual != *want)
                .map(|(name, actual, want)| format!("{name}: got {actual}, want {want}"))
                .collect();
            if bad.is_empty() {
                Ok(Some(record))
            } else {
                Err(format!(
                    "{} parses, but its DACL is not the required boundary: {}",
                    target.display(),
                    bad.join("; ")
                ))
            }
        }
        // not being able to judge the permissions is not permission to trust the file
        Err(e) => Err(format!(
            "{}: cannot verify its DACL ({e})",
            target.display()
        )),
    }
}

/// The content question on its own. Used by `inspect`, which judges permissions separately, and by
/// tests that deliberately build files without the production DACL.
pub fn read_content_at(target: &Path) -> Result<Option<Record>, String> {
    match std::fs::read(target) {
        Ok(bytes) => Record::parse(&String::from_utf8_lossy(&bytes)).map(Some),
        // the only route to "no record" is a real `NotFound`. A sharing violation, an access denial
        // or a path that cannot be stat'ed says nothing about whether a record exists.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot read {}: {e}", target.display())),
    }
}

/// Non-Windows stub so the crate still compiles.
#[cfg(not(target_os = "windows"))]
pub fn read_verified() -> Result<Option<Record>, String> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full(state: Provenance) -> Record {
        let mut r = Record::new(PINNED_SHA256_DER, "2026-10-12T00:00:00");
        for store in STORES {
            r.stores.insert(store.to_string(), state);
        }
        r
    }

    #[test]
    fn a_record_survives_a_round_trip() {
        for state in [
            Provenance::Absent,
            Provenance::Preexisting,
            Provenance::AddedByInstall,
            Provenance::UnknownLegacy,
        ] {
            let r = full(state);
            let text = r.render();
            assert_eq!(
                Record::parse(&text),
                Ok(r.clone()),
                "{state:?} must round-trip"
            );
        }
    }

    /// Corruption is not "no information": it has to be distinguishable, because it is the case in
    /// which deletion must stop.
    #[test]
    fn corruption_is_rejected_loudly() {
        assert!(Record::parse("sha256_der = whatever\n").is_err());
        assert!(
            Record::parse("").is_err(),
            "an empty file is not a valid record"
        );
        assert!(
            Record::parse("written_at = now\n").is_err(),
            "no identity at all"
        );
        assert!(
            Record::parse(&format!("sha256_der = {}\n", &PINNED_SHA256_DER[..60])).is_err(),
            "63 hex characters is a truncated digest, not a digest"
        );
        // truncated identity
        let mut bad = full(Provenance::AddedByInstall);
        bad.sha256_der = bad.sha256_der[..40].to_string();
        assert!(
            Record::parse(&bad.render()).is_err(),
            "a 40-hex value is not the DER anchor"
        );
        // wrong identity: exactly the case where a rewritten file would steer deletion elsewhere
        let mut foreign = full(Provenance::AddedByInstall);
        foreign.sha256_der = "F".repeat(64);
        let err = Record::parse(&foreign.render())
            .expect_err("a record naming another identity is refused");
        assert!(err.contains("pinned"), "{err}");
        // duplicated and unknown stores
        let dup =
            format!("sha256_der = {PINNED_SHA256_DER}\nRoot = absent\nRoot = added-by-install\n");
        assert!(
            Record::parse(&dup).is_err(),
            "two statements about one store is a contradiction"
        );
        let unknown = format!("sha256_der = {PINNED_SHA256_DER}\nMy = added-by-install\n");
        assert!(
            Record::parse(&unknown).is_err(),
            "only the two managed stores may appear"
        );
        let value = format!("sha256_der = {PINNED_SHA256_DER}\nRoot = deleted-by-someone\n");
        assert!(Record::parse(&value).is_err());
    }

    /// An entry we added stays ours even though it now looks "already present".
    #[test]
    fn an_our_own_entry_is_never_reclassified_as_preexisting() {
        let previous = full(Provenance::AddedByInstall);
        let present = vec![
            ("Root".to_string(), true),
            ("TrustedPublisher".to_string(), true),
        ];
        let merged = Record::plan(Some(&previous), &present);
        assert_eq!(
            merged.stores.get("Root").copied(),
            Some(Provenance::AddedByInstall)
        );
        assert_eq!(merged.stores_to_clean().len(), 2);

        // no record before, entry present => somebody else put it there; do not claim it
        let fresh = Record::plan(None, &present);
        assert_eq!(
            fresh.stores.get("Root").copied(),
            Some(Provenance::Preexisting)
        );
        assert!(
            fresh.stores_to_clean().is_empty(),
            "preexisting entries are not ours to delete"
        );

        // legacy installs keep their flag through an upgrade
        let legacy = full(Provenance::UnknownLegacy);
        let upgraded = Record::plan(Some(&legacy), &present);
        assert_eq!(
            upgraded.stores.get("Root").copied(),
            Some(Provenance::UnknownLegacy)
        );

        // absent in the store means absent, whatever the old record said
        let gone = vec![
            ("Root".to_string(), false),
            ("TrustedPublisher".to_string(), false),
        ];
        let cleared = Record::plan(Some(&previous), &gone);
        assert!(cleared.stores_to_clean().is_empty());
    }

    #[test]
    fn marking_added_only_touches_stores_it_really_wrote() {
        let base = Record::new(PINNED_SHA256_DER, "");
        let written = vec![
            "Root/954E6103349748270B90C8A8A68652A44946ABF1".to_string(),
            "TrustedPublisher/954E6103349748270B90C8A8A68652A44946ABF1".to_string(),
            "My/whatever".to_string(),
        ];
        let marked = base.with_added(&written, "2026-10-12T00:00:01");
        assert_eq!(
            marked.stores.get("Root").copied(),
            Some(Provenance::AddedByInstall)
        );
        assert_eq!(
            marked.stores.get("TrustedPublisher").copied(),
            Some(Provenance::AddedByInstall)
        );
        assert!(
            !marked.stores.contains_key("My"),
            "a store outside our scope never enters the record"
        );
        assert_eq!(marked.written_at, "2026-10-12T00:00:01");
    }

    #[test]
    fn the_acl_shape_this_record_demands() {
        // Two trustees, and the service account plus ordinary users are explicitly on the deny list.
        assert_eq!(GRANTS.len(), 2);
        assert!(GRANTS.iter().any(|(sid, _)| *sid == "*S-1-5-18"));
        assert!(GRANTS.iter().any(|(sid, _)| *sid == "*S-1-5-32-544"));
        assert!(
            MUST_NOT_WRITE.contains(&"*S-1-5-19"),
            "LOCAL SERVICE must not modify it"
        );
        assert!(
            MUST_NOT_WRITE.contains(&"*S-1-5-32-545"),
            "ordinary users must not modify it"
        );
        // grants are file-scoped: an inherited form here is what broke a config file once before
        for (_sid, rights) in GRANTS {
            assert!(
                !rights.contains("(OI)") && !rights.contains("(CI)"),
                "inheritence flags on a file make the ACE inert"
            );
        }
    }

    #[test]
    fn the_acl_plan_grants_only_the_two_administrators_and_inherits_nothing() {
        let plan = grant_plan(Path::new(r"C:\ProgramData\CM400\state\trust-ownership.kv"));
        assert_eq!(
            plan.len(),
            1,
            "one icacls call, as the config-file hardening already does"
        );
        let argv = &plan[0];
        // argv[0] is the file, because this is an icacls parameter list rather than a command line
        assert!(argv[0].ends_with("trust-ownership.kv"), "{:?}", argv);
        assert!(argv.contains(&"/inheritance:r".to_string()), "{:?}", argv);
        let grant_at = argv
            .iter()
            .position(|a| *a == "/grant:r")
            .expect("/grant:r present");
        let trustees = &argv[grant_at + 1..];
        assert_eq!(
            trustees.len(),
            2,
            "one argument per trustee; a ';' join made icacls fail with 87"
        );
        let joined = argv.join(" ");
        assert!(joined.contains("*S-1-5-18:(F)"), "{joined}");
        assert!(joined.contains("*S-1-5-32-544:(F)"), "{joined}");
        assert!(
            !joined.contains("S-1-5-19"),
            "LOCAL SERVICE must not appear in any grant"
        );
        assert!(
            !joined.contains("S-1-5-32-545"),
            "ordinary users must not appear in any grant"
        );
        assert!(
            !joined.contains("(OI)") && !joined.contains("(CI)") && !joined.contains(" /T"),
            "inheritence flags and /T on a file are what broke a config file's DACL once before"
        );
    }

    #[test]
    fn cleanup_decisions_cover_every_approved_row() {
        // Preexisting -> keep
        assert_eq!(
            cleanup_targets(Some(&full(Provenance::Preexisting))),
            Cleanup::Nothing("present before this product in Root, TrustedPublisher".into())
        );
        // AddedByInstall -> clean those stores
        assert_eq!(
            cleanup_targets(Some(&full(Provenance::AddedByInstall))),
            Cleanup::Targets(vec!["Root".into(), "TrustedPublisher".into()])
        );
        // mixed per-store state is honoured per store, not merged into one verdict
        let mut mixed = full(Provenance::Absent);
        mixed
            .stores
            .insert("Root".into(), Provenance::AddedByInstall);
        mixed
            .stores
            .insert("TrustedPublisher".into(), Provenance::Preexisting);
        assert_eq!(
            cleanup_targets(Some(&mixed)),
            Cleanup::Targets(vec!["Root".into()])
        );
        // no record at all -> approved legacy branch, both stores considered
        assert_eq!(
            cleanup_targets(None),
            Cleanup::Targets(vec!["Root".into(), "TrustedPublisher".into()])
        );
        // a corrupt record must NOT arrive at the legacy branch
        assert!(matches!(
            cleanup_decision(Err("duplicate entry for store Root".into())),
            Cleanup::Refused(_)
        ));
        // and Absent everywhere is "nothing to do", not a failure
        assert!(matches!(
            cleanup_targets(Some(&full(Provenance::Absent))),
            Cleanup::Nothing(_)
        ));
    }

    /// "Cannot believe it" and "not there" are different answers, and only one of them permits the
    /// legacy cleanup branch.
    #[test]
    fn the_three_states_never_collapse_into_each_other() {
        let corrupt = inspect_with(
            true,
            Some(b"sha256_der = nonsense\n".to_vec()),
            None,
            vec![],
        );
        assert!(matches!(corrupt, Existing::Untrusted { .. }), "{corrupt:?}");
        assert!(
            !corrupt.publishable(),
            "a corrupt record may not be published over"
        );
        assert_eq!(
            corrupt.rollback_action(),
            Rollback::LeaveAlone,
            "and may not be deleted either"
        );

        let unreadable = inspect_with(true, None, Some("access denied".into()), vec![]);
        assert!(
            matches!(unreadable, Existing::Unreadable { .. }),
            "{unreadable:?}"
        );
        assert!(!unreadable.publishable(), "cannot read is not absent");
        assert_eq!(unreadable.rollback_action(), Rollback::LeaveAlone);

        // a record that parses but whose ACL was widened is still untrusted, because the ACL is part
        // of what makes it usable as an authorization input
        let widened = inspect_with(
            true,
            Some(full(Provenance::AddedByInstall).render().into_bytes()),
            None,
            vec!["Users can write: got true, want false".to_string()],
        );
        assert!(matches!(widened, Existing::Untrusted { .. }), "{widened:?}");

        let good = inspect_with(
            true,
            Some(full(Provenance::AddedByInstall).render().into_bytes()),
            None,
            vec![],
        );
        assert!(good.publishable());
        assert!(matches!(good, Existing::Trustworthy { .. }));

        let absent = inspect_with(false, None, None, vec![]);
        assert_eq!(absent, Existing::Absent);
        assert_eq!(
            absent.rollback_action(),
            Rollback::RemoveOwnPublication,
            "only our own partial publication may be removed"
        );
    }

    /// A re-publish over a good record that then fails must put the old bytes back, so an uninstall can
    /// still read the ownership it depends on.
    #[test]
    fn a_replaced_record_is_the_one_that_gets_restored() {
        let bytes = full(Provenance::AddedByInstall).render().into_bytes();
        let existing = inspect_with(true, Some(bytes.clone()), None, vec![]);
        assert_eq!(existing.rollback_action(), Rollback::Restore(bytes));
    }

    /// End to end on a temp file: publishing over a corrupt record is refused **without touching it**,
    /// and publishing over nothing / over a good record works. ACL enforcement is off here (that path
    /// is measured separately on the real file); the point of this test is the file-level decision.
    #[cfg(target_os = "windows")]
    #[test]
    fn publishing_refuses_to_overwrite_an_untrustworthy_record() {
        let dir = std::env::temp_dir().join(format!("cm400-ownership-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("trust-ownership.kv");

        // corrupt on purpose: unreadable identity, so it is evidence, not a blank slate
        std::fs::write(&target, b"sha256_der = nonsense\nRoot = added-by-install\n").unwrap();
        let before = std::fs::read(&target).unwrap();
        let err = write_verified_at(&target, &full(Provenance::AddedByInstall), "t1", false)
            .expect_err("refusing to publish over a record that cannot be believed");
        assert!(err.contains("left untouched"), "{err}");
        assert_eq!(
            std::fs::read(&target).unwrap(),
            before,
            "the corrupt record must survive byte-for-byte"
        );

        // a good record can be replaced (retry / upgrade path)
        let good = full(Provenance::AddedByInstall).render();
        std::fs::write(&target, &good).unwrap();
        let mut upgraded = full(Provenance::Preexisting);
        upgraded.sha256_der = PINNED_SHA256_DER.to_string();
        write_verified_at(&target, &upgraded, "t2", false)
            .expect("publishing over a trustworthy record works");
        let now = read_content_at(&target).unwrap().expect("record readable");
        assert_eq!(
            now.stores.get("Root").copied(),
            Some(Provenance::Preexisting)
        );

        // absent -> created
        std::fs::remove_file(&target).unwrap();
        write_verified_at(&target, &full(Provenance::AddedByInstall), "t3", false)
            .expect("first publication works");
        assert!(target.exists());
        assert!(read_content_at(&target).unwrap().is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The point of verifying permissions on the read path: a record that parses perfectly and names
    /// the right identity still cannot authorize a deletion once anybody but the two administrators can
    /// change it. Measured with a real widened DACL, not asserted in a comment.
    #[cfg(target_os = "windows")]
    #[test]
    fn a_widened_dacl_invalidates_the_record_even_when_its_content_is_perfect() {
        let dir = std::env::temp_dir().join(format!("cm400-ownership-dacl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("trust-ownership.kv");
        std::fs::write(&target, full(Provenance::AddedByInstall).render()).unwrap();

        // content alone is accepted, so the two checks really are separate
        assert!(
            read_content_at(&target).unwrap().is_some(),
            "content must parse"
        );

        let probe = std::process::Command::new("icacls.exe")
            .args([
                target.to_string_lossy().as_ref(),
                "/grant:r",
                "*S-1-5-32-545:(F)",
            ])
            .output();
        if !probe.as_ref().map(|o| o.status.success()).unwrap_or(false) {
            eprintln!("skipped: cannot widen the DACL on this file (icacls failed)");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let err = read_verified_at(&target).expect_err(
            "a record writable by ordinary users must not authorize certificate deletion",
        );
        assert!(err.contains("DACL"), "{err}");
        // and it is an error, never the legacy `Ok(None)` that would permit cleanup
        assert!(
            !err.contains("cannot read"),
            "reported as a permission problem: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `Path::exists()` is not a stand-in for "there is no record": a directory in the way, or an
    /// access denial, must land in `Unreadable` and stop cleanup rather than in `Absent`.
    #[cfg(target_os = "windows")]
    #[test]
    fn a_blocked_path_is_unreadable_and_not_absent() {
        let dir =
            std::env::temp_dir().join(format!("cm400-ownership-blocked-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // a directory occupying the record path: `read` fails with an access/invalid error, not NotFound
        let blocked = dir.join("trust-ownership.kv");
        std::fs::create_dir_all(&blocked).unwrap();
        match inspect(&blocked) {
            Existing::Unreadable { .. } | Existing::Untrusted { .. } => {}
            other => panic!("a path that cannot be read as a file must not look absent: {other:?}"),
        }
        // the cleanup decision that follows must be refusal (or "nothing to do"), never the legacy branch
        let decision = cleanup_decision(read_verified_at(&blocked));
        assert!(
            matches!(decision, Cleanup::Refused(_)) || matches!(decision, Cleanup::Nothing(_)),
            "a blocked path may not be read as \"no record, clean both stores\": {decision:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unconfirmed_write_is_neither_absent_nor_someone_elses() {
        let mut r = full(Provenance::Absent);
        r.mark_uncertain(&[
            "Root".to_string(),
            "TrustedPublisher".to_string(),
            "My".to_string(),
        ]);
        assert_eq!(
            r.stores.get("Root").copied(),
            Some(Provenance::UnknownLegacy)
        );
        assert_eq!(
            r.stores.get("TrustedPublisher").copied(),
            Some(Provenance::UnknownLegacy)
        );
        assert!(
            !r.stores.contains_key("My"),
            "a store outside our scope is never added by marking"
        );
        // still removable, unlike Preexisting - with the uncertainty stated in the report
        assert_eq!(
            cleanup_targets(Some(&r)),
            Cleanup::Targets(vec!["Root".into(), "TrustedPublisher".into()])
        );
        // and the round trip keeps it, because the record is what a later process reads
        let again = Record::parse(&r.render()).expect("uncertain state survives a round trip");
        assert_eq!(again, r);
    }

    /// The crash-recovery mapping, asserted in both directions.
    #[test]
    fn an_interrupted_write_is_claimed_as_ours_and_not_as_preexisting() {
        let mut prior = Record::new(PINNED_SHA256_DER, "t0");
        prior.stores.insert("Root".into(), Provenance::PendingAdd);
        prior
            .stores
            .insert("TrustedPublisher".into(), Provenance::PendingAdd);

        // the store really received the certificate before the process died
        let after_crash = Record::plan(
            Some(&prior),
            &[
                ("Root".to_string(), true),
                ("TrustedPublisher".to_string(), false),
            ],
        );
        assert_eq!(
            after_crash.stores.get("Root").copied(),
            Some(Provenance::AddedByInstall),
            "a pending write that landed is ours, and must stay cleanable"
        );
        assert_eq!(
            after_crash.stores.get("TrustedPublisher").copied(),
            Some(Provenance::Absent),
            "a pending write that never landed is simply absent"
        );
        // and the pending state is removable before any re-plan happens
        assert!(Provenance::PendingAdd.removable());
        let mut pending = full(Provenance::Absent);
        pending.mark_pending(&["Root".to_string()]);
        assert_eq!(
            pending.stores.get("Root").copied(),
            Some(Provenance::PendingAdd)
        );
        assert_eq!(
            pending.stores.get("TrustedPublisher").copied(),
            Some(Provenance::Absent),
            "only the store being written is declared pending"
        );
        // marking never overwrites a state that already carries information
        let mut claimed = full(Provenance::Preexisting);
        claimed.mark_pending(&["Root".to_string()]);
        assert_eq!(
            claimed.stores.get("Root").copied(),
            Some(Provenance::Preexisting)
        );
        // round trip so a later process reads the same thing
        let back = Record::parse(&pending.render()).expect("pending-add parses");
        assert_eq!(back, pending);
    }

    /// The refusal has to come from the exit code, and it has to reach the cleanup decision.
    #[test]
    fn a_failing_icacls_is_not_an_acl_report() {
        // the shape `icacls` really produces when it fails: a path line, a complaint, and a non-zero
        // status. The first line looks like a report and is not one.
        let stdout = "C:\\ProgramData\\CM400\\state\\trust-ownership.kv: Access is denied.\r\nSuccessfully processed 0 files; Failed processing 1 files\r\n";
        let err = interpret_icacls_output(1, stdout, "", "C:\\x\\trust-ownership.kv")
            .expect_err("a non-zero exit must not yield a report");
        assert!(err.contains("exited 1"), "{err}");
        assert!(
            !err.contains("Access is denied.\r\nSuccessfully"),
            "only one line is quoted: {err}"
        );

        // success with no ACEs is an unknown state, not an empty-but-safe one
        let err = interpret_icacls_output(0, "C:\\x: \r\n", "", "C:\\x")
            .expect_err("no ACE means unknown permissions");
        assert!(err.contains("no access control entries"), "{err}");

        // a real report passes
        let ok = interpret_icacls_output(
            0,
            "C:\\x: NT AUTHORITY\\SYSTEM:(F)\r\n     BUILTIN\\Administrators:(F)\r\n",
            "",
            "C:\\x",
        )
        .expect("a successful report is accepted");
        assert!(ok.contains("SYSTEM"), "{ok}");

        // and the decision that the uninstaller acts on cannot land in the legacy branch because of it
        let refused =
            interpret_icacls_output(5, stdout, "", "C:\\x").expect_err("exit 5 must be an error");
        assert!(matches!(
            cleanup_decision(Err(refused)),
            Cleanup::Refused(_)
        ));
    }

    /// Measured against the real binary: an unreachable path produces a non-zero status, and that is
    /// reported rather than passed on as an ACL.
    #[cfg(target_os = "windows")]
    #[test]
    fn dacl_report_refuses_a_path_icacls_cannot_read() {
        let missing =
            std::env::temp_dir().join(format!("cm400-no-such-acl-{}", std::process::id()));
        let err =
            dacl_report(&missing).expect_err("icacls cannot report on a path that is not there");
        assert!(err.contains("exited"), "{err}");
        // and this is what the cleanup decision does with it: refuse, never "absent, so clean both"
        assert!(matches!(cleanup_decision(Err(err)), Cleanup::Refused(_)));
    }

    #[test]
    fn path_is_the_documented_location() {
        let p = path();
        assert_eq!(p.file_name().unwrap(), "trust-ownership.kv");
        assert!(p.to_string_lossy().contains("ProgramData"));
    }
}
