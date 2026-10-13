//! Access-control hardening for the directory the service trusts at runtime.
//!
//! The daemon reads `config.toml` and `state\state.kv` from `C:\ProgramData\CM400` and treats
//! what it finds there as fact: a backend selection becomes motor policy, and a persisted motor
//! state becomes the assumed physical position after a restart. ProgramData's default ACL hands
//! `BUILTIN\Users` inheritable child-create rights, which on this machine measured as
//! `BUILTIN\Users:(I)(CI)(WD,AD,WEA,WA)` - enough for any interactive user to place files in
//! those directories, including the predictable temp name the atomic state save writes to
//! (`state.kv.tmp`). That is a trust boundary, so the installer owns it explicitly rather than
//! inheriting whatever ProgramData happens to grant.
//!
//! Deliberately narrow: this module builds the grant list, and *judges* an `icacls` report. It
//! never applies anything itself - the caller is the elevated installer (`cm400-setup`), because
//! a LocalService daemon must not be able to widen or narrow its own trust surface.

/// The complete set of principals on the CM400 data tree, and what each gets. Everything else is
/// removed: inheritance is stripped rather than layered over, so an inherited `Users` write ACE
/// cannot survive a repair.
///
/// `LocalService` needs `M` (modify, inherited by children) because it creates, replaces and
/// deletes `state.kv.tmp`/`state.kv` and appends to the log. `Users` keep `RX` so an ordinary
/// user can still read the log for support, and get nothing that lets them create or replace
/// anything the service will read.
pub const DATA_DIR_GRANTS: [(&str, &str, &str); 4] = [
    ("*S-1-5-18", "(OI)(CI)F", "NT AUTHORITY\\SYSTEM"),
    ("*S-1-5-32-544", "(OI)(CI)F", "BUILTIN\\Administrators"),
    ("*S-1-5-19", "(OI)(CI)M", "NT AUTHORITY\\LOCAL SERVICE"),
    ("*S-1-5-32-545", "(OI)(CI)RX", "BUILTIN\\Users"),
];

/// The commands that replace the data tree's DACL, in order.
///
/// Two phases, and the order matters:
///
/// 1. on each **directory**: strip inheritance and write the explicit grants. `(OI)(CI)` are
///    inheritance-only flags, which grant nothing to the object carrying them - so they belong on
///    directories and must never be applied to files. Applying them to a file leaves it with an
///    empty *effective* DACL, unreadable and unwritable by everyone including the service and
///    even Administrators (measured the hard way on this machine while writing this function).
/// 2. on each directory's **children**: `/reset`, which drops the bad explicit ACEs so the files
///    inherit effective rights from their parent instead.
///
/// Not `/T` on the grant step, for the reason above. `/C` so one unpublishable entry cannot leave
/// the pass half-applied without a report to judge.
pub fn data_tree_plan(dir: &str) -> Vec<Vec<String>> {
    let grants: Vec<String> = DATA_DIR_GRANTS
        .iter()
        .map(|(sid, rights, _)| format!("{sid}:{rights}"))
        .collect();
    let mut plan = Vec::new();
    for target in data_tree_dirs(dir) {
        plan.push(
            std::iter::once(target.clone())
                .chain(["/inheritance:r".into(), "/grant:r".into()])
                .chain(grants.iter().cloned())
                .chain(["/C".into()])
                .collect(),
        );
        plan.push(vec![format!("{target}\\*"), "/reset".into(), "/C".into()]);
    }
    plan
}

/// Directories whose DACL the plan owns; the installer must create them before applying it, since
/// `icacls` cannot grant on a path that does not exist.
pub fn data_tree_dirs(dir: &str) -> Vec<String> {
    vec![
        dir.to_string(),
        format!("{dir}\\state"),
        format!("{dir}\\logs"),
    ]
}

/// Rights on the **config file**, deliberately narrower than the tree's.
///
/// `LocalService` needs to read the backend selection; it has no business rewriting it. A daemon
/// that can edit its own configuration can turn a fail-closed default into an enabled experiment on
/// its own, which is precisely the kind of silent privilege growth an installer exists to prevent.
/// Administrators and System keep full control, so the operator can still change the setting.
///
/// Note the absence of `OI`/`CI` here: those are inheritance-only flags and grant nothing to the
/// object carrying them, so on a file they produce an empty effective DACL - measured the hard way on
/// this machine. Anything applied to a file must be plain rights.
pub const CONFIG_FILE_GRANTS: [(&str, &str, &str); 4] = [
    ("*S-1-5-18", "(F)", "NT AUTHORITY\\SYSTEM"),
    ("*S-1-5-32-544", "(F)", "BUILTIN\\Administrators"),
    ("*S-1-5-19", "(RX)", "NT AUTHORITY\\LOCAL SERVICE"),
    ("*S-1-5-32-545", "(RX)", "BUILTIN\\Users"),
];

/// The `icacls` arguments that narrow the config file to service-read-only. The caller skips this
/// when the file does not exist yet - normal on a fresh install, where the config is written after
/// the tree is hardened, and a later repair pass applies it.
pub fn config_file_args(path: &str) -> Vec<String> {
    let mut args: Vec<String> = vec![path.to_string(), "/inheritance:r".into(), "/grant:r".into()];
    args.extend(
        CONFIG_FILE_GRANTS
            .iter()
            .map(|(sid, rights, _)| format!("{sid}:{rights}")),
    );
    args.push("/C".into());
    args
}

/// Atomic rights the model reasons about.
///
/// `icacls` reports coarse shorthands (`F`, `M`, `W`, `RX`) alongside narrow ones (`WD`, `DC`), and an
/// allow/deny comparison done on those literal tokens is simply wrong: an ACE granting `F` and a deny
/// ACE for `W` share no text yet the deny removes write access, and `(D)` is the delete right while
/// `(DENY)` is a flag. Every token is therefore expanded into this small set before anything is
/// compared, and a deny only subtracts rights it actually covers.
const READ: &str = "READ";
const EXECUTE: &str = "EXECUTE";
const WRITE_DATA: &str = "WRITE_DATA";
const APPEND_DATA: &str = "APPEND_DATA";
const WRITE_EA: &str = "WRITE_EA";
const WRITE_DAC: &str = "WRITE_DAC";
const WRITE_OWNER: &str = "WRITE_OWNER";
const DELETE: &str = "DELETE";
const DELETE_CHILD: &str = "DELETE_CHILD";

const ALL_RIGHTS: [&str; 9] = [
    READ,
    EXECUTE,
    WRITE_DATA,
    APPEND_DATA,
    WRITE_EA,
    WRITE_DAC,
    WRITE_OWNER,
    DELETE,
    DELETE_CHILD,
];

/// Everything that lets a principal create, replace, delete or re-permission an entry. Execute is
/// deliberately not one of them: running a binary is not the same claim as being able to replace it.
const PERTURBING: [&str; 7] = [
    WRITE_DATA,
    APPEND_DATA,
    WRITE_EA,
    WRITE_DAC,
    WRITE_OWNER,
    DELETE,
    DELETE_CHILD,
];

/// Expand one `icacls` rights token. An unrecognised token expands to nothing: it neither grants nor
/// denies, which keeps an unexpected spelling from being read as a capability.
fn expand_right(token: &str) -> &'static [&'static str] {
    match token.to_ascii_uppercase().as_str() {
        // full control
        "F" => &ALL_RIGHTS,
        // modify: everything except changing the DACL or the owner
        "M" => &[
            READ,
            EXECUTE,
            WRITE_DATA,
            APPEND_DATA,
            WRITE_EA,
            DELETE,
            DELETE_CHILD,
        ],
        // generic write
        "W" => &[WRITE_DATA, APPEND_DATA, WRITE_EA],
        "RX" | "RE" => &[READ, EXECUTE],
        "R" | "RD" | "RA" | "GEA" => &[READ],
        // `(D)` is icacls for delete - not a denial, which is `(DENY)`
        "D" | "DE" => &[DELETE],
        "DC" => &[DELETE_CHILD],
        "WD" => &[WRITE_DATA],
        "AD" => &[APPEND_DATA],
        "WEA" => &[WRITE_EA],
        "WA" => &[WRITE_DATA, APPEND_DATA],
        "WO" => &[WRITE_OWNER],
        "S" => &[WRITE_DAC],
        // "no access", and anything we cannot name
        _ => &[],
    }
}

/// Inheritance markers are flags, not rights.
fn is_inherit_flag(token: &str) -> bool {
    matches!(token, "I" | "OI" | "CI" | "IO" | "NP")
}

/// SIDs an ordinary interactive user is actually a member of, i.e. everyone who is not an
/// administrator on the machine.
const NON_PRIVILEGED_TRUSTEES: [&str; 5] = [
    "BUILTIN\\Users",
    "NT AUTHORITY\\Authenticated Users",
    "Everyone",
    "NT AUTHORITY\\INTERACTIVE",
    "INTERACTIVE",
];

/// The rights the daemon itself needs on the tree it owns: write its state file, append to the log,
/// and - on a directory - create those files in the first place. `WRITE_DATA` and `APPEND_DATA` carry
/// both meanings, which is how `icacls` writes them for files and containers alike.
const SERVICE_WRITE: [&str; 2] = [WRITE_DATA, APPEND_DATA];
/// Rights that let a principal read a file at all - including the narrow read-only grants the
/// config file is supposed to end up with.
const SERVICE_READ: [&str; 1] = [READ];

/// Shared walk: does `trustee` effectively hold any of `wanted` on the reported object?
///
/// "Effectively" is the whole point. Windows evaluates the deny ACEs first, so a principal that holds
/// `F` from one ACE and is denied `W` by another cannot write - and a check that only skips the deny
/// ACE while still reading the allow ACE says "can write", which is how a DACL acceptance could pass
/// on a machine where the access is actually refused. Rights are expanded to atoms first, so the
/// comparison works for the coarse shorthands too.
///
/// `file` says what the report describes. On a **file**, an ACE that is not marked `(I)` and carries
/// `OI`/`CI` is pending inheritance: it grants nothing to that object, which is the trap that made
/// this machine's `state.kv` unreadable. Inheritance flags alone must never be read as access.
fn principal_holds(report: &str, trustee: &str, file: bool, wanted: &[&str]) -> bool {
    let (allowed, denied) = trustee_effective_rights(report, trustee, file);
    wanted
        .iter()
        .any(|right| allowed.iter().any(|a| a == right) && !denied.iter().any(|d| d == right))
}

/// Hardening that locks the service out of its own files is not a fix - that is exactly how an
/// inherit-only ACE applied to a file behaves - so both halves are asserted before anything is
/// reported as done.
pub fn principal_can_write(report: &str, trustee: &str, file: bool) -> bool {
    principal_holds(report, trustee, file, &SERVICE_WRITE)
}

/// The read side, needed to prove the config file is still readable after it is narrowed to
/// `(RX)` - a hardening step that silently broke reading would be caught here rather than by a
/// service that comes up on the wrong backend.
pub fn principal_can_read(report: &str, trustee: &str, file: bool) -> bool {
    principal_holds(report, trustee, file, &SERVICE_READ)
}

/// The trustee of an ACE: `icacls` writes `PRINCIPAL:(flags)(rights)`, with the principal
/// possibly containing spaces (`NT AUTHORITY\LOCAL SERVICE`) and the first one on a line glued to
/// the reported path. So a trustee is recognised as a known name that the text before `:(`
/// *ends* with, preceded by a space or the start of the segment - never a substring of a longer
/// word.
fn ends_with_trustee(text: &str, name: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let needle = name.to_ascii_lowercase();
    if !lower.ends_with(&needle) {
        return false;
    }
    match lower.len().checked_sub(needle.len()) {
        // The name is the whole text before `:(`.
        Some(0) => true,
        // ...or it starts at a boundary, so `BUILTIN\Administrators` cannot match `BUILTIN\Users`
        // and a path component ending in the same letters cannot either.
        Some(i) => matches!(lower.as_bytes()[i - 1], b' ' | b'\\'),
        None => false,
    }
}

/// The right groups of one ACE, as written after its `:(`. Public because "is this the shape our own
/// installer produced?" has to be asked from another module, and re-implementing the parse there is
/// how two copies of the same ACL grammar start disagreeing.
pub fn ace_groups(text: &str) -> Vec<Vec<String>> {
    groups_after(text)
}

/// Rights groups following a `:(`, as raw token lists, stopping at the first token that is
/// another trustee (i.e. when we reach the next `:(`).
fn groups_after(text: &str) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    let mut rest = text;
    while rest.starts_with('(') {
        match rest.find(')') {
            Some(end) => {
                out.push(
                    rest[1..end]
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .collect(),
                );
                rest = &rest[end + 1..];
                if rest.starts_with(' ') {
                    rest = rest[1..].trim_start();
                }
            }
            None => break,
        }
    }
    out
}

/// Names that must never hold a write-like right on the service image or its directory. This is a
/// deny-list by nature, so it cannot be the only answer: a local group nobody thought of, a renamed
/// account, or an ACL line in a form the parser does not recognise would be read as safe.
/// `unexpected_write_grants` is the complementary check, and it fails closed.
pub fn standard_user_can_perturb(report: &str) -> bool {
    NON_PRIVILEGED_TRUSTEES
        .iter()
        .any(|trustee| effective_perturbing(report, trustee))
}

/// Rights a trustee actually holds on the reported object, as atoms: allow ACEs grant, deny ACEs take
/// away, and Windows evaluates deny first.
///
/// `file` applies the pending-inheritance rule described on `principal_holds`. Tokens are expanded via
/// `expand_right` so a deny of `W` subtracts what an allow of `F` granted, instead of the two failing
/// to match as text.
fn trustee_effective_rights(
    report: &str,
    trustee: &str,
    file: bool,
) -> (Vec<&'static str>, Vec<&'static str>) {
    let mut allowed: Vec<&'static str> = Vec::new();
    let mut denied: Vec<&'static str> = Vec::new();
    for line in report.lines() {
        let mut cursor = 0usize;
        while let Some(offset) = line[cursor..].find(":(") {
            let at = cursor + offset;
            let before = &line[..at];
            let after = &line[at + 1..];
            cursor = at + 1;
            let same_name = ends_with_trustee(before, trustee)
                || before.trim().eq_ignore_ascii_case(trustee.trim());
            if !same_name {
                continue;
            }
            let groups = groups_after(after);
            if groups.is_empty() {
                continue;
            }
            let tokens: Vec<String> = groups.iter().flatten().cloned().collect();
            let inherited = tokens.iter().any(|t| t == "I");
            let inherit_only = tokens.iter().any(|t| t == "OI" || t == "CI");
            if file && !inherited && inherit_only {
                // pending inheritance: nothing on this object
                continue;
            }
            let deny_ace = tokens.iter().any(|t| t.eq_ignore_ascii_case("DENY"));
            for token in &tokens {
                if is_inherit_flag(token) || token.eq_ignore_ascii_case("DENY") {
                    continue;
                }
                for atom in expand_right(token) {
                    let bucket = if deny_ace { &mut denied } else { &mut allowed };
                    if !bucket.contains(atom) {
                        bucket.push(*atom);
                    }
                }
            }
        }
    }
    (allowed, denied)
}

/// True when `trustee` holds a write-like right that nothing in the same ACL denies it.
fn effective_perturbing(report: &str, trustee: &str) -> bool {
    principal_holds(report, trustee, false, &PERTURBING)
}

/// Every principal that holds a write-like right, minus the ones the caller explicitly allows.
///
/// Unlike `standard_user_can_perturb`, this treats an ACE it cannot classify as a finding: the
/// question an installer must answer is "who can replace the service image", and "some name I do not
/// recognise, holding (WD,AD,WEA)" is not an answer of "nobody".
///
/// Returns human-readable findings; empty means every write grant in the report belongs to
/// `allowed_writers` and every ACE line could be read.
pub fn unexpected_write_grants(report: &str, allowed_writers: &[&str]) -> Vec<String> {
    let mut findings = Vec::new();
    let mut saw_ace = false;
    // collect every trustee the report mentions, then judge each one's effective rights: a trustee
    // can appear in several lines and ACEs, and deny only wins against that same trustee's grants
    let mut trustees: Vec<String> = Vec::new();
    for line in report.lines() {
        let mut cursor = 0usize;
        while let Some(offset) = line[cursor..].find(":(") {
            let at = cursor + offset;
            let before = line[..at].trim().to_string();
            cursor = at + 1;
            saw_ace = true;
            // `icacls` glues the reported path to the first trustee on the line, and indents the rest.
            // Splitting on the first `": "` separates them; matching the whole segment instead would
            // never equal a trustee name, so every finding would silently disappear.
            let trustee = match before.split_once(": ") {
                Some((_path, who)) => who.trim().to_string(),
                None => before.trim().to_string(),
            };
            if trustee.is_empty() {
                continue;
            }
            if !trustees
                .iter()
                .any(|t: &String| t.eq_ignore_ascii_case(&trustee))
            {
                trustees.push(trustee);
            }
        }
    }
    if !saw_ace {
        findings.push(
            "the report contained no readable ACE, so the permissions are unknown".to_string(),
        );
        return findings;
    }
    for trustee in &trustees {
        // judge from the whole report so a deny ACE on another line still counts, and judge the
        // effective rights: an unrecognized trustee with `F` and a matching deny is not a finding,
        // while one holding only `WA` is
        let holds = principal_holds(report, trustee, false, &PERTURBING);
        if !holds {
            continue;
        }
        let writer = allowed_writers.iter().any(|w| {
            trustee
                .to_ascii_lowercase()
                .ends_with(&w.to_ascii_lowercase())
        });
        if !writer {
            let (granted, denied) = trustee_effective_rights(report, trustee, false);
            findings.push(format!(
                "{trustee} holds a write-like right and is not an allowed writer (effective {granted:?}, denied {denied:?})"
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deny ACE grants nothing. This matters in the direction that hurts: a check that read
    /// `(DENY)(WD,AD)` as "holds WD" could report an account as able to write when the ACL forbids it,
    /// and the reverse - reading the *rights* letter `D` (delete) as a denial - would hide a real
    /// delete right, so both halves are pinned.
    #[test]
    fn deny_ace_grants_nothing_while_the_delete_right_still_counts() {
        let denied = r"C:\Program Files\CM400\bin\cm400d.exe: NT AUTHORITY\SYSTEM:(DENY)(F)";
        assert!(
            !principal_can_write(denied, "NT AUTHORITY\\SYSTEM", true),
            "an explicit deny must not be read as a grant"
        );
        let deleter = r"C:\x\cm400d.exe: BUILTIN\Users:(D)";
        assert!(
            standard_user_can_perturb(deleter),
            "`(D)` is the delete right, not a denial"
        );
        let mixed = r"C:\x\cm400d.exe: BUILTIN\Users:(DENY)(WD,AD)";
        assert!(
            !standard_user_can_perturb(mixed),
            "a denied write is not a capability"
        );
    }

    /// The case token-matching cannot express: a coarse allow and a coarse deny for the same trustee.
    /// `F` and `W` share no text, yet the deny of generic write takes the write atoms away from full
    /// control, so an implementation that merely skips deny ACEs would still report "can write".
    #[test]
    fn a_deny_subtracts_from_a_coarser_allow_for_the_same_trustee() {
        let report = "C:\\ProgramData\\CM400\\state: NT AUTHORITY\\LOCAL SERVICE:(F)\r\n             NT AUTHORITY\\LOCAL SERVICE:(DENY)(W)\r\n";
        assert!(
            !principal_can_write(report, "NT AUTHORITY\\LOCAL SERVICE", true),
            "deny of W must subtract from an allow of F: {report}"
        );
        assert!(
            principal_can_read(report, "NT AUTHORITY\\LOCAL SERVICE", true),
            "the deny covers write only, so reading is still granted"
        );

        // denying delete leaves the create/replace rights alone - the opposite over-reaction
        let delete_only = "C:\\x: BUILTIN\\Users:(M)\r\n     BUILTIN\\Users:(DENY)(D)\r\n";
        assert!(principal_can_write(delete_only, "BUILTIN\\Users", true));
        assert!(
            standard_user_can_perturb(delete_only),
            "still able to create and replace"
        );

        // and a trustee whose grant is fully denied holds nothing the checks should treat as access
        let fully_denied = "C:\\x: BUILTIN\\Users:(F)\r\n     BUILTIN\\Users:(DENY)(F)\r\n";
        assert!(!standard_user_can_perturb(fully_denied));
        assert!(!principal_can_write(fully_denied, "BUILTIN\\Users", true));
        assert!(!principal_can_read(fully_denied, "BUILTIN\\Users", true));
    }

    /// The installer's acceptance question runs the other way too: when an administrator is the one
    /// being denied, `principal_can_write` must answer false rather than leaning on the allow ACE,
    /// because that answer is what decides whether a hardening step counts as done.
    #[test]
    fn a_denied_administrator_is_not_counted_as_able_to_write() {
        // both write atoms denied: denying only `WD` would still leave `AD`, and reporting "cannot
        // write" in that case would be the test being wrong rather than the ACL being tight
        let report = "C:\\Program Files\\CM400\\bin: NT AUTHORITY\\SYSTEM:(F)\r\n     BUILTIN\\Administrators:(DENY)(WD,AD)\r\n     BUILTIN\\Administrators:(F)\r\n";
        assert!(principal_can_write(report, "NT AUTHORITY\\SYSTEM", false));
        assert!(
            !principal_can_write(report, "BUILTIN\\Administrators", false),
            "create-files and append-data denied for Administrators must not read as writable"
        );
        // they still hold delete and DACL rights from `F`, which is a perturbation the deny-list
        // cannot see, so the acceptance answer for "can write content" and "can disturb entries"
        // are deliberately different here
        assert!(
            principal_holds(report, "BUILTIN\\Administrators", false, &PERTURBING),
            "partial denial must not pretend the trustee holds nothing"
        );
        // nobody outside the allowed writers holds an effective write right here: the denied
        // administrator contributes nothing, and SYSTEM is permitted
        assert_eq!(
            unexpected_write_grants(report, &["NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators"]),
            Vec::<String>::new(),
            "{report}"
        );

        // the same shape with a stranger: partial denial still leaves the trustee able to perturb
        let stranger = "C:\\x: NT AUTHORITY\\SYSTEM:(F)\r\n     MYCORP\\Bob:(M)\r\n     MYCORP\\Bob:(DENY)(D)\r\n";
        let findings = unexpected_write_grants(stranger, &["NT AUTHORITY\\SYSTEM"]);
        assert_eq!(
            findings.len(),
            1,
            "Bob keeps create/append rights: {findings:?}"
        );
        assert!(findings[0].contains("Bob"), "{findings:?}");
    }

    /// The fail-closed half of the ACL question: an unrecognised principal holding a write-like right,
    /// or a report from which no ACE can be read, is a finding rather than a clean result.
    #[test]
    fn unknown_write_grantees_and_unreadable_reports_are_findings() {
        let allowed = ["NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators"];
        let good = "C:\\x: NT AUTHORITY\\SYSTEM:(OI)(CI)(F)\r\n             BUILTIN\\Administrators:(OI)(CI)(F)\r\n             BUILTIN\\Users:(I)(OI)(CI)(RX)\r\n";
        assert_eq!(
            unexpected_write_grants(good, &allowed),
            Vec::<String>::new(),
            "only the two administrators write, and Users is read/execute"
        );

        let mystery_group = "C:\\x: MYCORP\\DeployAgents:(OI)(CI)(M)\r\n";
        let findings = unexpected_write_grants(mystery_group, &allowed);
        assert_eq!(findings.len(), 1, "{:?}", findings);
        assert!(findings[0].contains("DeployAgents"), "{findings:?}");

        // the same line the deny-list would have missed, because the name is not in it
        assert!(
            !standard_user_can_perturb(mystery_group),
            "the deny-list cannot see a group it does not know - which is why this check exists"
        );

        let nothing_readable = "C:\\x: <unreadable>\r\n";
        let findings = unexpected_write_grants(nothing_readable, &allowed);
        assert!(
            findings.iter().any(|f| f.contains("no readable ACE")),
            "an unknown ACL state is not a safe one: {findings:?}"
        );
    }

    /// Captured with `icacls C:\ProgramData\CM400` on 2026-10-12, before hardening - the real
    /// inherited state this module exists to remove, including the trailing localized summary line
    /// `icacls` prints on this machine.
    const BEFORE_DIR: &str = r#"C:\ProgramData\CM400 NT AUTHORITY\LOCAL SERVICE:(OI)(CI)(M)
                     NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
                     BUILTIN\Administrators:(I)(OI)(CI)(F)
                     CREATOR OWNER:(I)(OI)(CI)(IO)(F)
                     BUILTIN\Users:(I)(OI)(CI)(RX)
                     BUILTIN\Users:(I)(CI)(WD,AD,WEA,WA)

已成功处理 1 个文件; 处理 0 个文件时失败
"#;

    /// What the hardened tree is expected to read like (verified against the machine afterwards).
    const AFTER_DIR: &str = r#"C:\ProgramData\CM400 BUILTIN\Administrators:(OI)(CI)(F)
                     NT AUTHORITY\SYSTEM:(OI)(CI)(F)
                     NT AUTHORITY\LOCAL SERVICE:(OI)(CI)(M)
                     BUILTIN\Users:(OI)(CI)(RX)
"#;

    /// The measured pre-state must be flagged. If this assertion ever stops firing, the detector
    /// is what broke - not the machine.
    #[test]
    fn flags_the_measured_inherited_write_ace() {
        assert!(
            standard_user_can_perturb(BEFORE_DIR),
            "the Users child-create ACE is exactly what must be reported"
        );
    }

    /// The first ACE of a file report is glued to the path (`C:\dir\name BUILTIN\Users:(I)(W)`).
    /// A detector that only worked on continuation lines would pass a sloppy fixture and fail on
    /// the real thing, so the shape with the path prefix is asserted on its own.
    #[test]
    fn sees_the_first_entry_of_a_path_prefixed_line() {
        let one_line = r#"C:\ProgramData\CM400\config.toml BUILTIN\Users:(I)(W)"#;
        assert!(standard_user_can_perturb(one_line));
        let one_line_ok = r#"C:\ProgramData\CM400\config.toml BUILTIN\Users:(I)(RX)"#;
        assert!(!standard_user_can_perturb(one_line_ok));
        // And a drive-lettered path must not be mistaken for a trustee on its own.
        assert!(!standard_user_can_perturb(r#"C:\ProgramData\CM400"#));
    }

    #[test]
    fn accepts_a_tree_that_only_grants_read_to_non_privileged_users() {
        assert!(!standard_user_can_perturb(AFTER_DIR));
    }

    /// Both halves of the judgement: the service keeps write access to its own tree, and a
    /// directory where an inherit-only ACE was pushed onto the files is reported as locked out.
    #[test]
    fn service_write_check_catches_a_lockout_it_cause() {
        let good_file = r#"C:\ProgramData\CM400\state\state.kv NT AUTHORITY\LOCAL SERVICE:(I)(M)
                     BUILTIN\Users:(I)(RX)
"#;
        assert!(principal_can_write(
            good_file,
            "NT AUTHORITY\\LOCAL SERVICE",
            true
        ));
        assert!(!standard_user_can_perturb(good_file));
        // The broken shape measured on this machine: the service's ACE is inherit-only, so the
        // file grants it nothing even though the text looks like a modify grant.
        let locked = r#"C:\ProgramData\CM400\state\state.kv NT AUTHORITY\LOCAL SERVICE:(OI)(CI)(M)
                     BUILTIN\Users:(I)(RX)
"#;
        assert!(
            !principal_can_write(locked, "NT AUTHORITY\\LOCAL SERVICE", true),
            "an inherit-only ACE on a file must read as no access"
        );
        // On a directory the same ACE does apply, to the children - so the same text is judged
        // differently depending on the object it sits on.
        assert!(principal_can_write(
            locked,
            "NT AUTHORITY\\LOCAL SERVICE",
            false
        ));
        assert!(!principal_can_write(good_file, "BUILTIN\\IIS_IUSRS", true));
    }

    #[test]
    fn reads_the_real_iccacls_shape_not_just_a_pretty_print() {
        // The single-line form for a file, trustee separated by a space.
        let cfg = r#"C:\ProgramData\CM400\config.toml NT AUTHORITY\LOCAL SERVICE:(I)(M)
                                 NT AUTHORITY\SYSTEM:(I)(F)
                                 BUILTIN\Administrators:(I)(F)
                                 BUILTIN\Users:(I)(RX)
"#;
        assert!(!standard_user_can_perturb(cfg), "read-only Users is fine");
        // Same shape, one group changed to a write right.
        let bad = cfg.replace("BUILTIN\\Users:(I)(RX)", "BUILTIN\\Users:(I)(W)");
        assert!(standard_user_can_perturb(&bad));
    }

    /// Other non-privileged identities are the same problem, and inheritance markers do not
    /// change that judgement.
    #[test]
    fn catches_every_other_writable_shape() {
        for (text, expected) in [
            ("X Everyone:(I)(OI)(CI)(RX)", false),
            ("X Everyone:(I)(OI)(CI)(M)", true),
            ("X NT AUTHORITY\\Authenticated Users:(I)(CI)(AD)", true),
            ("X BUILTIN\\Users:(I)(OI)(CI)(R)", false),
            ("X BUILTIN\\Users:(I)(CI)(DC)", true),
            // An administrator ACE is not perturbation by a standard user.
            ("X BUILTIN\\Administrators:(I)(OI)(CI)(F)", false),
            ("X CREATOR OWNER:(I)(OI)(CI)(IO)(F)", false),
        ] {
            assert_eq!(standard_user_can_perturb(text), expected, "line: {text}");
        }
    }

    /// The config file gets a narrower DACL than the tree around it, and it must never carry
    /// inheritance-only flags - that combination is what made this machine's service files unusable.
    #[test]
    fn the_config_file_is_read_only_for_the_service() {
        let args = config_file_args("C:\\ProgramData\\CM400\\config.toml");
        assert!(args[0].ends_with("config.toml"));
        assert!(args.iter().any(|a| a == "/inheritance:r"));
        assert!(args.iter().any(|a| a == "/grant:r"));
        assert!(
            !args.iter().any(|a| a == "/T"),
            "a file step must not walk the tree"
        );
        for (sid, rights, name) in CONFIG_FILE_GRANTS {
            assert!(
                !rights.contains("OI") && !rights.contains("CI"),
                "{name} would get inheritance-only flags on a file: {rights}"
            );
            assert!(args.contains(&format!("{sid}:{rights}")), "missing {name}");
        }
        // The service reads and may not write: no token in its group is a write right.
        let ls = CONFIG_FILE_GRANTS
            .iter()
            .find(|(sid, _, _)| *sid == "*S-1-5-19")
            .unwrap();
        assert_eq!(ls.1, "(RX)");
        assert!(!principal_can_write(
            "C:\\x\\config.toml NT AUTHORITY\\LOCAL SERVICE:(I)(RX)",
            "NT AUTHORITY\\LOCAL SERVICE",
            true
        ));
        // And the narrower file DACL still reads as closed to ordinary users.
        assert!(!standard_user_can_perturb(
            "C:\\ProgramData\\CM400\\config.toml BUILTIN\\Users:(I)(RX) NT AUTHORITY\\SYSTEM:(I)(F)"
        ));
    }

    /// The plan must put inherit-only grants on directories and nothing else, and must reset the
    /// children so they inherit effective rights. `(OI)(CI)` on a file is an empty DACL wearing a
    /// mask, which is the failure this shape exists to prevent.
    #[test]
    fn hardening_grants_on_directories_and_resets_children() {
        let plan = data_tree_plan("C:\\ProgramData\\CM400");
        assert_eq!(plan.len(), 6, "grant + reset for the tree, state and logs");
        for (i, step) in plan.iter().enumerate() {
            assert!(
                step.iter().any(|a| a == "/C"),
                "step {i} must not stop half-applied"
            );
            assert!(
                !step.iter().any(|a| a == "/T"),
                "step {i} must not push inherit-only ACEs onto files"
            );
            if i % 2 == 0 {
                assert!(
                    step.iter().any(|a| a == "/inheritance:r"),
                    "step {i} strips inheritance"
                );
                assert!(
                    step.iter().any(|a| a == "/grant:r"),
                    "step {i} replaces, not adds"
                );
                for (sid, rights, name) in DATA_DIR_GRANTS {
                    let grant = format!("{sid}:{rights}");
                    assert!(step.contains(&grant), "missing grant for {name}");
                }
            } else {
                assert!(
                    step.iter().any(|a| a == "/reset"),
                    "step {i} resets children"
                );
                assert!(
                    step[0].ends_with("\\*"),
                    "step {i} targets children: {}",
                    step[0]
                );
            }
        }
        // LocalService keeps modify: without it the atomic state save cannot replace its own
        // temp file, and hardening that breaks the service is not a fix.
        assert!(DATA_DIR_GRANTS
            .iter()
            .any(|(sid, r, _)| *sid == "*S-1-5-19" && *r == "(OI)(CI)M"));
        // Ordinary users must not appear with any write-ish right in the intended set.
        assert_eq!(DATA_DIR_GRANTS[3].1, "(OI)(CI)RX");
    }
}
