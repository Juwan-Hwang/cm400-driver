//! Whole-package integrity, verified as a set.
//!
//! Why this is a module and not a line in a script: the release model tells a user to verify the
//! SHA-256 of **every** file the installer will read. Checking only the executable would leave the
//! INF, the catalog and the certificate beside it free to be replaced, and the installer would then
//! establish trust for a package nobody verified. The manifest is therefore a precondition of the
//! trust step, in code, with its own exit code.
//!
//! The names inside the file are treated as untrusted input. A manifest entry is a filename, so a
//! path that escapes the package folder (`..\x`, an absolute path, or one with an alternate data
//! stream) is refused rather than opened - otherwise "verify the package" would mean "hash files
//! anywhere on disk and call it a package".

use std::path::{Component, Path};

/// One line of `SHA256SUMS.txt`, already validated as `<64 hex>  <relative file name>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub sha256: String,
    pub name: String,
}

/// What a verification pass found. `clean()` is what the installer checks before trusting anything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    pub checked: usize,
    pub problems: Vec<String>,
}

impl Report {
    pub fn clean(&self) -> bool {
        self.problems.is_empty()
    }
}

/// The files an install actually consumes. A manifest that omits one of them proves nothing about it,
/// so `verify_dir` is not enough on its own: the file the service will run could simply be left off the
/// list and swapped without any hash disagreeing.
///
/// `cm400.cat` and `SHA256SUMS.txt` are deliberately absent: neither can carry its own digest. The
/// catalog is the signed object itself, and the manifest is attested a stronger way - by being a member
/// of that catalog (`install_flow` checks `file_catalog_membership`).
pub const REQUIRED_FILES: [&str; 4] = ["cm400-setup.exe", "cm400d.exe", "cm400.inf", "cm400.cer"];

/// Which required files the manifest does not speak about.
pub fn uncovered<'a>(entries: &'a [Entry], required: &[&'a str]) -> Vec<&'a str> {
    let listed: Vec<String> = entries
        .iter()
        .map(|e| e.name.replace('\\', "/").to_ascii_lowercase())
        .collect();
    required
        .iter()
        .filter(|name| !listed.contains(&name.replace('\\', "/").to_ascii_lowercase()))
        .copied()
        .collect()
}

/// Parse the manifest. Deliberately strict about shape: a truncated digest, a non-hex digest, or a
/// name that could escape the package folder is an error for the whole file, not one bad line to
/// skip. Skipping is how an attacker-supplied manifest would hide entries.
pub fn parse(text: &str) -> Result<Vec<Entry>, String> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(digest), Some(name), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(format!(
                "line {}: expected `<sha256> <file>`, got {line:?}",
                n + 1
            ));
        };
        if digest.len() != 64 || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("line {}: {digest} is not a SHA-256 digest", n + 1));
        }
        if !is_safe_relative_name(name) {
            return Err(format!(
                "line {}: {name} is not a name inside the package folder",
                n + 1
            ));
        }
        out.push(Entry {
            sha256: digest.to_ascii_uppercase(),
            name: name.to_string(),
        });
    }
    if out.is_empty() {
        return Err("the manifest lists no files".to_string());
    }
    Ok(out)
}

fn is_safe_relative_name(name: &str) -> bool {
    if name.is_empty() || name.contains(':') || name.starts_with('/') || name.starts_with('\\') {
        return false;
    }
    // `Component` normalises the interesting cases: parent-directory hops, repeated separators, and
    // path roots all show up as something other than `Normal`.
    Path::new(name)
        .components()
        .all(|c| matches!(c, Component::Normal(_)))
}

/// Hash every file the manifest names, in `dir`. Missing files are problems, not skips.
#[cfg(target_os = "windows")]
pub fn verify_dir(dir: &Path) -> Result<Report, String> {
    let path = dir.join("SHA256SUMS.txt");
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("no package manifest at {}: {e}", path.display()))?;
    let entries = parse(&text)?;
    let mut report = Report::default();
    // A manifest that stays silent about a file the install consumes attests nothing about it, so the
    // gap is reported here rather than being left for a caller to remember to check.
    for gap in uncovered(&entries, &REQUIRED_FILES) {
        report.problems.push(format!(
            "{gap} is used by the installer but is not covered by SHA256SUMS.txt"
        ));
    }
    for entry in entries {
        let file = dir.join(&entry.name);
        if !file.exists() {
            report.problems.push(format!(
                "{} is listed in the manifest but absent from the package",
                entry.name
            ));
            continue;
        }
        match sha256_of_file(&file) {
            Some(actual) if actual == entry.sha256 => report.checked += 1,
            Some(actual) => report.problems.push(format!(
                "{} has SHA-256 {actual}, the manifest says {}",
                entry.name, entry.sha256
            )),
            None => report
                .problems
                .push(format!("{} could not be hashed", entry.name)),
        }
    }
    Ok(report)
}

/// `certutil` is present on every Windows install, so this adds no dependency and no assumption
/// about what else the machine has. Only the line that is purely hex counts, because the header and
/// trailer are localized text (and localized bytes are how a "successful" parse once came back as
/// mojibake elsewhere in this project).
#[cfg(target_os = "windows")]
pub fn sha256_of_file(path: &Path) -> Option<String> {
    let out = std::process::Command::new("certutil.exe")
        .arg("-hashfile")
        .arg(path)
        .arg("SHA256")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|line| {
            // joined without whitespace, so a digest printed in spaced or wrapped form still matches
            let t: String = line
                .trim()
                .chars()
                .filter(|c| !c.is_whitespace() && *c != ':')
                .collect::<String>()
                .to_ascii_uppercase();
            (t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit())).then_some(t)
        })
}

#[cfg(not(target_os = "windows"))]
pub fn sha256_of_file(_path: &Path) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: &str = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

    #[test]
    fn the_manifest_shape_is_strict() {
        let good = format!("{H}  cm400.inf\n# comment\n\n{H}  cm400-setup.exe\n");
        let entries = parse(&good).expect("two entries");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "cm400.inf");

        assert!(parse("").is_err(), "an empty manifest is not a manifest");
        assert!(parse("not-a-pair").is_err());
        assert!(
            parse(&format!("{}  cm400.inf", &H[..62])).is_err(),
            "a short digest is refused"
        );
        assert!(
            parse(&format!("{H}x  cm400.inf")).is_err(),
            "a long digest is refused"
        );
        assert!(
            parse(&format!("{H}  a  b")).is_err(),
            "extra columns mean the format is not what we think"
        );
        assert!(
            parse(&format!("{}  cm400.inf", "Z".repeat(64))).is_err(),
            "non-hex is refused"
        );
    }

    /// A manifest is a list of files to hash. If a line can name a file outside the package, hashing
    /// "the package" means hashing whatever the operator was pointed at.
    #[test]
    fn names_that_escape_the_package_are_refused() {
        for name in [
            "../outside",
            "..\\outside",
            "sub/../../x",
            "C:\\Windows\\win.ini",
            "/etc/passwd",
            "\\\\server\\share\\x",
            "cm400.inf:secret",
            "",
        ] {
            let text = format!("{H}  {name}\n");
            assert!(
                parse(&text).is_err(),
                "{name:?} must not be accepted as a package-relative name"
            );
        }
        // ordinary nesting inside the package is fine
        assert!(parse(&format!("{H}  docs/readme.md\n")).is_ok());
    }

    /// The hole this closes: every listed hash can match and the install can still be unattested, if
    /// the file the service will run was simply left off the list.
    #[test]
    fn a_manifest_can_leave_a_used_file_unattested() {
        let text = format!("{H}  cm400.inf\n{H}  cm400-setup.exe\n");
        let entries = parse(&text).expect("well formed");
        let gaps = uncovered(&entries, &REQUIRED_FILES);
        assert!(
            gaps.contains(&"cm400d.exe"),
            "the daemon must be reported missing: {gaps:?}"
        );
        assert!(
            gaps.contains(&"cm400.cer"),
            "the release certificate too: {gaps:?}"
        );
        assert_eq!(gaps.len(), 2, "{:?} - cer and daemon, nothing else", gaps);

        let full = ["cm400-setup.exe", "cm400d.exe", "cm400.inf", "cm400.cer"]
            .iter()
            .map(|n| format!("{H}  {n}"))
            .collect::<Vec<_>>()
            .join("\n");
        let entries = parse(&full).expect("full manifest");
        assert!(
            uncovered(&entries, &REQUIRED_FILES).is_empty(),
            "a complete manifest covers what is used"
        );

        // case and separators must not fabricate a gap, and a traversal name is refused outright
        let odd = parse(
            &[
                format!("{H}  CM400D.EXE"),
                format!("{H}  cm400-setup.exe"),
                format!("{H}  cm400.inf"),
                format!("{H}  cm400.cer"),
            ]
            .join("\n"),
        )
        .expect("upper case is still the same file");
        assert!(
            uncovered(&odd, &REQUIRED_FILES).is_empty(),
            "case-insensitive matching"
        );
        assert!(
            parse(&format!("{H}  ..\\cm400d.exe")).is_err(),
            "cannot smuggle a path out of the package"
        );
    }

    /// A complete package, because the required-coverage rule makes a two-file manifest an automatic
    /// failure and that would hide the three cases this test is actually about.
    #[cfg(target_os = "windows")]
    fn staged_package(dir: &Path) {
        for name in REQUIRED_FILES {
            std::fs::write(dir.join(name), format!("contents of {name}")).unwrap();
        }
    }

    #[cfg(target_os = "windows")]
    fn write_manifest(dir: &Path, extra_line: Option<&str>) {
        let mut text = String::new();
        for name in REQUIRED_FILES {
            let hash = sha256_of_file(&dir.join(name)).expect("certutil must hash a local file");
            text.push_str(&format!("{hash}  {name}\n"));
        }
        if let Some(extra) = extra_line {
            text.push_str(extra);
        }
        std::fs::write(dir.join("SHA256SUMS.txt"), text).unwrap();
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn a_mismatch_or_a_missing_file_is_a_problem_not_a_pass() {
        let dir = std::env::temp_dir().join(format!("cm400-manifest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // the baseline: complete coverage, everything matches
        staged_package(&dir);
        write_manifest(&dir, None);
        let report = verify_dir(&dir).unwrap();
        assert!(
            report.clean(),
            "a full package must pass, got {:?}",
            report.problems
        );
        assert_eq!(report.checked, REQUIRED_FILES.len());

        // a listed file that is not there
        write_manifest(
            &dir,
            Some("F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7  gone.txt\n"),
        );
        let report = verify_dir(&dir).unwrap();
        assert!(!report.clean());
        assert!(
            report.problems.iter().any(|p| p.contains("gone.txt")),
            "{:?}",
            report.problems
        );

        // a file whose bytes changed under the manifest's eye
        std::fs::write(
            dir.join("cm400d.exe"),
            b"swapped by whoever can write this folder",
        )
        .unwrap();
        let report = verify_dir(&dir).unwrap();
        assert!(
            report
                .problems
                .iter()
                .any(|p| p.contains("cm400d.exe") && p.contains("SHA-256")),
            "{:?}",
            report.problems
        );

        // and a manifest that simply omits the daemon the service runs: no hash disagrees, yet the
        // install is unattested. This is the hole `REQUIRED_FILES` exists to close.
        std::fs::write(
            dir.join("SHA256SUMS.txt"),
            format!(
                "{}  cm400.inf\n",
                sha256_of_file(&dir.join("cm400.inf")).unwrap()
            ),
        )
        .unwrap();
        let report = verify_dir(&dir).unwrap();
        assert!(
            report
                .problems
                .iter()
                .any(|p| p.contains("cm400d.exe") && p.contains("not covered")),
            "{:?}",
            report.problems
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn a_missing_manifest_is_an_error_not_a_clean_pass() {
        let dir =
            std::env::temp_dir().join(format!("cm400-manifest-absent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let err = verify_dir(&dir).expect_err("no SHA256SUMS.txt cannot verify a package");
        assert!(err.contains("manifest"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }
}
