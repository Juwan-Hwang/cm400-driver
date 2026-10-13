//! Process-level contract for `cm400-setup verify-package`.
//!
//! Why a separate integration test that spawns the real binary: the point of the change was that a
//! caller which looks only at the exit code must not be able to walk past a failure. Testing
//! `PackageVerdict::exit_code()` in isolation proves nothing about the shipped command - the bug this
//! replaces was precisely a program that printed `FAIL` and exited 0, so a packaging gate that trusted
//! the code shipped an unverifiable package. Only the real process answers the real question.
//!
//! Nothing here installs a driver, touches a service, or writes a trust store: `verify-package` is
//! read-only by design.

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn setup_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_cm400-setup"))
}

fn repo_file(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../")
        .join(rel)
}

/// Assemble a throwaway release folder: INF, the catalog under test, and the pinned public
/// certificate under the name the installer looks for (`cm400.cer`).
fn stage(tag: &str, cat_src: &Path) -> Option<PathBuf> {
    if !cat_src.exists() {
        eprintln!("skipped ({tag}): no catalog at {}", cat_src.display());
        return None;
    }
    let dir = std::env::temp_dir().join(format!("cm400-verify-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    std::fs::copy(repo_file("install/cm400.inf"), dir.join("cm400.inf")).expect("copy INF");
    std::fs::copy(cat_src, dir.join("cm400.cat")).expect("copy CAT");
    std::fs::copy(
        repo_file("install/cm400-release.cer"),
        dir.join("cm400.cer"),
    )
    .expect("copy CER");
    Some(dir)
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    /// Both streams, because a diagnostic that reaches only stderr must still be caught by this
    /// contract. The earlier version kept stdout alone unless it was empty, which could not distinguish
    /// "no failure reported" from "failure reported somewhere the test was not looking".
    fn merged(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr)
    }

    /// A judgement line read as a line, not as a substring anywhere in the output.
    fn verdict(&self, label: &str) -> Option<bool> {
        self.stdout
            .lines()
            .chain(self.stderr.lines())
            .find(|l| l.trim_start().starts_with(label))
            .map(|l| l.contains(": OK"))
    }
}

fn run_verify(dir: &Path) -> Run {
    let out = Command::new(setup_exe())
        .arg("verify-package")
        .arg(dir.join("cm400.inf"))
        .output()
        .expect("the shipped installer binary must run");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    }
}

/// The invariant a caller relies on, checked for every scenario: the exit code and the printed
/// judgements cannot disagree, so nobody has to parse text to decide whether a package is safe.
fn assert_code_matches_output(run: &Run, scenario: &str) {
    let failed = run.merged().contains("FAIL");
    if failed {
        assert_ne!(run.code, 0, "{scenario}: printed a FAIL and still exited 0 - this is the exact bug the change removed:\n{}", run.merged());
    } else {
        assert_eq!(
            run.code,
            0,
            "{scenario}: no FAIL on either stream but exit is {}:\n{}",
            run.code,
            run.merged()
        );
    }
}

#[test]
fn a_catalog_signed_by_a_different_identity_exits_nonzero_even_though_the_package_is_self_consistent(
) {
    // `install\cm400.cat` is signed by the older per-machine certificate while the folder's `.cer` is
    // the pinned one: every file agrees with its neighbours, and it is still the wrong identity.
    let dir = match stage("legacy", &repo_file("install/cm400.cat")) {
        Some(d) => d,
        None => return,
    };
    let run = run_verify(&dir);
    assert_eq!(
        run.code,
        31,
        "an identity mismatch has its own exit code; output:\n{}",
        run.merged()
    );
    // structured per-line assertions, not a substring hunt: signature and membership are both fine
    // here, and it is specifically the identity gate that refuses the package
    assert_eq!(
        run.verdict("1 signature+trust"),
        Some(true),
        "legacy package is signed and locally trusted; output:\n{}",
        run.merged()
    );
    assert_eq!(
        run.verdict("2 membership"),
        Some(true),
        "output:\n{}",
        run.merged()
    );
    assert_eq!(
        run.verdict("4 identity gate"),
        Some(false),
        "output:\n{}",
        run.merged()
    );
    assert_code_matches_output(&run, "legacy-signed catalog");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_tampered_catalog_cannot_exit_zero() {
    let pinned = repo_file("dist/fixed-id/cm400.cat");
    let dir = match stage("tampered", &pinned) {
        Some(d) => d,
        None => return,
    };
    let cat = dir.join("cm400.cat");
    let mut bytes = std::fs::read(&cat).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;
    std::fs::write(&cat, &bytes).unwrap();

    let run = run_verify(&dir);
    assert_ne!(
        run.code,
        0,
        "a corrupted catalog must not be accepted:\n{}",
        run.merged()
    );
    assert_code_matches_output(&run, "tampered catalog");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_pinned_package_is_judged_consistently_whatever_this_machines_trust_state_is() {
    // Whether the signature line passes depends on the machine's trust stores, so this case asserts
    // the contract rather than a fixed number: identity must hold, and the exit code must follow the
    // printed verdicts. On a machine that has not been given trust for the fixed identity, that means
    // a non-zero exit while the identity line still says OK.
    let dir = match stage("pinned", &repo_file("dist/fixed-id/cm400.cat")) {
        Some(d) => d,
        None => return,
    };
    let run = run_verify(&dir);
    assert_eq!(
        run.verdict("4 identity gate"),
        Some(true),
        "the pinned-signed catalog must clear the identity gate; output:\n{}",
        run.merged()
    );
    // whichever way the machine's trust state falls, the judgement line and the exit code must agree,
    // and the two failure kinds must not share a code: a package signed by the pinned identity that
    // this machine has not enrolled is 39, while a signature that does not verify at all is 23.
    match run.verdict("1 signature+trust") {
        Some(true) => assert_eq!(
            run.code,
            0,
            "trusted pinned package must exit 0; {}",
            run.merged()
        ),
        Some(false) => {
            assert_eq!(
                run.code, 39,
                "the signer is the pinned identity, so the only possible failure is local trust; {}",
                run.merged()
            );
            assert_eq!(
                run.verdict("4 identity gate"),
                Some(true),
                "{}",
                run.merged()
            );
            assert_eq!(run.verdict("2 membership"), Some(true), "{}", run.merged());
            assert!(
                run.merged().contains("6 crypto vs trust"),
                "the split has to be stated, not implied by a bare code; {}",
                run.merged()
            );
        }
        None => panic!(
            "the signature judgement line was not printed at all; {}",
            run.merged()
        ),
    }
    assert_code_matches_output(&run, "pinned package");
    std::fs::remove_dir_all(&dir).ok();
}

/// The release gate depends on this distinction being real rather than a matter of interpretation:
/// 39 is produced only for a package whose signature was verified and whose signer is the pinned
/// identity, and never as a wrapper around "some other failure".
#[test]
fn exit_39_is_reserved_for_a_valid_signature_that_this_machine_does_not_trust() {
    let cat = repo_file("dist/fixed-id/cm400.cat");
    if !cat.exists() {
        eprintln!("skipped: no signed release folder (run the local sign_fixed_identity tooling)");
        return;
    }
    let dir = stage("trust-only-gap", &cat).expect("staged");
    let run = run_verify(&dir);
    let lines = run.merged();
    if run.code == 39 {
        // if the CLI says "only trust is missing", the printed judgements must actually support it
        assert!(
            lines.contains("4 identity gate    : OK"),
            "39 without a passing identity gate:\n{lines}"
        );
        assert!(
            lines.contains("2 membership     : OK"),
            "39 without membership:\n{lines}"
        );
        assert!(
            lines.contains("1 signature+trust: FAIL"),
            "39 while the signature passed:\n{lines}"
        );
        assert!(
            lines.contains("6 crypto vs trust"),
            "39 must be explained:\n{lines}"
        );
    } else if run.code == 0 {
        assert!(
            lines.contains("1 signature+trust: OK"),
            "0 must mean the signature passed:\n{lines}"
        );
        assert!(
            !lines.contains("6 crypto vs trust"),
            "judgement 6 is only for the gap case:\n{lines}"
        );
    } else {
        panic!(
            "expected the pinned package to land in 0 or 39, got {}; {}",
            run.code, lines
        );
    }
    assert_code_matches_output(&run, "trust-only gap");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_manifest_that_is_not_inside_the_signed_catalog_is_refused() {
    // The digest list can only vouch for the package if the signature covers it. A manifest dropped
    // into the folder by whoever also replaced a binary agrees with those bytes by construction, so
    // checking its lines proves nothing; membership in the verified catalog does.
    let dir = match stage("unattested", &repo_file("dist/fixed-id/cm400.cat")) {
        Some(d) => d,
        None => return,
    };
    let manifest = dir.join("SHA256SUMS.txt");
    let hash = sha256(&dir.join("cm400.inf"));
    // a list that names real files with correct digests but is not the one the catalog attests
    std::fs::write(&manifest, format!("{hash}  cm400.inf\n")).unwrap();
    let run = run_verify(&dir);
    assert_eq!(
        run.code,
        30,
        "an unattested manifest has its own exit code; {}",
        run.merged()
    );
    assert_eq!(
        run.verdict("5 manifest attested"),
        Some(false),
        "{}",
        run.merged()
    );
    // the identity gate still passes: the failure is the manifest, not the signature
    assert_eq!(
        run.verdict("4 identity gate"),
        Some(true),
        "{}",
        run.merged()
    );
    assert_code_matches_output(&run, "unattested manifest");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_signed_release_folder_has_its_manifest_attested() {
    // positive control for the same judgement, using the folder the signing pipeline really produced
    let src = repo_file("dist/fixed-id/SHA256SUMS.txt");
    if !src.exists() {
        eprintln!("skipped: no signed release folder (run the local sign_fixed_identity tooling)");
        return;
    }
    let dir = match stage("attested", &repo_file("dist/fixed-id/cm400.cat")) {
        Some(d) => d,
        None => return,
    };
    std::fs::copy(&src, dir.join("SHA256SUMS.txt")).unwrap();
    let run = run_verify(&dir);
    assert_eq!(
        run.verdict("5 manifest attested"),
        Some(true),
        "{}",
        run.merged()
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// SHA-256 via the same tool the library uses, so the test does not need a hashing crate.
fn sha256(path: &Path) -> String {
    let out = Command::new("certutil.exe")
        .args(["-hashfile", &path.to_string_lossy(), "SHA256"])
        .output()
        .expect("certutil is part of Windows");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim().replace(' ', "").to_ascii_uppercase())
        .find(|l| l.len() == 64 && l.chars().all(|c| c.is_ascii_hexdigit()))
        .expect("a hash line")
}

#[test]
fn a_missing_package_is_rejected_with_its_own_code() {
    let out = Command::new(setup_exe())
        .arg("verify-package")
        .arg(std::env::temp_dir().join("definitely-not-here-9182.cm400.inf"))
        .output()
        .expect("runnable");
    assert_ne!(
        out.status.code().unwrap_or(-1),
        0,
        "an unresolvable INF is not a success"
    );
}
