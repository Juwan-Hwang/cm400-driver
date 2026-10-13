//! Experiment B harness: drives the PRODUCTION trust component (`cm400_windows::trust`) end to end,
//! on a machine where the release identity is deliberately not yet trusted.
//!
//! Why a separate binary instead of a switch on `cm400-setup`: the release whitelist is what keeps
//! experiment tools out of a user's machine, so a new CLI flag on the shipped installer would widen
//! the attack surface of the thing that already runs as a service installer. This binary is rejected
//! by `install/release_package.ps1` and calls the same library functions the installer will use - the
//! point of the run is to measure real writes, real store re-reads and real rollback, not to print a
//! plan.
//!
//! Order is fixed by the design and enforced here: artifact manifest -> certificate identity ->
//! package verification while untrusted -> trust write -> store re-read -> package verification again
//! -> cleanup. Nothing is written before the first three have passed.

use std::path::{Path, PathBuf};
use std::process::Command;

use cm400_windows::cert_cleanup;
use cm400_windows::{native_trust, trust};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = args.first().map(|s| s.as_str()).unwrap_or("");
    let fingerprint = opt(&args, "--fingerprint").unwrap_or_default();
    let cer = opt(&args, "--cer").map(PathBuf::from);
    let package = opt(&args, "--package").map(PathBuf::from);
    let induce = args.iter().any(|a| a == "--induce-second-write-failure");

    if fingerprint.len() != 40 || !fingerprint.chars().all(|c| c.is_ascii_hexdigit()) {
        println!("usage: cm400-trust-test <status|establish|cleanup|ownership> --fingerprint <40-hex> [--cer f.cer --package f.inf] [--induce-second-write-failure] [--write (ownership)]");
        std::process::exit(2);
    }
    let fingerprint = fingerprint.to_uppercase();

    println!("=== cm400-trust-test mode={mode} fingerprint={fingerprint} ===");
    println!(
        "  elevation: {}",
        if is_elevated() {
            "elevated"
        } else {
            "NOT elevated"
        }
    );

    match mode {
        "status" => {
            print_stores(&fingerprint);
            return;
        }
        "cleanup" => {
            let outcome = cert_cleanup::cleanup(&fingerprint);
            println!("  {}", outcome.describe());
            print_stores(&fingerprint);
            if outcome.failed() {
                std::process::exit(1);
            }
            return;
        }
        "ownership" => {
            // The ownership record decides whether an administrator's uninstall deletes a
            // certificate, so its ACL is part of the security boundary and has to be measured, not
            // asserted in a comment.
            let write = args.iter().any(|a| a == "--write");
            if write && !is_elevated() {
                println!("  REFUSING: writing the ownership record needs elevation; nothing was changed.");
                std::process::exit(3);
            }
            if let Err(e) = run_ownership(write) {
                println!("  FAIL: {e}");
                std::process::exit(38);
            }
            return;
        }
        "decoy-message" => {
            // TEST FIXTURE ONLY, and it is not a production concern: this re-encodes a signed catalog
            // with an extra certificate in its collection, to prove the identity check reads the
            // verified signer rather than searching the message for something that matches the pin.
            // The released CLI has no equivalent switch, and the release whitelist rejects this
            // binary outright.
            let (Some(src), Some(bait), Some(out), Some(inf)) = (
                opt(&args, "--cat").map(PathBuf::from),
                opt(&args, "--cer").map(PathBuf::from),
                opt(&args, "--out").map(PathBuf::from),
                opt(&args, "--inf").map(PathBuf::from),
            ) else {
                println!("usage: cm400-trust-test decoy-message --cat in.cat --cer bait.cer --out out.cat --inf in.inf --fingerprint <40-hex>");
                std::process::exit(2);
            };
            match make_in_message_decoy(&src, &bait, &out, &inf) {
                Ok(()) => return,
                Err(e) => {
                    println!("  FIXTURE FAILED: {e}");
                    std::process::exit(12);
                }
            }
        }
        "establish" => {}
        other => {
            println!("unknown mode {other:?}");
            std::process::exit(2);
        }
    }

    // Writing to LocalMachine trust stores cannot work unelevated. Checked here rather than letting
    // the child script report it, because an unelevated run used to be able to claim success.
    if !is_elevated() {
        println!("  REFUSING: not elevated, nothing was changed.");
        std::process::exit(3);
    }
    let Some(cer) = cer else {
        println!("  REFUSING: --cer is required, trust needs an exact file to verify first");
        std::process::exit(2);
    };
    let Some(package) = package else {
        println!("  REFUSING: --package <inf> is required so the trust claim is tested against a real package");
        std::process::exit(2);
    };
    // The catalog is the one sitting next to the INF, and the verdicts come back as typed results.
    // Asking `cm400-setup verify-package` and parsing its stdout would tie this harness's answer to
    // the wording of a display function - the same class of mistake the packaging gate already made.
    let cat = package.with_extension("cat");
    if !cat.exists() {
        println!("  REFUSING: no catalog next to {}", package.display());
        std::process::exit(2);
    }

    println!("--- [1] precondition: the identity must not already be trusted ---");
    print_stores(&fingerprint);
    if store_has("Root", &fingerprint) || store_has("TrustedPublisher", &fingerprint) {
        println!("  REFUSING: the fingerprint is already present, so the before/after observation would prove nothing.");
        println!("  Run `cm400-trust-test cleanup --fingerprint {fingerprint}` first, or use a machine without it.");
        std::process::exit(4);
    }

    println!("--- [2] artifact manifest: hash every file in the release folder before trusting anything ---");
    let manifest = cer.parent().map(|d| d.join("SHA256SUMS.txt"));
    match manifest.as_ref().filter(|p| p.exists()) {
        Some(path) => match check_manifest(path) {
            Ok((checked, bad)) => {
                println!("  entries checked={checked} mismatches={bad}");
                if bad > 0 {
                    println!("  REFUSING: a mismatched package must never be trusted.");
                    std::process::exit(5);
                }
            }
            Err(e) => {
                println!("  REFUSING: manifest could not be verified ({e})");
                std::process::exit(5);
            }
        },
        None => {
            println!("  REFUSING: no SHA256SUMS.txt next to the certificate. Trusting an unverified package is what the model forbids.");
            std::process::exit(5);
        }
    }

    println!("--- [3] certificate identity, checked from the file itself ---");
    match trust::read_certificate_file(&cer) {
        Ok(o) => {
            println!(
                "  file {} -> sha256={} thumbprint={} subject={} issuer={}",
                cer.display(),
                o.sha256_der,
                o.thumbprint,
                o.subject,
                o.issuer
            );
            let pinned = trust::is_pinned_identity(&o);
            println!(
                "  pinned identity (DER hash + store handle + subject + self-signed): {pinned}"
            );
            if !pinned {
                println!("  REFUSING: this file is not the pinned release identity, whatever directory it came in.");
                std::process::exit(6);
            }
            match native_trust::catalog_signer(&cat.to_string_lossy()) {
                Ok(s) => println!(
                    "  catalog's verified signer: sha256={} subject={} (matched pinned: {})",
                    s.sha256_der,
                    s.subject,
                    trust::is_pinned_identity(&s)
                ),
                Err(e) => println!("  catalog signer: FAILED - {e}"),
            }
        }
        Err(e) => {
            println!("  REFUSING: {e}");
            std::process::exit(6);
        }
    }

    println!("--- [4] verification while UNTRUSTED (typed library verdicts) ---");
    let before = verify(&package, &cat, &cer);
    println!("  {}", before.summary());
    if before.trust {
        println!("  NOTE: the package already verifies as trusted while the fingerprint is not in either store.");
        println!("  That contradicts the precondition, so the observation would be meaningless; stopping.");
        std::process::exit(7);
    }

    println!("--- [5] trust write through the production component ---");
    let result = if induce {
        println!(
            "  (fault injection: the second store write is made to fail after the first succeeded)"
        );
        trust::establish_with_fault_after(&fingerprint, &cer, Some(1))
    } else {
        trust::establish(&fingerprint, &cer)
    };

    let added: Vec<String> = match &result {
        Ok(e) => {
            println!("  {}", e.describe());
            e.written().to_vec()
        }
        Err(errors) => {
            for e in errors {
                println!("  ERROR: {e}");
            }
            println!("--- [6] state after the failure: rollback must have left nothing behind ---");
            print_stores(&fingerprint);
            let still =
                store_has("Root", &fingerprint) || store_has("TrustedPublisher", &fingerprint);
            println!(
                "  RESULT: write failed and {} - this is the answer, not a pass to ignore",
                if still {
                    "LEFT TRUST IN PLACE (rollback incomplete)"
                } else {
                    "nothing was left trusted (rollback confirmed)"
                }
            );
            // A deliberately injected failure that rolls back cleanly is the expected outcome of the
            // partial-success test (exit 0). The same shape in a production run is not a pass.
            std::process::exit(if still {
                9
            } else if induce {
                0
            } else {
                8
            });
        }
    };

    println!("--- [6] store re-read after the write ---");
    print_stores(&fingerprint);
    for store in ["Root", "TrustedPublisher"] {
        println!(
            "  {store} lists the fingerprint: {}",
            store_has(store, &fingerprint)
        );
    }

    println!("--- [7] verification again, through the same typed library verdicts ---");
    let after = verify(&package, &cat, &cer);
    println!("  {}", after.summary());
    let flipped = !before.trust && after.trust && after.membership;
    println!("  judgement changed untrusted->trusted: {flipped}");

    println!("--- [8] cleanup of the success path with the existing precise logic ---");
    let outcome = if added.is_empty() {
        println!("  nothing was written by this run, so nothing is removed");
        None
    } else {
        let o = cert_cleanup::cleanup(&fingerprint);
        println!("  {}", o.describe());
        Some(o)
    };
    print_stores(&fingerprint);

    match outcome {
        Some(o) if o.failed() => std::process::exit(10),
        _ if flipped => {
            println!("=== B RESULT: trust established, observed by the production verifier, and removed again ===");
        }
        _ => {
            println!("=== B RESULT: the trust write landed but the verifier did NOT change its judgement. Treat as unexplained, not as success. ===");
            std::process::exit(11);
        }
    }
}

struct Verify {
    trust: bool,
    membership: bool,
    identity: bool,
    signer: String,
}

impl Verify {
    fn summary(&self) -> String {
        format!(
            "signature+trust={} membership={} identity-gate={} (signer {})",
            self.trust,
            self.membership,
            self.identity,
            if self.signer.is_empty() {
                "unresolved"
            } else {
                &self.signer
            }
        )
    }
}

/// All four judgements come back as typed library results, from the same functions the installer
/// will call. Nothing here parses another program's stdout: a decision that depends on the wording of
/// a display function is one `println!` away from being wrong.
fn verify(inf: &Path, cat: &Path, cer: &Path) -> Verify {
    let verdict = native_trust::verify_package(&inf.to_string_lossy(), &cat.to_string_lossy());
    let gate = trust::package_identity_gate(inf, cat, cer);
    let signer = match native_trust::catalog_signer(&cat.to_string_lossy()) {
        Ok(s) => s.sha256_der,
        Err(_) => String::new(),
    };
    Verify {
        trust: verdict.signature.is_ok(),
        membership: verdict.membership.is_ok(),
        identity: gate.is_ok(),
        signer,
    }
}

fn store_has(store: &str, fingerprint: &str) -> bool {
    trust::observe_release_certificates(fingerprint)
        .iter()
        .any(|o| o.store.eq_ignore_ascii_case(store) && o.thumbprint == fingerprint)
}

fn print_stores(fingerprint: &str) {
    for store in ["Root", "TrustedPublisher"] {
        let listed: Vec<String> = trust::observe_release_certificates(fingerprint)
            .into_iter()
            .filter(|o| o.store.eq_ignore_ascii_case(store))
            .map(|o| format!("{} ({})", o.thumbprint, o.subject))
            .collect();
        println!(
            "  {store}: {}",
            if listed.is_empty() {
                "(no CM400 identity)".to_string()
            } else {
                listed.join(", ")
            }
        );
    }
}

/// `certutil -hashfile <path> SHA256` is on every Windows install, so the manifest check adds no
/// crate and no assumption about what else is on the machine.
fn check_manifest(path: &Path) -> Result<(usize, usize), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut checked = 0usize;
    let mut bad = 0usize;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(hash), Some(name)) = (parts.next(), parts.next()) else {
            return Err(format!("malformed manifest line {line:?}"));
        };
        let file = dir.join(name);
        if !file.exists() {
            println!("    absent  {name}");
            bad += 1;
            continue;
        }
        match certutil_sha256(&file) {
            Some(actual) if actual.eq_ignore_ascii_case(hash) => checked += 1,
            Some(actual) => {
                println!("    MISMATCH {name}\n      manifest={hash}\n      actual  ={actual}");
                bad += 1;
            }
            None => {
                println!("    UNHASHABLE {name}");
                bad += 1;
            }
        }
    }
    Ok((checked, bad))
}

fn certutil_sha256(path: &Path) -> Option<String> {
    let out = Command::new("certutil.exe")
        .arg("-hashfile")
        .arg(path)
        .arg("SHA256")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    // The hash is the only line made purely of hex; the header and trailer are localized text.
    String::from_utf8_lossy(&out.stdout).lines().find_map(|l| {
        let t = l.trim().replace(' ', "");
        if !t.is_empty() && t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(t.to_uppercase())
        } else {
            None
        }
    })
}

fn is_elevated() -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // Asking the token directly, instead of a heuristic like `net session`: the answer decides
    // whether anything gets written, and a wrong "yes" is exactly the failure this harness existed
    // to avoid.
    unsafe {
        let mut token = windows::Win32::Foundation::HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut core::ffi::c_void),
            core::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
        .is_ok();
        let _ = CloseHandle(token);
        // `TokenIsElevated`, not a BOOL wrapper - measured against the crate's own declaration.
        ok && elevation.TokenIsElevated != 0
    }
}

/// Add the pinned release certificate to an already-signed catalog's PKCS#7 certificate collection
/// and re-encode it, then **measure** the result before calling anything a success.
///
/// `CryptMsgControl(CMSG_CTRL_ADD_CERT)` on the handle `CryptQueryObject` hands back, then
/// `CryptMsgGetParam(CMSG_ENCODED_MESSAGE)` - no new signature, no re-enrollment, no hand-rolled FFI:
/// `windows` 0.58 exports everything needed. Adding a certificate must not disturb the existing
/// signature, because the signed value covers the content, not the bystander certificate - but that is
/// a claim this function verifies rather than assumes: the identity gate, the signer, and the
/// collection are all read back from the produced file, and an API that returns success while the
/// artifact did not change is reported as a failure.
#[cfg(windows)]
fn make_in_message_decoy(src: &Path, bait: &Path, out: &Path, inf: &Path) -> Result<(), String> {
    use std::ffi::c_void;
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CryptMsgClose, CryptMsgControl, CryptMsgGetParam, CryptQueryObject,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED, CERT_QUERY_FORMAT_FLAG_BINARY,
        CERT_QUERY_OBJECT_BLOB, CMSG_CTRL_ADD_CERT, CMSG_ENCODED_MESSAGE, CRYPT_INTEGER_BLOB,
        HCERTSTORE,
    };

    let bytes = std::fs::read(src).map_err(|e| format!("cannot read {}: {e}", src.display()))?;
    let bait_bytes =
        std::fs::read(bait).map_err(|e| format!("cannot read {}: {e}", bait.display()))?;
    #[repr(C)]
    struct Blob {
        cb_data: u32,
        pb_data: *mut u8,
    }
    let mut blob = Blob {
        cb_data: bytes.len() as u32,
        pb_data: bytes.as_ptr() as *mut u8,
    };

    let produced: Result<(), String> = unsafe {
        let mut store = HCERTSTORE::default();
        let mut hmsg: *mut c_void = core::ptr::null_mut();
        CryptQueryObject(
            CERT_QUERY_OBJECT_BLOB,
            &mut blob as *mut Blob as *const c_void,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            None,
            None,
            None,
            Some(&mut store),
            Some(&mut hmsg),
            None,
        )
        .map_err(|e| {
            format!(
                "CryptQueryObject would not open {} as a signed catalog ({e})",
                src.display()
            )
        })?;

        let outcome = (|| -> Result<(), String> {
            let bait_blob = CRYPT_INTEGER_BLOB {
                cbData: bait_bytes.len() as u32,
                pbData: bait_bytes.as_ptr() as *mut u8,
            };
            CryptMsgControl(
                hmsg as *const c_void,
                0,
                CMSG_CTRL_ADD_CERT,
                Some(&bait_blob as *const CRYPT_INTEGER_BLOB as *const c_void),
            )
            .map_err(|e| format!("CryptMsgControl(CMSG_CTRL_ADD_CERT) refused: {e}"))?;

            let mut len = 0u32;
            CryptMsgGetParam(
                hmsg as *const c_void,
                CMSG_ENCODED_MESSAGE,
                0,
                None,
                &mut len,
            )
            .map_err(|e| format!("sizing CMSG_ENCODED_MESSAGE failed: {e}"))?;
            let mut buf = vec![0u8; len as usize];
            CryptMsgGetParam(
                hmsg as *const c_void,
                CMSG_ENCODED_MESSAGE,
                0,
                Some(buf.as_mut_ptr() as *mut c_void),
                &mut len,
            )
            .map_err(|e| format!("reading CMSG_ENCODED_MESSAGE failed: {e}"))?;
            buf.truncate(len as usize);
            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
            }
            std::fs::write(out, &buf)
                .map_err(|e| format!("cannot write {}: {e}", out.display()))?;
            println!(
                "  wrote {} bytes={} (source was {})",
                out.display(),
                buf.len(),
                bytes.len()
            );
            Ok(())
        })();
        let _ = CryptMsgClose(Some(hmsg));
        let _ = CertCloseStore(store, 0);
        outcome
    };
    produced?;

    // From here on the artifact is judged as an outside observer would, by the same production
    // functions the installer uses. A fixture that "succeeded" at the API level but does not carry
    // both certificates is a failure, not a pass.
    let certs = native_trust::catalog_certificates(&out.to_string_lossy())
        .map_err(|e| format!("output does not parse as a signed catalog: {e}"))?;
    let signer = native_trust::catalog_signer(&out.to_string_lossy())
        .map_err(|e| format!("output has no verifiable signer: {e}"))?;
    let has_bait = certs
        .iter()
        .any(|c| c.sha256_der == trust::PINNED_SHA256_DER);
    let signer_in_collection = certs.iter().any(|c| c.sha256_der == signer.sha256_der);
    println!("  measured on the output:");
    println!(
        "    collection            : {} certificate(s) {}",
        certs.len(),
        certs
            .iter()
            .map(|c| c.thumbprint.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "    verified signer       : thumbprint={} sha256={} subject={}",
        signer.thumbprint, signer.sha256_der, signer.subject
    );
    println!("    pinned bait present   : {has_bait}   signer present in collection: {signer_in_collection}");
    match trust::package_identity_gate(inf, out, bait) {
        Ok(report) => println!("    identity gate         : UNEXPECTEDLY OK (signer {}) - the fixture does not test what it is for", report.signer.sha256_der),
        Err(errors) => println!("    identity gate         : refused -> {}", errors.join(" | ")),
    }

    let mut problems = Vec::new();
    if !has_bait {
        problems.push("the pinned certificate is not inside the message, so the in-message decoy case was not produced");
    }
    if !signer_in_collection {
        problems.push("the verified signer is not listed in the message's own collection (unexpected, and the test would be ambiguous)");
    }
    if signer.sha256_der == trust::PINNED_SHA256_DER {
        problems.push("the output is signed by the pinned identity; adding the certificate must not change who signed it");
    }
    if trust::package_identity_gate(inf, out, bait).is_ok() {
        problems
            .push("the identity gate accepted a package whose signer is not the pinned identity");
    }
    if problems.is_empty() {
        println!("  fixture OK: two distinct certificates inside one signed message, signer is the non-pinned one, gate refuses");
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

fn opt(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}

/// Write (optionally) and verify the ownership record. Every judgement is read back from the machine:
/// the DACL comes from `icacls` and is judged by the library function the installer will use, and the
/// record is re-read from disk and compared with what was intended.
fn run_ownership(write: bool) -> Result<(), String> {
    use cm400_windows::trust_ownership::{self, Provenance};

    let target = trust_ownership::path();
    if write {
        let now = format!(
            "{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        );
        let mut record = trust_ownership::Record::new(trust::PINNED_SHA256_DER, &now);
        for store in ["Root", "TrustedPublisher"] {
            record
                .stores
                .insert(store.to_string(), Provenance::AddedByInstall);
        }
        let read_back = trust_ownership::write_verified(&record, &now)?;
        // exact equality, timestamp included: the first draft compared a record whose `written_at`
        // was still empty and printed "identical: false" as if the write had been wrong
        println!(
            "  record published and read back byte-identically: {}",
            read_back == record
        );
        if read_back != record {
            return Err(format!(
                "record differs from what was decided: {read_back:?} vs {record:?}"
            ));
        }
    }

    if !target.exists() {
        return Err(format!("{} does not exist", target.display()));
    }
    let text = trust_ownership::dacl_report(&target)?;
    // icacls ends with a localized "processed N file(s)" summary. It is not matched by text (that is
    // how a codepage-dependent bug stays hidden), so the print keeps only ACE lines and the header.
    let name = target.to_string_lossy().to_string();
    for line in text
        .lines()
        .filter(|l| l.contains(":(") || l.contains(&name))
    {
        println!("  DACL | {}", line.trim_end());
    }
    let mut bad = Vec::new();
    for (name, actual, want) in trust_ownership::acl_judgements(&text) {
        println!("  {name}: {actual} (want {want})");
        if actual != want {
            bad.push(format!("{name}: got {actual}, want {want}"));
        }
    }
    match trust_ownership::read_verified() {
        Ok(Some(r)) => println!(
            "  record parses and is bound to the pinned identity: {}",
            r.sha256_der == trust::PINNED_SHA256_DER
        ),
        Ok(None) => println!("  record absent - the legacy case, which is a documented state"),
        Err(e) => bad.push(format!("record unreadable: {e}")),
    }
    if bad.is_empty() {
        Ok(())
    } else {
        Err(bad.join("; "))
    }
}
