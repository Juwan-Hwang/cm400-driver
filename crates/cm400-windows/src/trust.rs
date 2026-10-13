//! Establishing local trust for the fixed publishing identity - the production component.
//!
//! Why this is a library module and not installer-inline code: the release model is "the user verifies
//! the whole package, then the installer establishes self-signed trust". That step has to be testable
//! on its own, before it is wired into `install`, and it must be the *same* code in both places. A
//! dry-run that only printed what it would have done would prove nothing about rollback, so this
//! module writes for real and reports only what it could read back.
//!
//! The three rules this module lives by:
//!
//! 1. **A file next to the package is not a reason to trust it.** The certificate is read, its
//!    thumbprint/subject/self-signed status are checked against the pinned release fingerprint, and
//!    anything else is refused. Trusting whatever `.cer` was shipped is the exact "unconditional
//!    trust" the design forbids.
//! 2. **A write counts only when the store agrees.** After each add the store is re-enumerated. The
//!    measured failure mode this avoids: a non-elevated run whose store open threw, that printed
//!    success anyway, and whose later "state restored" check was therefore vacuously true.
//! 3. **Rollback removes only what this call added.** If `Root` already trusted the certificate and
//!    `TrustedPublisher` was added here, a failure must undo the second and leave the first alone.
//!
//! Mechanically, the store write goes through the same delegated path as certificate removal
//! (`cert_cleanup`): measured on this machine, `CertOpenSystemStoreW` has no write access to these
//! stores even elevated, while the .NET `X509Store` route works. Only the mechanism is delegated;
//! every decision - which certificate, which store, whether it took effect, whether to roll back -
//! stays in Rust, and the child script is ASCII-only with `$ErrorActionPreference='Stop'` so a
//! failure cannot arrive as undecodable text or fall through to exit 0.

use std::path::Path;

use crate::cert_cleanup::{
    classify_identity, find_all_thumbprints, read_context, IdentityMatch, Observed,
    EXPECTED_SUBJECT, STORES,
};

/// The SHA-256 of the publishing certificate's DER encoding. This is the authorization anchor: it is
/// compiled into the binary and never read from the release folder. A package can ship a `.cer`, a
/// catalog signed by it and a fingerprint file that all agree with each other - all three arrive
/// together and can all three be replaced, so their mutual agreement proves only consistency, not
/// identity.
pub const PINNED_SHA256_DER: &str =
    "E0F6085D48AD522FC0C78901D81E3C4D789B7C28769D5FC0A188809CEAE655F5";

/// The same certificate's SHA-1 thumbprint, which is the handle Windows keys its certificate stores
/// by. Used only to locate an entry; a match here without a `PINNED_SHA256_DER` match is treated as a
/// collision and refused, never downgraded to "legacy".
pub const PINNED_SHA1_THUMBPRINT: &str = "954E6103349748270B90C8A8A68652A44946ABF1";

/// True only for the pinned publishing identity. Trust is granted exclusively on this.
pub fn is_pinned_identity(cert: &Observed) -> bool {
    cert.sha256_der == PINNED_SHA256_DER
        && cert.thumbprint == PINNED_SHA1_THUMBPRINT
        && cert.subject.eq_ignore_ascii_case(EXPECTED_SUBJECT)
        && cert.self_signed()
}

/// What one establishment attempt did. The variants cannot be confused with each other, and only
/// `Added`/`AlreadyTrusted` claim anything was achieved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Established {
    /// Every target store already listed exactly this fingerprint; nothing was written.
    AlreadyTrusted(Vec<String>),
    /// These `store/fingerprint` entries were written and confirmed present on re-read.
    Added(Vec<String>),
}

impl Established {
    /// The stores this call actually wrote, i.e. the only ones a rollback may undo.
    pub fn written(&self) -> &[String] {
        match self {
            Established::AlreadyTrusted(_) => &[],
            Established::Added(list) => list,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Established::AlreadyTrusted(list) => {
                format!("trust already established in: {}", list.join(", "))
            }
            Established::Added(list) => {
                format!(
                    "trust established and confirmed on re-read in: {}",
                    list.join(", ")
                )
            }
        }
    }
}

/// Read a certificate file into the fields the decision needs. Read-only: `CERT_CONTEXT` never
/// carries a private key, so a `.cer` that somehow had one could not be described by this path -
/// which is why the add script also checks `HasPrivateKey` on the object it is about to store.
#[cfg(target_os = "windows")]
pub fn read_certificate_file(path: &Path) -> Result<Observed, String> {
    use windows::Win32::Security::Cryptography::{
        CertCreateCertificateContext, CertFreeCertificateContext, X509_ASN_ENCODING,
    };

    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if bytes.is_empty() {
        return Err(format!("{} is empty", path.display()));
    }
    let ctx = unsafe { CertCreateCertificateContext(X509_ASN_ENCODING, &bytes) };
    if ctx.is_null() {
        return Err(format!(
            "{} is not a decodable X.509 certificate",
            path.display()
        ));
    }
    let observed = read_context(ctx, "file");
    unsafe {
        let _ = CertFreeCertificateContext(Some(ctx));
    }
    observed.ok_or_else(|| format!("{}: thumbprint or names could not be read", path.display()))
}

/// Command-line characters that would let a path break out of the single-quoted string in the child
/// script. A certificate path is chosen by the installer, not by an attacker, but this is a write to
/// a system trust store: the argument surface gets the same scrutiny as the deletion path.
fn path_is_safe_arg(path: &Path) -> bool {
    let text = path.to_string_lossy();
    !text.is_empty()
        && text.len() < 260
        && text.chars().all(|c| (c as u32) < 128)
        && !text.contains('\'')
        && !text.contains('"')
        && !text.contains('`')
        && !text.contains('$')
}

/// The command that adds one certificate to one store, as argv, or `None` when the request is outside
/// what this module may do (store not in `STORES`, path not a plain ASCII `.cer`/`.crt`).
pub fn add_command(store: &str, cert_path: &Path) -> Option<Vec<String>> {
    if !STORES.iter().any(|s| s.eq_ignore_ascii_case(store)) {
        return None;
    }
    if !path_is_safe_arg(cert_path) {
        return None;
    }
    let ext = cert_path
        .extension()?
        .to_string_lossy()
        .to_ascii_lowercase();
    if ext != "cer" && ext != "crt" {
        return None;
    }
    let path = cert_path.to_string_lossy().to_string();
    let script = format!(
        "$ErrorActionPreference='Stop';\
         try {{\
          $b=[IO.File]::ReadAllBytes('{path}');\
          $c=[System.Security.Cryptography.X509Certificates.X509Certificate2]::new($b);\
          if ($c.HasPrivateKey) {{ exit 3 }};\
          $s=New-Object System.Security.Cryptography.X509Certificates.X509Store('{store}','LocalMachine');\
          $s.Open('ReadWrite');\
          $s.Add($c);\
          $s.Close()\
         }} catch {{ exit 1 }};\
         exit 0"
    );
    Some(vec![
        "powershell.exe".to_string(),
        "-NoProfile".to_string(),
        "-NonInteractive".to_string(),
        "-Command".to_string(),
        script,
    ])
}

/// Run one delegated command and return `Err(reason)` on any failure. The exit code is captured but
/// never treated as the answer - `establish_in` re-reads the store afterwards.
fn run(argv: &[String]) -> Result<(), String> {
    let output = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| format!("could not run the store write ({e})"))?;
    if output.status.success() {
        return Ok(());
    }
    let reason = String::from_utf8_lossy(&output.stderr)
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim()
        .chars()
        .take(200)
        .collect::<String>();
    Err(format!(
        "store write failed ({})",
        if reason.is_empty() {
            format!("exit {}", output.status.code().unwrap_or(-1))
        } else {
            reason
        }
    ))
}

/// Every entry in the two stores whose subject is this project's, plus any entry carrying the pinned
/// fingerprint. For evidence in a report; never used to decide a write, because a subject alone is
/// not an identity and the identity gate is `matches_release_identity`.
#[cfg(target_os = "windows")]
pub fn observe_release_certificates(fingerprint: &str) -> Vec<Observed> {
    use windows::core::PCWSTR;
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CertEnumCertificatesInStore, CertOpenSystemStoreW, CERT_CONTEXT,
        HCRYPTPROV_LEGACY,
    };

    let mut out = Vec::new();
    for store in STORES {
        let wide: Vec<u16> = store.encode_utf16().chain([0]).collect();
        let opened =
            unsafe { CertOpenSystemStoreW(HCRYPTPROV_LEGACY::default(), PCWSTR(wide.as_ptr())) };
        let Ok(h) = opened else {
            continue;
        };
        let mut prev: *const CERT_CONTEXT = core::ptr::null();
        loop {
            let ctx = unsafe { CertEnumCertificatesInStore(h, Some(prev)) };
            if ctx.is_null() {
                break;
            }
            prev = ctx;
            let Some(o) = read_context(ctx, store) else {
                continue;
            };
            if o.subject.eq_ignore_ascii_case(EXPECTED_SUBJECT)
                || o.thumbprint.eq_ignore_ascii_case(fingerprint)
            {
                // The second clause matters: an entry with our fingerprint but somebody else's
                // subject is a collision or a tampered artifact, and must be shown, not dropped.
                out.push(o);
            }
        }
        unsafe {
            let _ = CertCloseStore(h, 0);
        }
    }
    out
}

/// Does this store list the fingerprint? Three answers, deliberately: `cert_cleanup`'s helper treats
/// "cannot read" as "still present" which is the right conservatism for verifying a deletion, but
/// using it to decide whether trust already exists would turn a read failure into a claim of
/// `AlreadyTrusted`.
#[cfg(target_os = "windows")]
fn store_lists(store: &str, fingerprint: &str) -> Result<bool, String> {
    Ok(find_all_thumbprints(store)?
        .iter()
        .any(|t| t.eq_ignore_ascii_case(fingerprint)))
}

/// Establish trust in the two stores this project owns. Production entry point.
#[cfg(target_os = "windows")]
pub fn establish(fingerprint: &str, certificate: &Path) -> Result<Established, Vec<String>> {
    // No fault injection on the production path.
    establish_inner(fingerprint, certificate, None)
}

/// Test-only fault injection point: `fail_after == Some(n)` makes the (n+1)-th attempted write fail
/// after the first n succeeded. This exists so the rollback path can be exercised for a *partial*
/// success on a single machine, where a real mid-write failure cannot be arranged. It is unreachable
/// from `establish`, and therefore from the released CLI, which always passes `None`.
#[cfg(target_os = "windows")]
pub fn establish_with_fault_after(
    fingerprint: &str,
    certificate: &Path,
    fail_after: Option<usize>,
) -> Result<Established, Vec<String>> {
    establish_inner(fingerprint, certificate, fail_after)
}

#[cfg(target_os = "windows")]
fn establish_inner(
    fingerprint: &str,
    certificate: &Path,
    fail_after: Option<usize>,
) -> Result<Established, Vec<String>> {
    // 1. identity gate, before anything is written. Two separate requirements, both strict:
    //    the caller must be asking about the pinned identity (so no code path can hand an arbitrary
    //    fingerprint to this function and get it trusted), and the file must classify as Pinned,
    //    which means its DER hash matches the compiled anchor.
    if fingerprint.trim().to_uppercase() != PINNED_SHA1_THUMBPRINT {
        return Err(vec![format!(
            "refused to trust {fingerprint}: only the pinned publishing identity \
             {PINNED_SHA1_THUMBPRINT} may be added to a trust store"
        )]);
    }
    let observed = match read_certificate_file(certificate) {
        Ok(o) => o,
        Err(e) => return Err(vec![format!("refused to trust: {e}")]),
    };
    if classify_identity(fingerprint, &observed) != IdentityMatch::Pinned
        || !is_pinned_identity(&observed)
    {
        return Err(vec![format!(
            "refused to trust {}: pinned identity check failed (file says sha256={}, thumbprint={}, subject={}, issuer={})",
            certificate.display(),
            observed.sha256_der,
            observed.thumbprint,
            observed.subject,
            observed.issuer
        )]);
    }

    let mut added: Vec<String> = Vec::new();
    let mut present: Vec<String> = Vec::new();
    let mut attempts = 0usize;

    for store in STORES {
        match store_lists(store, fingerprint) {
            Ok(true) => {
                present.push(format!("{store}/{fingerprint}"));
                continue;
            }
            Ok(false) => {}
            // Not being able to read the store is not evidence that it is empty.
            Err(e) => {
                return Err(finish_failure(
                    &added,
                    fingerprint,
                    vec![format!("{store}: cannot read the store to decide ({e})")],
                ))
            }
        }
        attempts += 1;
        if let Some(n) = fail_after {
            if attempts > n {
                // Fault injection: the earlier writes are real, this one is made to fail here, so the
                // rollback below has to undo exactly the stores genuinely written.
                return Err(finish_failure(
                    &added,
                    fingerprint,
                    vec![format!(
                        "{store}: injected failure after the first write (fault injection)"
                    )],
                ));
            }
        }
        let Some(argv) = add_command(store, certificate) else {
            return Err(finish_failure(
                &added,
                fingerprint,
                vec![format!(
                    "{store}: refused to build a trust command for this certificate path"
                )],
            ));
        };
        if let Err(e) = run(&argv) {
            return Err(finish_failure(
                &added,
                fingerprint,
                vec![format!("{store}: {e}")],
            ));
        }
        // 2. the write is only real if the store lists it.
        match store_lists(store, fingerprint) {
            Ok(true) => {
                added.push(format!("{store}/{fingerprint}"));
            }
            Ok(false) => {
                return Err(finish_failure(
                    &added,
                    fingerprint,
                    vec![format!(
                        "{store}: write reported no error but the certificate is not in the store"
                    )],
                ))
            }
            Err(e) => {
                return Err(finish_failure(
                    &added,
                    fingerprint,
                    vec![format!("{store}: wrote but cannot confirm ({e})")],
                ))
            }
        }
    }

    if added.is_empty() {
        if present.is_empty() {
            return Err(vec![format!(
                "{fingerprint}: nothing was written and nothing was already trusted"
            )]);
        }
        return Ok(Established::AlreadyTrusted(present));
    }
    Ok(Established::Added(added))
}

/// Roll back exactly what this call added, then report. Rollback failure is appended to the errors,
/// because "the trust write failed" and "the trust write failed AND could not be undone" are not the
/// same situation for whoever reads the log.
#[cfg(target_os = "windows")]
fn finish_failure(added: &[String], fingerprint: &str, mut errors: Vec<String>) -> Vec<String> {
    match rollback(added, fingerprint) {
        Ok(leftover) => {
            if !leftover.is_empty() {
                errors.push(format!(
                    "rollback incomplete, still trusted in: {}",
                    leftover.join(", ")
                ));
            } else if !added.is_empty() {
                errors.push(format!(
                    "rollback confirmed by re-read: {}",
                    added.join(", ")
                ));
            }
        }
        Err(e) => errors.push(format!("rollback failed: {e}")),
    }
    errors
}

/// Remove the entries this call wrote, and only those. Returns the stores where the certificate is
/// still listed after the attempt.
#[cfg(target_os = "windows")]
pub fn rollback(added: &[String], fingerprint: &str) -> Result<Vec<String>, String> {
    let mut leftover = Vec::new();
    for entry in added {
        let Some((store, _)) = entry.split_once('/') else {
            return Err(format!("malformed rollback target {entry}"));
        };
        match crate::cert_cleanup::remove_from(store, fingerprint) {
            Ok(_) => {}
            Err(e) => return Err(e),
        }
        if store_lists(store, fingerprint).unwrap_or(true) {
            leftover.push(entry.to_string());
        }
    }
    Ok(leftover)
}

/// Non-Windows stub so the crate still compiles: the trust stores are a Windows concept.
#[cfg(not(target_os = "windows"))]
pub fn establish(_fingerprint: &str, _certificate: &Path) -> Result<Established, Vec<String>> {
    Err(vec!["certificate trust stores are Windows-only".to_string()])
}

/// Everything the installer has to believe about a package's identity before it touches a device.
#[derive(Debug, Clone)]
pub struct IdentityReport {
    /// The certificate that actually produced the catalog signature, verified by crypt32.
    pub signer: Observed,
    /// The certificate shipped inside the package.
    pub certificate: Observed,
    pub membership: Result<(), String>,
    /// Recorded, never required here: this is the local-trust verdict, and the whole point of the
    /// flow is that trust may not exist yet when identity is being judged.
    pub signature: Result<(), String>,
}

/// The identity gate: both the shipped `.cer` and the catalog's real signer must be the pinned
/// identity, and the INF must actually be a member of that catalog.
///
/// Agreement between package files is not accepted as evidence. `.cer`, `.cat` and the fingerprint
/// file all arrive in the same folder and can all be replaced together, so only the constant
/// compiled into this binary decides.
#[cfg(target_os = "windows")]
pub fn package_identity_gate(
    inf: &Path,
    cat: &Path,
    cer: &Path,
) -> Result<IdentityReport, Vec<String>> {
    let (inf, cat, cer) = (
        inf.to_string_lossy().to_string(),
        cat.to_string_lossy().to_string(),
        cer.to_string_lossy().to_string(),
    );
    let mut errors: Vec<String> = Vec::new();

    let certificate = match read_certificate_file(Path::new(&cer)) {
        Ok(o) => o,
        Err(e) => {
            errors.push(e);
            return Err(errors);
        }
    };
    if !is_pinned_identity(&certificate) {
        errors.push(format!(
            "shipped certificate is not the pinned identity: sha256={} thumbprint={} subject={}",
            certificate.sha256_der, certificate.thumbprint, certificate.subject
        ));
    }

    let signer = match crate::native_trust::catalog_signer(&cat) {
        Ok(o) => Some(o),
        Err(e) => {
            // No signer is not a pass with one check missing: if crypt32 cannot verify who signed
            // the catalog, nothing about the package can be accepted.
            errors.push(e);
            None
        }
    };
    if let Some(s) = &signer {
        if !is_pinned_identity(s) {
            errors.push(format!(
                "the catalog's verified signer is not the pinned identity: sha256={} thumbprint={} subject={} - the signature is attributed to that certificate by crypt32, so no other content of the message can stand in for it",
                s.sha256_der, s.thumbprint, s.subject
            ));
        }
    }

    let membership = crate::native_trust::inf_catalog_membership(&inf, &cat);
    if let Err(e) = &membership {
        errors.push(format!("membership: {e}"));
    }
    let signature = crate::native_trust::catalog_signature(&cat);

    match signer {
        Some(signer) if errors.is_empty() => Ok(IdentityReport {
            signer,
            certificate,
            membership,
            signature,
        }),
        _ => {
            if errors.is_empty() {
                errors.push("identity gate could not be evaluated".to_string());
            }
            Err(errors)
        }
    }
}

/// Where inside the install transaction a failure happened. The rollback question has different
/// answers per stage, so the stage is data rather than a comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// fingerprint / signer / membership checks
    Identity,
    /// the ownership record could not be persisted before any trust was written
    TrustPersist,
    /// a trust write failed, or the store did not list it afterwards
    TrustWrite,
    /// trust was written but the record could not be updated to say so
    OwnershipUpdate,
    /// the package still does not verify after trust exists
    PackageVerify,
    /// driver staging or binding failed
    DriverStage,
    /// our own interface never appeared
    InterfaceCheck,
    /// the service could not be created
    ServiceRegister,
    /// driver installed, interface bound, service registered - but not running
    ServiceRunning,
    /// everything worked except the data-directory ACL verdict
    DataAcl,
}

impl Stage {
    /// Approved retention policy: trust may be left in place only when the install got past the
    /// point where retrying is the useful action - the driver is staged, our interface exists, and
    /// the service is registered but failed to reach `Running`. Before that, an incomplete install
    /// must not leave new trust behind.
    pub fn retains_trust(self) -> bool {
        matches!(self, Stage::ServiceRunning | Stage::DataAcl)
    }
}

/// The stores a failure at `stage` must un-trust: only the ones this run wrote, and none at all in
/// the retention case.
pub fn rollback_stores(stage: Stage, written: &[String]) -> Vec<String> {
    if stage.retains_trust() {
        Vec::new()
    } else {
        written.to_vec()
    }
}

/// One store's state before this run touched it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreState {
    pub store: String,
    pub present_before: bool,
}

impl StoreState {
    /// Present but not written by us is somebody else's certificate: it may not be recorded as ours
    /// even though the store lists it.
    pub fn provenance_before(&self) -> crate::trust_ownership::Provenance {
        use crate::trust_ownership::Provenance;
        if self.present_before {
            Provenance::Preexisting
        } else {
            Provenance::Absent
        }
    }
}

/// Read the pinned identity's presence out of both stores. Three-state on purpose: a store that
/// cannot be enumerated is not an empty store.
#[cfg(target_os = "windows")]
pub fn snapshot_states() -> Result<Vec<StoreState>, Vec<String>> {
    let mut out = Vec::new();
    for store in STORES {
        match store_lists(store, PINNED_SHA1_THUMBPRINT) {
            Ok(present) => out.push(StoreState {
                store: store.to_string(),
                present_before: present,
            }),
            Err(e) => return Err(vec![format!("{store}: cannot be enumerated ({e})")]),
        }
    }
    Ok(out)
}

/// Try to heal the ownership record's permissions against the machine's actual store state.
///
/// `Ok(None)` means there was nothing to heal: the record is believable (or genuinely absent, which is
/// the legacy case). `Ok(Some(Repaired))` means the file's DACL was restored to the documented
/// boundary and verified by reading it back. `Ok(Some(Refused))` is the answer whenever the evidence
/// does not say "this product's own hardening did this" - the refusal is the point, because a repair
/// granted without that evidence would convert "cannot be trusted" into "trusted".
///
/// The caller decides what to print and whether to continue; this function has no opinion about the
/// transaction beyond the evidence check.
#[cfg(target_os = "windows")]
pub fn heal_ownership_record() -> Result<Option<crate::trust_ownership::Repair>, Vec<String>> {
    use crate::trust_ownership::{self, Repair};

    if trust_ownership::read_verified().is_ok() {
        return Ok(None);
    }
    let states = snapshot_states()?;
    let observed: Vec<(String, bool)> = states
        .iter()
        .map(|s| (s.store.clone(), s.present_before))
        .collect();
    match trust_ownership::guarded_repair(&observed) {
        Repair::NotNeeded => Ok(None),
        other => Ok(Some(other)),
    }
}

/// The stores this transaction is about to write, i.e. the ones the record currently calls absent.
/// After a failure these are exactly the entries whose truth is unknown, because a partially applied
/// write leaves the store ahead of the record.
#[cfg(target_os = "windows")]
fn attempted_stores(record: &crate::trust_ownership::Record) -> Vec<String> {
    use crate::trust_ownership::Provenance;
    record
        .stores
        .iter()
        .filter(|(_, state)| matches!(state, Provenance::Absent))
        .map(|(store, _)| store.clone())
        .collect()
}

/// Make the ownership record state what the stores actually contain, right now.
///
/// The install transaction calls this on every failure path. Without it, a failure can leave a record
/// that contradicts the machine in either direction: `Absent` while a certificate is really installed
/// (so a later uninstall skips the store and strands trust), or `AddedByInstall` after a successful
/// rollback (so a later uninstall deletes a certificate somebody else reinstalled in the meantime).
/// `uncertain` names the stores whose content this run may have changed without confirming it.
#[cfg(target_os = "windows")]
pub fn sync_record_to_reality(
    now: &str,
    uncertain: &[String],
) -> Result<crate::trust_ownership::Record, Vec<String>> {
    use crate::trust_ownership::{self, Record};

    let states = snapshot_states()?;
    let prior = trust_ownership::read_verified().map_err(|e| {
        vec![format!(
            "ownership record cannot be read or trusted ({e}); automatic cleanup must be refused"
        )]
    })?;
    let observed: Vec<(String, bool)> = states
        .iter()
        .map(|s| (s.store.clone(), s.present_before))
        .collect();
    let mut record = Record::plan(prior.as_ref(), &observed);
    record.mark_uncertain(uncertain);
    trust_ownership::write_verified(&record, now)
        .map_err(|e| vec![format!("ownership record could not be persisted ({e}); the ownership state is unknown and automatic cleanup must be refused")])
}

/// The installer's entry point: persist an ownership record **before** writing trust, then write
/// trust, then update the record. It is called whether or not anything needs adding, because the
/// record - not the store contents - is what a later uninstall relies on: skipping it on a machine
/// that already trusted the certificate would leave no record at all, and an absent record is read as
/// the approved `unknown_legacy` case, which permits deleting a certificate that predates this
/// product. Any failure re-synchronises the record with what the stores really hold.
#[cfg(target_os = "windows")]
pub fn establish_with_ownership(
    certificate: &Path,
    now: &str,
) -> Result<(Established, crate::trust_ownership::Record), Vec<String>> {
    use crate::trust_ownership::{self, Record};

    let states = snapshot_states()?;
    let observed: Vec<(String, bool)> = states
        .iter()
        .map(|s| (s.store.clone(), s.present_before))
        .collect();
    let prior = trust_ownership::read_verified().map_err(|e| {
        vec![format!(
            "ownership record unreadable, so nothing may be trusted ({e})"
        )]
    })?;
    // `plan` keeps an earlier `AddedByInstall` flag, which is what makes a retry reuse the identity
    // instead of reclassifying our own entry as pre-existing.
    let base = Record::plan(prior.as_ref(), &observed);
    let attempted = attempted_stores(&base);
    // Declare the intent before touching a store. A normal error return can be handled by re-syncing,
    // but a process kill or a power loss in the middle leaves only what is on disk - and the record on
    // disk has to say "this transaction was about to write here", so a later run can tell our own
    // residue apart from trust that predates the product.
    let mut base = base;
    base.mark_pending(&attempted);
    let base = trust_ownership::write_verified(&base, now)
        .map_err(|e| vec![format!("ownership record could not be persisted before any trust write ({e}); no trust was added")])?;

    let established = match establish(PINNED_SHA1_THUMBPRINT, certificate) {
        Ok(established) => established,
        Err(mut errors) => {
            // The write may have landed in some stores before failing, so the record must not keep
            // saying those were absent.
            errors.extend(
                sync_record_to_reality(now, &attempted)
                    .err()
                    .unwrap_or_default(),
            );
            return Err(errors);
        }
    };
    let updated = base.clone().with_added(established.written(), now);
    match trust_ownership::write_verified(&updated, now) {
        Ok(record) => Ok((established, record)),
        Err(e) => {
            let written: Vec<String> = established.written().to_vec();
            let leftover = rollback(&written, PINNED_SHA1_THUMBPRINT)
                .unwrap_or_else(|err| vec![format!("rollback could not run ({err})")]);
            let mut errors = vec![format!(
                "ownership record could not be updated after the trust write ({e}); new trust may not be left without a durable owner"
            )];
            if leftover.is_empty() && !written.is_empty() {
                errors.push(format!(
                    "rolled back and confirmed absent: {}",
                    written.join(", ")
                ));
            }
            if !leftover.is_empty() {
                errors.push(format!(
                    "ROLLBACK INCOMPLETE, still trusted: {}",
                    leftover.join(", ")
                ));
            }
            // whatever the rollback achieved, the record has to describe it
            errors.extend(
                sync_record_to_reality(now, &leftover)
                    .err()
                    .unwrap_or_default(),
            );
            Err(errors)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TP: &str = PINNED_SHA1_THUMBPRINT;

    fn cert(store: &str, sha1: &str, sha256: &str, subject: &str, issuer: &str) -> Observed {
        Observed {
            store: store.into(),
            thumbprint: sha1.into(),
            sha256_der: sha256.into(),
            subject: subject.into(),
            issuer: issuer.into(),
        }
    }

    /// The package-level decoy: a catalog genuinely signed by a throwaway certificate that shares our
    /// subject, shipped beside the real pinned `cm400.cer`.
    #[cfg(target_os = "windows")]
    #[test]
    fn a_throwaway_signed_package_beside_the_pinned_certificate_is_still_refused() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../dist/identity-decoy");
        let (inf, cat, cer) = (
            format!("{dir}/cm400.inf"),
            format!("{dir}/cm400.cat"),
            format!("{dir}/cm400.cer"),
        );
        if std::fs::metadata(&cat).is_err() {
            eprintln!("skipped: no throwaway-signed artifact at {cat} (run the local make_identity_decoy tooling)");
            return;
        }
        let signer =
            crate::native_trust::catalog_signer(&cat).expect("the artifact is a signed catalog");
        assert_ne!(
            signer.sha256_der, PINNED_SHA256_DER,
            "the signer must be the throwaway"
        );
        assert_eq!(
            signer.subject, EXPECTED_SUBJECT,
            "same subject on purpose: subject alone proves nothing"
        );
        assert!(signer.self_signed());
        let errors = package_identity_gate(Path::new(&inf), Path::new(&cat), Path::new(&cer))
            .expect_err(
                "a package holding the right certificate in the wrong place is not our release",
            );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("signer is not the pinned identity")),
            "{errors:?}"
        );
        // and measure whether the message itself carries the pinned certificate as bait
        let inside = crate::native_trust::catalog_certificates(&cat).unwrap();
        let bait = inside.iter().any(|c| c.sha256_der == PINNED_SHA256_DER);
        eprintln!(
            "T-A status: in-message decoy present={bait} (message carries {:?}); if false, the in-PKCS7 decoy variant is still NOT covered and this is the package-level version only",
            inside.iter().map(|c| &c.thumbprint).collect::<Vec<_>>()
        );
    }

    /// T-A as specified: the pinned release certificate is **inside the same PKCS#7** as a bystander,
    /// while the verified signer is a different, same-subject certificate. An implementation that
    /// resolved identity by scanning the message's collection would pass here; the one under test
    /// refuses. Produced by the local make_identity_decoy tooling via
    /// `cm400-trust-test decoy-message` (`CryptMsgControl(CMSG_CTRL_ADD_CERT)` plus
    /// `CryptMsgGetParam(CMSG_ENCODED_MESSAGE)`), and only asserted against the artifact that actually
    /// exists - a fixture the tests never see is not coverage.
    #[cfg(target_os = "windows")]
    #[test]
    fn a_pinned_certificate_planted_inside_the_message_does_not_make_the_signer_ours() {
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../dist/identity-decoy/in-message"
        );
        let (inf, cat, cer) = (
            format!("{dir}/cm400.inf"),
            format!("{dir}/cm400.cat"),
            format!("{dir}/cm400.cer"),
        );
        if std::fs::metadata(&cat).is_err() {
            // The fixture is machine-built output under the ignored `dist/` tree, so a clean checkout
            // has to be able to produce it rather than silently lose the test. Build it through the
            // documented generator; only a machine without the SDK toolchain may skip, and it says why.
            match ensure_in_message_fixture() {
                Ok(()) => {}
                Err(reason) if reason == SKIP => return,
                Err(reason) => panic!("the fixture could not be produced on a machine that has the toolchain: {reason}"),
            }
        }
        let certs = crate::native_trust::catalog_certificates(&cat)
            .expect("the fixture is a signed catalog");
        let signer =
            crate::native_trust::catalog_signer(&cat).expect("the fixture has a verifiable signer");
        assert!(
            certs.iter().any(|c| c.sha256_der == PINNED_SHA256_DER),
            "the bait has to be inside the message, or this test proves nothing"
        );
        assert!(
            !signer.sha256_der.eq_ignore_ascii_case(PINNED_SHA256_DER),
            "the verified signer must be the throwaway"
        );
        assert_eq!(
            certs.len(),
            2,
            "exactly the throwaway and the planted release certificate"
        );
        assert!(
            certs.iter().any(|c| c.sha256_der == signer.sha256_der),
            "the signer must itself be one of the certificates in the message"
        );
        let errors = package_identity_gate(Path::new(&inf), Path::new(&cat), Path::new(&cer))
            .expect_err("a message containing our certificate is not a message signed by it");
        assert!(
            errors
                .iter()
                .any(|e| e.contains("signer is not the pinned identity")),
            "{errors:?}"
        );
    }

    /// Sentinel meaning "this environment cannot host the test at all", as opposed to "the test ran
    /// and the product is wrong". The distinction is the reason the skip is explicit.
    #[cfg(windows)]
    const SKIP: &str = "__skipped__";

    /// True when the SDK tools the generator needs are on this machine.
    #[cfg(windows)]
    fn has_catalog_toolchain() -> bool {
        let root = std::path::Path::new(r"C:\Program Files (x86)\Windows Kits\10\bin");
        let Ok(entries) = std::fs::read_dir(root) else {
            return false;
        };
        entries
            .flatten()
            .any(|e| e.path().join("x64").join("makecat.exe").exists())
    }

    /// Produce the fixture by invoking the same script a developer would, so the security test is not
    /// a function of one machine having run it once. A missing toolchain is a skip with a reason;
    /// a generator that ran and produced nothing is left to fail the test, because that is a real
    /// defect rather than an unavailable environment.
    #[cfg(windows)]
    fn ensure_in_message_fixture() -> Result<(), String> {
        if !has_catalog_toolchain() {
            eprintln!("skipped: no Windows SDK makecat/signtool on this machine, so the in-message decoy cannot be built here");
            return Err(SKIP.to_string());
        }
        let script = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../install/make_identity_decoy.ps1"
        );
        let out = std::process::Command::new("pwsh")
            .args(["-NoProfile", "-File", script])
            .output()
            .map_err(|e| format!("cannot run the generator {script}: {e}"))?;
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        if !out.status.success() {
            return Err(format!(
                "generator failed (exit {:?}):\n{}",
                out.status.code(),
                text
            ));
        }
        if text.contains("in-message decoy NOT built") || text.contains("fixture exit=2") {
            return Err(format!(
                "the generator could not build the artifact; it needs `cargo build --workspace --bins --release` first:\n{text}"
            ));
        }
        Ok(())
    }

    /// The anchor is the DER hash, so both constants have to be well-formed on their own: a truncated
    /// or wrong-length value would silently disable every comparison.
    #[test]
    fn pinned_constants_are_well_formed() {
        assert_eq!(PINNED_SHA256_DER.len(), 64, "SHA-256 as 64 hex");
        assert!(PINNED_SHA256_DER.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(PINNED_SHA256_DER, PINNED_SHA256_DER.to_uppercase());
        assert_eq!(PINNED_SHA1_THUMBPRINT.len(), 40, "SHA-1 as 40 hex");
        assert!(PINNED_SHA1_THUMBPRINT
            .chars()
            .all(|c| c.is_ascii_hexdigit()));
        assert_eq!(EXPECTED_SUBJECT, "CN=CM400 Driver");
    }

    /// The release folder records the same identity; if they ever disagree, either the code was
    /// rotated without the artifact or the artifact was replaced. Either way the release is
    /// inconsistent and the test, not a customer machine, has to notice.
    #[test]
    fn pinned_constants_match_the_recorded_release_identity() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../install");
        let thumb = std::fs::read_to_string(format!("{dir}/cm400-release.thumbprint.txt"))
            .expect("the release fingerprint file is part of the repository");
        let sha = std::fs::read_to_string(format!("{dir}/cm400-release.sha256.txt"))
            .expect("the release SHA-256 anchor file is part of the repository");
        let recorded_tp = crate::cert_cleanup::parse_fingerprint(&thumb);
        let recorded_sha = crate::cert_cleanup::parse_fingerprint(&sha);
        assert_eq!(
            recorded_tp.as_deref(),
            Some(PINNED_SHA1_THUMBPRINT),
            "cm400-release.thumbprint.txt disagrees with the pinned SHA-1"
        );
        assert_eq!(
            recorded_sha.as_deref(),
            Some(PINNED_SHA256_DER),
            "cm400-release.sha256.txt disagrees with the pinned DER anchor"
        );
    }

    /// Trust is granted to the pinned identity only, and a matching SHA-1 is not sufficient.
    #[test]
    fn only_the_pinned_der_hash_authorizes_trust() {
        let pinned = cert(
            "file",
            TP,
            PINNED_SHA256_DER,
            EXPECTED_SUBJECT,
            EXPECTED_SUBJECT,
        );
        assert!(is_pinned_identity(&pinned));

        let collision = cert(
            "file",
            TP,
            &"A".repeat(64),
            EXPECTED_SUBJECT,
            EXPECTED_SUBJECT,
        );
        assert!(
            !is_pinned_identity(&collision),
            "same SHA-1 handle, different DER hash: a collision is never the pinned identity"
        );
        // and the cleanup classifier must not quietly treat that as a legacy certificate either
        assert_eq!(
            classify_identity(TP, &collision),
            IdentityMatch::No,
            "a pinned SHA-1 with a wrong DER hash is refused outright, not downgraded to legacy"
        );

        let lookalike = cert(
            "file",
            TP,
            PINNED_SHA256_DER,
            "CN=Some Real CA Root",
            "CN=Some Real CA Root",
        );
        assert!(!is_pinned_identity(&lookalike));

        let issued_by_someone_else = cert(
            "file",
            TP,
            PINNED_SHA256_DER,
            EXPECTED_SUBJECT,
            "CN=Contoso CA",
        );
        assert!(!is_pinned_identity(&issued_by_someone_else));

        // A legacy per-machine certificate stays cleanable (so old installs do not strand a root),
        // but it is never an identity we may trust.
        let legacy_tp = "B".repeat(40);
        let legacy = cert(
            "Root",
            &legacy_tp,
            &"C".repeat(64),
            EXPECTED_SUBJECT,
            EXPECTED_SUBJECT,
        );
        assert_eq!(
            classify_identity(&legacy_tp, &legacy),
            IdentityMatch::LegacyArtifact
        );
        assert!(!is_pinned_identity(&legacy));
        assert_eq!(
            classify_identity(TP, &legacy),
            IdentityMatch::No,
            "a fingerprint that is not ours matches nothing"
        );
    }

    #[test]
    fn the_trust_command_is_as_narrow_as_the_removal_command() {
        let argv = add_command("Root", Path::new("C:\\cm400\\cm400.cer"))
            .expect("our own .cer is trustworthy input");
        let joined = argv.join(" ");
        assert_eq!(argv[0], "powershell.exe");
        assert!(
            joined.contains("X509Store('Root','LocalMachine')"),
            "{joined}"
        );
        assert!(joined.contains("Open('ReadWrite')"));
        assert!(
            joined.contains("$ErrorActionPreference='Stop'"),
            "no silent partial failure"
        );
        assert!(joined.contains("catch { exit 1 }"));
        assert!(
            joined.contains("HasPrivateKey") && joined.contains("exit 3"),
            "a file carrying a private key must never be installed into a trust store"
        );
        assert!(!joined.contains('*'), "no wildcards");
        assert!(
            joined.chars().all(|c| (c as u32) < 128),
            "ASCII only, so a failure message cannot arrive undecodable"
        );

        // Stores outside our own two are out of scope whatever the file is.
        assert!(add_command("My", Path::new("C:\\cm400\\cm400.cer")).is_none());
        assert!(add_command("AuthRoot", Path::new("C:\\cm400\\cm400.cer")).is_none());
        // Extensions that are not certificate encodings, and paths that could break out of the
        // single-quoted literal, are refused.
        assert!(add_command("Root", Path::new("C:\\cm400\\cm400.pfx")).is_none());
        assert!(add_command("Root", Path::new("C:\\cm400\\cm400.txt")).is_none());
        assert!(add_command("Root", Path::new("C:\\x\\a'.cer")).is_none());
        assert!(add_command("Root", Path::new("C:\\x\\a`b.cer")).is_none());
        assert!(add_command("Root", Path::new("C:\\x\\a$b.cer")).is_none());
        assert!(
            add_command("Root", Path::new("C:\\café\\cm400.cer")).is_none(),
            "non-ASCII path refused"
        );
        assert!(add_command("TrustedPublisher", Path::new("C:\\cm400\\cm400.crt")).is_some());
    }

    /// The failure matrix, as data: which stage leaves trust behind and which does not.
    #[test]
    fn only_the_approved_stages_retain_trust() {
        let written = vec!["Root/954E6103349748270B90C8A8A68652A44946ABF1".to_string()];
        for stage in [
            Stage::Identity,
            Stage::TrustPersist,
            Stage::TrustWrite,
            Stage::OwnershipUpdate,
            Stage::PackageVerify,
            Stage::DriverStage,
            Stage::InterfaceCheck,
            Stage::ServiceRegister,
        ] {
            assert_eq!(
                rollback_stores(stage, &written),
                written,
                "{stage:?} must undo what this run wrote"
            );
            assert!(!stage.retains_trust());
        }
        for stage in [Stage::ServiceRunning, Stage::DataAcl] {
            assert!(
                rollback_stores(stage, &written).is_empty(),
                "{stage:?} is the approved retention case"
            );
            assert!(stage.retains_trust());
        }
        // a stage that retains trust is never also asked to roll back a partial write
        assert!(rollback_stores(Stage::ServiceRunning, &[]).is_empty());
    }

    #[test]
    fn a_present_certificate_is_never_recorded_as_ours() {
        let seen = StoreState {
            store: "Root".into(),
            present_before: true,
        };
        let missing = StoreState {
            store: "TrustedPublisher".into(),
            present_before: false,
        };
        assert_eq!(
            seen.provenance_before(),
            crate::trust_ownership::Provenance::Preexisting,
            "the store listing it is not the same statement as us having put it there"
        );
        assert_eq!(
            missing.provenance_before(),
            crate::trust_ownership::Provenance::Absent
        );
    }

    /// Which stores a failure must re-check: exactly the ones the record believed were absent.
    #[test]
    fn attempted_stores_are_the_ones_the_record_calls_absent() {
        use crate::trust_ownership::{Provenance, Record};
        let mut r = Record::new(PINNED_SHA256_DER, "t");
        r.stores.insert("Root".into(), Provenance::Absent);
        r.stores
            .insert("TrustedPublisher".into(), Provenance::Preexisting);
        assert_eq!(attempted_stores(&r), vec!["Root".to_string()]);

        let mut none = Record::new(PINNED_SHA256_DER, "t");
        none.stores
            .insert("Root".into(), Provenance::AddedByInstall);
        none.stores
            .insert("TrustedPublisher".into(), Provenance::Preexisting);
        assert!(
            attempted_stores(&none).is_empty(),
            "a retry that writes nothing marks nothing uncertain"
        );
    }

    #[test]
    fn rollback_targets_are_validated_before_any_removal() {
        // A malformed target must fail the whole call rather than skip an entry and report success.
        assert!(rollback(&["Root".to_string()], TP).is_err());
        assert!(rollback(&["".to_string()], TP).is_err());
        // An empty list is a no-op, and notably never removes anything.
        assert_eq!(rollback(&[], TP).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn established_written_only_names_real_writes() {
        assert!(Established::AlreadyTrusted(vec!["Root/x".into()])
            .written()
            .is_empty());
        let added =
            Established::Added(vec![format!("Root/{TP}"), format!("TrustedPublisher/{TP}")]);
        assert_eq!(added.written().len(), 2);
        assert!(
            added.describe().contains("confirmed on re-read"),
            "success wording carries its own evidence"
        );
        assert!(Established::AlreadyTrusted(vec![format!("Root/{TP}")])
            .describe()
            .contains("already established"));
    }

    /// The gate must be measured against real bytes, not only synthetic identities. On this machine
    /// `install\cm400.cat` was signed by the older per-machine identity and
    /// `dist\fixed-id\cm400.cat` by the pinned one, which is exactly the pair a passing check needs:
    /// a catalog that is valid, self-consistent and even locally trusted, but is not our identity,
    /// must be refused. Cases that cannot run here report that they were skipped instead of passing.
    #[cfg(target_os = "windows")]
    #[test]
    fn identity_gate_against_the_catalogs_on_this_machine() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../install");
        let inf = format!("{dir}/cm400.inf");
        let cer = format!("{dir}/cm400-release.cer");
        let legacy = format!("{dir}/cm400.cat");
        let pinned = format!("{dir}/../dist/fixed-id/cm400.cat");

        if std::fs::metadata(&legacy).is_ok() {
            let errors = package_identity_gate(Path::new(&inf), Path::new(&legacy), Path::new(&cer))
                .expect_err("a catalog signed by the legacy per-machine identity must not clear the pinned gate");
            assert!(
                errors
                    .iter()
                    .any(|e| e.contains("signer is not the pinned identity")),
                "{errors:?}"
            );
            // What this case is, and what it is not. Measured: the message carries one certificate and
            // it is not the pinned one, so there is no decoy inside the signed data here. T-A is
            // defined as "somebody else's signature over the package, with our release certificate
            // present in the same message as bait", and this fixture does not contain that bait, so it
            // does not cover T-A. It does kill the weaker wrong implementations - trusting the shipped
            // `.cer`, trusting a matching subject, trusting a locally-installed certificate - because
            // the legacy certificate shares our subject and is self-signed and trusted on this machine.
            let inside = crate::native_trust::catalog_certificates(&legacy)
                .expect("the legacy catalog must still be parseable as a signed catalog");
            assert!(
                !inside.iter().any(|c| c.sha256_der == PINNED_SHA256_DER),
                "if this ever becomes true, this fixture has turned into T-A and the label must be revised"
            );
            eprintln!(
                "T-A status: NOT COVERED - legacy catalog's message holds {} certificate(s) {:?}, none of them the pinned one, so no decoy-in-message case yet",
                inside.len(),
                inside.iter().map(|c| &c.thumbprint).collect::<Vec<_>>()
            );
        } else {
            eprintln!("skipped: no legacy-signed catalog at {legacy}");
        }

        if std::fs::metadata(&pinned).is_ok() {
            let report =
                package_identity_gate(Path::new(&inf), Path::new(&pinned), Path::new(&cer))
                    .expect("the catalog signed by the pinned identity must clear the gate");
            assert_eq!(report.signer.sha256_der, PINNED_SHA256_DER);
            assert_eq!(report.signer.thumbprint, PINNED_SHA1_THUMBPRINT);
            assert_eq!(report.certificate.sha256_der, PINNED_SHA256_DER);
            assert!(
                report.membership.is_ok(),
                "INF must be a member of that very catalog"
            );
            // positive control on the same measurement path
            let inside = crate::native_trust::catalog_certificates(&pinned)
                .expect("the pinned catalog must parse");
            assert!(inside.iter().any(|c| c.sha256_der == PINNED_SHA256_DER));
        } else {
            eprintln!("skipped: no pinned-identity catalog at {pinned} (run the local sign_fixed_identity tooling)");
        }

        // A file that is not a signed catalog yields no verified signer, and "no signer" is a refusal
        // rather than a check that was skipped.
        assert!(
            crate::native_trust::catalog_signer(&inf).is_err(),
            "the INF is not a signed catalog and must not produce a signer"
        );
    }
}
