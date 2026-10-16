//! Precise removal of the release's own self-signed certificate from the local machine.
//!
//! Why this exists: signing is a build-time step (`install/d3_sign_catalog.ps1`) that mints a
//! per-machine self-signed certificate, signs the package catalog, and enrolls the public copy into
//! `LocalMachine\Root` and `LocalMachine\TrustedPublisher`. An uninstall that leaves it behind keeps
//! a trusted root on a machine that no longer has the product.
//!
//! What is *not* implied: the private key is destroyed right after signing (the script asserts
//! `HasPrivateKey=false`), so a leftover certificate cannot sign anything new. The residue is
//! trust, not signing capability - which is still a reason to remove it, and not a reason to
//! overreach.
//!
//! Removal is deliberately narrow. A certificate is deleted only when all of these hold:
//! - its SHA-1 thumbprint equals the release fingerprint, exactly (case-insensitive hex);
//! - its rendered subject equals the project's own `CN=CM400 Driver`;
//! - it is self-signed (subject and issuer render identically);
//! - it sits in one of the two stores this project touches, and nowhere else.
//!
//! The fingerprint alone is never treated as an instruction. Without the subject and self-signed
//! checks, a tampered fingerprint file could point at any certificate on the machine - including a
//! real CA root, which is exactly the mistake this module must not make.

use std::path::Path;

/// The subject this project's own certificate carries, and the guard that keeps a wrong fingerprint
/// from deleting somebody else's certificate.
pub const EXPECTED_SUBJECT: &str = "CN=CM400 Driver";

/// The only two stores this module reads, and the only two it will ever name in a removal command.
pub const STORES: [&str; 2] = ["Root", "TrustedPublisher"];

/// One certificate as observed in a store, reduced to what the decision needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    pub store: String,
    /// Upper-case hex SHA-1, the form both `certutil` and PowerShell use. Windows keys its stores by
    /// this value, so it is a lookup handle - never an authorization on its own.
    pub thumbprint: String,
    /// Upper-case hex SHA-256 over the certificate's DER encoding (`pbCertEncoded`). This is the
    /// identity anchor used for trust decisions and for deletion.
    pub sha256_der: String,
    pub subject: String,
    pub issuer: String,
}

impl Observed {
    pub fn self_signed(&self) -> bool {
        self.subject.eq_ignore_ascii_case(&self.issuer)
    }
}

/// How well a store entry matches what the release says it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityMatch {
    /// The pinned publishing identity: SHA-1 handle matches, SHA-256 anchor matches, subject matches
    /// and the certificate is self-signed. Only this class may be granted trust.
    Pinned,
    /// A legacy per-machine certificate named by the package artifact. Retained deliberately: the
    /// release currently installed on machines out there was signed before the fixed identity existed,
    /// and refusing to clean those would strand a trusted root on the user's machine. Always reported
    /// as legacy, never treated as an identity we can trust.
    LegacyArtifact,
    /// Not ours. Includes the case where the SHA-1 handle matches but the SHA-256 anchor does not -
    /// that is a collision or a forged artifact, and it must not fall through to the legacy path.
    No,
}

/// The identity strings to try, and the outcome of a cleanup attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Entries confirmed gone, as `store/thumbprint`.
    Removed(Vec<String>),
    /// Nothing matched in the two stores: never installed, or already removed.
    Absent,
    /// Something was refused or could not be confirmed. Never reported as done.
    Failed(Vec<String>),
}

impl Outcome {
    /// One line for the installer output, distinct per outcome.
    pub fn describe(&self) -> String {
        match self {
            Outcome::Removed(list) => format!(
                "certificate cleanup: removed {} ({}) - confirmed absent on re-read",
                list.len(),
                list.join(", ")
            ),
            Outcome::Absent => "certificate cleanup: nothing to remove (no certificate with the release fingerprint and subject in Root/TrustedPublisher)".to_string(),
            Outcome::Failed(list) => format!("certificate cleanup: FAILED - {}", list.join("; ")),
        }
    }

    pub fn failed(&self) -> bool {
        matches!(self, Outcome::Failed(_))
    }
}

/// The decision, isolated so it can be tested without touching a certificate store.
pub fn matches_release_identity(fingerprint: &str, cert: &Observed) -> bool {
    classify_identity(fingerprint, cert) != IdentityMatch::No
}

/// The full classification. `fingerprint` is whatever the caller was asked to clean up; the pinned
/// values come from the code, never from a file that arrived inside the same folder.
pub fn classify_identity(fingerprint: &str, cert: &Observed) -> IdentityMatch {
    let want = fingerprint.trim().to_uppercase();
    if want.is_empty()
        || !cert.subject.eq_ignore_ascii_case(EXPECTED_SUBJECT)
        || !cert.self_signed()
        || cert.thumbprint.to_uppercase() != want
    {
        return IdentityMatch::No;
    }
    if want == crate::trust::PINNED_SHA1_THUMBPRINT {
        // The pinned identity is the strictest case, and it is all-or-nothing: a certificate that
        // carries our SHA-1 handle but a different DER hash is not a legacy release, it is a
        // collision or a tampered artifact, and it must not be deleted under the legacy allowance.
        return if cert.sha256_der == crate::trust::PINNED_SHA256_DER {
            IdentityMatch::Pinned
        } else {
            IdentityMatch::No
        };
    }
    IdentityMatch::LegacyArtifact
}

/// The command that performs one deletion, as argv, or `None` when the request is outside what this
/// module is allowed to do (non-hex or wrong-length thumbprint, store not in `STORES`).
///
/// Why a child process instead of `CertDeleteCertificateFromStore`: measured on this machine,
/// `CertOpenSystemStoreW` opens the store without delete access so the deletion returns
/// `ERROR_ACCESS_DENIED` even elevated, and `CertOpenStore` with `CERT_SYSTEM_STORE_LOCAL_MACHINE`
/// fails with error 203 for every flag combination probed. The .NET `X509Store` route - which the
/// build-time signing script already uses to add and remove these same certificates - does work. So
/// only the mechanical deletion is delegated; every decision stays in Rust, and the result is
/// verified by re-reading the store rather than by trusting an exit code.
pub fn delete_command(store: &str, thumbprint: &str) -> Option<Vec<String>> {
    let tp: String = thumbprint
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    // Exactly 40 hex characters, and only after normalising: anything shorter would let a prefix
    // match a different certificate, anything longer means non-hex characters were in the input.
    if tp.len() != 40 {
        return None;
    }
    if !STORES.iter().any(|s| s.eq_ignore_ascii_case(store)) {
        return None;
    }
    let tp = tp.to_uppercase();
    // ASCII only, so a failure cannot come back as text that cannot be decoded (measured: a
    // localized PowerShell error arrived as mojibake when read as UTF-8).
    let script = format!(
        "$ErrorActionPreference='Stop';\
         try {{\
          $s=New-Object System.Security.Cryptography.X509Certificates.X509Store('{store}','LocalMachine');\
          $s.Open('ReadWrite');\
          $c=@($s.Certificates | Where-Object {{ $_.Thumbprint -eq '{tp}' }});\
          if ($c.Count -gt 0) {{ $s.Remove($c[0]) }};\
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

/// Read the release identity digest out of its artifact. The artifact is written as `key = value`
/// lines (`subject`, `thumbprint`, `signed_at`, and the SHA-256 anchor file's `sha256_der`), so a
/// value comes either from a bare line or from the right-hand side of an assignment; colons and
/// spaces inside a hex blob are ignored because tools print thumbprints in both forms.
///
/// Accepts both identity digests this project uses - 40 hex (the SHA-1 handle Windows keys stores by)
/// and 64 hex (the SHA-256 DER anchor) - but nothing else: a truncated or padded value stops the
/// search rather than falling through, because a loose match here is what would let a corrupted file
/// point at somebody else's certificate.
pub fn parse_fingerprint(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let value = match line.split_once('=') {
            Some((key, rest)) if !key.trim().is_empty() => rest.trim(),
            _ => line,
        };
        let candidate: String = value
            .chars()
            .filter(|c| !c.is_whitespace() && *c != ':')
            .collect();
        let hexish = candidate.chars().all(|c| c.is_ascii_hexdigit());
        if hexish && (candidate.len() == 40 || candidate.len() == 64) {
            return Some(candidate.to_uppercase());
        }
        if line
            .to_ascii_lowercase()
            .replace(' ', "")
            .starts_with("thumbprint")
            || line
                .to_ascii_lowercase()
                .replace(' ', "")
                .starts_with("sha256")
        {
            return None;
        }
    }
    None
}

/// Where the installer looks for the fingerprint artifact, in order: next to itself, then one
/// directory down in `install\`, which is the two layouts a release folder uses.
pub fn artifact_candidates(base: &Path) -> Vec<std::path::PathBuf> {
    [
        "cm400.cat.thumbprint.txt",
        "install/cm400.cat.thumbprint.txt",
    ]
    .into_iter()
    .map(|name| base.join(name))
    .collect()
}

/// The release fingerprint, or `None` when no readable artifact exists. A missing file is *not*
/// treated as "nothing to clean": the caller has to report that it skipped, because quietly claiming
/// a clean uninstall is the exact failure this step exists to avoid.
pub fn read_fingerprint(base: &Path) -> Option<String> {
    artifact_candidates(base)
        .into_iter()
        .find_map(|path| std::fs::read_to_string(path).ok())
        .and_then(|text| parse_fingerprint(&text))
}

/// Remove the release certificate from ONE store and confirm it by re-reading.
///
/// This is the per-store primitive. `cleanup` walks both stores, while a rollback must be able to undo
/// exactly the stores it wrote to: if `Root` already trusted the certificate and only
/// `TrustedPublisher` was added, rolling back has to leave the pre-existing entry alone.
#[cfg(target_os = "windows")]
pub fn remove_from(store_name: &str, fingerprint: &str) -> Result<bool, String> {
    let Some(observed) = find_one(store_name, fingerprint)? else {
        return Ok(false);
    };
    let Some(argv) = delete_command(store_name, &observed.thumbprint) else {
        return Err(format!("{store_name}: refused to build a removal command"));
    };
    let output = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| {
            format!(
                "{store_name}/{}: could not run the removal ({e})",
                observed.thumbprint
            )
        })?;
    if !output.status.success() {
        let reason = String::from_utf8_lossy(&output.stderr)
            .lines()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("")
            .trim()
            .chars()
            .take(200)
            .collect::<String>();
        return Err(format!(
            "{store_name}/{}: removal failed ({})",
            observed.thumbprint,
            if reason.is_empty() {
                format!("exit {}", output.status.code().unwrap_or(-1))
            } else {
                reason
            }
        ));
    }
    if store_still_has(store_name, &observed.thumbprint) {
        return Err(format!(
            "{store_name}/{}: still listed after the removal attempt",
            observed.thumbprint
        ));
    }
    Ok(true)
}

/// Remove every certificate in the two stores that matches the release identity, then confirm.
#[cfg(target_os = "windows")]
pub fn cleanup(fingerprint: &str) -> Outcome {
    let mut removed: Vec<String> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    for store_name in STORES {
        // A handful of passes, each removing at most one entry, so a store holding two copies of our
        // certificate still ends up clean without ever continuing an invalidated enumeration.
        for _ in 0..4 {
            let observed = match find_one(store_name, fingerprint) {
                Ok(Some(o)) => o,
                Ok(None) => break,
                Err(e) => {
                    errors.push(format!("{store_name}: {e}"));
                    break;
                }
            };
            let Some(argv) = delete_command(store_name, &observed.thumbprint) else {
                errors.push(format!(
                    "{store_name}/{}: refused to build a removal command",
                    observed.thumbprint
                ));
                break;
            };
            let output = std::process::Command::new(&argv[0])
                .args(&argv[1..])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .output();
            let (status, reason) = match output {
                Ok(o) => (
                    o.status,
                    String::from_utf8_lossy(&o.stderr)
                        .lines()
                        .find(|l| !l.trim().is_empty())
                        .unwrap_or("")
                        .trim()
                        .chars()
                        .take(200)
                        .collect::<String>(),
                ),
                Err(e) => {
                    errors.push(format!(
                        "{store_name}/{}: could not run the removal ({e})",
                        observed.thumbprint
                    ));
                    break;
                }
            };
            if !status.success() {
                // The reason goes into the report: a bare exit code told an operator nothing about
                // why a certificate could not be removed (measured: exit 1 with the message thrown
                // away).
                errors.push(format!(
                    "{store_name}/{}: removal failed ({})",
                    observed.thumbprint,
                    if reason.is_empty() {
                        format!("exit {}", status.code().unwrap_or(-1))
                    } else {
                        reason
                    }
                ));
                break;
            }
            // The exit code only buys a re-read; the store decides whether it counts.
            if store_still_has(store_name, &observed.thumbprint) {
                errors.push(format!(
                    "{store_name}/{}: still listed after the removal attempt",
                    observed.thumbprint
                ));
                break;
            }
            removed.push(format!("{store_name}/{}", observed.thumbprint));
        }
    }

    if !errors.is_empty() {
        Outcome::Failed(errors)
    } else if removed.is_empty() {
        Outcome::Absent
    } else {
        Outcome::Removed(removed)
    }
}

/// The first certificate in `store_name` that matches the release identity.
#[cfg(target_os = "windows")]
pub(crate) fn find_one(store_name: &str, fingerprint: &str) -> Result<Option<Observed>, String> {
    use windows::core::PCWSTR;
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CertEnumCertificatesInStore, CertOpenSystemStoreW, CERT_CONTEXT,
        HCRYPTPROV_LEGACY,
    };

    let wide: Vec<u16> = store_name.encode_utf16().chain([0]).collect();
    let store =
        unsafe { CertOpenSystemStoreW(HCRYPTPROV_LEGACY::default(), PCWSTR(wide.as_ptr())) }
            .map_err(|e| format!("cannot open store ({e})"))?;
    let mut found = None;
    let mut prev: *const CERT_CONTEXT = core::ptr::null();
    loop {
        let ctx = unsafe { CertEnumCertificatesInStore(store, Some(prev)) };
        if ctx.is_null() {
            break;
        }
        prev = ctx;
        let Some(observed) = read_context(ctx, store_name) else {
            continue;
        };
        if matches_release_identity(fingerprint, &observed) {
            found = Some(observed);
            break;
        }
    }
    unsafe {
        let _ = CertCloseStore(store, 0);
    }
    Ok(found)
}

/// Does a store still list this thumbprint? A verification step, so "removed" means the store agrees.
#[cfg(target_os = "windows")]
pub(crate) fn store_still_has(store_name: &str, thumbprint: &str) -> bool {
    match find_all_thumbprints(store_name) {
        Ok(list) => list.iter().any(|t| t.eq_ignore_ascii_case(thumbprint)),
        // Cannot check is not the same as absent: report as still there.
        Err(_) => true,
    }
}

/// Every SHA-1 handle in one store. Public because the installer's uninstall step reports which
/// stores still list the pinned identity after cleanup, and that evidence has to come from the store.
#[cfg(target_os = "windows")]
pub fn find_all_thumbprints(store_name: &str) -> Result<Vec<String>, String> {
    use windows::core::PCWSTR;
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CertEnumCertificatesInStore, CertOpenSystemStoreW, CERT_CONTEXT,
        HCRYPTPROV_LEGACY,
    };

    let wide: Vec<u16> = store_name.encode_utf16().chain([0]).collect();
    let store =
        unsafe { CertOpenSystemStoreW(HCRYPTPROV_LEGACY::default(), PCWSTR(wide.as_ptr())) }
            .map_err(|e| format!("cannot open store ({e})"))?;
    let mut out = Vec::new();
    let mut prev: *const CERT_CONTEXT = core::ptr::null();
    loop {
        let ctx = unsafe { CertEnumCertificatesInStore(store, Some(prev)) };
        if ctx.is_null() {
            break;
        }
        prev = ctx;
        if let Some(tp) = sha1_of(ctx) {
            out.push(tp);
        }
    }
    unsafe {
        let _ = CertCloseStore(store, 0);
    }
    Ok(out)
}

/// Read one context into the fields the decision needs. Anything unreadable makes the entry
/// unmatchable rather than assumed-safe.
#[cfg(target_os = "windows")]
pub(crate) fn read_context(
    ctx: *const windows::Win32::Security::Cryptography::CERT_CONTEXT,
    store: &str,
) -> Option<Observed> {
    Some(Observed {
        store: store.to_string(),
        thumbprint: sha1_of(ctx)?,
        sha256_der: sha256_of(ctx)?,
        subject: render_name(ctx, true)?,
        issuer: render_name(ctx, false)?,
    })
}

/// SHA-256 over the certificate's own DER encoding. Read from `pbCertEncoded` rather than from the
/// file that was handed in, because the file could be PEM-wrapped, padded or re-encoded and still
/// contain this certificate - the anchor has to describe the certificate, not the container.
#[cfg(target_os = "windows")]
pub(crate) fn sha256_of(
    ctx: *const windows::Win32::Security::Cryptography::CERT_CONTEXT,
) -> Option<String> {
    use windows::core::PCWSTR;
    use windows::Win32::Security::Cryptography::{
        CryptAcquireContextW, CryptCreateHash, CryptDestroyHash, CryptGetHashParam, CryptHashData,
        CryptReleaseContext, CALG_SHA_256, CRYPT_VERIFYCONTEXT, HP_HASHVAL, PROV_RSA_AES,
    };

    let info = unsafe { &*ctx };
    if info.pbCertEncoded.is_null() || info.cbCertEncoded == 0 {
        return None;
    }
    let der =
        unsafe { core::slice::from_raw_parts(info.pbCertEncoded, info.cbCertEncoded as usize) };
    unsafe {
        let mut prov = 0usize;
        if CryptAcquireContextW(
            &mut prov,
            PCWSTR::null(),
            PCWSTR::null(),
            PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT,
        )
        .is_err()
        {
            return None;
        }
        let mut hash = 0usize;
        if CryptCreateHash(prov, CALG_SHA_256, 0, 0, &mut hash).is_err() {
            let _ = CryptReleaseContext(prov, 0);
            return None;
        }
        let mut out = None;
        if CryptHashData(hash, der, 0).is_ok() {
            let mut len = 0u32;
            if CryptGetHashParam(hash, HP_HASHVAL.0, None, &mut len, 0).is_ok()
                && len as usize == 32
            {
                let mut buf = vec![0u8; len as usize];
                if CryptGetHashParam(hash, HP_HASHVAL.0, Some(buf.as_mut_ptr()), &mut len, 0)
                    .is_ok()
                {
                    out = Some(buf.iter().map(|b| format!("{b:02X}")).collect::<String>());
                }
            }
        }
        let _ = CryptDestroyHash(hash);
        let _ = CryptReleaseContext(prov, 0);
        out
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn sha1_of(
    ctx: *const windows::Win32::Security::Cryptography::CERT_CONTEXT,
) -> Option<String> {
    use windows::Win32::Security::Cryptography::CertGetCertificateContextProperty;

    let mut len = 0u32;
    if unsafe { CertGetCertificateContextProperty(ctx, CERT_SHA1_PROP, None, &mut len) }.is_err() {
        return None;
    }
    let mut buf = vec![0u8; len as usize];
    if unsafe {
        CertGetCertificateContextProperty(
            ctx,
            CERT_SHA1_PROP,
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            &mut len,
        )
    }
    .is_err()
    {
        return None;
    }
    Some(buf.iter().map(|b| format!("{b:02X}")).collect::<String>())
}

#[cfg(target_os = "windows")]
pub(crate) fn render_name(
    ctx: *const windows::Win32::Security::Cryptography::CERT_CONTEXT,
    subject: bool,
) -> Option<String> {
    use windows::Win32::Security::Cryptography::{
        CertNameToStrW, CERT_X500_NAME_STR, CRYPT_INTEGER_BLOB, X509_ASN_ENCODING,
    };

    let info = unsafe { &*(*ctx).pCertInfo };
    let blob = if subject { &info.Subject } else { &info.Issuer };
    // The parameter wants a `CRYPT_INTEGER_BLOB`; subject and issuer are the same
    // { length, pointer } shape, so a copy of the two fields is all that is needed.
    let name = CRYPT_INTEGER_BLOB {
        cbData: blob.cbData,
        pbData: blob.pbData,
    };
    let mut buffer = vec![0u16; 512];
    let written = unsafe {
        CertNameToStrW(
            X509_ASN_ENCODING,
            &name,
            CERT_X500_NAME_STR,
            Some(&mut buffer),
        )
    };
    if written == 0 || written as usize >= buffer.len() {
        return None;
    }
    let units = &buffer[..written as usize];
    let end = units.iter().position(|c| *c == 0).unwrap_or(units.len());
    Some(String::from_utf16_lossy(&units[..end]))
}

/// `CERT_SHA1_HASH_PROP_ID` under a stable local name (exported as a plain `u32`).
#[cfg(target_os = "windows")]
const CERT_SHA1_PROP: u32 = windows::Win32::Security::Cryptography::CERT_SHA1_HASH_PROP_ID;

#[cfg(test)]
mod tests {
    use super::*;

    const TP: &str = "A7A1F0C4B3D2E5F60718293A4B5C6D7E8F90A1B2";
    // exactly 64 hex, because "a digest-shaped value of the wrong length" is one of the cases this
    // parser has to refuse; the first draft of this constant was 70 characters and passed unnoticed
    const SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn cert(store: &str, thumb: &str, subject: &str, issuer: &str) -> Observed {
        Observed {
            store: store.into(),
            thumbprint: thumb.into(),
            // any 64-hex value; these cases are about the SHA-1 handle, subject and issuer, and the
            // pinned-anchor behaviour is covered in `trust::tests`
            sha256_der: SHA.into(),
            subject: subject.into(),
            issuer: issuer.into(),
        }
    }

    /// A fingerprint alone must not be enough. Each rejected case below is a certificate somebody
    /// else legitimately needs in `Root`, and deleting any of them would be a far worse bug than
    /// leaving our own residue behind.
    #[test]
    fn only_our_own_self_signed_certificate_matches() {
        let ours = cert("Root", TP, EXPECTED_SUBJECT, EXPECTED_SUBJECT);
        assert!(matches_release_identity(TP, &ours));
        assert!(
            matches_release_identity(&TP.to_lowercase(), &ours),
            "hex is case-insensitive"
        );
        assert!(matches_release_identity(
            &format!(" {TP} "),
            &cert("Root", TP, "cn=cm400 driver", "cn=CM400 DRIVER")
        ));

        let wrong_thumb = cert("Root", &"B".repeat(40), EXPECTED_SUBJECT, EXPECTED_SUBJECT);
        assert!(
            !matches_release_identity(TP, &wrong_thumb),
            "fingerprint must match"
        );

        let lookalike = cert("Root", TP, "CN=Some Real CA Root", "CN=Some Real CA Root");
        assert!(
            !matches_release_identity(TP, &lookalike),
            "a different subject is never ours, whatever the fingerprint says"
        );

        let issued_by_other = cert("Root", TP, EXPECTED_SUBJECT, "CN=Contoso Issuing CA");
        assert!(
            !matches_release_identity(TP, &issued_by_other),
            "only self-signed entries created by the signing script qualify"
        );

        assert!(
            !matches_release_identity("", &ours),
            "an empty fingerprint matches nothing"
        );
        // The store is deliberately not part of the identity decision: `STORES` limits which stores
        // are ever walked, and `delete_command` refuses any other store. Two separate guards.
    }

    #[test]
    fn the_removal_command_cannot_be_widened() {
        let argv = delete_command("Root", TP).expect("our own certificate is removable");
        assert_eq!(argv[0], "powershell.exe");
        let joined = argv.join(" ");
        assert!(
            joined.contains("X509Store('Root','LocalMachine')"),
            "{joined}"
        );
        assert!(
            joined.contains("Open('ReadWrite')"),
            "the store has to be opened for writing"
        );
        assert!(
            joined.contains("$ErrorActionPreference='Stop'"),
            "a failing step must not fall through to exit 0"
        );
        assert!(
            joined.contains("catch { exit 1 }"),
            "and the child must report that failure"
        );
        assert!(
            joined.contains(&format!("-eq '{TP}'")),
            "selection is by exact thumbprint: {joined}"
        );
        assert!(!joined.contains('*'), "no wildcards in a deletion command");
        assert!(
            joined.chars().all(|c| (c as u32) < 128),
            "the script stays ASCII so a failure message cannot arrive undecodable"
        );
        assert!(
            delete_command("My", TP).is_none(),
            "other stores are out of scope"
        );
        assert!(
            delete_command("Root", &TP[..38]).is_none(),
            "a truncated thumbprint is refused"
        );
        assert!(delete_command("Root", "not-hex-at-all-00000000000000000000000000").is_none());
        assert!(delete_command("Root", "").is_none());
        assert!(
            delete_command("TrustedPublisher", &TP.to_lowercase())
                .unwrap()
                .join(" ")
                .contains(TP),
            "normalised to the upper-case form the store uses"
        );
    }

    #[test]
    fn the_fingerprint_artifact_is_strict() {
        assert_eq!(
            parse_fingerprint(&format!(
                "# CM400 release certificate fingerprint\nsubject = {EXPECTED_SUBJECT}\nthumbprint = {TP}\nsigned_at = 2026-10-12T00:00:00\r\n"
            )),
            Some(TP.to_string())
        );
        assert_eq!(parse_fingerprint(TP), Some(TP.to_string()));
        assert_eq!(
            parse_fingerprint("A7A1: F0C4: B3D2: E5F6: 0718: 293A: 4B5C: 6D7E: 8F90: A1B2"),
            Some(TP.to_string())
        );
        // the SHA-256 anchor file uses the same shape, and is the only place a 64-hex value is legal;
        // the value comes back normalised to upper case whether the file wrote it lower or upper
        assert_eq!(
            parse_fingerprint(&format!(
                "subject = {EXPECTED_SUBJECT}\nsha256_der = {SHA}\n"
            )),
            Some(SHA.to_uppercase())
        );
        assert_eq!(parse_fingerprint("not-a-thumbprint"), None);
        assert_eq!(
            parse_fingerprint(&format!("thumbprint = {}", &TP[..38])),
            None,
            "truncated is refused, not widened"
        );
        assert_eq!(
            parse_fingerprint(&format!("sha256_der = {}", &SHA[..62])),
            None
        );
        assert_eq!(
            parse_fingerprint(&format!("thumbprint = {}", &SHA[..41])),
            None,
            "41 characters is neither digest length, and a value presented as a thumbprint that does \
             not parse is a stop, not a fallback"
        );
        assert_eq!(parse_fingerprint("thumbprint = zzzz"), None);
        assert_eq!(parse_fingerprint(""), None);
        assert_eq!(parse_fingerprint("# only a comment\n"), None);
    }

    #[test]
    fn the_artifact_is_only_read_from_the_release_folder() {
        let base = Path::new("D:\\cm400");
        let list = artifact_candidates(base);
        assert_eq!(list.len(), 2);
        assert!(list[0].ends_with("cm400.cat.thumbprint.txt"));
        assert!(list[1].to_string_lossy().contains("install"));
        assert_eq!(
            read_fingerprint(base),
            None,
            "nothing on disk means None, which the caller reports as skipped"
        );
    }

    #[test]
    fn a_malformed_artifact_produces_no_fingerprint() {
        let dir = std::env::temp_dir().join(format!("cm400-cert-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("cm400.cat.thumbprint.txt"), "thumbprint = zzzz\n").unwrap();
        assert_eq!(read_fingerprint(&dir), None);
        std::fs::write(
            dir.join("cm400.cat.thumbprint.txt"),
            format!("# comment\nsubject = {EXPECTED_SUBJECT}\nthumbprint = {TP}\n"),
        )
        .unwrap();
        assert_eq!(read_fingerprint(&dir).as_deref(), Some(TP));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The three outcomes must read differently, and only `Removed` may claim success.
    #[test]
    fn outcomes_stay_distinct() {
        assert!(Outcome::Absent.describe().contains("nothing to remove"));
        assert!(!Outcome::Absent.failed());
        let removed = Outcome::Removed(vec![format!("Root/{TP}")]);
        assert!(removed.describe().contains("removed 1"));
        assert!(
            removed.describe().contains("confirmed absent"),
            "success claims the verification"
        );
        assert!(!removed.failed());
        let failed = Outcome::Failed(vec![format!(
            "Root/{TP}: still listed after the removal attempt"
        )]);
        assert!(failed.describe().starts_with("certificate cleanup: FAILED"));
        assert!(
            failed.failed(),
            "an unconfirmed delete is never cleanup done"
        );
    }
}
