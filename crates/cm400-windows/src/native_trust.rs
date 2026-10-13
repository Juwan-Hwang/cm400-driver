//! Native Windows package verification, shared by the installer and the trust harness.
//!
//! Moved out of `bin/cm400_setup.rs` unchanged so the production installer and the development
//! harness consume the same typed results, instead of one of them re-implementing the check or
//! reading another program stdout. The three questions below stay separate on purpose.

/// Native package verification. Replaces the SDK `signtool` CLI dependency: a
/// customer machine must not need the Windows SDK to install this driver.
///
/// STATUS: active. This replaces the SDK `signtool` CLI so a customer machine needs
/// nothing but Windows itself. File hashing uses a `std::fs::File` handle on purpose:
/// `CreateFileW`'s access/share/disposition constants are easy to mis-import and buy
/// us nothing here.
/// The three questions are separate functions with separate results on purpose:
///   1. is the catalog's own signature cryptically valid and trusted here  -> WinVerifyTrust
///   2. is this INF actually a member of THAT catalog                      -> CryptCATAdmin* + CryptSIP hashes
///   3. is the verdict a local-trust statement, not "Microsoft signed this" -> documented at each call site
use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;
use windows::core::{HRESULT, PCWSTR, PWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Foundation::HWND;
use windows::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle, CryptCATAdminReleaseContext,
    CryptCATClose, CryptCATEnumerateMember, CryptCATOpen, CRYPTCAT_OPEN_FLAGS, CRYPTCAT_VERSION,
};
use windows::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
    WTD_CHOICE_FILE, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
    WTD_UI_NONE,
};

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 1. The catalog's own Authenticode signature, verified and trusted on THIS
///    machine (WinVerifyTrust consults the system trust lists, so a self-signed
///    catalog passes only because its certificate is in Local Machine\Trusted
///    Publishers - that is exactly the distinction we must not blur).
pub fn catalog_signature(cat_path: &str) -> Result<(), String> {
    unsafe {
        let w = wide(cat_path);
        let mut fi = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR(w.as_ptr()),
            hFile: HANDLE::default(),
            pgKnownSubject: core::ptr::null_mut(),
        };

        // Everything except the anonymous union member can be stated up front; `pFile` has to be
        // assigned afterwards because it borrows `fi`.
        let mut td = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            pPolicyCallbackData: core::ptr::null_mut::<c_void>(),
            pSIPClientData: core::ptr::null_mut::<c_void>(),
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
            dwUnionChoice: WTD_CHOICE_FILE,
            dwStateAction: WTD_STATEACTION_VERIFY,
            hWVTStateData: HANDLE::default(),
            pwszURLReference: PWSTR::null(),
            dwProvFlags: Default::default(),
            dwUIContext: Default::default(),
            pSignatureSettings: core::ptr::null_mut(),
            ..Default::default()
        };
        td.Anonymous.pFile = &mut fi as *mut WINTRUST_FILE_INFO;

        // The API wants a mutable GUID pointer; the GUID itself is a constant, so
        // take a local copy rather than casting away the const.
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let hr = WinVerifyTrust(
            HWND::default(),
            &mut action,
            &mut td as *mut WINTRUST_DATA as *mut c_void,
        );
        // Always release the state data WinTrust allocated during VERIFY.
        let mut close = td;
        close.dwStateAction = WTD_STATEACTION_CLOSE;
        close.dwUnionChoice = WTD_CHOICE_FILE;
        close.Anonymous.pFile = &mut fi as *mut WINTRUST_FILE_INFO;
        let _ = WinVerifyTrust(
            HWND::default(),
            &mut action,
            &mut close as *mut WINTRUST_DATA as *mut c_void,
        );
        // The 0.58 binding returns the raw HRESULT as i32, so say so explicitly:
        // a non-success code is a verdict, not a panic.
        if HRESULT(hr).is_ok() {
            Ok(())
        } else {
            Err(format!("WinVerifyTrust failed with {:#010x}", hr))
        }
    }
}

/// Every reference tag the catalog declares, with no name-matching convenience applied.
///
/// `inf_catalog_membership` also accepts a tag equal to the file's name because INFs can be catalogued
/// that way; a release gate must not, since a name is not an attestation of content. This returns the
/// tags as they are so the caller can bind them to digests it computed itself.
pub fn catalog_member_ids(cat_path: &str) -> Result<Vec<String>, String> {
    unsafe {
        let hcat = CryptCATOpen(
            PCWSTR(wide(cat_path).as_ptr()),
            CRYPTCAT_OPEN_FLAGS(0),
            0,
            CRYPTCAT_VERSION(0),
            0,
        );
        if hcat.is_invalid() {
            return Err(format!("CryptCATOpen failed for {cat_path}"));
        }
        let mut prev = core::ptr::null_mut();
        let mut out = Vec::new();
        loop {
            let m = CryptCATEnumerateMember(hcat, prev);
            if m.is_null() {
                break;
            }
            prev = m;
            if (*m).pwszReferenceTag.is_null() {
                continue;
            }
            out.push((*m).pwszReferenceTag.to_string().unwrap_or_default());
        }
        let _ = CryptCATClose(hcat);
        Ok(out)
    }
}

/// The authoritative catalog digest of a file on disk: crypt32's own calculation, the same function
/// `makecat` uses, so a digest mismatch cannot be blamed on a hashing difference between tools.
pub fn file_catalog_digest(path: &str) -> Result<String, String> {
    file_sha1_hex_upper(path)
}

/// 2. Membership, verified against THIS catalog file with no system side effects.
///
/// Why not `CryptCATAdminEnumCatalogFromHash` alone: that call only searches
/// catalogs already registered in the system catalog database, so an unregistered
/// `cm400.cat` would make a perfectly valid pair look like a failure. Instead we
/// compute the file digest the same way makecat does (SHA-1, upper-case hex, which
/// is the member identifier inside the catalog) and walk the catalog's own member
/// list comparing reference tags.
///
/// As a convenience we also accept a tag equal to the file's name, because INFs
/// can be catalogued that way.
pub fn inf_catalog_membership(inf_path: &str, cat_path: &str) -> Result<(), String> {
    let want = file_sha1_hex_upper(inf_path)?;
    unsafe {
        let hcat = CryptCATOpen(
            PCWSTR(wide(cat_path).as_ptr()),
            CRYPTCAT_OPEN_FLAGS(0),
            0,
            CRYPTCAT_VERSION(0),
            0,
        );
        if hcat.is_invalid() {
            return Err(format!("CryptCATOpen failed for {cat_path}"));
        }
        let mut prev = core::ptr::null_mut();
        let mut matched = false;
        let mut seen: Vec<String> = Vec::new();
        loop {
            let m = CryptCATEnumerateMember(hcat, prev);
            if m.is_null() {
                break;
            }
            prev = m;
            // PWSTR renders itself up to the first NUL, which is exactly what we
            // need here and avoids hand-walking a raw pointer.
            if (*m).pwszReferenceTag.is_null() {
                continue;
            }
            let tag = (*m).pwszReferenceTag.to_string().unwrap_or_default();
            let name = if (*m).pwszFileName.is_null() {
                String::new()
            } else {
                (*m).pwszFileName.to_string().unwrap_or_default()
            };
            seen.push(tag.clone());
            let base = inf_path.rsplit(['\\', '/']).next().unwrap_or(inf_path);
            if tag.eq_ignore_ascii_case(&want)
                || tag.eq_ignore_ascii_case(base)
                || name.eq_ignore_ascii_case(base)
            {
                matched = true;
            }
        }
        let _ = CryptCATClose(hcat);
        if matched {
            Ok(())
        } else {
            Err(format!(
                "INF hash {want} not among the {} member(s) of {cat_path}: {:?}",
                seen.len(),
                seen
            ))
        }
    }
}

/// A signed catalog is not the same statement as "its signer is our release identity", and picking
/// the certificate in the message that happens to match what we are looking for would prove nothing:
/// the message's certificate collection is attacker-supplied data. This asks crypt32 to resolve the
/// CMS `SignerInfo` and **verify the signature**, then returns the certificate that actually produced
/// it.
///
/// `windows` 0.58 exposes exactly one shape for this: `CryptMsgGetAndVerifySigner` takes a message
/// handle and returns a verified `CERT_CONTEXT` plus its index. `CryptMsgOpenByBlob` is not exposed
/// in that version, so the message handle comes from `CryptQueryObject`'s `phmsg` output. Neither
/// `WTY_SIGNER` nor `WTD_PROVIDER_CERTIFICATE_CONTEXT` exists here either, which rules out reading
/// the signer out of a `WinVerifyTrust` state block - the route an earlier draft of the design named.
///
/// `CRYPT_DATA_BLOB` is also not exported by 0.58, and what crypt32 reads is the ABI, so the mirror
/// below is declared locally rather than reaching for a type that is not on the public surface.
#[repr(C)]
struct DataBlob {
    cb_data: u32,
    pb_data: *mut u8,
}

#[cfg(target_os = "windows")]
pub fn catalog_signer(cat_path: &str) -> Result<crate::cert_cleanup::Observed, String> {
    use std::ffi::c_void;
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CertFreeCertificateContext, CryptMsgClose, CryptMsgGetAndVerifySigner,
        CryptQueryObject, CERT_CONTEXT, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
        CERT_QUERY_CONTENT_PKCS7_SIGNED, CERT_QUERY_CONTENT_TYPE, CERT_QUERY_FORMAT_FLAG_BINARY,
        CERT_QUERY_FORMAT_TYPE, CERT_QUERY_OBJECT_BLOB, HCERTSTORE,
    };

    let bytes = std::fs::read(cat_path).map_err(|e| format!("cannot read {cat_path}: {e}"))?;
    if bytes.is_empty() {
        return Err(format!("{cat_path} is empty"));
    }
    let mut blob = DataBlob {
        cb_data: bytes.len() as u32,
        pb_data: bytes.as_ptr() as *mut u8,
    };

    unsafe {
        let mut content = CERT_QUERY_CONTENT_TYPE(0);
        let mut format = CERT_QUERY_FORMAT_TYPE(0);
        let mut store = HCERTSTORE::default();
        let mut hmsg: *mut c_void = core::ptr::null_mut();
        CryptQueryObject(
            CERT_QUERY_OBJECT_BLOB,
            &mut blob as *mut DataBlob as *const c_void,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            None,
            Some(&mut content),
            Some(&mut format),
            Some(&mut store),
            Some(&mut hmsg),
            None,
        )
        .map_err(|e| format!("CryptQueryObject rejected {cat_path} as a signed catalog ({e})"))?;

        // Close whatever was handed back on every exit path, including the error paths below.
        let finish = |err: String| -> String {
            let _ = CryptMsgClose(Some(hmsg));
            let _ = CertCloseStore(store, 0);
            err
        };

        if content != CERT_QUERY_CONTENT_PKCS7_SIGNED {
            return Err(finish(format!(
                "{cat_path} decoded as content type {content:?}, not a PKCS#7 signed-data catalog"
            )));
        }

        let mut signer: *mut CERT_CONTEXT = core::ptr::null_mut();
        let mut index = 0u32;
        if let Err(e) =
            CryptMsgGetAndVerifySigner(hmsg, Some(&[store]), 0, Some(&mut signer), Some(&mut index))
        {
            return Err(finish(format!(
                "no signer signature in {cat_path} could be verified ({e})"
            )));
        }
        if signer.is_null() {
            return Err(finish(format!(
                "CryptMsgGetAndVerifySigner reported success for {cat_path} but returned no signer"
            )));
        }
        let observed = crate::cert_cleanup::read_context(signer, "catalog-signer");
        let _ = CertFreeCertificateContext(Some(signer));
        let _ = CryptMsgClose(Some(hmsg));
        let _ = CertCloseStore(store, 0);
        observed
            .ok_or_else(|| format!("{cat_path}: the signer's identity fields could not be read"))
    }
}

/// Every certificate the catalog's PKCS#7 message carries, as identity records.
///
/// This exists so a test can *measure* whether a message contains a second, unrelated certificate
/// instead of asserting it in prose. The distinction matters for the signer check: the collection is
/// attacker-supplied data and `catalog_signer` must not be satisfied by finding a match inside it.
#[cfg(target_os = "windows")]
pub fn catalog_certificates(cat_path: &str) -> Result<Vec<crate::cert_cleanup::Observed>, String> {
    use std::ffi::c_void;
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CertEnumCertificatesInStore, CryptMsgClose, CryptQueryObject, CERT_CONTEXT,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED, CERT_QUERY_FORMAT_FLAG_BINARY,
        CERT_QUERY_OBJECT_BLOB, HCERTSTORE,
    };

    let bytes = std::fs::read(cat_path).map_err(|e| format!("cannot read {cat_path}: {e}"))?;
    if bytes.is_empty() {
        return Err(format!("{cat_path} is empty"));
    }
    let mut blob = DataBlob {
        cb_data: bytes.len() as u32,
        pb_data: bytes.as_ptr() as *mut u8,
    };
    unsafe {
        let mut store = HCERTSTORE::default();
        let mut hmsg: *mut c_void = core::ptr::null_mut();
        CryptQueryObject(
            CERT_QUERY_OBJECT_BLOB,
            &mut blob as *mut DataBlob as *const c_void,
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
            format!("CryptQueryObject could not open {cat_path} as a signed catalog ({e})")
        })?;

        let mut out = Vec::new();
        // `CertEnumCertificatesInStore` releases the context passed in as `prev`, so the loop keeps
        // only the pointer it handed back and frees nothing itself.
        let mut prev: *const CERT_CONTEXT = core::ptr::null();
        loop {
            let ctx = CertEnumCertificatesInStore(store, Some(prev));
            if ctx.is_null() {
                break;
            }
            prev = ctx;
            if let Some(o) = crate::cert_cleanup::read_context(ctx, "message-certificate") {
                out.push(o);
            }
        }
        let _ = prev;
        let _ = CryptMsgClose(Some(hmsg));
        let _ = CertCloseStore(store, 0);
        Ok(out)
    }
}

/// The two questions the installer must have answered before it touches a device, as data.
///
/// Deliberately `Result` and not a string: the installer used to print these verdicts, and printing
/// them is fine, but a decision that is parsed back out of stdout is one `println!` away from being
/// wrong. The `verify-package` subcommand is now only a display in front of this.
#[derive(Debug, Clone)]
pub struct PackageVerdict {
    pub signature: Result<(), String>,
    pub membership: Result<(), String>,
}

impl PackageVerdict {
    pub fn accepted(&self) -> bool {
        self.signature.is_ok() && self.membership.is_ok()
    }

    /// Exit code for the `verify-package` diagnostic: non-zero as soon as a required judgement fails,
    /// because returning 0 while printing `FAIL` is what misled a packaging gate once already.
    pub fn exit_code(&self) -> i32 {
        if self.accepted() {
            0
        } else {
            23
        }
    }
}

/// Ask both questions about one INF/CAT pair. Order matters only for the messages: membership is
/// checked against the catalog file itself, so an unregistered package still answers correctly.
#[cfg(target_os = "windows")]
pub fn verify_package(inf_path: &str, cat_path: &str) -> PackageVerdict {
    PackageVerdict {
        signature: catalog_signature(cat_path),
        membership: inf_catalog_membership(inf_path, cat_path),
    }
}

/// The same question about any file: is this file's digest a member of that catalog?
///
/// Needed because `SHA256SUMS.txt` has to be inside the signed catalog. A manifest that merely sits in
/// the same folder proves nothing - whoever can replace a file can replace the line that describes it.
/// Membership in the catalog, whose signer is checked against the pinned identity, is what makes the
/// digest list trustworthy.
pub fn file_catalog_membership(file_path: &str, cat_path: &str) -> Result<(), String> {
    inf_catalog_membership(file_path, cat_path)
}

/// SHA-1 hex of a file, upper-case - the identifier form makecat writes.
fn file_sha1_hex_upper(path: &str) -> Result<String, String> {
    unsafe {
        let mut admin: isize = 0;
        CryptCATAdminAcquireContext2(&mut admin, None, PCWSTR(wide("SHA1").as_ptr()), None, 0)
            .map_err(|e| format!("CryptCATAdminAcquireContext2: {e}"))?;
        let file = std::fs::File::open(path).map_err(|e| format!("open {path}: {e}"))?;
        let h = HANDLE(file.as_raw_handle());
        let mut len = 0u32;
        if !CryptCATAdminCalcHashFromFileHandle(h, &mut len, None, 0).as_bool() || len == 0 {
            let _ = CryptCATAdminReleaseContext(admin, 0);
            return Err(format!("hash size query failed for {path}"));
        }
        let mut hash = vec![0u8; len as usize];
        let mut len2 = len;
        if !CryptCATAdminCalcHashFromFileHandle(h, &mut len2, Some(hash.as_mut_ptr()), 0).as_bool()
        {
            let _ = CryptCATAdminReleaseContext(admin, 0);
            return Err(format!("hash computation failed for {path}"));
        }
        drop(file);
        let _ = CryptCATAdminReleaseContext(admin, 0);
        Ok(hash.iter().map(|b| format!("{b:02X}")).collect::<String>())
    }
}
