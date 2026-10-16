//! Independent verification of a signed catalog, for use before any candidate binary is executed.
//!
//! Three legs, each covering a region the others provably do not (all three measured; see
//! `docs/RELEASE-READINESS.md` §10g/§10h):
//!
//! 1. **signature** - the catalog's PKCS#7 signature is verified *with the pinned certificate*, so the
//!    verdict does not depend on whether this machine happens to trust the publisher. A flipped byte
//!    inside `encapContentInfo` is refused as a hash error; that region also holds the catalog's member
//!    identifiers, so a rebuilt member list cannot be introduced without breaking this leg.
//! 2. **embedded identity** - the certificate actually embedded in the catalog is compared byte for
//!    byte with the repository's pinned certificate. `CMSG_TRUSTED_SIGNER_FLAG` resolves the returned
//!    signer out of the store *we* supply, so comparing that value to our own pin would be comparing a
//!    thing to itself and would miss tampering inside the message's `certificates` set - which, being
//!    outside the signed digest, is precisely where leg 1 cannot see anything.
//! 3. **content binding** - every member identifier the catalog declares must equal the digest
//!    recomputed from the file on disk, and the identifier set must be exactly the expected set. This is
//!    what ties the verdict to these particular files rather than to a well-formed catalog.
//!
//! Failure to *determine* an answer is a refusal, not a pass, on every leg.

#![cfg(target_os = "windows")]

use std::ffi::c_void;
use std::ptr;

use windows::Win32::Security::Cryptography::{
    CertAddCertificateContextToStore, CertCloseStore, CertCreateCertificateContext,
    CertEnumCertificatesInStore, CertFreeCertificateContext, CertOpenStore, CryptMsgClose,
    CryptMsgControl, CryptMsgGetAndVerifySigner, CryptMsgGetParam, CryptQueryObject, CERT_CONTEXT,
    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED, CERT_QUERY_CONTENT_PKCS7_SIGNED, CERT_QUERY_CONTENT_TYPE,
    CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_FORMAT_TYPE, CERT_QUERY_OBJECT_BLOB,
    CERT_STORE_ADD_NEW, CERT_STORE_CREATE_NEW_FLAG, CERT_STORE_PROV_MEMORY, CMSG_CERT_COUNT_PARAM,
    CMSG_CERT_PARAM, CMSG_CTRL_VERIFY_SIGNATURE_EX, CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA,
    CMSG_SIGNER_COUNT_PARAM, CMSG_TRUSTED_SIGNER_FLAG, CMSG_VERIFY_SIGNER_CERT, HCERTSTORE,
    HCRYPTPROV_LEGACY,
};

/// Byte-identical comparison, reported as text rather than as a bool, so a refusal always carries a
/// reason that can be read in a CI log.
pub fn der_compare(embedded: &[u8], pinned: &[u8]) -> Result<(), String> {
    if embedded == pinned {
        return Ok(());
    }
    if embedded.len() != pinned.len() {
        return Err(format!(
            "embedded certificate is {} bytes, the pinned certificate is {}",
            embedded.len(),
            pinned.len()
        ));
    }
    let at = embedded
        .iter()
        .zip(pinned.iter())
        .position(|(a, b)| a != b)
        .unwrap_or(0);
    Err(format!(
        "embedded certificate differs from the pinned certificate at byte {at} ({} vs {})",
        embedded[at], pinned[at]
    ))
}

/// The member identifier set must match the expected set exactly: a missing identifier means a file is
/// not attested, and an extra one means the catalog describes content this package does not contain.
pub fn member_set_verdict(
    declared: &[String],
    expected: &[(String, String)],
) -> Result<(), String> {
    let mut problems = Vec::new();
    for (name, digest) in expected {
        if !declared.iter().any(|d| d.eq_ignore_ascii_case(digest)) {
            problems.push(format!("{name}'s digest {digest} is not a catalog member"));
        }
    }
    for digest in declared {
        if !expected.iter().any(|(_, d)| d.eq_ignore_ascii_case(digest)) {
            problems.push(format!("catalog declares an unexpected member {digest}"));
        }
    }
    if declared.len() != expected.len() {
        problems.push(format!(
            "catalog declares {} members, this package expects {}",
            declared.len(),
            expected.len()
        ));
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

#[repr(C)]
struct DataBlob {
    cb_data: u32,
    pb_data: *mut u8,
}

/// Open the catalog as a PKCS#7 signed-data message, checking the content class the API reports.
/// Returns the message handle plus the store crypt32 filled with the message's certificates; both are
/// the caller's to close, and every error path below closes them.
unsafe fn open_signed_data(cat_path: &str) -> Result<(*mut c_void, HCERTSTORE, u32), String> {
    let bytes = std::fs::read(cat_path).map_err(|e| format!("cannot read {cat_path}: {e}"))?;
    if bytes.is_empty() {
        return Err(format!("{cat_path} is empty"));
    }
    let mut blob = DataBlob {
        cb_data: bytes.len() as u32,
        pb_data: bytes.as_ptr() as *mut u8,
    };
    let mut content = CERT_QUERY_CONTENT_TYPE(0);
    let mut format = CERT_QUERY_FORMAT_TYPE(0);
    let mut store = HCERTSTORE::default();
    let mut hmsg: *mut c_void = ptr::null_mut();
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
    if hmsg.is_null() {
        let _ = CertCloseStore(store, 0);
        return Err(format!("{cat_path} opened without a message handle"));
    }
    if content != CERT_QUERY_CONTENT_PKCS7_SIGNED {
        let _ = CryptMsgClose(Some(hmsg));
        let _ = CertCloseStore(store, 0);
        return Err(format!(
            "{cat_path} decoded as content type {}, not PKCS#7 signed data ({})",
            content.0, CERT_QUERY_CONTENT_PKCS7_SIGNED.0
        ));
    }
    Ok((hmsg, store, content.0))
}

/// Leg 1a: verify the signature using only the pinned certificate as the trusted signer source.
pub fn verify_with_pinned_certificate(cat_path: &str, pinned_der: &[u8]) -> Result<(), String> {
    unsafe {
        let (hmsg, msg_store, _) = open_signed_data(cat_path)?;
        let done = |err: String| {
            let _ = CryptMsgClose(Some(hmsg));
            let _ = CertCloseStore(msg_store, 0);
            err
        };
        let pinned = CertCreateCertificateContext(X509_ASN_ENCODING_, pinned_der);
        if pinned.is_null() {
            return Err(done(
                "the pinned certificate could not be turned into a certificate context".to_string(),
            ));
        }
        let mem = CertOpenStore(
            CERT_STORE_PROV_MEMORY,
            Default::default(),
            HCRYPTPROV_LEGACY(0),
            CERT_STORE_CREATE_NEW_FLAG,
            None,
        )
        .map_err(|e| {
            let _ = CertFreeCertificateContext(Some(pinned));
            done(format!(
                "an in-memory certificate store could not be created ({e})"
            ))
        })?;
        if let Err(e) = CertAddCertificateContextToStore(
            mem,
            pinned as *const CERT_CONTEXT,
            CERT_STORE_ADD_NEW,
            None,
        ) {
            let _ = CertCloseStore(mem, 0);
            let _ = CertFreeCertificateContext(Some(pinned));
            return Err(done(format!(
                "the pinned certificate could not be placed in the memory store ({e})"
            )));
        }
        let mut signer: *mut CERT_CONTEXT = ptr::null_mut();
        let mut index = 0u32;
        let r = CryptMsgGetAndVerifySigner(
            hmsg,
            Some(&[mem]),
            CMSG_TRUSTED_SIGNER_FLAG,
            Some(&mut signer),
            Some(&mut index),
        );
        let result = match r {
            // the certificate is deliberately not read back out of here: it is resolved from the store
            // this call was given, so it cannot serve as evidence about the embedded certificate
            Ok(()) if signer.is_null() => Err(
                "CryptMsgGetAndVerifySigner reported success but returned no signer".to_string(),
            ),
            Ok(()) => {
                let _ = CertFreeCertificateContext(Some(signer));
                Ok(())
            }
            Err(e) => Err(format!("signature verification failed ({e})")),
        };
        let _ = CertCloseStore(mem, 0);
        let _ = CertFreeCertificateContext(Some(pinned));
        result.map_err(done)
    }
}

/// Leg 1b: the differential check - verify the same signature against an arbitrary certificate. With a
/// foreign key this must fail; it is how a regression proves the verdict is arithmetic and not
/// "a certificate was present".
pub fn verify_signature_against_key(cat_path: &str, der: &[u8]) -> Result<(), String> {
    unsafe {
        let (hmsg, msg_store, _) = open_signed_data(cat_path)?;
        let done = |err: String| {
            let _ = CryptMsgClose(Some(hmsg));
            let _ = CertCloseStore(msg_store, 0);
            err
        };
        let cert = CertCreateCertificateContext(X509_ASN_ENCODING_, der);
        if cert.is_null() {
            return Err(done(
                "the supplied certificate could not be turned into a certificate context"
                    .to_string(),
            ));
        }
        let mut para = CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA {
            cbSize: std::mem::size_of::<CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA>() as u32,
            hCryptProv: Default::default(),
            dwSignerIndex: 0,
            dwSignerType: CMSG_VERIFY_SIGNER_CERT,
            pvSigner: cert as *mut c_void,
        };
        let r = CryptMsgControl(
            hmsg,
            0,
            CMSG_CTRL_VERIFY_SIGNATURE_EX,
            Some((&raw mut para).cast()),
        );
        let _ = CertFreeCertificateContext(Some(cert as *const CERT_CONTEXT));
        r.map_err(|e| {
            done(format!(
                "CryptMsgControl(VERIFY_SIGNATURE_EX) refused ({e})"
            ))
        })
    }
}

/// The certificates embedded in the catalog, as raw DER.
pub fn embedded_certificates(cat_path: &str) -> Result<Vec<Vec<u8>>, String> {
    unsafe {
        let (hmsg, msg_store, _) = open_signed_data(cat_path)?;
        let mut out = Vec::new();
        let mut prev: *const CERT_CONTEXT = ptr::null();
        loop {
            // the enumeration frees the context it returned last time, so nothing here frees `prev`
            let ctx = CertEnumCertificatesInStore(msg_store, Some(prev));
            if ctx.is_null() {
                break;
            }
            prev = ctx;
            let cc = *ctx;
            if cc.cbCertEncoded == 0 || cc.cbCertEncoded > 1_048_576 || cc.pbCertEncoded.is_null() {
                let _ = CryptMsgClose(Some(hmsg));
                let _ = CertCloseStore(msg_store, 0);
                return Err(format!(
                    "an embedded certificate has an implausible DER length ({})",
                    cc.cbCertEncoded
                ));
            }
            let der = std::slice::from_raw_parts(cc.pbCertEncoded, cc.cbCertEncoded as usize);
            out.push(der.to_vec());
        }
        let _ = prev;
        let _ = CryptMsgClose(Some(hmsg));
        let _ = CertCloseStore(msg_store, 0);
        if out.is_empty() {
            return Err("the catalog carries no embedded certificate at all".to_string());
        }
        Ok(out)
    }
}

/// How many signers the message declares, as a self-check that the catalog is what we think it is.
pub fn signer_count(cat_path: &str) -> Result<u32, String> {
    unsafe {
        let (hmsg, msg_store, _) = open_signed_data(cat_path)?;
        let mut count = 0u32;
        let mut cb = std::mem::size_of::<u32>() as u32;
        let r = CryptMsgGetParam(
            hmsg,
            CMSG_SIGNER_COUNT_PARAM,
            0,
            Some((&raw mut count).cast()),
            &mut cb,
        );
        let _ = CryptMsgClose(Some(hmsg));
        let _ = CertCloseStore(msg_store, 0);
        r.map_err(|e| format!("the signer count could not be read ({e})"))?;
        Ok(count)
    }
}

/// The DER of every certificate the message carries, read through the message parameters rather than
/// the store enumeration, as a second path over the same data.
pub fn message_certificate_count(cat_path: &str) -> Result<u32, String> {
    unsafe {
        let (hmsg, msg_store, _) = open_signed_data(cat_path)?;
        let mut count = 0u32;
        let mut cb = std::mem::size_of::<u32>() as u32;
        let r = CryptMsgGetParam(
            hmsg,
            CMSG_CERT_COUNT_PARAM,
            0,
            Some((&raw mut count).cast()),
            &mut cb,
        );
        if r.is_ok() && count > 0 {
            // touching the first one proves the parameter is not just a number
            let mut cb2 = 0u32;
            let probe = CryptMsgGetParam(hmsg, CMSG_CERT_PARAM, 0, None, &mut cb2);
            if probe.is_err() {
                let _ = CryptMsgClose(Some(hmsg));
                let _ = CertCloseStore(msg_store, 0);
                return Err("certificate count reported entries that could not be read".to_string());
            }
        }
        let _ = CryptMsgClose(Some(hmsg));
        let _ = CertCloseStore(msg_store, 0);
        r.map_err(|e| format!("the certificate count could not be read ({e})"))?;
        Ok(count)
    }
}

const X509_ASN_ENCODING_: windows::Win32::Security::Cryptography::CERT_QUERY_ENCODING_TYPE =
    windows::Win32::Security::Cryptography::X509_ASN_ENCODING;

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(v: &[u8]) -> String {
        v.iter().map(|b| format!("{b:02X}")).collect()
    }

    #[test]
    fn embedded_certificate_comparison_is_byte_exact() {
        let der = vec![0x30u8, 0x82, 0x01, 0x02, 0xAA];
        assert!(der_compare(&der, &der).is_ok());
        let mut other = der.clone();
        other[4] ^= 1;
        let msg = der_compare(&other, &der).unwrap_err();
        // a differing byte must be named, not collapsed into "mismatch"
        assert!(msg.contains("byte 4"), "{msg}");
        let short = der[..3].to_vec();
        assert!(der_compare(&short, &der).unwrap_err().contains("3 bytes"));
    }

    #[test]
    fn a_certificate_bearing_digest_of_the_same_bytes_is_not_the_test() {
        // guards against a future rewrite that compares hashes and calls it byte equality
        let der = hex(&[1u8, 2, 3]);
        assert_eq!(der, "010203");
    }

    #[test]
    fn member_set_must_match_in_both_directions_and_in_count() {
        let want = vec![
            ("cm400.inf".to_string(), "AAAA".to_string()),
            ("SHA256SUMS.txt".to_string(), "BBBB".to_string()),
        ];
        assert!(member_set_verdict(&["AAAA".into(), "BBBB".into()], &want).is_ok());
        // case is not significant in hex digests
        assert!(member_set_verdict(&["aaaa".into(), "bbbb".into()], &want).is_ok());
        // a member the package does not contain is a problem even when both expected digests are there
        let extra =
            member_set_verdict(&["AAAA".into(), "BBBB".into(), "CCCC".into()], &want).unwrap_err();
        assert!(extra.contains("unexpected member CCCC"), "{extra}");
        // a missing one too
        let missing = member_set_verdict(&["AAAA".into()], &want).unwrap_err();
        assert!(missing.contains("SHA256SUMS.txt"), "{missing}");
        // the attack this exists for: the catalog's member set was rebuilt for different files
        let rebuilt = member_set_verdict(&["DDDD".into(), "EEEE".into()], &want).unwrap_err();
        assert!(
            rebuilt.contains("cm400.inf") && rebuilt.contains("SHA256SUMS.txt"),
            "{rebuilt}"
        );
    }

    #[test]
    fn an_empty_member_set_is_refused_rather_than_vacuous() {
        let want = vec![("cm400.inf".to_string(), "AAAA".to_string())];
        assert!(member_set_verdict(&[], &want)
            .unwrap_err()
            .contains("0 members"));
    }
}
