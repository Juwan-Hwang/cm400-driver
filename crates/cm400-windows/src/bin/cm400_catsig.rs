//! Candidate catalog verifier: the pre-execution gate for a release package.
//!
//! This binary is deliberately **not** one of the nine shipped files. The point of the check is that
//! the thing doing the checking is not the thing being checked, so the acceptance job builds it from
//! the repository it already trusts rather than running anything out of the downloaded package.
//!
//!     cm400-catsig verify   --cat <package\cm400.cat> --cer <pinned.cer> [--bind name=file]...
//!     cm400-catsig negative --cat <package\cm400.cat> --der <other.cer>
//!
//! `verify` passes only when all three independent legs pass:
//!   signature   the catalog's signature verifies against the pinned certificate itself, so the result
//!               does not depend on whether this machine trusts the publisher's chain;
//!   identity    the certificate *embedded in the catalog* is byte-for-byte the pinned certificate
//!               (the message's certificate set is not covered by the signed digest, so this leg has to
//!               read the embedded copy rather than trust what the verification call hands back);
//!   binding     each declared member identifier equals the catalog digest of the corresponding file on
//!               disk, and the identifier set is exactly the expected set.
//!
//! `negative` is its mirror: it asserts that verifying the same signature against a certificate that is
//! not ours is refused. A differential that does not refuse is the more dangerous outcome, so it exits
//! with its own code.
//!
//! Exit codes: 0 accepted (for `negative`: the foreign key was refused at the signature check itself),
//! 2 refused, 3 usage or unreadable input, 4 the negative control wrongly accepted a foreign key,
//! 5 the negative control never reached the signature check and therefore proves nothing.

use std::path::PathBuf;

const ACCEPT: i32 = 0;
const REFUSE: i32 = 2;
const BAD_ARGS: i32 = 3;
const NEGATIVE_FAILED: i32 = 4;
const NEGATIVE_INCONCLUSIVE: i32 = 5;

#[derive(Default)]
struct Opt {
    mode: String,
    cat: Option<String>,
    cert: Option<String>,
    bind: Vec<(String, String)>,
}

fn parse(args: &[String]) -> Result<Opt, String> {
    let mut o = Opt::default();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let take = |i: &mut usize| -> Result<String, String> {
            *i += 1;
            args.get(*i)
                .cloned()
                .ok_or_else(|| format!("{a} needs a value"))
        };
        match a {
            "verify" | "negative" => o.mode = a.to_string(),
            "--cat" => o.cat = Some(take(&mut i)?),
            "--cer" | "--der" => o.cert = Some(take(&mut i)?),
            "--bind" => {
                let spec = take(&mut i)?;
                let (name, path) = spec
                    .split_once('=')
                    .ok_or_else(|| format!("--bind expects name=path, got {spec}"))?;
                o.bind.push((name.to_string(), path.to_string()));
            }
            other => return Err(format!("unrecognised argument {other}")),
        }
        i += 1;
    }
    if o.mode.is_empty() {
        return Err("mode `verify` or `negative` is required".to_string());
    }
    let cat = o
        .cat
        .clone()
        .ok_or_else(|| "--cat is required".to_string())?;
    PathBuf::from(&cat)
        .exists()
        .then_some(())
        .ok_or_else(|| format!("catalog not found: {cat}"))?;
    if o.cert.is_none() {
        return Err("--cer/--der is required".to_string());
    }
    if o.mode == "verify" && o.bind.is_empty() {
        return Err("verify needs at least one --bind name=path".to_string());
    }
    Ok(o)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let opt = match parse(&args[1..]) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("usage error: {e}");
            std::process::exit(BAD_ARGS);
        }
    };
    let cat = opt.cat.clone().unwrap_or_default();
    let cert = opt.cert.clone().unwrap_or_default();
    let pinned_der = match std::fs::read(&cert) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("cannot read {cert}: {e}");
            std::process::exit(BAD_ARGS);
        }
    };

    if pinned_der.len() < 100 {
        eprintln!("{cert} is too short to be a certificate");
        std::process::exit(BAD_ARGS);
    }
    if pinned_der[0] != 0x30 {
        eprintln!("{cert} does not start with an ASN.1 SEQUENCE, so it is not a DER certificate");
        std::process::exit(BAD_ARGS);
    }

    #[cfg(target_os = "windows")]
    {
        use cm400_windows::{catalog_trust, native_trust};

        if opt.mode == "negative" {
            match catalog_trust::verify_signature_against_key(&cat, &pinned_der) {
                Ok(()) => {
                    println!("VERDICT negative-control=WRONGLY-ACCEPTED");
                    println!(
                        "  a signature verified against a certificate that is not the publisher's"
                    );
                    std::process::exit(NEGATIVE_FAILED);
                }
                Err(e) => {
                    // "could not get as far as the signature check" is not a cryptographic refusal, and
                    // reporting it as one would let an unparseable message look like a passed negative
                    // test. Only a refusal raised by the verification control itself counts.
                    if e.contains("VERIFY_SIGNATURE_EX") {
                        println!("VERDICT negative-control=REFUSED");
                        println!("  refused at the signature check, as required: {e}");
                        std::process::exit(ACCEPT);
                    }
                    println!("VERDICT negative-control=INCONCLUSIVE");
                    println!("  the foreign-key test never reached the signature check: {e}");
                    std::process::exit(NEGATIVE_INCONCLUSIVE);
                }
            }
        }

        // leg 1: signature, verified with the pinned certificate rather than with whatever the machine
        // happens to trust
        let signature = catalog_trust::verify_with_pinned_certificate(&cat, &pinned_der);
        let signers = catalog_trust::signer_count(&cat);
        // leg 2: identity, against the certificate embedded in the catalog
        let identity = catalog_trust::embedded_certificates(&cat).and_then(|certs| {
            let matches: Vec<usize> = certs
                .iter()
                .enumerate()
                .filter(|(_, der)| catalog_trust::der_compare(der, &pinned_der).is_ok())
                .map(|(i, _)| i)
                .collect();
            if certs.len() != 1 {
                return Err(format!(
                    "the catalog embeds {} certificates; exactly one is expected",
                    certs.len()
                ));
            }
            if matches.len() != 1 {
                let detail = catalog_trust::der_compare(&certs[0], &pinned_der)
                    .err()
                    .unwrap_or_else(|| "no single embedded certificate matched".to_string());
                return Err(format!(
                    "the embedded certificate is not the pinned one: {detail}"
                ));
            }
            Ok(())
        });
        // leg 3: content binding, digest recomputed from the files on disk
        let declared = native_trust::catalog_member_ids(&cat);
        let binding = || -> Result<(), String> {
            let declared = declared.clone()?;
            let mut expected = Vec::new();
            for (name, path) in &opt.bind {
                let digest = native_trust::file_catalog_digest(path)?;
                expected.push((name.clone(), digest));
            }
            catalog_trust::member_set_verdict(&declared, &expected)
        };
        let binding = binding();

        let line = |label: &str, r: &Result<(), String>| match r {
            Ok(()) => format!("OK   {label}"),
            Err(e) => format!("FAIL {label}: {e}"),
        };
        println!("{}", line("signature", &signature));
        println!(
            "{}",
            match &signers {
                Ok(n) => format!("INFO signers={n}"),
                Err(e) => format!("FAIL signer-count: {e}"),
            }
        );
        println!("{}", line("embedded-identity", &identity));
        println!("{}", line("content-binding", &binding));
        println!(
            "{}",
            match &declared {
                Ok(ids) => format!("INFO declared-members={}", ids.len()),
                Err(e) => format!("FAIL member-enumeration: {e}"),
            }
        );

        let ok = signature.is_ok() && identity.is_ok() && binding.is_ok() && signers.is_ok();
        println!("VERDICT {}", if ok { "ACCEPTED" } else { "REFUSED" });
        std::process::exit(if ok { ACCEPT } else { REFUSE });
    }

    #[cfg(not(target_os = "windows"))]
    {
        eprintln!("catalog verification requires Windows");
        std::process::exit(REFUSE);
    }
}
