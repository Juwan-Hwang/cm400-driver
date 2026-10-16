//! Developer and packaging tool for the single-file installer bundle: append a bundle to a host
//! executable, inspect what a host carries, or extract it again. It is deliberately NOT part of a
//! release package - the same rule that keeps `cm400-catsig` out of the shipped artifacts.
//!
//! Ordering it exists to enforce: pack, then sign. Signing last means the appended bundle sits before
//! the certificate table, which is the layout the reader locates by parsing that table.

use cm400_windows::bundle::{self, Bundle};
use std::fs;
use std::path::PathBuf;

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let code = match run(&argv) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("cm400-bundle: {e}");
            1
        }
    };
    std::process::exit(code);
}

fn usage() -> String {
    "usage:\n  \
     cm400-bundle pack --host <exe> --out <exe> --files <path> [<path>...]\n  \
     cm400-bundle list <exe>\n  \
     cm400-bundle extract <exe> --to <dir>"
        .to_string()
}

fn run(argv: &[String]) -> Result<(), String> {
    let Some(cmd) = argv.get(1) else {
        return Err(usage());
    };
    match cmd.as_str() {
        "pack" => {
            let host = flag(&argv[2..], "--host")?;
            let out = flag(&argv[2..], "--out")?;
            let files = rest_after(&argv[2..], "--files")?;
            if files.is_empty() {
                return Err("pack needs at least one file".to_string());
            }
            let bundle = bundle::pack(&files)?;
            let mut bytes = fs::read(&host).map_err(|e| format!("cannot read host: {e}"))?;
            bytes.extend_from_slice(&bundle);
            fs::write(&out, &bytes).map_err(|e| format!("cannot write {out:?}: {e}"))?;
            let parsed = Bundle::read(&out)?;
            println!(
                "packed {} entries, {} bundle bytes -> {}",
                parsed.entries().len(),
                bundle.len(),
                out.display()
            );
            for e in parsed.entries() {
                println!("  {:<22} {:>9}B  {}", e.name, e.length, e.sha256);
            }
            Ok(())
        }
        "list" => {
            let path = positional(&argv[2..])?;
            let len = fs::metadata(&path)
                .map_err(|e| format!("cannot stat: {e}"))?
                .len();
            let (append_end, cert) = bundle::appendable_end(&path, len)?;
            match cert {
                Some((off, size)) => println!(
                    "host is SIGNED: certificate table at {off} + {size} bytes; appendable region ends at {append_end}"
                ),
                None => println!("host is unsigned: appendable region ends at {append_end} (file size {len})"),
            }
            let parsed = Bundle::read(&path)?;
            println!("{} entries:", parsed.entries().len());
            for e in parsed.entries() {
                println!("  {:<22} {:>9}B  {}", e.name, e.length, e.sha256);
            }
            Ok(())
        }
        "extract" => {
            let path = positional(&argv[2..])?;
            let dir = flag(&argv[2..], "--to")?;
            fs::create_dir_all(&dir).map_err(|e| format!("cannot create target: {e}"))?;
            let parsed = Bundle::read(&path)?;
            let files = parsed.extract_all(&path, &dir)?;
            println!("extracted {} file(s) to {}", files.len(), dir.display());
            for f in files {
                println!("  {}", f.display());
            }
            Ok(())
        }
        "--help" | "-h" => {
            println!("{}", usage());
            Ok(())
        }
        other => Err(format!("unknown command {other:?}\n{}", usage())),
    }
}

fn flag(argv: &[String], name: &str) -> Result<PathBuf, String> {
    let i = argv
        .iter()
        .position(|a| a == name)
        .ok_or_else(|| format!("missing {name}"))?;
    let v = argv
        .get(i + 1)
        .ok_or_else(|| format!("{name} needs a value"))?;
    Ok(PathBuf::from(v))
}

fn rest_after(argv: &[String], name: &str) -> Result<Vec<PathBuf>, String> {
    let i = argv
        .iter()
        .position(|a| a == name)
        .ok_or_else(|| format!("missing {name}"))?;
    Ok(argv[i + 1..].iter().map(PathBuf::from).collect())
}

fn positional(argv: &[String]) -> Result<PathBuf, String> {
    argv.iter()
        .find(|a| !a.starts_with('-'))
        .map(PathBuf::from)
        .ok_or_else(|| "expected a path argument".to_string())
}
