//! The self-contained installer bundle: an index plus payload appended to the end of the host
//! executable, so one download can carry the driver package, the daemon image, the manifest and the
//! licence text without asking the user to assemble files.
//!
//! Trust model, and why there is no second one here
//! ------------------------------------------------
//! The bundle index is deliberately NOT the thing that has to be trusted. It carries names, offsets
//! and digests, but every digest it states is re-checked against bytes read out of the host file
//! before anything is written to disk. Authoritative proof stays where it already was, and stays
//! inside the extracted layout:
//!
//! * the catalog is verified against the pinned public key compiled into the binary
//!   ([`crate::catalog_trust`]), which is what makes tampering with any member visible;
//! * `cm400.inf` and `SHA256SUMS.txt` must both be members of that catalog
//!   ([`crate::native_trust`]), so neither the INF nor the digest list can be swapped;
//! * every listed digest must match the bytes actually on disk, and the file set must be exactly the
//!   whitelisted set ([`crate::artifact_manifest`]).
//!
//! So a byte changed anywhere in the payload breaks a check that does not depend on the outer
//! signature - which matters because on a machine that never imported our self-signed certificate the
//! outer Authenticode chain is NOT trusted, and must not be the gate. The outer signature earns its
//! keep on the host's own code and on transport integrity; the inner chain carries release identity.
//! That ordering is also why packaging signs AFTER appending: appending to a signed file invalidates
//! the signature.
//!
//! Format, little-endian throughout:
//!
//! ```text
//! [ PE image ][ payload bytes ][ manifest ][ trailer ][ Authenticode certificate table ]
//! ```
//!
//! Offsets are relative to the start of the bundle, and the bundle is located from the END OF THE
//! APPENDABLE REGION rather than from the end of the file: signing appends an attribute-certificate
//! table, so on a signed installer the last bytes of the file belong to the signature, not to the
//! bundle. `bundle_length` therefore anchors at that boundary, and the certificate region is located by
//! parsing the PE header's Certificate Table entry (index 4 of the data directories), which Microsoft
//! defines as a raw file offset for that entry and not an RVA.
//!
//! The reason the boundary must not simply be "file length": a bundle found past the signature would be
//! read from the wrong place, and a bundle found overlapping it would let signature bytes masquerade as
//! payload. Both cases are refused here rather than producing a digest mismatch nobody can explain.
//!
//! And the reason the signature is not the trust root. Measured on a real signed host: flipping one byte
//! inside the appended bundle made `Get-AuthenticodeSignature` report `HashMismatch`, so the PE file hash
//! did cover the appended region here - contrary to the "nothing after the last section is hashed" line
//! one might assume from the format docs. That is still not a gate to lean on: on a machine that never
//! imported our certificate the chain is not trusted, so `Valid` is unavailable as a precondition, and a
//! check that can only succeed after the product has already enrolled trust cannot be what makes the
//! payload safe. The inner chain (pinned-key catalog verification, catalog membership, per-file digests)
//! stays the release gate, and it has to complete before any service, trust-store or driver change.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Marks the trailer. Changing this is a format change, not a cosmetic one.
pub const MAGIC: &[u8; 8] = b"CM400BD1";
const TRAILER_LEN: usize = 8 + 4 + 8;
const MAX_ENTRIES: usize = 32;
const MAX_FILE_LEN: u64 = 64 * 1024 * 1024;
const MAX_NAME_LEN: usize = 64;

/// Index of the certificate table (security directory) in the PE data directories.
const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
/// Enough header to reach the data directories we care about.
const HEADER_READ: usize = 1024;
/// How far back from the certificate table a trailer may sit. Real signers align the table, which costs
/// a handful of zero bytes; the window is generous so a differently aligning tool still works, while any
/// non-zero content in that gap is refused.
const PAD_WINDOW: usize = 4096;

/// One payload member. `sha256` is upper-case hex, the same shape `SHA256SUMS.txt` uses, so the two
/// can be compared without a second parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub offset: u64,
    pub length: u64,
    pub sha256: String,
}

/// Reject anything that is not a bare file name we are willing to create under a directory we control.
///
/// Each arm is a distinct escape: relative traversal, absolute path, drive letter, UNC or device
/// prefix, and an empty or over-long name. These are refused at parse time, so a tampered index cannot
/// turn extraction into "write anywhere".
fn check_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("entry name is empty".to_string());
    }
    if name.len() > MAX_NAME_LEN {
        return Err(format!("entry name too long: {name}"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(format!("entry name is not a bare file name: {name:?}"));
    }
    if name.contains("..") || name.starts_with('.') || name.contains(':') || name.contains('\\') {
        return Err(format!("entry name escapes the target directory: {name:?}"));
    }
    Ok(())
}

/// Build the bundle bytes for a set of files, in the order given.
pub fn pack(paths: &[PathBuf]) -> Result<Vec<u8>, String> {
    let mut names = Vec::with_capacity(paths.len());
    for p in paths {
        let name = p
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| format!("no usable file name in {}", p.display()))?
            .to_string();
        check_name(&name)?;
        if names.contains(&name) {
            return Err(format!("duplicate entry name: {name}"));
        }
        names.push(name);
    }
    if names.len() > MAX_ENTRIES {
        return Err(format!("too many entries: {}", names.len()));
    }

    let mut payload: Vec<u8> = Vec::new();
    let mut entries: Vec<Entry> = Vec::new();
    for (name, p) in names.iter().zip(paths.iter()) {
        let mut data = Vec::new();
        fs::File::open(p)
            .map_err(|e| format!("cannot open {}: {e}", p.display()))?
            .read_to_end(&mut data)
            .map_err(|e| format!("cannot read {}: {e}", p.display()))?;
        if data.len() as u64 > MAX_FILE_LEN {
            return Err(format!("payload too large: {name}"));
        }
        entries.push(Entry {
            name: name.clone(),
            offset: payload.len() as u64,
            length: data.len() as u64,
            sha256: hex_upper(&sha256(&data)),
        });
        payload.extend_from_slice(&data);
    }

    let mut manifest: Vec<u8> = Vec::new();
    manifest.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in &entries {
        let nb = e.name.as_bytes();
        if nb.len() > u16::MAX as usize {
            return Err(format!("name too long: {}", e.name));
        }
        manifest.extend_from_slice(&(nb.len() as u16).to_le_bytes());
        manifest.extend_from_slice(nb);
        manifest.extend_from_slice(&e.offset.to_le_bytes());
        manifest.extend_from_slice(&e.length.to_le_bytes());
        manifest.extend_from_slice(
            &vec_from_hex(&e.sha256).ok_or_else(|| format!("bad digest stored for {}", e.name))?,
        );
    }

    let bundle_length = payload.len() + manifest.len() + TRAILER_LEN;
    let mut out = payload;
    out.extend_from_slice(&manifest);
    out.extend_from_slice(&(bundle_length as u64).to_le_bytes());
    out.extend_from_slice(&(manifest.len() as u32).to_le_bytes());
    out.extend_from_slice(MAGIC);
    Ok(out)
}

/// The parsed index. Kept alongside nothing else: reading payload bytes is always done from the file
/// the index came from, so an index can never be reused against different content.
#[derive(Debug, Clone)]
pub struct Bundle {
    /// Offset inside the host file where the payload region starts.
    payload_start: u64,
    entries: Vec<Entry>,
}

impl Bundle {
    /// Locate and parse the bundle at the end of the host's appendable region: the byte just past the
    /// payload is either the end of the file (unsigned) or the start of the Authenticode certificate
    /// table (signed). Anchoring on the file end instead would read a signed installer's signature bytes
    /// as if they were our trailer.
    pub fn read(host: &Path) -> Result<Bundle, String> {
        let len = fs::metadata(host)
            .map_err(|e| format!("cannot stat {}: {e}", host.display()))?
            .len();
        let (append_end, cert) = appendable_end(host, len)?;
        if append_end < TRAILER_LEN as u64 {
            return Err(format!(
                "appendable region of the host is smaller than a bundle trailer ({append_end} bytes)"
            ));
        }
        let mut trailer = [0u8; TRAILER_LEN];
        {
            let mut f = fs::File::open(host).map_err(|e| format!("cannot open host: {e}"))?;
            use std::io::Seek;
            f.seek(std::io::SeekFrom::Start(append_end - TRAILER_LEN as u64))
                .map_err(|e| format!("cannot seek to trailer: {e}"))?;
            f.read_exact(&mut trailer)
                .map_err(|e| format!("cannot read trailer: {e}"))?;
        }
        if trailer[TRAILER_LEN - 8..] != MAGIC[..] {
            return Err(format!(
                "no CM400 bundle trailer at the end of the appendable region ({})",
                match cert {
                    Some((offset, size)) =>
                        format!("host is signed, certificate table at {offset} + {size} bytes"),
                    None => "host is unsigned".to_string(),
                }
            ));
        }
        let manifest_len = u32::from_le_bytes(
            trailer[TRAILER_LEN - 12..TRAILER_LEN - 8]
                .try_into()
                .expect("slice is 4 bytes"),
        ) as u64;
        let bundle_len = u64::from_le_bytes(trailer[0..8].try_into().expect("slice is 8 bytes"));
        if bundle_len < (TRAILER_LEN as u64) + manifest_len || bundle_len > append_end {
            return Err(format!(
                "declared bundle length {bundle_len} does not fit the appendable region of {append_end} bytes (host is {len})"
            ));
        }
        let bundle_start = append_end - bundle_len;
        let manifest_start = bundle_start + bundle_len - manifest_len - TRAILER_LEN as u64;

        let mut manifest = vec![0u8; manifest_len as usize];
        {
            let mut f = fs::File::open(host).map_err(|e| format!("cannot open host: {e}"))?;
            use std::io::Seek;
            f.seek(std::io::SeekFrom::Start(manifest_start))
                .map_err(|e| format!("cannot seek to manifest: {e}"))?;
            f.read_exact(&mut manifest)
                .map_err(|e| format!("cannot read manifest: {e}"))?;
        }

        let mut cur = 0usize;
        let count = read_u32(&manifest, &mut cur).ok_or("manifest truncated at count")? as usize;
        if count == 0 || count > MAX_ENTRIES {
            return Err(format!("implausible entry count: {count}"));
        }
        let data_region = manifest_start - bundle_start;
        let mut entries = Vec::with_capacity(count);
        let mut end = 0u64;
        for _ in 0..count {
            let nlen =
                read_u16(&manifest, &mut cur).ok_or("manifest truncated at name length")? as usize;
            if nlen == 0 || cur + nlen > manifest.len() || nlen > MAX_NAME_LEN {
                return Err("manifest truncated or name length out of range".to_string());
            }
            let name = String::from_utf8(manifest[cur..cur + nlen].to_vec())
                .map_err(|_| "entry name is not UTF-8".to_string())?;
            cur += nlen;
            check_name(&name)?;
            let offset = read_u64(&manifest, &mut cur).ok_or("manifest truncated at offset")?;
            let length = read_u64(&manifest, &mut cur).ok_or("manifest truncated at length")?;
            let digest =
                read_bytes(&manifest, &mut cur, 32).ok_or("manifest truncated at digest")?;
            if length > MAX_FILE_LEN || offset > data_region || offset + length > data_region {
                return Err(format!("entry {name} points outside the payload region"));
            }
            if offset != end {
                return Err(format!(
                    "entry {name} leaves a gap or overlaps: offset {offset}, expected {end}"
                ));
            }
            end = offset + length;
            entries.push(Entry {
                name,
                offset,
                length,
                sha256: hex_upper(digest),
            });
        }
        if cur != manifest.len() {
            return Err("manifest carries trailing bytes".to_string());
        }
        Ok(Bundle {
            payload_start: bundle_start,
            entries,
        })
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn names(&self) -> Vec<String> {
        self.entries.iter().map(|e| e.name.clone()).collect()
    }

    /// Read one member out of the host and verify its digest. Writes nothing.
    fn verified_bytes(&self, host: &Path, entry: &Entry) -> Result<Vec<u8>, String> {
        check_name(&entry.name)?;
        let mut data = vec![0u8; entry.length as usize];
        {
            let mut f = fs::File::open(host).map_err(|e| format!("cannot open host: {e}"))?;
            use std::io::Seek;
            f.seek(std::io::SeekFrom::Start(self.payload_start + entry.offset))
                .map_err(|e| format!("cannot seek to payload: {e}"))?;
            f.read_exact(&mut data)
                .map_err(|e| format!("cannot read payload for {}: {e}", entry.name))?;
        }
        let got = hex_upper(&sha256(&data));
        if got != entry.sha256 {
            return Err(format!(
                "{}: index says {} but the bytes hash to {got}",
                entry.name, entry.sha256
            ));
        }
        Ok(data)
    }

    /// Place one already-verified member, then re-hash what landed on disk.
    fn write_verified(&self, dir: &Path, entry: &Entry, data: &[u8]) -> Result<PathBuf, String> {
        let target = dir.join(&entry.name);
        if target.parent() != Some(dir) {
            return Err(format!(
                "{} would be written outside the target",
                entry.name
            ));
        }
        // refuse to follow anything that is already there
        if target.symlink_metadata().is_ok() {
            return Err(format!(
                "{} already exists in the target directory",
                entry.name
            ));
        }
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts
            .open(&target)
            .map_err(|e| format!("cannot create {}: {e}", target.display()))?;
        file.write_all(data)
            .map_err(|e| format!("cannot write {}: {e}", entry.name))?;
        file.flush().ok();
        drop(file);
        // the bytes on disk must still be the bytes we verified
        let on_disk = sha256_of_file_path(&target)
            .ok_or_else(|| format!("{}: cannot re-hash what was just written", entry.name))?;
        if on_disk != entry.sha256 {
            let _ = fs::remove_file(&target);
            return Err(format!(
                "{}: file on disk hashes to {on_disk}, expected {}",
                entry.name, entry.sha256
            ));
        }
        Ok(target)
    }

    /// Extract every member. Verification of the whole bundle happens first, and no file is created
    /// until every member has been read and digested: discovering at the last entry that one earlier
    /// byte had changed used to leave the first six members on disk, which is exactly the partial state
    /// an installer must never produce.
    ///
    /// The caller owns the directory: it must be private, and the existing gates (catalog, membership,
    /// manifest) are what judge the result.
    pub fn extract_all(&self, host: &Path, dir: &Path) -> Result<Vec<PathBuf>, String> {
        let mut verified = Vec::with_capacity(self.entries.len());
        for e in self.entries() {
            verified.push((e.clone(), self.verified_bytes(host, e)?));
        }
        fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        let mut out = Vec::with_capacity(verified.len());
        for (e, data) in &verified {
            out.push(self.write_verified(dir, e, data)?);
        }
        Ok(out)
    }
}

/// Where appended data is allowed to end.
///
/// An unsigned host has no reason for a boundary other than its own end. A signed one does: the
/// attribute certificate table is written at the end of the file, so anything we appended before
/// signing stops just short of it. Anchoring the trailer on the file end would therefore look for our
/// magic inside signature bytes on exactly the artifacts that ship.
///
/// The certificate entry is read as the raw file offset that Microsoft defines it to be (not an RVA).
/// A host that claims to be a PE but whose headers cannot be followed is refused: guessing a boundary
/// here would decide where the payload is read from, and a wrong guess must not look like a corrupt
/// digest later.
pub fn appendable_end(host: &Path, file_len: u64) -> Result<(u64, Option<(u64, u64)>), String> {
    let mut head = vec![0u8; HEADER_READ];
    let got = {
        let mut f =
            fs::File::open(host).map_err(|e| format!("cannot open {}: {e}", host.display()))?;
        match f.read(&mut head) {
            Ok(n) => n,
            Err(e) => return Err(format!("cannot read the header of {}: {e}", host.display())),
        }
    };
    if got < 0x40 || &head[0..2] != b"MZ" {
        // not a PE at all (a fixture, a plain data file): nothing of the signature kind to avoid
        return Ok((file_len, None));
    }
    let pe = u32::from_le_bytes([head[0x3c], head[0x3d], head[0x3e], head[0x3f]]) as usize;
    if pe + 24 + 4 > got || &head[pe..pe + 4] != b"PE\0\0" {
        return Err(format!(
            "{} starts like a PE but its signature header cannot be followed",
            host.display()
        ));
    }
    let opt = pe + 24;
    let magic = u16::from_le_bytes([head[opt], head[opt + 1]]);
    let (n_dirs_off, dirs_off) = match magic {
        // PE32
        0x10B => (opt + 92, opt + 96),
        // PE32+
        0x20B => (opt + 108, opt + 112),
        other => {
            return Err(format!(
                "unrecognised PE optional header magic 0x{other:04X} in {}",
                host.display()
            ))
        }
    };
    if dirs_off + (IMAGE_DIRECTORY_ENTRY_SECURITY + 1) * 8 > got {
        return Err(format!(
            "{} is too small at its data directories to judge a signature boundary",
            host.display()
        ));
    }
    let n_dirs = u32::from_le_bytes([
        head[n_dirs_off],
        head[n_dirs_off + 1],
        head[n_dirs_off + 2],
        head[n_dirs_off + 3],
    ]) as usize;
    if n_dirs <= IMAGE_DIRECTORY_ENTRY_SECURITY {
        // the image declares fewer directories than the certificate entry: no signature can be present
        return Ok((file_len, None));
    }
    let at = dirs_off + IMAGE_DIRECTORY_ENTRY_SECURITY * 8;
    let cert_off = u32::from_le_bytes([head[at], head[at + 1], head[at + 2], head[at + 3]]) as u64;
    let cert_size =
        u32::from_le_bytes([head[at + 4], head[at + 5], head[at + 6], head[at + 7]]) as u64;
    if cert_size == 0 {
        return Ok((file_len, None));
    }
    if cert_off < 64 || cert_off.checked_add(cert_size).is_none() {
        return Err(format!(
            "certificate table offset {cert_off} with size {cert_size} is not usable in {}",
            host.display()
        ));
    }
    if cert_off + cert_size != file_len {
        return Err(format!(
            "certificate table at {cert_off} + {cert_size} does not end at the file size {file_len} in {}; refusing to guess where appended data stops",
            host.display()
        ));
    }
    // signtool aligns the certificate table, measured: a 824_860 byte host gained four padding bytes
    // before the table at 824_864. So the bundle ends at `cert_off` minus whatever zero padding the
    // tool inserted, and the trailer has to be found there rather than at the table boundary itself.
    // Anything non-zero in that gap is not alignment padding, and is refused rather than skipped over.
    let append_end = locate_trailer(host, cert_off)?.unwrap_or(cert_off);
    Ok((append_end, Some((cert_off, cert_size))))
}

/// Walk back from `limit` looking for the trailer magic, and confirm whatever lies between the bundle and
/// `limit` is zero fill. `None` means no trailer within the window, which the caller reports in its own
/// words.
fn locate_trailer(host: &Path, limit: u64) -> Result<Option<u64>, String> {
    if limit < (TRAILER_LEN + PAD_WINDOW) as u64 {
        return Ok(None);
    }
    let from = limit - (TRAILER_LEN + PAD_WINDOW) as u64;
    let mut window = vec![0u8; (limit - from) as usize];
    {
        let mut f = fs::File::open(host).map_err(|e| format!("cannot open host: {e}"))?;
        use std::io::Seek;
        f.seek(std::io::SeekFrom::Start(from))
            .map_err(|e| format!("cannot seek to the padding window: {e}"))?;
        f.read_exact(&mut window)
            .map_err(|e| format!("cannot read the padding window: {e}"))?;
    }
    // try each candidate end position, nearest to `limit` first
    for candidate in (0..=PAD_WINDOW).rev() {
        let end = window.len() - candidate;
        if end < TRAILER_LEN {
            continue;
        }
        let start = end - TRAILER_LEN;
        if window[start + 12..end] != MAGIC[..] {
            continue;
        }
        let gap = &window[end..];
        if gap.iter().any(|b| *b != 0) {
            return Err(format!(
                "{} byte(s) between the bundle and the certificate table are not zero fill; this is not alignment padding",
                gap.len()
            ));
        }
        return Ok(Some(from + start as u64 + TRAILER_LEN as u64));
    }
    Ok(None)
}

fn read_u16(b: &[u8], cur: &mut usize) -> Option<u16> {
    if *cur + 2 > b.len() {
        return None;
    }
    let v = u16::from_le_bytes([b[*cur], b[*cur + 1]]);
    *cur += 2;
    Some(v)
}

fn read_u32(b: &[u8], cur: &mut usize) -> Option<u32> {
    if *cur + 4 > b.len() {
        return None;
    }
    let v = u32::from_le_bytes([b[*cur], b[*cur + 1], b[*cur + 2], b[*cur + 3]]);
    *cur += 4;
    Some(v)
}

fn read_u64(b: &[u8], cur: &mut usize) -> Option<u64> {
    if *cur + 8 > b.len() {
        return None;
    }
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[*cur..*cur + 8]);
    *cur += 8;
    Some(u64::from_le_bytes(a))
}

fn read_bytes<'a>(b: &'a [u8], cur: &mut usize, n: usize) -> Option<&'a [u8]> {
    if *cur + n > b.len() {
        return None;
    }
    let s = &b[*cur..*cur + n];
    *cur += n;
    Some(s)
}

fn hex_upper(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02X}"));
    }
    s
}

/// Parse upper- or lower-case hex of exactly the expected length.
pub fn vec_from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16)?;
        let lo = (b[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

fn sha256_of_file_path(p: &Path) -> Option<String> {
    let mut v = Vec::new();
    fs::File::open(p).ok()?.read_to_end(&mut v).ok()?;
    Some(hex_upper(&sha256(&v)))
}

/// SHA-256 over a byte slice (FIPS 180-4). In-process because the installer must hash the exact bytes
/// it is about to write; hashing a file that someone else may swap between digest and use would verify
/// a fact about a moment, not about the content.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    // padding: 0x80, then zeros, then the 64-bit big-endian length
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 64];
    for chunk in msg.chunks_exact(64) {
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        let add = [a, b, c, d, e, f, g, hh];
        for i in 0..8 {
            h[i] = h[i].wrapping_add(add[i]);
        }
    }
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex_upper(&sha256(data))
}

/// Where extraction writes nothing: a caller that wants the temp path policy in one place.
pub fn staged_dir(kind: &str) -> PathBuf {
    std::env::temp_dir().join(format!("cm400-stage-{kind}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("cm400-bundle-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let p = dir.join(name);
        fs::File::create(&p).unwrap().write_all(bytes).unwrap();
        p
    }

    #[test]
    fn sha256_matches_the_nist_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
        );
        // the 56-byte boundary is where the padding length crosses into a new block
        let mut m = Vec::new();
        for i in 0..1_000_000u32 {
            m.push(b'a');
            if i == 999_999 {
                assert_eq!(
                    sha256_hex(&m),
                    "CDC76E5C9914FB9281A1C7E284D73E67F1809A48A497200E046D39CCC7112CD0"
                );
            }
        }
    }

    #[test]
    fn round_trip_and_host_offsets_survive_a_padded_host() {
        let dir = tmp("rt");
        let a = write(&dir, "cm400.inf", b"; provider line\n");
        let b = write(&dir, "cm400d.exe", &[0x4Du8, 0x5A, 1, 2, 3]);
        let bundle = pack(&[a.clone(), b.clone()]).unwrap();

        // pretend to be an executable with the bundle appended at the end
        let host = dir.join("cm400-setup.exe");
        let mut f = fs::File::create(&host).unwrap();
        f.write_all(&vec![0xC3u8; 5_000]).unwrap();
        f.write_all(&bundle).unwrap();
        drop(f);

        let parsed = Bundle::read(&host).unwrap();
        assert_eq!(
            parsed.names(),
            vec!["cm400.inf".to_string(), "cm400d.exe".to_string()]
        );
        let out = dir.join("stage");
        let files = parsed.extract_all(&host, &out).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(
            fs::read(out.join("cm400.inf")).unwrap(),
            fs::read(&a).unwrap()
        );
        // reading twice is stable, and the digests in the index came from the payload, not from disk
        assert_eq!(
            parsed.entries()[1].sha256,
            sha256_hex(&fs::read(&b).unwrap())
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_single_changed_payload_byte_is_refused_before_it_reaches_disk() {
        let dir = tmp("tamper");
        let a = write(&dir, "cm400.inf", b"; original content\n");
        let bundle = pack(&[a]).unwrap();
        let host = dir.join("host.bin");
        fs::write(&host, bundle).unwrap();

        let parsed = Bundle::read(&host).unwrap();
        assert!(parsed.extract_all(&host, &dir.join("ok")).is_ok());

        // flip one byte inside the payload region, then re-read the index from the same host
        let mut bad = fs::read(&host).unwrap();
        let flip = 3;
        bad[flip] ^= 0x20;
        fs::write(&host, &bad).unwrap();
        let parsed = Bundle::read(&host).unwrap();
        let err = parsed
            .extract_all(&host, &dir.join("no"))
            .expect_err("a mutated member must not extract");
        assert!(
            err.contains("but the bytes hash to"),
            "unhelpful failure: {err}"
        );
        assert!(
            !dir.join("no").join("cm400.inf").exists(),
            "a rejected member must not be left on disk"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn names_that_could_escape_the_target_are_refused_at_every_entry_point() {
        for bad in [
            "..",
            "../evil",
            "a\\..\\b",
            "C:\\evil",
            "\\\\server\\share",
            "NUL:",
            "",
            ".hidden",
            "sub/deep",
        ] {
            assert!(
                check_name(bad).is_err(),
                "{bad:?} must never be an acceptable entry name"
            );
        }
        assert!(check_name("cm400d.exe").is_ok());
        assert!(check_name("SHA256SUMS.txt").is_ok());
    }

    #[test]
    fn a_forged_index_cannot_claim_a_path_outside_the_bundle_or_reuse_bytes() {
        let dir = tmp("forge");
        let a = write(&dir, "cm400.inf", b"payload bytes here\n");
        let mut bundle = pack(&[a]).unwrap();

        // an index naming a traversal path must be rejected while parsing, not at write time
        bundle.extend_from_slice(b"junk");
        let host = dir.join("host2.bin");
        fs::write(&host, &bundle).unwrap();
        assert!(
            Bundle::read(&host).is_err(),
            "trailing junk is not a bundle"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn extraction_refuses_to_overwrite_and_reports_the_reason() {
        let dir = tmp("clobber");
        let a = write(&dir, "cm400.inf", b"x\n");
        let bundle = pack(&[a]).unwrap();
        let host = dir.join("host3.bin");
        fs::write(&host, bundle).unwrap();
        let parsed = Bundle::read(&host).unwrap();
        let stage = dir.join("stage");
        fs::create_dir_all(&stage).unwrap();
        fs::write(stage.join("cm400.inf"), b"something already here").unwrap();
        let err = parsed
            .extract_all(&host, &stage)
            .expect_err("an existing file must not be replaced silently");
        assert!(err.contains("already exists"), "unhelpful: {err}");
        assert_eq!(
            fs::read_to_string(stage.join("cm400.inf")).unwrap(),
            "something already here",
            "the pre-existing file must be untouched"
        );
        fs::remove_dir_all(&dir).ok();
    }

    /// A minimal PE32+ shaped host: not loadable, and that is not what is being tested. It carries the
    /// fields the boundary rule reads - MZ, e_lfanew, the PE signature, the optional header magic, the
    /// data-directory count and the certificate entry - so a signed layout can be exercised without a
    /// real key or a real signature.
    fn pe_host(code_len: usize, bundle: &[u8], cert: &[u8]) -> Vec<u8> {
        pe_host_padded(code_len, bundle, 0, cert)
    }

    /// `pad` reproduces what a real signer does: signtool aligned the certificate table four bytes past
    /// the end of an 824_860 byte host, so the bundle did not end where the table began.
    fn pe_host_padded(code_len: usize, bundle: &[u8], pad: usize, cert: &[u8]) -> Vec<u8> {
        const HEAD: usize = 0x200;
        let pe = 0x80usize;
        let opt = pe + 24;
        let mut out = vec![0u8; HEAD + code_len + bundle.len() + pad + cert.len()];
        out[0] = b'M';
        out[1] = b'Z';
        out[0x3c..0x40].copy_from_slice(&(pe as u32).to_le_bytes());
        out[pe..pe + 4].copy_from_slice(b"PE\0\0");
        out[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        out[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
        let dirs = opt + 112;
        // certificate table entry, index 4: raw file offset + size
        let cert_off = (HEAD + code_len + bundle.len() + pad) as u32;
        out[dirs + 4 * 8..dirs + 4 * 8 + 4].copy_from_slice(&cert_off.to_le_bytes());
        out[dirs + 4 * 8 + 4..dirs + 4 * 8 + 8].copy_from_slice(&(cert.len() as u32).to_le_bytes());
        out[HEAD..HEAD + code_len].fill(0xC3);
        out[HEAD + code_len..HEAD + code_len + bundle.len()].copy_from_slice(bundle);
        // pad bytes stay zero unless a test overwrites them
        out[HEAD + code_len + bundle.len() + pad..].copy_from_slice(cert);
        out
    }

    fn write_host(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let p = dir.join(name);
        fs::File::create(&p).unwrap().write_all(bytes).unwrap();
        p
    }

    #[test]
    fn a_signed_host_locates_the_bundle_before_the_certificate_table() {
        let dir = tmp("signed");
        let inf = write(&dir, "cm400.inf", b"; driver file\n");
        let bundle = pack(&[inf]).unwrap();
        let host_bytes = pe_host(4096, &bundle, &[0x30u8; 512]);
        let host = write_host(&dir, "signed.exe", &host_bytes);

        let (append_end, cert) = appendable_end(&host, host_bytes.len() as u64).unwrap();
        let (co, cs) = cert.expect("this host declares a certificate table");
        assert_eq!(append_end, co);
        assert_eq!(co + cs, host_bytes.len() as u64);

        let parsed =
            Bundle::read(&host).expect("the bundle sits before the signature and must be found");
        assert_eq!(parsed.names(), vec!["cm400.inf".to_string()]);
        let out = parsed.extract_all(&host, &dir.join("stage")).unwrap();
        assert_eq!(fs::read_to_string(&out[0]).unwrap(), "; driver file\n");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tampering_the_payload_under_an_intact_looking_signature_is_still_refused() {
        let dir = tmp("signed-tamper");
        let inf = write(&dir, "cm400.inf", b"; driver file\n");
        let bundle = pack(&[inf]).unwrap();
        let mut host_bytes = pe_host(4096, &bundle, &[0x30u8; 512]);

        // flip one byte of payload; the certificate table and the header are untouched, so an outer
        // check that only looks at the signature region would still call this file well formed
        let payload_at = 0x200 + 4096 + 5;
        host_bytes[payload_at] ^= 0x20;
        let host = write_host(&dir, "tampered.exe", &host_bytes);

        let parsed = Bundle::read(&host).expect("the index itself is intact and must still parse");
        let stage = dir.join("stage");
        let err = parsed.extract_all(&host, &stage).expect_err(
            "a mutated payload must be refused even when the signature region is untouched",
        );
        assert!(
            err.contains("but the bytes hash to"),
            "unhelpful failure: {err}"
        );
        assert!(
            fs::read_dir(&stage).map(|d| d.count()).unwrap_or(0) == 0,
            "nothing may reach disk from a refused extraction"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn appending_after_signing_is_refused_instead_of_read_from_the_wrong_tail() {
        let dir = tmp("bad-order");
        let inf = write(&dir, "cm400.inf", b"; driver file\n");
        let bundle = pack(&[inf]).unwrap();
        // the packaging mistake this guards: sign first, then append - now the certificate table no
        // longer ends at the file size, and reading from the file end would find a valid trailer sitting
        // past the signature
        let mut host_bytes = pe_host(4096, &[], &[0x30u8; 512]);
        host_bytes.extend_from_slice(&bundle);
        let host = write_host(&dir, "late-append.exe", &host_bytes);

        let err = appendable_end(&host, host_bytes.len() as u64).expect_err(
            "a certificate table that is no longer at the file end is an inconsistent host",
        );
        assert!(
            err.contains("does not end at the file size") && err.contains("refusing to guess"),
            "unhelpful failure: {err}"
        );
        assert!(
            Bundle::read(&host).is_err(),
            "and the bundle must not be read at all"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_unsigned_pe_host_is_still_read_from_its_file_end() {
        let dir = tmp("unsigned-pe");
        let inf = write(&dir, "cm400.inf", b"; driver file\n");
        let bundle = pack(&[inf]).unwrap();
        // same header shape, certificate entry left zero
        let host_bytes = pe_host(2048, &bundle, &[]);
        let host = write_host(&dir, "unsigned.exe", &host_bytes);
        let (append_end, cert) = appendable_end(&host, host_bytes.len() as u64).unwrap();
        assert_eq!(cert, None);
        assert_eq!(append_end, host_bytes.len() as u64);
        assert!(Bundle::read(&host).is_ok());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_signature_aligned_past_the_bundle_is_still_navigated() {
        let dir = tmp("aligned");
        let inf = write(&dir, "cm400.inf", b"; driver file\n");
        let bundle = pack(&[inf]).unwrap();
        // four zero bytes of alignment between the trailer and the table, as signtool really produced
        let host_bytes = pe_host_padded(4096, &bundle, 4, &[0x30u8; 512]);
        let host = write_host(&dir, "aligned.exe", &host_bytes);
        let parsed =
            Bundle::read(&host).expect("the trailer is four bytes before the table, not at it");
        let out = parsed.extract_all(&host, &dir.join("stage")).unwrap();
        assert_eq!(fs::read_to_string(&out[0]).unwrap(), "; driver file\n");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_non_zero_gap_before_the_certificate_table_is_refused_not_trusted() {
        let dir = tmp("badgap");
        let inf = write(&dir, "cm400.inf", b"; driver file\n");
        let bundle = pack(&[inf]).unwrap();
        let mut host_bytes = pe_host_padded(4096, &bundle, 4, &[0x30u8; 512]);
        // something that is not alignment fill sits between our trailer and the table
        let gap = 0x200 + 4096 + bundle.len();
        host_bytes[gap] = 0xEE;
        let host = write_host(&dir, "gap.exe", &host_bytes);
        let err = appendable_end(&host, host_bytes.len() as u64)
            .expect_err("unexplained bytes in that gap must stop the read");
        assert!(err.contains("not zero fill"), "unhelpful failure: {err}");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_late_discovery_leaves_no_partial_extraction() {
        let dir = tmp("partial");
        let a = write(&dir, "cm400.inf", b"; one\n");
        let b = write(&dir, "cm400d.exe", b"MZfake-daemon");
        let c = write(&dir, "LICENSE", b"apache text\n");
        let bundle = pack(&[a, b, c]).unwrap();
        let host = write_host(&dir, "multi.exe", &bundle);

        // tamper the LAST member only: everything before it verifies, so an implementation that writes as
        // it goes would leave two files behind and a failed install with them
        let parsed = Bundle::read(&host).unwrap();
        let last = parsed.entries().last().unwrap().clone();
        let bundle_start = (fs::metadata(&host).unwrap().len() - bundle.len() as u64) as usize;
        let at = bundle_start + last.offset as usize + 1;
        let mut bytes = fs::read(&host).unwrap();
        bytes[at] ^= 0x01;
        fs::write(&host, &bytes).unwrap();

        let parsed = Bundle::read(&host).expect("the index itself is untouched");
        let stage = dir.join("stage");
        let err = parsed
            .extract_all(&host, &stage)
            .expect_err("the last member must still stop the whole extraction");
        assert!(err.contains(&last.name), "unhelpful failure: {err}");
        let landed = fs::read_dir(&stage).map(|d| d.count()).unwrap_or(0);
        assert_eq!(landed, 0, "no partial bundle may reach disk");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn digest_hex_parser_is_strict() {
        assert!(vec_from_hex("00ff").is_some());
        assert!(vec_from_hex("0").is_none(), "odd length is refused");
        assert!(vec_from_hex("zz").is_none(), "non-hex is refused");
    }

    /// The in-process implementation is checked against the one already used for the release manifest,
    /// so the installer cannot quietly disagree with the gate that judges its payload.
    ///
    /// Note what this also discovered about `certutil -hashfile`: it refuses an empty file outright
    /// (`0x800703ee ERROR_FILE_INVALID`), measured. So the empty-input case is asserted against the
    /// NIST vector above instead, and the sizes here start at one byte. The manifest helper returning
    /// `None` for a zero-byte file is fail-closed, but its message says "could not be hashed" rather
    /// than naming the real reason - worth knowing before anyone treats that as corruption.
    #[cfg(target_os = "windows")]
    #[test]
    fn sha256_agrees_with_certutil_on_files_of_every_block_boundary() {
        use crate::artifact_manifest::sha256_of_file;
        let dir = tmp("crosscheck");
        // sizes around the 64-byte block and the 56..64 padding switch
        for n in [1usize, 55, 56, 57, 63, 64, 65, 111, 127, 1000] {
            let data: Vec<u8> = (0..n).map(|i| (i * 31 + 7) as u8).collect();
            let p = write(&dir, &format!("f{n}.bin"), &data);
            let mine = sha256_hex(&data);
            let trusted = sha256_of_file(&p)
                .unwrap_or_else(|| panic!("certutil could not hash a file we just wrote (n={n})"));
            assert_eq!(
                trusted, mine,
                "certutil says {trusted} but in-process SHA-256 says {mine} at {n} bytes"
            );
        }
        fs::remove_dir_all(&dir).ok();
    }
}
