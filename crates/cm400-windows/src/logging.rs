//! Bounded retention for the service's own log file.
//!
//! The daemon writes one line per event through [`crate::log`], and on this machine the file had
//! already grown to ~8.9 MB with no limit and no rotation. Truncating at startup would throw away
//! exactly the history a long-running fault is diagnosed from, so the bound is enforced while
//! running: when the active file is about to cross the cap, the chain shifts and a fresh file is
//! started. Total footprint is capped at `LOG_MAX_BYTES * (LOG_KEEP + 1)`.
//!
//! Rotation never loses a line: the previous file is renamed, not deleted, and only the oldest
//! archived generation is dropped when the keep limit is exceeded. If renaming fails the line is
//! still appended - a log that cannot rotate must not become a log that stops recording, and must
//! certainly not take the service down with it.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Size an active log file may reach before the chain shifts.
pub const LOG_MAX_BYTES: u64 = 4 * 1024 * 1024;
/// Archived generations kept besides the active one: `name.log.1` .. `name.log.LOG_KEEP`.
pub const LOG_KEEP: usize = 3;

static ROTATION_FAILURES: AtomicU64 = AtomicU64::new(0);

/// Times a rotation was attempted and could not complete. The log keeps growing in that case -
/// visible, bounded by nothing, but never silent.
pub fn rotation_failures() -> u64 {
    ROTATION_FAILURES.load(Ordering::Relaxed)
}

fn archived(path: &Path, index: usize) -> PathBuf {
    let name = format!("{}.{}", path.display(), index);
    PathBuf::from(name)
}

/// Shift `log -> log.1 -> ... -> log.(KEEP-1)`, dropping what falls off the end. Returns the
/// number of archived generations left in place.
pub fn rotate(path: &Path) -> io::Result<usize> {
    let oldest = archived(path, LOG_KEEP);
    if fs::metadata(&oldest).is_ok() {
        fs::remove_file(&oldest)?;
    }
    for index in (1..LOG_KEEP).rev() {
        let from = archived(path, index);
        if fs::metadata(&from).is_ok() {
            fs::rename(&from, archived(path, index + 1))?;
        }
    }
    if fs::metadata(path).is_ok() {
        fs::rename(path, archived(path, 1))?;
    }
    Ok(LOG_KEEP.min(1.max(archived_count(path))))
}

/// How many archived generations currently exist.
pub fn archived_count(path: &Path) -> usize {
    (1..=LOG_KEEP)
        .filter(|i| fs::metadata(archived(path, *i)).is_ok())
        .count()
}

/// Total bytes held by the active file plus every archive.
pub fn total_bytes(path: &Path) -> u64 {
    let active = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let archives: u64 = (1..=LOG_KEEP)
        .map(|i| {
            fs::metadata(archived(path, i))
                .map(|m| m.len())
                .unwrap_or(0)
        })
        .sum();
    active + archives
}

/// Append one line, rotating first if the active file is at its cap. The caller's line is written
/// either way: this function's failures are recorded, never propagated into a decision.
pub fn append_line(path: &Path, line: &str) -> io::Result<()> {
    let over_cap = fs::metadata(path)
        .map(|m| m.len() >= LOG_MAX_BYTES)
        .unwrap_or(false);
    if over_cap {
        match rotate(path) {
            Ok(kept) => {
                let note = format!(
                    "[log] rotated at {} bytes, keeping {} archives of {}\n",
                    LOG_MAX_BYTES, kept, LOG_KEEP
                );
                return write_new(path, line, &note);
            }
            Err(e) => {
                ROTATION_FAILURES.fetch_add(1, Ordering::Relaxed);
                // Fall through and append anyway: losing the line is worse than overshooting.
                let _ = e;
            }
        }
    }
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let _ = f.write_all(line.as_bytes());
    let _ = f.write_all(b"\n");
    Ok(())
}

/// Write to the freshly rotated file: the rotation note first, then the caller's line, so the
/// reason a new file exists is recorded in the file itself.
fn write_new(path: &Path, line: &str, note: &str) -> io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let _ = f.write_all(note.as_bytes());
    let _ = f.write_all(line.as_bytes());
    let _ = f.write_all(b"\n");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!("cm400-logtest-{tag}-{nanos}"));
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn fill(path: &Path, bytes: usize) {
        fs::write(path, vec![b'x'; bytes]).unwrap();
    }

    /// A file at the cap is archived rather than truncated, and the new file carries both the
    /// rotation note and the line that triggered it.
    #[test]
    fn rotates_at_the_cap_without_losing_history() {
        let dir = sandbox("rotate");
        let log = dir.join("cm400d.log");
        fill(&log, LOG_MAX_BYTES as usize);

        append_line(&log, "second").unwrap();

        let archive = archived(&log, 1);
        assert!(fs::metadata(&archive).is_ok(), "the old file must be kept");
        assert_eq!(fs::read(&archive).unwrap().len(), LOG_MAX_BYTES as usize);
        let fresh = fs::read_to_string(&log).unwrap();
        assert!(
            fresh.contains("rotated"),
            "the new file says why it exists: {fresh}"
        );
        assert!(
            fresh.contains("second"),
            "the triggering line is not dropped"
        );
        assert!(
            (fs::metadata(&log).unwrap().len()) < LOG_MAX_BYTES,
            "the active file starts over"
        );
        fs::remove_dir_all(&dir).ok();
    }

    /// The chain shifts and only the oldest generation is dropped, so the configured ceiling is
    /// the ceiling - not a number that quietly grows with uptime.
    #[test]
    fn keeps_exactly_the_configured_number_of_archives() {
        let dir = sandbox("keep");
        let log = dir.join("cm400d.log");
        for i in 0..=LOG_KEEP {
            fill(&log, LOG_MAX_BYTES as usize);
            append_line(&log, &format!("round{i}")).unwrap();
        }
        assert_eq!(archived_count(&log), LOG_KEEP, "no archive beyond LOG_KEEP");
        assert!(fs::metadata(archived(&log, 1)).is_ok());
        assert!(fs::metadata(archived(&log, LOG_KEEP)).is_ok());
        assert!(
            total_bytes(&log) <= LOG_MAX_BYTES * (LOG_KEEP as u64 + 1),
            "footprint bounded: {}",
            total_bytes(&log)
        );
        // Newest archive holds the most recent rotation's content.
        let newest = fs::read_to_string(archived(&log, 1)).unwrap();
        assert!(newest.starts_with('x'), "archive .1 is the previous file");
        fs::remove_dir_all(&dir).ok();
    }

    /// Below the cap nothing is renamed: an ordinary write leaves the file alone.
    #[test]
    fn appends_without_rotating_below_the_cap() {
        let dir = sandbox("below");
        let log = dir.join("cm400d.log");
        append_line(&log, "one").unwrap();
        append_line(&log, "two").unwrap();
        assert_eq!(fs::read_to_string(&log).unwrap(), "one\ntwo\n");
        assert_eq!(archived_count(&log), 0);
        fs::remove_dir_all(&dir).ok();
    }

    /// If the archive slot is unusable the write still lands, and the failure is counted instead
    /// of being swallowed or taking the process down.
    #[test]
    fn a_blocked_rotation_still_writes_the_line_and_is_counted() {
        let dir = sandbox("blocked");
        let log = dir.join("cm400d.log");
        fill(&log, LOG_MAX_BYTES as usize);
        // The shift starts by dropping the oldest archive; a directory in that slot makes
        // `remove_file` fail for real, which is the failure mode this must survive.
        fs::create_dir_all(archived(&log, LOG_KEEP)).unwrap();
        let before = rotation_failures();

        append_line(&log, "must-not-be-lost").unwrap();

        assert!(
            rotation_failures() > before,
            "the failed rotation is recorded"
        );
        assert_eq!(
            fs::metadata(&log).unwrap().len(),
            LOG_MAX_BYTES + 17,
            "the line was appended to the existing file anyway"
        );
        assert!(fs::read_to_string(&log)
            .unwrap()
            .contains("must-not-be-lost"));
        fs::remove_dir_all(&dir).ok();
    }
}
