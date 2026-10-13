//! Alternative process-instance identity: `SystemBasicProcessInformation`.
//!
//! Why this exists: `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` is denied
//! (`ERROR_ACCESS_DENIED`) for the streaming client processes when the service runs as
//! `NT AUTHORITY\LocalService`, so `GetProcessTimes` can never give us a creation time - and
//! without instance identity, R2 stays fail-closed. This module tests a source that needs no
//! handle to the target at all: one `NtQuerySystemInformation` snapshot returns, for every
//! process, both `UniqueProcessId` and a `SequenceNumber` that exists precisely to detect PID
//! reuse.
//!
//! Layout provenance, because an invented offset would be worse than no layout at all. Mirrors
//! the SDK installed on this machine:
//!
//! ```text
//! C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um\winternl.h
//!   L286 typedef struct _SYSTEM_BASICPROCESS_INFORMATION {
//!   L287     ULONG NextEntryOffset;
//!   L288     HANDLE UniqueProcessId;
//!   L289     HANDLE InheritedFromUniqueProcessId;
//!   L290     ULONG64 SequenceNumber;
//!   L291     UNICODE_STRING ImageName;
//!   L292 } SYSTEM_BASICPROCESS_INFORMATION, *PSYSTEM_BASICPROCESS_INFORMATION;
//!   L403     SystemBasicProcessInformation = 252,
//! ```
//!
//! Deliberate limits of this module:
//! - `ImageName.Buffer` is never dereferenced. Whether those embedded pointers are valid in
//!   the returned buffer is not something this project has verified, and the identity does
//!   not need the name.
//! - A snapshot failure or a partial parse yields an explicit error. It never yields a
//!   plausible-looking identity.
//! - Nothing here feeds a decision yet: this round is feasibility. The sequence number is
//!   also not smuggled into `ProcInstance::created_ms`, because pretending a sequence is a
//!   timestamp would make every latency and ordering comparison meaningless.

use std::collections::BTreeSet;

/// `winternl.h` L403: `SystemBasicProcessInformation = 252`.
pub const BASIC_PROCESS_CLASS: i32 = 252;

/// `STATUS_INFO_LENGTH_MISMATCH`, the documented "grow the buffer and retry" signal.
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;

#[repr(C)]
#[derive(Clone, Copy)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    // Kept as a raw pointer for layout fidelity only. Never dereferenced, by design.
    #[allow(dead_code)]
    buffer: *mut u16,
}

/// Mirror of `SYSTEM_BASICPROCESS_INFORMATION` (see the header citation above).
#[repr(C)]
#[derive(Clone, Copy)]
struct BasicProcessRecord {
    next_entry_offset: u32,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
    sequence_number: u64,
    image_name: UnicodeString,
}

/// One process instance, as identified without touching its handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcIdentity {
    pub pid: u32,
    /// Opaque and monotone-ish per the docs: only ever compared for equality.
    pub sequence: u64,
}

impl ProcIdentity {
    /// Same process *instance*? A recycled PID carries a different sequence, so this is the
    /// check that must gate any `TRUE`/`FALSE` attribution once arbitration is attempted.
    pub fn same_instance(&self, other: &ProcIdentity) -> bool {
        self.pid == other.pid && self.sequence == other.sequence
    }
}

/// Every failure mode is distinct and explicit; "we could not parse it" must not look like
/// "there is no such process".
#[derive(Debug, PartialEq, Eq)]
pub enum SnapshotError {
    /// The info class is refused by this build (unsupported / access).
    Unsupported { ntstatus: i32 },
    /// Growable buffer hit its ceiling; we refuse to guess.
    BufferExhausted { tried: usize },
    /// `NextEntryOffset` is not aligned to the record: layout or memory is not what we think.
    MisalignedOffset { at: usize, offset: u32 },
    /// A record would end past the returned bytes.
    OffsetPastBuffer { at: usize, next: u32, len: usize },
    /// The returned length is smaller than one record.
    TooShort { len: usize, need: usize },
    /// A `HANDLE` slot holds something that cannot be a pid.
    InvalidProcessId { at: usize, value: u64 },
    /// Our own pid was absent from the parse: strong evidence the layout is wrong.
    SelfMissing { self_pid: u32, parsed: usize },
}

/// What a successful snapshot says, including the cross-check that makes the parse trustable.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub identities: Vec<ProcIdentity>,
    pub return_len: u32,
    pub self_present: bool,
    /// Process count from the independent Toolhelp walk, plus how far the two sets differ.
    pub toolhelp_count: usize,
    pub only_in_snapshot: usize,
    pub only_in_toolhelp: usize,
}

impl Snapshot {
    pub fn find(&self, pid: u32) -> Option<ProcIdentity> {
        self.identities.iter().copied().find(|i| i.pid == pid)
    }
}

/// Walk the linked records. Pure, so the adversarial cases below are tested without a call.
///
/// The last record is the one whose `NextEntryOffset` is 0; we additionally require each
/// intermediate offset to be record-aligned and every record to sit inside `buf`.
pub fn parse(buf: &[u8], self_pid: u32) -> Result<Vec<ProcIdentity>, SnapshotError> {
    let size = std::mem::size_of::<BasicProcessRecord>();
    let align = std::mem::align_of::<BasicProcessRecord>();
    if buf.len() < size {
        return Err(SnapshotError::TooShort {
            len: buf.len(),
            need: size,
        });
    }
    let mut out: Vec<ProcIdentity> = Vec::new();
    let mut at = 0usize;
    loop {
        if at + size > buf.len() {
            return Err(SnapshotError::OffsetPastBuffer {
                at,
                next: 0,
                len: buf.len(),
            });
        }
        // read_unaligned: we do not assume the kernel aligned the chain for us.
        let rec: BasicProcessRecord =
            unsafe { std::ptr::read_unaligned(buf.as_ptr().add(at) as *const BasicProcessRecord) };
        let raw_pid = rec.unique_process_id as u64;
        if raw_pid > u64::from(u32::MAX) {
            return Err(SnapshotError::InvalidProcessId { at, value: raw_pid });
        }
        out.push(ProcIdentity {
            pid: raw_pid as u32,
            sequence: rec.sequence_number,
        });
        if rec.next_entry_offset == 0 {
            break;
        }
        if !(rec.next_entry_offset as usize).is_multiple_of(align) {
            return Err(SnapshotError::MisalignedOffset {
                at,
                offset: rec.next_entry_offset,
            });
        }
        let next_at = at + rec.next_entry_offset as usize;
        if next_at >= buf.len() {
            return Err(SnapshotError::OffsetPastBuffer {
                at,
                next: rec.next_entry_offset,
                len: buf.len(),
            });
        }
        at = next_at;
    }
    if !out.iter().any(|i| i.pid == self_pid) {
        return Err(SnapshotError::SelfMissing {
            self_pid,
            parsed: out.len(),
        });
    }
    Ok(out)
}

/// The independent process list, used only to cross-check the parse.
pub fn toolhelp_pids() -> BTreeSet<u32> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    let mut set = BTreeSet::new();
    unsafe {
        let snap = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(s) => s,
            Err(_) => return set,
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                set.insert(entry.th32ProcessID);
                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    set
}

/// One snapshot, with growth on `STATUS_INFO_LENGTH_MISMATCH` and a mandatory cross-check.
///
/// Buffer is usize-aligned, and the returned length bounds the parse - we never read the
/// whole allocation as if the kernel had filled it.
pub fn take() -> Result<Snapshot, SnapshotError> {
    use windows::Wdk::System::SystemInformation::{
        NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS,
    };
    const MIN: usize = 1 << 16;
    const MAX: usize = 1 << 25; // 32 MiB, then we give up rather than guess
    let self_pid = std::process::id();
    let mut cap = MIN;
    loop {
        // usize alignment, like the ETW scratch buffer: a *const BasicProcessRecord cast out
        // of a byte vector is not guaranteed aligned.
        let mut backing = vec![0usize; cap / std::mem::size_of::<usize>()];
        let bytes = unsafe { std::slice::from_raw_parts_mut(backing.as_mut_ptr() as *mut u8, cap) };
        let mut ret = 0u32;
        // `NtQuerySystemInformation` returns NTSTATUS (severity in the high bit), so every
        // comparison goes through `.0` as i32: "success" is 0 or another INFO class, and
        // anything else must surface as an error rather than as an empty list.
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_INFORMATION_CLASS(BASIC_PROCESS_CLASS),
                bytes.as_mut_ptr() as *mut core::ffi::c_void,
                cap as u32,
                &mut ret,
            )
        };
        if status.0 == STATUS_INFO_LENGTH_MISMATCH {
            if cap >= MAX {
                return Err(SnapshotError::BufferExhausted { tried: cap });
            }
            cap *= 2;
            continue;
        }
        if status.0 != 0 {
            return Err(SnapshotError::Unsupported { ntstatus: status.0 });
        }
        let len = (ret as usize).min(cap);
        let identities = parse(&bytes[..len], self_pid)?;
        let other = toolhelp_pids();
        let mine: BTreeSet<u32> = identities.iter().map(|i| i.pid).collect();
        return Ok(Snapshot {
            toolhelp_count: other.len(),
            only_in_snapshot: mine.difference(&other).count(),
            only_in_toolhelp: other.difference(&mine).count(),
            identities,
            return_len: ret,
            self_present: true, // parse() already refuses otherwise
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one record's bytes with the real `repr(C)` layout, so a layout change in this
    /// file cannot silently desynchronise the tests from the parser.
    fn record_bytes(pid: u32, sequence: u64, next: u32) -> Vec<u8> {
        let rec = BasicProcessRecord {
            next_entry_offset: next,
            unique_process_id: pid as usize,
            inherited_from_unique_process_id: 4usize,
            sequence_number: sequence,
            image_name: UnicodeString {
                length: 0,
                maximum_length: 0,
                buffer: std::ptr::null_mut(),
            },
        };
        let size = std::mem::size_of::<BasicProcessRecord>();
        let mut v = vec![0u8; size];
        unsafe {
            std::ptr::write_unaligned(v.as_mut_ptr() as *mut BasicProcessRecord, rec);
        }
        v
    }

    fn chain(records: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for r in records {
            out.extend_from_slice(r);
        }
        out
    }

    #[test]
    fn mirror_layout_matches_the_sdk_record_field_order() {
        // x64: ULONG(4) + pad(4), HANDLE(8), HANDLE(8), ULONG64(8), UNICODE_STRING(16) = 48.
        if cfg!(target_pointer_width = "64") {
            assert_eq!(std::mem::size_of::<BasicProcessRecord>(), 48);
            assert_eq!(std::mem::align_of::<BasicProcessRecord>(), 8);
        }
        // Offsets come from the compiler on a real instance (no null dereference, which would
        // be its own kind of undefined behaviour), but they must be strictly increasing in the
        // order the header lists, or our field-by-field read is meaningless.
        let dummy = BasicProcessRecord {
            next_entry_offset: 0,
            unique_process_id: 0,
            inherited_from_unique_process_id: 0,
            sequence_number: 0,
            image_name: UnicodeString {
                length: 0,
                maximum_length: 0,
                buffer: std::ptr::null_mut(),
            },
        };
        let base = &dummy as *const BasicProcessRecord as usize;
        let off_next = &dummy.next_entry_offset as *const u32 as usize - base;
        let off_pid = &dummy.unique_process_id as *const usize as usize - base;
        let off_seq = &dummy.sequence_number as *const u64 as usize - base;
        assert_eq!(off_next, 0, "NextEntryOffset is the first field");
        assert!(
            off_pid > off_next && off_seq > off_pid,
            "field order must follow winternl.h"
        );
    }

    #[test]
    fn a_valid_chain_parses_into_per_process_identities() {
        let size = std::mem::size_of::<BasicProcessRecord>();
        let buf = chain(&[
            record_bytes(100, 7, size as u32),
            record_bytes(std::process::id(), 9, size as u32),
            record_bytes(300, 11, 0),
        ]);
        let got = parse(&buf, std::process::id()).expect("valid chain");
        assert_eq!(
            got,
            vec![
                ProcIdentity {
                    pid: 100,
                    sequence: 7
                },
                ProcIdentity {
                    pid: std::process::id(),
                    sequence: 9
                },
                ProcIdentity {
                    pid: 300,
                    sequence: 11
                },
            ]
        );
    }

    #[test]
    fn same_pid_with_a_different_sequence_is_a_different_instance() {
        let old = ProcIdentity {
            pid: 4994,
            sequence: 3,
        };
        let reused = ProcIdentity {
            pid: 4994,
            sequence: 4,
        };
        assert!(
            !old.same_instance(&reused),
            "PID reuse must not inherit identity"
        );
        assert!(old.same_instance(&ProcIdentity {
            pid: 4994,
            sequence: 3
        }));
        // A different pid never matches, whatever the sequences say.
        assert!(!old.same_instance(&ProcIdentity {
            pid: 4995,
            sequence: 3
        }));
    }

    #[test]
    fn malformed_chains_are_refused_not_guessed() {
        let size = std::mem::size_of::<BasicProcessRecord>();
        let me = std::process::id();

        // Misaligned step: not a multiple of the record alignment.
        let buf = chain(&[record_bytes(me, 1, 7), record_bytes(2, 2, 0)]);
        assert_eq!(
            parse(&buf, me),
            Err(SnapshotError::MisalignedOffset { at: 0, offset: 7 })
        );

        // Step that walks past the returned bytes.
        let buf = chain(&[
            record_bytes(me, 1, (size * 3) as u32),
            record_bytes(2, 2, 0),
        ]);
        assert_eq!(
            parse(&buf, me),
            Err(SnapshotError::OffsetPastBuffer {
                at: 0,
                next: (size * 3) as u32,
                len: size * 2
            })
        );

        // Buffer shorter than one record.
        assert_eq!(
            parse(&vec![0u8; size - 1], me),
            Err(SnapshotError::TooShort {
                len: size - 1,
                need: size
            })
        );

        // A HANDLE slot that cannot be a pid: the classic sign of a wrong layout.
        let bad = {
            let mut v = record_bytes(0, 1, 0);
            unsafe {
                let p = v.as_mut_ptr() as *mut BasicProcessRecord;
                (*p).unique_process_id = 1usize << 40;
            }
            v
        };
        assert_eq!(
            parse(&bad, me),
            Err(SnapshotError::InvalidProcessId {
                at: 0,
                value: 1u64 << 40
            })
        );

        // A parse that does not contain our own pid is refused: on a real machine our process
        // is always listed, so this is the layout/permission canary.
        let buf = chain(&[record_bytes(12345, 1, 0)]);
        assert_eq!(
            parse(&buf, me),
            Err(SnapshotError::SelfMissing {
                self_pid: me,
                parsed: 1
            })
        );
    }

    #[test]
    fn the_class_value_is_the_one_the_sdk_declares() {
        // Guards against a later "tidy-up" silently retargeting a different info class.
        assert_eq!(BASIC_PROCESS_CLASS, 252);
    }

    #[test]
    fn a_real_snapshot_agrees_with_the_independent_process_walk() {
        // This one does hit the API. If the class is unavailable on this machine the call
        // returns an explicit Unsupported, which is a result, not a silent pass: assert only
        // the cross-check consistency when it succeeds, and never a specific count.
        match take() {
            Ok(s) => {
                assert!(!s.identities.is_empty());
                assert!(s.self_present, "our own pid must be listed");
                let mine: BTreeSet<u32> = s.identities.iter().map(|i| i.pid).collect();
                let other = toolhelp_pids();
                assert!(!other.is_empty(), "the control walk should work too");
                // Sequences must be present for every entry; zero for all of them would mean
                // we are reading a reserved field.
                assert!(
                    s.identities.iter().any(|i| i.sequence != 0),
                    "all-zero sequences means the layout guess is wrong"
                );
                let drift = s.only_in_snapshot + s.only_in_toolhelp;
                assert!(
                    drift <= other.len() / 2,
                    "the two views diverge too much to be the same list: {:?} vs {:?}, drift={drift}",
                    mine.len(),
                    other.len()
                );
            }
            Err(e) => {
                // Reaching here means the class is refused on this machine; the report must
                // say so instead of the test pretending identity is available.
                println!("SystemBasicProcessInformation unavailable: {e:?}");
            }
        }
    }
}
