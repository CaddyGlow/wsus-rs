//! Per-handler log hook and detached-process watching.
//!
//! OBSERVED on a guest (2026-10-05): the Defender package executables exit 0
//! before the update is applied. `AM_Engine.exe` leaves a detached
//! `MpSigStub.exe` that waits for the sibling packages and then applies the
//! update and writes `%SystemRoot%\Temp\MpSigStub.log` (UTF-16LE). Exit codes
//! therefore cannot prove success; the executor polls the evaluator and, as
//! evidence only, records this log's new tail and any `MpSigStub.exe` that
//! started during the run. Neither is ever used to decide success.
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

/// Maximum excerpt size in bytes of the raw log.
pub const MAX_EXCERPT_BYTES: u64 = 64 * 1024;

/// A process that was started during the run and was still alive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetachedProcess {
    pub name: String,
    pub pid: u32,
    /// Unix seconds, when known.
    pub started_unix: Option<i64>,
}

/// Lists running processes by image name. Hook; never kills anything.
pub trait ProcessWatcher {
    fn running(&self, image_name: &str) -> Vec<DetachedProcess>;
}

/// Watches nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoWatcher;

impl ProcessWatcher for NoWatcher {
    fn running(&self, _image_name: &str) -> Vec<DetachedProcess> {
        Vec::new()
    }
}

/// Test double with a fixed answer.
#[derive(Debug, Clone, Default)]
pub struct FixedWatcher(pub Vec<DetachedProcess>);

impl ProcessWatcher for FixedWatcher {
    fn running(&self, image_name: &str) -> Vec<DetachedProcess> {
        self.0
            .iter()
            .filter(|p| p.name.eq_ignore_ascii_case(image_name))
            .cloned()
            .collect()
    }
}

/// A handler's log and detached process, selected by payload file names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandlerLog {
    /// Lower-case payload file names that select this hook (exact).
    pub programs: Vec<String>,
    /// Lower-case file-name prefixes that select it as well.
    pub program_prefixes: Vec<String>,
    pub log_path: PathBuf,
    pub watch_process: String,
}

impl HandlerLog {
    /// The Defender packages: `AM_*.exe` and `MpSigStub.exe`; log
    /// `<system_root>\\Temp\\MpSigStub.log`; stub process `MpSigStub.exe`.
    pub fn defender(system_root: &Path) -> Self {
        Self {
            programs: vec!["mpsigstub.exe".into()],
            program_prefixes: vec!["am_".into()],
            log_path: system_root.join("Temp").join("MpSigStub.log"),
            watch_process: "MpSigStub.exe".into(),
        }
    }

    pub fn applies_to(&self, file_name: &str) -> bool {
        let l = file_name.to_ascii_lowercase();
        self.programs.contains(&l) || self.program_prefixes.iter().any(|p| l.starts_with(p))
    }
}

/// Current length of the log (0 when absent or unreadable).
pub fn mark(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

/// Decodes the bytes appended after `from` (at most the last
/// [`MAX_EXCERPT_BYTES`], marked as truncated otherwise). UTF-16LE with an
/// optional BOM. Best effort: any problem yields `None`.
pub fn read_excerpt(path: &Path, from: u64) -> Option<String> {
    let mut f = File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    let from = if len < from { 0 } else { from };
    if len <= from {
        return None;
    }
    let mut start = from;
    let mut truncated = false;
    if len - start > MAX_EXCERPT_BYTES {
        start = len - MAX_EXCERPT_BYTES;
        truncated = true;
    }
    if start % 2 == 1 {
        start += 1;
    }
    f.seek(SeekFrom::Start(start)).ok()?;
    let mut bytes = Vec::new();
    f.take(len - start).read_to_end(&mut bytes).ok()?;
    if bytes.len() % 2 == 1 {
        bytes.pop();
    }
    let mut units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    if start == 0 && units.first() == Some(&0xFEFF) {
        units.remove(0);
    }
    let text = String::from_utf16_lossy(&units);
    Some(if truncated {
        format!("[truncated: earlier lines omitted]\n{text}")
    } else {
        text
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str, bom: bool) -> Vec<u8> {
        let mut v = Vec::new();
        if bom {
            v.extend([0xFF, 0xFE]);
        }
        for u in s.encode_utf16() {
            v.extend(u.to_le_bytes());
        }
        v
    }

    #[test]
    fn reads_only_appended_lines_and_strips_the_bom() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("l.log");
        std::fs::write(&p, utf16("old line\r\n", true)).unwrap();
        let m = mark(&p);
        assert_eq!(read_excerpt(&p, m), None);
        let mut b = std::fs::read(&p).unwrap();
        b.extend(utf16("MpSigStub successfully updated\r\n", false));
        std::fs::write(&p, b).unwrap();
        assert_eq!(
            read_excerpt(&p, m).unwrap(),
            "MpSigStub successfully updated\r\n"
        );
        assert!(read_excerpt(&p, 0).unwrap().starts_with("old line"));
        assert_eq!(read_excerpt(&d.path().join("none"), 0), None);
    }

    #[test]
    fn truncates_to_the_tail() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("l.log");
        let line = "x".repeat(99) + "\n";
        let text = line.repeat(1500) + "LAST\n";
        std::fs::write(&p, utf16(&text, true)).unwrap();
        let e = read_excerpt(&p, 0).unwrap();
        assert!(e.starts_with("[truncated"));
        assert!(e.ends_with("LAST\n"));
        assert!(e.len() <= (MAX_EXCERPT_BYTES / 2) as usize + 64);
    }

    #[test]
    fn selects_defender_packages() {
        let h = HandlerLog::defender(Path::new("C:/Windows"));
        assert!(h.applies_to("AM_Engine.exe") && h.applies_to("MpSigStub.exe"));
        assert!(!h.applies_to("NoOp.exe"));
    }
}
