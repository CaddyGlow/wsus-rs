//! Loader for the stored real revisions (read-only test input).
#![allow(dead_code)]
use std::path::PathBuf;

use serde_json::Value;

/// One stored revision of the real catalog.
#[derive(Debug, Clone)]
pub struct Revision {
    /// File stem, `<update-id>_<revision>`.
    pub stem: String,
    pub update_id: String,
    pub revision: u32,
    /// Server-local revision id (`deployment.id`), the numbering of
    /// `InstalledNonLeafUpdateIDs`.
    pub server_id: i64,
    pub is_leaf: bool,
    pub update_type: String,
    pub core_xml: String,
}

/// Directory named by `WSUS_REAL_REVISIONS` (default
/// `~/vm-lab/wsus-m0/client-run5/state/meta/revisions`), if it exists.
pub fn revisions_dir() -> Option<PathBuf> {
    let dir = std::env::var_os("WSUS_REAL_REVISIONS")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .map(|h| PathBuf::from(h).join("vm-lab/wsus-m0/client-run5/state/meta/revisions"))
        });
    match dir {
        Some(d) if d.is_dir() => Some(d),
        other => {
            eprintln!(
                "SKIPPED: real revisions not found ({}); set WSUS_REAL_REVISIONS to the \
                 directory of stored revision JSON files",
                other.map(|d| d.display().to_string()).unwrap_or_default()
            );
            None
        }
    }
}

/// Load every `*.json` revision, sorted by file name.
pub fn load_revisions(dir: &std::path::Path) -> Vec<Revision> {
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .expect("read revisions dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    files.sort();
    files
        .into_iter()
        .map(|p| {
            let v: Value = serde_json::from_slice(&std::fs::read(&p).expect("read")).expect("json");
            Revision {
                stem: p.file_stem().unwrap().to_string_lossy().into_owned(),
                update_id: v["identity"]["id"].as_str().expect("id").to_owned(),
                revision: v["identity"]["revision"].as_u64().expect("revision") as u32,
                server_id: v["deployment"]["id"].as_i64().expect("deployment.id"),
                is_leaf: v["is_leaf"].as_bool().expect("is_leaf"),
                update_type: v["update_type"].as_str().unwrap_or("").to_owned(),
                core_xml: v["core"]["xml"].as_str().expect("core.xml").to_owned(),
            }
        })
        .collect()
}

/// One `UpdateInfo` recovered from a `SyncUpdatesResponse` body.
#[derive(Debug, Clone)]
pub struct LenientInfo {
    pub id: i64,
    pub is_leaf: bool,
    pub action: Option<String>,
    /// The Core fragment, XML-unescaped.
    pub xml: String,
}

fn between<'a>(s: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let i = s.find(open)? + open.len();
    let j = s[i..].find(close)? + i;
    Some(&s[i..j])
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Every COMPLETE `UpdateInfo` of a response body, also from a TRUNCATED body (some captured
/// scan responses are cut off mid-document and no longer parse as XML; the strict decoder
/// then yields nothing, silently dropping up to 30 updates per such response).
pub fn lenient_update_infos(body: &[u8]) -> Vec<LenientInfo> {
    let text = String::from_utf8_lossy(body);
    let mut out = Vec::new();
    let mut rest: &str = &text;
    while let Some(i) = rest.find("<UpdateInfo>") {
        let Some(j) = rest[i..].find("</UpdateInfo>") else {
            break;
        };
        let item = &rest[i..i + j];
        rest = &rest[i + j + "</UpdateInfo>".len()..];
        let (Some(id), Some(xml)) = (
            between(item, "<ID>", "</ID>"),
            between(item, "<Xml>", "</Xml>"),
        ) else {
            continue;
        };
        out.push(LenientInfo {
            id: id.trim().parse().unwrap_or(-1),
            is_leaf: between(item, "<IsLeaf>", "</IsLeaf>").is_some_and(|l| l.trim() == "true"),
            action: between(item, "<Action>", "</Action>").map(str::to_owned),
            xml: unescape(xml),
        });
    }
    out
}
