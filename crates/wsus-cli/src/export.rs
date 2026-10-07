//! Native WSUS metadata export from one immutable catalog generation.
//!
//! Package publication is atomic and refuses replacement. Payload files,
//! approvals and computer state are not embedded in a metadata CAB.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::json;
use sha2::{Digest, Sha256};
use wsus_server::export::{ExportOptions, export_cab};

use crate::admin::Admin;
use crate::output::Output;

/// Export the selected source's active generation without modifying its catalog.
pub fn catalog_export(
    admin: &Admin,
    source: Option<&str>,
    out: &Path,
    content_base_url: Option<&str>,
) -> Result<Output> {
    if !out
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("cab"))
    {
        bail!("native metadata export requires an output name ending in .cab");
    }
    if out.symlink_metadata().is_ok() {
        bail!("refusing to replace existing export {}", out.display());
    }
    let source = admin.source(source)?;
    let snapshot = admin
        .catalog
        .snapshot(source.id)?
        .context("source has no active catalog generation")?;
    let options = ExportOptions {
        server_id: admin.db.server_id()?.0,
        content_base_url: content_base_url
            .map(str::to_owned)
            .or_else(|| admin.config.server.advertised_content_url.clone()),
        ..ExportOptions::default()
    };
    let parent = out
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .context("cannot create temporary export next to destination")?;
    let report = export_cab(&snapshot, &options, temporary.as_file_mut())
        .context("cannot export native WSUS metadata")?;
    temporary.flush()?;
    temporary.as_file().sync_all()?;
    temporary.as_file_mut().seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0; 64 * 1024];
    loop {
        let count = temporary.as_file_mut().read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    let sha256 = format!("{:x}", hash.finalize());
    temporary
        .persist_noclobber(out)
        .with_context(|| format!("cannot publish new export {}", out.display()))?;
    Ok(Output::ok(json!({
        "source": source.name,
        "package": out,
        "sha256": sha256,
        "metadata_only": true,
        "export": report,
    })))
}
