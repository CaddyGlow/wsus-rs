//! Reading files out of a declared `.msu` container.
//!
//! A Windows 11 24H2/25H2 `.msu` is a WIM archive (OBSERVED: `7z l` of the real
//! `Windows11.0-KB5043080-x64.msu`, 533,761,740 bytes, lists `DesktopDeployment.cab`,
//! `SSU-26100.1738-x64.cab`, `Windows11.0-KB5043080-x64.psf`, `Windows11.0-KB5043080-x64.wim`,
//! `onepackage.AggregatedMetadata.cab` and `wsusscan.cab` at the image root). The ActionList of a
//! monthly update names Express files (`Windows11.0-KB5043080-x64.wim`, `...mumx.esd`) that the WSUS does
//! not declare as files; they, and the canonical `SSU-<build>-x64.cab`, are members of the declared
//! `.msu` files (`AltSourceName` in the ActionList). `extract_member` takes one such member out.
use std::path::{Path, PathBuf};
use wim::{ImageIndex, OpenOptions, Wim};

/// Extracts the file `name` (matched case-insensitively at the image root) from the WIM archive
/// `container` into the directory `dest` and returns the extracted path. `Err` says why not (the archive
/// cannot be opened as a WIM, or no image holds the member): the caller tries its other containers.
pub fn extract_member(container: &Path, name: &str, dest: &Path) -> Result<PathBuf, String> {
    if let Err(e) = std::fs::File::open(container) {
        return Err(format!(
            "cannot open {} for reading: {e} (os error {:?})",
            container.display(),
            e.raw_os_error()
        ));
    }
    let mut archive = Wim::open(container, OpenOptions::default())
        .map_err(|e| format!("cannot open {} as a WIM: {e}", container.display()))?;
    let images = archive.info().map_err(|e| e.to_string())?.image_count;
    let mut last = format!("{name} is not a member");
    for i in 1..=images {
        let index = ImageIndex::try_from(i).map_err(|e| e.to_string())?;
        match archive.extract_path_case_insensitive(index, name, dest) {
            Ok(path) => return Ok(path),
            Err(e) => last = format!("image {i}: {e}"),
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_member_is_extracted_from_a_wim_container_and_a_missing_one_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("Windows11.0-KB1-x64.wim"),
            b"express baseline bytes",
        )
        .unwrap();
        std::fs::write(src.join("other.cab"), b"other").unwrap();
        let msu = dir.path().join("update.msu");
        let mut w = Wim::new(wim::Compression::None).unwrap();
        w.capture_image(&src).unwrap();
        w.write(&msu).unwrap();
        drop(w);

        let out = dir.path().join("out");
        std::fs::create_dir_all(&out).unwrap();
        let got = extract_member(&msu, "windows11.0-kb1-x64.WIM", &out)
            .expect("member found case-insensitively");
        assert_eq!(std::fs::read(&got).unwrap(), b"express baseline bytes");
        assert!(extract_member(&msu, "absent.esd", &out).is_err());
        let notwim = dir.path().join("plain.msu");
        std::fs::write(&notwim, b"not a wim").unwrap();
        assert!(extract_member(&notwim, "x", &out).is_err());
    }

    /// Needs the real baseline `.msu` (set `WSUS_REAL_MSU` to its path); run with `--ignored`.
    #[test]
    #[ignore]
    fn the_real_baseline_msu_yields_its_express_wim() {
        let msu = std::env::var("WSUS_REAL_MSU").expect("WSUS_REAL_MSU");
        let out = tempfile::tempdir().unwrap();
        let got = extract_member(Path::new(&msu), "Windows11.0-KB5043080-x64.wim", out.path())
            .expect("the baseline wim is a member");
        assert_eq!(std::fs::metadata(got).unwrap().len(), 113_666_182);
    }
}
