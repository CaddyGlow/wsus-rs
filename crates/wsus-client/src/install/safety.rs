//! Path safety for payload execution.
//!
//! * the payload must lie inside the verified store root (compared after
//!   canonicalisation) and no component below the root may be a symbolic link
//!   or a reparse point;
//! * unless the operator opted out, neither the payload nor its directory nor
//!   the store root may be writable by everyone (Unix: the `o+w` bit;
//!   Windows: an ACL check, see `windows_acl.rs`);
//! * the file is opened for reading with a share mode that denies writers and
//!   deleters (Windows) and that handle is kept until the process has been
//!   started, so the content hashed and signature-checked is the content
//!   executed.
//!
//! The Windows ACL code is unvalidated; `--allow-writable-store` exists
//! because of that (and because a state directory under `C:\` usually grants
//! `Authenticated Users` modify rights by inheritance).
use std::{
    fs::{self, File},
    io,
    path::{Path, PathBuf},
};

/// Path policy.
#[derive(Debug, Clone, Copy, Default)]
pub struct PathPolicy {
    /// Skip the world-writable check (recorded in the job evidence).
    pub allow_writable_store: bool,
}

#[cfg(windows)]
fn is_reparse_point(meta: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_meta: &fs::Metadata) -> bool {
    false
}

fn is_link(meta: &fs::Metadata) -> bool {
    meta.file_type().is_symlink() || is_reparse_point(meta)
}

/// Absolute form without touching the file system (no symlink resolution, no
/// verbatim prefix).
pub fn absolute(path: &Path) -> Result<PathBuf, String> {
    std::path::absolute(path).map_err(|e| format!("cannot make {} absolute: {e}", path.display()))
}

/// Checks that `path` is an acceptable payload location.
pub fn confine(path: &Path, store_root: &Path, policy: &PathPolicy) -> Result<(), String> {
    let path = &absolute(path)?;
    let store_root = &absolute(store_root)?;
    let canon =
        fs::canonicalize(path).map_err(|e| format!("cannot resolve the payload path: {e}"))?;
    let root =
        fs::canonicalize(store_root).map_err(|e| format!("cannot resolve the store root: {e}"))?;
    if !canon.starts_with(&root) {
        return Err("the payload is outside the verified store".into());
    }
    // Walk the components below the (given, not canonical) store root.
    let rel = path
        .strip_prefix(store_root)
        .map_err(|_| "the payload path is not below the store root as given".to_owned())?;
    let mut cur = store_root.to_path_buf();
    for c in rel.components() {
        cur.push(c);
        let meta = fs::symlink_metadata(&cur)
            .map_err(|e| format!("cannot inspect {}: {e}", cur.display()))?;
        if is_link(&meta) {
            return Err(format!("{} is a link", cur.display()));
        }
    }
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err("the payload is not a regular file".into());
    }
    if !policy.allow_writable_store {
        let mut checked: Vec<PathBuf> = vec![path.to_path_buf(), store_root.to_path_buf()];
        if let Some(p) = path.parent() {
            checked.push(p.to_path_buf());
        }
        for p in checked {
            if world_writable(&p)? {
                return Err(format!(
                    "{} is writable by everyone (use a private store directory, or \
                     --allow-writable-store on a disposable machine)",
                    p.display()
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn world_writable(p: &Path) -> Result<bool, String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(p)
        .map_err(|e| format!("cannot inspect {}: {e}", p.display()))?
        .permissions()
        .mode();
    Ok(mode & 0o002 != 0)
}

#[cfg(windows)]
fn world_writable(p: &Path) -> Result<bool, String> {
    super::windows_acl::grants_write_to_everyone(p)
}

#[cfg(not(any(unix, windows)))]
fn world_writable(_p: &Path) -> Result<bool, String> {
    Err("no permission model on this platform".into())
}

/// Opens the payload for reading, denying writers and deleters on Windows.
pub fn open_payload(path: &Path) -> io::Result<File> {
    let mut o = fs::OpenOptions::new();
    o.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 1;
        o.share_mode(FILE_SHARE_READ);
    }
    o.open(path)
}

/// True for an argument that looks like a file system path (absolute, or
/// containing a separator).
pub fn looks_like_path(token: &str) -> bool {
    let b = token.as_bytes();
    token.contains('\\')
        || (b.len() >= 3 && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/'))
        || (token.starts_with('/') && token[1..].contains('/'))
}

/// Replaces path-like arguments outside `store_root` by `<path>`; paths inside
/// the store are shown relative as `<store>/...`.
pub fn redact_args(args: &[String], store_root: &Path) -> Vec<String> {
    args.iter()
        .map(|a| {
            if !looks_like_path(a) {
                return a.clone();
            }
            match Path::new(a).strip_prefix(store_root) {
                Ok(rel) => format!("<store>/{}", rel.display().to_string().replace('\\', "/")),
                Err(_) => "<path>".to_owned(),
            }
        })
        .collect()
}

/// `program` shown relative to the store, or just its file name when outside.
pub fn redact_program(program: &Path, store_root: &Path) -> String {
    match program.strip_prefix(store_root) {
        Ok(rel) => format!("<store>/{}", rel.display().to_string().replace('\\', "/")),
        Err(_) => format!(
            "<outside-store>/{}",
            program
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        ),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn private(dir: &Path) {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn accepts_a_private_payload_in_the_store() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("store");
        fs::create_dir_all(root.join("complete/x")).unwrap();
        let f = root.join("complete/x/a.exe");
        fs::write(&f, b"x").unwrap();
        for d in [&root, &root.join("complete"), &root.join("complete/x")] {
            private(d);
        }
        fs::set_permissions(&f, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(confine(&f, &root, &PathPolicy::default()).is_ok());
    }

    #[test]
    fn rejects_world_writable_and_links_and_outside() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("store");
        fs::create_dir_all(&root).unwrap();
        private(&root);
        let f = root.join("a.exe");
        fs::write(&f, b"x").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o666)).unwrap();
        let e = confine(&f, &root, &PathPolicy::default()).unwrap_err();
        assert!(e.contains("writable by everyone"), "{e}");
        assert!(
            confine(
                &f,
                &root,
                &PathPolicy {
                    allow_writable_store: true
                }
            )
            .is_ok()
        );
        let outside = t.path().join("o.exe");
        fs::write(&outside, b"x").unwrap();
        assert!(confine(&outside, &root, &PathPolicy::default()).is_err());
        let link = root.join("l.exe");
        symlink(&outside, &link).unwrap();
        let e = confine(
            &link,
            &root,
            &PathPolicy {
                allow_writable_store: true,
            },
        )
        .unwrap_err();
        assert!(e.contains("outside") || e.contains("link"), "{e}");
    }

    #[test]
    fn redacts_paths_outside_the_store() {
        let root = Path::new("/s/store");
        let args = vec![
            "/q".to_owned(),
            "WD".to_owned(),
            "/etc/passwd".to_owned(),
            "/s/store/complete/x/a.exe".to_owned(),
            "C:\\Users\\x\\y".to_owned(),
        ];
        assert_eq!(
            redact_args(&args, root),
            ["/q", "WD", "<path>", "<store>/complete/x/a.exe", "<path>"]
        );
    }
}
