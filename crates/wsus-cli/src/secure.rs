//! Local filesystem protection for the server database and content.
//!
//! Administrative authority is deliberately local: there is no administrative
//! network interface and no administrative credential in the protocol. Whoever
//! can write the database file can administer the server, and the database
//! also holds the cookie signing key. These helpers keep the files private and
//! refuse to administer a store that others can modify.

use anyhow::{Context, Result};
use std::path::Path;

/// Creates a directory (and parents) readable only by its owner on Unix.
pub fn ensure_private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .with_context(|| format!("cannot create directory {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("cannot restrict {}", path.display()))?;
        }
    }
    Ok(())
}

/// Restricts an existing file to its owner on Unix.
pub fn restrict_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    if path.exists() {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("cannot restrict {}", path.display()))?;
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Fails when group or others can write the database file or its directory
/// (Unix). This is the administrative access check.
pub fn check_admin_access(database: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use anyhow::bail;
        use std::os::unix::fs::PermissionsExt;
        let mut paths = vec![database.to_path_buf()];
        if let Some(parent) = database.parent().filter(|p| !p.as_os_str().is_empty()) {
            paths.push(parent.to_path_buf());
        }
        for p in paths {
            if let Ok(meta) = std::fs::metadata(&p)
                && meta.permissions().mode() & 0o022 != 0
            {
                bail!(
                    "{} is writable by other users; administration is authorized by file \
                     ownership, so tighten it (chmod go-w) first",
                    p.display()
                );
            }
        }
    }
    #[cfg(not(unix))]
    let _ = database;
    Ok(())
}
