//! Filesystem helpers that keep the "owner only" mode on Unix and skip it on Windows, where mode bits
//! do not exist and the user profile already carries an ACL. Creating the file or directory always
//! happens; only the mode is Unix-specific, so the callers keep one code path.

use std::path::Path;

/// Creates or truncates a file for its owner only (0600 on Unix; the default on Windows).
pub fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Creates a file that must not exist yet, for its owner only (0600 on Unix; the default on Windows).
pub fn create_new_private(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Restricts an existing file to its owner (0600 on Unix). No-op on Windows: no mode bits to set.
pub fn restrict(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Creates a directory and its parents for its owner only (0700 on Unix; the default on Windows).
pub fn create_dir_private(path: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}
