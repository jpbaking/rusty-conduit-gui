//! Stages a session's MITM CA from the vault as a short-lived private file.
//!
//! The engine loads its CA from a path, while the app keeps the CA only in the vault. So at
//! session start the vault's normalized PEM (certificate chain and unencrypted PKCS#8 key) is
//! written to an owner-only file in an owner-only directory, the engine loads it, and the
//! directory is removed when this value is dropped, which happens as soon as loading is done.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use uuid::Uuid;

const FILE_NAME: &str = "ca.pem";

/// A private copy of one CA. Removed, with its directory, on drop.
#[derive(Debug)]
pub(crate) struct MitmCaFile {
    dir: PathBuf,
    file: PathBuf,
}

impl MitmCaFile {
    /// Writes `pem` under the platform's per-user runtime or temp directory.
    pub(crate) fn write(pem: &[u8]) -> io::Result<Self> {
        Self::write_in(&default_base(), pem)
    }

    pub(crate) fn write_in(base: &Path, pem: &[u8]) -> io::Result<Self> {
        let dir = base.join(format!("rc-mitm-{}", Uuid::new_v4().simple()));
        create_private_dir(&dir)?;
        let staged = Self { file: dir.join(FILE_NAME), dir };
        conduit_openssh::write_private_file(&staged.file, pem)?;
        Ok(staged)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.file
    }
}

impl Drop for MitmCaFile {
    fn drop(&mut self) {
        // Overwrite first, so the key does not linger in a file a later crash could leave.
        if let Ok(len) = fs::metadata(&self.file).map(|m| m.len()) {
            let _ = fs::write(&self.file, vec![0u8; len as usize]);
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Fails if the directory already exists, so an existing directory is never reused.
fn create_private_dir(path: &Path) -> io::Result<()> {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// `$XDG_RUNTIME_DIR` (memory-backed and per-user) on Linux when set, else the user's temp dir.
fn default_base() -> PathBuf {
    #[cfg(target_os = "linux")]
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from) {
        if dir.is_absolute() && dir.is_dir() {
            return dir;
        }
    }
    std::env::temp_dir()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rc-mitm-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn file_is_private_and_removed_on_drop() {
        let base = scratch();
        let staged = MitmCaFile::write_in(&base, b"-----BEGIN CERTIFICATE-----").unwrap();
        let path = staged.path().to_path_buf();
        assert_eq!(fs::read(&path).unwrap(), b"-----BEGIN CERTIFICATE-----");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&path), 0o600);
            assert_eq!(mode(path.parent().unwrap()), 0o700);
        }
        drop(staged);
        assert!(!path.exists());
        assert!(!path.parent().unwrap().exists());
        assert_eq!(fs::read_dir(&base).unwrap().count(), 0);
        fs::remove_dir_all(base).unwrap();
    }
}
