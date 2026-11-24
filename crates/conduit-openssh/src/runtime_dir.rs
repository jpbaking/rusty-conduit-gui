//! A short, space-free, private directory for one session's runtime files.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use ring::rand::{SecureRandom, SystemRandom};

/// Longest accepted base directory, so socket paths stay under the Unix limit.
pub const MAX_BASE_LEN: usize = 64;
/// Longest accepted runtime directory path.
pub const MAX_DIR_LEN: usize = 80;

const CREATE_ATTEMPTS: usize = 16;

/// A private directory that is deleted when this value is dropped.
#[derive(Debug)]
pub struct RuntimeDir {
    path: PathBuf,
}

impl RuntimeDir {
    /// Creates the directory under the platform's preferred short base.
    pub fn create() -> io::Result<Self> {
        Self::create_in(&default_base()?)
    }

    /// Creates `<base>/rc-<short_hex>`, mode `0700` on Unix.
    pub fn create_in(base: &Path) -> io::Result<Self> {
        let rng = SystemRandom::new();
        for _ in 0..CREATE_ATTEMPTS {
            let mut bytes = [0u8; 4];
            rng.fill(&mut bytes)
                .map_err(|_| io::Error::other("system random source failed"))?;
            let path = base.join(format!("rc-{}", crate::hex(&bytes)));
            if !is_short_and_space_free(&path, MAX_DIR_LEN) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("runtime path {} is too long or has spaces", path.display()),
                ));
            }
            match create_private_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not find a free runtime directory name",
        ))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for RuntimeDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Writes `contents` to a file only the current user can read (`0600` on Unix).
///
/// Refuses to follow a symlink at `path`.
pub fn write_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(contents)?;
    file.flush()
}

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

fn is_short_and_space_free(path: &Path, max_len: usize) -> bool {
    let text = path.as_os_str().to_string_lossy();
    text.len() <= max_len && !text.chars().any(char::is_whitespace)
}

/// Uses `$XDG_RUNTIME_DIR` when it is absolute, space-free, and short. Otherwise `fallback`.
#[cfg(any(unix, test))]
fn select_linux_base(xdg: Option<&Path>, fallback: &Path) -> PathBuf {
    match xdg {
        Some(dir) if dir.is_absolute() && is_short_and_space_free(dir, MAX_BASE_LEN) => {
            dir.to_path_buf()
        }
        _ => fallback.to_path_buf(),
    }
}

#[cfg(target_os = "linux")]
fn default_base() -> io::Result<PathBuf> {
    let xdg = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    Ok(select_linux_base(xdg.as_deref(), Path::new("/tmp")))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn default_base() -> io::Result<PathBuf> {
    // The macOS per-user temp path is long enough to break Unix socket limits.
    Ok(select_linux_base(None, Path::new("/tmp")))
}

#[cfg(not(unix))]
fn default_base() -> io::Result<PathBuf> {
    let base = std::env::temp_dir();
    if is_short_and_space_free(&base, MAX_BASE_LEN) {
        return Ok(base);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "temp directory {} is too long or has spaces; set TEMP to a short path",
            base.display()
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_dir_is_short_space_free_and_cleaned_up() {
        let dir = RuntimeDir::create().unwrap();
        let path = dir.path().to_path_buf();
        let text = path.to_str().unwrap();
        assert!(path.is_dir());
        assert!(text.len() <= MAX_DIR_LEN, "{text}");
        assert!(!text.contains(' '));
        assert!(path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("rc-"));
        fs::write(path.join("inner"), b"x").unwrap();
        drop(dir);
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn runtime_dir_and_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = RuntimeDir::create().unwrap();
        let mode = fs::metadata(dir.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);

        let file = dir.path().join("f");
        fs::write(&file, b"old").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        write_private_file(&file, b"new").unwrap();
        assert_eq!(fs::read(&file).unwrap(), b"new");
        let mode = fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn runtime_dir_write_refuses_symlinks() {
        let dir = RuntimeDir::create().unwrap();
        let target = dir.path().join("target");
        fs::write(&target, b"keep").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(write_private_file(&link, b"overwrite").is_err());
        assert_eq!(fs::read(&target).unwrap(), b"keep");
    }

    #[test]
    fn runtime_dir_rejects_spaces_and_long_bases() {
        let spaced = Path::new("/tmp/has space");
        assert_eq!(
            RuntimeDir::create_in(spaced).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        let long = PathBuf::from(format!("/tmp/{}", "a".repeat(MAX_DIR_LEN)));
        assert_eq!(
            RuntimeDir::create_in(&long).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn runtime_dir_base_prefers_a_usable_xdg_path() {
        let tmp = Path::new("/tmp");
        let good = Path::new("/run/user/1000");
        assert_eq!(select_linux_base(Some(good), tmp), good);
        assert_eq!(select_linux_base(None, tmp), tmp);
        assert_eq!(select_linux_base(Some(Path::new("/run/my user")), tmp), tmp);
        assert_eq!(select_linux_base(Some(Path::new("relative")), tmp), tmp);
        let long = PathBuf::from(format!("/{}", "a".repeat(MAX_BASE_LEN)));
        assert_eq!(select_linux_base(Some(&long), tmp), tmp);
    }
}
