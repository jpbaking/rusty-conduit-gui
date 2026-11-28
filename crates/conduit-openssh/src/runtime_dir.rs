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
/// Empty file in every runtime directory, so the startup sweep only removes directories this
/// app created (the macOS base is the shared `/tmp`).
const RUNTIME_MARKER: &str = ".rusty-conduit-runtime";

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

    /// Creates `<base>/rc-<short_hex>`, mode `0700` on Unix, holding the sweep marker.
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
                Ok(()) => {
                    // On failure, dropping `dir` removes the new directory again.
                    let dir = Self { path };
                    write_private_file(&dir.path.join(RUNTIME_MARKER), b"")?;
                    return Ok(dir);
                }
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

/// Removes the runtime directories a crashed app left in the default base (its `Drop` never
/// ran). Call once at startup, before any session starts; the single-instance guard ensures no
/// other instance is using them. Returns how many were removed.
pub fn sweep_stale_runtime_dirs() -> io::Result<usize> {
    sweep_in(&default_base()?)
}

/// Removes every `<base>/rc-<8 lowercase hex>` directory that holds the runtime marker and,
/// on Unix, is owned by the current user. Anything else is left alone.
pub fn sweep_in(base: &Path) -> io::Result<usize> {
    let entries = match fs::read_dir(base) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if entry.file_name().to_str().is_some_and(is_runtime_dir_name)
            && is_own_dir(&path)
            && fs::symlink_metadata(path.join(RUNTIME_MARKER)).is_ok_and(|m| m.is_file())
            && fs::remove_dir_all(&path).is_ok()
        {
            removed += 1;
        }
    }
    Ok(removed)
}

/// `rc-` followed by exactly the 8 lowercase hex characters [`RuntimeDir::create_in`] writes.
fn is_runtime_dir_name(name: &str) -> bool {
    name.strip_prefix("rc-").is_some_and(|hex| {
        hex.len() == 8 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// A real directory (not a symlink), owned by the current user on Unix.
fn is_own_dir(path: &Path) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: `getuid` has no preconditions.
        if meta.uid() != unsafe { libc::getuid() } {
            return false;
        }
    }
    meta.is_dir()
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
#[cfg(unix)]
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
    fn runtime_dir_sweep_removes_only_marked_stale_dirs() {
        let base = RuntimeDir::create().unwrap();
        let base = base.path();
        let stale = base.join("rc-0a1b2c3d");
        create_private_dir(&stale).unwrap();
        fs::write(stale.join(RUNTIME_MARKER), b"").unwrap();
        fs::write(stale.join("agent.sock"), b"x").unwrap();
        // No marker: a same-named directory this app did not create.
        create_private_dir(&base.join("rc-0a1b2c3e")).unwrap();
        // Marked, but the name does not match.
        for name in ["rc-xyz", "rc-0a1b2c3d0", "other"] {
            create_private_dir(&base.join(name)).unwrap();
            fs::write(base.join(name).join(RUNTIME_MARKER), b"").unwrap();
        }
        fs::write(base.join("rc-01234567"), b"plain file").unwrap();

        assert_eq!(sweep_in(base).unwrap(), 1);
        assert!(!stale.exists());
        for name in [
            "rc-0a1b2c3e",
            "rc-xyz",
            "rc-0a1b2c3d0",
            "other",
            "rc-01234567",
        ] {
            assert!(base.join(name).exists(), "{name} was removed");
        }
        assert_eq!(sweep_in(&base.join("missing")).unwrap(), 0);
    }

    #[test]
    fn runtime_dir_holds_the_sweep_marker() {
        let base = RuntimeDir::create().unwrap();
        let dir = RuntimeDir::create_in(base.path()).unwrap();
        assert!(dir.path().join(RUNTIME_MARKER).is_file());
        let name = dir.path().file_name().unwrap().to_str().unwrap();
        assert!(is_runtime_dir_name(name), "{name}");
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

    #[cfg(unix)]
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
