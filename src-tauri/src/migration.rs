//! One-time upgrade migration from `Rusty Conduit (SSH)` (`io.github.rusty-conduit-ssh-gui`)
//! to `Rusty Conduit GUI` (`io.github.rusty-conduit-gui`). See `docs/MASTER-PLAN.md` §3.3.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use ring::digest::{Context, SHA256};

use crate::commands::AutostartControl;

pub const OLD_BUNDLE_ID: &str = "io.github.rusty-conduit-ssh-gui";
pub const NEW_BUNDLE_ID: &str = "io.github.rusty-conduit-gui";
pub const OLD_APP_NAME: &str = "Rusty Conduit (SSH)";
pub const NEW_APP_NAME: &str = "Rusty Conduit GUI";
pub const OLD_BINARY_NAME: &str = "rusty-conduit-ssh-gui";
pub const OLD_AUTOSTART_NAME: &str = "rusty-conduit-ssh-gui";

/// One-time banner shown after migrating an existing v0.1.0 profile.
pub const MIGRATED_BANNER: &str =
    "Rusty Conduit (SSH) is now Rusty Conduit GUI. Your sessions, vault, and settings were migrated.";

/// Banner shown when both old and non-empty new data directories exist.
pub const NON_EMPTY_CONFLICT_BANNER: &str =
    "Rusty Conduit (SSH) data was found, but the Rusty Conduit GUI data folder is already in use. Existing files were kept without merging.";

/// Outcome of the data-directory migration step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataDirMigration {
    /// Fresh install or already migrated: no old data directory existed.
    None,
    /// Moved the old data directory to the new path.
    Migrated { cross_volume: bool },
    /// Both directories exist and the new one is non-empty; refused to merge.
    SkippedNonEmpty { old_dir: PathBuf, new_dir: PathBuf },
}

impl DataDirMigration {
    /// Returns `(message, is_warning)` for the one-time UI banner, if any.
    pub fn banner(&self) -> Option<(String, bool)> {
        match self {
            Self::None => None,
            Self::Migrated { .. } => Some((MIGRATED_BANNER.to_string(), false)),
            Self::SkippedNonEmpty { .. } => Some((NON_EMPTY_CONFLICT_BANNER.to_string(), true)),
        }
    }
}

/// Fatal startup migration errors.
#[derive(Debug)]
pub enum MigrationError {
    OldInstanceRunning,
    Io(String),
}

impl fmt::Display for MigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OldInstanceRunning => write!(
                f,
                "{OLD_APP_NAME} is still running. Please quit it before starting {NEW_APP_NAME} so both apps do not bind the same ports or write the same vault."
            ),
            Self::Io(message) => write!(f, "upgrade migration failed: {message}"),
        }
    }
}

impl std::error::Error for MigrationError {}

/// Derives the legacy `io.github.rusty-conduit-ssh-gui` data directory sibling to `new_dir`.
pub fn legacy_data_dir_for(new_dir: &Path) -> Option<PathBuf> {
    let name = new_dir.file_name()?.to_str()?;
    if name == OLD_BUNDLE_ID {
        return None;
    }
    Some(new_dir.parent()?.join(OLD_BUNDLE_ID))
}

/// Refuses to start if the legacy `Rusty Conduit (SSH)` process is still running.
pub fn ensure_old_instance_not_running_with(
    is_running: impl FnOnce() -> bool,
) -> Result<(), MigrationError> {
    if is_running() {
        return Err(MigrationError::OldInstanceRunning);
    }
    Ok(())
}

/// Refuses to start if the legacy `Rusty Conduit (SSH)` process is currently running on this OS.
pub fn ensure_old_instance_not_running() -> Result<(), MigrationError> {
    ensure_old_instance_not_running_with(is_old_app_running)
}

#[cfg(target_os = "linux")]
fn is_old_app_running() -> bool {
    let my_pid = std::process::id().to_string();
    let Ok(entries) = fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid_str) = name.to_str() else {
            continue;
        };
        if pid_str == my_pid || !pid_str.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        if let Ok(cmdline) = fs::read(entry.path().join("cmdline")) {
            if let Some(argv0) = cmdline.split(|&b| b == 0).next() {
                if let Ok(s) = std::str::from_utf8(argv0) {
                    if Path::new(s).file_name().and_then(|n| n.to_str()) == Some(OLD_BINARY_NAME) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

#[cfg(target_os = "macos")]
fn is_old_app_running() -> bool {
    let mut cmd = std::process::Command::new("pgrep");
    cmd.args(["-x", OLD_BINARY_NAME]);
    crate::platform::sanitize_child_env(&mut cmd);
    cmd.output().map(|o| o.status.success()).unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn is_old_app_running() -> bool {
    let image = format!("{OLD_BINARY_NAME}.exe");
    let mut cmd = std::process::Command::new("tasklist");
    cmd.args(["/FI", &format!("IMAGENAME eq {image}"), "/NH"]);
    crate::platform::sanitize_child_env(&mut cmd);
    cmd.output()
        .map(|o| {
            o.status.success()
                && String::from_utf8_lossy(&o.stdout)
                    .to_ascii_lowercase()
                    .contains(&image.to_ascii_lowercase())
        })
        .unwrap_or(false)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn is_old_app_running() -> bool {
    false
}

/// Migrates the legacy data directory sibling to `new_dir`, if present.
pub fn migrate_data_dir(new_dir: &Path) -> Result<DataDirMigration, MigrationError> {
    let Some(old_dir) = legacy_data_dir_for(new_dir) else {
        return Ok(DataDirMigration::None);
    };
    migrate_data_dir_paths(&old_dir, new_dir, |from, to| fs::rename(from, to))
}

/// Core data-dir migration with an injectable rename function so tests can exercise the
/// cross-volume copy-verify-remove fallback deterministically.
pub fn migrate_data_dir_paths(
    old_dir: &Path,
    new_dir: &Path,
    rename_fn: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> Result<DataDirMigration, MigrationError> {
    if !old_dir.is_dir() {
        return Ok(DataDirMigration::None);
    }

    if new_dir.exists() {
        let is_empty = fs::read_dir(new_dir)
            .map_err(|e| MigrationError::Io(format!("read {}: {e}", new_dir.display())))?
            .next()
            .is_none();
        if !is_empty {
            return Ok(DataDirMigration::SkippedNonEmpty {
                old_dir: old_dir.to_path_buf(),
                new_dir: new_dir.to_path_buf(),
            });
        }
        fs::remove_dir(new_dir)
            .map_err(|e| MigrationError::Io(format!("remove empty {}: {e}", new_dir.display())))?;
    } else if let Some(parent) = new_dir.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| MigrationError::Io(format!("create parent {}: {e}", parent.display())))?;
    }

    match rename_fn(old_dir, new_dir) {
        Ok(()) => {
            enforce_owner_only_dir(new_dir)?;
            Ok(DataDirMigration::Migrated { cross_volume: false })
        }
        Err(rename_err) if is_cross_device_error(&rename_err) => {
            copy_verify_remove(old_dir, new_dir)?;
            Ok(DataDirMigration::Migrated { cross_volume: true })
        }
        Err(err) => Err(MigrationError::Io(format!(
            "move {} to {}: {err}",
            old_dir.display(),
            new_dir.display()
        ))),
    }
}

fn is_cross_device_error(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::CrossesDevices
}

fn copy_verify_remove(old_dir: &Path, new_dir: &Path) -> Result<(), MigrationError> {
    let parent = new_dir.parent().ok_or_else(|| {
        MigrationError::Io(format!("{} has no parent directory", new_dir.display()))
    })?;
    let staging = parent.join(format!(".{NEW_BUNDLE_ID}.migrate-{}", std::process::id()));
    if staging.exists() {
        let _ = fs::remove_dir_all(&staging);
    }

    let copy_result = copy_tree(old_dir, &staging).and_then(|()| verify_trees_match(old_dir, &staging));
    if let Err(err) = copy_result {
        let _ = fs::remove_dir_all(&staging);
        return Err(err);
    }

    if let Err(err) = fs::rename(&staging, new_dir) {
        let _ = fs::remove_dir_all(&staging);
        return Err(MigrationError::Io(format!(
            "finalize staged migration into {}: {err}",
            new_dir.display()
        )));
    }

    fs::remove_dir_all(old_dir)
        .map_err(|e| MigrationError::Io(format!("remove old dir {}: {e}", old_dir.display())))?;
    Ok(())
}

fn copy_tree(src: &Path, dst: &Path) -> Result<(), MigrationError> {
    fs::create_dir_all(dst)
        .map_err(|e| MigrationError::Io(format!("create {}: {e}", dst.display())))?;
    enforce_owner_only_dir(dst)?;

    for entry in fs::read_dir(src)
        .map_err(|e| MigrationError::Io(format!("read {}: {e}", src.display())))?
    {
        let entry = entry.map_err(|e| MigrationError::Io(format!("dir entry: {e}")))?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let file_type = entry
            .file_type()
            .map_err(|e| MigrationError::Io(format!("stat {}: {e}", src_path.display())))?;

        if file_type.is_dir() {
            copy_tree(&src_path, &dst_path)?;
        } else if file_type.is_file() {
            fs::copy(&src_path, &dst_path).map_err(|e| {
                MigrationError::Io(format!(
                    "copy {} to {}: {e}",
                    src_path.display(),
                    dst_path.display()
                ))
            })?;
            enforce_owner_only_file(&dst_path)?;
        }
    }
    Ok(())
}

fn verify_trees_match(src: &Path, dst: &Path) -> Result<(), MigrationError> {
    for entry in fs::read_dir(src)
        .map_err(|e| MigrationError::Io(format!("verify read {}: {e}", src.display())))?
    {
        let entry = entry.map_err(|e| MigrationError::Io(format!("verify entry: {e}")))?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let file_type = entry
            .file_type()
            .map_err(|e| MigrationError::Io(format!("verify stat {}: {e}", src_path.display())))?;

        if file_type.is_dir() {
            if !dst_path.is_dir() {
                return Err(MigrationError::Io(format!(
                    "missing migrated directory {}",
                    dst_path.display()
                )));
            }
            verify_trees_match(&src_path, &dst_path)?;
        } else if file_type.is_file() && sha256_file(&src_path)? != sha256_file(&dst_path)? {
            return Err(MigrationError::Io(format!(
                "checksum mismatch for {}",
                dst_path.display()
            )));
        }
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<Vec<u8>, MigrationError> {
    let mut file = fs::File::open(path)
        .map_err(|e| MigrationError::Io(format!("open {}: {e}", path.display())))?;
    let mut ctx = Context::new(&SHA256);
    let mut buf = [0u8; 8192];
    loop {
        let n = io::Read::read(&mut file, &mut buf)
            .map_err(|e| MigrationError::Io(format!("read {}: {e}", path.display())))?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    Ok(ctx.finish().as_ref().to_vec())
}

#[cfg(unix)]
fn enforce_owner_only_dir(path: &Path) -> Result<(), MigrationError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|e| MigrationError::Io(format!("chmod 0700 {}: {e}", path.display())))
}

#[cfg(not(unix))]
fn enforce_owner_only_dir(_path: &Path) -> Result<(), MigrationError> {
    Ok(())
}

#[cfg(unix)]
fn enforce_owner_only_file(path: &Path) -> Result<(), MigrationError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| MigrationError::Io(format!("chmod 0600 {}: {e}", path.display())))
}

#[cfg(not(unix))]
fn enforce_owner_only_file(_path: &Path) -> Result<(), MigrationError> {
    Ok(())
}

/// Abstraction for migrating a legacy login autostart registration.
pub trait LegacyAutostart {
    fn is_legacy_enabled(&self) -> Result<bool, String>;
    fn disable_legacy(&self) -> Result<(), String>;
    fn enable_current(&self) -> Result<(), String>;
}

/// If login autostart was enabled under `rusty-conduit-ssh-gui`, enables `rusty-conduit-gui`
/// first and then removes the old registration. Returns `Ok(true)` if migrated.
pub fn migrate_autostart(backend: &dyn LegacyAutostart) -> Result<bool, String> {
    if !backend.is_legacy_enabled()? {
        return Ok(false);
    }
    backend.enable_current()?;
    backend.disable_legacy()?;
    Ok(true)
}

/// OS-backed legacy autostart adapter paired with the current `AutostartControl`.
pub struct OsLegacyAutostart<'a> {
    current: &'a dyn AutostartControl,
}

impl<'a> OsLegacyAutostart<'a> {
    pub fn new(current: &'a dyn AutostartControl) -> Self {
        Self { current }
    }
}

#[cfg(target_os = "linux")]
fn legacy_autostart_files() -> Vec<PathBuf> {
    let config_dir = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));
    match config_dir {
        Some(dir) => vec![dir.join("autostart").join(format!("{OLD_AUTOSTART_NAME}.desktop"))],
        None => Vec::new(),
    }
}

#[cfg(target_os = "macos")]
fn legacy_autostart_files() -> Vec<PathBuf> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Vec::new();
    };
    let agents = home.join("Library/LaunchAgents");
    vec![
        agents.join(format!("{OLD_AUTOSTART_NAME}.plist")),
        agents.join(format!("{OLD_BUNDLE_ID}.plist")),
    ]
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl LegacyAutostart for OsLegacyAutostart<'_> {
    fn is_legacy_enabled(&self) -> Result<bool, String> {
        Ok(legacy_autostart_files().iter().any(|p| p.exists()))
    }

    fn disable_legacy(&self) -> Result<(), String> {
        for path in legacy_autostart_files() {
            if path.exists() {
                fs::remove_file(&path)
                    .map_err(|e| format!("remove legacy autostart {}: {e}", path.display()))?;
            }
        }
        Ok(())
    }

    fn enable_current(&self) -> Result<(), String> {
        self.current.set_enabled(true)
    }
}

#[cfg(target_os = "windows")]
impl LegacyAutostart for OsLegacyAutostart<'_> {
    fn is_legacy_enabled(&self) -> Result<bool, String> {
        let mut cmd = std::process::Command::new("reg");
        cmd.args([
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            OLD_AUTOSTART_NAME,
        ]);
        crate::platform::sanitize_child_env(&mut cmd);
        let output = cmd.output().map_err(|e| e.to_string())?;
        Ok(output.status.success())
    }

    fn disable_legacy(&self) -> Result<(), String> {
        let mut cmd = std::process::Command::new("reg");
        cmd.args([
            "delete",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            OLD_AUTOSTART_NAME,
            "/f",
        ]);
        crate::platform::sanitize_child_env(&mut cmd);
        let output = cmd.output().map_err(|e| e.to_string())?;
        if output.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
        }
    }

    fn enable_current(&self) -> Result<(), String> {
        self.current.set_enabled(true)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
impl LegacyAutostart for OsLegacyAutostart<'_> {
    fn is_legacy_enabled(&self) -> Result<bool, String> {
        Ok(false)
    }

    fn disable_legacy(&self) -> Result<(), String> {
        Ok(())
    }

    fn enable_current(&self) -> Result<(), String> {
        self.current.set_enabled(true)
    }
}

/// Runs the OS autostart migration using `current` to register the new entry.
pub fn migrate_os_autostart(current: &dyn AutostartControl) -> Result<bool, String> {
    migrate_autostart(&OsLegacyAutostart::new(current))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::test_support::TempDir;
    use std::cell::RefCell;

    #[test]
    fn migration_fresh_install_is_noop() {
        let root = TempDir::new();
        let new_dir = root.path().join(NEW_BUNDLE_ID);
        let outcome = migrate_data_dir(&new_dir).unwrap();
        assert_eq!(outcome, DataDirMigration::None);
        assert!(outcome.banner().is_none());
        assert!(!new_dir.exists());
    }

    #[test]
    fn migration_same_volume_upgrade_moves_files_and_sets_owner_permissions() {
        let root = TempDir::new();
        let old_dir = root.path().join(OLD_BUNDLE_ID);
        let new_dir = root.path().join(NEW_BUNDLE_ID);
        fs::create_dir_all(old_dir.join("nested")).unwrap();
        fs::write(old_dir.join("vault.bin"), b"encrypted-vault").unwrap();
        fs::write(old_dir.join("nested/config.json"), b"{\"v\":1}").unwrap();

        let outcome = migrate_data_dir(&new_dir).unwrap();
        assert_eq!(outcome, DataDirMigration::Migrated { cross_volume: false });
        assert_eq!(outcome.banner(), Some((MIGRATED_BANNER.to_string(), false)));
        assert!(!old_dir.exists());
        assert_eq!(fs::read(new_dir.join("vault.bin")).unwrap(), b"encrypted-vault");
        assert_eq!(fs::read(new_dir.join("nested/config.json")).unwrap(), b"{\"v\":1}");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&new_dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
        }
    }

    #[test]
    fn migration_cross_volume_fallback_copies_verifies_and_removes_old() {
        let root = TempDir::new();
        let old_dir = root.path().join(OLD_BUNDLE_ID);
        let new_dir = root.path().join(NEW_BUNDLE_ID);
        fs::create_dir_all(old_dir.join("sub")).unwrap();
        fs::write(old_dir.join("vault.bin"), b"vault-bytes-12345").unwrap();
        fs::write(old_dir.join("sub/known_hosts.json"), b"[]").unwrap();

        let outcome = migrate_data_dir_paths(&old_dir, &new_dir, |_from, _to| {
            Err(io::Error::new(io::ErrorKind::CrossesDevices, "simulated EXDEV"))
        })
        .unwrap();

        assert_eq!(outcome, DataDirMigration::Migrated { cross_volume: true });
        assert_eq!(outcome.banner(), Some((MIGRATED_BANNER.to_string(), false)));
        assert!(!old_dir.exists());
        assert_eq!(fs::read(new_dir.join("vault.bin")).unwrap(), b"vault-bytes-12345");
        assert_eq!(fs::read(new_dir.join("sub/known_hosts.json")).unwrap(), b"[]");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_mode = fs::metadata(&new_dir).unwrap().permissions().mode() & 0o777;
            let file_mode = fs::metadata(new_dir.join("vault.bin")).unwrap().permissions().mode() & 0o777;
            assert_eq!(dir_mode, 0o700);
            assert_eq!(file_mode, 0o600);
        }
    }

    #[test]
    fn migration_non_empty_new_dir_never_merges_and_returns_warning_banner() {
        let root = TempDir::new();
        let old_dir = root.path().join(OLD_BUNDLE_ID);
        let new_dir = root.path().join(NEW_BUNDLE_ID);
        fs::create_dir_all(&old_dir).unwrap();
        fs::create_dir_all(&new_dir).unwrap();
        fs::write(old_dir.join("vault.bin"), b"old-vault").unwrap();
        fs::write(new_dir.join("vault.bin"), b"new-vault").unwrap();

        let outcome = migrate_data_dir(&new_dir).unwrap();
        assert_eq!(
            outcome,
            DataDirMigration::SkippedNonEmpty { old_dir: old_dir.clone(), new_dir: new_dir.clone() }
        );
        assert_eq!(outcome.banner(), Some((NON_EMPTY_CONFLICT_BANNER.to_string(), true)));
        // Neither directory was overwritten or deleted.
        assert_eq!(fs::read(old_dir.join("vault.bin")).unwrap(), b"old-vault");
        assert_eq!(fs::read(new_dir.join("vault.bin")).unwrap(), b"new-vault");
    }

    #[test]
    fn migration_old_instance_running_refuses_startup() {
        let err = ensure_old_instance_not_running_with(|| true).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains(OLD_APP_NAME), "missing old app name in: {msg}");
        assert!(msg.contains(NEW_APP_NAME), "missing new app name in: {msg}");

        assert!(ensure_old_instance_not_running_with(|| false).is_ok());
    }

    struct FakeLegacyAutostart {
        legacy_enabled: bool,
        events: RefCell<Vec<&'static str>>,
    }

    impl LegacyAutostart for FakeLegacyAutostart {
        fn is_legacy_enabled(&self) -> Result<bool, String> {
            Ok(self.legacy_enabled)
        }

        fn disable_legacy(&self) -> Result<(), String> {
            self.events.borrow_mut().push("disable_legacy");
            Ok(())
        }

        fn enable_current(&self) -> Result<(), String> {
            self.events.borrow_mut().push("enable_current");
            Ok(())
        }
    }

    #[test]
    fn migration_autostart_enables_new_then_disables_old_only_when_legacy_was_enabled() {
        let inactive = FakeLegacyAutostart { legacy_enabled: false, events: RefCell::new(Vec::new()) };
        assert!(!migrate_autostart(&inactive).unwrap());
        assert!(inactive.events.borrow().is_empty());

        let active = FakeLegacyAutostart { legacy_enabled: true, events: RefCell::new(Vec::new()) };
        assert!(migrate_autostart(&active).unwrap());
        assert_eq!(*active.events.borrow(), vec!["enable_current", "disable_legacy"]);
    }
}
