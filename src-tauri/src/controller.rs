//! [`AppController`]: every IPC operation as a plain Rust method, testable without a window.
//!
//! The controller owns `config.json`, `known_hosts.json`, `vault.bin`, and the
//! [`SessionManager`]. Secrets only ever flow inward: methods accept [`SecretInput`], which
//! cannot be serialized, and return opaque metadata.

pub mod export;
pub mod keys;
pub mod mitm_ca;
pub mod parity;
pub mod sessions;
#[cfg(test)]
pub(crate) mod test_support;

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use conduit_core::{
    load_app_config, load_known_hosts, save_app_config, save_known_hosts, AppConfig, KeyId,
    KnownHostsStore, SecretRef, SessionProfile, StorageError, ValidateError,
};
use conduit_runtime::{HostKeyPrompt, ManagerConfig, RuntimeError, RuntimeEvent, SessionManager};
use conduit_vault::{Argon2Params, KeyringBackend, OsKeyringBackend, Vault, VaultError};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use tokio::sync::broadcast::error::RecvError;
use uuid::Uuid;
use zeroize::Zeroizing;

use keys::Usage;

/// Current `config.json` schema version.
const SCHEMA_VERSION: u32 = 1;

/// Cost of the throwaway vault used until the user creates a real one. Its password is random
/// and discarded, so it protects nothing and needs no real work factor.
const PLACEHOLDER_ARGON: Argon2Params = Argon2Params {
    memory_kib: 8 * 1024,
    time_cost: 1,
    parallelism: 1,
    derived_key_len: 32,
};

/// A secret arriving from the WebView. Deliberately has no `Serialize` impl, so it cannot be
/// placed in an IPC response. Zeroized on drop.
pub struct SecretInput(Zeroizing<String>);

impl SecretInput {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    fn require_non_empty(&self, what: &str) -> Result<(), AppError> {
        if self.0.is_empty() {
            return Err(AppError::Invalid(format!("{what} must not be empty")));
        }
        Ok(())
    }
}

impl fmt::Debug for SecretInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretInput(<redacted>)")
    }
}

impl<'de> Deserialize<'de> for SecretInput {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

/// A failed controller operation. Serialized to the WebView as `{ code, message, usage? }`.
#[derive(Debug, Error)]
pub enum AppError {
    #[error(transparent)]
    Vault(#[from] VaultError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Validate(#[from] ValidateError),
    #[error(transparent)]
    Runtime(#[from] RuntimeError),
    #[error("the vault has not been created yet")]
    VaultNotInitialized,
    #[error("a vault already exists and will not be overwritten")]
    VaultExists,
    #[error("{kind} not found: {id}")]
    NotFound { kind: &'static str, id: String },
    #[error("a key with fingerprint {fingerprint} is already in the vault")]
    DuplicateKey { fingerprint: String },
    #[error("a MITM CA with fingerprint {fingerprint} is already in the vault")]
    DuplicateCa { fingerprint: String },
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Io(String),
    #[error("background task failed: {0}")]
    Task(String),
}

impl AppError {
    fn code(&self) -> &'static str {
        match self {
            Self::Vault(VaultError::Locked) => "vault_locked",
            Self::Vault(VaultError::UnlockFailed) => "unlock_failed",
            Self::Vault(_) => "vault",
            Self::Storage(_) => "storage",
            Self::Validate(_) => "validation",
            Self::Runtime(_) => "runtime",
            Self::VaultNotInitialized => "vault_not_initialized",
            Self::VaultExists => "vault_exists",
            Self::NotFound { .. } => "not_found",
            Self::DuplicateKey { .. } => "duplicate_key",
            Self::DuplicateCa { .. } => "duplicate_ca",
            Self::Invalid(_) => "invalid",
            Self::Io(_) => "io",
            Self::Task(_) => "task",
        }
    }
}

impl Serialize for AppError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AppError", 2)?;
        state.serialize_field("code", self.code())?;
        state.serialize_field("message", &self.to_string())?;
        state.end()
    }
}

/// Vault state shown to the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct VaultStatus {
    /// `vault.bin` exists.
    pub initialized: bool,
    pub unlocked: bool,
    /// The vault's key is also in the OS keyring, so it can be unlocked without the password.
    pub keyring: bool,
}

/// Opaque result of storing a secret. Never carries the secret itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecretMeta {
    pub secret_ref: SecretRef,
    pub has_secret: bool,
}

/// Construction settings. Tests swap in a memory keyring and cheap Argon2 parameters.
pub struct ControllerOptions {
    pub argon: Argon2Params,
    pub manager: ManagerConfig,
    pub keyring: Arc<dyn KeyringBackend + Send + Sync>,
}

impl Default for ControllerOptions {
    fn default() -> Self {
        Self {
            argon: Argon2Params::BASELINE,
            manager: ManagerConfig::default(),
            keyring: Arc::new(OsKeyringBackend::new()),
        }
    }
}

struct Paths {
    config: PathBuf,
    known_hosts: PathBuf,
    vault: PathBuf,
    /// Present while the vault's key is stored in the OS keyring. Kept next to the vault on this
    /// machine, never exported, so the app knows without reading the keyring (which can prompt).
    vault_keyring: PathBuf,
}

struct Inner {
    paths: Paths,
    argon: Argon2Params,
    keyring: Arc<dyn KeyringBackend + Send + Sync>,
    config: Mutex<AppConfig>,
    known_hosts: Arc<RwLock<KnownHostsStore>>,
    vault: Arc<RwLock<Vault>>,
    manager: SessionManager,
    /// Keeps concurrent saves of `known_hosts.json` in order.
    known_hosts_save: Mutex<()>,
    /// Serializes vault creation and unlocking.
    vault_lifecycle: Mutex<()>,
    /// The unknown key each session's latest chain test saw, so the user can trust exactly it.
    tested_host_keys: Mutex<HashMap<Uuid, HostKeyPrompt>>,
}

/// The application backend. Cloning yields another handle to the same state.
#[derive(Clone)]
pub struct AppController {
    inner: Arc<Inner>,
}

// Guarded values are replaced whole, so a poisoned lock still holds valid data.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Stands in until the user creates a vault, because [`SessionManager`] needs one from the
/// start. It stays locked, has no file on disk, and is replaced by [`AppController::create_vault`].
fn placeholder_vault(dir: &Path) -> Result<Vault, AppError> {
    let path = dir.join(format!(".vault-placeholder-{}.bin", Uuid::new_v4()));
    let password = Zeroizing::new(Uuid::new_v4().to_string());
    let mut vault = Vault::create_with_password(&path, password.as_bytes(), PLACEHOLDER_ARGON)?;
    fs::remove_file(&path).map_err(|e| AppError::Io(format!("failed to remove placeholder: {e}")))?;
    vault.lock();
    Ok(vault)
}

fn create_private_dir(dir: &Path) -> Result<(), AppError> {
    fs::create_dir_all(dir)
        .map_err(|e| AppError::Io(format!("failed to create {}: {e}", dir.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| AppError::Io(format!("failed to secure {}: {e}", dir.display())))?;
    }
    Ok(())
}

/// Vault record ids are UUID strings; `KeyId` and `SecretRef` are their typed forms.
pub(crate) fn key_id_from_record(id: &str) -> Result<KeyId, AppError> {
    serde_json::from_value(serde_json::Value::String(id.to_owned()))
        .map_err(|e| AppError::Invalid(format!("invalid key id: {e}")))
}

pub(crate) fn secret_ref_from_record(id: &str) -> Result<SecretRef, AppError> {
    serde_json::from_value(serde_json::Value::String(id.to_owned()))
        .map_err(|e| AppError::Invalid(format!("invalid secret reference: {e}")))
}

impl AppController {
    /// Opens the app data directory. Existing files are loaded and never overwritten here; a
    /// corrupt file is an error rather than a silent reset.
    pub fn open(app_data_dir: impl AsRef<Path>, options: ControllerOptions) -> Result<Self, AppError> {
        let dir = app_data_dir.as_ref();
        create_private_dir(dir)?;
        let paths = Paths {
            config: dir.join("config.json"),
            known_hosts: dir.join("known_hosts.json"),
            vault: dir.join("vault.bin"),
            vault_keyring: dir.join("vault.keyring"),
        };

        let config = if paths.config.exists() {
            load_app_config(&paths.config)?
        } else {
            AppConfig {
                schema_version: SCHEMA_VERSION,
                ..AppConfig::default()
            }
        };
        let known_hosts = if paths.known_hosts.exists() {
            load_known_hosts(&paths.known_hosts)?
        } else {
            KnownHostsStore::default()
        };
        let vault = if paths.vault.exists() {
            Vault::open_locked(&paths.vault)?
        } else {
            placeholder_vault(dir)?
        };

        let vault = Arc::new(RwLock::new(vault));
        let known_hosts = Arc::new(RwLock::new(known_hosts));
        let manager = SessionManager::new(Arc::clone(&vault), Arc::clone(&known_hosts), options.manager);
        for profile in &config.sessions {
            manager.upsert_profile(profile.clone());
        }

        Ok(Self {
            inner: Arc::new(Inner {
                paths,
                argon: options.argon,
                keyring: options.keyring,
                config: Mutex::new(config),
                known_hosts,
                vault,
                manager,
                known_hosts_save: Mutex::new(()),
                vault_lifecycle: Mutex::new(()),
                tested_host_keys: Mutex::new(HashMap::new()),
            }),
        })
    }

    /// Unknown host keys seen by the latest chain test of each session.
    pub(crate) fn tested_host_keys(&self) -> MutexGuard<'_, HashMap<Uuid, HostKeyPrompt>> {
        lock(&self.inner.tested_host_keys)
    }

    pub(crate) fn manager(&self) -> &SessionManager {
        &self.inner.manager
    }

    /// Reports an OS wake so live sessions are recycled once the burst settles. Must be called
    /// inside a Tokio runtime.
    pub fn notify_system_wake(&self) {
        self.inner.manager.notify_system_wake();
    }

    /// A new stream of runtime events.
    pub fn subscribe_events(&self) -> tokio::sync::broadcast::Receiver<RuntimeEvent> {
        self.inner.manager.subscribe_events()
    }

    pub(crate) fn argon(&self) -> Argon2Params {
        self.inner.argon
    }

    pub(crate) fn vault_read(&self) -> RwLockReadGuard<'_, Vault> {
        self.inner.vault.read().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn vault_write(&self) -> RwLockWriteGuard<'_, Vault> {
        self.inner.vault.write().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn known_hosts(&self) -> &Arc<RwLock<KnownHostsStore>> {
        &self.inner.known_hosts
    }

    /// A copy of the current app document.
    pub(crate) fn config_snapshot(&self) -> AppConfig {
        lock(&self.inner.config).clone()
    }

    /// Applies `change` to a draft, saves it atomically, then publishes it. On any error the
    /// in-memory config and `config.json` are both unchanged.
    pub(crate) fn mutate_config<T>(
        &self,
        change: impl FnOnce(&mut AppConfig) -> Result<T, AppError>,
    ) -> Result<T, AppError> {
        let mut config = lock(&self.inner.config);
        let mut draft = config.clone();
        let output = change(&mut draft)?;
        save_app_config(&self.inner.paths.config, &draft)?;
        *config = draft;
        Ok(output)
    }

    /// Hands updated profiles to the session manager. Running sessions use them on next start.
    pub(crate) fn sync_profiles(&self, profiles: impl IntoIterator<Item = SessionProfile>) {
        for profile in profiles {
            self.inner.manager.upsert_profile(profile);
        }
    }

    /// Atomically saves the current known hosts.
    pub(crate) fn persist_known_hosts(&self) -> Result<(), AppError> {
        let _order = lock(&self.inner.known_hosts_save);
        let snapshot = self
            .inner
            .known_hosts
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        save_known_hosts(&self.inner.paths.known_hosts, &snapshot)?;
        Ok(())
    }

    /// A task that saves `known_hosts.json` whenever the runtime reports a pin change. It
    /// subscribes immediately, so no event after this call is missed.
    pub fn known_hosts_autosave(&self) -> impl Future<Output = ()> + Send + 'static {
        let mut events = self.inner.manager.subscribe_events();
        let controller = self.clone();
        async move {
            loop {
                match events.recv().await {
                    // After a lag an event may have been lost, so save to be safe.
                    Ok(RuntimeEvent::KnownHostsChanged { .. }) | Err(RecvError::Lagged(_)) => {
                        let saver = controller.clone();
                        let saved = tokio::task::spawn_blocking(move || saver.persist_known_hosts()).await;
                        match saved {
                            Ok(Ok(())) => {}
                            Ok(Err(error)) => eprintln!("failed to save known hosts: {error}"),
                            Err(error) => eprintln!("known hosts save task failed: {error}"),
                        }
                    }
                    Ok(_) => {}
                    Err(RecvError::Closed) => break,
                }
            }
        }
    }

    // -----------------------------------------------------------------------------------------
    // Vault lifecycle.
    // -----------------------------------------------------------------------------------------

    pub fn vault_status(&self) -> VaultStatus {
        VaultStatus {
            initialized: self.inner.paths.vault.exists(),
            unlocked: self.vault_read().is_unlocked(),
            keyring: self.inner.paths.vault_keyring.exists(),
        }
    }

    /// Stores the unlocked vault's key in the OS keyring, or removes it. Storing needs the vault
    /// unlocked; removing does not. The master password keeps working either way.
    pub async fn set_vault_keyring(&self, enabled: bool) -> Result<VaultStatus, AppError> {
        let controller = self.clone();
        run_blocking(move || {
            let inner = &controller.inner;
            let _lifecycle = lock(&inner.vault_lifecycle);
            let marker = &inner.paths.vault_keyring;
            if enabled {
                controller.vault_read().store_in_keyring(inner.keyring.as_ref())?;
                fs::write(marker, b"").map_err(|e| {
                    AppError::Io(format!("failed to record the keyring setting: {e}"))
                })?;
            } else {
                controller.vault_read().remove_from_keyring(inner.keyring.as_ref())?;
                match fs::remove_file(marker) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        return Err(AppError::Io(format!(
                            "failed to record the keyring setting: {e}"
                        )))
                    }
                }
            }
            Ok(())
        })
        .await?;
        Ok(self.vault_status())
    }

    /// Creates `vault.bin`, unlocked. With `use_keyring` the key is also stored in the OS
    /// keyring. An existing vault is never overwritten.
    pub async fn create_vault(
        &self,
        password: SecretInput,
        use_keyring: bool,
    ) -> Result<VaultStatus, AppError> {
        password.require_non_empty("master password")?;
        let controller = self.clone();
        run_blocking(move || {
            let inner = &controller.inner;
            let _lifecycle = lock(&inner.vault_lifecycle);
            if inner.paths.vault.exists() {
                return Err(AppError::VaultExists);
            }
            let vault = if use_keyring {
                Vault::create_with_keyring(
                    &inner.paths.vault,
                    inner.keyring.as_ref(),
                    password.as_bytes(),
                    inner.argon,
                )?
            } else {
                Vault::create_with_password(&inner.paths.vault, password.as_bytes(), inner.argon)?
            };
            if use_keyring {
                fs::write(&inner.paths.vault_keyring, b"").map_err(|e| {
                    AppError::Io(format!("failed to record the keyring setting: {e}"))
                })?;
            }
            *controller.vault_write() = vault;
            Ok(())
        })
        .await?;
        self.inner.manager.on_vault_unlocked().await;
        Ok(self.vault_status())
    }

    /// Unlocks with the master password.
    pub async fn unlock_vault_with_password(
        &self,
        password: SecretInput,
    ) -> Result<VaultStatus, AppError> {
        self.unlock_with(move |vault, _| vault.unlock_with_password(password.as_bytes()))
            .await
    }

    /// Unlocks with the key stored in the OS keyring. A missing entry is an error and never
    /// recreates the vault.
    pub async fn unlock_vault_with_keyring(&self) -> Result<VaultStatus, AppError> {
        self.unlock_with(|vault, keyring| vault.unlock_with_keyring(keyring))
            .await
    }

    /// Unlocks a fresh copy of the vault and swaps it in, so slow key derivation never holds
    /// the lock that running sessions read through.
    async fn unlock_with(
        &self,
        unlock: impl FnOnce(&mut Vault, &dyn KeyringBackend) -> Result<(), VaultError> + Send + 'static,
    ) -> Result<VaultStatus, AppError> {
        let controller = self.clone();
        run_blocking(move || {
            let inner = &controller.inner;
            let _lifecycle = lock(&inner.vault_lifecycle);
            if !inner.paths.vault.exists() {
                return Err(AppError::VaultNotInitialized);
            }
            if controller.vault_read().is_unlocked() {
                return Ok(());
            }
            let mut fresh = Vault::open_locked(&inner.paths.vault)?;
            unlock(&mut fresh, inner.keyring.as_ref())?;
            *controller.vault_write() = fresh;
            controller.purge_retired_records();
            Ok(())
        })
        .await?;
        self.inner.manager.on_vault_unlocked().await;
        Ok(self.vault_status())
    }

    /// Deletes vault records no config can refer to any more: MITM CA passphrases, which
    /// earlier betas stored for path-based CAs. Best effort, since they are unreachable anyway.
    fn purge_retired_records(&self) {
        let mut vault = self.vault_write();
        let retired: Vec<String> = vault
            .list_keys()
            .into_iter()
            .filter(|r| r.r#type == keys::RETIRED_PASSPHRASE_RECORD)
            .map(|r| r.id)
            .collect();
        for id in retired {
            if let Err(error) = vault.delete_secret(&id) {
                eprintln!("failed to delete a retired vault record: {error}");
            }
        }
    }

    /// Wipes the in-memory key. Connected sessions stay up; reconnects then wait in `Locked`.
    pub fn lock_vault(&self) -> VaultStatus {
        self.vault_write().lock();
        self.vault_status()
    }
}

/// Runs slow or disk-bound work off the async executor.
pub(crate) async fn run_blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, AppError> + Send + 'static,
) -> Result<T, AppError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| AppError::Task(e.to_string()))?
}

/// `true` when nothing references the key or secret.
pub(crate) fn usage_is_empty(usage: &Usage) -> bool {
    usage.hosts.is_empty() && usage.sessions.is_empty()
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use conduit_core::{HostKeyLookup, HostKeyRecord, Timestamp};
    use std::time::Duration;

    #[tokio::test]
    async fn notify_system_wake_is_callable_without_sessions() {
        let dir = TempDir::new();
        let c = controller(&dir);
        c.notify_system_wake();
        c.notify_system_wake();
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(c.manager().snapshots().is_empty());
    }

    #[tokio::test]
    async fn fresh_directory_has_no_vault_and_writes_nothing() {
        let dir = TempDir::new();
        let c = controller(&dir);
        assert_eq!(
            c.vault_status(),
            VaultStatus { initialized: false, unlocked: false, keyring: false }
        );
        let names: Vec<_> = fs::read_dir(dir.path()).unwrap().collect();
        assert!(names.is_empty(), "opening must leave no files behind");
        assert!(matches!(
            c.unlock_vault_with_password(SecretInput::new("x")).await,
            Err(AppError::VaultNotInitialized)
        ));
    }

    #[tokio::test]
    async fn create_lock_and_unlock_with_password() {
        let dir = TempDir::new();
        let c = controller(&dir);
        let status = c.create_vault(SecretInput::new("master"), false).await.unwrap();
        assert_eq!(status, VaultStatus { initialized: true, unlocked: true, keyring: false });

        assert!(!c.lock_vault().unlocked);
        assert!(matches!(
            c.unlock_vault_with_password(SecretInput::new("wrong")).await,
            Err(AppError::Vault(VaultError::UnlockFailed))
        ));
        assert!(!c.vault_status().unlocked);
        assert!(c
            .unlock_vault_with_password(SecretInput::new("master"))
            .await
            .unwrap()
            .unlocked);
    }

    #[tokio::test]
    async fn keyring_unlock_survives_reopen() {
        let dir = TempDir::new();
        let keyring = Arc::new(conduit_vault::MemoryKeyringBackend::new());
        let c = controller_with_keyring(&dir, keyring.clone());
        c.create_vault(SecretInput::new("master"), true).await.unwrap();
        drop(c);

        let c = controller_with_keyring(&dir, keyring);
        assert_eq!(c.vault_status(), VaultStatus { initialized: true, unlocked: false, keyring: true });
        assert!(c.unlock_vault_with_keyring().await.unwrap().unlocked);
    }

    #[tokio::test]
    async fn keyring_can_be_turned_on_and_off_for_a_password_vault() {
        let dir = TempDir::new();
        let keyring = Arc::new(conduit_vault::MemoryKeyringBackend::new());
        let c = controller_with_keyring(&dir, keyring.clone());
        c.create_vault(SecretInput::new("master"), false).await.unwrap();
        assert!(!c.vault_status().keyring);

        assert!(c.set_vault_keyring(true).await.unwrap().keyring);
        assert!(dir.path().join("vault.keyring").exists());
        c.lock_vault();
        assert!(c.unlock_vault_with_keyring().await.unwrap().unlocked);

        assert!(!c.set_vault_keyring(false).await.unwrap().keyring);
        assert!(!dir.path().join("vault.keyring").exists());
        c.lock_vault();
        assert!(matches!(
            c.unlock_vault_with_keyring().await,
            Err(AppError::Vault(VaultError::KeyringEntryMissing { .. }))
        ));
        assert!(c.unlock_vault_with_password(SecretInput::new("master")).await.unwrap().unlocked);
    }

    #[tokio::test]
    async fn unlock_deletes_retired_mitm_passphrase_records() {
        let dir = TempDir::new();
        let c = controller(&dir);
        c.create_vault(SecretInput::new("master"), false).await.unwrap();
        let retired = c.vault_write().put_secret(keys::RETIRED_PASSPHRASE_RECORD, b"old").unwrap();
        let kept = c.set_password_secret(None, SecretInput::new("pw")).unwrap().secret_ref;
        c.lock_vault();
        c.unlock_vault_with_password(SecretInput::new("master")).await.unwrap();
        assert!(c.record_type(&retired).is_none());
        assert_eq!(c.record_type(&kept.to_string()).as_deref(), Some(keys::PASSWORD_RECORD));
    }

    #[tokio::test]
    async fn missing_keyring_entry_keeps_vault_intact() {
        let dir = TempDir::new();
        let c = controller(&dir);
        c.create_vault(SecretInput::new("master"), false).await.unwrap();
        let before = fs::read(dir.path().join("vault.bin")).unwrap();
        c.lock_vault();
        assert!(matches!(
            c.unlock_vault_with_keyring().await,
            Err(AppError::Vault(VaultError::KeyringEntryMissing { .. }))
        ));
        assert_eq!(before, fs::read(dir.path().join("vault.bin")).unwrap());
    }

    #[tokio::test]
    async fn create_refuses_to_overwrite_existing_vault() {
        let dir = TempDir::new();
        let c = controller(&dir);
        c.create_vault(SecretInput::new("master"), false).await.unwrap();
        let before = fs::read(dir.path().join("vault.bin")).unwrap();
        assert!(matches!(
            c.create_vault(SecretInput::new("other"), false).await,
            Err(AppError::VaultExists)
        ));
        assert_eq!(before, fs::read(dir.path().join("vault.bin")).unwrap());
    }

    #[tokio::test]
    async fn empty_master_password_is_rejected() {
        let dir = TempDir::new();
        let c = controller(&dir);
        assert!(matches!(
            c.create_vault(SecretInput::new(""), false).await,
            Err(AppError::Invalid(_))
        ));
        assert!(!dir.path().join("vault.bin").exists());
    }

    #[tokio::test]
    async fn corrupt_config_is_an_error_and_is_not_replaced() {
        let dir = TempDir::new();
        let path = dir.path().join("config.json");
        fs::write(&path, b"{not json").unwrap();
        assert!(matches!(
            AppController::open(dir.path(), test_options()),
            Err(AppError::Storage(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), b"{not json");
    }

    #[tokio::test]
    async fn failed_mutation_changes_nothing() {
        let dir = TempDir::new();
        let c = controller(&dir);
        let result: Result<(), AppError> = c.mutate_config(|config| {
            config.schema_version = 99;
            Err(AppError::Invalid("stop".into()))
        });
        assert!(result.is_err());
        assert_eq!(c.config_snapshot().schema_version, SCHEMA_VERSION);
        assert!(!dir.path().join("config.json").exists());
    }

    #[tokio::test]
    async fn config_mutations_persist_across_reopen() {
        let dir = TempDir::new();
        let c = controller(&dir);
        c.mutate_config(|config| {
            config.sessions.push(profile("persisted", 22));
            Ok(())
        })
        .unwrap();
        drop(c);
        let c = controller(&dir);
        assert_eq!(c.config_snapshot().sessions[0].name, "persisted");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn data_directory_and_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new();
        let data = dir.path().join("nested");
        let c = AppController::open(&data, test_options()).unwrap();
        c.create_vault(SecretInput::new("master"), false).await.unwrap();
        c.mutate_config(|_| Ok(())).unwrap();
        let mode = |p: PathBuf| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(data.clone()), 0o700);
        assert_eq!(mode(data.join("vault.bin")), 0o600);
        assert_eq!(mode(data.join("config.json")), 0o600);
    }

    #[tokio::test]
    async fn persist_known_hosts_round_trips() {
        let dir = TempDir::new();
        let c = controller(&dir);
        c.known_hosts().write().unwrap().insert(
            HostKeyLookup { hop_id: "h".into(), host: "example".into(), port: 22 },
            HostKeyRecord {
                algorithm: "ssh-ed25519".into(),
                fingerprint_sha256: "SHA256:abc".into(),
                first_seen: Timestamp(1),
                approved: true,
                public_key_openssh: None,
            },
        );
        c.persist_known_hosts().unwrap();
        drop(c);
        let c = controller(&dir);
        assert!(c.known_hosts().read().unwrap().contains_key("h", "example", 22));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn autosave_writes_known_hosts_after_host_key_approval() {
        let dir = TempDir::new();
        let node = spawn_node().await;
        let c = controller(&dir);
        let saver = tokio::spawn(c.known_hosts_autosave());

        let session = node.session("autosave");
        let id = session.id;
        c.mutate_config(|config| {
            config.sessions.push(session.clone());
            Ok(())
        })
        .unwrap();
        c.sync_profiles([session]);
        c.manager().start(id).await.unwrap();
        let prompt = wait_for_prompt(&c, id).await;

        // Bypass the controller's own save so only the event listener can write the file.
        c.manager().approve_host_key(id, &prompt.sha256).unwrap();
        let path = dir.path().join("known_hosts.json");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !path.exists() {
            assert!(tokio::time::Instant::now() < deadline, "autosave never ran");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let saved = load_known_hosts(&path).unwrap();
        assert!(saved.get(&prompt.hop_id, &prompt.host, prompt.port).unwrap().approved);

        c.manager().stop(id).await.unwrap();
        saver.abort();
    }
}
