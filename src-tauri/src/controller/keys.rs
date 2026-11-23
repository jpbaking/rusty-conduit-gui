//! Key-vault and write-only secret operations.

use std::fs;
use std::path::{Path, PathBuf};

use conduit_core::{
    AppConfig, AuthMethod, KeyId, KeySource, SecretRef, SessionProfile, Timestamp, VaultKeyMeta,
};
use conduit_vault::{BackupKey, KeyGenAlgorithm, KeyInfo, VaultError};
use russh::keys::ssh_key::LineEnding;
use russh::keys::PrivateKey;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use super::{
    key_id_from_record, secret_ref_from_record, usage_is_empty, AppController, AppError,
    SecretInput, SecretMeta,
};

const KEY_RECORD: &str = "key";
const PASSWORD_RECORD: &str = "password";
const PASSPHRASE_RECORD: &str = "passphrase";

/// A host or session that references a key or secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UsageRef {
    pub id: Uuid,
    pub name: String,
}

/// Everything referencing a key or secret.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Usage {
    pub hosts: Vec<UsageRef>,
    pub sessions: Vec<UsageRef>,
}

/// A vault key with its "Used by N" indicator. Contains no private material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyView {
    #[serde(flatten)]
    pub meta: VaultKeyMeta,
    pub used_by: usize,
    pub usage: Usage,
}

/// Outcome of a delete. When something still references the item and `force` was not set,
/// `deleted` is `false` and `usage` lists what the UI should warn about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeleteResult {
    pub deleted: bool,
    pub used_by: usize,
    pub usage: Usage,
}

/// Algorithms offered by the in-app generator.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GenerateAlgorithm {
    #[default]
    Ed25519,
    EcdsaP256,
}

/// Result of writing a backup bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BackupSummary {
    pub path: PathBuf,
    pub key_count: usize,
}

/// Result of restoring a backup bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportBackupResult {
    pub imported: Vec<VaultKeyMeta>,
    /// Keys already present, matched by fingerprint.
    pub skipped: usize,
}

fn usage_of(config: &AppConfig, uses: impl Fn(&AuthMethod) -> bool) -> Usage {
    let hosts = config
        .hosts
        .iter()
        .filter(|h| h.auth.iter().any(&uses))
        .map(|h| UsageRef { id: h.id, name: h.name.clone() })
        .collect();
    let sessions = config
        .sessions
        .iter()
        .filter(|s| s.hops.iter().any(|hop| hop.host.auth.iter().any(&uses)))
        .map(|s| UsageRef { id: s.id, name: s.name.clone() })
        .collect();
    Usage { hosts, sessions }
}

fn key_usage(config: &AppConfig, id: &KeyId) -> Usage {
    usage_of(config, |m| matches!(m, AuthMethod::Key { key } if key == id))
}

fn mitm_uses(session: &SessionProfile, secret: &SecretRef) -> bool {
    session
        .mitm
        .as_ref()
        .is_some_and(|m| m.passphrase.as_ref() == Some(secret))
}

fn secret_usage(config: &AppConfig, secret: &SecretRef) -> Usage {
    let mut usage = usage_of(config, |m| matches!(m, AuthMethod::Password { secret: s } if s == secret));
    for session in &config.sessions {
        if mitm_uses(session, secret) && !usage.sessions.iter().any(|u| u.id == session.id) {
            usage.sessions.push(UsageRef { id: session.id, name: session.name.clone() });
        }
    }
    usage
}

/// Applies `edit` to every host's and hop's auth list, returning the sessions it changed.
fn edit_auth(config: &mut AppConfig, edit: impl Fn(&mut Vec<AuthMethod>)) -> Vec<SessionProfile> {
    for host in &mut config.hosts {
        edit(&mut host.auth);
    }
    let mut changed = Vec::new();
    for session in &mut config.sessions {
        let before = session.hops.clone();
        for hop in &mut session.hops {
            edit(&mut hop.host.auth);
        }
        if session.hops != before {
            changed.push(session.clone());
        }
    }
    changed
}

fn require_name(name: &str) -> Result<String, AppError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(AppError::Invalid("name must not be empty".into()));
    }
    Ok(name.to_owned())
}

fn source_label(source: KeySource) -> &'static str {
    match source {
        KeySource::Uploaded => "Uploaded",
        KeySource::Pasted => "Pasted",
        KeySource::Generated => "Generated",
    }
}

fn parse_source(label: &str) -> KeySource {
    match label {
        "Pasted" => KeySource::Pasted,
        "Generated" => KeySource::Generated,
        _ => KeySource::Uploaded,
    }
}

/// Writes `bytes` beside `path`, owner-only, then renames over it.
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), AppError> {
    use std::io::Write;
    let io_error = |e: std::io::Error| AppError::Io(format!("failed to write {}: {e}", path.display()));
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let temp = dir.join(format!(".conduit-backup-{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.map_err(io_error)
}

impl AppController {
    /// Stores a normalized key and records its metadata. Rolls the vault back if saving fails.
    fn store_key(
        &self,
        name: String,
        key: &PrivateKey,
        info: KeyInfo,
        source: KeySource,
        created_at: Timestamp,
    ) -> Result<VaultKeyMeta, AppError> {
        if self
            .config_snapshot()
            .keys
            .iter()
            .any(|k| k.fingerprint_sha256 == info.fingerprint_sha256)
        {
            return Err(AppError::DuplicateKey { fingerprint: info.fingerprint_sha256 });
        }
        let pem = key
            .to_openssh(LineEnding::LF)
            .map_err(|e| VaultError::Crypto { reason: format!("failed to encode key: {e}") })?;
        let record = self.vault_write().put_secret(KEY_RECORD, pem.as_bytes())?;
        let meta = VaultKeyMeta {
            id: key_id_from_record(&record)?,
            name,
            algorithm: info.algorithm,
            fingerprint_sha256: info.fingerprint_sha256,
            public_key_openssh: info.public_key_openssh,
            source,
            created_at,
        };
        let stored = meta.clone();
        if let Err(error) = self.mutate_config(move |config| {
            config.keys.push(stored);
            Ok(())
        }) {
            let _ = self.vault_write().delete_secret(&record);
            return Err(error);
        }
        Ok(meta)
    }

    /// Validates, decrypts if needed, and vaults a pasted or uploaded private key.
    pub fn import_key_pem(
        &self,
        name: &str,
        pem: SecretInput,
        passphrase: Option<SecretInput>,
        source: KeySource,
    ) -> Result<VaultKeyMeta, AppError> {
        let name = require_name(name)?;
        if source == KeySource::Generated {
            return Err(AppError::Invalid("an imported key cannot have source Generated".into()));
        }
        if !self.vault_read().is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        let (key, info) =
            conduit_vault::import_key(pem.as_str(), passphrase.as_ref().map(SecretInput::as_bytes))?;
        self.store_key(name, &key, info, source, Timestamp::now())
    }

    /// Generates a keypair in the vault. Only the public half is returned.
    pub fn generate_key(
        &self,
        name: &str,
        algorithm: GenerateAlgorithm,
    ) -> Result<VaultKeyMeta, AppError> {
        let name = require_name(name)?;
        if !self.vault_read().is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        let algorithm = match algorithm {
            GenerateAlgorithm::Ed25519 => KeyGenAlgorithm::Ed25519,
            GenerateAlgorithm::EcdsaP256 => KeyGenAlgorithm::EcdsaP256,
        };
        let (key, info) = conduit_vault::generate_key(algorithm)?;
        self.store_key(name, &key, info, KeySource::Generated, Timestamp::now())
    }

    pub fn rename_key(&self, id: &KeyId, name: &str) -> Result<VaultKeyMeta, AppError> {
        let name = require_name(name)?;
        self.mutate_config(|config| {
            let key = config
                .keys
                .iter_mut()
                .find(|k| k.id == *id)
                .ok_or_else(|| AppError::NotFound { kind: "key", id: id.to_string() })?;
            key.name = name;
            Ok(key.clone())
        })
    }

    pub fn list_keys(&self) -> Vec<KeyView> {
        let config = self.config_snapshot();
        config
            .keys
            .iter()
            .map(|meta| {
                let usage = key_usage(&config, &meta.id);
                KeyView {
                    meta: meta.clone(),
                    used_by: usage.hosts.len() + usage.sessions.len(),
                    usage,
                }
            })
            .collect()
    }

    /// Deletes a key. If it is referenced and `force` is false, nothing changes and the
    /// references are returned. With `force`, the references are removed too.
    pub fn delete_key(&self, id: &KeyId, force: bool) -> Result<DeleteResult, AppError> {
        let config = self.config_snapshot();
        if !config.keys.iter().any(|k| k.id == *id) {
            return Err(AppError::NotFound { kind: "key", id: id.to_string() });
        }
        let usage = key_usage(&config, id);
        let used_by = usage.hosts.len() + usage.sessions.len();
        if !usage_is_empty(&usage) && !force {
            return Ok(DeleteResult { deleted: false, used_by, usage });
        }
        if !self.vault_read().is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        let changed = self.mutate_config(|config| {
            config.keys.retain(|k| k.id != *id);
            Ok(edit_auth(config, |auth| {
                auth.retain(|m| !matches!(m, AuthMethod::Key { key } if key == id));
            }))
        })?;
        self.sync_profiles(changed);
        // The config no longer names this record, so a missing record is already the goal.
        match self.vault_write().delete_secret(&id.to_string()) {
            Ok(()) | Err(VaultError::SecretNotFound { .. }) => {}
            Err(error) => return Err(error.into()),
        }
        Ok(DeleteResult { deleted: true, used_by, usage })
    }

    fn record_type(&self, id: &str) -> Option<String> {
        self.vault_read()
            .list_keys()
            .into_iter()
            .find(|r| r.id == id)
            .map(|r| r.r#type)
    }

    /// Stores a password. With `existing`, rotates it: every reference moves to the new record
    /// and the old record is destroyed.
    pub fn set_password_secret(
        &self,
        existing: Option<&SecretRef>,
        password: SecretInput,
    ) -> Result<SecretMeta, AppError> {
        password.require_non_empty("password")?;
        if let Some(old) = existing {
            if self.record_type(&old.to_string()).as_deref() != Some(PASSWORD_RECORD) {
                return Err(AppError::NotFound { kind: "password", id: old.to_string() });
            }
        }
        let record = self.vault_write().put_secret(PASSWORD_RECORD, password.as_bytes())?;
        let secret_ref = secret_ref_from_record(&record)?;

        if let Some(old) = existing {
            let replacement = secret_ref.clone();
            let moved = self.mutate_config(|config| {
                Ok(edit_auth(config, |auth| {
                    for method in auth.iter_mut() {
                        if let AuthMethod::Password { secret } = method {
                            if secret == old {
                                *secret = replacement.clone();
                            }
                        }
                    }
                }))
            });
            let changed = match moved {
                Ok(changed) => changed,
                Err(error) => {
                    let _ = self.vault_write().delete_secret(&record);
                    return Err(error);
                }
            };
            self.sync_profiles(changed);
            self.vault_write().delete_secret(&old.to_string())?;
        }
        Ok(SecretMeta { secret_ref, has_secret: true })
    }

    /// Stores a session's MITM CA passphrase, replacing any previous one.
    pub fn set_mitm_passphrase(
        &self,
        session_id: Uuid,
        passphrase: SecretInput,
    ) -> Result<SecretMeta, AppError> {
        passphrase.require_non_empty("passphrase")?;
        let session = self
            .config_snapshot()
            .sessions
            .into_iter()
            .find(|s| s.id == session_id)
            .ok_or_else(|| AppError::NotFound { kind: "session", id: session_id.to_string() })?;
        let mitm = session
            .mitm
            .as_ref()
            .ok_or_else(|| AppError::Invalid("this session has no MITM configuration".into()))?;
        if mitm.ca_passphrase_file.is_some() {
            return Err(conduit_core::ValidateError::ConflictingPassphrase.into());
        }
        let previous = mitm.passphrase.clone();

        let record = self.vault_write().put_secret(PASSPHRASE_RECORD, passphrase.as_bytes())?;
        let secret_ref = secret_ref_from_record(&record)?;
        let replacement = secret_ref.clone();
        let updated = self.mutate_config(|config| {
            let session = config
                .sessions
                .iter_mut()
                .find(|s| s.id == session_id)
                .ok_or_else(|| AppError::NotFound { kind: "session", id: session_id.to_string() })?;
            let mitm = session
                .mitm
                .as_mut()
                .ok_or_else(|| AppError::Invalid("this session has no MITM configuration".into()))?;
            mitm.passphrase = Some(replacement);
            Ok(session.clone())
        });
        let updated = match updated {
            Ok(updated) => updated,
            Err(error) => {
                let _ = self.vault_write().delete_secret(&record);
                return Err(error);
            }
        };
        self.sync_profiles([updated]);
        if let Some(previous) = previous {
            match self.vault_write().delete_secret(&previous.to_string()) {
                Ok(()) | Err(VaultError::SecretNotFound { .. }) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(SecretMeta { secret_ref, has_secret: true })
    }

    /// Deletes a password or passphrase. Same `force` contract as [`Self::delete_key`]. Key
    /// records are refused, because they must go through `delete_key`.
    pub fn delete_secret(&self, secret: &SecretRef, force: bool) -> Result<DeleteResult, AppError> {
        match self.record_type(&secret.to_string()).as_deref() {
            None => return Err(AppError::NotFound { kind: "secret", id: secret.to_string() }),
            Some(KEY_RECORD) => {
                return Err(AppError::Invalid("use delete_key to remove a private key".into()))
            }
            Some(_) => {}
        }
        let usage = secret_usage(&self.config_snapshot(), secret);
        let used_by = usage.hosts.len() + usage.sessions.len();
        if !usage_is_empty(&usage) && !force {
            return Ok(DeleteResult { deleted: false, used_by, usage });
        }
        if !self.vault_read().is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        let changed = self.mutate_config(|config| {
            let mut changed = edit_auth(config, |auth| {
                auth.retain(|m| !matches!(m, AuthMethod::Password { secret: s } if s == secret));
            });
            for session in &mut config.sessions {
                if mitm_uses(session, secret) {
                    if let Some(mitm) = session.mitm.as_mut() {
                        mitm.passphrase = None;
                    }
                    changed.retain(|s: &SessionProfile| s.id != session.id);
                    changed.push(session.clone());
                }
            }
            Ok(changed)
        })?;
        self.sync_profiles(changed);
        self.vault_write().delete_secret(&secret.to_string())?;
        Ok(DeleteResult { deleted: true, used_by, usage })
    }

    /// Writes every vault key to a passphrase-encrypted bundle at `path` (owner-only).
    pub fn export_backup(
        &self,
        path: &Path,
        passphrase: SecretInput,
    ) -> Result<BackupSummary, AppError> {
        passphrase.require_non_empty("backup passphrase")?;
        let metas = self.config_snapshot().keys;
        let mut entries = Vec::with_capacity(metas.len());
        {
            let vault = self.vault_read();
            if !vault.is_unlocked() {
                return Err(VaultError::Locked.into());
            }
            for meta in &metas {
                let material = vault.get_secret(&meta.id.to_string())?;
                let text = std::str::from_utf8(&material)
                    .map_err(|_| AppError::Invalid(format!("key {} is not valid text", meta.id)))?;
                let (key, info) = conduit_vault::import_key(text, None)?;
                entries.push(BackupKey::from_key(
                    &meta.name,
                    &key,
                    &info,
                    source_label(meta.source),
                    meta.created_at.0,
                ));
            }
        }
        let bundle = conduit_vault::export_backup(&entries, passphrase.as_bytes(), self.argon());
        for entry in &mut entries {
            entry.private_key_openssh.zeroize();
        }
        write_private_file(path, &bundle?)?;
        Ok(BackupSummary { path: path.to_path_buf(), key_count: metas.len() })
    }

    /// Restores keys from a bundle. Keys already present are skipped.
    pub fn import_backup(
        &self,
        path: &Path,
        passphrase: SecretInput,
    ) -> Result<ImportBackupResult, AppError> {
        if !self.vault_read().is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        let data = fs::read(path)
            .map_err(|e| AppError::Io(format!("failed to read {}: {e}", path.display())))?;
        let mut entries = conduit_vault::import_backup(&data, passphrase.as_bytes())?;
        let result = self.restore_entries(&entries);
        for entry in &mut entries {
            entry.private_key_openssh.zeroize();
        }
        result
    }

    fn restore_entries(&self, entries: &[BackupKey]) -> Result<ImportBackupResult, AppError> {
        let mut imported = Vec::new();
        let mut skipped = 0;
        for entry in entries {
            let (key, info) = conduit_vault::import_key(&entry.private_key_openssh, None)?;
            match self.store_key(
                entry.name.clone(),
                &key,
                info,
                parse_source(&entry.source),
                Timestamp(entry.created_at),
            ) {
                Ok(meta) => imported.push(meta),
                Err(AppError::DuplicateKey { .. }) => skipped += 1,
                Err(error) => return Err(error),
            }
        }
        Ok(ImportBackupResult { imported, skipped })
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::*;
    use conduit_core::{MitmCaMode, MitmConfig};

    fn openssh_pem() -> String {
        let (key, _) = conduit_vault::generate_key(KeyGenAlgorithm::Ed25519).unwrap();
        key.to_openssh(LineEnding::LF).unwrap().to_string()
    }

    fn encrypted_pem(passphrase: &str) -> String {
        let (key, _) = conduit_vault::generate_key(KeyGenAlgorithm::Ed25519).unwrap();
        key.encrypt(&mut getrandom::SysRng, passphrase)
            .unwrap()
            .to_openssh(LineEnding::LF)
            .unwrap()
            .to_string()
    }

    fn with_key(c: &AppController, session: &str, host: &str, key: &KeyId) -> (Uuid, Uuid) {
        let mut s = profile(session, 22);
        s.hops[0].host.auth = vec![AuthMethod::Key { key: key.clone() }];
        let mut h = super::super::test_support::host(host, 22, vec![AuthMethod::Key { key: key.clone() }]);
        h.id = Uuid::new_v4();
        let ids = (s.id, h.id);
        c.mutate_config(|config| {
            config.sessions.push(s.clone());
            config.hosts.push(h);
            Ok(())
        })
        .unwrap();
        c.sync_profiles([s]);
        ids
    }

    #[tokio::test]
    async fn keys_import_stores_usable_material_and_returns_metadata_only() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        let pem = openssh_pem();
        let meta = c
            .import_key_pem("Pasted", SecretInput::new(pem.clone()), None, KeySource::Pasted)
            .unwrap();
        assert_eq!(meta.algorithm, "Ed25519");
        assert!(meta.fingerprint_sha256.starts_with("SHA256:"));
        assert!(meta.public_key_openssh.starts_with("ssh-ed25519 "));

        let stored = c.vault_read().get_secret(&meta.id.to_string()).unwrap();
        let (_, info) = conduit_vault::import_key(std::str::from_utf8(&stored).unwrap(), None).unwrap();
        assert_eq!(info.fingerprint_sha256, meta.fingerprint_sha256);
    }

    #[tokio::test]
    async fn keys_encrypted_import_verifies_passphrase_and_stores_decrypted() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        let pem = encrypted_pem("key-pass");
        assert!(c
            .import_key_pem("k", SecretInput::new(pem.clone()), None, KeySource::Uploaded)
            .is_err());
        assert!(c
            .import_key_pem(
                "k",
                SecretInput::new(pem.clone()),
                Some(SecretInput::new("wrong")),
                KeySource::Uploaded
            )
            .is_err());
        let meta = c
            .import_key_pem(
                "k",
                SecretInput::new(pem),
                Some(SecretInput::new("key-pass")),
                KeySource::Uploaded,
            )
            .unwrap();
        // Unattended reconnects read the stored key with no passphrase.
        let stored = c.vault_read().get_secret(&meta.id.to_string()).unwrap();
        assert!(conduit_vault::import_key(std::str::from_utf8(&stored).unwrap(), None).is_ok());
    }

    #[tokio::test]
    async fn keys_import_rejects_garbage_duplicates_and_generated_source() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        assert!(c
            .import_key_pem("bad", SecretInput::new("not a key"), None, KeySource::Pasted)
            .is_err());
        let pem = openssh_pem();
        assert!(matches!(
            c.import_key_pem("x", SecretInput::new(pem.clone()), None, KeySource::Generated),
            Err(AppError::Invalid(_))
        ));
        c.import_key_pem("one", SecretInput::new(pem.clone()), None, KeySource::Pasted)
            .unwrap();
        assert!(matches!(
            c.import_key_pem("two", SecretInput::new(pem), None, KeySource::Pasted),
            Err(AppError::DuplicateKey { .. })
        ));
        assert_eq!(c.list_keys().len(), 1);
        assert_eq!(c.vault_read().record_count(), 1);
    }

    #[tokio::test]
    async fn keys_operations_require_unlocked_vault() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        let meta = c.generate_key("k", GenerateAlgorithm::Ed25519).unwrap();
        c.lock_vault();
        let locked = |e: AppError| matches!(e, AppError::Vault(VaultError::Locked));
        assert!(locked(c.generate_key("x", GenerateAlgorithm::Ed25519).unwrap_err()));
        assert!(locked(
            c.import_key_pem("x", SecretInput::new(openssh_pem()), None, KeySource::Pasted)
                .unwrap_err()
        ));
        assert!(locked(c.set_password_secret(None, SecretInput::new("p")).unwrap_err()));
        assert!(locked(c.delete_key(&meta.id, false).unwrap_err()));
        assert!(locked(
            c.export_backup(&dir.path().join("b"), SecretInput::new("p")).unwrap_err()
        ));
        assert!(locked(
            c.import_backup(&dir.path().join("b"), SecretInput::new("p")).unwrap_err()
        ));
    }

    #[tokio::test]
    async fn keys_generate_both_algorithms() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        let ed = c.generate_key("ed", GenerateAlgorithm::Ed25519).unwrap();
        let ec = c.generate_key("ec", GenerateAlgorithm::EcdsaP256).unwrap();
        assert_eq!(ed.algorithm, "Ed25519");
        assert_eq!(ec.algorithm, "ECDSA-P256");
        assert_eq!(ed.source, KeySource::Generated);
        assert!(matches!(c.generate_key("  ", GenerateAlgorithm::Ed25519), Err(AppError::Invalid(_))));
    }

    #[tokio::test]
    async fn keys_rename_persists() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        let meta = c.generate_key("old", GenerateAlgorithm::Ed25519).unwrap();
        assert_eq!(c.rename_key(&meta.id, " new ").unwrap().name, "new");
        drop(c);
        assert_eq!(controller(&dir).list_keys()[0].meta.name, "new");
    }

    #[tokio::test]
    async fn keys_list_reports_usage() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        let meta = c.generate_key("k", GenerateAlgorithm::Ed25519).unwrap();
        with_key(&c, "sess", "hosty", &meta.id);
        let view = &c.list_keys()[0];
        assert_eq!(view.used_by, 2);
        assert_eq!(view.usage.hosts[0].name, "hosty");
        assert_eq!(view.usage.sessions[0].name, "sess");
    }

    #[tokio::test]
    async fn keys_delete_referenced_needs_force_and_strips_references() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        let meta = c.generate_key("k", GenerateAlgorithm::Ed25519).unwrap();
        with_key(&c, "sess", "hosty", &meta.id);

        let refused = c.delete_key(&meta.id, false).unwrap();
        assert!(!refused.deleted);
        assert_eq!(refused.used_by, 2);
        assert_eq!(refused.usage.sessions[0].name, "sess");
        assert_eq!(c.vault_read().record_count(), 1);

        assert!(c.delete_key(&meta.id, true).unwrap().deleted);
        assert_eq!(c.vault_read().record_count(), 0);
        let config = c.config_snapshot();
        assert!(config.keys.is_empty());
        assert!(config.hosts[0].auth.is_empty());
        assert!(config.sessions[0].hops[0].host.auth.is_empty());
        assert!(matches!(c.delete_key(&meta.id, true), Err(AppError::NotFound { .. })));
    }

    #[tokio::test]
    async fn keys_delete_unreferenced_needs_no_force() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        let meta = c.generate_key("k", GenerateAlgorithm::Ed25519).unwrap();
        assert!(c.delete_key(&meta.id, false).unwrap().deleted);
    }

    #[tokio::test]
    async fn keys_password_rotation_moves_references_and_destroys_old_record() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        let first = c.set_password_secret(None, SecretInput::new("one")).unwrap();
        assert!(first.has_secret);
        let mut s = profile("s", 22);
        s.hops[0].host.auth = vec![AuthMethod::Password { secret: first.secret_ref.clone() }];
        c.mutate_config(|config| {
            config.sessions.push(s.clone());
            Ok(())
        })
        .unwrap();

        let second = c
            .set_password_secret(Some(&first.secret_ref), SecretInput::new("two"))
            .unwrap();
        assert_ne!(first.secret_ref, second.secret_ref);
        assert_eq!(
            c.config_snapshot().sessions[0].hops[0].host.auth,
            vec![AuthMethod::Password { secret: second.secret_ref.clone() }]
        );
        assert_eq!(c.vault_read().record_count(), 1);
        let value = c.vault_read().get_secret(&second.secret_ref.to_string()).unwrap();
        assert_eq!(value.as_slice(), b"two");
    }

    #[tokio::test]
    async fn keys_password_rejects_empty_and_unknown_existing() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        assert!(matches!(
            c.set_password_secret(None, SecretInput::new("")),
            Err(AppError::Invalid(_))
        ));
        assert!(matches!(
            c.set_password_secret(Some(&SecretRef::new()), SecretInput::new("x")),
            Err(AppError::NotFound { .. })
        ));
        assert_eq!(c.vault_read().record_count(), 0);
    }

    fn mitm_session(c: &AppController) -> Uuid {
        let mut s = profile("mitm", 22);
        s.mitm = Some(MitmConfig {
            ca_mode: MitmCaMode::Pkcs12 { path: "/tmp/ca.p12".into() },
            ..MitmConfig::default()
        });
        let id = s.id;
        c.mutate_config(|config| {
            config.sessions.push(s.clone());
            Ok(())
        })
        .unwrap();
        c.sync_profiles([s]);
        id
    }

    #[tokio::test]
    async fn keys_mitm_passphrase_set_replace_and_validate() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        let id = mitm_session(&c);
        let first = c.set_mitm_passphrase(id, SecretInput::new("one")).unwrap();
        let second = c.set_mitm_passphrase(id, SecretInput::new("two")).unwrap();
        assert_eq!(c.vault_read().record_count(), 1);
        let session = c.config_snapshot().sessions[0].clone();
        assert_eq!(session.mitm.unwrap().passphrase, Some(second.secret_ref));
        assert!(c.vault_read().get_secret(&first.secret_ref.to_string()).is_err());

        let plain = profile("plain", 22);
        let plain_id = plain.id;
        c.mutate_config(|config| {
            config.sessions.push(plain);
            Ok(())
        })
        .unwrap();
        assert!(matches!(
            c.set_mitm_passphrase(plain_id, SecretInput::new("x")),
            Err(AppError::Invalid(_))
        ));
        assert!(matches!(
            c.set_mitm_passphrase(Uuid::new_v4(), SecretInput::new("x")),
            Err(AppError::NotFound { .. })
        ));
    }

    #[tokio::test]
    async fn keys_delete_secret_contract() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        let id = mitm_session(&c);
        let meta = c.set_mitm_passphrase(id, SecretInput::new("one")).unwrap();

        let refused = c.delete_secret(&meta.secret_ref, false).unwrap();
        assert!(!refused.deleted);
        assert_eq!(refused.usage.sessions[0].name, "mitm");

        assert!(c.delete_secret(&meta.secret_ref, true).unwrap().deleted);
        assert_eq!(c.vault_read().record_count(), 0);
        assert_eq!(c.config_snapshot().sessions[0].mitm.as_ref().unwrap().passphrase, None);
        assert!(matches!(
            c.delete_secret(&meta.secret_ref, true),
            Err(AppError::NotFound { .. })
        ));

        let key = c.generate_key("k", GenerateAlgorithm::Ed25519).unwrap();
        let as_secret = secret_ref_from_record(&key.id.to_string()).unwrap();
        assert!(matches!(c.delete_secret(&as_secret, true), Err(AppError::Invalid(_))));
        assert_eq!(c.vault_read().record_count(), 1);
    }

    #[tokio::test]
    async fn keys_backup_round_trip_skips_duplicates() {
        let source_dir = TempDir::new();
        let c = unlocked(&source_dir).await;
        let meta = c.generate_key("k", GenerateAlgorithm::Ed25519).unwrap();
        let path = source_dir.path().join("backup.bin");
        let summary = c.export_backup(&path, SecretInput::new("backup-pass")).unwrap();
        assert_eq!(summary.key_count, 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }

        let target_dir = TempDir::new();
        let t = unlocked(&target_dir).await;
        assert!(t.import_backup(&path, SecretInput::new("wrong")).is_err());
        let restored = t.import_backup(&path, SecretInput::new("backup-pass")).unwrap();
        assert_eq!(restored.imported.len(), 1);
        assert_eq!(restored.imported[0].fingerprint_sha256, meta.fingerprint_sha256);
        assert_eq!(restored.imported[0].source, KeySource::Generated);

        let again = t.import_backup(&path, SecretInput::new("backup-pass")).unwrap();
        assert!(again.imported.is_empty());
        assert_eq!(again.skipped, 1);
    }
}
