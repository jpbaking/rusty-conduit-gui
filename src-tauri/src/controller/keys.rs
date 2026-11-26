//! Key-vault and write-only secret operations.

use std::fs;
use std::path::Path;

use conduit_core::{
    AppConfig, AuthMethod, KeyId, KeySource, Proxy, SecretRef, SessionProfile, Timestamp, Tunnel,
    UpstreamPasswordSource, UpstreamProfile, VaultKeyMeta,
};
use conduit_vault::{BackupKey, KeyGenAlgorithm, KeyInfo, VaultError, UPSTREAM_PASSWORD_RECORD};
use russh::keys::ssh_key::LineEnding;
use russh::keys::PrivateKey;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    key_id_from_record, secret_ref_from_record, usage_is_empty, AppController, AppError,
    SecretInput, SecretMeta,
};

pub(super) const KEY_RECORD: &str = "key";
pub(super) const PASSWORD_RECORD: &str = "password";
/// MITM CA passphrases, stored by earlier betas for path-based CAs. Nothing refers to them now;
/// they are deleted on unlock.
pub(super) const RETIRED_PASSPHRASE_RECORD: &str = "passphrase";

/// A host, session, Tunnel, or Proxy that references a key, secret, CA, or Tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UsageRef {
    pub id: Uuid,
    pub name: String,
}

/// Everything referencing a key, secret, CA, or Tunnel.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Usage {
    pub hosts: Vec<UsageRef>,
    pub sessions: Vec<UsageRef>,
    pub tunnels: Vec<UsageRef>,
    pub proxies: Vec<UsageRef>,
    /// Names of Profile Library entries.
    pub library_profiles: Vec<String>,
}

impl Usage {
    /// How many things reference the item.
    pub fn count(&self) -> usize {
        self.hosts.len()
            + self.sessions.len()
            + self.tunnels.len()
            + self.proxies.len()
            + self.library_profiles.len()
    }
}

pub(super) fn tunnel_ref(tunnel: &Tunnel) -> UsageRef {
    UsageRef { id: tunnel.id.as_uuid(), name: tunnel.name.clone() }
}

pub(super) fn proxy_ref(proxy: &Proxy) -> UsageRef {
    UsageRef { id: proxy.id.as_uuid(), name: proxy.name.clone() }
}

/// Every Proxy and Profile Library entry with an upstream profile matching `uses`.
fn profile_usage(config: &AppConfig, uses: impl Fn(&UpstreamProfile) -> bool) -> Usage {
    Usage {
        proxies: config
            .proxies
            .iter()
            .filter(|p| p.profiles.iter().any(&uses))
            .map(proxy_ref)
            .collect(),
        library_profiles: config
            .profile_library
            .iter()
            .filter(|p| uses(p))
            .map(|p| p.name.clone())
            .collect(),
        ..Usage::default()
    }
}

fn uses_upstream_password(profile: &UpstreamProfile, secret: &SecretRef) -> bool {
    matches!(&profile.password, Some(UpstreamPasswordSource::Vault(s)) if s == secret)
}

/// Applies `edit` to every Proxy profile and Profile Library entry, returning the Proxies it
/// changed.
pub(super) fn edit_upstream_profiles(
    config: &mut AppConfig,
    edit: impl Fn(&mut UpstreamProfile),
) -> Vec<Proxy> {
    for profile in &mut config.profile_library {
        edit(profile);
    }
    let mut changed = Vec::new();
    for proxy in &mut config.proxies {
        let before = proxy.profiles.clone();
        for profile in &mut proxy.profiles {
            edit(profile);
        }
        if proxy.profiles != before {
            changed.push(proxy.clone());
        }
    }
    changed
}

/// Sessions and Tunnels whose hop auth an edit changed.
#[derive(Default)]
pub(super) struct AuthChanges {
    sessions: Vec<SessionProfile>,
    tunnels: Vec<Tunnel>,
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
    let tunnels = config
        .tunnels
        .iter()
        .filter(|t| t.hops.iter().any(|hop| hop.host.auth.iter().any(&uses)))
        .map(tunnel_ref)
        .collect();
    Usage { hosts, sessions, tunnels, ..Usage::default() }
}

fn key_usage(config: &AppConfig, id: &KeyId) -> Usage {
    usage_of(config, |m| matches!(m, AuthMethod::Key { key } if key == id))
}

fn secret_usage(config: &AppConfig, secret: &SecretRef) -> Usage {
    let hops = usage_of(config, |m| matches!(m, AuthMethod::Password { secret: s } if s == secret));
    let upstream = profile_usage(config, |p| uses_upstream_password(p, secret));
    Usage { proxies: upstream.proxies, library_profiles: upstream.library_profiles, ..hops }
}

/// Applies `edit` to every host's and hop's auth list, returning the sessions and Tunnels it
/// changed.
fn edit_auth(config: &mut AppConfig, edit: impl Fn(&mut Vec<AuthMethod>)) -> AuthChanges {
    for host in &mut config.hosts {
        edit(&mut host.auth);
    }
    let mut changed = AuthChanges::default();
    for session in &mut config.sessions {
        let before = session.hops.clone();
        for hop in &mut session.hops {
            edit(&mut hop.host.auth);
        }
        if session.hops != before {
            changed.sessions.push(session.clone());
        }
    }
    for tunnel in &mut config.tunnels {
        let before = tunnel.hops.clone();
        for hop in &mut tunnel.hops {
            edit(&mut hop.host.auth);
        }
        if tunnel.hops != before {
            changed.tunnels.push(tunnel.clone());
        }
    }
    changed
}

pub(super) fn require_name(name: &str) -> Result<String, AppError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(AppError::Invalid("name must not be empty".into()));
    }
    Ok(name.to_owned())
}

/// Reads the source label a key-only backup recorded.
fn parse_source(label: &str) -> KeySource {
    match label {
        "Pasted" => KeySource::Pasted,
        "Generated" => KeySource::Generated,
        _ => KeySource::Uploaded,
    }
}

/// Writes `bytes` beside `path`, owner-only, then renames over it.
pub(super) fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), AppError> {
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
    fn sync_auth_changes(&self, changed: AuthChanges) {
        self.sync_profiles(changed.sessions);
        self.sync_tunnels(changed.tunnels);
    }

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
                KeyView { meta: meta.clone(), used_by: usage.count(), usage }
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
        let used_by = usage.count();
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
        self.sync_auth_changes(changed);
        // The config no longer names this record, so a missing record is already the goal.
        match self.vault_write().delete_secret(&id.to_string()) {
            Ok(()) | Err(VaultError::SecretNotFound { .. }) => {}
            Err(error) => return Err(error.into()),
        }
        Ok(DeleteResult { deleted: true, used_by, usage })
    }

    pub(super) fn record_type(&self, id: &str) -> Option<String> {
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
            self.sync_auth_changes(changed);
            self.vault_write().delete_secret(&old.to_string())?;
        }
        Ok(SecretMeta { secret_ref, has_secret: true })
    }

    /// Stores an upstream proxy password. With `existing`, rotates it: every Proxy profile and
    /// Profile Library entry moves to the new record, running Proxies reload with it, and the
    /// old record is destroyed.
    pub async fn set_upstream_password(
        &self,
        existing: Option<SecretRef>,
        password: SecretInput,
    ) -> Result<SecretMeta, AppError> {
        password.require_non_empty("password")?;
        if let Some(old) = &existing {
            if self.record_type(&old.to_string()).as_deref() != Some(UPSTREAM_PASSWORD_RECORD) {
                return Err(AppError::NotFound { kind: "upstream password", id: old.to_string() });
            }
        }
        let record = self.vault_write().put_upstream_password(password.as_bytes())?;
        drop(password);
        let secret_ref = secret_ref_from_record(&record)?;
        let Some(old) = existing else {
            return Ok(SecretMeta { secret_ref, has_secret: true });
        };
        let replacement = secret_ref.clone();
        let moved = self.mutate_config(|config| {
            Ok(edit_upstream_profiles(config, |profile| {
                if uses_upstream_password(profile, &old) {
                    profile.password = Some(UpstreamPasswordSource::Vault(replacement.clone()));
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
        for proxy in changed {
            // The saved config already names the new record; a rejected reload keeps the
            // running state, which still holds the old password in memory until restarted.
            if let Err(error) = self.proxies().upsert_proxy(proxy).await {
                eprintln!("a proxy did not reload after its password changed: {error}");
            }
        }
        self.vault_write().delete_secret(&old.to_string())?;
        Ok(SecretMeta { secret_ref, has_secret: true })
    }

    /// Deletes a password: a hop password or an upstream proxy password. Same `force` contract
    /// as [`Self::delete_key`]; forcing also stops running Proxies that used it, since they hold
    /// it in memory. Key and CA records are refused, because they must go through `delete_key`
    /// and `delete_mitm_ca`.
    pub async fn delete_secret(&self, secret: &SecretRef, force: bool) -> Result<DeleteResult, AppError> {
        let controller = self.clone();
        let target = secret.clone();
        let (outcome, proxies) =
            super::run_blocking(move || controller.detach_secret(&target, force)).await?;
        if !outcome.deleted {
            return Ok(outcome);
        }
        self.stop_and_sync_proxies(proxies).await?;
        let controller = self.clone();
        let record = secret.to_string();
        super::run_blocking(move || Ok(controller.vault_write().delete_secret(&record)?)).await?;
        Ok(outcome)
    }

    /// The config half of [`Self::delete_secret`]: drops every reference to the secret.
    fn detach_secret(
        &self,
        secret: &SecretRef,
        force: bool,
    ) -> Result<(DeleteResult, Vec<Proxy>), AppError> {
        match self.record_type(&secret.to_string()).as_deref() {
            None => return Err(AppError::NotFound { kind: "secret", id: secret.to_string() }),
            Some(KEY_RECORD) => {
                return Err(AppError::Invalid("use delete_key to remove a private key".into()))
            }
            Some(super::mitm_ca::MITM_CA_RECORD) => {
                return Err(AppError::Invalid("use delete_mitm_ca to remove a MITM CA".into()))
            }
            Some(_) => {}
        }
        let usage = secret_usage(&self.config_snapshot(), secret);
        let used_by = usage.count();
        if !usage_is_empty(&usage) && !force {
            return Ok((DeleteResult { deleted: false, used_by, usage }, Vec::new()));
        }
        if !self.vault_read().is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        let (changed, proxies) = self.mutate_config(|config| {
            let changed = edit_auth(config, |auth| {
                auth.retain(|m| !matches!(m, AuthMethod::Password { secret: s } if s == secret));
            });
            let proxies = edit_upstream_profiles(config, |profile| {
                if uses_upstream_password(profile, secret) {
                    profile.password = None;
                }
            });
            Ok((changed, proxies))
        })?;
        self.sync_auth_changes(changed);
        Ok((DeleteResult { deleted: true, used_by, usage }, proxies))
    }

    /// Stores the keys of a key-only backup, returning how many were added and skipped.
    pub(super) fn restore_entries(&self, entries: &[BackupKey]) -> Result<(usize, usize), AppError> {
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
        Ok((imported.len(), skipped))
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::*;

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

    #[tokio::test]
    async fn keys_delete_secret_contract() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        let meta = c.set_password_secret(None, SecretInput::new("one")).unwrap();
        let mut s = profile("pw", 22);
        s.hops[0].host.auth = vec![AuthMethod::Password { secret: meta.secret_ref.clone() }];
        c.upsert_session(s).unwrap();

        let refused = c.delete_secret(&meta.secret_ref, false).await.unwrap();
        assert!(!refused.deleted);
        assert_eq!(refused.usage.sessions[0].name, "pw");

        assert!(c.delete_secret(&meta.secret_ref, true).await.unwrap().deleted);
        assert_eq!(c.vault_read().record_count(), 0);
        assert!(c.config_snapshot().sessions[0].hops[0].host.auth.is_empty());
        assert!(matches!(
            c.delete_secret(&meta.secret_ref, true).await,
            Err(AppError::NotFound { .. })
        ));

        let key = c.generate_key("k", GenerateAlgorithm::Ed25519).unwrap();
        let as_secret = secret_ref_from_record(&key.id.to_string()).unwrap();
        assert!(matches!(c.delete_secret(&as_secret, true).await, Err(AppError::Invalid(_))));
        assert_eq!(c.vault_read().record_count(), 1);
    }

    #[tokio::test]
    async fn an_old_key_only_backup_still_imports_and_skips_duplicates() {
        let source_dir = TempDir::new();
        let c = unlocked(&source_dir).await;
        let meta = c.generate_key("k", GenerateAlgorithm::Ed25519).unwrap();
        // Written the way the removed "Encrypted key backup" flow wrote it.
        let pem = c.vault_read().get_secret(&meta.id.to_string()).unwrap();
        let (key, info) = conduit_vault::import_key(std::str::from_utf8(&pem).unwrap(), None).unwrap();
        let entry = BackupKey::from_key("k", &key, &info, "Generated", meta.created_at.0);
        let bundle =
            conduit_vault::export_backup(&[entry], b"backup-pass", FAST_ARGON)
                .unwrap();
        let path = source_dir.path().join("backup.bin");
        fs::write(&path, bundle).unwrap();

        let target_dir = TempDir::new();
        let t = unlocked(&target_dir).await;
        assert!(matches!(t.import_config(&path, None, false), Err(AppError::Invalid(_))));
        assert!(t.import_config(&path, Some(SecretInput::new("wrong")), false).is_err());
        let restored = t.import_config(&path, Some(SecretInput::new("backup-pass")), false).unwrap();
        assert!(restored.key_only_backup);
        assert_eq!((restored.keys_added, restored.keys_skipped), (1, 0));
        let keys = t.list_keys();
        assert_eq!(keys[0].meta.fingerprint_sha256, meta.fingerprint_sha256);
        assert_eq!(keys[0].meta.source, KeySource::Generated);

        let again = t.import_config(&path, Some(SecretInput::new("backup-pass")), false).unwrap();
        assert_eq!((again.keys_added, again.keys_skipped), (0, 1));
    }
}
