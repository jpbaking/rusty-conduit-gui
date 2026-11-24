//! Config export and import.
//!
//! * A **plain** export is JSON holding the app config. It has opaque secret references but no
//!   secret values, and no `vault.bin` bytes.
//! * An **encrypted** bundle also holds known hosts and every referenced vault secret, sealed
//!   with XChaCha20-Poly1305 under an Argon2id key derived from the export passphrase.
//!
//! A plain file is unauthenticated, so anyone could have edited it. Importing one therefore
//! never lets a file attach an existing credential to a new destination: a key, password,
//! agent key, or CA passphrase reference survives only where the same host, port, and user
//! already hold it.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::PoisonError;

use conduit_core::{
    validate, AppConfig, AuthMethod, HopEntry, HostProfile, KeyId, KnownHostsStore, SecretRef,
    SessionProfile, VaultKeyMeta,
};
use conduit_vault::{
    decrypt_record, derive_master_key, encrypt_record, generate_dek, Argon2Params, Dek, VaultError,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use super::keys::{write_private_file, KEY_RECORD, PASSPHRASE_RECORD, PASSWORD_RECORD};
use super::{
    key_id_from_record, secret_ref_from_record, AppController, AppError, SecretInput,
    SCHEMA_VERSION,
};

const FORMAT: &str = "rusty-conduit-config";
const VERSION: u32 = 1;
/// Bound into the ciphertext as authenticated data.
const BUNDLE_RECORD_ID: &[u8] = b"conduit-config-bundle";
const BUNDLE_RECORD_TYPE: &[u8] = b"config-bundle-v1";
const SALT_LEN: usize = 16;
const MAX_IMPORT_BYTES: u64 = 64 * 1024 * 1024;

// An import file chooses its own Argon2 cost, so a hostile one must not be able to hang the app.
const MAX_ARGON_MEMORY_KIB: u32 = 1024 * 1024;
const MAX_ARGON_TIME_COST: u32 = 64;
const MAX_ARGON_PARALLELISM: u8 = 16;

#[derive(Deserialize)]
struct Probe {
    format: String,
    version: u32,
    encrypted: bool,
}

#[derive(Serialize, Deserialize)]
struct PlainExport {
    format: String,
    version: u32,
    encrypted: bool,
    config: AppConfig,
}

#[derive(Serialize, Deserialize)]
struct EncryptedExport {
    format: String,
    version: u32,
    encrypted: bool,
    argon2: Argon2Params,
    salt: Vec<u8>,
    payload: Vec<u8>,
}

/// One vault record inside the encrypted payload. Zeroized on drop.
#[derive(Serialize, Deserialize)]
struct BundleSecret {
    id: String,
    record_type: String,
    value: Vec<u8>,
}

impl Drop for BundleSecret {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
struct BundlePayload {
    config: AppConfig,
    known_hosts: KnownHostsStore,
    secrets: Vec<BundleSecret>,
}

/// Result of writing an export. Holds counts only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportSummary {
    pub path: PathBuf,
    pub encrypted: bool,
    pub session_count: usize,
    pub host_count: usize,
    pub key_count: usize,
    /// Vault records sealed into the bundle. Always `0` for a plain export.
    pub secret_count: usize,
    /// References whose vault record no longer exists, so they could not be included.
    pub missing_secrets: usize,
}

/// Result of an import.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ImportSummary {
    pub encrypted: bool,
    pub sessions_added: usize,
    pub sessions_updated: usize,
    pub sessions_skipped: usize,
    pub hosts_added: usize,
    pub hosts_updated: usize,
    pub hosts_skipped: usize,
    pub keys_added: usize,
    pub secrets_added: usize,
    pub known_hosts_added: usize,
    pub known_hosts_updated: usize,
    /// Credential references dropped because they could not be trusted or resolved.
    pub credentials_removed: usize,
}

fn not_an_export() -> AppError {
    // Parser errors can quote file content, so they are deliberately not passed on.
    AppError::Invalid("this file is not a valid Rusty Conduit config export".into())
}

fn all_hosts(config: &AppConfig) -> impl Iterator<Item = &HostProfile> {
    config
        .hosts
        .iter()
        .chain(config.sessions.iter().flat_map(|s| s.hops.iter().map(|h| &h.host)))
}

/// Every vault record the config refers to.
fn referenced_records(config: &AppConfig) -> BTreeSet<String> {
    let mut ids: BTreeSet<String> = config.keys.iter().map(|k| k.id.to_string()).collect();
    for method in all_hosts(config).flat_map(|h| &h.auth) {
        match method {
            AuthMethod::Key { key } => ids.insert(key.to_string()),
            AuthMethod::Password { secret } => ids.insert(secret.to_string()),
            _ => false,
        };
    }
    for session in &config.sessions {
        ids.extend(
            session
                .hops
                .iter()
                .flat_map(|h| &h.agent_forward_keys)
                .map(ToString::to_string),
        );
        if let Some(secret) = session.mitm.as_ref().and_then(|m| m.passphrase.as_ref()) {
            ids.insert(secret.to_string());
        }
    }
    ids
}

/// Assigns missing ids and validates every imported session and host.
fn prepare(config: &mut AppConfig) -> Result<(), AppError> {
    if config.schema_version > SCHEMA_VERSION {
        return Err(AppError::Invalid(format!(
            "this export uses config schema {}, newer than this app supports",
            config.schema_version
        )));
    }
    let mut session_ids = HashSet::new();
    for session in &mut config.sessions {
        if session.id.is_nil() {
            session.id = Uuid::new_v4();
        }
        if !session_ids.insert(session.id) {
            return Err(AppError::Invalid(format!("duplicate session id {}", session.id)));
        }
        let mut hop_ids = HashSet::new();
        for hop in &mut session.hops {
            if hop.hop_id.trim().is_empty() {
                hop.hop_id = Uuid::new_v4().to_string();
            }
            if !hop_ids.insert(hop.hop_id.clone()) {
                return Err(AppError::Invalid(format!("duplicate hop id {:?}", hop.hop_id)));
            }
        }
        validate(session)?;
    }
    let mut host_ids = HashSet::new();
    for host in &mut config.hosts {
        if host.id.is_nil() {
            host.id = Uuid::new_v4();
        }
        if !host_ids.insert(host.id) {
            return Err(AppError::Invalid(format!("duplicate host id {}", host.id)));
        }
        for (label, value) in [("name", &host.name), ("host", &host.host), ("user", &host.user)] {
            if value.trim().is_empty() {
                return Err(AppError::Invalid(format!("host {label} must not be empty")));
            }
        }
    }
    Ok(())
}

fn same_endpoint(a: &HostProfile, b: &HostProfile) -> bool {
    a.host == b.host && a.port == b.port && a.user == b.user
}

fn is_credential(method: &AuthMethod) -> bool {
    !matches!(method, AuthMethod::KeyboardInteractive { .. })
}

/// Keeps a credential only when `trusted` holds it for the same endpoint.
fn strip_host(host: &mut HostProfile, trusted: Option<&HostProfile>) -> usize {
    let trusted = trusted.filter(|t| same_endpoint(t, host));
    let before = host.auth.len();
    host.auth
        .retain(|m| !is_credential(m) || trusted.is_some_and(|t| t.auth.contains(m)));
    before - host.auth.len()
}

fn strip_hop(hop: &mut HopEntry, trusted: Option<&HopEntry>) -> usize {
    let trusted = trusted.filter(|t| same_endpoint(&t.host, &hop.host));
    let before = hop.agent_forward_keys.len();
    hop.agent_forward_keys
        .retain(|k| trusted.is_some_and(|t| t.agent_forward_keys.contains(k)));
    let removed = before - hop.agent_forward_keys.len();
    removed + strip_host(&mut hop.host, trusted.map(|t| &t.host))
}

/// Removes every credential reference a plain file is not entitled to. See the module docs.
fn strip_untrusted_credentials(incoming: &mut AppConfig, current: &AppConfig) -> usize {
    let mut removed = 0;
    for host in &mut incoming.hosts {
        let trusted = current.hosts.iter().find(|h| h.id == host.id);
        removed += strip_host(host, trusted);
    }
    for session in &mut incoming.sessions {
        let existing = current.sessions.iter().find(|s| s.id == session.id);
        for hop in &mut session.hops {
            let trusted = existing.and_then(|s| s.hops.iter().find(|h| h.hop_id == hop.hop_id));
            removed += strip_hop(hop, trusted);
        }
        if let Some(mitm) = session.mitm.as_mut().filter(|m| m.passphrase.is_some()) {
            let keep = existing.and_then(|s| s.mitm.as_ref()).is_some_and(|e| {
                e.passphrase == mitm.passphrase && e.ca_mode == mitm.ca_mode
            });
            if !keep {
                mitm.passphrase = None;
                removed += 1;
            }
        }
    }
    removed
}

/// Merges hosts and sessions into `config`, returning the counts and the sessions it changed.
fn merge(
    config: &mut AppConfig,
    incoming: AppConfig,
    replace: bool,
    untrusted: bool,
) -> (ImportSummary, Vec<SessionProfile>) {
    let mut summary = ImportSummary::default();
    let mut touched = BTreeSet::new();
    for host in incoming.hosts {
        let Some(index) = config.hosts.iter().position(|h| h.id == host.id) else {
            config.hosts.push(host);
            summary.hosts_added += 1;
            continue;
        };
        if !replace {
            summary.hosts_skipped += 1;
            continue;
        }
        for session in &mut config.sessions {
            for hop in session.hops.iter_mut().filter(|h| h.host.id == host.id) {
                // A linked hop follows its host, so its agent keys must not follow an
                // endpoint change that came from an unauthenticated file.
                if untrusted && !same_endpoint(&hop.host, &host) {
                    summary.credentials_removed += hop.agent_forward_keys.len();
                    hop.agent_forward_keys.clear();
                }
                hop.host = host.clone();
                touched.insert(session.id);
            }
        }
        config.hosts[index] = host;
        summary.hosts_updated += 1;
    }
    for session in incoming.sessions {
        match config.sessions.iter().position(|s| s.id == session.id) {
            None => {
                touched.insert(session.id);
                config.sessions.push(session);
                summary.sessions_added += 1;
            }
            Some(_) if !replace => summary.sessions_skipped += 1,
            Some(index) => {
                touched.insert(session.id);
                config.sessions[index] = session;
                summary.sessions_updated += 1;
            }
        }
    }
    let changed = config
        .sessions
        .iter()
        .filter(|s| touched.contains(&s.id))
        .cloned()
        .collect();
    (summary, changed)
}

fn bundle_key(passphrase: &[u8], params: &Argon2Params, salt: &[u8]) -> Result<Dek, AppError> {
    let master = derive_master_key(passphrase, params, salt)?;
    Ok(Dek::from_bytes(master.as_slice())?)
}

fn check_bundle_params(file: &EncryptedExport) -> Result<(), AppError> {
    let params = &file.argon2;
    let sane = params.derived_key_len == 32
        && params.memory_kib <= MAX_ARGON_MEMORY_KIB
        && (1..=MAX_ARGON_TIME_COST).contains(&params.time_cost)
        && (1..=MAX_ARGON_PARALLELISM).contains(&params.parallelism)
        && file.salt.len() == SALT_LEN;
    if sane {
        Ok(())
    } else {
        Err(AppError::Invalid("this bundle has unsupported encryption parameters".into()))
    }
}

/// Vault records restored from a bundle, keyed by their id inside the bundle.
#[derive(Default)]
struct RestoredRecords {
    keys: HashMap<String, KeyId>,
    passwords: HashMap<String, SecretRef>,
    passphrases: HashMap<String, SecretRef>,
    new_metas: Vec<VaultKeyMeta>,
    /// Records created by this import, deleted again if it fails.
    created: Vec<String>,
}

impl RestoredRecords {
    fn remap_auth(&self, auth: &mut Vec<AuthMethod>) -> usize {
        let before = auth.len();
        auth.retain_mut(|method| match method {
            AuthMethod::Key { key } => match self.keys.get(&key.to_string()) {
                Some(new) => {
                    *key = new.clone();
                    true
                }
                None => false,
            },
            AuthMethod::Password { secret } => match self.passwords.get(&secret.to_string()) {
                Some(new) => {
                    *secret = new.clone();
                    true
                }
                None => false,
            },
            _ => true,
        });
        before - auth.len()
    }

    /// Points every reference at its restored record and drops any that did not resolve.
    fn remap(&self, config: &mut AppConfig) -> usize {
        let mut removed = 0;
        for host in &mut config.hosts {
            removed += self.remap_auth(&mut host.auth);
        }
        for session in &mut config.sessions {
            for hop in &mut session.hops {
                removed += self.remap_auth(&mut hop.host.auth);
                let before = hop.agent_forward_keys.len();
                let mapped: Vec<KeyId> = hop
                    .agent_forward_keys
                    .iter()
                    .filter_map(|k| self.keys.get(&k.to_string()).cloned())
                    .collect();
                removed += before - mapped.len();
                hop.agent_forward_keys = mapped;
            }
            if let Some(mitm) = session.mitm.as_mut() {
                if let Some(old) = mitm.passphrase.take() {
                    mitm.passphrase = self.passphrases.get(&old.to_string()).cloned();
                    removed += usize::from(mitm.passphrase.is_none());
                }
            }
        }
        removed
    }
}

impl AppController {
    /// Writes a config export, owner-only. Secrets are included only in the encrypted form.
    pub fn export_config(
        &self,
        path: &Path,
        include_secrets: bool,
        passphrase: Option<SecretInput>,
    ) -> Result<ExportSummary, AppError> {
        let config = self.config_snapshot();
        let mut summary = ExportSummary {
            path: path.to_path_buf(),
            encrypted: include_secrets,
            session_count: config.sessions.len(),
            host_count: config.hosts.len(),
            key_count: config.keys.len(),
            secret_count: 0,
            missing_secrets: 0,
        };
        if !include_secrets {
            // Refuse rather than write plaintext for someone who expected encryption.
            if passphrase.is_some() {
                return Err(AppError::Invalid(
                    "a passphrase is only used when the export includes secrets".into(),
                ));
            }
            let file = PlainExport {
                format: FORMAT.into(),
                version: VERSION,
                encrypted: false,
                config,
            };
            let bytes = serde_json::to_vec_pretty(&file)
                .map_err(|e| AppError::Io(format!("failed to encode the export: {e}")))?;
            write_private_file(path, &bytes)?;
            return Ok(summary);
        }

        let passphrase = passphrase
            .ok_or_else(|| AppError::Invalid("an export with secrets needs a passphrase".into()))?;
        passphrase.require_non_empty("export passphrase")?;
        let mut secrets = Vec::new();
        {
            let vault = self.vault_read();
            if !vault.is_unlocked() {
                return Err(VaultError::Locked.into());
            }
            let types: HashMap<String, String> =
                vault.list_keys().into_iter().map(|r| (r.id, r.r#type)).collect();
            for id in referenced_records(&config) {
                let Some(record_type) = types.get(&id).cloned() else {
                    summary.missing_secrets += 1;
                    continue;
                };
                let value = vault.get_secret(&id)?;
                secrets.push(BundleSecret { id, record_type, value: value.to_vec() });
            }
        }
        summary.secret_count = secrets.len();

        let known_hosts = self
            .known_hosts()
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let payload = BundlePayload { config, known_hosts, secrets };
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&payload)
                .map_err(|e| AppError::Io(format!("failed to encode the export: {e}")))?,
        );
        drop(payload);

        let params = self.argon();
        let mut salt = generate_dek().to_bytes();
        salt.truncate(SALT_LEN);
        let key = bundle_key(passphrase.as_bytes(), &params, &salt)?;
        let file = EncryptedExport {
            format: FORMAT.into(),
            version: VERSION,
            encrypted: true,
            argon2: params,
            salt,
            payload: encrypt_record(&key, BUNDLE_RECORD_ID, BUNDLE_RECORD_TYPE, &plaintext),
        };
        let bytes = serde_json::to_vec(&file)
            .map_err(|e| AppError::Io(format!("failed to encode the export: {e}")))?;
        write_private_file(path, &bytes)?;
        Ok(summary)
    }

    /// Imports a plain or encrypted export, detected from the file. Nothing is changed unless
    /// every session and host in it is valid. Existing items are updated only with
    /// `replace_existing`; otherwise they are skipped.
    pub fn import_config(
        &self,
        path: &Path,
        passphrase: Option<SecretInput>,
        replace_existing: bool,
    ) -> Result<ImportSummary, AppError> {
        let io_error = |e: std::io::Error| AppError::Io(format!("failed to read {}: {e}", path.display()));
        if fs::metadata(path).map_err(io_error)?.len() > MAX_IMPORT_BYTES {
            return Err(AppError::Invalid("this file is too large to be a config export".into()));
        }
        let data = fs::read(path).map_err(io_error)?;
        let probe: Probe = serde_json::from_slice(&data).map_err(|_| not_an_export())?;
        if probe.format != FORMAT {
            return Err(not_an_export());
        }
        if probe.version != VERSION {
            return Err(AppError::Invalid(format!(
                "unsupported config export version {}",
                probe.version
            )));
        }
        if probe.encrypted {
            self.import_encrypted(&data, passphrase, replace_existing)
        } else {
            self.import_plain(&data, replace_existing)
        }
    }

    fn import_plain(&self, data: &[u8], replace: bool) -> Result<ImportSummary, AppError> {
        let file: PlainExport = serde_json::from_slice(data).map_err(|_| not_an_export())?;
        let mut incoming = file.config;
        prepare(&mut incoming)?;
        // Key metadata without its vault record would list a key that cannot be used.
        incoming.keys.clear();
        let (summary, changed) = self.mutate_config(move |config| {
            let removed = strip_untrusted_credentials(&mut incoming, config);
            let (mut summary, changed) = merge(config, incoming, replace, true);
            summary.credentials_removed += removed;
            Ok((summary, changed))
        })?;
        self.sync_profiles(changed);
        Ok(summary)
    }

    fn import_encrypted(
        &self,
        data: &[u8],
        passphrase: Option<SecretInput>,
        replace: bool,
    ) -> Result<ImportSummary, AppError> {
        let passphrase = passphrase
            .ok_or_else(|| AppError::Invalid("this export is encrypted and needs its passphrase".into()))?;
        passphrase.require_non_empty("export passphrase")?;
        if !self.vault_read().is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        let file: EncryptedExport = serde_json::from_slice(data).map_err(|_| not_an_export())?;
        check_bundle_params(&file)?;
        let key = bundle_key(passphrase.as_bytes(), &file.argon2, &file.salt)?;
        let plaintext = decrypt_record(&key, BUNDLE_RECORD_ID, BUNDLE_RECORD_TYPE, &file.payload)?;
        let BundlePayload { config: mut incoming, known_hosts, secrets } =
            serde_json::from_slice(&plaintext).map_err(|_| not_an_export())?;
        drop(plaintext);
        prepare(&mut incoming)?;

        // Skipped items must not bring their secrets along.
        let current = self.config_snapshot();
        let before = (incoming.sessions.len(), incoming.hosts.len());
        if !replace {
            incoming.sessions.retain(|s| !current.sessions.iter().any(|e| e.id == s.id));
            incoming.hosts.retain(|h| !current.hosts.iter().any(|e| e.id == h.id));
        }
        let sessions_skipped = before.0 - incoming.sessions.len();
        let hosts_skipped = before.1 - incoming.hosts.len();

        let mut restored = RestoredRecords::default();
        let stored = self.restore_records(&incoming, &secrets, &current, &mut restored);
        let merged = stored.and_then(|()| {
            let removed = restored.remap(&mut incoming);
            let metas = restored.new_metas.clone();
            self.mutate_config(move |config| {
                for meta in metas {
                    if !config.keys.iter().any(|k| k.fingerprint_sha256 == meta.fingerprint_sha256) {
                        config.keys.push(meta);
                    }
                }
                let (mut summary, changed) = merge(config, incoming, replace, false);
                summary.credentials_removed += removed;
                Ok((summary, changed))
            })
        });
        let (mut summary, changed) = match merged {
            Ok(merged) => merged,
            Err(error) => {
                let mut vault = self.vault_write();
                for id in &restored.created {
                    let _ = vault.delete_secret(id);
                }
                return Err(error);
            }
        };
        self.sync_profiles(changed);

        summary.encrypted = true;
        summary.sessions_skipped += sessions_skipped;
        summary.hosts_skipped += hosts_skipped;
        summary.keys_added = restored.new_metas.len();
        summary.secrets_added = restored.created.len() - restored.new_metas.len();
        let (added, updated) = self.merge_known_hosts(known_hosts, replace)?;
        summary.known_hosts_added = added;
        summary.known_hosts_updated = updated;
        Ok(summary)
    }

    /// Stores the bundle's keys and the passwords and passphrases `incoming` still refers to.
    fn restore_records(
        &self,
        incoming: &AppConfig,
        secrets: &[BundleSecret],
        current: &AppConfig,
        restored: &mut RestoredRecords,
    ) -> Result<(), AppError> {
        let find = |id: &str, kind: &str| {
            secrets.iter().find(|s| s.id == id && s.record_type == kind)
        };
        let mut fingerprints: HashMap<String, KeyId> = current
            .keys
            .iter()
            .map(|k| (k.fingerprint_sha256.clone(), k.id.clone()))
            .collect();
        for meta in &incoming.keys {
            let bundle_id = meta.id.to_string();
            let Some(secret) = find(&bundle_id, KEY_RECORD) else { continue };
            let text = std::str::from_utf8(&secret.value)
                .map_err(|_| AppError::Invalid(format!("key {bundle_id} is not valid text")))?;
            let (_, info) = conduit_vault::import_key(text, None)?;
            if info.fingerprint_sha256 != meta.fingerprint_sha256 {
                return Err(AppError::Invalid(format!(
                    "key {bundle_id} does not match its recorded fingerprint"
                )));
            }
            if let Some(existing) = fingerprints.get(&info.fingerprint_sha256) {
                restored.keys.insert(bundle_id, existing.clone());
                continue;
            }
            let record = self.vault_write().put_secret(KEY_RECORD, &secret.value)?;
            restored.created.push(record.clone());
            let id = key_id_from_record(&record)?;
            fingerprints.insert(info.fingerprint_sha256.clone(), id.clone());
            restored.keys.insert(bundle_id, id.clone());
            restored.new_metas.push(VaultKeyMeta {
                id,
                name: meta.name.clone(),
                algorithm: info.algorithm,
                fingerprint_sha256: info.fingerprint_sha256,
                public_key_openssh: info.public_key_openssh,
                source: meta.source,
                created_at: meta.created_at,
            });
        }

        let passwords: BTreeSet<String> = all_hosts(incoming)
            .flat_map(|h| &h.auth)
            .filter_map(|m| match m {
                AuthMethod::Password { secret } => Some(secret.to_string()),
                _ => None,
            })
            .collect();
        for id in passwords {
            if let Some(secret) = find(&id, PASSWORD_RECORD) {
                let reference = self.restore_secret(secret, restored)?;
                restored.passwords.insert(id, reference);
            }
        }
        let passphrases: BTreeSet<String> = incoming
            .sessions
            .iter()
            .filter_map(|s| s.mitm.as_ref()?.passphrase.as_ref())
            .map(ToString::to_string)
            .collect();
        for id in passphrases {
            if let Some(secret) = find(&id, PASSPHRASE_RECORD) {
                let reference = self.restore_secret(secret, restored)?;
                restored.passphrases.insert(id, reference);
            }
        }
        Ok(())
    }

    /// Reuses the record when this vault already holds the identical secret under the same id.
    fn restore_secret(
        &self,
        secret: &BundleSecret,
        restored: &mut RestoredRecords,
    ) -> Result<SecretRef, AppError> {
        if self.record_type(&secret.id).as_deref() == Some(secret.record_type.as_str()) {
            let existing = self.vault_read().get_secret(&secret.id)?;
            if existing.as_slice() == secret.value.as_slice() {
                return secret_ref_from_record(&secret.id);
            }
        }
        let record = self.vault_write().put_secret(&secret.record_type, &secret.value)?;
        restored.created.push(record.clone());
        secret_ref_from_record(&record)
    }

    /// Adds new pins. A pin that differs from an existing one replaces it only on request.
    fn merge_known_hosts(
        &self,
        incoming: KnownHostsStore,
        replace: bool,
    ) -> Result<(usize, usize), AppError> {
        let (mut added, mut updated) = (0, 0);
        {
            let mut store = self.known_hosts().write().unwrap_or_else(PoisonError::into_inner);
            for entry in incoming.entries {
                let existing = store.get(&entry.key.hop_id, &entry.key.host, entry.key.port);
                match existing {
                    None => added += 1,
                    Some(record) if *record != entry.record && replace => updated += 1,
                    Some(_) => continue,
                }
                store.insert(entry.key, entry.record);
            }
        }
        if added + updated > 0 {
            self.persist_known_hosts()?;
        }
        Ok((added, updated))
    }
}

#[cfg(test)]
mod tests {
    use super::super::keys::GenerateAlgorithm;
    use super::super::test_support::*;
    use super::*;
    use conduit_core::{HostKeyLookup, HostKeyRecord, MitmCaMode, MitmConfig, Timestamp};
    use serde_json::{json, Value};

    const PASSWORD: &str = "export-canary-password-71fe";
    const MITM: &str = "export-canary-mitm-pass-2c90";
    const BUNDLE_PASS: &str = "export-canary-bundle-pass-a4d1";

    struct Seed {
        key: VaultKeyMeta,
        password: SecretRef,
        session: Uuid,
        host: Uuid,
    }

    /// A linked host and a session that uses every kind of credential.
    fn seed(c: &AppController) -> Seed {
        let key = c.generate_key("seed-key", GenerateAlgorithm::Ed25519).unwrap();
        let password = c.set_password_secret(None, SecretInput::new(PASSWORD)).unwrap().secret_ref;
        let linked = c
            .upsert_host(host("linked", 22, vec![AuthMethod::Key { key: key.id.clone() }]))
            .unwrap();
        let mut session = profile("seed", 22);
        session.hops[0].host = linked.clone();
        session.hops[0].host.auth = vec![
            AuthMethod::Key { key: key.id.clone() },
            AuthMethod::Password { secret: password.clone() },
        ];
        session.hops[0].agent_forward = true;
        session.hops[0].agent_forward_keys = vec![key.id.clone()];
        session.mitm = Some(MitmConfig {
            ca_mode: MitmCaMode::Pkcs12 { path: "/tmp/seed.p12".into() },
            ..MitmConfig::default()
        });
        let saved = c.upsert_session(session).unwrap();
        c.set_mitm_passphrase(saved.id, SecretInput::new(MITM)).unwrap();
        Seed { key, password, session: saved.id, host: linked.id }
    }

    fn pin(fingerprint: &str) -> HostKeyRecord {
        HostKeyRecord {
            algorithm: "ssh-ed25519".into(),
            fingerprint_sha256: fingerprint.into(),
            first_seen: Timestamp(1),
            approved: true,
        }
    }

    fn lookup() -> HostKeyLookup {
        HostKeyLookup { hop_id: "hop-0".into(), host: "127.0.0.1".into(), port: 22 }
    }

    fn edit_json(path: &Path, edit: impl FnOnce(&mut Value)) {
        let mut value: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        edit(&mut value);
        fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
    }

    fn bundle(c: &AppController, dir: &TempDir) -> PathBuf {
        let path = dir.path().join("bundle.json");
        c.export_config(&path, true, Some(SecretInput::new(BUNDLE_PASS))).unwrap();
        path
    }

    fn pass() -> Option<SecretInput> {
        Some(SecretInput::new(BUNDLE_PASS))
    }

    #[tokio::test]
    async fn export_plain_holds_no_secret_values_and_is_owner_only() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        let seeded = seed(&c);
        let material = c.vault_read().get_secret(&seeded.key.id.to_string()).unwrap();
        let pem = String::from_utf8(material.to_vec()).unwrap();
        c.lock_vault();

        // A redacted export needs no vault access.
        let path = dir.path().join("plain.json");
        let summary = c.export_config(&path, false, None).unwrap();
        assert!(!summary.encrypted);
        assert_eq!((summary.session_count, summary.key_count, summary.secret_count), (1, 1, 0));

        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("seed-key"));
        for secret in [PASSWORD, MITM, "PRIVATE KEY", "ciphertext", "wrapped_dek"] {
            assert!(!text.contains(secret), "plain export leaked {secret}");
        }
        for line in pem.lines().filter(|l| !l.starts_with("-----") && l.len() >= 16) {
            assert!(!text.contains(line));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[tokio::test]
    async fn export_passphrase_rules() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        let path = dir.path().join("x.json");
        for bad in [None, Some(SecretInput::new(""))] {
            assert!(matches!(c.export_config(&path, true, bad), Err(AppError::Invalid(_))));
        }
        assert!(matches!(
            c.export_config(&path, false, pass()),
            Err(AppError::Invalid(_))
        ));
        assert!(!path.exists());
        c.lock_vault();
        assert!(matches!(
            c.export_config(&path, true, pass()),
            Err(AppError::Vault(VaultError::Locked))
        ));
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn export_encrypted_round_trip_restores_everything_under_new_ids() {
        let source_dir = TempDir::new();
        let c = unlocked(&source_dir).await;
        let seeded = seed(&c);
        c.known_hosts().write().unwrap().insert(lookup(), pin("SHA256:original"));
        let path = bundle(&c, &source_dir);

        let text = fs::read_to_string(&path).unwrap();
        for secret in [PASSWORD, MITM, BUNDLE_PASS, "PRIVATE KEY", "seed-key", "linked"] {
            assert!(!text.contains(secret), "bundle exposed {secret}");
        }

        let target_dir = TempDir::new();
        let t = unlocked(&target_dir).await;
        assert!(matches!(
            t.import_config(&path, Some(SecretInput::new("wrong")), false),
            Err(AppError::Vault(VaultError::UnlockFailed))
        ));
        assert!(matches!(t.import_config(&path, None, false), Err(AppError::Invalid(_))));
        assert_eq!(t.vault_read().record_count(), 0);

        let summary = t.import_config(&path, pass(), false).unwrap();
        assert!(summary.encrypted);
        assert_eq!((summary.sessions_added, summary.hosts_added), (1, 1));
        assert_eq!((summary.keys_added, summary.secrets_added), (1, 2));
        assert_eq!(summary.known_hosts_added, 1);
        assert_eq!(summary.credentials_removed, 0);

        let config = t.config_snapshot();
        let new_key = &config.keys[0];
        assert_ne!(new_key.id, seeded.key.id);
        assert_eq!(new_key.fingerprint_sha256, seeded.key.fingerprint_sha256);
        let hop = &config.sessions[0].hops[0];
        assert_eq!(hop.agent_forward_keys, vec![new_key.id.clone()]);
        assert_eq!(config.hosts[0].auth, vec![AuthMethod::Key { key: new_key.id.clone() }]);
        let AuthMethod::Password { secret } = &hop.host.auth[1] else { panic!("password lost") };
        assert_ne!(*secret, seeded.password);
        assert_eq!(t.vault_read().get_secret(&secret.to_string()).unwrap().as_slice(), PASSWORD.as_bytes());
        let mitm = config.sessions[0].mitm.as_ref().unwrap().passphrase.clone().unwrap();
        assert_eq!(t.vault_read().get_secret(&mitm.to_string()).unwrap().as_slice(), MITM.as_bytes());
        assert!(t.known_hosts().read().unwrap().contains_key("hop-0", "127.0.0.1", 22));
        assert!(target_dir.path().join("known_hosts.json").exists());
        assert!(t.manager().snapshot(seeded.session).is_ok(), "the runtime must know the session");
    }

    #[tokio::test]
    async fn export_encrypted_reimport_adds_no_duplicate_records() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        seed(&c);
        let path = bundle(&c, &dir);
        let records = c.vault_read().record_count();

        let skipped = c.import_config(&path, pass(), false).unwrap();
        assert_eq!((skipped.sessions_skipped, skipped.hosts_skipped), (1, 1));
        let updated = c.import_config(&path, pass(), true).unwrap();
        assert_eq!((updated.sessions_updated, updated.hosts_updated), (1, 1));
        assert_eq!((updated.keys_added, updated.secrets_added), (0, 0));
        assert_eq!(c.vault_read().record_count(), records);
        assert_eq!(c.config_snapshot().keys.len(), 1);
    }

    #[tokio::test]
    async fn export_import_changed_pin_needs_replace() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        seed(&c);
        c.known_hosts().write().unwrap().insert(lookup(), pin("SHA256:bundled"));
        let path = bundle(&c, &dir);
        c.known_hosts().write().unwrap().insert(lookup(), pin("SHA256:current"));
        let read = || {
            c.known_hosts().read().unwrap().get("hop-0", "127.0.0.1", 22).unwrap().fingerprint_sha256.clone()
        };

        assert_eq!(c.import_config(&path, pass(), false).unwrap().known_hosts_updated, 0);
        assert_eq!(read(), "SHA256:current");
        assert_eq!(c.import_config(&path, pass(), true).unwrap().known_hosts_updated, 1);
        assert_eq!(read(), "SHA256:bundled");
    }

    #[tokio::test]
    async fn export_import_needs_unlocked_vault_for_a_bundle() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        seed(&c);
        let path = bundle(&c, &dir);
        c.lock_vault();
        assert!(matches!(
            c.import_config(&path, pass(), true),
            Err(AppError::Vault(VaultError::Locked))
        ));
    }

    #[tokio::test]
    async fn export_tampered_bundle_is_rejected_and_changes_nothing() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        seed(&c);
        let path = bundle(&c, &dir);
        let before = c.config_snapshot();
        edit_json(&path, |v| {
            let byte = v["payload"][40].as_u64().unwrap();
            v["payload"][40] = json!(byte ^ 1);
        });
        assert!(matches!(
            c.import_config(&path, pass(), true),
            Err(AppError::Vault(VaultError::UnlockFailed))
        ));
        assert_eq!(c.config_snapshot(), before);
    }

    #[tokio::test]
    async fn export_bundle_with_hostile_kdf_cost_is_refused() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        let path = bundle(&c, &dir);
        edit_json(&path, |v| v["argon2"]["memory_kib"] = json!(u32::MAX));
        assert!(matches!(c.import_config(&path, pass(), false), Err(AppError::Invalid(_))));
    }

    #[tokio::test]
    async fn export_plain_import_on_a_fresh_install_carries_no_credentials() {
        let source_dir = TempDir::new();
        let c = unlocked(&source_dir).await;
        let seeded = seed(&c);
        let path = source_dir.path().join("plain.json");
        c.export_config(&path, false, None).unwrap();

        let target_dir = TempDir::new();
        let t = unlocked(&target_dir).await;
        let summary = t.import_config(&path, None, false).unwrap();
        assert!(!summary.encrypted);
        assert_eq!((summary.sessions_added, summary.hosts_added), (1, 1));
        // Host key, hop key, hop password, agent key, and MITM passphrase.
        assert_eq!(summary.credentials_removed, 5);

        let config = t.config_snapshot();
        assert!(config.keys.is_empty());
        assert!(config.hosts[0].auth.is_empty());
        let session = config.sessions.iter().find(|s| s.id == seeded.session).unwrap();
        assert!(session.hops[0].host.auth.is_empty());
        assert!(session.hops[0].agent_forward_keys.is_empty());
        assert_eq!(session.mitm.as_ref().unwrap().passphrase, None);
    }

    #[tokio::test]
    async fn export_plain_reimport_on_same_install_keeps_credentials() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        seed(&c);
        let before = c.config_snapshot();
        let path = dir.path().join("plain.json");
        c.export_config(&path, false, None).unwrap();

        let summary = c.import_config(&path, None, true).unwrap();
        assert_eq!(summary.credentials_removed, 0);
        assert_eq!((summary.sessions_updated, summary.hosts_updated), (1, 1));
        assert_eq!(c.config_snapshot(), before);
    }

    #[tokio::test]
    async fn export_edited_plain_file_cannot_send_credentials_to_a_new_host() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        let seeded = seed(&c);
        let path = dir.path().join("plain.json");
        c.export_config(&path, false, None).unwrap();
        edit_json(&path, |v| {
            v["config"]["sessions"][0]["hops"][0]["host"]["host"] = json!("attacker.example");
            v["config"]["sessions"][0]["mitm"]["ca_mode"] = json!({ "Pkcs12": { "path": "/tmp/evil.p12" } });
        });

        c.import_config(&path, None, true).unwrap();
        let config = c.config_snapshot();
        let session = config.sessions.iter().find(|s| s.id == seeded.session).unwrap();
        assert_eq!(session.hops[0].host.host, "attacker.example");
        assert!(session.hops[0].host.auth.is_empty());
        assert!(session.hops[0].agent_forward_keys.is_empty());
        assert_eq!(session.mitm.as_ref().unwrap().passphrase, None);
    }

    #[tokio::test]
    async fn export_edited_host_cannot_redirect_a_linked_hops_agent_keys() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        let seeded = seed(&c);
        let path = dir.path().join("plain.json");
        c.export_config(&path, false, None).unwrap();
        edit_json(&path, |v| {
            v["config"]["sessions"] = json!([]);
            v["config"]["hosts"][0]["host"] = json!("attacker.example");
        });

        c.import_config(&path, None, true).unwrap();
        let config = c.config_snapshot();
        assert_eq!(config.hosts[0].id, seeded.host);
        assert!(config.hosts[0].auth.is_empty());
        let hop = &config.sessions[0].hops[0];
        assert_eq!(hop.host.host, "attacker.example");
        assert!(hop.host.auth.is_empty());
        assert!(hop.agent_forward_keys.is_empty());
    }

    #[tokio::test]
    async fn export_import_invalid_content_changes_nothing() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        seed(&c);
        let before = c.config_snapshot();
        let path = dir.path().join("plain.json");
        c.export_config(&path, false, None).unwrap();
        let good = fs::read(&path).unwrap();

        edit_json(&path, |v| v["config"]["sessions"][0]["forward"]["allow"] = json!(["10.0.0.0/99"]));
        assert!(matches!(c.import_config(&path, None, true), Err(AppError::Validate(_))));

        fs::write(&path, &good).unwrap();
        edit_json(&path, |v| v["config"]["hosts"][0]["user"] = json!(" "));
        assert!(matches!(c.import_config(&path, None, true), Err(AppError::Invalid(_))));

        fs::write(&path, &good).unwrap();
        edit_json(&path, |v| {
            let session = v["config"]["sessions"][0].clone();
            v["config"]["sessions"].as_array_mut().unwrap().push(session);
        });
        assert!(matches!(c.import_config(&path, None, true), Err(AppError::Invalid(_))));

        fs::write(&path, &good).unwrap();
        edit_json(&path, |v| v["config"]["schema_version"] = json!(SCHEMA_VERSION + 1));
        assert!(matches!(c.import_config(&path, None, true), Err(AppError::Invalid(_))));

        fs::write(&path, &good).unwrap();
        edit_json(&path, |v| v["version"] = json!(VERSION + 1));
        assert!(matches!(c.import_config(&path, None, true), Err(AppError::Invalid(_))));

        fs::write(&path, b"{\"format\":\"something-else\",\"version\":1,\"encrypted\":false}").unwrap();
        assert!(matches!(c.import_config(&path, None, true), Err(AppError::Invalid(_))));
        fs::write(&path, PASSWORD).unwrap();
        let error = c.import_config(&path, None, true).unwrap_err();
        assert!(!error.to_string().contains(PASSWORD), "errors must not quote file content");

        assert_eq!(c.config_snapshot(), before);
    }
}
