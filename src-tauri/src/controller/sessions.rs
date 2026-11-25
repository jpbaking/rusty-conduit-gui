//! Session, host-profile, runtime, and host-key operations.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use conduit_core::{
    parse_openssh_known_hosts_for_host, validate, AppConfig, AuthMethod, HostKeyEntry, HostKeyLookup,
    HopEntry, HostKeyRecord, HostProfile, SessionProfile, Timestamp,
};
use conduit_runtime::{HostKeyPrompt, LogLine, SessionSnapshot};
use conduit_ssh::{
    test_chain, ChainOptions, ChannelPolicy, HopAuth, HopSpec, HopStatus, HostKeyVerifier, SshError,
};
use conduit_vault::{Vault, VaultError};
use serde::Serialize;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{AppController, AppError, VaultStatus};

/// A saved session with its live runtime view. Profiles hold opaque secret references only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionView {
    pub profile: SessionProfile,
    pub runtime: SessionSnapshot,
}

/// Everything the shell needs for its first paint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StateSummary {
    pub vault: VaultStatus,
    pub session_count: usize,
    pub host_count: usize,
    pub key_count: usize,
    pub sessions: Vec<SessionSnapshot>,
}

/// Per-hop result of a chain test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HopTestResult {
    pub hop_index: usize,
    pub hop_id: String,
    pub host: String,
    pub port: u16,
    /// `connected` | `failed` | `host_key_unknown` | `not_attempted`.
    pub status: &'static str,
    pub error: Option<String>,
    pub elapsed_ms: u64,
    /// The key the hop presented, when it is not pinned yet. The user may trust it, then retest.
    pub host_key: Option<HostKeyPrompt>,
}

/// Result of probing a session's chain prefix by prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChainTestResult {
    pub session_id: Uuid,
    pub all_connected: bool,
    pub hops: Vec<HopTestResult>,
}

fn not_found(kind: &'static str, id: impl ToString) -> AppError {
    AppError::NotFound { kind, id: id.to_string() }
}

/// Rejects auth methods that point at records the vault does not hold.
fn check_auth_refs(
    config: &AppConfig,
    records: &HashSet<String>,
    auth: &[AuthMethod],
) -> Result<(), AppError> {
    for method in auth {
        match method {
            AuthMethod::Key { key } if !config.keys.iter().any(|k| k.id == *key) => {
                return Err(not_found("key", key));
            }
            AuthMethod::Password { secret } if !records.contains(&secret.to_string()) => {
                return Err(not_found("secret", secret));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Resolves one hop credential, matching what the session runtime does at connect time.
fn resolve_auth(vault: &Vault, method: &AuthMethod) -> Result<Option<HopAuth>, AppError> {
    match method {
        AuthMethod::Key { key } => {
            let material = vault.get_secret(&key.to_string())?;
            let text = std::str::from_utf8(&material)
                .map_err(|_| AppError::Invalid(format!("key {key} is not valid text")))?;
            let (private, _) = conduit_vault::import_key(text, None)?;
            Ok(Some(HopAuth::Key(Arc::new(private))))
        }
        AuthMethod::Password { secret } => {
            let material = vault.get_secret(&secret.to_string())?;
            let text = std::str::from_utf8(&material)
                .map_err(|_| AppError::Invalid(format!("secret {secret} is not valid text")))?;
            Ok(Some(HopAuth::Password(Zeroizing::new(text.to_owned()))))
        }
        AuthMethod::KeyboardInteractive { .. } => Ok(Some(HopAuth::KeyboardInteractive(Vec::new()))),
        AuthMethod::SystemAgentOptIn => Ok(None),
    }
}

fn resolve_hops(profile: &SessionProfile, vault: &Vault) -> Result<Vec<HopSpec>, AppError> {
    let needs_vault = profile.hops.iter().any(|hop| {
        hop.host
            .auth
            .iter()
            .any(|m| matches!(m, AuthMethod::Key { .. } | AuthMethod::Password { .. }))
    });
    if needs_vault && !vault.is_unlocked() {
        return Err(VaultError::Locked.into());
    }
    profile
        .hops
        .iter()
        .map(|hop| {
            let mut auth = Vec::with_capacity(hop.host.auth.len());
            for method in &hop.host.auth {
                if let Some(resolved) = resolve_auth(vault, method)? {
                    auth.push(resolved);
                }
            }
            Ok(HopSpec {
                hop_id: hop.hop_id.clone(),
                host: hop.host.host.clone(),
                port: hop.host.port,
                user: hop.host.user.clone(),
                auth,
                // A chain test never accepts server-initiated channels.
                policy: ChannelPolicy::default(),
            })
        })
        .collect()
}

impl AppController {
    fn record_ids(&self) -> HashSet<String> {
        self.vault_read().list_keys().into_iter().map(|r| r.id).collect()
    }

    pub(crate) fn session_profile(&self, id: Uuid) -> Result<SessionProfile, AppError> {
        self.config_snapshot()
            .sessions
            .into_iter()
            .find(|s| s.id == id)
            .ok_or_else(|| not_found("session", id))
    }

    pub fn get_state_summary(&self) -> StateSummary {
        let config = self.config_snapshot();
        StateSummary {
            vault: self.vault_status(),
            session_count: config.sessions.len(),
            host_count: config.hosts.len(),
            key_count: config.keys.len(),
            sessions: self.manager().snapshots(),
        }
    }

    pub fn list_sessions(&self) -> Result<Vec<SessionView>, AppError> {
        self.config_snapshot()
            .sessions
            .into_iter()
            .map(|profile| {
                let runtime = self.manager().snapshot(profile.id)?;
                Ok(SessionView { profile, runtime })
            })
            .collect()
    }

    /// Validates and saves a session. A nil id or empty hop id is assigned here. A running
    /// session uses the update on its next start.
    pub fn upsert_session(&self, mut profile: SessionProfile) -> Result<SessionProfile, AppError> {
        if profile.id.is_nil() {
            profile.id = Uuid::new_v4();
        }
        for hop in &mut profile.hops {
            if hop.hop_id.trim().is_empty() {
                hop.hop_id = Uuid::new_v4().to_string();
            }
        }
        // A forward's id keys its live status, so a missing or repeated one gets a new id.
        let mut forward_ids = HashSet::new();
        for forward in &mut profile.port_forwards {
            if forward.id.is_nil() || !forward_ids.insert(forward.id) {
                forward.id = Uuid::new_v4();
                forward_ids.insert(forward.id);
            }
            forward.dest_host = forward.dest_host.trim().to_string();
        }
        // `hop_id` keys known_hosts, so two hops sharing one would share a host-key pin.
        let mut seen = HashSet::new();
        if let Some(hop) = profile.hops.iter().find(|h| !seen.insert(h.hop_id.as_str())) {
            return Err(AppError::Invalid(format!("duplicate hop id {:?}", hop.hop_id)));
        }
        validate(&profile)?;

        let records = self.record_ids();
        let saved = profile.clone();
        self.mutate_config(|config| {
            for hop in &profile.hops {
                check_auth_refs(config, &records, &hop.host.auth)?;
            }
            if let Some(ca) = profile.mitm.as_ref().and_then(|m| m.ca.as_ref()) {
                if !config.mitm_cas.iter().any(|c| c.id == *ca) {
                    return Err(not_found("MITM CA", ca));
                }
            }
            match config.sessions.iter_mut().find(|s| s.id == profile.id) {
                Some(existing) => *existing = profile,
                None => config.sessions.push(profile),
            }
            Ok(())
        })?;
        self.sync_profiles([saved.clone()]);
        Ok(saved)
    }

    /// Stops a session and removes it, with the host-key pins only its hops used.
    pub async fn delete_session(&self, id: Uuid) -> Result<(), AppError> {
        let profile = self.session_profile(id)?;
        self.manager().remove_profile(id).await?;
        let remaining = self.mutate_config(|config| {
            config.sessions.retain(|s| s.id != id);
            Ok(config.sessions.clone())
        })?;
        // Older configs may share a hop id between sessions; such a pin is still in use.
        let in_use: HashSet<&str> = remaining
            .iter()
            .flat_map(|s| s.hops.iter().map(|h| h.hop_id.as_str()))
            .collect();
        let orphaned: HashSet<&str> = profile
            .hops
            .iter()
            .map(|h| h.hop_id.as_str())
            .filter(|hop_id| !in_use.contains(hop_id))
            .collect();
        let removed = {
            let mut store = self
                .known_hosts()
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let before = store.entries.len();
            store.entries.retain(|e| !orphaned.contains(e.key.hop_id.as_str()));
            store.entries.len() != before
        };
        if removed {
            self.persist_known_hosts()?;
        }
        Ok(())
    }

    /// Saves a copy of a saved session, named "<name> (copy)" and not started with the app.
    ///
    /// Hops get new ids, because a hop id keys its host-key pin, and each trusted pin is copied
    /// to the new hop so the copy connects without asking again. Saved passwords and the MITM
    /// CA are shared by reference; replacing a password always writes a new record.
    pub fn duplicate_session(&self, id: Uuid) -> Result<SessionProfile, AppError> {
        let mut copy = self.session_profile(id)?;
        copy.id = Uuid::nil();
        copy.name = format!("{} (copy)", copy.name.trim());
        copy.autostart = false;
        let renamed: Vec<(String, HopEntry)> = copy
            .hops
            .iter_mut()
            .map(|hop| {
                let old = std::mem::replace(&mut hop.hop_id, Uuid::new_v4().to_string());
                (old, hop.clone())
            })
            .collect();
        let saved = self.upsert_session(copy)?;

        let copied = {
            let mut store = self
                .known_hosts()
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let pins: Vec<HostKeyEntry> = renamed
                .iter()
                .filter_map(|(old, hop)| {
                    let record = store.get(old, &hop.host.host, hop.host.port)?;
                    record.approved.then(|| HostKeyEntry {
                        key: HostKeyLookup {
                            hop_id: hop.hop_id.clone(),
                            host: hop.host.host.clone(),
                            port: hop.host.port,
                        },
                        record: record.clone(),
                    })
                })
                .collect();
            let copied = !pins.is_empty();
            for pin in pins {
                store.insert(pin.key, pin.record);
            }
            copied
        };
        if copied {
            self.persist_known_hosts()?;
        }
        Ok(saved)
    }

    pub fn list_hosts(&self) -> Vec<HostProfile> {
        self.config_snapshot().hosts
    }

    /// Saves a host. Hops linked to it (by `host.id`) receive the new connection details.
    pub fn upsert_host(&self, mut host: HostProfile) -> Result<HostProfile, AppError> {
        if host.id.is_nil() {
            host.id = Uuid::new_v4();
        }
        for (label, value) in [("name", &host.name), ("host", &host.host), ("user", &host.user)] {
            if value.trim().is_empty() {
                return Err(AppError::Invalid(format!("host {label} must not be empty")));
            }
        }
        let records = self.record_ids();
        let saved = host.clone();
        let changed = self.mutate_config(|config| {
            check_auth_refs(config, &records, &host.auth)?;
            let mut changed = Vec::new();
            for session in &mut config.sessions {
                let mut touched = false;
                for hop in session.hops.iter_mut().filter(|h| h.host.id == host.id) {
                    hop.host = host.clone();
                    touched = true;
                }
                if touched {
                    changed.push(session.clone());
                }
            }
            match config.hosts.iter_mut().find(|h| h.id == host.id) {
                Some(existing) => *existing = host,
                None => config.hosts.push(host),
            }
            Ok(changed)
        })?;
        self.sync_profiles(changed);
        Ok(saved)
    }

    /// Deletes a host. Linked hops keep working from their inline copy and become unlinked.
    pub fn delete_host(&self, id: Uuid) -> Result<(), AppError> {
        let changed = self.mutate_config(|config| {
            let before = config.hosts.len();
            config.hosts.retain(|h| h.id != id);
            if config.hosts.len() == before {
                return Err(not_found("host", id));
            }
            let mut changed = Vec::new();
            for session in &mut config.sessions {
                let mut touched = false;
                for hop in session.hops.iter_mut().filter(|h| h.host.id == id) {
                    hop.host.id = Uuid::nil();
                    touched = true;
                }
                if touched {
                    changed.push(session.clone());
                }
            }
            Ok(changed)
        })?;
        self.sync_profiles(changed);
        Ok(())
    }

    /// Saves an inline hop as a reusable host and links the hop to it.
    pub fn promote_hop_to_host(
        &self,
        session_id: Uuid,
        hop_id: &str,
        name: Option<&str>,
    ) -> Result<HostProfile, AppError> {
        let (session, host) = self.mutate_config(|config| {
            let known: HashSet<Uuid> = config.hosts.iter().map(|h| h.id).collect();
            let session = config
                .sessions
                .iter_mut()
                .find(|s| s.id == session_id)
                .ok_or_else(|| not_found("session", session_id))?;
            let hop = session
                .hops
                .iter_mut()
                .find(|h| h.hop_id == hop_id)
                .ok_or_else(|| not_found("hop", hop_id))?;
            if known.contains(&hop.host.id) {
                return Err(AppError::Invalid("this hop is already linked to a host".into()));
            }
            let chosen = name.map(str::trim).filter(|n| !n.is_empty());
            let mut host = hop.host.clone();
            host.id = Uuid::new_v4();
            host.name = chosen.unwrap_or(hop.name.as_str()).to_owned();
            hop.host.id = host.id;
            hop.host.name = host.name.clone();
            let session = session.clone();
            config.hosts.push(host.clone());
            Ok((session, host))
        })?;
        self.sync_profiles([session]);
        Ok(host)
    }

    pub async fn start_session(&self, id: Uuid) -> Result<(), AppError> {
        Ok(self.manager().start(id).await?)
    }

    pub async fn stop_session(&self, id: Uuid) -> Result<(), AppError> {
        Ok(self.manager().stop(id).await?)
    }

    pub async fn restart_session(&self, id: Uuid) -> Result<(), AppError> {
        Ok(self.manager().restart(id).await?)
    }

    pub async fn start_all(&self) {
        self.manager().start_all().await;
    }

    pub async fn stop_all(&self) {
        self.manager().stop_all().await;
    }

    /// Starts autostart sessions with a stagger. Sessions that need a locked vault wait in
    /// `Locked` and resume when it is unlocked.
    pub async fn start_autostart(&self) {
        self.manager().start_autostart_staggered().await;
    }

    pub fn get_session_logs(&self, id: Uuid, limit: Option<usize>) -> Result<Vec<LogLine>, AppError> {
        Ok(self.manager().logs(id)?.query(limit))
    }

    pub fn clear_session_logs(&self, id: Uuid) -> Result<(), AppError> {
        self.manager().logs(id)?.clear();
        Ok(())
    }

    /// Pins the key the user saw and saves it before returning.
    pub fn approve_host_key(&self, id: Uuid, sha256: &str) -> Result<(), AppError> {
        self.manager().approve_host_key(id, sha256)?;
        self.persist_known_hosts()
    }

    pub fn reject_host_key(&self, id: Uuid) -> Result<(), AppError> {
        Ok(self.manager().reject_host_key(id)?)
    }

    /// Returns all app-owned host-key pins (read-only metadata, never reads `~/.ssh/known_hosts`).
    pub fn list_host_key_pins(&self) -> Vec<conduit_core::HostKeyEntry> {
        self.known_hosts()
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
            .clone()
    }

    /// Forgets a pin so the next connection asks again. Returns whether a pin existed.
    pub fn reset_host_key(&self, hop_id: &str, host: &str, port: u16) -> Result<bool, AppError> {
        let removed = {
            let mut store = self
                .known_hosts()
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let before = store.entries.len();
            store
                .entries
                .retain(|e| !(e.key.hop_id == hop_id && e.key.host == host && e.key.port == port));
            store.entries.len() != before
        };
        if removed {
            self.persist_known_hosts()?;
        }
        Ok(removed)
    }

    /// Pins the key for `(hop_id, host, port)` from an OpenSSH `known_hosts` file the user chose.
    ///
    /// Reads only `path`, which the user supplies explicitly; `~/.ssh/known_hosts` is never read
    /// or used as a default. The first matching key replaces any existing pin and is saved.
    pub fn import_known_host_from_file(
        &self,
        hop_id: &str,
        host: &str,
        port: u16,
        path: &Path,
    ) -> Result<HostKeyEntry, AppError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| AppError::Io(format!("cannot read {}: {e}", path.display())))?;
        let imported = parse_openssh_known_hosts_for_host(&content, host, port)
            .into_iter()
            .next()
            .ok_or_else(|| not_found("known_hosts entry", format!("{host}:{port} in {}", path.display())))?;
        let entry = HostKeyEntry {
            key: HostKeyLookup { hop_id: hop_id.to_string(), host: host.to_string(), port },
            record: HostKeyRecord {
                algorithm: imported.algorithm,
                fingerprint_sha256: imported.fingerprint_sha256,
                first_seen: Timestamp::now(),
                approved: true,
                public_key_openssh: Some(imported.public_key),
            },
        };
        self.known_hosts()
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(entry.key.clone(), entry.record.clone());
        self.persist_known_hosts()?;
        Ok(entry)
    }

    /// Probes the chain hop by hop. Never pins a key by itself: an unknown key stops the test,
    /// and is kept so [`Self::trust_tested_host_key`] can pin exactly that key if the user agrees.
    pub async fn test_session_chain(&self, id: Uuid) -> Result<ChainTestResult, AppError> {
        self.tested_host_keys().remove(&id);
        let profile = self.session_profile(id)?;
        validate(&profile)?;
        let options = ChainOptions::from_tunnel(&profile.tunnel)
            .map_err(|e| AppError::Invalid(e.to_string()))?;
        let hops = resolve_hops(&profile, &self.vault_read())?;
        let verifier = HostKeyVerifier::from_shared(Arc::clone(self.known_hosts()));

        let report = test_chain(&hops, &verifier, &options).await;
        drop(hops);
        let all_connected = report.all_connected();
        let mut unknown_key = None;
        let hops = report
            .hops
            .into_iter()
            .map(|hop| {
                let (status, error, host_key) = match hop.status {
                    HopStatus::Connected => ("connected", None, None),
                    HopStatus::Failed(error) => match unknown_host_key(&error) {
                        Some(prompt) => {
                            unknown_key = Some(prompt.clone());
                            ("host_key_unknown", Some(error.to_string()), Some(prompt))
                        }
                        None => ("failed", Some(error.to_string()), None),
                    },
                    HopStatus::NotAttempted => ("not_attempted", None, None),
                };
                HopTestResult {
                    hop_index: hop.hop_index,
                    hop_id: hop.hop_id,
                    host: hop.host,
                    port: hop.port,
                    status,
                    error,
                    elapsed_ms: u64::try_from(hop.elapsed.as_millis()).unwrap_or(u64::MAX),
                    host_key,
                }
            })
            .collect();
        if let Some(prompt) = unknown_key {
            self.tested_host_keys().insert(id, prompt);
        }
        Ok(ChainTestResult { session_id: id, all_connected, hops })
    }

    /// Pins the unknown key the latest chain test of `id` saw, and saves it.
    ///
    /// `sha256` must be the fingerprint the user saw. A pin that already holds a different key
    /// is never replaced here: the user resets it explicitly first.
    pub fn trust_tested_host_key(&self, id: Uuid, sha256: &str) -> Result<HostKeyEntry, AppError> {
        let prompt = {
            let mut tested = self.tested_host_keys();
            match tested.get(&id) {
                None => return Err(not_found("tested host key", id)),
                Some(prompt) if prompt.sha256 != sha256 => {
                    return Err(AppError::Invalid(
                        "the host key changed since it was shown; test the chain again".into(),
                    ));
                }
                Some(_) => tested.remove(&id).expect("checked above"),
            }
        };
        let key = HostKeyLookup { hop_id: prompt.hop_id, host: prompt.host, port: prompt.port };
        let record = {
            let mut store = self
                .known_hosts()
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let existing = store.get(&key.hop_id, &key.host, key.port);
            if existing.is_some_and(|pin| pin.fingerprint_sha256 != prompt.sha256) {
                return Err(AppError::Invalid(
                    "this hop already has a different pinned key; reset it first".into(),
                ));
            }
            let record = HostKeyRecord {
                algorithm: prompt.algorithm,
                fingerprint_sha256: prompt.sha256,
                first_seen: existing.map_or_else(Timestamp::now, |pin| pin.first_seen),
                approved: true,
                public_key_openssh: prompt.public_key_openssh,
            };
            store.insert(key.clone(), record.clone());
            record
        };
        self.persist_known_hosts()?;
        Ok(HostKeyEntry { key, record })
    }
}

/// The prompt for a hop that failed only because its key is not trusted yet.
fn unknown_host_key(error: &SshError) -> Option<HostKeyPrompt> {
    let SshError::HostKeyUnknown { hop_index, hop_id, host, port, algorithm, sha256, public_key_openssh } =
        error
    else {
        return None;
    };
    Some(HostKeyPrompt {
        hop_index: *hop_index,
        hop_id: hop_id.clone(),
        host: host.clone(),
        port: *port,
        algorithm: algorithm.clone(),
        sha256: sha256.clone(),
        public_key_openssh: public_key_openssh.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::super::SecretInput;
    use super::*;
    use conduit_core::{load_known_hosts, KeyId, SecretRef};
    use conduit_runtime::{RuntimeError, SessionState};

    fn pin(c: &AppController, hop_id: &str, node: &Node) {
        c.known_hosts().write().unwrap().insert(
            HostKeyLookup { hop_id: hop_id.into(), host: "127.0.0.1".into(), port: node.port },
            HostKeyRecord {
                algorithm: node.host_key.algorithm().as_str().to_string(),
                fingerprint_sha256: node.fingerprint(),
                public_key_openssh: None,
                first_seen: Timestamp(1),
                approved: true,
            },
        );
    }

    fn password_session(c: &AppController, node: &Node, name: &str) -> SessionProfile {
        let secret = c
            .set_password_secret(None, SecretInput::new(SERVER_PASSWORD))
            .unwrap();
        let mut session = node.session(name);
        session.hops[0].host.auth = vec![AuthMethod::Password { secret: secret.secret_ref }];
        c.upsert_session(session).unwrap()
    }

    // Generated with `ssh-keygen -t ed25519`; fingerprint from `ssh-keygen -l`; hashed with
    // `ssh-keygen -H` for `example.com` (port 22).
    const IMPORT_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIMAKvbC1OkNvrNiAjJ6wli5nNQS5707OnbcrowxpV2Q";
    const IMPORT_FP: &str = "SHA256:9I6JDw93SZWDRe51mShFze57vAaKMdUWr3LkP0+FEEM";
    const IMPORT_HASHED_22: &str = "|1|P/k1CxSv4YGoqUDOlqdNkrBY8L4=|RBraJUa1OYhkRqoJgqCS5mwsc94=";

    fn write_known_hosts(dir: &TempDir, content: &str) -> std::path::PathBuf {
        let path = dir.path().join("user-known_hosts");
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn import_known_host_plain_entry_pins_and_persists() {
        let dir = TempDir::new();
        let c = controller(&dir);
        let path = write_known_hosts(&dir, &format!("# comment\n[example.com]:2222 {IMPORT_KEY}\n"));

        let entry = c.import_known_host_from_file("hop-1", "example.com", 2222, &path).unwrap();
        assert_eq!(entry.key, HostKeyLookup { hop_id: "hop-1".into(), host: "example.com".into(), port: 2222 });
        assert_eq!(entry.record.algorithm, "ssh-ed25519");
        assert_eq!(entry.record.fingerprint_sha256, IMPORT_FP);
        assert_eq!(entry.record.public_key_openssh.as_deref(), Some(IMPORT_KEY));
        assert!(entry.record.approved);
        assert!(entry.record.first_seen.0 > 0);

        let saved = load_known_hosts(&dir.path().join("known_hosts.json")).unwrap();
        assert_eq!(saved.get("hop-1", "example.com", 2222), Some(&entry.record));
        assert_eq!(c.list_host_key_pins(), vec![entry]);
    }

    #[test]
    fn import_known_host_hashed_entry_replaces_existing_pin() {
        let dir = TempDir::new();
        let c = controller(&dir);
        c.known_hosts().write().unwrap().insert(
            HostKeyLookup { hop_id: "hop-1".into(), host: "example.com".into(), port: 22 },
            HostKeyRecord {
                algorithm: "ssh-rsa".into(),
                fingerprint_sha256: "SHA256:old".into(),
                first_seen: Timestamp(1),
                approved: true,
                public_key_openssh: None,
            },
        );
        let path = write_known_hosts(&dir, &format!("{IMPORT_HASHED_22} {IMPORT_KEY}\n"));

        let entry = c.import_known_host_from_file("hop-1", "example.com", 22, &path).unwrap();
        assert_eq!(entry.record.fingerprint_sha256, IMPORT_FP);
        let saved = load_known_hosts(&dir.path().join("known_hosts.json")).unwrap();
        assert_eq!(saved.entries.len(), 1);
        assert_eq!(saved.get("hop-1", "example.com", 22).unwrap().fingerprint_sha256, IMPORT_FP);
    }

    #[test]
    fn import_known_host_without_match_is_not_found_and_pins_nothing() {
        let dir = TempDir::new();
        let c = controller(&dir);
        let path = write_known_hosts(&dir, &format!("other.com {IMPORT_KEY}\n@revoked example.com {IMPORT_KEY}\n"));

        let err = c.import_known_host_from_file("hop-1", "example.com", 22, &path).unwrap_err();
        assert!(matches!(err, AppError::NotFound { .. }), "{err:?}");
        assert!(c.known_hosts().read().unwrap().entries.is_empty());
        assert!(!dir.path().join("known_hosts.json").exists());
    }

    #[test]
    fn import_known_host_missing_file_is_an_io_error() {
        let dir = TempDir::new();
        let c = controller(&dir);
        let err = c
            .import_known_host_from_file("hop-1", "example.com", 22, &dir.path().join("missing"))
            .unwrap_err();
        assert!(matches!(err, AppError::Io(_)), "{err:?}");
        assert!(c.known_hosts().read().unwrap().entries.is_empty());
    }

    #[tokio::test]
    async fn sessions_upsert_assigns_ids_and_persists() {
        let dir = TempDir::new();
        let c = controller(&dir);
        let mut session = profile("one", 22);
        session.id = Uuid::nil();
        session.hops[0].hop_id = String::new();
        let saved = c.upsert_session(session).unwrap();
        assert!(!saved.id.is_nil());
        assert!(!saved.hops[0].hop_id.is_empty());

        let mut renamed = saved.clone();
        renamed.name = "two".into();
        c.upsert_session(renamed).unwrap();
        let listed = c.list_sessions().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].profile.name, "two");
        assert_eq!(listed[0].runtime.state, SessionState::Stopped);

        drop(c);
        let c = controller(&dir);
        assert_eq!(c.list_sessions().unwrap()[0].profile.id, saved.id);
    }

    #[tokio::test]
    async fn sessions_upsert_rejects_invalid_profiles() {
        let dir = TempDir::new();
        let c = controller(&dir);

        let mut no_hops = profile("x", 22);
        no_hops.hops.clear();
        assert!(matches!(c.upsert_session(no_hops), Err(AppError::Validate(_))));

        let mut no_listener = profile("x", 22);
        no_listener.forward.http_port = 0;
        assert!(matches!(c.upsert_session(no_listener), Err(AppError::Validate(_))));

        let mut duplicate = profile("x", 22);
        duplicate.hops.push(duplicate.hops[0].clone());
        assert!(matches!(c.upsert_session(duplicate), Err(AppError::Invalid(_))));

        let mut dangling_key = profile("x", 22);
        dangling_key.hops[0].host.auth = vec![AuthMethod::Key { key: KeyId::new() }];
        assert!(matches!(c.upsert_session(dangling_key), Err(AppError::NotFound { .. })));

        let mut dangling_secret = profile("x", 22);
        dangling_secret.hops[0].host.auth = vec![AuthMethod::Password { secret: SecretRef::new() }];
        assert!(matches!(c.upsert_session(dangling_secret), Err(AppError::NotFound { .. })));

        assert!(c.list_sessions().unwrap().is_empty());
    }

    #[tokio::test]
    async fn sessions_duplicate_copies_settings_pins_and_secret_refs() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        let secret = c.set_password_secret(None, SecretInput::new("pw")).unwrap().secret_ref;
        let mut original = profile("work", 2222);
        original.autostart = true;
        original.hops[0].host.auth = vec![AuthMethod::Password { secret: secret.clone() }];
        let original = c.upsert_session(original).unwrap();
        let fake = "SHA256:original".to_string();
        trust(&c, "hop-0", 2222, &fake);

        let copy = c.duplicate_session(original.id).unwrap();
        assert_ne!(copy.id, original.id);
        assert_eq!(copy.name, "work (copy)");
        assert!(!copy.autostart, "a copy must not start with the app beside the original");
        assert_eq!(copy.forward, original.forward);
        assert_eq!(copy.hops[0].host.auth, vec![AuthMethod::Password { secret }]);
        let new_hop = copy.hops[0].hop_id.clone();
        assert_ne!(new_hop, "hop-0", "hop ids key pins, so they must not be shared");

        let store = c.known_hosts().read().unwrap().clone();
        assert_eq!(store.get(&new_hop, "127.0.0.1", 2222).unwrap().fingerprint_sha256, fake);
        assert!(store.get("hop-0", "127.0.0.1", 2222).is_some(), "the original keeps its pin");
        assert_eq!(c.list_sessions().unwrap().len(), 2);
        assert!(matches!(c.duplicate_session(Uuid::new_v4()), Err(AppError::NotFound { .. })));
    }

    #[tokio::test]
    async fn sessions_delete_removes_only_its_own_pins() {
        let dir = TempDir::new();
        let c = controller(&dir);
        let gone = c.upsert_session(profile("gone", 2222)).unwrap();
        let mut kept = profile("kept", 2223);
        kept.hops[0].hop_id = "hop-kept".into();
        let kept = c.upsert_session(kept).unwrap();
        trust(&c, "hop-0", 2222, "SHA256:gone");
        trust(&c, "hop-kept", 2223, "SHA256:kept");

        c.delete_session(gone.id).await.unwrap();
        let store = c.known_hosts().read().unwrap().clone();
        assert!(store.get("hop-0", "127.0.0.1", 2222).is_none());
        assert!(store.get("hop-kept", "127.0.0.1", 2223).is_some());
        assert_eq!(c.list_sessions().unwrap()[0].profile.id, kept.id);
    }

    fn trust(c: &AppController, hop_id: &str, port: u16, fingerprint: &str) {
        c.known_hosts().write().unwrap().insert(
            HostKeyLookup { hop_id: hop_id.into(), host: "127.0.0.1".into(), port },
            HostKeyRecord {
                algorithm: "ssh-ed25519".into(),
                fingerprint_sha256: fingerprint.into(),
                public_key_openssh: None,
                first_seen: Timestamp(1),
                approved: true,
            },
        );
    }

    #[tokio::test]
    async fn sessions_delete_removes_from_config_and_manager() {
        let dir = TempDir::new();
        let c = controller(&dir);
        let saved = c.upsert_session(profile("gone", 22)).unwrap();
        c.delete_session(saved.id).await.unwrap();
        assert!(c.list_sessions().unwrap().is_empty());
        assert!(matches!(
            c.manager().snapshot(saved.id),
            Err(RuntimeError::UnknownSession(_))
        ));
        assert!(matches!(c.delete_session(saved.id).await, Err(AppError::NotFound { .. })));
    }

    #[tokio::test]
    async fn sessions_state_summary_counts_everything() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        c.upsert_session(profile("s", 22)).unwrap();
        c.upsert_host(host("h", 22, Vec::new())).unwrap();
        c.generate_key("k", super::super::keys::GenerateAlgorithm::Ed25519).unwrap();
        let summary = c.get_state_summary();
        assert_eq!(
            (summary.session_count, summary.host_count, summary.key_count),
            (1, 1, 1)
        );
        assert!(summary.vault.unlocked);
        assert_eq!(summary.sessions[0].name, "s");
    }

    #[tokio::test]
    async fn sessions_host_crud_propagates_to_linked_hops() {
        let dir = TempDir::new();
        let c = controller(&dir);
        let saved = c.upsert_host(host("bastion", 22, Vec::new())).unwrap();
        assert!(!saved.id.is_nil());

        let mut session = profile("linked", 22);
        session.hops[0].host = saved.clone();
        let session = c.upsert_session(session).unwrap();

        let mut moved = saved.clone();
        moved.port = 2222;
        c.upsert_host(moved).unwrap();
        assert_eq!(c.list_hosts()[0].port, 2222);
        assert_eq!(c.list_sessions().unwrap()[0].profile.hops[0].host.port, 2222);

        c.delete_host(saved.id).unwrap();
        assert!(c.list_hosts().is_empty());
        let hop = &c.list_sessions().unwrap()[0].profile.hops[0];
        assert_eq!(hop.host.port, 2222, "the inline copy keeps working");
        assert!(hop.host.id.is_nil());
        assert_eq!(c.list_sessions().unwrap()[0].profile.id, session.id);
        assert!(matches!(c.delete_host(saved.id), Err(AppError::NotFound { .. })));
    }

    #[tokio::test]
    async fn sessions_host_validation() {
        let dir = TempDir::new();
        let c = controller(&dir);
        let mut blank = host("h", 22, Vec::new());
        blank.user = " ".into();
        assert!(matches!(c.upsert_host(blank), Err(AppError::Invalid(_))));
        let dangling = host("h", 22, vec![AuthMethod::Key { key: KeyId::new() }]);
        assert!(matches!(c.upsert_host(dangling), Err(AppError::NotFound { .. })));
    }

    #[tokio::test]
    async fn sessions_promote_hop_links_it_to_a_new_host() {
        let dir = TempDir::new();
        let c = controller(&dir);
        let session = c.upsert_session(profile("s", 2200)).unwrap();
        let hop_id = session.hops[0].hop_id.clone();

        let promoted = c.promote_hop_to_host(session.id, &hop_id, Some(" Bastion ")).unwrap();
        assert_eq!(promoted.name, "Bastion");
        assert_eq!(promoted.port, 2200);
        assert_eq!(c.list_hosts().len(), 1);
        assert_eq!(c.list_sessions().unwrap()[0].profile.hops[0].host.id, promoted.id);

        assert!(matches!(
            c.promote_hop_to_host(session.id, &hop_id, None),
            Err(AppError::Invalid(_))
        ));
        assert!(matches!(
            c.promote_hop_to_host(session.id, "nope", None),
            Err(AppError::NotFound { .. })
        ));
        assert!(matches!(
            c.promote_hop_to_host(Uuid::new_v4(), &hop_id, None),
            Err(AppError::NotFound { .. })
        ));
    }

    #[tokio::test]
    async fn sessions_runtime_commands_reject_unknown_ids() {
        let dir = TempDir::new();
        let c = controller(&dir);
        let id = Uuid::new_v4();
        let unknown = |e: AppError| matches!(e, AppError::Runtime(RuntimeError::UnknownSession(_)));
        assert!(unknown(c.start_session(id).await.unwrap_err()));
        assert!(unknown(c.stop_session(id).await.unwrap_err()));
        assert!(unknown(c.restart_session(id).await.unwrap_err()));
        assert!(unknown(c.get_session_logs(id, None).unwrap_err()));
        assert!(unknown(c.clear_session_logs(id).unwrap_err()));
        assert!(unknown(c.approve_host_key(id, "SHA256:x").unwrap_err()));
        assert!(unknown(c.reject_host_key(id).unwrap_err()));
        assert!(matches!(c.test_session_chain(id).await, Err(AppError::NotFound { .. })));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sessions_locked_vault_parks_session_and_unlock_resumes_it() {
        let dir = TempDir::new();
        let node = spawn_node().await;
        let c = unlocked(&dir).await;
        let session = password_session(&c, &node, "locked");
        pin(&c, "hop-0", &node);
        c.lock_vault();

        c.start_session(session.id).await.unwrap();
        wait_for_state(&c, session.id, SessionState::Locked).await;

        c.unlock_vault_with_password(SecretInput::new("master")).await.unwrap();
        wait_for_state(&c, session.id, SessionState::Connected).await;
        c.stop_all().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sessions_host_key_approval_connects_and_persists_pin() {
        let dir = TempDir::new();
        let node = spawn_node().await;
        let c = unlocked(&dir).await;
        let session = password_session(&c, &node, "approve");

        c.start_session(session.id).await.unwrap();
        let prompt = wait_for_prompt(&c, session.id).await;
        assert_eq!(prompt.sha256, node.fingerprint());
        assert!(c.approve_host_key(session.id, "SHA256:wrong").is_err());

        c.approve_host_key(session.id, &prompt.sha256).unwrap();
        wait_for_state(&c, session.id, SessionState::Connected).await;
        let saved = load_known_hosts(&dir.path().join("known_hosts.json")).unwrap();
        assert!(saved.get(&prompt.hop_id, &prompt.host, prompt.port).unwrap().approved);

        c.restart_session(session.id).await.unwrap();
        wait_for_state(&c, session.id, SessionState::Connected).await;
        c.stop_session(session.id).await.unwrap();
        assert_eq!(
            c.manager().snapshot(session.id).unwrap().state,
            SessionState::Stopped
        );

        let logs = c.get_session_logs(session.id, None).unwrap();
        assert!(!logs.is_empty(), "the proxy logs its listener");
        c.clear_session_logs(session.id).unwrap();
        assert!(c.get_session_logs(session.id, None).unwrap().is_empty());

        assert!(c.reset_host_key(&prompt.hop_id, &prompt.host, prompt.port).unwrap());
        assert!(!c.reset_host_key(&prompt.hop_id, &prompt.host, prompt.port).unwrap());
        let saved = load_known_hosts(&dir.path().join("known_hosts.json")).unwrap();
        assert!(saved.get(&prompt.hop_id, &prompt.host, prompt.port).is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sessions_host_key_rejection_needs_attention_and_pins_nothing() {
        let dir = TempDir::new();
        let node = spawn_node().await;
        let c = unlocked(&dir).await;
        let session = password_session(&c, &node, "reject");

        c.start_session(session.id).await.unwrap();
        wait_for_prompt(&c, session.id).await;
        c.reject_host_key(session.id).unwrap();

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            let state = c.manager().snapshot(session.id).unwrap().state;
            if matches!(state, SessionState::NeedsAttention { .. }) {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "state: {state:?}");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(c.known_hosts().read().unwrap().entries.is_empty());
        c.stop_session(session.id).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sessions_start_all_and_stop_all() {
        let dir = TempDir::new();
        let node = spawn_node().await;
        let c = unlocked(&dir).await;
        let a = password_session(&c, &node, "a");
        let b = password_session(&c, &node, "b");
        pin(&c, "hop-0", &node);

        c.start_all().await;
        wait_for_state(&c, a.id, SessionState::Connected).await;
        wait_for_state(&c, b.id, SessionState::Connected).await;
        c.stop_all().await;
        wait_for_state(&c, a.id, SessionState::Stopped).await;
        wait_for_state(&c, b.id, SessionState::Stopped).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sessions_chain_test_reports_each_hop() {
        let dir = TempDir::new();
        let node = spawn_node().await;
        let c = unlocked(&dir).await;
        let secret = c
            .set_password_secret(None, SecretInput::new(SERVER_PASSWORD))
            .unwrap()
            .secret_ref;
        let auth = vec![AuthMethod::Password { secret }];

        // Hop 1 tunnels through hop 0 back to the same server.
        let mut session = node.session("chain");
        session.hops = vec![hop("hop-0", node.port, auth.clone()), hop("hop-1", node.port, auth)];
        let session = c.upsert_session(session).unwrap();

        // Unknown key: the first hop stops with the key it saw, the second is not attempted, and
        // nothing is pinned until the user trusts it.
        let report = c.test_session_chain(session.id).await.unwrap();
        assert!(!report.all_connected);
        assert_eq!(report.hops[0].status, "host_key_unknown");
        assert!(report.hops[0].error.as_deref().unwrap().contains("unknown host key"));
        let seen = report.hops[0].host_key.clone().expect("the unknown key is reported");
        assert_eq!(seen.hop_id, "hop-0");
        assert_eq!(seen.sha256, node.fingerprint());
        assert_eq!(report.hops[1].status, "not_attempted");
        assert_eq!(report.hops[1].elapsed_ms, 0);
        assert!(c.known_hosts().read().unwrap().entries.is_empty());

        // Only the fingerprint that was shown can be trusted.
        assert!(matches!(
            c.trust_tested_host_key(session.id, "SHA256:something-else"),
            Err(AppError::Invalid(_))
        ));
        assert!(c.known_hosts().read().unwrap().entries.is_empty());

        // Trusting hop 0 pins it, so the test moves on to hop 1's unknown key.
        let entry = c.trust_tested_host_key(session.id, &seen.sha256).unwrap();
        assert!(entry.record.approved);
        assert_eq!(entry.key.hop_id, "hop-0");
        assert!(matches!(
            c.trust_tested_host_key(session.id, &seen.sha256),
            Err(AppError::NotFound { .. })
        ));
        let report = c.test_session_chain(session.id).await.unwrap();
        assert_eq!(report.hops[0].status, "connected");
        assert_eq!(report.hops[1].status, "host_key_unknown");

        pin(&c, "hop-1", &node);
        let report = c.test_session_chain(session.id).await.unwrap();
        assert!(report.all_connected);
        assert_eq!(report.hops[1].hop_id, "hop-1");
        assert_eq!(report.hops[1].port, node.port);
    }

    #[tokio::test]
    async fn sessions_chain_test_needs_unlocked_vault_for_secrets() {
        let dir = TempDir::new();
        let node = spawn_node().await;
        let c = unlocked(&dir).await;
        let session = password_session(&c, &node, "locked-test");
        c.lock_vault();
        assert!(matches!(
            c.test_session_chain(session.id).await,
            Err(AppError::Vault(VaultError::Locked))
        ));
    }
}
