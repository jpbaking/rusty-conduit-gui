//! Tunnel operations: CRUD, lifecycle, safe deletion, host keys, and Test Chain.
//!
//! A Tunnel is the SSH half of a v1 session. Proxies route through it with a `tunnel` upstream
//! profile, so deleting one that Proxies reference needs confirmation.

use std::collections::HashSet;
use std::sync::Arc;

use conduit_core::{
    proxy_referenced_tunnels, validate_tunnel, AppConfig, AuthMethod, HopEntry, HostKeyEntry,
    HostKeyLookup, Tunnel, TunnelId, TunnelStartMode,
};
use conduit_runtime::{HostKeyPrompt, LogLine, ProxyError, TunnelSnapshot};
use conduit_ssh::{
    test_chain, ChainOptions, ChannelPolicy, HopAuth, HopSpec, HopStatus, HostKeyVerifier, SshError,
};
use conduit_vault::{Vault, VaultError};
use serde::Serialize;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::keys::{proxy_ref, DeleteResult, Usage, UsageRef};
use super::sessions::HopTestResult;
use super::{AppController, AppError};

/// A saved Tunnel with its live view and the Proxies that route through it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TunnelView {
    pub profile: Tunnel,
    pub snapshot: TunnelSnapshot,
    pub used_by: Vec<UsageRef>,
}

/// Result of probing a Tunnel's chain prefix by prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TunnelChainTestResult {
    pub tunnel_id: TunnelId,
    pub all_connected: bool,
    pub hops: Vec<HopTestResult>,
}

fn not_found(kind: &'static str, id: impl ToString) -> AppError {
    AppError::NotFound { kind, id: id.to_string() }
}

/// The Proxies whose upstream profiles route through `id`.
pub(crate) fn tunnel_users(config: &AppConfig, id: TunnelId) -> Vec<UsageRef> {
    config
        .proxies
        .iter()
        .filter(|p| proxy_referenced_tunnels(p).contains(&id))
        .map(proxy_ref)
        .collect()
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

/// Resolves one hop credential, matching what the Tunnel runtime does at connect time.
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

fn resolve_hops(tunnel: &Tunnel, vault: &Vault) -> Result<Vec<HopSpec>, AppError> {
    let needs_vault = tunnel.hops.iter().any(|hop| {
        hop.host
            .auth
            .iter()
            .any(|m| matches!(m, AuthMethod::Key { .. } | AuthMethod::Password { .. }))
    });
    if needs_vault && !vault.is_unlocked() {
        return Err(VaultError::Locked.into());
    }
    tunnel
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

impl AppController {
    pub(crate) fn tunnel_profile(&self, id: TunnelId) -> Result<Tunnel, AppError> {
        self.config_snapshot()
            .tunnels
            .into_iter()
            .find(|t| t.id == id)
            .ok_or_else(|| not_found("tunnel", id))
    }

    pub fn list_tunnels(&self) -> Result<Vec<TunnelView>, AppError> {
        let config = self.config_snapshot();
        config
            .tunnels
            .iter()
            .map(|profile| {
                let snapshot = self.tunnels().snapshot(profile.id)?;
                let used_by = tunnel_users(&config, profile.id);
                Ok(TunnelView { profile: profile.clone(), snapshot, used_by })
            })
            .collect()
    }

    /// Validates and saves a Tunnel. A nil id, empty hop id, or missing forward id is assigned
    /// here. A running Tunnel uses the update on its next start.
    pub fn upsert_tunnel(&self, mut tunnel: Tunnel) -> Result<Tunnel, AppError> {
        if tunnel.id.as_uuid().is_nil() {
            tunnel.id = TunnelId::new();
        }
        tunnel.name = super::keys::require_name(&tunnel.name)?;
        for hop in &mut tunnel.hops {
            if hop.hop_id.trim().is_empty() {
                hop.hop_id = Uuid::new_v4().to_string();
            }
        }
        // A forward's id keys its live status, so a missing or repeated one gets a new id.
        let mut forward_ids = HashSet::new();
        for forward in &mut tunnel.port_forwards {
            if forward.id.is_nil() || !forward_ids.insert(forward.id) {
                forward.id = Uuid::new_v4();
                forward_ids.insert(forward.id);
            }
            forward.dest_host = forward.dest_host.trim().to_string();
        }
        // `hop_id` keys known_hosts, so two hops sharing one would share a host-key pin.
        let mut seen = HashSet::new();
        if let Some(hop) = tunnel.hops.iter().find(|h| !seen.insert(h.hop_id.as_str())) {
            return Err(AppError::Invalid(format!("duplicate hop id {:?}", hop.hop_id)));
        }
        validate_tunnel(&tunnel)?;

        let records = self.record_ids_v2();
        let saved = tunnel.clone();
        self.mutate_config(|config| {
            for hop in &tunnel.hops {
                check_auth_refs(config, &records, &hop.host.auth)?;
            }
            if let Some(ca) = tunnel.mitm.as_ref().and_then(|m| m.ca.as_ref()) {
                if !config.mitm_cas.iter().any(|c| c.id == *ca) {
                    return Err(not_found("MITM CA", ca));
                }
            }
            match config.tunnels.iter_mut().find(|t| t.id == tunnel.id) {
                Some(existing) => *existing = tunnel,
                None => config.tunnels.push(tunnel),
            }
            Ok(())
        })?;
        self.sync_tunnels([saved.clone()]);
        Ok(saved)
    }

    pub(crate) fn record_ids_v2(&self) -> HashSet<String> {
        self.vault_read().list_keys().into_iter().map(|r| r.id).collect()
    }

    /// Deletes a Tunnel. If Proxies route through it and `force` is false, nothing changes and
    /// they are returned. With `force`, those Proxies are stopped and keep their reference,
    /// which then keeps them from starting until it is fixed. Host-key pins only this Tunnel's
    /// hops used are removed.
    pub async fn delete_tunnel(&self, id: TunnelId, force: bool) -> Result<DeleteResult, AppError> {
        let config = self.config_snapshot();
        let tunnel = config
            .tunnels
            .iter()
            .find(|t| t.id == id)
            .cloned()
            .ok_or_else(|| not_found("tunnel", id))?;
        let usage = Usage { proxies: tunnel_users(&config, id), ..Usage::default() };
        let used_by = usage.count();
        if used_by > 0 && !force {
            return Ok(DeleteResult { deleted: false, used_by, usage });
        }
        for user in &usage.proxies {
            match self.proxies().stop(conduit_core::ProxyId::from_uuid(user.id)).await {
                Ok(()) | Err(ProxyError::UnknownProxy(_)) => {}
                Err(error) => return Err(error.into()),
            }
        }
        self.tunnels().remove_tunnel(id).await?;
        let controller = self.clone();
        let remaining = super::run_blocking(move || {
            controller.mutate_config(|config| {
                config.tunnels.retain(|t| t.id != id);
                Ok(config.clone())
            })
        })
        .await?;
        self.forget_orphaned_pins(&tunnel.hops, &remaining)?;
        Ok(DeleteResult { deleted: true, used_by, usage })
    }

    /// Removes the host-key pins of `hops` that no saved session or Tunnel still uses.
    fn forget_orphaned_pins(&self, hops: &[HopEntry], remaining: &AppConfig) -> Result<(), AppError> {
        let in_use: HashSet<&str> = remaining
            .sessions
            .iter()
            .flat_map(|s| s.hops.iter())
            .chain(remaining.tunnels.iter().flat_map(|t| t.hops.iter()))
            .map(|h| h.hop_id.as_str())
            .collect();
        let orphaned: HashSet<&str> = hops
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

    /// Saves a copy of a Tunnel, named "<name> (copy)" and not started with the app.
    ///
    /// Hops get new ids, because a hop id keys its host-key pin, and each trusted pin is copied
    /// to the new hop so the copy connects without asking again.
    pub fn duplicate_tunnel(&self, id: TunnelId) -> Result<Tunnel, AppError> {
        let mut copy = self.tunnel_profile(id)?;
        copy.id = TunnelId::new();
        copy.name = format!("{} (copy)", copy.name.trim());
        if let TunnelStartMode::Manual { autostart } = &mut copy.start_mode {
            *autostart = false;
        }
        let renamed: Vec<(String, HopEntry)> = copy
            .hops
            .iter_mut()
            .map(|hop| {
                let old = std::mem::replace(&mut hop.hop_id, Uuid::new_v4().to_string());
                (old, hop.clone())
            })
            .collect();
        let saved = self.upsert_tunnel(copy)?;

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

    pub async fn start_tunnel(&self, id: TunnelId) -> Result<(), AppError> {
        Ok(self.tunnels().start(id).await?)
    }

    pub async fn stop_tunnel(&self, id: TunnelId) -> Result<(), AppError> {
        Ok(self.tunnels().stop(id).await?)
    }

    pub async fn restart_tunnel(&self, id: TunnelId) -> Result<(), AppError> {
        Ok(self.tunnels().restart(id).await?)
    }

    pub fn get_tunnel_logs(&self, id: TunnelId, limit: Option<usize>) -> Result<Vec<LogLine>, AppError> {
        Ok(self.tunnels().logs(id)?.query(limit))
    }

    pub fn clear_tunnel_logs(&self, id: TunnelId) -> Result<(), AppError> {
        self.tunnels().logs(id)?.clear();
        Ok(())
    }

    /// Pins the key the user saw and saves it before returning.
    pub fn approve_tunnel_host_key(&self, id: TunnelId, sha256: &str) -> Result<(), AppError> {
        self.tunnels().approve_host_key(id, sha256)?;
        self.persist_known_hosts()
    }

    pub fn reject_tunnel_host_key(&self, id: TunnelId) -> Result<(), AppError> {
        Ok(self.tunnels().reject_host_key(id)?)
    }

    /// Probes the Tunnel's chain hop by hop. Never pins a key by itself: an unknown key stops
    /// the test, and is kept (under the Tunnel's UUID) so `trust_tested_host_key` can pin
    /// exactly that key if the user agrees.
    pub async fn test_tunnel_chain(&self, id: TunnelId) -> Result<TunnelChainTestResult, AppError> {
        self.tested_host_keys().remove(&id.as_uuid());
        let tunnel = self.tunnel_profile(id)?;
        validate_tunnel(&tunnel)?;
        let options = ChainOptions::from_tunnel(&tunnel.keepalive)
            .map_err(|e| AppError::Invalid(e.to_string()))?;
        let hops = resolve_hops(&tunnel, &self.vault_read())?;
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
            self.tested_host_keys().insert(id.as_uuid(), prompt);
        }
        Ok(TunnelChainTestResult { tunnel_id: id, all_connected, hops })
    }

}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::super::SecretInput;
    use super::*;
    use conduit_core::{HostKeyRecord, Proxy, ProxyId, Timestamp, UpstreamKind, UpstreamProfile};
    use conduit_runtime::SessionState;

    /// A Manual Tunnel to `port` on loopback.
    pub(crate) fn tunnel(name: &str, port: u16) -> Tunnel {
        Tunnel {
            name: name.into(),
            start_mode: TunnelStartMode::Manual { autostart: false },
            hops: vec![hop("", port, Vec::new())],
            ..Tunnel::default()
        }
    }

    fn proxy_through(name: &str, tunnel_id: TunnelId) -> Proxy {
        Proxy {
            id: ProxyId::new(),
            name: name.into(),
            profiles: vec![UpstreamProfile {
                name: "t".into(),
                kind: UpstreamKind::Tunnel { tunnel_id },
                host: None,
                port: None,
                username: None,
                password: None,
                bypass: Vec::new(),
                color: None,
            }],
            ..Proxy::default()
        }
    }

    #[tokio::test]
    async fn tunnels_upsert_assigns_ids_persists_and_lists() {
        let dir = TempDir::new();
        let c = controller(&dir);
        let saved = c.upsert_tunnel(tunnel("bastion", 22)).unwrap();
        assert!(!saved.id.as_uuid().is_nil());
        assert!(!saved.hops[0].hop_id.is_empty());

        let mut renamed = saved.clone();
        renamed.name = "jump".into();
        c.upsert_tunnel(renamed).unwrap();
        let listed = c.list_tunnels().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].profile.name, "jump");
        assert_eq!(listed[0].snapshot.state, SessionState::Stopped);
        assert!(listed[0].used_by.is_empty());

        drop(c);
        let c = controller(&dir);
        assert_eq!(c.list_tunnels().unwrap()[0].profile.id, saved.id);
        assert_eq!(c.tunnels().snapshots().len(), 1, "reopen loads saved Tunnels");
    }

    #[tokio::test]
    async fn tunnels_upsert_rejects_invalid_tunnels_and_unknown_secrets() {
        let dir = TempDir::new();
        let c = controller(&dir);
        let mut empty = tunnel("none", 22);
        empty.hops.clear();
        assert!(matches!(c.upsert_tunnel(empty), Err(AppError::Validate(_))));

        let mut blank = tunnel("  ", 22);
        blank.hops[0].hop_id = "h".into();
        assert!(matches!(c.upsert_tunnel(blank), Err(AppError::Invalid(_))));

        let mut twins = tunnel("twins", 22);
        twins.hops = vec![hop("same", 22, Vec::new()), hop("same", 23, Vec::new())];
        assert!(matches!(c.upsert_tunnel(twins), Err(AppError::Invalid(_))));

        let mut ghost = tunnel("ghost", 22);
        ghost.hops[0].host.auth =
            vec![AuthMethod::Password { secret: conduit_core::SecretRef::new() }];
        assert!(matches!(c.upsert_tunnel(ghost), Err(AppError::NotFound { .. })));
        assert!(c.config_snapshot().tunnels.is_empty());
    }

    #[tokio::test]
    async fn tunnels_delete_referenced_needs_force_and_stops_the_proxies() {
        let dir = TempDir::new();
        let c = controller(&dir);
        let t = c.upsert_tunnel(tunnel("bastion", 22)).unwrap();
        let p = proxy_through("web", t.id);
        c.mutate_config(|config| {
            config.proxies.push(p.clone());
            Ok(())
        })
        .unwrap();

        assert_eq!(c.list_tunnels().unwrap()[0].used_by[0].name, "web");
        let refused = c.delete_tunnel(t.id, false).await.unwrap();
        assert!(!refused.deleted);
        assert_eq!(refused.used_by, 1);
        assert_eq!(refused.usage.proxies[0].id, p.id.as_uuid());
        assert_eq!(c.config_snapshot().tunnels.len(), 1);

        let forced = c.delete_tunnel(t.id, true).await.unwrap();
        assert!(forced.deleted);
        assert!(c.config_snapshot().tunnels.is_empty());
        assert!(c.tunnels().snapshots().is_empty());
        // The Proxy keeps its now-dangling reference, which blocks it from starting.
        assert_eq!(c.config_snapshot().proxies[0].profiles.len(), 1);
        assert!(matches!(c.delete_tunnel(t.id, true).await, Err(AppError::NotFound { .. })));
    }

    #[tokio::test]
    async fn tunnels_delete_forgets_only_orphaned_pins() {
        let dir = TempDir::new();
        let c = controller(&dir);
        let t = c.upsert_tunnel(tunnel("bastion", 22)).unwrap();
        let hop_id = t.hops[0].hop_id.clone();
        let record = HostKeyRecord {
            algorithm: "ssh-ed25519".into(),
            fingerprint_sha256: "SHA256:abc".into(),
            first_seen: Timestamp(1),
            approved: true,
            public_key_openssh: None,
        };
        c.known_hosts().write().unwrap().insert(
            HostKeyLookup { hop_id: hop_id.clone(), host: "127.0.0.1".into(), port: 22 },
            record.clone(),
        );
        c.known_hosts().write().unwrap().insert(
            HostKeyLookup { hop_id: "other".into(), host: "127.0.0.1".into(), port: 22 },
            record,
        );
        let copy = c.duplicate_tunnel(t.id).unwrap();
        assert!(copy.name.ends_with(" (copy)"));
        assert_ne!(copy.hops[0].hop_id, hop_id);
        assert!(c.known_hosts().read().unwrap().contains_key(&copy.hops[0].hop_id, "127.0.0.1", 22));

        c.delete_tunnel(t.id, false).await.unwrap();
        let store = c.known_hosts().read().unwrap().clone();
        assert!(!store.contains_key(&hop_id, "127.0.0.1", 22));
        assert!(store.contains_key("other", "127.0.0.1", 22));
        assert!(store.contains_key(&copy.hops[0].hop_id, "127.0.0.1", 22));
    }

    #[tokio::test]
    async fn tunnels_duplicate_turns_off_autostart() {
        let dir = TempDir::new();
        let c = controller(&dir);
        let mut t = tunnel("auto", 22);
        t.start_mode = TunnelStartMode::Manual { autostart: true };
        let t = c.upsert_tunnel(t).unwrap();
        let copy = c.duplicate_tunnel(t.id).unwrap();
        assert_eq!(copy.start_mode, TunnelStartMode::Manual { autostart: false });
        assert_ne!(copy.id, t.id);
        assert_eq!(c.list_tunnels().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn tunnels_lifecycle_logs_and_host_key_errors() {
        let dir = TempDir::new();
        let c = controller(&dir);
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let t = c.upsert_tunnel(tunnel("closed", closed)).unwrap();
        c.start_tunnel(t.id).await.unwrap();
        c.restart_tunnel(t.id).await.unwrap();
        c.stop_tunnel(t.id).await.unwrap();
        assert_eq!(c.tunnels().snapshot(t.id).unwrap().state, SessionState::Stopped);
        assert!(c.get_tunnel_logs(t.id, Some(10)).is_ok());
        c.clear_tunnel_logs(t.id).unwrap();
        assert!(c.get_tunnel_logs(t.id, None).unwrap().is_empty());
        assert!(matches!(c.approve_tunnel_host_key(t.id, "SHA256:x"), Err(AppError::Tunnel(_))));
        assert!(matches!(c.reject_tunnel_host_key(t.id), Err(AppError::Tunnel(_))));
        let unknown = TunnelId::new();
        assert!(matches!(c.start_tunnel(unknown).await, Err(AppError::Tunnel(_))));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn tunnels_test_chain_reports_an_unknown_key_that_can_then_be_trusted() {
        let dir = TempDir::new();
        let node = spawn_node().await;
        let c = unlocked(&dir).await;
        let secret = c.set_password_secret(None, SecretInput::new(SERVER_PASSWORD)).unwrap();
        let session = node.session("chain");
        let mut t = tunnel("chain", node.port);
        t.hops = session.hops.clone();
        t.hops[0].host.auth = vec![AuthMethod::Password { secret: secret.secret_ref }];
        let t = c.upsert_tunnel(t).unwrap();

        let report = c.test_tunnel_chain(t.id).await.unwrap();
        assert!(!report.all_connected);
        assert_eq!(report.tunnel_id, t.id);
        assert_eq!(report.hops[0].status, "host_key_unknown");
        let sha = report.hops[0].host_key.as_ref().unwrap().sha256.clone();
        c.trust_tested_host_key(t.id.as_uuid(), &sha).unwrap();

        let report = c.test_tunnel_chain(t.id).await.unwrap();
        assert!(report.all_connected, "{report:?}");
    }

    #[tokio::test]
    async fn tunnels_used_by_lists_proxies() {
        let dir = TempDir::new();
        let c = controller(&dir);
        let t = c.upsert_tunnel(tunnel("bastion", 22)).unwrap();
        let p = proxy_through("web", t.id);
        let config = AppConfig { proxies: vec![p.clone()], ..AppConfig::default() };
        assert_eq!(tunnel_users(&config, t.id), vec![proxy_ref(&p)]);
        assert!(tunnel_users(&config, TunnelId::new()).is_empty());
    }
}
