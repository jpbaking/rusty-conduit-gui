//! Proxy operations: CRUD, lifecycle, hot reload, tray override, Route Tester, Test Upstream,
//! access records, the Profile Library, and v2 Start All / Stop All / autostart.
//!
//! Saving a running Proxy reloads its routing at once; changes only a restart applies set
//! `restart_required` on its snapshot. Upstream passwords live in the vault and are referenced
//! by [`SecretRef`], never inlined.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use conduit_core::{
    validate_proxy, AppConfig, Proxy, ProxyId, RouteInbound, TunnelId, TunnelStartMode,
    UpstreamKind, UpstreamPasswordSource, UpstreamProfile,
};
use conduit_runtime::{
    LogLine, ProxyError, ProxySnapshot, ProxyState, RouteTestResult, UpstreamProbeResult,
};
use conduit_runtime::{ProxyManager, SessionState};
use conduit_vault::UPSTREAM_PASSWORD_RECORD;
use rusty_conduit_engine::logging::AccessRecord;
use rusty_conduit_engine::routing::{PROFILE_BLOCK, PROFILE_DIRECT};
use serde::Serialize;

use super::keys::require_name;
use super::{AppController, AppError};

/// Longest Test Upstream timeout the UI may ask for.
const MAX_PROBE_TIMEOUT: Duration = Duration::from_secs(60);

/// A saved Proxy with its live view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProxyView {
    pub profile: Proxy,
    pub snapshot: ProxySnapshot,
}

/// What saving a Proxy did to its running instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProxySaveResult {
    pub profile: Proxy,
    pub snapshot: ProxySnapshot,
    /// A running Proxy swapped in the new routing (`snapshot.config_generation` went up).
    pub reloaded: bool,
    /// A running Proxy rejected the new routing and kept the old one; the save still stands.
    pub reload_error: Option<String>,
}

/// A structured access record for the log drawer. `upstream` is always redacted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccessRecordView {
    /// `http` or `socks`.
    pub kind: &'static str,
    /// Unix time in milliseconds.
    pub ts_ms: i64,
    /// `forward` | `reverse`, when tagged.
    pub direction: Option<&'static str>,
    pub client: SocketAddr,
    pub proto: String,
    /// HTTP method, or SOCKS command.
    pub method: String,
    pub target: String,
    pub rule: String,
    pub profile: String,
    pub upstream: String,
    /// HTTP status code, or the SOCKS status label.
    pub status: String,
    pub mitm: bool,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub duration_ms: u64,
}

impl From<&AccessRecord> for AccessRecordView {
    fn from(record: &AccessRecord) -> Self {
        let ms = |ts: time::OffsetDateTime| {
            i64::try_from(ts.unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX)
        };
        match record {
            AccessRecord::Http(r) => Self {
                kind: record.kind(),
                ts_ms: ms(r.ts),
                direction: r.direction.map(|d| d.as_str()),
                client: r.client,
                proto: r.proto.clone(),
                method: r.method.clone(),
                target: r.target.clone(),
                rule: r.rule.clone(),
                profile: r.profile.clone(),
                upstream: r.upstream.clone(),
                status: r.status.to_string(),
                mitm: r.mitm,
                bytes_in: r.bytes_in,
                bytes_out: r.bytes_out,
                duration_ms: r.duration_ms,
            },
            AccessRecord::Socks(r) => Self {
                kind: record.kind(),
                ts_ms: ms(r.ts),
                direction: r.direction.map(|d| d.as_str()),
                client: r.client,
                proto: r.proto.clone(),
                method: r.cmd.clone(),
                target: r.target.clone(),
                rule: r.rule.clone(),
                profile: r.profile.clone(),
                upstream: r.upstream.clone(),
                status: r.status.clone(),
                mitm: false,
                bytes_in: r.bytes_in,
                bytes_out: r.bytes_out,
                duration_ms: r.duration_ms,
            },
        }
    }
}

fn not_found(kind: &'static str, id: impl ToString) -> AppError {
    AppError::NotFound { kind, id: id.to_string() }
}

fn known_tunnels(config: &AppConfig) -> Vec<TunnelId> {
    config.tunnels.iter().map(|t| t.id).collect()
}

/// Rejects an upstream profile whose vault password or Tunnel does not exist.
fn check_profile_refs(
    config: &AppConfig,
    upstream_records: &HashSet<String>,
    profile: &UpstreamProfile,
) -> Result<(), AppError> {
    if let Some(UpstreamPasswordSource::Vault(secret)) = &profile.password {
        if !upstream_records.contains(&secret.to_string()) {
            return Err(not_found("upstream password", secret));
        }
    }
    if let UpstreamKind::Tunnel { tunnel_id } = &profile.kind {
        if !config.tunnels.iter().any(|t| t.id == *tunnel_id) {
            return Err(not_found("tunnel", tunnel_id));
        }
    }
    Ok(())
}

impl AppController {
    fn upstream_records(&self) -> HashSet<String> {
        self.vault_read()
            .list_keys()
            .into_iter()
            .filter(|r| r.r#type == UPSTREAM_PASSWORD_RECORD)
            .map(|r| r.id)
            .collect()
    }

    pub(crate) fn proxy_profile(&self, id: ProxyId) -> Result<Proxy, AppError> {
        self.config_snapshot()
            .proxies
            .into_iter()
            .find(|p| p.id == id)
            .ok_or_else(|| not_found("proxy", id))
    }

    pub fn list_proxies(&self) -> Result<Vec<ProxyView>, AppError> {
        self.config_snapshot()
            .proxies
            .into_iter()
            .map(|profile| {
                let snapshot = self.proxies().snapshot(profile.id)?;
                Ok(ProxyView { profile, snapshot })
            })
            .collect()
    }

    /// Validates and saves a Proxy (a nil id is assigned here). A running Proxy reloads its
    /// routing at once; a rejected reload keeps the old routing and is reported, not an error.
    pub async fn upsert_proxy(&self, mut proxy: Proxy) -> Result<ProxySaveResult, AppError> {
        if proxy.id.as_uuid().is_nil() {
            proxy.id = ProxyId::new();
        }
        proxy.name = require_name(&proxy.name)?;
        let records = self.upstream_records();
        let controller = self.clone();
        let saved = proxy.clone();
        super::run_blocking(move || {
            controller.mutate_config(|config| {
                validate_proxy(&proxy, &known_tunnels(config), &[])?;
                for profile in &proxy.profiles {
                    check_profile_refs(config, &records, profile)?;
                }
                if let Some(ca) = proxy.mitm.as_ref().and_then(|m| m.ca.as_ref()) {
                    if !config.mitm_cas.iter().any(|c| c.id == *ca) {
                        return Err(not_found("MITM CA", ca));
                    }
                }
                match config.proxies.iter_mut().find(|p| p.id == proxy.id) {
                    Some(existing) => *existing = proxy,
                    None => config.proxies.push(proxy),
                }
                Ok(())
            })
        })
        .await?;

        let before = self.proxies().snapshot(saved.id).ok();
        let reload_error = self.proxies().upsert_proxy(saved.clone()).await.err().map(|e| e.to_string());
        let snapshot = self.proxies().snapshot(saved.id)?;
        let reloaded = before.is_some_and(|b| snapshot.config_generation > b.config_generation);
        Ok(ProxySaveResult { profile: saved, snapshot, reloaded, reload_error })
    }

    /// Stops a Proxy and removes it.
    pub async fn delete_proxy(&self, id: ProxyId) -> Result<(), AppError> {
        self.proxy_profile(id)?;
        match self.proxies().remove_proxy(id).await {
            Ok(()) | Err(ProxyError::UnknownProxy(_)) => {}
            Err(error) => return Err(error.into()),
        }
        let controller = self.clone();
        super::run_blocking(move || {
            controller.mutate_config(|config| {
                config.proxies.retain(|p| p.id != id);
                Ok(())
            })
        })
        .await
    }

    /// Saves a copy of a Proxy, named "<name> (copy)" and not started with the app. Vaulted
    /// passwords and the MITM CA are shared by reference.
    pub async fn duplicate_proxy(&self, id: ProxyId) -> Result<ProxySaveResult, AppError> {
        let mut copy = self.proxy_profile(id)?;
        copy.id = ProxyId::new();
        copy.name = format!("{} (copy)", copy.name.trim());
        copy.autostart = false;
        self.upsert_proxy(copy).await
    }

    pub async fn start_proxy(&self, id: ProxyId) -> Result<(), AppError> {
        Ok(self.proxies().start(id).await?)
    }

    pub async fn stop_proxy(&self, id: ProxyId) -> Result<(), AppError> {
        Ok(self.proxies().stop(id).await?)
    }

    pub async fn restart_proxy(&self, id: ProxyId) -> Result<(), AppError> {
        Ok(self.proxies().restart(id).await?)
    }

    /// Tray override: `Some(profile)` sends everything to it (`direct` included); `None`
    /// returns to *Auto Switch*.
    pub async fn set_proxy_override(
        &self,
        id: ProxyId,
        override_profile: Option<String>,
    ) -> Result<ProxySnapshot, AppError> {
        self.proxies().set_override(id, override_profile).await?;
        Ok(self.proxies().snapshot(id)?)
    }

    pub fn get_proxy_logs(&self, id: ProxyId, limit: Option<usize>) -> Result<Vec<LogLine>, AppError> {
        Ok(self.proxies().logs(id)?.query(limit))
    }

    /// Clears both the Proxy's log lines and its structured access records.
    pub fn clear_proxy_logs(&self, id: ProxyId) -> Result<(), AppError> {
        self.proxies().logs(id)?.clear();
        self.proxies().access_records(id)?.clear();
        Ok(())
    }

    pub fn get_proxy_access_records(
        &self,
        id: ProxyId,
        limit: Option<usize>,
    ) -> Result<Vec<AccessRecordView>, AppError> {
        Ok(self
            .proxies()
            .access_records(id)?
            .query(limit)
            .iter()
            .map(AccessRecordView::from)
            .collect())
    }

    /// Route Tester: where `raw_target` goes under the draft `proxy`. Needs no vault.
    pub fn test_route(
        proxy: &Proxy,
        raw_target: &str,
        inbound: RouteInbound,
    ) -> Result<RouteTestResult, AppError> {
        Ok(ProxyManager::test_route(proxy, raw_target, inbound)?)
    }

    /// Test Upstream: dials `host:port` through the draft `proxy`'s profile, with timing.
    pub async fn test_upstream(
        &self,
        proxy: &Proxy,
        profile_name: &str,
        host: &str,
        port: u16,
        timeout_ms: u64,
    ) -> Result<UpstreamProbeResult, AppError> {
        if timeout_ms == 0 {
            return Err(AppError::Invalid("the timeout must be greater than 0".into()));
        }
        let timeout = Duration::from_millis(timeout_ms).min(MAX_PROBE_TIMEOUT);
        Ok(self.proxies().test_upstream(proxy, profile_name, host, port, timeout).await?)
    }

    // -----------------------------------------------------------------------------------------
    // Profile Library: shared upstream profiles any Proxy can copy in.
    // -----------------------------------------------------------------------------------------

    pub fn list_profile_library(&self) -> Vec<UpstreamProfile> {
        self.config_snapshot().profile_library
    }

    /// Saves a library profile, replacing the one with the same name.
    pub fn upsert_library_profile(&self, mut profile: UpstreamProfile) -> Result<UpstreamProfile, AppError> {
        profile.name = require_name(&profile.name)?;
        if profile.name == PROFILE_DIRECT || profile.name == PROFILE_BLOCK {
            return Err(AppError::Invalid(format!(
                "`{}` is a built-in profile name and cannot be used",
                profile.name
            )));
        }
        let records = self.upstream_records();
        let saved = profile.clone();
        self.mutate_config(|config| {
            check_profile_refs(config, &records, &profile)?;
            match config.profile_library.iter_mut().find(|p| p.name == profile.name) {
                Some(existing) => *existing = profile,
                None => config.profile_library.push(profile),
            }
            Ok(())
        })?;
        Ok(saved)
    }

    pub fn delete_library_profile(&self, name: &str) -> Result<(), AppError> {
        self.mutate_config(|config| {
            let before = config.profile_library.len();
            config.profile_library.retain(|p| p.name != name);
            if config.profile_library.len() == before {
                return Err(not_found("library profile", name));
            }
            Ok(())
        })
    }

    // -----------------------------------------------------------------------------------------
    // Global v2 lifecycle.
    // -----------------------------------------------------------------------------------------

    /// Starts every enabled Manual Tunnel, then every enabled Proxy (which starts its Linked
    /// Tunnels). A failed start shows in that item's state and does not stop the rest.
    pub async fn start_all_v2(&self) {
        let config = self.config_snapshot();
        for tunnel in config.tunnels.iter().filter(|t| {
            t.enabled && matches!(t.start_mode, TunnelStartMode::Manual { .. })
        }) {
            let _ = self.tunnels().start(tunnel.id).await;
        }
        for proxy in config.proxies.iter().filter(|p| p.enabled) {
            let _ = self.proxies().start(proxy.id).await;
        }
    }

    /// Stops every Proxy, then every Tunnel.
    pub async fn stop_all_v2(&self) {
        self.proxies().stop_all().await;
        self.tunnels().stop_all().await;
    }

    /// Starts autostart Manual Tunnels and autostart Proxies in name order, pausing between
    /// them. Items that need a locked vault wait in `Locked` and resume when it is unlocked.
    pub async fn start_autostart_v2(&self) {
        enum Item {
            Tunnel(TunnelId),
            Proxy(ProxyId),
        }
        let config = self.config_snapshot();
        let mut targets: Vec<(String, Item)> = config
            .tunnels
            .iter()
            .filter(|t| t.enabled && t.start_mode == TunnelStartMode::Manual { autostart: true })
            .map(|t| (t.name.clone(), Item::Tunnel(t.id)))
            .collect();
        targets.extend(
            config
                .proxies
                .iter()
                .filter(|p| p.enabled && p.autostart)
                .map(|p| (p.name.clone(), Item::Proxy(p.id))),
        );
        targets.sort_by(|a, b| a.0.cmp(&b.0));
        let stagger = self.manager_config().autostart_stagger;
        for (index, (_, item)) in targets.into_iter().enumerate() {
            if index > 0 {
                tokio::time::sleep(stagger).await;
            }
            match item {
                Item::Tunnel(id) => drop(self.tunnels().start(id).await),
                Item::Proxy(id) => drop(self.proxies().start(id).await),
            }
        }
    }

    /// Restarts Tunnels and Proxies that were waiting on the vault.
    pub(crate) async fn resume_locked_v2(&self) {
        if !self.vault_read().is_unlocked() {
            return;
        }
        for tunnel in self.tunnels().snapshots() {
            if tunnel.state == SessionState::Locked {
                let _ = self.tunnels().start(tunnel.id).await;
            }
        }
        for proxy in self.proxies().snapshots() {
            if proxy.state == ProxyState::Locked {
                let _ = self.proxies().start(proxy.id).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::super::SecretInput;
    use super::*;
    use conduit_core::{
        ListenerConfig, MitmConfig, RouteOneOrMany, RoutingRule, RoutingTablesConfig, SecretRef,
        Tunnel,
    };
    use std::net::{IpAddr, Ipv4Addr};

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    fn http_profile(name: &str, port: u16, password: Option<UpstreamPasswordSource>) -> UpstreamProfile {
        UpstreamProfile {
            name: name.into(),
            kind: UpstreamKind::Http,
            host: Some("127.0.0.1".into()),
            port: Some(port),
            username: password.as_ref().map(|_| "user".into()),
            password,
            bypass: Vec::new(),
            color: None,
        }
    }

    /// A Proxy on a free loopback HTTP port whose default is `direct`, with one `corp` profile.
    fn proxy(name: &str) -> Proxy {
        Proxy {
            name: name.into(),
            listeners: ListenerConfig {
                bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
                http_port: free_port(),
                socks_port: 0,
                ..ListenerConfig::default()
            },
            profiles: vec![http_profile("corp", 9, None)],
            routing: RoutingTablesConfig {
                default: RouteOneOrMany::One(PROFILE_DIRECT.into()),
                ..RoutingTablesConfig::default()
            },
            ..Proxy::default()
        }
    }

    fn corp_rule(host: &str) -> RoutingRule {
        RoutingRule {
            name: Some("corp-rule".into()),
            host: Some(RouteOneOrMany::One(host.into())),
            ..RoutingRule::to_target(RouteOneOrMany::One("corp".into()))
        }
    }

    #[tokio::test]
    async fn proxies_upsert_assigns_an_id_persists_and_lists() {
        let dir = TempDir::new();
        let c = controller(&dir);
        let saved = c.upsert_proxy(proxy("web")).await.unwrap();
        assert!(!saved.profile.id.as_uuid().is_nil());
        assert!(!saved.reloaded);
        assert_eq!(saved.reload_error, None);
        assert_eq!(saved.snapshot.state, ProxyState::Stopped);
        assert_eq!(c.list_proxies().unwrap()[0].profile.name, "web");

        drop(c);
        let c = controller(&dir);
        assert_eq!(c.list_proxies().unwrap()[0].profile.id, saved.profile.id);
        assert_eq!(c.proxies().snapshots().len(), 1, "reopen loads saved Proxies");
    }

    #[tokio::test]
    async fn proxies_upsert_rejects_invalid_and_dangling_references() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        let mut none = proxy("none");
        none.listeners.http_port = 0;
        assert!(matches!(c.upsert_proxy(none).await, Err(AppError::ProxyValidate(_))));

        let mut tunnel = proxy("tunnel");
        tunnel.profiles.push(UpstreamProfile {
            kind: UpstreamKind::Tunnel { tunnel_id: TunnelId::new() },
            host: None,
            port: None,
            ..http_profile("ssh", 1, None)
        });
        assert!(c.upsert_proxy(tunnel).await.is_err());

        let mut ghost = proxy("ghost");
        ghost.profiles[0] = http_profile("corp", 9, Some(UpstreamPasswordSource::Vault(SecretRef::new())));
        assert!(matches!(c.upsert_proxy(ghost).await, Err(AppError::NotFound { .. })));

        let mut ca = proxy("ca");
        ca.mitm = Some(MitmConfig { ca: Some(conduit_core::MitmCaId::new()), ..MitmConfig::default() });
        assert!(matches!(c.upsert_proxy(ca).await, Err(AppError::NotFound { .. })));

        // A hop password is not an upstream password.
        let hop = c.set_password_secret(None, SecretInput::new("hop")).unwrap();
        let mut wrong = proxy("wrong");
        wrong.profiles[0] = http_profile("corp", 9, Some(UpstreamPasswordSource::Vault(hop.secret_ref)));
        assert!(matches!(c.upsert_proxy(wrong).await, Err(AppError::NotFound { .. })));
        assert!(c.config_snapshot().proxies.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn proxies_hot_reload_override_and_restart_required() {
        let dir = TempDir::new();
        let c = controller(&dir);
        let saved = c.upsert_proxy(proxy("live")).await.unwrap().profile;
        let id = saved.id;
        c.start_proxy(id).await.unwrap();
        let generation = c.proxies().snapshot(id).unwrap().config_generation;

        // A routing change reloads in place.
        let mut edited = saved.clone();
        edited.routing.rules.push(corp_rule("intranet.example"));
        let result = c.upsert_proxy(edited.clone()).await.unwrap();
        assert!(result.reloaded, "{result:?}");
        assert_eq!(result.snapshot.config_generation, generation + 1);
        assert!(!result.snapshot.restart_required);

        // Tray override, then back to Auto Switch.
        let forced = c.set_proxy_override(id, Some(PROFILE_DIRECT.into())).await.unwrap();
        assert_eq!(forced.override_profile.as_deref(), Some(PROFILE_DIRECT));
        assert!(matches!(
            c.set_proxy_override(id, Some("nope".into())).await,
            Err(AppError::Proxy(ProxyError::UnknownProfile(_)))
        ));
        assert_eq!(c.set_proxy_override(id, None).await.unwrap().override_profile, None);

        // A listener change only applies on restart.
        let mut moved = edited.clone();
        moved.listeners.max_connections += 1;
        let result = c.upsert_proxy(moved).await.unwrap();
        assert!(result.snapshot.restart_required);
        c.restart_proxy(id).await.unwrap();
        assert!(!c.proxies().snapshot(id).unwrap().restart_required);

        assert!(c.get_proxy_logs(id, Some(50)).unwrap().iter().any(|l| l.text.contains("reloaded")));
        assert!(c.get_proxy_access_records(id, None).unwrap().is_empty());
        c.clear_proxy_logs(id).unwrap();
        assert!(c.get_proxy_logs(id, None).unwrap().is_empty());

        c.stop_proxy(id).await.unwrap();
        assert!(matches!(
            c.set_proxy_override(id, None).await,
            Err(AppError::Proxy(ProxyError::NotRunning(_)))
        ));
    }

    #[tokio::test]
    async fn proxies_delete_and_duplicate() {
        let dir = TempDir::new();
        let c = controller(&dir);
        let mut original = proxy("orig");
        original.autostart = true;
        let saved = c.upsert_proxy(original).await.unwrap().profile;
        let copy = c.duplicate_proxy(saved.id).await.unwrap().profile;
        assert_eq!(copy.name, "orig (copy)");
        assert!(!copy.autostart);
        assert_ne!(copy.id, saved.id);
        assert_eq!(c.list_proxies().unwrap().len(), 2);

        c.delete_proxy(saved.id).await.unwrap();
        assert_eq!(c.list_proxies().unwrap().len(), 1);
        assert!(c.proxies().snapshot(saved.id).is_err());
        assert!(matches!(c.delete_proxy(saved.id).await, Err(AppError::NotFound { .. })));
    }

    #[tokio::test]
    async fn proxies_route_tester_and_test_upstream() {
        let dir = TempDir::new();
        let c = controller(&dir);
        let mut draft = proxy("draft");
        draft.routing.rules.push(corp_rule("intranet.example"));

        let hit = AppController::test_route(&draft, "intranet.example:443", RouteInbound::Http).unwrap();
        assert_eq!(hit.matched_rule.as_deref(), Some("corp-rule"));
        assert_eq!(hit.targets[0].profile, "corp");
        let miss = AppController::test_route(&draft, "http://other.example/", RouteInbound::Socks).unwrap();
        assert_eq!(miss.matched_rule, None);
        assert_eq!(miss.targets[0].profile, PROFILE_DIRECT);
        assert!(matches!(
            AppController::test_route(&draft, "", RouteInbound::Http),
            Err(AppError::Proxy(ProxyError::InvalidTarget(_)))
        ));

        let open = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = open.local_addr().unwrap().port();
        let probe = c.test_upstream(&draft, PROFILE_DIRECT, "127.0.0.1", port, 2_000).await.unwrap();
        assert!(probe.ok, "{probe:?}");
        assert!(matches!(
            c.test_upstream(&draft, "missing", "127.0.0.1", port, 2_000).await,
            Err(AppError::Proxy(ProxyError::UnknownProfile(_)))
        ));
        assert!(matches!(
            c.test_upstream(&draft, PROFILE_DIRECT, "127.0.0.1", port, 0).await,
            Err(AppError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn proxies_profile_library_crud() {
        let dir = TempDir::new();
        let c = controller(&dir);
        assert!(c.list_profile_library().is_empty());
        c.upsert_library_profile(http_profile("corp", 8080, None)).unwrap();
        c.upsert_library_profile(http_profile("corp", 3128, None)).unwrap();
        c.upsert_library_profile(http_profile("lab", 8080, None)).unwrap();
        let library = c.list_profile_library();
        assert_eq!(library.len(), 2);
        assert_eq!(library[0].port, Some(3128), "same name replaces");

        assert!(matches!(
            c.upsert_library_profile(http_profile(PROFILE_DIRECT, 1, None)),
            Err(AppError::Invalid(_))
        ));
        assert!(matches!(
            c.upsert_library_profile(http_profile("  ", 1, None)),
            Err(AppError::Invalid(_))
        ));
        c.delete_library_profile("corp").unwrap();
        assert!(matches!(c.delete_library_profile("corp"), Err(AppError::NotFound { .. })));
        drop(c);
        assert_eq!(controller(&dir).list_profile_library()[0].name, "lab");
    }

    #[tokio::test]
    async fn proxies_upstream_passwords_rotate_and_force_delete_clears_references() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        let first = c.set_upstream_password(None, SecretInput::new("up-one")).await.unwrap();
        assert_eq!(c.record_type(&first.secret_ref.to_string()).as_deref(), Some(UPSTREAM_PASSWORD_RECORD));
        let vaulted = || Some(UpstreamPasswordSource::Vault(first.secret_ref.clone()));
        let mut p = proxy("auth");
        p.profiles[0] = http_profile("corp", 9, vaulted());
        let p = c.upsert_proxy(p).await.unwrap().profile;
        c.upsert_library_profile(http_profile("shared", 9, vaulted())).unwrap();

        // Rotation moves every reference and destroys the old record.
        let second = c
            .set_upstream_password(Some(first.secret_ref.clone()), SecretInput::new("up-two"))
            .await
            .unwrap();
        let moved = Some(UpstreamPasswordSource::Vault(second.secret_ref.clone()));
        assert_eq!(c.proxy_profile(p.id).unwrap().profiles[0].password, moved);
        assert_eq!(c.list_profile_library()[0].password, moved);
        assert!(c.record_type(&first.secret_ref.to_string()).is_none());
        assert_eq!(&*c.vault_read().get_upstream_password(&second.secret_ref.to_string()).unwrap(), b"up-two");
        assert!(matches!(
            c.set_upstream_password(Some(first.secret_ref.clone()), SecretInput::new("x")).await,
            Err(AppError::NotFound { .. })
        ));
        assert!(matches!(c.set_upstream_password(None, SecretInput::new("")).await, Err(AppError::Invalid(_))));

        // Safe deletion lists the Proxy and the library entry, then clears both when forced.
        let refused = c.delete_secret(&second.secret_ref, false).await.unwrap();
        assert!(!refused.deleted);
        assert_eq!(refused.used_by, 2);
        assert_eq!(refused.usage.proxies[0].name, "auth");
        assert_eq!(refused.usage.library_profiles, vec!["shared".to_string()]);
        assert!(c.delete_secret(&second.secret_ref, true).await.unwrap().deleted);
        assert_eq!(c.proxy_profile(p.id).unwrap().profiles[0].password, None);
        assert_eq!(c.list_profile_library()[0].password, None);
        assert!(c.record_type(&second.secret_ref.to_string()).is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn proxies_force_deleting_a_ca_stops_the_proxy_and_clears_it() {
        use super::super::mitm_ca::test_ca::valid_ca;
        use super::super::mitm_ca::MitmCaUpload;
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        let ca = valid_ca("Proxy CA");
        let meta = c
            .import_mitm_ca(
                "ca",
                MitmCaUpload::Pem { cert: ca.cert_pem.clone(), key: SecretInput::new(ca.key_pem.as_str()) },
                None,
            )
            .unwrap();
        let mut p = proxy("mitm");
        p.mitm = Some(MitmConfig { ca: Some(meta.id.clone()), ..MitmConfig::default() });
        let id = c.upsert_proxy(p).await.unwrap().profile.id;
        c.start_proxy(id).await.unwrap();
        assert!(matches!(c.proxies().snapshot(id).unwrap().state, ProxyState::Running { .. }));

        let listed = c.list_mitm_cas();
        assert_eq!((listed[0].used_by, listed[0].usage.proxies[0].name.as_str()), (1, "mitm"));
        assert!(!c.delete_mitm_ca(&meta.id, false).await.unwrap().deleted);
        assert!(c.delete_mitm_ca(&meta.id, true).await.unwrap().deleted);
        assert_eq!(c.proxies().snapshot(id).unwrap().state, ProxyState::Stopped);
        let mitm = c.proxy_profile(id).unwrap().mitm.unwrap();
        assert_eq!(mitm.ca, None, "MITM stays on without a CA, so it cannot start");
        assert!(c.start_proxy(id).await.is_err());
    }

    #[tokio::test]
    async fn proxies_locked_vault_resumes_after_unlock() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        let secret = c.set_upstream_password(None, SecretInput::new("pw")).await.unwrap();
        let mut p = proxy("locked");
        p.profiles[0] = http_profile("corp", 9, Some(UpstreamPasswordSource::Vault(secret.secret_ref)));
        let id = c.upsert_proxy(p).await.unwrap().profile.id;
        c.lock_vault();
        assert!(matches!(c.start_proxy(id).await, Err(AppError::Proxy(ProxyError::VaultLocked))));
        assert_eq!(c.proxies().snapshot(id).unwrap().state, ProxyState::Locked);

        c.unlock_vault_with_password(SecretInput::new(TEST_MASTER)).await.unwrap();
        assert!(matches!(c.proxies().snapshot(id).unwrap().state, ProxyState::Running { .. }));
        c.stop_all_v2().await;
        assert_eq!(c.proxies().snapshot(id).unwrap().state, ProxyState::Stopped);
    }

    #[tokio::test]
    async fn proxies_start_all_and_autostart_skip_disabled_and_linked() {
        let dir = TempDir::new();
        let c = controller(&dir);
        let mut auto = proxy("a-auto");
        auto.autostart = true;
        let auto = c.upsert_proxy(auto).await.unwrap().profile.id;
        let mut off = proxy("b-off");
        off.enabled = false;
        off.autostart = true;
        let off = c.upsert_proxy(off).await.unwrap().profile.id;
        let manual = proxy("c-manual");
        let manual = c.upsert_proxy(manual).await.unwrap().profile.id;
        let linked = c
            .upsert_tunnel(Tunnel {
                name: "linked".into(),
                hops: vec![hop("", 1, Vec::new())],
                ..Tunnel::default()
            })
            .unwrap()
            .id;

        c.start_autostart_v2().await;
        let running = |id| matches!(c.proxies().snapshot(id).unwrap().state, ProxyState::Running { .. });
        assert!(running(auto));
        assert!(!running(off));
        assert!(!running(manual));
        c.stop_all_v2().await;

        c.start_all_v2().await;
        assert!(running(auto) && running(manual) && !running(off));
        assert_eq!(c.tunnels().snapshot(linked).unwrap().state, SessionState::Stopped);
        c.stop_all_v2().await;
        assert!(!running(auto) && !running(manual));
    }
}
