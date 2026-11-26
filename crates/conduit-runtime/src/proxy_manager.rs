//! `conduit-runtime` — the Proxy supervisor.
//!
//! [`ProxyManager`] runs every saved [`Proxy`]: it resolves vaulted upstream passwords and the
//! MITM CA in memory, compiles a hot-swappable [`RoutingState`] (with one external dialer per
//! referenced Tunnel, taken from the [`TunnelManager`]), binds the listeners, and keeps Linked
//! Tunnels running while the Proxy runs.
//!
//! Saving a running Proxy ([`ProxyManager::upsert_proxy`] / [`ProxyManager::reload`]) compiles
//! the next routing state and swaps it in atomically, keeping the traffic counters. Changes
//! that need new sockets or a new MITM / logging setup only set `restart_required`.
//! Tray overrides ([`ProxyManager::set_override`]) swap in a temporary rule-less state and
//! restore the saved one on *Auto Switch*. [`ProxyManager::test_route`] and
//! [`ProxyManager::test_upstream`] back the Route Tester and Test Upstream.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex, PoisonError, RwLock, Weak};
use std::time::{Duration, Instant};

use conduit_core::{
    proxy_mitm_options, proxy_referenced_tunnels, proxy_server_options, proxy_to_routing_input,
    proxy_vault_secret_refs, validate_proxy, Proxy, ProxyId, RouteInbound, SourceMode, TunnelId,
    UpstreamKind, UpstreamPasswordSource,
};
use conduit_vault::{Vault, VaultError};
use rusty_conduit_engine::logging::{
    AccessLogConfig, AccessLogger, AccessRecord, AccessRecordSink, LogFormat, LogLevel, Logger,
    ProxyDirection,
};
use rusty_conduit_engine::mitm::MitmState;
use rusty_conduit_engine::router::{ParsedTarget, RouteRequest, Router};
use rusty_conduit_engine::routing::{
    Inbound, OneOrMany, RoutingConfig, RoutingState, SharedRouting, TrafficSnapshot,
    PROFILE_BLOCK, PROFILE_DIRECT,
};
use rusty_conduit_engine::server::{EngineHandlers, ProtocolHandlers, Server, ShutdownReport};
use rusty_conduit_engine::upstream::{dialer_for_profile, DialerOptions};
use serde::Serialize;
use thiserror::Error;
use tokio::sync::broadcast;
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::logs::{redact, LogRingBuffer};
use crate::manager::ManagerConfig;
use crate::state::ListenerInfo;
use crate::toml_watcher::{
    merge_external_toml_text, spawn_toml_watcher, TomlWatchEvent, TomlWatcherHandle,
};
use crate::tunnel_manager::{TunnelError, TunnelManager};

/// Stands in for vaulted passwords where only routing, not dialing, is needed.
const PLACEHOLDER_PASSWORD: &str = "<vaulted>";

// Guarded values are replaced whole, so a poisoned lock still holds valid data.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Where a Proxy is in its lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProxyState {
    Stopped,
    Starting,
    /// Listeners are bound. `override_profile` is the tray override (`None` = Auto Switch).
    Running {
        override_profile: Option<String>,
        config_generation: u64,
        restart_required: bool,
    },
    Reloading,
    /// Needs vaulted secrets (upstream passwords or the MITM CA) while the vault is locked.
    Locked,
    NeedsAttention {
        reason: String,
    },
    Stopping,
}

/// Serializable mirror of the engine's [`TrafficSnapshot`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ProxyTrafficSnapshot {
    pub active: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub hits: u64,
}

impl From<TrafficSnapshot> for ProxyTrafficSnapshot {
    fn from(s: TrafficSnapshot) -> Self {
        Self {
            active: s.active,
            bytes_in: s.bytes_in,
            bytes_out: s.bytes_out,
            hits: s.hits,
        }
    }
}

fn traffic_map(map: BTreeMap<String, TrafficSnapshot>) -> BTreeMap<String, ProxyTrafficSnapshot> {
    map.into_iter().map(|(k, v)| (k, v.into())).collect()
}

/// A point-in-time view of one Proxy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProxySnapshot {
    pub id: ProxyId,
    pub name: String,
    pub enabled: bool,
    pub state: ProxyState,
    /// Bound listeners, while running.
    pub listeners: Vec<ListenerInfo>,
    pub config_generation: u64,
    pub override_profile: Option<String>,
    /// The saved config changed something that only a restart applies.
    pub restart_required: bool,
    /// Traffic by serving profile, while running.
    pub profile_counters: BTreeMap<String, ProxyTrafficSnapshot>,
    /// Traffic by rule label, while running.
    pub rule_counters: BTreeMap<String, ProxyTrafficSnapshot>,
    pub referenced_tunnels: Vec<TunnelId>,
}

/// Something about a Proxy the UI may want to react to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ProxyEvent {
    StateChanged {
        proxy_id: ProxyId,
        state: ProxyState,
    },
    /// A new routing state went live.
    Reloaded {
        proxy_id: ProxyId,
        config_generation: u64,
    },
    /// The tray override changed (`None` = Auto Switch).
    OverrideChanged {
        proxy_id: ProxyId,
        override_profile: Option<String>,
    },
}

/// A request the Proxy manager could not carry out. Messages never carry secrets.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProxyError {
    #[error("unknown proxy {0}")]
    UnknownProxy(ProxyId),
    #[error("proxy {0} is not running")]
    NotRunning(ProxyId),
    #[error("the vault is locked: unlock it to use this proxy's vaulted secrets")]
    VaultLocked,
    #[error("cannot read vault secret: {0}")]
    Vault(String),
    #[error("{0}")]
    Invalid(String),
    #[error("listener {addr} is already used by proxy \"{other}\"")]
    PortConflict { addr: SocketAddr, other: String },
    #[error("routing setup failed: {0}")]
    Routing(String),
    #[error("MITM setup failed: {0}")]
    Mitm(String),
    #[error("failed to open access log: {0}")]
    AccessLog(String),
    #[error("failed to bind listeners: {0}")]
    Bind(String),
    #[error("unknown upstream profile `{0}`")]
    UnknownProfile(String),
    #[error("profile `{0}` has no dialer of its own (a composite profile picks another profile)")]
    NoDialer(String),
    #[error("invalid target: {0}")]
    InvalidTarget(String),
    #[error("tunnel {0} does not exist")]
    UnknownTunnel(TunnelId),
    #[error(transparent)]
    Tunnel(#[from] TunnelError),
}

fn vault_error(error: VaultError) -> ProxyError {
    match error {
        VaultError::Locked => ProxyError::VaultLocked,
        other => ProxyError::Vault(other.to_string()),
    }
}

/// One element of a Route Tester failover chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RouteTestTarget {
    /// The name as written in the rule or default.
    pub name: String,
    /// The concrete profile dialed (after composite resolution and bypass).
    pub profile: String,
    pub redacted_upstream: String,
    /// A profile `bypass` list sent the target `direct`.
    pub bypassed: bool,
}

/// What the Route Tester shows for one target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RouteTestResult {
    /// `[routing]`, `[routing.http]`, or `[routing.socks]`; `None` when the filter denied it.
    pub table: Option<String>,
    /// The matched rule's label; `None` = the table default (or denied).
    pub matched_rule: Option<String>,
    pub blocked_by_filter: bool,
    pub filter_reason: Option<String>,
    /// The failover chain, in order.
    pub targets: Vec<RouteTestTarget>,
}

/// The outcome of a Test Upstream probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpstreamProbeResult {
    pub ok: bool,
    pub elapsed_ms: u64,
    pub redacted_upstream: String,
    /// Redacted reason when `ok` is false.
    pub error: Option<String>,
}

/// Bounded buffer of structured [`AccessRecord`]s for the log drawer; oldest dropped first.
#[derive(Clone)]
pub struct AccessRecordBuffer {
    inner: Arc<Mutex<VecDeque<AccessRecord>>>,
    capacity: usize,
}

impl AccessRecordBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(capacity.min(1024)))),
            capacity: capacity.max(1),
        }
    }

    pub fn push(&self, record: AccessRecord) {
        let mut records = lock(&self.inner);
        while records.len() >= self.capacity {
            records.pop_front();
        }
        records.push_back(record);
    }

    /// The newest `limit` records (all when `None`), oldest first.
    pub fn query(&self, limit: Option<usize>) -> Vec<AccessRecord> {
        let records = lock(&self.inner);
        let skip = limit.map_or(0, |l| records.len().saturating_sub(l));
        records.iter().skip(skip).cloned().collect()
    }

    pub fn len(&self) -> usize {
        lock(&self.inner).len()
    }

    pub fn is_empty(&self) -> bool {
        lock(&self.inner).is_empty()
    }

    pub fn clear(&self) {
        lock(&self.inner).clear();
    }

    /// A sink feeding this buffer, for [`AccessLogger::with_sink`].
    pub fn sink(&self) -> AccessRecordSink {
        let buffer = self.clone();
        Arc::new(move |record: &AccessRecord| buffer.push(record.clone()))
    }
}

/// `true` when going from `running` to `saved` needs new listeners, a new MITM state, or new
/// loggers, which only a restart applies.
pub fn requires_restart(running: &Proxy, saved: &Proxy) -> bool {
    running.listeners != saved.listeners
        || running.mitm != saved.mitm
        || running.socks_block_web != saved.socks_block_web
        || running.logging != saved.logging
}

fn profile_exists(proxy: &Proxy, name: &str) -> bool {
    name == PROFILE_DIRECT || name == PROFILE_BLOCK || proxy.profiles.iter().any(|p| p.name == name)
}

fn placeholder_passwords(proxy: &Proxy) -> BTreeMap<String, Zeroizing<String>> {
    proxy_vault_secret_refs(proxy)
        .into_iter()
        .map(|(name, _)| (name, Zeroizing::new(PLACEHOLDER_PASSWORD.to_string())))
        .collect()
}

fn engine_inbound(inbound: RouteInbound) -> Inbound {
    match inbound {
        RouteInbound::Http => Inbound::Http,
        RouteInbound::Socks => Inbound::Socks,
    }
}

fn invalid(error: impl ToString) -> ProxyError {
    ProxyError::Invalid(error.to_string())
}

/// A rule-less copy of `saved` sending everything to `profile`, sharing its dialers, counters,
/// and generation. Needs no secrets: the router only reads profile shapes.
fn override_state(
    proxy: &Proxy,
    saved: &RoutingState,
    profile: &str,
    listeners: &[SocketAddr],
) -> Result<RoutingState, ProxyError> {
    let mut input =
        proxy_to_routing_input(proxy, &placeholder_passwords(proxy), listeners).map_err(invalid)?;
    input.routing = RoutingConfig {
        default: OneOrMany::One(profile.to_string()),
        ..RoutingConfig::default()
    };
    let router = Router::from_input(&input).map_err(|e| ProxyError::Routing(e.to_string()))?;
    Ok(RoutingState {
        router: Arc::new(router),
        ..saved.clone()
    })
}

/// In-memory copies of a Proxy's vaulted secrets, wiped on drop.
struct Secrets {
    passwords: BTreeMap<String, Zeroizing<String>>,
    ca_pem: Option<Zeroizing<Vec<u8>>>,
}

struct ServerHandles {
    token: CancellationToken,
    run: JoinHandle<ShutdownReport>,
    reaper: Option<JoinHandle<()>>,
    access: AccessLogger,
    logger: Logger,
}

/// What a running Proxy is serving.
struct Live {
    /// The config the listeners, MITM, and loggers were built from.
    baseline: Proxy,
    /// The config the saved routing state was compiled from.
    compiled: Proxy,
    routing: SharedRouting,
    /// The compiled state Auto Switch serves.
    saved: Arc<RoutingState>,
    override_profile: Option<String>,
    generation: u64,
    restart_required: bool,
    /// Tunnels this Proxy holds a Linked reference on.
    tunnels: Vec<TunnelId>,
    listeners: Vec<ListenerInfo>,
}

impl Live {
    fn running_state(&self) -> ProxyState {
        ProxyState::Running {
            override_profile: self.override_profile.clone(),
            config_generation: self.generation,
            restart_required: self.restart_required,
        }
    }

    fn bound(&self) -> Vec<SocketAddr> {
        self.listeners.iter().map(|l| l.addr).collect()
    }
}

/// The External TOML watcher of a running linked Proxy.
struct LinkedWatcher {
    path: PathBuf,
    debounce_ms: u64,
    _handle: TomlWatcherHandle,
}

struct ProxySlot {
    proxy: Mutex<Proxy>,
    state: Mutex<ProxyState>,
    logs: LogRingBuffer,
    records: AccessRecordBuffer,
    live: Mutex<Option<Live>>,
    /// Serializes start, stop, reload, and override, so a Proxy never has two servers.
    lifecycle: tokio::sync::Mutex<Option<ServerHandles>>,
    /// Follows the linked file while an External TOML Proxy runs; dropping it stops it.
    watcher: Mutex<Option<LinkedWatcher>>,
}

impl ProxySlot {
    fn snapshot(&self) -> ProxySnapshot {
        let proxy = lock(&self.proxy).clone();
        let state = lock(&self.state).clone();
        let live = lock(&self.live);
        let mut snapshot = ProxySnapshot {
            id: proxy.id,
            name: proxy.name.clone(),
            enabled: proxy.enabled,
            state,
            listeners: Vec::new(),
            config_generation: 0,
            override_profile: None,
            restart_required: false,
            profile_counters: BTreeMap::new(),
            rule_counters: BTreeMap::new(),
            referenced_tunnels: proxy_referenced_tunnels(&proxy),
        };
        if let Some(live) = live.as_ref() {
            let current = live.routing.load();
            snapshot.listeners = live.listeners.clone();
            snapshot.config_generation = live.generation;
            snapshot.override_profile = live.override_profile.clone();
            snapshot.restart_required = live.restart_required;
            snapshot.profile_counters = traffic_map(current.counters().profiles());
            snapshot.rule_counters = traffic_map(current.counters().rules());
        }
        snapshot
    }
}

struct Inner {
    tunnels: Arc<TunnelManager>,
    vault: Arc<RwLock<Vault>>,
    config: ManagerConfig,
    events: broadcast::Sender<ProxyEvent>,
    proxies: Mutex<HashMap<ProxyId, Arc<ProxySlot>>>,
}

/// Supervises every Proxy. Cloning yields another handle to the same manager.
#[derive(Clone)]
pub struct ProxyManager {
    inner: Arc<Inner>,
}

impl ProxyManager {
    pub fn new(
        tunnels: Arc<TunnelManager>,
        vault: Arc<RwLock<Vault>>,
        config: ManagerConfig,
    ) -> Self {
        let (events, _) = broadcast::channel(config.event_capacity.max(1));
        Self {
            inner: Arc::new(Inner {
                tunnels,
                vault,
                config,
                events,
                proxies: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<ProxyEvent> {
        self.inner.events.subscribe()
    }

    fn emit(&self, event: ProxyEvent) {
        let _ = self.inner.events.send(event);
    }

    fn set_state(&self, slot: &ProxySlot, id: ProxyId, state: ProxyState) {
        {
            let mut current = lock(&slot.state);
            if *current == state {
                return;
            }
            *current = state.clone();
        }
        self.emit(ProxyEvent::StateChanged {
            proxy_id: id,
            state,
        });
    }

    fn slot(&self, id: ProxyId) -> Result<Arc<ProxySlot>, ProxyError> {
        lock(&self.inner.proxies)
            .get(&id)
            .cloned()
            .ok_or(ProxyError::UnknownProxy(id))
    }

    fn slots(&self) -> Vec<Arc<ProxySlot>> {
        lock(&self.inner.proxies).values().cloned().collect()
    }

    fn known_tunnels(&self) -> Vec<TunnelId> {
        self.inner.tunnels.snapshots().iter().map(|s| s.id).collect()
    }

    /// Listeners a Proxy must never route to: other running Proxies' and Tunnels' reverse
    /// listeners.
    fn other_listeners(&self, id: ProxyId) -> Vec<SocketAddr> {
        let mut addrs = self.inner.tunnels.reverse_listeners();
        for slot in self.slots() {
            if lock(&slot.proxy).id == id {
                continue;
            }
            if let Some(live) = lock(&slot.live).as_ref() {
                addrs.extend(live.bound());
            }
        }
        addrs
    }

    /// The first of `wanted` another running Proxy already listens on.
    fn port_conflict(&self, id: ProxyId, wanted: &[SocketAddr]) -> Option<(SocketAddr, String)> {
        for slot in self.slots() {
            let name = {
                let proxy = lock(&slot.proxy);
                if proxy.id == id {
                    continue;
                }
                proxy.name.clone()
            };
            let live = lock(&slot.live);
            let Some(live) = live.as_ref() else { continue };
            for bound in live.bound() {
                if let Some(w) = wanted.iter().find(|w| {
                    w.port() == bound.port()
                        && (w.ip() == bound.ip()
                            || w.ip().is_unspecified()
                            || bound.ip().is_unspecified())
                }) {
                    return Some((*w, name));
                }
            }
        }
        None
    }

    /// Reads the Proxy's vaulted upstream passwords and, with `with_ca`, its MITM CA.
    fn read_secrets(&self, proxy: &Proxy, with_ca: bool) -> Result<Secrets, ProxyError> {
        let refs = proxy_vault_secret_refs(proxy);
        let ca = proxy
            .mitm
            .as_ref()
            .and_then(|m| m.ca.as_ref())
            .filter(|_| with_ca);
        let mut secrets = Secrets {
            passwords: BTreeMap::new(),
            ca_pem: None,
        };
        if refs.is_empty() && ca.is_none() {
            return Ok(secrets);
        }
        let vault = self.inner.vault.read().unwrap_or_else(PoisonError::into_inner);
        if !vault.is_unlocked() {
            return Err(ProxyError::VaultLocked);
        }
        for (name, secret) in refs {
            let bytes = vault
                .get_upstream_password(&secret.to_string())
                .map_err(vault_error)?;
            let text = std::str::from_utf8(&bytes).map_err(|_| {
                ProxyError::Vault(format!("the password of profile `{name}` is not valid UTF-8"))
            })?;
            secrets.passwords.insert(name, Zeroizing::new(text.to_string()));
        }
        if let Some(ca) = ca {
            secrets.ca_pem = Some(vault.get_secret(&ca.to_string()).map_err(vault_error)?);
        }
        Ok(secrets)
    }

    /// Dialer options carrying the dialer of every Tunnel the Proxy's profiles route through.
    fn external_dialers(&self, proxy: &Proxy) -> Result<DialerOptions, ProxyError> {
        let mut opts = DialerOptions::default();
        for p in &proxy.profiles {
            if let UpstreamKind::Tunnel { tunnel_id } = p.kind {
                let dialer = self
                    .inner
                    .tunnels
                    .dialer(tunnel_id)
                    .ok_or(ProxyError::UnknownTunnel(tunnel_id))?;
                opts = opts.with_external(p.name.clone(), dialer);
            }
        }
        Ok(opts)
    }

    fn compile_routing(
        &self,
        proxy: &Proxy,
        passwords: &BTreeMap<String, Zeroizing<String>>,
        extra_listeners: &[SocketAddr],
    ) -> Result<RoutingState, ProxyError> {
        let input = proxy_to_routing_input(proxy, passwords, extra_listeners).map_err(invalid)?;
        let opts = self.external_dialers(proxy)?;
        RoutingState::from_input(&input, opts).map_err(|e| ProxyError::Routing(e.to_string()))
    }

    async fn release_all(&self, tunnels: &[TunnelId], holder: ProxyId) {
        for tid in tunnels {
            let _ = self.inner.tunnels.release_linked(*tid, holder).await;
        }
    }

    /// Adds a Proxy, or updates it. A running Proxy reloads its routing at once; a failed
    /// reload keeps the running state and returns the error (the update stays saved).
    pub async fn upsert_proxy(&self, proxy: Proxy) -> Result<(), ProxyError> {
        let id = proxy.id;
        let slot = {
            let mut proxies = lock(&self.inner.proxies);
            match proxies.get(&id) {
                Some(slot) => {
                    *lock(&slot.proxy) = proxy;
                    Arc::clone(slot)
                }
                None => {
                    let slot = Arc::new(ProxySlot {
                        proxy: Mutex::new(proxy),
                        state: Mutex::new(ProxyState::Stopped),
                        logs: LogRingBuffer::new(self.inner.config.log_capacity),
                        records: AccessRecordBuffer::new(self.inner.config.log_capacity),
                        live: Mutex::new(None),
                        lifecycle: tokio::sync::Mutex::new(None),
                        watcher: Mutex::new(None),
                    });
                    proxies.insert(id, Arc::clone(&slot));
                    slot
                }
            }
        };
        if lock(&slot.live).is_none() {
            return Ok(());
        }
        let result = match self.reload(id).await {
            Ok(_) | Err(ProxyError::NotRunning(_)) => Ok(()),
            Err(e) => Err(e),
        };
        let logger = slot.lifecycle.lock().await.as_ref().map(|h| h.logger.clone());
        self.sync_watcher(&slot, id, logger);
        result
    }

    /// Starts, keeps, or stops the External TOML watcher so it matches the Proxy's source.
    /// `logger` is the running server's logger (`None` = not running: no watcher).
    fn sync_watcher(&self, slot: &ProxySlot, id: ProxyId, logger: Option<Logger>) {
        let source = lock(&slot.proxy).source.clone();
        let mut watcher = lock(&slot.watcher);
        let (SourceMode::ExternalToml { path, debounce_ms }, Some(logger)) = (source, logger) else {
            *watcher = None;
            return;
        };
        if watcher
            .as_ref()
            .is_some_and(|w| w.path == path && w.debounce_ms == debounce_ms)
        {
            return;
        }
        let weak: Weak<Inner> = Arc::downgrade(&self.inner);
        let watched = path.clone();
        let handle = spawn_toml_watcher(path.clone(), debounce_ms, move |event| {
            let weak = weak.clone();
            let logger = logger.clone();
            let watched = watched.clone();
            async move {
                if let Some(inner) = weak.upgrade() {
                    ProxyManager { inner }
                        .apply_external_toml(id, &watched, event, &logger)
                        .await;
                }
            }
        });
        *watcher = Some(LinkedWatcher { path, debounce_ms, _handle: handle });
    }

    /// Applies a linked-file change to a running Proxy. An unreadable file, invalid TOML, or a
    /// config the reload rejects is logged and the last good routing keeps serving.
    async fn apply_external_toml(
        &self,
        id: ProxyId,
        path: &Path,
        event: TomlWatchEvent,
        logger: &Logger,
    ) {
        let shown = path.display();
        let bytes = match event {
            TomlWatchEvent::Unreadable(error) => {
                logger.error(format!(
                    "warning: external TOML {shown} cannot be read ({error}); keeping the last \
                     good configuration"
                ));
                return;
            }
            TomlWatchEvent::Changed(bytes) => bytes,
        };
        let Ok(slot) = self.slot(id) else { return };
        let (previous, merged) = {
            let mut proxy = lock(&slot.proxy);
            // A stale event from a watcher being replaced or stopped.
            if !matches!(&proxy.source, SourceMode::ExternalToml { path: p, .. } if p == path) {
                return;
            }
            let Ok(text) = std::str::from_utf8(&bytes) else {
                logger.error(format!(
                    "warning: external TOML {shown} is not valid UTF-8; keeping the last good \
                     configuration"
                ));
                return;
            };
            let merged = match merge_external_toml_text(&proxy, text) {
                Ok(merged) => merged,
                Err(error) => {
                    logger.error(format!(
                        "warning: external TOML {shown} was rejected ({}); keeping the last good \
                         configuration",
                        redact(&error)
                    ));
                    return;
                }
            };
            if merged.proxy == *proxy {
                return;
            }
            let previous = std::mem::replace(&mut *proxy, merged.proxy.clone());
            (previous, merged)
        };
        for warning in &merged.warnings {
            logger.info(format!("external TOML {shown}: {warning}"));
        }
        match self.reload(id).await {
            Ok(generation) => logger.info(format!(
                "external TOML {shown} applied (generation {generation})"
            )),
            Err(ProxyError::NotRunning(_)) => {}
            Err(error) => {
                {
                    let mut proxy = lock(&slot.proxy);
                    if *proxy == merged.proxy {
                        *proxy = previous;
                    }
                }
                logger.error(format!(
                    "warning: external TOML {shown} was rejected ({error}); keeping the last good \
                     configuration"
                ));
            }
        }
    }

    /// Stops a Proxy and forgets it.
    pub async fn remove_proxy(&self, id: ProxyId) -> Result<(), ProxyError> {
        self.stop(id).await?;
        lock(&self.inner.proxies).remove(&id);
        Ok(())
    }

    /// Starts a Proxy. Does nothing if it is already running.
    pub async fn start(&self, id: ProxyId) -> Result<(), ProxyError> {
        let slot = self.slot(id)?;
        let mut lifecycle = slot.lifecycle.lock().await;
        if lifecycle.is_some() {
            return Ok(());
        }
        let proxy = lock(&slot.proxy).clone();
        self.set_state(&slot, id, ProxyState::Starting);
        match self.launch(&slot, &proxy).await {
            Ok((handles, live)) => {
                let state = live.running_state();
                let logger = handles.logger.clone();
                *lock(&slot.live) = Some(live);
                *lifecycle = Some(handles);
                self.set_state(&slot, id, state);
                self.sync_watcher(&slot, id, Some(logger));
                Ok(())
            }
            Err(error) => {
                let state = match &error {
                    ProxyError::VaultLocked => ProxyState::Locked,
                    other => ProxyState::NeedsAttention {
                        reason: other.to_string(),
                    },
                };
                self.set_state(&slot, id, state);
                Err(error)
            }
        }
    }

    async fn launch(
        &self,
        slot: &ProxySlot,
        proxy: &Proxy,
    ) -> Result<(ServerHandles, Live), ProxyError> {
        let server_options = proxy_server_options(proxy);
        if let Some((addr, other)) = self.port_conflict(proxy.id, &server_options.listeners()) {
            return Err(ProxyError::PortConflict { addr, other });
        }
        let extra = self.other_listeners(proxy.id);
        validate_proxy(proxy, &self.known_tunnels(), &extra).map_err(invalid)?;
        let level = LogLevel::from_str(&proxy.logging.level).map_err(ProxyError::Invalid)?;
        let format = LogFormat::from_str(&proxy.logging.format).map_err(ProxyError::Invalid)?;

        let secrets = self.read_secrets(proxy, true)?;
        let state = self.compile_routing(proxy, &secrets.passwords, &extra)?;
        let mitm = match (proxy_mitm_options(proxy), secrets.ca_pem.as_deref()) {
            (Some(opts), Some(pem)) => Some(
                MitmState::from_pem_bytes(pem, pem, &opts)
                    .map_err(|e| ProxyError::Mitm(e.to_string()))?,
            ),
            _ => None,
        };
        // The routing state and MITM state hold what they need now.
        drop(secrets);

        let logger = Logger::with_writer(level, Box::new(slot.logs.writer()));
        if let Some(m) = &mitm {
            m.cache.set_logger(logger.clone());
        }
        for notice in state.router.notices() {
            logger.info(notice.clone());
        }
        let access = AccessLogger::start_with_stdout(
            AccessLogConfig::new(
                level,
                format,
                proxy.logging.http_access_log.clone(),
                proxy.logging.socks_log.clone(),
            )
            .with_routing_fields(true),
            Box::new(slot.logs.writer()),
            logger.clone(),
        )
        .await
        .map_err(|e| ProxyError::AccessLog(e.to_string()))?
        .with_sink(slot.records.sink());

        let fail = |error: ProxyError, access: AccessLogger, logger: Logger| async move {
            let _ = access.shutdown().await;
            logger.flush();
            error
        };

        // Linked Tunnels first, staggered; the Proxy runs while they connect.
        let tunnels = proxy_referenced_tunnels(proxy);
        let mut acquired = Vec::new();
        for (index, tid) in tunnels.iter().enumerate() {
            if index > 0 {
                tokio::time::sleep(self.inner.config.autostart_stagger).await;
            }
            if let Err(e) = self.inner.tunnels.acquire_linked(*tid, proxy.id).await {
                // The holder is recorded even when the start failed.
                acquired.push(*tid);
                self.release_all(&acquired, proxy.id).await;
                return Err(fail(e.into(), access, logger).await);
            }
            acquired.push(*tid);
        }

        let routing = state.shared();
        let saved = routing.load_full();
        let mut handlers = EngineHandlers::from_routing(
            Arc::clone(&routing),
            access.clone().with_direction(ProxyDirection::Forward),
            logger.clone(),
        );
        if let Some(m) = &mitm {
            handlers = handlers.with_mitm(Arc::new(m.interceptor.clone()), false);
        }
        if proxy.socks_block_web || proxy.mitm.as_ref().is_some_and(|c| c.socks_block_web) {
            handlers = handlers.with_socks_block_web();
        }
        let handlers: Arc<dyn ProtocolHandlers> = Arc::new(handlers);
        let server = match Server::from_options(&server_options, handlers, logger.clone()).await {
            Ok(server) => server.with_runtime(Arc::clone(&routing)),
            Err(e) => {
                self.release_all(&acquired, proxy.id).await;
                return Err(fail(ProxyError::Bind(e.to_string()), access, logger).await);
            }
        };
        let listeners: Vec<ListenerInfo> = server
            .listeners()
            .into_iter()
            .map(|(role, addr)| {
                logger.info(format!("{role} proxy listening on {addr}"));
                ListenerInfo {
                    role: role.to_string(),
                    addr,
                }
            })
            .collect();
        let token = server.shutdown_token();
        let reaper = mitm
            .as_ref()
            .map(|m| m.cache.spawn_reaper(token.clone(), logger.clone()));
        let run = tokio::spawn(server.run());

        let handles = ServerHandles {
            token,
            run,
            reaper,
            access,
            logger,
        };
        let live = Live {
            baseline: proxy.clone(),
            compiled: proxy.clone(),
            routing,
            saved,
            override_profile: None,
            generation: 0,
            restart_required: false,
            tunnels: acquired,
            listeners,
        };
        Ok((handles, live))
    }

    /// Stops a Proxy: drain the server, stop the reaper, flush the loggers, release Tunnels.
    pub async fn stop(&self, id: ProxyId) -> Result<(), ProxyError> {
        let slot = self.slot(id)?;
        // Not awaited: a change being applied would wait on the lifecycle lock held below.
        lock(&slot.watcher).take();
        let mut lifecycle = slot.lifecycle.lock().await;
        if let Some(handles) = lifecycle.take() {
            self.set_state(&slot, id, ProxyState::Stopping);
            handles.token.cancel();
            if let Ok(report) = handles.run.await {
                if report.drained {
                    handles.logger.debug("all connections drained");
                }
            }
            if let Some(reaper) = handles.reaper {
                let _ = reaper.await;
            }
            handles.logger.info("shutting down");
            if let Err(e) = handles.access.shutdown().await {
                handles
                    .logger
                    .error(format!("failed to flush access logs: {e}"));
            }
            handles.logger.flush();
        }
        let live = lock(&slot.live).take();
        if let Some(live) = live {
            self.release_all(&live.tunnels, id).await;
        }
        self.set_state(&slot, id, ProxyState::Stopped);
        Ok(())
    }

    pub async fn restart(&self, id: ProxyId) -> Result<(), ProxyError> {
        self.stop(id).await?;
        self.start(id).await
    }

    /// Stops every Proxy concurrently.
    pub async fn stop_all(&self) {
        let mut stops = JoinSet::new();
        for id in lock(&self.inner.proxies).keys().copied().collect::<Vec<_>>() {
            let manager = self.clone();
            stops.spawn(async move {
                let _ = manager.stop(id).await;
            });
        }
        while stops.join_next().await.is_some() {}
    }

    /// Recompiles a running Proxy's routing from its saved config and swaps it in, keeping
    /// the counters. Returns the new generation. On failure nothing changes.
    pub async fn reload(&self, id: ProxyId) -> Result<u64, ProxyError> {
        let slot = self.slot(id)?;
        let lifecycle = slot.lifecycle.lock().await;
        let Some(handles) = lifecycle.as_ref() else {
            return Err(ProxyError::NotRunning(id));
        };
        let proxy = lock(&slot.proxy).clone();
        let (baseline, prev_saved, prev_generation, prev_override, prev_tunnels, bound, routing) = {
            let live = lock(&slot.live);
            let live = live.as_ref().ok_or(ProxyError::NotRunning(id))?;
            (
                live.baseline.clone(),
                Arc::clone(&live.saved),
                live.generation,
                live.override_profile.clone(),
                live.tunnels.clone(),
                live.bound(),
                Arc::clone(&live.routing),
            )
        };
        self.set_state(&slot, id, ProxyState::Reloading);

        let mut extra = self.other_listeners(id);
        extra.extend(bound);
        let generation = prev_generation + 1;
        let compiled = validate_proxy(&proxy, &self.known_tunnels(), &extra)
            .map_err(invalid)
            .and_then(|()| self.read_secrets(&proxy, false))
            .and_then(|secrets| self.compile_routing(&proxy, &secrets.passwords, &extra));
        let next = match compiled {
            Ok(state) => Arc::new(
                state
                    .with_counters(prev_saved.counters().clone())
                    .with_generation(generation),
            ),
            Err(error) => {
                handles.logger.error(format!("reload rejected: {error}"));
                self.restore_running(&slot, id);
                return Err(error);
            }
        };

        // New Linked references before the swap, so routes to them have a live Tunnel.
        let next_tunnels = proxy_referenced_tunnels(&proxy);
        let mut added = Vec::new();
        for tid in next_tunnels.iter().filter(|t| !prev_tunnels.contains(t)) {
            if let Err(e) = self.inner.tunnels.acquire_linked(*tid, id).await {
                added.push(*tid);
                self.release_all(&added, id).await;
                let error = ProxyError::from(e);
                handles.logger.error(format!("reload rejected: {error}"));
                self.restore_running(&slot, id);
                return Err(error);
            }
            added.push(*tid);
        }

        let (active, override_profile, cleared) = match prev_override {
            Some(profile) if profile_exists(&proxy, &profile) => {
                match override_state(&proxy, &next, &profile, &extra) {
                    Ok(state) => (Arc::new(state), Some(profile), false),
                    Err(_) => (Arc::clone(&next), None, true),
                }
            }
            Some(_) => (Arc::clone(&next), None, true),
            None => (Arc::clone(&next), None, false),
        };
        routing.store(active);

        let removed: Vec<TunnelId> = prev_tunnels
            .iter()
            .filter(|t| !next_tunnels.contains(t))
            .copied()
            .collect();
        self.release_all(&removed, id).await;

        let state = {
            let mut live = lock(&slot.live);
            let live = live.as_mut().ok_or(ProxyError::NotRunning(id))?;
            live.restart_required = requires_restart(&baseline, &proxy);
            live.compiled = proxy;
            live.saved = next;
            live.generation = generation;
            live.override_profile = override_profile;
            live.tunnels = next_tunnels;
            live.running_state()
        };
        handles
            .logger
            .info(format!("configuration reloaded (generation {generation})"));
        self.emit(ProxyEvent::Reloaded {
            proxy_id: id,
            config_generation: generation,
        });
        if cleared {
            self.emit(ProxyEvent::OverrideChanged {
                proxy_id: id,
                override_profile: None,
            });
        }
        self.set_state(&slot, id, state);
        Ok(generation)
    }

    fn restore_running(&self, slot: &ProxySlot, id: ProxyId) {
        let state = lock(&slot.live).as_ref().map(Live::running_state);
        if let Some(state) = state {
            self.set_state(slot, id, state);
        }
    }

    /// Tray override: `Some(profile)` (e.g. `"direct"`) sends everything to that profile;
    /// `None` (*Auto Switch*) restores the saved routing.
    pub async fn set_override(
        &self,
        id: ProxyId,
        override_profile: Option<String>,
    ) -> Result<(), ProxyError> {
        let slot = self.slot(id)?;
        let lifecycle = slot.lifecycle.lock().await;
        if lifecycle.is_none() {
            return Err(ProxyError::NotRunning(id));
        }
        let (compiled, saved, routing, bound) = {
            let live = lock(&slot.live);
            let live = live.as_ref().ok_or(ProxyError::NotRunning(id))?;
            (
                live.compiled.clone(),
                Arc::clone(&live.saved),
                Arc::clone(&live.routing),
                live.bound(),
            )
        };
        let active = match &override_profile {
            Some(profile) => {
                if !profile_exists(&compiled, profile) {
                    return Err(ProxyError::UnknownProfile(profile.clone()));
                }
                let mut extra = self.other_listeners(id);
                extra.extend(bound);
                Arc::new(override_state(&compiled, &saved, profile, &extra)?)
            }
            None => saved,
        };
        routing.store(active);
        let state = {
            let mut live = lock(&slot.live);
            let live = live.as_mut().ok_or(ProxyError::NotRunning(id))?;
            live.override_profile = override_profile.clone();
            live.running_state()
        };
        self.emit(ProxyEvent::OverrideChanged {
            proxy_id: id,
            override_profile,
        });
        self.set_state(&slot, id, state);
        Ok(())
    }

    /// Route Tester: where `raw_target` (`host[:port]` or an `http(s)://` URL) goes under
    /// `proxy`'s draft config. Needs no vault: vaulted passwords are placeholders.
    pub fn test_route(
        proxy: &Proxy,
        raw_target: &str,
        inbound: RouteInbound,
    ) -> Result<RouteTestResult, ProxyError> {
        let target = ParsedTarget::parse(raw_target).map_err(ProxyError::InvalidTarget)?;
        let input =
            proxy_to_routing_input(proxy, &placeholder_passwords(proxy), &[]).map_err(invalid)?;
        let router = Router::from_input(&input).map_err(|e| ProxyError::Routing(e.to_string()))?;
        let request = RouteRequest {
            inbound: engine_inbound(inbound),
            host: &target.host,
            port: target.port,
            scheme: target.scheme.as_deref(),
            url: target.url.as_deref(),
        };
        let decision = match router.route(&request) {
            Ok(decision) => decision,
            Err(denied) => {
                return Ok(RouteTestResult {
                    table: None,
                    matched_rule: None,
                    blocked_by_filter: true,
                    filter_reason: Some(denied.to_string()),
                    targets: Vec::new(),
                })
            }
        };
        let redacted = |profile: &str| -> String {
            match proxy.profiles.iter().find(|p| p.name == profile).map(|p| &p.kind) {
                Some(UpstreamKind::Tunnel { tunnel_id }) => format!("tunnel {tunnel_id}"),
                _ => router
                    .profile(profile)
                    .map(|p| p.redacted_upstream())
                    .unwrap_or_else(|| profile.to_string()),
            }
        };
        Ok(RouteTestResult {
            table: Some(decision.table.as_str().to_string()),
            matched_rule: decision.rule.clone(),
            blocked_by_filter: false,
            filter_reason: None,
            targets: decision
                .targets
                .iter()
                .map(|t| RouteTestTarget {
                    name: t.name.clone(),
                    profile: t.profile.clone(),
                    redacted_upstream: redacted(&t.profile),
                    bypassed: t.bypassed,
                })
                .collect(),
        })
    }

    /// Test Upstream: dial `host:port` through `profile_name`'s dialer (a Tunnel's included),
    /// timing it. Dial failures are `Ok` with `ok: false` and a redacted error.
    pub async fn test_upstream(
        &self,
        proxy: &Proxy,
        profile_name: &str,
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<UpstreamProbeResult, ProxyError> {
        let profile = proxy.profiles.iter().find(|p| p.name == profile_name);
        if profile.is_none() && !profile_exists(proxy, profile_name) {
            return Err(ProxyError::UnknownProfile(profile_name.to_string()));
        }
        let mut passwords = placeholder_passwords(proxy);
        if let Some(UpstreamPasswordSource::Vault(_)) = profile.and_then(|p| p.password.as_ref()) {
            let only = Proxy {
                profiles: profile.into_iter().cloned().collect(),
                mitm: None,
                ..Proxy::default()
            };
            passwords.extend(self.read_secrets(&only, false)?.passwords);
        }
        let input = proxy_to_routing_input(proxy, &passwords, &[]).map_err(invalid)?;
        let mut opts = DialerOptions {
            keepalive: input.keepalive,
            filter: input.filter.clone().map(Arc::new),
            ..DialerOptions::default()
        };
        if let Some(UpstreamKind::Tunnel { tunnel_id }) = profile.map(|p| &p.kind) {
            let dialer = self
                .inner
                .tunnels
                .dialer(*tunnel_id)
                .ok_or(ProxyError::UnknownTunnel(*tunnel_id))?;
            opts = opts.with_external(profile_name, dialer);
        }
        let profiles = input.profiles_with_builtins();
        let config = profiles
            .get(profile_name)
            .ok_or_else(|| ProxyError::UnknownProfile(profile_name.to_string()))?;
        let dialer = dialer_for_profile(profile_name, config, &opts)
            .map_err(|e| ProxyError::Routing(redact(&e.to_string())))?
            .ok_or_else(|| ProxyError::NoDialer(profile_name.to_string()))?;
        drop(passwords);

        let redacted_upstream = dialer.redacted_upstream();
        let started = Instant::now();
        let outcome = tokio::time::timeout(
            timeout + Duration::from_secs(1),
            dialer.connect(host, port, timeout),
        )
        .await;
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let error = match outcome {
            Ok(Ok(stream)) => {
                drop(stream);
                None
            }
            Ok(Err(e)) => Some(redact(&e.to_string())),
            Err(_) => Some(format!("timed out after {} ms", timeout.as_millis())),
        };
        Ok(UpstreamProbeResult {
            ok: error.is_none(),
            elapsed_ms,
            redacted_upstream,
            error,
        })
    }

    /// A view of every Proxy, sorted by name.
    pub fn snapshots(&self) -> Vec<ProxySnapshot> {
        let mut snapshots: Vec<ProxySnapshot> =
            self.slots().iter().map(|s| s.snapshot()).collect();
        snapshots.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then(a.id.as_uuid().cmp(&b.id.as_uuid()))
        });
        snapshots
    }

    pub fn snapshot(&self, id: ProxyId) -> Result<ProxySnapshot, ProxyError> {
        Ok(self.slot(id)?.snapshot())
    }

    /// The log buffer for a Proxy, for querying, clearing, or subscribing.
    pub fn logs(&self, id: ProxyId) -> Result<LogRingBuffer, ProxyError> {
        Ok(self.slot(id)?.logs.clone())
    }

    /// The structured access records for a Proxy's log drawer.
    pub fn access_records(&self, id: ProxyId) -> Result<AccessRecordBuffer, ProxyError> {
        Ok(self.slot(id)?.records.clone())
    }

    /// The routing state currently serving a running Proxy (override included).
    pub fn current_routing(&self, id: ProxyId) -> Result<Option<Arc<RoutingState>>, ProxyError> {
        let slot = self.slot(id)?;
        let live = lock(&slot.live);
        Ok(live.as_ref().map(|l| l.routing.load_full()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use conduit_core::{
        GlobalFilterConfig, HopEntry, HostProfile, KnownHostsStore, MitmConfig, RouteOneOrMany,
        RoutingRule, SecretRef, Tunnel, UpstreamProfile,
    };
    use conduit_vault::Argon2Params;
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use uuid::Uuid;

    const TIMEOUT: Duration = Duration::from_secs(5);

    fn temp_vault() -> Vault {
        let path = std::env::temp_dir()
            .join(format!("conduit-runtime-proxy-test-{}", Uuid::new_v4()))
            .join("vault.bin");
        let params = Argon2Params {
            memory_kib: 8 * 1024,
            time_cost: 1,
            parallelism: 1,
            derived_key_len: 32,
        };
        Vault::create_with_password(path, b"pw", params).unwrap()
    }

    fn manager_with(vault: Vault) -> (ProxyManager, Arc<TunnelManager>) {
        let vault = Arc::new(RwLock::new(vault));
        let config = ManagerConfig {
            autostart_stagger: Duration::from_millis(1),
            ..ManagerConfig::default()
        };
        let tunnels = Arc::new(TunnelManager::new(
            Arc::clone(&vault),
            Arc::new(RwLock::new(KnownHostsStore::default())),
            config.clone(),
        ));
        (
            ProxyManager::new(Arc::clone(&tunnels), vault, config),
            tunnels,
        )
    }

    fn upstream(name: &str, kind: UpstreamKind, host: &str, port: u16) -> UpstreamProfile {
        UpstreamProfile {
            name: name.into(),
            kind,
            host: Some(host.into()),
            port: Some(port),
            username: None,
            password: None,
            bypass: Vec::new(),
            color: None,
        }
    }

    fn rule(name: &str, wildcard: &str, target: &str) -> RoutingRule {
        let mut rule = RoutingRule::to_target(RouteOneOrMany::One(target.into()));
        rule.name = Some(name.into());
        rule.host_wildcard = Some(RouteOneOrMany::One(wildcard.into()));
        rule
    }

    /// A Proxy with a `corp` HTTP profile and one rule sending `*.corp.example` to it.
    fn corp_proxy(http_port: u16) -> Proxy {
        let mut proxy = Proxy {
            id: ProxyId::new(),
            name: "corp".into(),
            ..Proxy::default()
        };
        proxy.listeners.http_port = http_port;
        proxy.listeners.socks_port = 0;
        proxy
            .profiles
            .push(upstream("corp", UpstreamKind::Http, "10.0.0.5", 3128));
        proxy.routing.rules.push(rule("corp-sites", "*.corp.example", "corp"));
        proxy
    }

    async fn free_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    }

    async fn spawn_echo() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = stream.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        addr
    }

    // ------------------------------------------------------------------ pure helpers

    #[test]
    fn proxy_state_serializes_tagged() {
        assert_eq!(
            serde_json::to_value(ProxyState::Stopped).unwrap(),
            json!({ "state": "stopped" })
        );
        assert_eq!(
            serde_json::to_value(ProxyState::Running {
                override_profile: Some("direct".into()),
                config_generation: 3,
                restart_required: true,
            })
            .unwrap(),
            json!({
                "state": "running",
                "override_profile": "direct",
                "config_generation": 3,
                "restart_required": true,
            })
        );
        assert_eq!(
            serde_json::to_value(ProxyState::NeedsAttention { reason: "x".into() }).unwrap(),
            json!({ "state": "needs_attention", "reason": "x" })
        );
        assert_eq!(
            serde_json::to_value(ProxyState::Locked).unwrap(),
            json!({ "state": "locked" })
        );
        let event = ProxyEvent::Reloaded {
            proxy_id: ProxyId::default(),
            config_generation: 2,
        };
        assert_eq!(serde_json::to_value(&event).unwrap()["event"], "reloaded");
    }

    #[test]
    fn restart_required_only_for_listeners_mitm_and_logging() {
        let base = corp_proxy(8080);

        let mut routing = base.clone();
        routing.routing.rules.clear();
        routing.network.connect_timeout = Duration::from_secs(3);
        routing.profiles[0].port = Some(3129);
        assert!(!requires_restart(&base, &routing));

        let mut port = base.clone();
        port.listeners.http_port = 8081;
        assert!(requires_restart(&base, &port));

        let mut max = base.clone();
        max.listeners.max_connections += 1;
        assert!(requires_restart(&base, &max));

        let mut mitm = base.clone();
        mitm.mitm = Some(MitmConfig::default());
        assert!(requires_restart(&base, &mitm));

        let mut logging = base.clone();
        logging.logging.level = "DEBUG".into();
        assert!(requires_restart(&base, &logging));
    }

    #[test]
    fn access_record_buffer_starts_empty() {
        let buffer = AccessRecordBuffer::new(2);
        assert!(buffer.is_empty());
        assert_eq!(buffer.query(None).len(), 0);
        assert_eq!(buffer.len(), 0);
    }

    // ------------------------------------------------------------------ route tester

    #[test]
    fn test_route_reports_rule_and_redacted_upstream() {
        let proxy = corp_proxy(8080);
        let hit =
            ProxyManager::test_route(&proxy, "https://app.corp.example/x", RouteInbound::Http)
                .unwrap();
        assert_eq!(hit.table.as_deref(), Some("[routing]"));
        assert_eq!(hit.matched_rule.as_deref(), Some("corp-sites"));
        assert!(!hit.blocked_by_filter);
        assert_eq!(
            hit.targets,
            vec![RouteTestTarget {
                name: "corp".into(),
                profile: "corp".into(),
                redacted_upstream: "http://10.0.0.5:3128".into(),
                bypassed: false,
            }]
        );

        let miss =
            ProxyManager::test_route(&proxy, "example.com:443", RouteInbound::Socks).unwrap();
        assert_eq!(miss.matched_rule, None);
        assert_eq!(miss.targets[0].profile, PROFILE_DIRECT);
        assert_eq!(miss.targets[0].redacted_upstream, "direct");
    }

    #[test]
    fn test_route_handles_bypass_filter_vault_and_bad_targets() {
        let mut proxy = corp_proxy(8080);
        proxy.profiles[0].bypass = vec!["skip.corp.example".into()];
        // A vaulted password needs no vault for route testing.
        proxy.profiles[0].password = Some(UpstreamPasswordSource::Vault(SecretRef::new()));
        let bypassed =
            ProxyManager::test_route(&proxy, "skip.corp.example", RouteInbound::Http).unwrap();
        assert_eq!(bypassed.matched_rule.as_deref(), Some("corp-sites"));
        assert!(bypassed.targets[0].bypassed);
        assert_eq!(bypassed.targets[0].profile, PROFILE_DIRECT);

        proxy.filter = GlobalFilterConfig::Block(vec!["evil.example".into()]);
        let denied = ProxyManager::test_route(&proxy, "evil.example", RouteInbound::Http).unwrap();
        assert!(denied.blocked_by_filter);
        assert!(denied.filter_reason.is_some());
        assert!(denied.targets.is_empty());

        assert!(matches!(
            ProxyManager::test_route(&proxy, "", RouteInbound::Http),
            Err(ProxyError::InvalidTarget(_))
        ));
        assert!(matches!(
            ProxyManager::test_route(&proxy, "ftp://x", RouteInbound::Http),
            Err(ProxyError::InvalidTarget(_))
        ));

        proxy.routing.rules.push(rule("bad", "*", "missing"));
        assert!(matches!(
            ProxyManager::test_route(&proxy, "a.example", RouteInbound::Http),
            Err(ProxyError::Routing(_) | ProxyError::Invalid(_))
        ));
    }

    #[test]
    fn test_route_labels_tunnel_profiles() {
        let tunnel_id = TunnelId::new();
        let mut proxy = corp_proxy(8080);
        proxy.profiles.push(UpstreamProfile {
            host: None,
            port: None,
            ..upstream("bastion", UpstreamKind::Tunnel { tunnel_id }, "", 0)
        });
        proxy.routing.rules.insert(0, rule("via-tunnel", "*.internal", "bastion"));
        let result =
            ProxyManager::test_route(&proxy, "db.internal:5432", RouteInbound::Socks).unwrap();
        assert_eq!(result.targets[0].profile, "bastion");
        assert_eq!(result.targets[0].redacted_upstream, format!("tunnel {tunnel_id}"));
    }

    // ------------------------------------------------------------------ test upstream

    #[tokio::test]
    async fn test_upstream_probes_direct_and_reports_failures() {
        let (manager, tunnels) = manager_with(temp_vault());
        let echo = spawn_echo().await;
        let proxy = corp_proxy(8080);

        let ok = manager
            .test_upstream(&proxy, PROFILE_DIRECT, "127.0.0.1", echo.port(), TIMEOUT)
            .await
            .unwrap();
        assert!(ok.ok, "{ok:?}");
        assert_eq!(ok.redacted_upstream, "direct");
        assert!(ok.error.is_none());

        let closed = free_port().await;
        let refused = manager
            .test_upstream(&proxy, PROFILE_DIRECT, "127.0.0.1", closed, TIMEOUT)
            .await
            .unwrap();
        assert!(!refused.ok);
        assert!(refused.error.is_some());

        assert_eq!(
            manager
                .test_upstream(&proxy, "nope", "127.0.0.1", 1, TIMEOUT)
                .await,
            Err(ProxyError::UnknownProfile("nope".into()))
        );

        // A Tunnel that is not connected refuses the dial.
        let tunnel = Tunnel {
            id: TunnelId::new(),
            name: "bastion".into(),
            hops: vec![HopEntry {
                hop_id: "h".into(),
                name: "h".into(),
                host: HostProfile {
                    host: "127.0.0.1".into(),
                    user: "u".into(),
                    ..Default::default()
                },
            }],
            ..Tunnel::default()
        };
        let mut via = proxy.clone();
        via.profiles.push(UpstreamProfile {
            host: None,
            port: None,
            ..upstream("bastion", UpstreamKind::Tunnel { tunnel_id: tunnel.id }, "", 0)
        });
        assert_eq!(
            manager
                .test_upstream(&via, "bastion", "127.0.0.1", echo.port(), TIMEOUT)
                .await,
            Err(ProxyError::UnknownTunnel(tunnel.id))
        );
        tunnels.upsert_tunnel(tunnel);
        let down = manager
            .test_upstream(&via, "bastion", "127.0.0.1", echo.port(), TIMEOUT)
            .await
            .unwrap();
        assert!(!down.ok);
        assert!(down.error.is_some());
    }

    #[tokio::test]
    async fn test_upstream_with_vaulted_password_needs_unlocked_vault() {
        let mut vault = temp_vault();
        vault.lock();
        let (manager, _tunnels) = manager_with(vault);
        let mut proxy = corp_proxy(8080);
        proxy.profiles[0].password = Some(UpstreamPasswordSource::Vault(SecretRef::new()));
        assert_eq!(
            manager
                .test_upstream(&proxy, "corp", "example.com", 80, TIMEOUT)
                .await,
            Err(ProxyError::VaultLocked)
        );
    }

    // ------------------------------------------------------------------ lifecycle

    #[tokio::test]
    async fn start_is_locked_when_vaulted_secrets_are_unavailable() {
        let mut vault = temp_vault();
        vault.lock();
        let (manager, _tunnels) = manager_with(vault);
        let mut proxy = corp_proxy(free_port().await);
        proxy.profiles[0].password = Some(UpstreamPasswordSource::Vault(SecretRef::new()));
        let id = proxy.id;
        manager.upsert_proxy(proxy).await.unwrap();
        assert_eq!(manager.start(id).await, Err(ProxyError::VaultLocked));
        assert_eq!(manager.snapshot(id).unwrap().state, ProxyState::Locked);
        manager.stop(id).await.unwrap();
        assert_eq!(manager.snapshot(id).unwrap().state, ProxyState::Stopped);
    }

    #[tokio::test]
    async fn invalid_proxy_needs_attention() {
        let (manager, _tunnels) = manager_with(temp_vault());
        let mut proxy = corp_proxy(0);
        let id = proxy.id;
        proxy.name = "none".into();
        manager.upsert_proxy(proxy).await.unwrap();
        assert!(matches!(manager.start(id).await, Err(ProxyError::Invalid(_))));
        assert!(matches!(
            manager.snapshot(id).unwrap().state,
            ProxyState::NeedsAttention { .. }
        ));
        assert_eq!(
            manager.start(ProxyId::new()).await.unwrap_err().to_string().split(' ').next(),
            Some("unknown")
        );
    }

    #[tokio::test]
    async fn run_reload_override_and_stop() {
        let (manager, _tunnels) = manager_with(temp_vault());
        let mut events = manager.subscribe_events();
        let echo = spawn_echo().await;
        let port = free_port().await;
        let proxy = corp_proxy(port);
        let id = proxy.id;
        manager.upsert_proxy(proxy.clone()).await.unwrap();
        manager.start(id).await.unwrap();

        let snapshot = manager.snapshot(id).unwrap();
        assert_eq!(
            snapshot.state,
            ProxyState::Running {
                override_profile: None,
                config_generation: 0,
                restart_required: false,
            }
        );
        assert_eq!(snapshot.listeners.len(), 1);
        let listen = snapshot.listeners[0].addr;
        assert_eq!(listen.port(), port);
        assert!(matches!(events.try_recv(), Ok(ProxyEvent::StateChanged { state: ProxyState::Starting, .. })));

        // A second Proxy on the same port is a conflict.
        let mut twin = corp_proxy(port);
        twin.name = "twin".into();
        let twin_id = twin.id;
        manager.upsert_proxy(twin).await.unwrap();
        assert!(matches!(
            manager.start(twin_id).await,
            Err(ProxyError::PortConflict { .. })
        ));

        // Traffic through CONNECT is counted for the default route.
        let mut client = TcpStream::connect(listen).await.unwrap();
        let request = format!(
            "CONNECT 127.0.0.1:{p} HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\n\r\n",
            p = echo.port()
        );
        client.write_all(request.as_bytes()).await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            client.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"), "{head:?}");
        client.write_all(b"ping").await.unwrap();
        let mut back = [0u8; 4];
        client.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"ping");
        drop(client);
        let counters = manager.snapshot(id).unwrap().profile_counters;
        assert!(counters[PROFILE_DIRECT].hits >= 1, "{counters:?}");

        // Hot reload of routing: new generation, counters kept, listeners untouched.
        let mut next = proxy.clone();
        next.routing.rules.push(rule("more", "*.more.example", "corp"));
        manager.upsert_proxy(next.clone()).await.unwrap();
        let snapshot = manager.snapshot(id).unwrap();
        assert_eq!(snapshot.config_generation, 1);
        assert!(!snapshot.restart_required);
        assert!(snapshot.profile_counters[PROFILE_DIRECT].hits >= 1);
        let routing = manager.current_routing(id).unwrap().unwrap();
        assert_eq!(routing.config_generation, 1);
        assert_eq!(routing.router.rule_count(), 2);

        // A bad config is rejected and the running state is kept.
        let mut bad = next.clone();
        bad.routing.rules.push(rule("bad", "*", "missing"));
        assert!(manager.upsert_proxy(bad).await.is_err());
        let snapshot = manager.snapshot(id).unwrap();
        assert_eq!(snapshot.config_generation, 1);
        assert!(matches!(snapshot.state, ProxyState::Running { .. }));
        assert_eq!(manager.current_routing(id).unwrap().unwrap().router.rule_count(), 2);

        // A listener change only flags a restart.
        let mut moved = next.clone();
        moved.listeners.http_port = free_port().await;
        manager.upsert_proxy(moved).await.unwrap();
        let snapshot = manager.snapshot(id).unwrap();
        assert_eq!(snapshot.config_generation, 2);
        assert!(snapshot.restart_required);
        assert_eq!(snapshot.listeners[0].addr, listen);
        manager.upsert_proxy(next.clone()).await.unwrap();
        assert!(!manager.snapshot(id).unwrap().restart_required);

        // Tray override swaps a rule-less state and Auto Switch restores the saved one.
        assert_eq!(
            manager.set_override(id, Some("missing".into())).await,
            Err(ProxyError::UnknownProfile("missing".into()))
        );
        manager.set_override(id, Some("corp".into())).await.unwrap();
        let forced = manager.current_routing(id).unwrap().unwrap();
        assert_eq!(forced.router.rule_count(), 0);
        assert_eq!(forced.config_generation, 3);
        assert_eq!(
            manager.snapshot(id).unwrap().override_profile.as_deref(),
            Some("corp")
        );
        let decision = forced
            .router
            .route(&RouteRequest::new(Inbound::Http, "example.com", 80))
            .unwrap();
        assert_eq!(decision.targets[0].profile, "corp");

        // A reload keeps a still-valid override applied.
        let mut again = next.clone();
        again.routing.rules.push(rule("again", "*.again.example", "corp"));
        manager.upsert_proxy(again.clone()).await.unwrap();
        assert_eq!(manager.current_routing(id).unwrap().unwrap().router.rule_count(), 0);
        assert_eq!(
            manager.snapshot(id).unwrap().override_profile.as_deref(),
            Some("corp")
        );

        // Removing the overridden profile clears the override on reload.
        let mut gone = again.clone();
        gone.profiles.clear();
        gone.routing.rules.clear();
        manager.upsert_proxy(gone).await.unwrap();
        assert_eq!(manager.snapshot(id).unwrap().override_profile, None);
        manager.upsert_proxy(again).await.unwrap();

        manager.set_override(id, Some(PROFILE_DIRECT.into())).await.unwrap();
        manager.set_override(id, None).await.unwrap();
        let restored = manager.current_routing(id).unwrap().unwrap();
        assert_eq!(restored.router.rule_count(), 3);
        assert_eq!(manager.snapshot(id).unwrap().override_profile, None);

        manager.stop(id).await.unwrap();
        let snapshot = manager.snapshot(id).unwrap();
        assert_eq!(snapshot.state, ProxyState::Stopped);
        assert!(snapshot.listeners.is_empty());
        assert!(manager.current_routing(id).unwrap().is_none());
        assert_eq!(manager.reload(id).await, Err(ProxyError::NotRunning(id)));
        assert_eq!(
            manager.set_override(id, None).await,
            Err(ProxyError::NotRunning(id))
        );
        assert!(TcpStream::connect(listen).await.is_err());
        manager.remove_proxy(id).await.unwrap();
        assert!(manager.snapshot(id).is_err());
        manager.stop_all().await;
    }

    #[tokio::test]
    async fn linked_tunnels_are_acquired_and_released() {
        let (manager, tunnels) = manager_with(temp_vault());
        let tunnel = Tunnel {
            id: TunnelId::new(),
            name: "bastion".into(),
            // Disabled, so acquiring records the holder without dialing SSH.
            enabled: false,
            hops: vec![HopEntry {
                hop_id: "h".into(),
                name: "h".into(),
                host: HostProfile {
                    host: "127.0.0.1".into(),
                    user: "u".into(),
                    ..Default::default()
                },
            }],
            ..Tunnel::default()
        };
        let tid = tunnel.id;
        tunnels.upsert_tunnel(tunnel);
        let mut proxy = corp_proxy(free_port().await);
        proxy.profiles.push(UpstreamProfile {
            host: None,
            port: None,
            ..upstream("bastion", UpstreamKind::Tunnel { tunnel_id: tid }, "", 0)
        });
        let id = proxy.id;
        manager.upsert_proxy(proxy.clone()).await.unwrap();
        manager.start(id).await.unwrap();
        assert_eq!(tunnels.snapshot(tid).unwrap().linked_holders, 1);
        assert_eq!(manager.snapshot(id).unwrap().referenced_tunnels, vec![tid]);

        // Dropping the reference on reload releases the Tunnel.
        let mut without = proxy.clone();
        without.profiles.retain(|p| p.name != "bastion");
        manager.upsert_proxy(without).await.unwrap();
        assert_eq!(tunnels.snapshot(tid).unwrap().linked_holders, 0);
        manager.upsert_proxy(proxy).await.unwrap();
        assert_eq!(tunnels.snapshot(tid).unwrap().linked_holders, 1);

        manager.stop(id).await.unwrap();
        assert_eq!(tunnels.snapshot(tid).unwrap().linked_holders, 0);
    }

    fn linked_toml(port: u16, rules: &[(&str, &str)]) -> String {
        let mut text = format!(
            "bind = \"127.0.0.1\"\nhttp_port = {port}\nsocks_port = 0\n\n\
             [profiles.corp]\ntype = \"http\"\nhost = \"10.0.0.5\"\nport = 3128\n\n\
             [routing]\ndefault = \"direct\"\n"
        );
        for (wildcard, target) in rules {
            text.push_str(&format!(
                "\n[[routing.rules]]\nhost_wildcard = \"{wildcard}\"\ntarget = \"{target}\"\n"
            ));
        }
        text
    }

    async fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + TIMEOUT;
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    #[tokio::test]
    async fn external_toml_hot_reloads_and_keeps_last_good_on_invalid_files() {
        let (manager, _tunnels) = manager_with(temp_vault());
        let mut events = manager.subscribe_events();
        let dir = std::env::temp_dir().join(format!("conduit-linked-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        let port = free_port().await;
        std::fs::write(&path, linked_toml(port, &[("*.corp.example", "corp")])).unwrap();

        let base = Proxy {
            id: ProxyId::new(),
            name: "linked".into(),
            source: SourceMode::ExternalToml { path: path.clone(), debounce_ms: 250 },
            ..Proxy::default()
        };
        let text = std::fs::read_to_string(&path).unwrap();
        let proxy = merge_external_toml_text(&base, &text).unwrap().proxy;
        let id = proxy.id;
        manager.upsert_proxy(proxy.clone()).await.unwrap();
        manager.start(id).await.unwrap();
        let rules = || manager.current_routing(id).unwrap().unwrap().router.rule_count();
        let generation = || manager.snapshot(id).unwrap().config_generation;
        assert_eq!((generation(), rules()), (0, 1));

        // An unchanged file is not reloaded; an edited one is, live.
        tokio::time::sleep(Duration::from_millis(800)).await;
        assert_eq!(generation(), 0);
        std::fs::write(
            &path,
            linked_toml(port, &[("*.corp.example", "corp"), ("*.more.example", "corp")]),
        )
        .unwrap();
        wait_until("the edited file to reload", || generation() == 1).await;
        assert_eq!(rules(), 2);
        assert!(!manager.snapshot(id).unwrap().restart_required);
        let mut reloaded = false;
        while let Ok(event) = events.try_recv() {
            reloaded |= matches!(event, ProxyEvent::Reloaded { config_generation: 1, .. });
        }
        assert!(reloaded);
        assert_eq!(lock(&manager.slot(id).unwrap().proxy).source, proxy.source);

        // Invalid TOML: a warning, and the last good routing keeps serving.
        let logs = manager.logs(id).unwrap();
        let warnings = |logs: &LogRingBuffer| {
            logs.query(None)
                .iter()
                .filter(|l| l.text.contains("external TOML") && l.text.contains("rejected"))
                .count()
        };
        std::fs::write(&path, "http_port = [\n").unwrap();
        wait_until("the invalid-TOML warning", || warnings(&logs) == 1).await;
        assert_eq!((generation(), rules()), (1, 2));
        assert!(matches!(manager.snapshot(id).unwrap().state, ProxyState::Running { .. }));

        // Valid TOML that fails validation: rejected, and the saved config is restored.
        std::fs::write(&path, linked_toml(port, &[("*", "missing")])).unwrap();
        wait_until("the rejected-config warning", || warnings(&logs) == 2).await;
        assert_eq!((generation(), rules()), (1, 2));
        assert_eq!(lock(&manager.slot(id).unwrap().proxy).routing.rules.len(), 2);

        // A deleted file is reported and changes nothing.
        std::fs::remove_file(&path).unwrap();
        wait_until("the unreadable warning", || {
            logs.query(None).iter().any(|l| l.text.contains("cannot be read"))
        })
        .await;
        assert_eq!((generation(), rules()), (1, 2));

        // It recovers on the next good file.
        std::fs::write(&path, linked_toml(port, &[("*.only.example", "direct")])).unwrap();
        wait_until("the recovered file to reload", || generation() == 2).await;
        assert_eq!(rules(), 1);

        // A listener change in the file only flags a restart.
        let moved = free_port().await;
        std::fs::write(&path, linked_toml(moved, &[("*.only.example", "direct")])).unwrap();
        wait_until("the listener change", || generation() == 3).await;
        assert!(manager.snapshot(id).unwrap().restart_required);

        // Unlinking (back to Managed) stops following the file.
        let mut managed = lock(&manager.slot(id).unwrap().proxy).clone();
        managed.source = SourceMode::Managed;
        manager.upsert_proxy(managed).await.unwrap();
        let after_unlink = generation();
        assert!(lock(&manager.slot(id).unwrap().watcher).is_none());
        std::fs::write(&path, linked_toml(moved, &[("*.a.example", "corp"), ("*.b.example", "corp")]))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(900)).await;
        assert_eq!(generation(), after_unlink);

        // Stopping a linked Proxy drops its watcher.
        let mut linked = lock(&manager.slot(id).unwrap().proxy).clone();
        linked.source = SourceMode::ExternalToml { path: path.clone(), debounce_ms: 250 };
        manager.upsert_proxy(linked).await.unwrap();
        assert!(lock(&manager.slot(id).unwrap().watcher).is_some());
        manager.stop(id).await.unwrap();
        assert!(lock(&manager.slot(id).unwrap().watcher).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
