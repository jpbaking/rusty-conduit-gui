//! [`TunnelManager`]: supervises v2 [`Tunnel`]s on behalf of Proxies and the UI.
//!
//! A Tunnel is the SSH half of a v1 session: its hops, reverse proxy (`-R`), and port
//! forwards (`-L` / `-R`), with no forward proxy listener. Proxies reach the target through
//! the Tunnel's dialer, which [`TunnelManager::dialer`] hands out once per Tunnel and which
//! stays the same `Arc` for the Tunnel's whole life. While the Tunnel is not `Connected`, that
//! dialer fails right away with [`DialError::NotConnected`], so an engine `FailoverDialer`
//! moves on to its next entry.
//!
//! The supervisor loop is the one [`crate::SessionManager`] uses, so the same lockout rules
//! hold: bad credentials, a changed host key, a locked vault, and an invalid Tunnel are never
//! retried automatically.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use conduit_core::{
    mitm_tls_warning, tunnel_forward_filter, tunnel_to_engine_config, validate_tunnel, EngineConfig,
    ForwardDirection, ForwardProxyProtocol, HostKeyLookup, HostKeyRecord, KnownHostsStore,
    PortForward, ProxyId, SessionProfile, SshEngine, Timestamp, Tunnel, TunnelId, TunnelStartMode,
};
use conduit_openssh::{
    check_openssh_binary, LogFn, OpenSshDialer, OpenSshSupervisor, SupervisorOptions, TunnelState,
};
use conduit_ssh::{
    connect_chain, reverse_policy, AtomicStats, ChainOptions, ChannelPolicy, DisconnectEvent,
    HostKeyVerifier, RemoteForward, ReverseError, ReverseInbound, ReverseRelay, RusshDialer,
    StatsDialer,
};
use conduit_vault::{Vault, VaultError};
use rusty_conduit_engine::filter::HostFilter;
use rusty_conduit_engine::logging::{AccessLogger, Logger, ProxyDirection};
use rusty_conduit_engine::mitm::MitmState;
use rusty_conduit_engine::routing::{
    OneOrMany, ProfileConfig, ProfileType, RoutingConfig, RoutingInput, RoutingSetupError,
    RoutingState, SharedRouting, DEFAULT_CONNECT_TIMEOUT,
};
use rusty_conduit_engine::server::{EngineHandlers, ProtocolHandlers, Server, ShutdownReport};
use rusty_conduit_engine::upstream::{
    DialError, DialFuture, DialerOptions, RouteBlocked, UpstreamDialer,
};
use serde::Serialize;
use thiserror::Error;
use tokio::sync::{broadcast, mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::backoff::Backoff;
use crate::events::{EventBus, RuntimeEvent};
use crate::forward_dialer::TunnelForwardDialer;
use crate::logs::LogRingBuffer;
use crate::manager::ManagerConfig;
use crate::port_forward::{self, LocalForwards, SharedForwards};
use crate::reverse::{ReverseForward, ReverseProxy};
use crate::runner::{
    access_log_config, classify, classify_openssh, classify_reverse, describe, halt_state,
    needs_secrets, probe_store, remote_listener_info, resolve_hops, supervise, supervisor_hops,
    BoxFut, Control, Link, LinkError, SharedListeners, SharedVault, LIVENESS_POLL,
    REVERSE_CHANNEL_CAPACITY, SOCKS_PORT_ATTEMPTS,
};
use crate::state::{
    ForwardStatus, ListenerInfo, SessionState, SessionStatsSnapshot, StateCell,
};

/// Local reverse-proxy listener addresses of one Tunnel.
type SharedAddrs = Arc<Mutex<Vec<SocketAddr>>>;

// Guarded values are replaced whole, so a poisoned lock still holds valid data.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A request the Tunnel manager could not carry out.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TunnelError {
    #[error("unknown tunnel {0}")]
    UnknownTunnel(TunnelId),
    #[error("tunnel {0} is not waiting for a host-key decision")]
    NoPendingHostKey(TunnelId),
    #[error("fingerprint does not match the key awaiting approval")]
    FingerprintMismatch,
    #[error("a different host key is already pinned for {hop_id}; it will not be overwritten")]
    PinConflict { hop_id: String },
    /// The saved Tunnel cannot run as it stands.
    #[error("tunnel cannot start: {0}")]
    InvalidTunnel(String),
}

/// Something about a Tunnel the UI or a Proxy may want to react to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum TunnelEvent {
    /// A Tunnel moved to a new state.
    StateChanged {
        tunnel_id: TunnelId,
        state: SessionState,
    },
    /// A host-key pin was approved. The owner of `known_hosts.json` should save it.
    KnownHostsChanged {
        tunnel_id: TunnelId,
        hop_id: String,
        host: String,
        port: u16,
    },
}

impl TunnelEvent {
    fn from_runtime(event: RuntimeEvent) -> Self {
        match event {
            RuntimeEvent::StateChanged { session_id, state } => Self::StateChanged {
                tunnel_id: TunnelId::from_uuid(session_id),
                state,
            },
            RuntimeEvent::KnownHostsChanged {
                session_id,
                hop_id,
                host,
                port,
            } => Self::KnownHostsChanged {
                tunnel_id: TunnelId::from_uuid(session_id),
                hop_id,
                host,
                port,
            },
        }
    }
}

/// Receives [`TunnelEvent`]s in the order they happened.
#[derive(Debug)]
pub struct TunnelEventReceiver {
    inner: broadcast::Receiver<RuntimeEvent>,
}

impl TunnelEventReceiver {
    pub async fn recv(&mut self) -> Result<TunnelEvent, broadcast::error::RecvError> {
        self.inner.recv().await.map(TunnelEvent::from_runtime)
    }

    pub fn try_recv(&mut self) -> Result<TunnelEvent, broadcast::error::TryRecvError> {
        self.inner.try_recv().map(TunnelEvent::from_runtime)
    }
}

/// A point-in-time view of one Tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TunnelSnapshot {
    pub id: TunnelId,
    pub name: String,
    pub enabled: bool,
    pub start_mode: TunnelStartMode,
    pub engine: SshEngine,
    pub state: SessionState,
    pub stats: SessionStatsSnapshot,
    /// Bound forward proxy listeners when `tunnel.forward.enabled`, empty otherwise.
    pub listeners: Vec<ListenerInfo>,
    /// Reverse proxy (`-R`) listeners bound on the target host, while connected.
    pub remote_listeners: Vec<ListenerInfo>,
    /// Loopback listeners of the reverse proxy on this computer.
    pub reverse_listeners: Vec<SocketAddr>,
    /// Port forwards: local ones once bound, remote ones while connected.
    pub port_forwards: Vec<ForwardStatus>,
    /// How many Proxies currently hold a Linked reference.
    pub linked_holders: usize,
}

/// The dialer half that changes: the live engine dialer while a link exists, gated on the
/// Tunnel being `Connected`.
pub(crate) struct SwitchableDialer {
    name: String,
    cell: Arc<StateCell>,
    inner: RwLock<Option<Arc<dyn UpstreamDialer>>>,
}

impl SwitchableDialer {
    fn new(name: String, cell: Arc<StateCell>) -> Self {
        Self {
            name,
            cell,
            inner: RwLock::new(None),
        }
    }

    /// Installs (or, with `None`, removes) the engine dialer.
    pub(crate) fn set(&self, dialer: Option<Arc<dyn UpstreamDialer>>) {
        *self.inner.write().unwrap_or_else(PoisonError::into_inner) = dialer;
    }

    fn current(&self) -> Option<Arc<dyn UpstreamDialer>> {
        if self.cell.get() != SessionState::Connected {
            return None;
        }
        self.inner
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// The error a down Tunnel's dialer returns.
fn not_connected(name: &str) -> io::Error {
    DialError::NotConnected {
        kind: io::ErrorKind::NotConnected,
        message: format!("tunnel `{name}` is not connected"),
    }
    .into_io()
}

impl UpstreamDialer for SwitchableDialer {
    fn connect(&self, host: &str, port: u16, timeout: Duration) -> DialFuture<'_> {
        let current = self.current();
        let host = host.to_string();
        Box::pin(async move {
            match current {
                Some(dialer) => dialer.connect(&host, port, timeout).await,
                None => Err(not_connected(&self.name)),
            }
        })
    }

    fn redacted_upstream(&self) -> String {
        format!("tunnel:{}", self.name)
    }
}

/// Wraps a Tunnel's counted [`SwitchableDialer`] with a live [`HostFilter`] (compiled from
/// `tunnel.forward.allow` / `tunnel.forward.block`), enforcing the tunnel's filter on Proxy
/// traffic even when `tunnel.forward.enabled == false`.
pub(crate) struct FilteredTunnelDialer {
    inner: Arc<dyn UpstreamDialer>,
    filter: Arc<RwLock<Option<HostFilter>>>,
}

impl FilteredTunnelDialer {
    pub(crate) fn new(
        inner: Arc<dyn UpstreamDialer>,
        filter: Arc<RwLock<Option<HostFilter>>>,
    ) -> Self {
        Self { inner, filter }
    }
}

impl UpstreamDialer for FilteredTunnelDialer {
    fn connect(&self, host: &str, port: u16, timeout: Duration) -> DialFuture<'_> {
        let host = host.to_string();
        Box::pin(async move {
            let denied = {
                let guard = self.filter.read().unwrap_or_else(PoisonError::into_inner);
                guard.as_ref().and_then(|f| f.check_host(&host).err())
            };
            if let Some(denied) = denied {
                return Err(RouteBlocked {
                    profile: format!("{} ({denied})", self.inner.redacted_upstream()),
                }
                .into_io());
            }
            self.inner.connect(&host, port, timeout).await
        })
    }

    fn redacted_upstream(&self) -> String {
        self.inner.redacted_upstream()
    }
}

fn compile_tunnel_filter(tunnel: &Tunnel) -> Option<HostFilter> {
    tunnel_forward_filter(tunnel).ok().flatten()
}

/// Everything one Tunnel run needs from the manager.
#[derive(Clone)]
pub(crate) struct TunnelContext {
    pub(crate) tunnel: Tunnel,
    pub(crate) vault: SharedVault,
    pub(crate) known_hosts: Arc<RwLock<KnownHostsStore>>,
    pub(crate) logs: LogRingBuffer,
    /// Where the link installs its engine dialer.
    pub(crate) gate: Arc<SwitchableDialer>,
    /// The persistent, counted raw dialer; port forwards and the optional forward listener dial it.
    pub(crate) dialer: Arc<dyn UpstreamDialer>,
    pub(crate) listeners: SharedListeners,
    pub(crate) remote_listeners: SharedListeners,
    pub(crate) reverse_listeners: SharedAddrs,
    pub(crate) forwards: SharedForwards,
}

/// Builds a [`Link`] for a Tunnel.
pub(crate) trait TunnelEngine: Send + Sync {
    fn prepare(&self, ctx: TunnelContext) -> BoxFut<'static, Result<Box<dyn Link>, LinkError>>;
}

/// The production engine. Routes each Tunnel to the SSH engine it selects.
#[derive(Debug, Default)]
pub(crate) struct DefaultTunnelEngine;

impl TunnelEngine for DefaultTunnelEngine {
    fn prepare(&self, ctx: TunnelContext) -> BoxFut<'static, Result<Box<dyn Link>, LinkError>> {
        Box::pin(async move {
            match ctx.tunnel.engine {
                SshEngine::OpenSsh => {
                    let link = OpenSshTunnelLink::prepare(ctx).await?;
                    Ok(Box::new(link) as Box<dyn Link>)
                }
                SshEngine::Russh => {
                    let link = RusshTunnelLink::prepare(ctx).await?;
                    Ok(Box::new(link) as Box<dyn Link>)
                }
            }
        })
    }
}

/// The hop-only view of a Tunnel the shared `runner` helpers read.
fn hop_profile(tunnel: &Tunnel) -> SessionProfile {
    SessionProfile {
        hops: tunnel.hops.clone(),
        ..Default::default()
    }
}

/// Runs one Tunnel until it stops or halts, then records its final state.
async fn run_tunnel(
    engine: Arc<dyn TunnelEngine>,
    ctx: TunnelContext,
    cell: Arc<StateCell>,
    mut control: mpsc::UnboundedReceiver<Control>,
    cancel: CancellationToken,
) {
    let logs = ctx.logs.clone();
    let gate = Arc::clone(&ctx.gate);
    let listeners = Arc::clone(&ctx.listeners);
    let remote_listeners = Arc::clone(&ctx.remote_listeners);
    let reverse_listeners = Arc::clone(&ctx.reverse_listeners);
    let forwards = Arc::clone(&ctx.forwards);
    let keepalive = &ctx.tunnel.keepalive;
    let backoff = Backoff::new(keepalive.reconnect_initial_delay, keepalive.reconnect_max_delay);
    let no_reconnect = keepalive.no_reconnect;

    let prepared = tokio::select! {
        biased;
        () = cancel.cancelled() => {
            cell.set(SessionState::Stopped);
            return;
        }
        prepared = engine.prepare(ctx) => prepared,
    };
    let final_state = match prepared {
        Ok(mut link) => {
            let state = supervise(
                link.as_mut(),
                &cell,
                &mut control,
                &cancel,
                backoff,
                no_reconnect,
                &logs,
            )
            .await;
            link.shutdown().await;
            state
        }
        Err(error) => halt_state(error),
    };
    gate.set(None);
    lock(&listeners).clear();
    lock(&remote_listeners).clear();
    lock(&reverse_listeners).clear();
    lock(&forwards).clear();
    logs.push(&format!("tunnel ended: {}", describe(&final_state)));
    cell.set(final_state);
}

const TUNNEL_PROFILE: &str = "tunnel";

fn tunnel_forward_routing(
    cfg: &EngineConfig,
    dialer: Arc<dyn UpstreamDialer>,
) -> Result<RoutingState, RoutingSetupError> {
    let profiles = BTreeMap::from([(
        TUNNEL_PROFILE.to_string(),
        ProfileConfig::of_kind(ProfileType::External),
    )]);
    let input = RoutingInput {
        profiles,
        routing: RoutingConfig {
            default: OneOrMany::One(TUNNEL_PROFILE.to_string()),
            ..RoutingConfig::default()
        },
        filter: cfg.forward_filter.clone(),
        mitm_enabled: cfg.mitm_enabled,
        listeners: Vec::new(),
        keepalive: cfg.keepalive,
        connect_timeout: DEFAULT_CONNECT_TIMEOUT,
    };
    RoutingState::from_input(
        &input,
        DialerOptions::default().with_external(TUNNEL_PROFILE, dialer),
    )
}

struct RunningServer {
    token: CancellationToken,
    run: JoinHandle<ShutdownReport>,
    reaper: Option<JoinHandle<()>>,
}

/// The proxy and forwarding side of a Tunnel shared by both SSH engines: logging, optional
/// forward proxy + MITM, reverse proxy, and port forwards.
struct TunnelStack {
    cfg: EngineConfig,
    logger: Logger,
    access: AccessLogger,
    reverse: Option<ReverseProxy>,
    routing: SharedRouting,
    mitm: Option<MitmState>,
    server: Option<RunningServer>,
    listeners: SharedListeners,
    dialer: Arc<dyn UpstreamDialer>,
    local_forwards: Option<LocalForwards>,
    forward_states: SharedForwards,
    port_forwards: Vec<PortForward>,
    reverse_listeners: SharedAddrs,
}

impl TunnelStack {
    /// Checks the vault, loads optional MITM CA, then starts access logging and the reverse proxy.
    async fn start(ctx: &TunnelContext) -> Result<Self, LinkError> {
        let needs_mitm = ctx.tunnel.forward.enabled && ctx.tunnel.mitm.is_some();
        let ca_pem: Option<Zeroizing<Vec<u8>>> = {
            let vault = ctx.vault.read().unwrap_or_else(PoisonError::into_inner);
            if (needs_secrets(&hop_profile(&ctx.tunnel)) || needs_mitm) && !vault.is_unlocked() {
                return Err(LinkError::Locked);
            }
            if ctx.tunnel.forward.enabled {
                match ctx.tunnel.mitm.as_ref().and_then(|m| m.ca.as_ref()) {
                    Some(ca) => Some(vault.get_secret(&ca.to_string()).map_err(|e| match e {
                        VaultError::Locked => LinkError::Locked,
                        other => {
                            LinkError::Fatal(format!("cannot read MITM CA from vault: {other}"))
                        }
                    })?),
                    None => None,
                }
            } else {
                None
            }
        };

        let cfg =
            tunnel_to_engine_config(&ctx.tunnel).map_err(|e| LinkError::Fatal(e.to_string()))?;
        let logger = Logger::with_writer(cfg.log_level, Box::new(ctx.logs.writer()));
        let access = AccessLogger::start_with_stdout(
            access_log_config(&cfg),
            Box::new(ctx.logs.writer()),
            logger.clone(),
        )
        .await
        .map_err(|e| LinkError::Fatal(format!("failed to open access log: {e}")))?;

        let routing = match tunnel_forward_routing(&cfg, Arc::clone(&ctx.dialer)) {
            Ok(state) => state.shared(),
            Err(e) => {
                drop(ca_pem);
                let _ = access.shutdown().await;
                logger.flush();
                return Err(LinkError::Fatal(format!("forward routing setup failed: {e}")));
            }
        };

        let mitm = if cfg.forward_enabled && cfg.mitm_enabled {
            match ca_pem.as_deref() {
                Some(pem) => match MitmState::from_pem_bytes(pem, pem, &cfg.mitm_options) {
                    Ok(state) => {
                        state.cache.set_logger(logger.clone());
                        if let Some(warning) = mitm_tls_warning(&cfg.mitm_options.upstream_tls) {
                            logger.error(warning);
                        }
                        Some(state)
                    }
                    Err(e) => {
                        drop(ca_pem);
                        let _ = access.shutdown().await;
                        logger.flush();
                        return Err(LinkError::Fatal(format!("MITM setup failed: {e}")));
                    }
                },
                None => None,
            }
        } else {
            None
        };
        drop(ca_pem);

        // Reverse proxy egresses directly without MITM.
        let reverse = match ReverseProxy::start(&cfg, None, &access, &logger).await {
            Ok(reverse) => reverse,
            Err(message) => {
                let _ = access.shutdown().await;
                logger.flush();
                return Err(LinkError::Fatal(message));
            }
        };
        *lock(&ctx.reverse_listeners) = reverse
            .as_ref()
            .map(ReverseProxy::local_listeners)
            .unwrap_or_default();

        Ok(Self {
            cfg,
            logger,
            access,
            reverse,
            routing,
            mitm,
            server: None,
            listeners: Arc::clone(&ctx.listeners),
            dialer: Arc::clone(&ctx.dialer),
            local_forwards: None,
            forward_states: Arc::clone(&ctx.forwards),
            port_forwards: ctx.tunnel.port_forwards.clone(),
            reverse_listeners: Arc::clone(&ctx.reverse_listeners),
        })
    }

    /// The switched-on remote port forwards.
    fn remote_forwards(&self) -> impl Iterator<Item = &PortForward> {
        self.port_forwards
            .iter()
            .filter(|f| f.enabled && f.direction == ForwardDirection::Remote)
    }

    /// Reports the remote forwards as listening on `bound`, or clears them when it is `None`.
    fn publish_remote(&self, bound: Option<&[(String, u32)]>) {
        let statuses = match bound {
            None => Vec::new(),
            Some(bound) => self
                .remote_forwards()
                .zip(bound)
                .map(|(forward, (address, port))| {
                    let mut status = port_forward::status(forward, None);
                    status.listen = SocketAddr::new(
                        address.parse().unwrap_or(forward.bind),
                        u16::try_from(*port).unwrap_or(forward.port),
                    );
                    status
                })
                .collect(),
        };
        port_forward::publish(&self.forward_states, ForwardDirection::Remote, statuses);
    }

    /// Reports the remote forward listening on `failed` as the reason a connect failed.
    fn publish_remote_failure(&self, failed: SocketAddr, message: &str) {
        let statuses = self
            .remote_forwards()
            .filter(|forward| forward.listen() == failed)
            .map(|forward| port_forward::status(forward, Some(message.to_string())))
            .collect();
        port_forward::publish(&self.forward_states, ForwardDirection::Remote, statuses);
    }

    /// Binds the local port forwards and optional forward proxy listeners once. They then stay
    /// bound across reconnects.
    async fn ensure_forwards(&mut self) -> Result<(), LinkError> {
        if self.local_forwards.is_none() {
            let local = self
                .port_forwards
                .iter()
                .filter(|f| f.enabled && f.direction == ForwardDirection::Local);
            self.local_forwards = Some(
                LocalForwards::bind(
                    local,
                    Arc::clone(&self.dialer),
                    &self.logger,
                    &self.forward_states,
                )
                .await,
            );
        }
        if self.server.is_some() || !self.cfg.forward_enabled {
            return Ok(());
        }
        let access = self.access.clone().with_direction(ProxyDirection::Forward);
        let mut handlers =
            EngineHandlers::from_routing(Arc::clone(&self.routing), access, self.logger.clone());
        if let Some(m) = &self.mitm {
            handlers = handlers.with_mitm(Arc::new(m.interceptor.clone()), false);
        }
        if self.cfg.socks_block_web_in_mitm {
            handlers = handlers.with_socks_block_web();
        }
        let handlers: Arc<dyn ProtocolHandlers> = Arc::new(handlers);
        let server = Server::from_options(&self.cfg.forward_server, handlers, self.logger.clone())
            .await
            .map_err(|e| LinkError::Fatal(e.to_string()))?;
        let bound: Vec<ListenerInfo> = server
            .listeners()
            .into_iter()
            .map(|(role, addr)| {
                self.logger.info(format!("{role} proxy listening on {addr}"));
                ListenerInfo {
                    role: role.to_string(),
                    addr,
                }
            })
            .collect();
        *lock(&self.listeners) = bound;
        let token = server.shutdown_token();
        let reaper = self
            .mitm
            .as_ref()
            .map(|m| m.cache.spawn_reaper(token.clone(), self.logger.clone()));
        let run = tokio::spawn(server.run());
        self.server = Some(RunningServer { token, run, reaper });
        Ok(())
    }

    /// First shutdown step: close the local port forwards and drain the optional forward proxy.
    async fn drain_forwards(&mut self) {
        if let Some(forwards) = self.local_forwards.take() {
            forwards.shutdown().await;
        }
        if let Some(server) = self.server.take() {
            server.token.cancel();
            if let Ok(report) = server.run.await {
                if report.drained {
                    self.logger.debug("all connections drained");
                }
            }
            if let Some(reaper) = server.reaper {
                let _ = reaper.await;
            }
        }
        lock(&self.listeners).clear();
    }

    /// Last shutdown steps, after SSH is down: drain the reverse proxy and flush the logs.
    async fn finish(mut self) {
        if let Some(reverse) = self.reverse.take() {
            if reverse.shutdown().await.drained {
                self.logger.debug("all reverse proxy connections drained");
            }
        }
        lock(&self.reverse_listeners).clear();
        self.logger.info("shutting down");
        if let Err(e) = self.access.shutdown().await {
            self.logger.error(format!("failed to flush access logs: {e}"));
        }
        self.logger.flush();
    }
}

/// The built-in engine: a `russh` chain, `tcpip-forward` for `-R`.
struct RusshTunnelLink {
    tunnel: Tunnel,
    hops_profile: SessionProfile,
    options: ChainOptions,
    verifier: HostKeyVerifier,
    vault: SharedVault,
    stack: TunnelStack,
    dialer: Arc<RusshDialer>,
    relay: Option<ReverseRelay>,
    remote_listeners: SharedListeners,
    disconnects: Option<mpsc::UnboundedReceiver<DisconnectEvent>>,
}

impl RusshTunnelLink {
    async fn prepare(ctx: TunnelContext) -> Result<Self, LinkError> {
        validate_tunnel(&ctx.tunnel).map_err(|e| LinkError::Fatal(e.to_string()))?;
        let options = ChainOptions::from_tunnel(&ctx.tunnel.keepalive)
            .map_err(|e| LinkError::Fatal(e.to_string()))?;
        let stack = TunnelStack::start(&ctx).await?;
        let dialer = Arc::new(RusshDialer::new());
        ctx.gate
            .set(Some(Arc::clone(&dialer) as Arc<dyn UpstreamDialer>));
        Ok(Self {
            hops_profile: hop_profile(&ctx.tunnel),
            tunnel: ctx.tunnel,
            options,
            verifier: HostKeyVerifier::from_shared(ctx.known_hosts),
            vault: ctx.vault,
            stack,
            dialer,
            relay: None,
            remote_listeners: ctx.remote_listeners,
            disconnects: None,
        })
    }

    async fn drop_connection(&mut self) {
        self.disconnects = None;
        let relay = self.relay.take();
        lock(&self.remote_listeners).clear();
        self.stack.publish_remote(None);
        if let Some(chain) = self.dialer.detach() {
            if let Some(relay) = relay {
                relay.stop(&chain).await;
            }
            // A dial still in flight holds the last reference and closes the chain when done.
            if let Ok(chain) = Arc::try_unwrap(chain) {
                chain.disconnect().await;
            }
        }
    }
}

impl Link for RusshTunnelLink {
    fn connect(&mut self) -> BoxFut<'_, Result<(), LinkError>> {
        Box::pin(async move {
            // The reverse proxy's listeners first, then the remote port forwards.
            let mut remote: Vec<RemoteForward> = self
                .stack
                .reverse
                .as_ref()
                .map(|reverse| {
                    reverse
                        .forwards()
                        .iter()
                        .map(ReverseForward::to_remote_forward)
                        .collect()
                })
                .unwrap_or_default();
            let proxy_forwards = remote.len();
            remote.extend(self.stack.remote_forwards().map(|forward| RemoteForward {
                remote: forward.listen(),
                host: forward.dest_host_unbracketed().to_string(),
                port: forward.dest_port,
            }));
            let (policy, inbound): (ChannelPolicy, Option<ReverseInbound>) = if remote.is_empty()
            {
                (ChannelPolicy::default(), None)
            } else {
                let (policy, inbound) = reverse_policy(REVERSE_CHANNEL_CAPACITY);
                (policy, Some(inbound))
            };
            let hops = {
                let vault = self.vault.read().unwrap_or_else(PoisonError::into_inner);
                if needs_secrets(&self.hops_profile) && !vault.is_unlocked() {
                    return Err(LinkError::Locked);
                }
                resolve_hops(&self.hops_profile, &vault, policy)?
            };

            let (events, receiver) = mpsc::unbounded_channel();
            let chain = connect_chain(&hops, &self.verifier, &self.options, Some(events))
                .await
                .map_err(classify)?;
            drop(hops);

            if let Some(inbound) = inbound {
                match ReverseRelay::start(&chain, &remote, inbound).await {
                    Ok(relay) => {
                        let (proxy_bound, forward_bound) = relay.bound().split_at(proxy_forwards);
                        if let Some(reverse) = &self.stack.reverse {
                            *lock(&self.remote_listeners) = remote_listener_info(
                                &self.tunnel.reverse,
                                reverse.forwards(),
                                proxy_bound,
                            );
                        }
                        self.stack.publish_remote(Some(forward_bound));
                        self.relay = Some(relay);
                    }
                    Err(error) => {
                        chain.disconnect().await;
                        if let ReverseError::Request { remote, .. } = &error {
                            self.stack.publish_remote_failure(*remote, &error.to_string());
                        }
                        return Err(classify_reverse(error));
                    }
                }
            }
            self.dialer.swap(chain);
            self.disconnects = Some(receiver);
            self.stack.ensure_forwards().await?;
            Ok(())
        })
    }

    fn lost(&mut self) -> BoxFut<'_, String> {
        Box::pin(async move {
            let dialer = Arc::clone(&self.dialer);
            let Some(receiver) = self.disconnects.as_mut() else {
                return "connection closed".to_string();
            };
            loop {
                tokio::select! {
                    event = receiver.recv() => {
                        return event.map_or_else(
                            || "connection closed".to_string(),
                            |e| format!("hop {} ({}): {}", e.hop_index, e.hop_id, e.detail),
                        );
                    }
                    () = sleep(LIVENESS_POLL) => {
                        if !dialer.is_connected() {
                            return "connection closed".to_string();
                        }
                    }
                }
            }
        })
    }

    fn disconnect(&mut self) -> BoxFut<'_, ()> {
        Box::pin(self.drop_connection())
    }

    fn shutdown(self: Box<Self>) -> BoxFut<'static, ()> {
        Box::pin(async move {
            let mut this = *self;
            this.stack.drain_forwards().await;
            this.drop_connection().await;
            this.stack.finish().await;
        })
    }
}

/// The opt-in engine: a supervised `ssh -N -D` process.
struct OpenSshTunnelLink {
    tunnel: Tunnel,
    hops_profile: SessionProfile,
    options: ChainOptions,
    known_hosts: Arc<RwLock<KnownHostsStore>>,
    vault: SharedVault,
    stack: TunnelStack,
    logs: LogRingBuffer,
    /// Feeds the engine dialer, and outlives each `ssh` process.
    state: watch::Sender<TunnelState>,
    supervisor: Option<OpenSshSupervisor>,
    supervisor_state: Option<watch::Receiver<TunnelState>>,
}

impl OpenSshTunnelLink {
    async fn prepare(ctx: TunnelContext) -> Result<Self, LinkError> {
        validate_tunnel(&ctx.tunnel).map_err(|e| LinkError::Fatal(e.to_string()))?;
        let options = ChainOptions::from_tunnel(&ctx.tunnel.keepalive)
            .map_err(|e| LinkError::Fatal(e.to_string()))?;

        let ssh_bin = ctx.tunnel.openssh.ssh_bin.clone();
        let info = tokio::task::spawn_blocking(move || check_openssh_binary(&ssh_bin))
            .await
            .map_err(|e| LinkError::Fatal(format!("OpenSSH binary check failed: {e}")))?;
        if !info.supported {
            return Err(LinkError::Fatal(format!(
                "OpenSSH binary cannot be used: {}",
                info.message
            )));
        }

        let stack = TunnelStack::start(&ctx).await?;
        let (state, receiver) = watch::channel(TunnelState::Connecting);
        ctx.gate
            .set(Some(Arc::new(OpenSshDialer::new(receiver)) as Arc<dyn UpstreamDialer>));
        Ok(Self {
            hops_profile: hop_profile(&ctx.tunnel),
            tunnel: ctx.tunnel,
            options,
            known_hosts: ctx.known_hosts,
            vault: ctx.vault,
            stack,
            logs: ctx.logs,
            state,
            supervisor: None,
            supervisor_state: None,
        })
    }

    /// Surfaces the first hop that needs a host-key decision, before `ssh` is launched.
    async fn probe_host_keys(&self, scratch: KnownHostsStore) -> Result<(), LinkError> {
        let hops = {
            let vault = self.vault.read().unwrap_or_else(PoisonError::into_inner);
            resolve_hops(&self.hops_profile, &vault, ChannelPolicy::default())?
        };
        let verifier = HostKeyVerifier::new(scratch);
        let chain = connect_chain(&hops, &verifier, &self.options, None)
            .await
            .map_err(classify)
            .map_err(|error| match error {
                // Without the key text, approving could never produce a usable `known_hosts`.
                LinkError::HostKey(prompt) if prompt.public_key_openssh.is_none() => {
                    LinkError::Fatal(format!(
                        "the host key of hop {} cannot be used with the OpenSSH engine",
                        prompt.hop_id
                    ))
                }
                other => other,
            })?;
        chain.disconnect().await;
        Ok(())
    }

    /// The configured SOCKS port, or a free one that is not a local port forward's.
    fn socks_port(&self) -> Result<u16, LinkError> {
        let configured = self.tunnel.openssh.ssh_socks_port;
        if configured != 0 {
            return Ok(configured);
        }
        let failed = |detail: String| LinkError::Transient {
            reason: format!("no free local port for the SSH tunnel: {detail}"),
            network: false,
        };
        // Rejected listeners stay open until return, so the OS cannot offer them again.
        let mut rejected = Vec::new();
        for _ in 0..SOCKS_PORT_ATTEMPTS {
            let listener = std::net::TcpListener::bind((self.tunnel.openssh.ssh_socks_bind, 0))
                .map_err(|e| failed(e.to_string()))?;
            let port = listener
                .local_addr()
                .map_err(|e| failed(e.to_string()))?
                .port();
            let local_forward = self
                .tunnel
                .active_forwards_in(ForwardDirection::Local)
                .any(|f| f.port == port);
            if !local_forward {
                return Ok(port);
            }
            rejected.push(listener);
        }
        Err(failed("every port offered is a port-forward port".into()))
    }

    async fn stop_supervisor(&mut self, reason: &str) {
        self.stack.publish_remote(None);
        self.state
            .send_replace(TunnelState::Disconnected(reason.to_string()));
        self.supervisor_state = None;
        if let Some(supervisor) = self.supervisor.take() {
            // Terminates and reaps `ssh` before its runtime directory is removed.
            supervisor.shutdown().await;
        }
    }
}

impl Link for OpenSshTunnelLink {
    fn connect(&mut self) -> BoxFut<'_, Result<(), LinkError>> {
        Box::pin(async move {
            {
                let vault = self.vault.read().unwrap_or_else(PoisonError::into_inner);
                if needs_secrets(&self.hops_profile) && !vault.is_unlocked() {
                    return Err(LinkError::Locked);
                }
            }
            let scratch = {
                let store = self.known_hosts.read().unwrap_or_else(PoisonError::into_inner);
                probe_store(&store, &self.hops_profile)
            };
            if let Some(scratch) = scratch {
                self.probe_host_keys(scratch).await?;
            }

            let hops = {
                let vault = self.vault.read().unwrap_or_else(PoisonError::into_inner);
                supervisor_hops(&self.hops_profile, &vault, &self.logs)?
            };
            let known_hosts = self
                .known_hosts
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            let mut reverse_forwards: Vec<String> = self
                .stack
                .reverse
                .as_ref()
                .map(|reverse| reverse.forwards().iter().map(ReverseForward::spec).collect())
                .unwrap_or_default();
            // Validated: each part is an IP, a port, or a host name, so `ssh` reads it as is.
            reverse_forwards.extend(self.stack.remote_forwards().map(PortForward::spec));
            let sink = self.logs.clone();
            let log: LogFn = Arc::new(move |line: &str| sink.push(line));
            let keepalive = &self.tunnel.keepalive;
            let options = SupervisorOptions {
                ssh_bin: self.tunnel.openssh.ssh_bin.clone(),
                worker_bin: None,
                hops,
                known_hosts,
                bind: self.tunnel.openssh.ssh_socks_bind,
                socks_port: self.socks_port()?,
                reverse_forwards,
                extra_args: self.tunnel.openssh.extra_args.clone(),
                ip_version: keepalive.ip_version.clone(),
                server_alive_interval: keepalive.server_alive_interval,
                server_alive_count_max: keepalive.server_alive_count_max,
                startup_timeout: keepalive.startup_timeout,
                log: Some(log),
            };

            self.state.send_replace(TunnelState::Connecting);
            let supervisor = match OpenSshSupervisor::start(options).await {
                Ok(supervisor) => supervisor,
                Err(error) => {
                    self.state
                        .send_replace(TunnelState::Disconnected(error.to_string()));
                    return Err(classify_openssh(error));
                }
            };
            self.state
                .send_replace(TunnelState::Ready(supervisor.socks_addr()));
            self.supervisor_state = Some(supervisor.state());
            self.supervisor = Some(supervisor);
            // `ExitOnForwardFailure` makes `ssh` exit if the target refuses one, and that is
            // reported as a lost connection.
            let requested: Vec<(String, u32)> = self
                .stack
                .remote_forwards()
                .map(|f| (f.bind.to_string(), u32::from(f.port)))
                .collect();
            self.stack.publish_remote(Some(&requested));
            self.stack.ensure_forwards().await?;
            Ok(())
        })
    }

    fn lost(&mut self) -> BoxFut<'_, String> {
        Box::pin(async move {
            let Some(state) = self.supervisor_state.as_mut() else {
                return "connection closed".to_string();
            };
            let reason = loop {
                let current = state.borrow_and_update().clone();
                if let TunnelState::Disconnected(reason) = current {
                    break reason;
                }
                if state.changed().await.is_err() {
                    break "ssh supervisor stopped".to_string();
                }
            };
            // New dials fail right away instead of reaching a dead SOCKS port.
            self.state
                .send_replace(TunnelState::Disconnected(reason.clone()));
            reason
        })
    }

    fn disconnect(&mut self) -> BoxFut<'_, ()> {
        Box::pin(self.stop_supervisor("reconnecting"))
    }

    fn shutdown(self: Box<Self>) -> BoxFut<'static, ()> {
        Box::pin(async move {
            let mut this = *self;
            this.stack.drain_forwards().await;
            this.stop_supervisor("stopped").await;
            this.stack.finish().await;
        })
    }
}

struct Running {
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

struct TunnelSlot {
    tunnel: Arc<Mutex<Tunnel>>,
    logs: LogRingBuffer,
    stats: Arc<AtomicStats>,
    cell: Arc<StateCell>,
    gate: Arc<SwitchableDialer>,
    /// Live tunnel-level forward filter, refreshed on `upsert_tunnel` and `start`.
    filter: Arc<RwLock<Option<HostFilter>>>,
    /// Counted raw SSH dialer (no tunnel filter): used by `-L` port forwards, the tunnel's
    /// own forward listener (which has its own router filter), and `TunnelForwardDialer`.
    raw_dialer: Arc<dyn UpstreamDialer>,
    /// The persistent filtered handle given to Proxies: counted, filtered, gated on `Connected`.
    dialer: Arc<dyn UpstreamDialer>,
    listeners: SharedListeners,
    remote_listeners: SharedListeners,
    reverse_listeners: SharedAddrs,
    forwards: SharedForwards,
    holders: Mutex<HashSet<ProxyId>>,
    control: Mutex<Option<mpsc::UnboundedSender<Control>>>,
    /// Serializes start and stop, so a Tunnel never has two supervisors.
    lifecycle: tokio::sync::Mutex<Option<Running>>,
}

impl TunnelSlot {
    fn send(&self, message: Control) {
        if let Some(sender) = lock(&self.control).as_ref() {
            let _ = sender.send(message);
        }
    }

    fn snapshot(&self) -> TunnelSnapshot {
        let tunnel = lock(&self.tunnel);
        TunnelSnapshot {
            id: tunnel.id,
            name: tunnel.name.clone(),
            enabled: tunnel.enabled,
            start_mode: tunnel.start_mode,
            engine: tunnel.engine,
            state: self.cell.get(),
            stats: SessionStatsSnapshot::from_stats(self.stats.snapshot(), self.cell.uptime_secs()),
            listeners: lock(&self.listeners).clone(),
            remote_listeners: lock(&self.remote_listeners).clone(),
            reverse_listeners: lock(&self.reverse_listeners).clone(),
            port_forwards: lock(&self.forwards).clone(),
            linked_holders: lock(&self.holders).len(),
        }
    }
}

struct Inner {
    vault: SharedVault,
    known_hosts: Arc<RwLock<KnownHostsStore>>,
    engine: Arc<dyn TunnelEngine>,
    config: ManagerConfig,
    /// Carries [`RuntimeEvent`]s keyed by the Tunnel's UUID; receivers map them to
    /// [`TunnelEvent`]s.
    events: EventBus,
    tunnels: Mutex<HashMap<TunnelId, Arc<TunnelSlot>>>,
    wake_generation: AtomicU64,
}

/// Supervises every Tunnel. Cloning yields another handle to the same manager.
#[derive(Clone)]
pub struct TunnelManager {
    inner: Arc<Inner>,
}

impl TunnelManager {
    pub fn new(
        vault: Arc<RwLock<Vault>>,
        known_hosts: Arc<RwLock<KnownHostsStore>>,
        config: ManagerConfig,
    ) -> Self {
        Self::with_engine(vault, known_hosts, config, Arc::new(DefaultTunnelEngine))
    }

    pub(crate) fn with_engine(
        vault: SharedVault,
        known_hosts: Arc<RwLock<KnownHostsStore>>,
        config: ManagerConfig,
        engine: Arc<dyn TunnelEngine>,
    ) -> Self {
        let events = EventBus::new(config.event_capacity);
        Self {
            inner: Arc::new(Inner {
                vault,
                known_hosts,
                engine,
                config,
                events,
                tunnels: Mutex::new(HashMap::new()),
                wake_generation: AtomicU64::new(0),
            }),
        }
    }

    /// Adds a Tunnel, or updates it. A running Tunnel uses the update on its next start; its
    /// dialer handle stays the same and its forward filter refreshes immediately.
    pub fn upsert_tunnel(&self, tunnel: Tunnel) {
        let mut tunnels = lock(&self.inner.tunnels);
        match tunnels.get(&tunnel.id) {
            Some(slot) => {
                let compiled = compile_tunnel_filter(&tunnel);
                *lock(&slot.tunnel) = tunnel;
                *slot.filter.write().unwrap_or_else(PoisonError::into_inner) = compiled;
            }
            None => {
                let id = tunnel.id;
                let compiled = compile_tunnel_filter(&tunnel);
                let cell = Arc::new(StateCell::new(id.as_uuid(), self.inner.events.clone()));
                let gate = Arc::new(SwitchableDialer::new(tunnel.name.clone(), Arc::clone(&cell)));
                let stats = Arc::new(AtomicStats::default());
                let filter = Arc::new(RwLock::new(compiled));
                let raw_dialer: Arc<dyn UpstreamDialer> = Arc::new(StatsDialer::new(
                    Arc::clone(&gate) as Arc<dyn UpstreamDialer>,
                    Arc::clone(&stats),
                ));
                let dialer: Arc<dyn UpstreamDialer> = Arc::new(FilteredTunnelDialer::new(
                    Arc::clone(&raw_dialer),
                    Arc::clone(&filter),
                ));
                let slot = TunnelSlot {
                    tunnel: Arc::new(Mutex::new(tunnel)),
                    logs: LogRingBuffer::new(self.inner.config.log_capacity),
                    stats,
                    cell,
                    gate,
                    filter,
                    raw_dialer,
                    dialer,
                    listeners: Arc::default(),
                    remote_listeners: Arc::default(),
                    reverse_listeners: Arc::default(),
                    forwards: Arc::default(),
                    holders: Mutex::new(HashSet::new()),
                    control: Mutex::new(None),
                    lifecycle: tokio::sync::Mutex::new(None),
                };
                tunnels.insert(id, Arc::new(slot));
            }
        }
    }

    /// Stops a Tunnel and forgets it. Its dialer handle then fails every dial.
    pub async fn remove_tunnel(&self, id: TunnelId) -> Result<(), TunnelError> {
        self.stop(id).await?;
        lock(&self.inner.tunnels).remove(&id);
        Ok(())
    }

    fn slot(&self, id: TunnelId) -> Result<Arc<TunnelSlot>, TunnelError> {
        lock(&self.inner.tunnels)
            .get(&id)
            .cloned()
            .ok_or(TunnelError::UnknownTunnel(id))
    }

    fn slots(&self) -> Vec<Arc<TunnelSlot>> {
        lock(&self.inner.tunnels).values().cloned().collect()
    }

    /// The Tunnel's persistent filtered dialer. It enforces the tunnel's forward `HostFilter`
    /// and fails with [`DialError::NotConnected`] (kind [`io::ErrorKind::NotConnected`]) unless
    /// the Tunnel is `Connected`.
    pub fn dialer(&self, id: TunnelId) -> Option<Arc<dyn UpstreamDialer>> {
        lock(&self.inner.tunnels)
            .get(&id)
            .map(|slot| Arc::clone(&slot.dialer))
    }

    /// An in-process proxy dialer for a tagged local (`-L`) [`PortForward`] on Tunnel `tid`.
    /// Returns `None` if the tunnel or forward does not exist, or if the forward is not a local
    /// forward with `proxy_protocol` set to `Http` or `Socks5`.
    pub fn forward_dialer(&self, tid: TunnelId, fid: Uuid) -> Option<Arc<dyn UpstreamDialer>> {
        let slot = lock(&self.inner.tunnels).get(&tid).cloned()?;
        let valid = {
            let tunnel = lock(&slot.tunnel);
            tunnel.port_forwards.iter().any(|f| {
                f.id == fid
                    && f.direction == ForwardDirection::Local
                    && f.proxy_protocol != ForwardProxyProtocol::None
            })
        };
        if !valid {
            return None;
        }
        Some(Arc::new(TunnelForwardDialer::new(
            Arc::clone(&slot.tunnel),
            fid,
            Arc::clone(&slot.filter),
            Arc::clone(&slot.raw_dialer),
        )))
    }

    /// Starts a Tunnel. Does nothing if it is already running.
    pub async fn start(&self, id: TunnelId) -> Result<(), TunnelError> {
        let slot = self.slot(id)?;
        let mut lifecycle = slot.lifecycle.lock().await;
        if lifecycle.as_ref().is_some_and(|r| !r.task.is_finished()) {
            return Ok(());
        }
        // A finished task has already published its final state.
        if let Some(previous) = lifecycle.take() {
            let _ = previous.task.await;
        }
        // Refused before anything starts, so the reason shows and nothing retries.
        let tunnel = lock(&slot.tunnel).clone();
        if let Err(error) = validate_tunnel(&tunnel) {
            let reason = error.to_string();
            *lock(&slot.control) = None;
            // A halted state is only left through `Starting`, as any failed start does.
            slot.cell.set(SessionState::Starting);
            slot.cell.set(SessionState::NeedsAttention {
                reason: reason.clone(),
            });
            return Err(TunnelError::InvalidTunnel(reason));
        }

        *slot.filter.write().unwrap_or_else(PoisonError::into_inner) =
            compile_tunnel_filter(&tunnel);

        let (sender, receiver) = mpsc::unbounded_channel();
        *lock(&slot.control) = Some(sender);
        slot.cell.set(SessionState::Starting);

        let ctx = TunnelContext {
            tunnel,
            vault: Arc::clone(&self.inner.vault),
            known_hosts: Arc::clone(&self.inner.known_hosts),
            logs: slot.logs.clone(),
            gate: Arc::clone(&slot.gate),
            dialer: Arc::clone(&slot.raw_dialer),
            listeners: Arc::clone(&slot.listeners),
            remote_listeners: Arc::clone(&slot.remote_listeners),
            reverse_listeners: Arc::clone(&slot.reverse_listeners),
            forwards: Arc::clone(&slot.forwards),
        };
        let cancel = CancellationToken::new();
        let run = tokio::spawn(run_tunnel(
            Arc::clone(&self.inner.engine),
            ctx,
            Arc::clone(&slot.cell),
            receiver,
            cancel.clone(),
        ));
        // A panic must not leave the UI showing a live Tunnel.
        let cell = Arc::clone(&slot.cell);
        let gate = Arc::clone(&slot.gate);
        let task = tokio::spawn(async move {
            if run.await.is_err() {
                gate.set(None);
                cell.set(SessionState::Failed {
                    reason: "tunnel task panicked".into(),
                });
            }
        });
        *lifecycle = Some(Running { cancel, task });
        Ok(())
    }

    /// Stops a Tunnel, waiting for its graceful shutdown.
    pub async fn stop(&self, id: TunnelId) -> Result<(), TunnelError> {
        let slot = self.slot(id)?;
        let mut lifecycle = slot.lifecycle.lock().await;
        if let Some(running) = lifecycle.take() {
            running.cancel.cancel();
            let _ = running.task.await;
        }
        *lock(&slot.control) = None;
        slot.gate.set(None);
        slot.cell.set(SessionState::Stopped);
        Ok(())
    }

    pub async fn restart(&self, id: TunnelId) -> Result<(), TunnelError> {
        self.stop(id).await?;
        self.start(id).await
    }

    /// Stops every Tunnel concurrently, so one slow drain does not delay the rest.
    pub async fn stop_all(&self) {
        let mut stops = JoinSet::new();
        for id in lock(&self.inner.tunnels).keys().copied().collect::<Vec<_>>() {
            let manager = self.clone();
            stops.spawn(async move {
                let _ = manager.stop(id).await;
            });
        }
        while stops.join_next().await.is_some() {}
    }

    /// Records that `holder` routes through the Tunnel. A `Linked`, enabled Tunnel starts.
    pub async fn acquire_linked(&self, id: TunnelId, holder: ProxyId) -> Result<(), TunnelError> {
        let slot = self.slot(id)?;
        lock(&slot.holders).insert(holder);
        let (linked, enabled) = {
            let tunnel = lock(&slot.tunnel);
            (tunnel.start_mode == TunnelStartMode::Linked, tunnel.enabled)
        };
        if linked && enabled {
            self.start(id).await?;
        }
        Ok(())
    }

    /// Drops `holder`'s reference. A `Linked` Tunnel with no holders left stops; a `Manual`
    /// one keeps running.
    pub async fn release_linked(&self, id: TunnelId, holder: ProxyId) -> Result<(), TunnelError> {
        let slot = self.slot(id)?;
        let empty = {
            let mut holders = lock(&slot.holders);
            holders.remove(&holder);
            holders.is_empty()
        };
        let linked = lock(&slot.tunnel).start_mode == TunnelStartMode::Linked;
        if linked && empty {
            self.stop(id).await?;
        }
        Ok(())
    }

    /// Pins the key awaiting approval and resumes the Tunnel.
    ///
    /// `sha256` must be the fingerprint the user saw, so a prompt that changed in the meantime
    /// cannot be approved by accident.
    pub fn approve_host_key(&self, id: TunnelId, sha256: &str) -> Result<(), TunnelError> {
        let slot = self.slot(id)?;
        let SessionState::AwaitingHostKey(prompt) = slot.cell.get() else {
            return Err(TunnelError::NoPendingHostKey(id));
        };
        if prompt.sha256 != sha256 {
            return Err(TunnelError::FingerprintMismatch);
        }
        {
            let mut store = self
                .inner
                .known_hosts
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            let existing = store.get(&prompt.hop_id, &prompt.host, prompt.port);
            if existing.is_some_and(|pin| pin.fingerprint_sha256 != prompt.sha256) {
                return Err(TunnelError::PinConflict {
                    hop_id: prompt.hop_id,
                });
            }
            let first_seen = existing.map_or_else(Timestamp::now, |pin| pin.first_seen);
            store.insert(
                HostKeyLookup {
                    hop_id: prompt.hop_id.clone(),
                    host: prompt.host.clone(),
                    port: prompt.port,
                },
                HostKeyRecord {
                    algorithm: prompt.algorithm.clone(),
                    fingerprint_sha256: prompt.sha256.clone(),
                    first_seen,
                    approved: true,
                    public_key_openssh: prompt.public_key_openssh.clone(),
                },
            );
        }
        self.inner.events.emit(RuntimeEvent::KnownHostsChanged {
            session_id: id.as_uuid(),
            hop_id: prompt.hop_id,
            host: prompt.host,
            port: prompt.port,
        });
        slot.send(Control::ApproveHostKey);
        Ok(())
    }

    /// Declines the key awaiting approval. The Tunnel halts in `NeedsAttention`.
    pub fn reject_host_key(&self, id: TunnelId) -> Result<(), TunnelError> {
        let slot = self.slot(id)?;
        if !matches!(slot.cell.get(), SessionState::AwaitingHostKey(_)) {
            return Err(TunnelError::NoPendingHostKey(id));
        }
        slot.send(Control::RejectHostKey);
        Ok(())
    }

    /// Reports a system wake. Bursts are merged, then live Tunnels are recycled once.
    ///
    /// Only `Connected` and `Reconnecting` Tunnels are touched. Must be called inside a Tokio
    /// runtime.
    pub fn on_system_wake(&self) {
        let generation = self.inner.wake_generation.fetch_add(1, Ordering::SeqCst) + 1;
        let manager = self.clone();
        tokio::spawn(async move {
            sleep(manager.inner.config.wake_debounce).await;
            if manager.inner.wake_generation.load(Ordering::SeqCst) != generation {
                return;
            }
            for slot in manager.slots() {
                if matches!(
                    slot.cell.get(),
                    SessionState::Connected | SessionState::Reconnecting { .. }
                ) {
                    slot.send(Control::Recycle);
                }
            }
        });
    }

    /// Every bound local reverse-proxy listener, across all Tunnels. A Proxy must never route
    /// to one of these, or traffic would loop back through the target.
    pub fn reverse_listeners(&self) -> Vec<SocketAddr> {
        let mut addrs: Vec<SocketAddr> = self
            .slots()
            .iter()
            .flat_map(|slot| lock(&slot.reverse_listeners).clone())
            .collect();
        addrs.sort();
        addrs
    }

    /// Every bound local forward-proxy listener, across all Tunnels.
    pub fn forward_listeners(&self) -> Vec<SocketAddr> {
        let mut addrs: Vec<SocketAddr> = self
            .slots()
            .iter()
            .flat_map(|slot| {
                lock(&slot.listeners)
                    .iter()
                    .map(|l| l.addr)
                    .collect::<Vec<_>>()
            })
            .collect();
        addrs.sort();
        addrs
    }

    /// Full saved [`Tunnel`] definitions currently registered with the manager, sorted by name.
    pub fn tunnels(&self) -> Vec<Tunnel> {
        let mut list: Vec<Tunnel> = self
            .slots()
            .iter()
            .map(|slot| lock(&slot.tunnel).clone())
            .collect();
        list.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.as_uuid().cmp(&b.id.as_uuid())));
        list
    }

    /// A view of every Tunnel, sorted by name.
    pub fn snapshots(&self) -> Vec<TunnelSnapshot> {
        let mut snapshots: Vec<TunnelSnapshot> =
            self.slots().iter().map(|s| s.snapshot()).collect();
        snapshots.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then(a.id.as_uuid().cmp(&b.id.as_uuid()))
        });
        snapshots
    }

    pub fn snapshot(&self, id: TunnelId) -> Result<TunnelSnapshot, TunnelError> {
        Ok(self.slot(id)?.snapshot())
    }

    /// The log buffer for a Tunnel, for querying, clearing, or subscribing.
    pub fn logs(&self, id: TunnelId) -> Result<LogRingBuffer, TunnelError> {
        Ok(self.slot(id)?.logs.clone())
    }

    pub fn subscribe_events(&self) -> TunnelEventReceiver {
        TunnelEventReceiver {
            inner: self.inner.events.subscribe(),
        }
    }
}

#[cfg(test)]
#[allow(dead_code)]
#[path = "../../conduit-ssh/tests/common/mod.rs"]
mod ssh_common;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::testing::{transient, until, Script, ScriptLink};
    use conduit_core::{AuthMethod, HopEntry, HostProfile, ReverseConfig, SecretRef, TunnelConfig};
    use conduit_vault::Argon2Params;
    use rusty_conduit_engine::upstream::{dial_error, UpstreamStream};
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use uuid::Uuid;

    use super::ssh_common::{spawn_echo, spawn_node, Node, PASSWORD};

    const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
    const STATE_TIMEOUT: Duration = Duration::from_secs(20);

    fn temp_vault() -> Vault {
        let path = std::env::temp_dir()
            .join(format!("conduit-runtime-tunnel-test-{}", Uuid::new_v4()))
            .join("vault.bin");
        let params = Argon2Params {
            memory_kib: 8 * 1024,
            time_cost: 1,
            parallelism: 1,
            derived_key_len: 32,
        };
        Vault::create_with_password(path, b"pw", params).unwrap()
    }

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    async fn free_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    }

    fn assert_not_connected(result: io::Result<UpstreamStream>) {
        let Err(error) = result else {
            panic!("a down tunnel must refuse dials");
        };
        assert_eq!(error.kind(), io::ErrorKind::NotConnected, "{error}");
        assert!(
            matches!(dial_error(&error), DialError::NotConnected { kind: io::ErrorKind::NotConnected, .. }),
            "{error:?}"
        );
    }

    async fn roundtrip<S: AsyncReadExt + AsyncWriteExt + Unpin>(mut stream: S, data: &[u8]) -> Vec<u8> {
        stream.write_all(data).await.unwrap();
        let mut back = vec![0; data.len()];
        stream.read_exact(&mut back).await.unwrap();
        back
    }

    // ---------------------------------------------------------------- scripted engine

    #[derive(Default)]
    struct ScriptEngine {
        scripts: Mutex<HashMap<TunnelId, Arc<Script>>>,
    }

    impl TunnelEngine for ScriptEngine {
        fn prepare(&self, ctx: TunnelContext) -> BoxFut<'static, Result<Box<dyn Link>, LinkError>> {
            let script = Arc::clone(&lock(&self.scripts)[&ctx.tunnel.id]);
            Box::pin(async move { Ok(Box::new(ScriptLink(script)) as Box<dyn Link>) })
        }
    }

    fn scripted_hop() -> HopEntry {
        HopEntry {
            hop_id: "hop".into(),
            name: "hop".into(),
            host: HostProfile {
                host: "127.0.0.1".into(),
                port: 22,
                user: "u".into(),
                ..Default::default()
            },
        }
    }

    fn tunnel(name: &str, start_mode: TunnelStartMode, hops: Vec<HopEntry>) -> Tunnel {
        Tunnel {
            id: TunnelId::new(),
            name: name.into(),
            start_mode,
            hops,
            keepalive: TunnelConfig {
                reconnect_initial_delay: Duration::from_secs(1),
                reconnect_max_delay: Duration::from_secs(2),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn scripted() -> (TunnelManager, Arc<ScriptEngine>) {
        let engine = Arc::new(ScriptEngine::default());
        let manager = TunnelManager::with_engine(
            Arc::new(RwLock::new(temp_vault())),
            Arc::new(RwLock::new(KnownHostsStore::default())),
            ManagerConfig {
                wake_debounce: Duration::from_secs(2),
                ..ManagerConfig::default()
            },
            Arc::clone(&engine) as Arc<dyn TunnelEngine>,
        );
        (manager, engine)
    }

    fn add(
        manager: &TunnelManager,
        engine: &ScriptEngine,
        tunnel: Tunnel,
        outcomes: Vec<Result<(), LinkError>>,
    ) -> (TunnelId, Arc<Script>) {
        let id = tunnel.id;
        let script = Script::new(outcomes);
        lock(&engine.scripts).insert(id, Arc::clone(&script));
        manager.upsert_tunnel(tunnel);
        (id, script)
    }

    fn state(manager: &TunnelManager, id: TunnelId) -> SessionState {
        manager.snapshot(id).unwrap().state
    }

    #[tokio::test(start_paused = true)]
    async fn dialer_is_persistent_and_refuses_while_not_connected() {
        let (manager, engine) = scripted();
        let (id, _script) = add(
            &manager,
            &engine,
            tunnel("t", TunnelStartMode::default(), vec![scripted_hop()]),
            vec![transient(), Ok(())],
        );
        let dialer = manager.dialer(id).unwrap();
        assert!(Arc::ptr_eq(&dialer, &manager.dialer(id).unwrap()), "one handle per tunnel");
        assert!(manager.dialer(TunnelId::new()).is_none());
        assert_not_connected(dialer.connect("example.test", 80, DIAL_TIMEOUT).await);

        manager.start(id).await.unwrap();
        until(|| matches!(state(&manager, id), SessionState::Reconnecting { .. })).await;
        assert_not_connected(dialer.connect("example.test", 80, DIAL_TIMEOUT).await);

        until(|| state(&manager, id) == SessionState::Connected).await;
        manager.stop(id).await.unwrap();
        assert_not_connected(dialer.connect("example.test", 80, DIAL_TIMEOUT).await);
        assert!(Arc::ptr_eq(&dialer, &manager.dialer(id).unwrap()), "same handle after stop");
    }

    #[tokio::test(start_paused = true)]
    async fn linked_acquire_and_release_start_and_stop_the_tunnel() {
        let (manager, engine) = scripted();
        let (id, script) = add(
            &manager,
            &engine,
            tunnel("linked", TunnelStartMode::Linked, vec![scripted_hop()]),
            vec![Ok(())],
        );
        let (a, b) = (ProxyId::new(), ProxyId::new());
        manager.acquire_linked(id, a).await.unwrap();
        until(|| state(&manager, id) == SessionState::Connected).await;
        manager.acquire_linked(id, b).await.unwrap();
        assert_eq!(manager.snapshot(id).unwrap().linked_holders, 2);
        assert_eq!(script.connects(), 1, "a second holder reuses the running tunnel");

        manager.release_linked(id, a).await.unwrap();
        assert_eq!(state(&manager, id), SessionState::Connected, "one holder is left");
        manager.release_linked(id, b).await.unwrap();
        assert_eq!(state(&manager, id), SessionState::Stopped);
        assert_eq!(script.shutdowns.load(Ordering::SeqCst), 1, "shut down cleanly once");
        assert_eq!(manager.snapshot(id).unwrap().linked_holders, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn disabled_linked_tunnel_is_not_started_by_a_holder() {
        let (manager, engine) = scripted();
        let mut off = tunnel("off", TunnelStartMode::Linked, vec![scripted_hop()]);
        off.enabled = false;
        let (id, script) = add(&manager, &engine, off, vec![Ok(())]);
        manager.acquire_linked(id, ProxyId::new()).await.unwrap();
        sleep(Duration::from_secs(5)).await;
        assert_eq!(state(&manager, id), SessionState::Stopped);
        assert_eq!(script.connects(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn manual_tunnel_is_not_started_or_stopped_by_holders() {
        let (manager, engine) = scripted();
        let (id, script) = add(
            &manager,
            &engine,
            tunnel("manual", TunnelStartMode::Manual { autostart: false }, vec![scripted_hop()]),
            vec![Ok(())],
        );
        let holder = ProxyId::new();
        manager.acquire_linked(id, holder).await.unwrap();
        sleep(Duration::from_secs(1)).await;
        assert_eq!(state(&manager, id), SessionState::Stopped, "manual waits for the user");

        manager.start(id).await.unwrap();
        until(|| state(&manager, id) == SessionState::Connected).await;
        manager.release_linked(id, holder).await.unwrap();
        sleep(Duration::from_secs(1)).await;
        assert_eq!(state(&manager, id), SessionState::Connected);
        assert_eq!(script.shutdowns.load(Ordering::SeqCst), 0);
        manager.stop_all().await;
        assert_eq!(state(&manager, id), SessionState::Stopped);
    }

    #[tokio::test(start_paused = true)]
    async fn system_wake_recycles_connected_tunnels_once() {
        let (manager, engine) = scripted();
        let (id, script) = add(
            &manager,
            &engine,
            tunnel("wake", TunnelStartMode::default(), vec![scripted_hop()]),
            vec![Ok(()), Ok(())],
        );
        manager.start(id).await.unwrap();
        until(|| state(&manager, id) == SessionState::Connected).await;
        manager.on_system_wake();
        manager.on_system_wake();
        until(|| script.connects() == 2).await;
        until(|| state(&manager, id) == SessionState::Connected).await;
        sleep(Duration::from_secs(5)).await;
        assert_eq!(script.connects(), 2, "a burst of wakes recycles once");
        assert_eq!(script.disconnects.load(Ordering::SeqCst), 1);
        manager.stop(id).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn invalid_tunnel_is_refused_before_start() {
        let (manager, engine) = scripted();
        let (id, script) = add(&manager, &engine, tunnel("empty", TunnelStartMode::default(), Vec::new()), vec![]);
        assert!(matches!(manager.start(id).await, Err(TunnelError::InvalidTunnel(_))));
        assert!(matches!(state(&manager, id), SessionState::NeedsAttention { .. }));
        assert_eq!(script.connects(), 0);
        let missing = TunnelId::new();
        assert_eq!(manager.start(missing).await, Err(TunnelError::UnknownTunnel(missing)));
    }

    #[test]
    fn tunnel_event_serializes_with_tunnel_id() {
        let id = TunnelId::new();
        let event = TunnelEvent::from_runtime(RuntimeEvent::StateChanged {
            session_id: id.as_uuid(),
            state: SessionState::Connected,
        });
        assert_eq!(event, TunnelEvent::StateChanged { tunnel_id: id, state: SessionState::Connected });
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["event"], "state_changed");
        assert_eq!(json["tunnel_id"], id.as_uuid().to_string());
    }

    // ---------------------------------------------------------------- loopback SSH

    struct Loopback {
        vault: SharedVault,
        known_hosts: Arc<RwLock<KnownHostsStore>>,
        manager: TunnelManager,
    }

    impl Loopback {
        fn new() -> Self {
            let vault = Arc::new(RwLock::new(temp_vault()));
            let known_hosts = Arc::new(RwLock::new(KnownHostsStore::default()));
            let manager = TunnelManager::new(
                Arc::clone(&vault),
                Arc::clone(&known_hosts),
                ManagerConfig::default(),
            );
            Self { vault, known_hosts, manager }
        }

        fn password(&self, value: &str) -> AuthMethod {
            let id = self.vault.write().unwrap().put_secret("password", value.as_bytes()).unwrap();
            let secret: SecretRef = serde_json::from_value(serde_json::Value::String(id)).unwrap();
            AuthMethod::Password { secret }
        }

        fn pin(&self, node: &Node) {
            use russh::keys::HashAlg;
            self.known_hosts.write().unwrap().insert(
                HostKeyLookup { hop_id: "hop-0".into(), host: "127.0.0.1".into(), port: node.port },
                HostKeyRecord {
                    algorithm: node.host_key.algorithm().as_str().to_string(),
                    fingerprint_sha256: node.host_key.fingerprint(HashAlg::Sha256).to_string(),
                    public_key_openssh: None,
                    first_seen: Timestamp(1),
                    approved: true,
                },
            );
        }

        fn tunnel(&self, node: &Node, password: &str) -> Tunnel {
            let hop = HopEntry {
                hop_id: "hop-0".into(),
                name: "hop-0".into(),
                host: HostProfile {
                    host: "127.0.0.1".into(),
                    port: node.port,
                    user: "tester".into(),
                    auth: vec![self.password(password)],
                    ..Default::default()
                },
            };
            tunnel("loopback", TunnelStartMode::Manual { autostart: false }, vec![hop])
        }

        fn state(&self, id: TunnelId) -> SessionState {
            self.manager.snapshot(id).unwrap().state
        }

        fn log_text(&self, id: TunnelId) -> String {
            self.manager
                .logs(id)
                .unwrap()
                .query(None)
                .into_iter()
                .map(|line| line.text)
                .collect::<Vec<_>>()
                .join("\n")
        }

        async fn until(&self, id: TunnelId, what: &str, check: impl Fn(&SessionState) -> bool) {
            let deadline = tokio::time::Instant::now() + STATE_TIMEOUT;
            loop {
                let state = self.state(id);
                if check(&state) {
                    return;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "timed out waiting for {what}; state {state:?}; logs:\n{}",
                    self.log_text(id)
                );
                sleep(Duration::from_millis(10)).await;
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn loopback_dialer_refuses_while_stopped_and_carries_traffic_when_connected() {
        let f = Loopback::new();
        let node = spawn_node(None).await;
        f.pin(&node);
        let echo = spawn_echo().await;
        let t = f.tunnel(&node, PASSWORD);
        let id = t.id;
        f.manager.upsert_tunnel(t);
        let dialer = f.manager.dialer(id).unwrap();
        assert_not_connected(dialer.connect("127.0.0.1", echo, DIAL_TIMEOUT).await);

        f.manager.start(id).await.unwrap();
        f.until(id, "Connected", |s| *s == SessionState::Connected).await;
        let stream = dialer.connect("127.0.0.1", echo, DIAL_TIMEOUT).await.unwrap();
        assert_eq!(roundtrip(stream, b"through the tunnel").await, b"through the tunnel");
        let stats = f.manager.snapshot(id).unwrap().stats;
        assert!(stats.total_connections >= 1, "{stats:?}");

        f.manager.stop(id).await.unwrap();
        assert_eq!(f.state(id), SessionState::Stopped);
        assert_not_connected(dialer.connect("127.0.0.1", echo, DIAL_TIMEOUT).await);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn loopback_host_key_approval_pins_and_connects() {
        use russh::keys::HashAlg;
        let f = Loopback::new();
        let node = spawn_node(None).await;
        let t = f.tunnel(&node, PASSWORD);
        let id = t.id;
        f.manager.upsert_tunnel(t);
        let mut events = f.manager.subscribe_events();

        f.manager.start(id).await.unwrap();
        f.until(id, "AwaitingHostKey", |s| matches!(s, SessionState::AwaitingHostKey(_))).await;
        let SessionState::AwaitingHostKey(prompt) = f.state(id) else { unreachable!() };
        let expected = node.host_key.fingerprint(HashAlg::Sha256).to_string();
        assert_eq!(prompt.sha256, expected);
        assert_eq!(node.state.password_attempts.load(Ordering::SeqCst), 0, "no credentials before trust");
        let dialer = f.manager.dialer(id).unwrap();
        assert_not_connected(dialer.connect("127.0.0.1", 9, DIAL_TIMEOUT).await);
        assert_eq!(f.manager.approve_host_key(id, "SHA256:nope"), Err(TunnelError::FingerprintMismatch));

        f.manager.approve_host_key(id, &prompt.sha256).unwrap();
        f.until(id, "Connected", |s| *s == SessionState::Connected).await;
        let pin = f.known_hosts.read().unwrap().get("hop-0", "127.0.0.1", node.port).cloned().unwrap();
        assert!(pin.approved);
        assert_eq!(pin.fingerprint_sha256, expected);

        let mut saw_pin = false;
        while let Ok(event) = events.try_recv() {
            if let TunnelEvent::KnownHostsChanged { tunnel_id, port, .. } = event {
                assert_eq!(tunnel_id, id);
                assert_eq!(port, node.port);
                saw_pin = true;
            }
        }
        assert!(saw_pin, "approval is announced");
        assert_eq!(f.manager.reject_host_key(id), Err(TunnelError::NoPendingHostKey(id)));
        f.manager.stop_all().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn loopback_auth_failure_halts_without_retry() {
        let f = Loopback::new();
        let node = spawn_node(None).await;
        f.pin(&node);
        let t = f.tunnel(&node, "wrong password");
        let id = t.id;
        f.manager.upsert_tunnel(t);

        f.manager.start(id).await.unwrap();
        f.until(id, "NeedsAttention", |s| matches!(s, SessionState::NeedsAttention { .. })).await;
        // Longer than the reconnect delay, so a wrongly scheduled retry would be seen.
        sleep(Duration::from_secs(3)).await;
        assert!(matches!(f.state(id), SessionState::NeedsAttention { .. }));
        assert_eq!(node.state.password_attempts.load(Ordering::SeqCst), 1, "never retried");
        assert!(!f.log_text(id).contains("wrong password"), "secret leaked to logs");
        f.manager.stop_all().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn loopback_reverse_proxy_and_port_forwards_run_and_report_listeners() {
        let f = Loopback::new();
        let node = spawn_node(None).await;
        f.pin(&node);
        let echo = spawn_echo().await;
        let (local_port, remote_port, reverse_port) = (free_port().await, free_port().await, free_port().await);
        let mut t = f.tunnel(&node, PASSWORD);
        t.reverse = ReverseConfig {
            enabled: true,
            reverse_bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            reverse_http_port: reverse_port,
            reverse_socks_port: reverse_port,
            ..ReverseConfig::default()
        };
        let local = PortForward {
            id: Uuid::new_v4(),
            direction: ForwardDirection::Local,
            port: local_port,
            dest_host: "127.0.0.1".into(),
            dest_port: echo,
            ..Default::default()
        };
        let remote = PortForward {
            id: Uuid::new_v4(),
            direction: ForwardDirection::Remote,
            port: remote_port,
            dest_host: "127.0.0.1".into(),
            dest_port: echo,
            ..Default::default()
        };
        t.port_forwards = vec![local.clone(), remote.clone()];
        let id = t.id;
        f.manager.upsert_tunnel(t);
        assert!(f.manager.reverse_listeners().is_empty());

        f.manager.start(id).await.unwrap();
        f.until(id, "Connected", |s| *s == SessionState::Connected).await;

        let snapshot = f.manager.snapshot(id).unwrap();
        assert_eq!(snapshot.reverse_listeners.len(), 1, "{snapshot:?}");
        assert!(snapshot.reverse_listeners[0].ip().is_loopback());
        assert_eq!(f.manager.reverse_listeners(), snapshot.reverse_listeners);
        assert_eq!(snapshot.remote_listeners.len(), 1, "{snapshot:?}");
        assert_eq!(snapshot.remote_listeners[0].addr.port(), reverse_port);
        assert_eq!(snapshot.port_forwards.len(), 2, "{:?}", snapshot.port_forwards);
        assert!(snapshot.port_forwards.iter().all(|s| s.error.is_none()));

        let through_local = TcpStream::connect(loopback(local_port)).await.unwrap();
        assert_eq!(roundtrip(through_local, b"-L").await, b"-L");
        let through_remote = TcpStream::connect(loopback(remote_port)).await.unwrap();
        assert_eq!(roundtrip(through_remote, b"-R").await, b"-R");
        // The reverse listener on the target is served by this machine's reverse proxy.
        assert!(TcpStream::connect(loopback(reverse_port)).await.is_ok());

        f.manager.stop(id).await.unwrap();
        let snapshot = f.manager.snapshot(id).unwrap();
        assert!(snapshot.reverse_listeners.is_empty());
        assert!(snapshot.remote_listeners.is_empty());
        assert!(snapshot.port_forwards.is_empty());
        assert!(f.manager.reverse_listeners().is_empty());
        assert!(TcpStream::connect(loopback(local_port)).await.is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn filtered_tunnel_dialer_blocks_denied_hosts_and_refreshes_on_upsert() {
        use rusty_conduit_engine::upstream::is_route_blocked;

        let f = Loopback::new();
        let node = spawn_node(None).await;
        f.pin(&node);
        let echo = spawn_echo().await;

        let mut t = f.tunnel(&node, PASSWORD);
        t.forward.enabled = false;
        t.forward.block = vec!["127.0.0.1".into()];
        let id = t.id;
        f.manager.upsert_tunnel(t.clone());
        let dialer = f.manager.dialer(id).unwrap();

        f.manager.start(id).await.unwrap();
        f.until(id, "Connected", |s| *s == SessionState::Connected).await;

        // Filter is enforced even while tunnel.forward.enabled == false.
        let err = dialer.connect("127.0.0.1", echo, DIAL_TIMEOUT).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(is_route_blocked(&err), "expected RouteBlocked, got {err}");

        // Refreshing the filter via upsert_tunnel takes effect immediately on the live dialer.
        t.forward.block.clear();
        f.manager.upsert_tunnel(t);
        let stream = dialer.connect("127.0.0.1", echo, DIAL_TIMEOUT).await.unwrap();
        assert_eq!(roundtrip(stream, b"allowed-now").await, b"allowed-now");

        f.manager.stop(id).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tunnel_forward_dialer_http_connect_and_filter() {
        use rusty_conduit_engine::upstream::is_route_blocked;

        // Local mock HTTP CONNECT proxy that echoes after 200 OK and sends an initial prefix byte.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock_port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut b = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if sock.read_exact(&mut b).await.is_err() {
                            return;
                        }
                        head.push(b[0]);
                    }
                    let req = String::from_utf8_lossy(&head);
                    if !req.starts_with("CONNECT app.internal:8080 HTTP/1.1\r\n") {
                        let _ = sock.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                        return;
                    }
                    // Write 200 OK plus immediate trailing bytes to exercise `with_prefix`.
                    let _ = sock
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\nHELLO:")
                        .await;
                    let (mut r, mut w) = sock.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });

        let f = Loopback::new();
        let node = spawn_node(None).await;
        f.pin(&node);

        let http_fid = Uuid::new_v4();
        let plain_fid = Uuid::new_v4();
        let mut t = f.tunnel(&node, PASSWORD);
        t.forward.block = vec!["blocked.internal".into()];
        t.port_forwards = vec![
            PortForward {
                id: http_fid,
                name: "corp-http".into(),
                direction: ForwardDirection::Local,
                port: free_port().await,
                dest_host: "127.0.0.1".into(),
                dest_port: mock_port,
                proxy_protocol: ForwardProxyProtocol::Http,
                ..Default::default()
            },
            PortForward {
                id: plain_fid,
                name: "plain-tcp".into(),
                direction: ForwardDirection::Local,
                port: free_port().await,
                dest_host: "127.0.0.1".into(),
                dest_port: mock_port,
                proxy_protocol: ForwardProxyProtocol::None,
                ..Default::default()
            },
        ];
        let id = t.id;
        f.manager.upsert_tunnel(t);

        // Untagged forward is rejected; tagged HTTP forward succeeds.
        assert!(f.manager.forward_dialer(id, plain_fid).is_none());
        assert!(f.manager.forward_dialer(id, Uuid::new_v4()).is_none());
        let fwd_dialer = f.manager.forward_dialer(id, http_fid).unwrap();
        assert_eq!(fwd_dialer.redacted_upstream(), "tunnel:loopback › corp-http (http)");

        f.manager.start(id).await.unwrap();
        f.until(id, "Connected", |s| *s == SessionState::Connected).await;

        // Tunnel filter blocks denied host before dialing.
        let denied = fwd_dialer
            .connect("blocked.internal", 8080, DIAL_TIMEOUT)
            .await
            .unwrap_err();
        assert!(is_route_blocked(&denied), "expected RouteBlocked, got {denied}");

        // Allowed host completes in-process HTTP CONNECT and replays trailing prefix bytes.
        let mut stream = fwd_dialer
            .connect("app.internal", 8080, DIAL_TIMEOUT)
            .await
            .unwrap();
        let mut prefix = [0u8; 6];
        stream.read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix, b"HELLO:");
        assert_eq!(roundtrip(stream, b"http-fwd-ok").await, b"http-fwd-ok");

        f.manager.stop(id).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tunnel_forward_dialer_socks5_and_filter() {
        use rusty_conduit_engine::upstream::is_route_blocked;

        // Local mock SOCKS5 proxy accepting no-auth + domain CONNECT and echoing payload.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock_port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut greet = [0u8; 3];
                    if sock.read_exact(&mut greet).await.is_err() || greet != [0x05, 0x01, 0x00] {
                        return;
                    }
                    if sock.write_all(&[0x05, 0x00]).await.is_err() {
                        return;
                    }
                    let mut req_head = [0u8; 4];
                    if sock.read_exact(&mut req_head).await.is_err()
                        || req_head[0] != 0x05
                        || req_head[1] != 0x01
                        || req_head[3] != 0x03
                    {
                        return;
                    }
                    let mut len = [0u8; 1];
                    if sock.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut rest = vec![0u8; usize::from(len[0]) + 2];
                    if sock.read_exact(&mut rest).await.is_err() {
                        return;
                    }
                    let domain = &rest[..usize::from(len[0])];
                    let port = u16::from_be_bytes([rest[rest.len() - 2], rest[rest.len() - 1]]);
                    if domain != b"db.internal" || port != 5432 {
                        let _ = sock.write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                        return;
                    }
                    // Success reply with IPv4 BND.ADDR 0.0.0.0:0.
                    let _ = sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                    let (mut r, mut w) = sock.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });

        let f = Loopback::new();
        let node = spawn_node(None).await;
        f.pin(&node);

        let socks_fid = Uuid::new_v4();
        let mut t = f.tunnel(&node, PASSWORD);
        t.forward.allow = vec!["db.internal".into()];
        t.port_forwards = vec![PortForward {
            id: socks_fid,
            name: "corp-socks".into(),
            direction: ForwardDirection::Local,
            port: free_port().await,
            dest_host: "127.0.0.1".into(),
            dest_port: mock_port,
            proxy_protocol: ForwardProxyProtocol::Socks5,
            ..Default::default()
        }];
        let id = t.id;
        f.manager.upsert_tunnel(t);

        let fwd_dialer = f.manager.forward_dialer(id, socks_fid).unwrap();
        assert_eq!(fwd_dialer.redacted_upstream(), "tunnel:loopback › corp-socks (socks5)");

        f.manager.start(id).await.unwrap();
        f.until(id, "Connected", |s| *s == SessionState::Connected).await;

        // Allowlist blocks non-matching host.
        let denied = fwd_dialer
            .connect("other.internal", 5432, DIAL_TIMEOUT)
            .await
            .unwrap_err();
        assert!(is_route_blocked(&denied), "expected RouteBlocked, got {denied}");

        // Allowed host completes in-process SOCKS5 handshake.
        let stream = fwd_dialer
            .connect("db.internal", 5432, DIAL_TIMEOUT)
            .await
            .unwrap();
        assert_eq!(roundtrip(stream, b"socks5-fwd-ok").await, b"socks5-fwd-ok");

        f.manager.stop(id).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn loopback_tunnel_forward_listener_enabled_and_disabled() {
        let f = Loopback::new();
        let node = spawn_node(None).await;
        f.pin(&node);
        let echo = spawn_echo().await;
        let http_port = free_port().await;

        // (1) forward.enabled = true: listeners populated and traffic flows through.
        let mut enabled_t = f.tunnel(&node, PASSWORD);
        enabled_t.forward.enabled = true;
        enabled_t.forward.bind = IpAddr::V4(Ipv4Addr::LOCALHOST);
        enabled_t.forward.http_port = http_port;
        enabled_t.forward.socks_port = 0;
        enabled_t.forward.block = vec!["blocked.example".into()];
        let enabled_id = enabled_t.id;
        f.manager.upsert_tunnel(enabled_t);

        f.manager.start(enabled_id).await.unwrap();
        f.until(enabled_id, "Connected", |s| *s == SessionState::Connected).await;

        let snap = f.manager.snapshot(enabled_id).unwrap();
        assert_eq!(snap.listeners.len(), 1, "{snap:?}");
        assert_eq!(snap.listeners[0].addr, loopback(http_port));
        assert_eq!(f.manager.forward_listeners(), vec![loopback(http_port)]);
        assert_eq!(f.manager.tunnels().len(), 1);

        // HTTP CONNECT through the tunnel's forward listener reaches the echo server.
        let mut sock = TcpStream::connect(loopback(http_port)).await.unwrap();
        let req = format!("CONNECT 127.0.0.1:{echo} HTTP/1.1\r\nHost: 127.0.0.1:{echo}\r\n\r\n");
        sock.write_all(req.as_bytes()).await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            sock.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        assert!(
            String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"),
            "unexpected CONNECT response: {}",
            String::from_utf8_lossy(&head)
        );
        assert_eq!(roundtrip(sock, b"via-tunnel-forward").await, b"via-tunnel-forward");

        // Blocked host is rejected with 403 by the tunnel's forward filter.
        let mut blocked = TcpStream::connect(loopback(http_port)).await.unwrap();
        blocked
            .write_all(b"CONNECT blocked.example:443 HTTP/1.1\r\nHost: blocked.example:443\r\n\r\n")
            .await
            .unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            blocked.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        assert!(
            String::from_utf8_lossy(&head).starts_with("HTTP/1.1 403"),
            "expected 403 for blocked host, got: {}",
            String::from_utf8_lossy(&head)
        );

        f.manager.stop(enabled_id).await.unwrap();
        assert!(f.manager.snapshot(enabled_id).unwrap().listeners.is_empty());
        assert!(f.manager.forward_listeners().is_empty());

        // (2) forward.enabled = false: listeners stay empty.
        let mut disabled_t = f.tunnel(&node, PASSWORD);
        disabled_t.forward.enabled = false;
        disabled_t.forward.http_port = http_port;
        let disabled_id = disabled_t.id;
        f.manager.upsert_tunnel(disabled_t);

        f.manager.start(disabled_id).await.unwrap();
        f.until(disabled_id, "Connected", |s| *s == SessionState::Connected).await;
        assert!(f.manager.snapshot(disabled_id).unwrap().listeners.is_empty());
        assert!(f.manager.forward_listeners().is_empty());

        f.manager.stop(disabled_id).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn loopback_tunnel_forward_mitm_requires_unlocked_vault() {
        use conduit_core::{MitmCaId, MitmConfig};

        let f = Loopback::new();
        let mut t = tunnel(
            "mitm-tunnel",
            TunnelStartMode::Manual { autostart: false },
            vec![scripted_hop()],
        );
        t.forward.enabled = true;
        t.forward.http_port = free_port().await;
        t.forward.socks_port = 0;
        t.mitm = Some(MitmConfig {
            ca: Some(MitmCaId::new()),
            ..MitmConfig::default()
        });
        let id = t.id;
        f.manager.upsert_tunnel(t);
        f.vault.write().unwrap().lock();

        f.manager.start(id).await.unwrap();
        f.until(id, "Locked", |s| *s == SessionState::Locked).await;
        f.manager.stop(id).await.unwrap();
    }
}
