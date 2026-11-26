//! Drives one session end to end.
//!
//! Startup: access log → reverse proxy → SSH chain → `tcpip-forward` → forward server.
//! Shutdown: drain forward server → tear down SSH → drain reverse proxy → flush access log.
//!
//! Secrets are read from the vault on every connect attempt and are not kept between attempts,
//! so locking the vault also stops future reconnects.

use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use conduit_core::{
    to_engine_config, validate, AuthMethod, EngineConfig, ForwardDirection, HostKeyLookup, KnownHostsStore,
    PortForward, SessionProfile, SshEngine,
};
use conduit_openssh::{
    check_openssh_binary, render_known_hosts, LogFn, OpenSshDialer, OpenSshError,
    OpenSshSupervisor, SupervisorHop, SupervisorOptions, TunnelState,
};
use conduit_ssh::{
    connect_chain, reverse_policy, AtomicStats, ChainOptions, ChannelPolicy, DisconnectEvent,
    HopAuth, HopSpec, HostKeyVerifier, RemoteForward, ReverseError, ReverseInbound, ReverseRelay,
    RusshDialer, ScopedAgent, SignAudit, SignAuditFn, SshError, StatsDialer,
};
use conduit_vault::{import_key, Vault, VaultError};
use rusty_conduit_engine::logging::{AccessLogConfig, AccessLogger, Logger, ProxyDirection};
use rusty_conduit_engine::mitm::MitmState;
use rusty_conduit_engine::routing::{
    OneOrMany, ProfileConfig, ProfileType, RoutingConfig, RoutingInput, RoutingSetupError,
    RoutingState, SharedRouting, DEFAULT_CONNECT_TIMEOUT,
};
use rusty_conduit_engine::server::{EngineHandlers, ProtocolHandlers, Server, ShutdownReport};
use rusty_conduit_engine::upstream::{DialerOptions, UpstreamDialer};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{sleep, Instant};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::backoff::Backoff;
use crate::logs::LogRingBuffer;
use crate::port_forward::{self, LocalForwards, SharedForwards};
use crate::reverse::{ReverseForward, ReverseProxy};
use crate::state::{HostKeyPrompt, ListenerInfo, SessionState, StateCell};

/// Queued inbound reverse channels per connection.
pub(crate) const REVERSE_CHANNEL_CAPACITY: usize = 64;
/// Backstop for noticing a dead chain if no disconnect event arrives.
pub(crate) const LIVENESS_POLL: Duration = Duration::from_secs(1);
/// A session has two forward ports, so a third pick is always different.
pub(crate) const SOCKS_PORT_ATTEMPTS: usize = 3;
/// The API-only `external` engine profile that carries all forward traffic through the SSH
/// tunnel. Never shown in logs (routing fields are disabled).
const TUNNEL_PROFILE: &str = "ssh-tunnel";

pub(crate) type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
pub(crate) type SharedVault = Arc<RwLock<Vault>>;
pub(crate) type SharedListeners = Arc<Mutex<Vec<ListenerInfo>>>;

/// Why a connect attempt or session setup failed, classified by what must happen next.
#[derive(Debug)]
pub(crate) enum LinkError {
    /// The vault must be unlocked first.
    Locked,
    /// An unknown host key needs a user decision.
    HostKey(HostKeyPrompt),
    /// Retrying could lock an account or bypass trust. Halt until the user acts.
    Attention(String),
    /// Retrying cannot help.
    Fatal(String),
    /// Safe to retry with backoff.
    Transient { reason: String, network: bool },
}

/// Messages from the manager to a running session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Control {
    ApproveHostKey,
    RejectHostKey,
    /// Replace the connection now (used after system wake).
    Recycle,
}

/// The connection a supervisor manages.
pub(crate) trait Link: Send {
    fn connect(&mut self) -> BoxFut<'_, Result<(), LinkError>>;
    /// Resolves with a reason once the current connection is gone.
    fn lost(&mut self) -> BoxFut<'_, String>;
    /// Drops the current connection. Listeners stay bound.
    fn disconnect(&mut self) -> BoxFut<'_, ()>;
    /// Stops everything in the graceful shutdown order.
    fn shutdown(self: Box<Self>) -> BoxFut<'static, ()>;
}

/// Builds a [`Link`] for a session.
pub(crate) trait Engine: Send + Sync {
    fn prepare(&self, ctx: SessionContext) -> BoxFut<'static, Result<Box<dyn Link>, LinkError>>;
}

/// Everything a session needs from the manager.
#[derive(Clone)]
pub(crate) struct SessionContext {
    pub(crate) profile: SessionProfile,
    pub(crate) vault: SharedVault,
    pub(crate) known_hosts: Arc<RwLock<KnownHostsStore>>,
    pub(crate) logs: LogRingBuffer,
    pub(crate) stats: Arc<AtomicStats>,
    pub(crate) listeners: SharedListeners,
    /// Reverse listeners on the target host. Set while connected, cleared on disconnect.
    pub(crate) remote_listeners: SharedListeners,
    /// Port forward states: local ones once bound, remote ones while connected.
    pub(crate) forwards: SharedForwards,
}

/// Runs one session until it stops or halts, then records its final state.
pub(crate) async fn run_session(
    engine: Arc<dyn Engine>,
    ctx: SessionContext,
    cell: Arc<StateCell>,
    mut control: mpsc::UnboundedReceiver<Control>,
    cancel: CancellationToken,
) {
    let logs = ctx.logs.clone();
    let listeners = Arc::clone(&ctx.listeners);
    let remote_listeners = Arc::clone(&ctx.remote_listeners);
    let forwards = Arc::clone(&ctx.forwards);
    let backoff = Backoff::new(
        ctx.profile.tunnel.reconnect_initial_delay,
        ctx.profile.tunnel.reconnect_max_delay,
    );
    let no_reconnect = ctx.profile.tunnel.no_reconnect;

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
    for shared in [&listeners, &remote_listeners] {
        shared.lock().unwrap_or_else(PoisonError::into_inner).clear();
    }
    forwards.lock().unwrap_or_else(PoisonError::into_inner).clear();
    logs.push(&format!("session ended: {}", describe(&final_state)));
    cell.set(final_state);
}

pub(crate) fn halt_state(error: LinkError) -> SessionState {
    match error {
        LinkError::Locked => SessionState::Locked,
        LinkError::Attention(reason) => SessionState::NeedsAttention { reason },
        LinkError::HostKey(prompt) => SessionState::NeedsAttention {
            reason: format!("unexpected host key prompt for {}", prompt.hop_id),
        },
        LinkError::Fatal(reason) | LinkError::Transient { reason, .. } => {
            SessionState::Failed { reason }
        }
    }
}

pub(crate) fn describe(state: &SessionState) -> String {
    match state {
        SessionState::NeedsAttention { reason } => format!("needs attention: {reason}"),
        SessionState::Failed { reason } => format!("failed: {reason}"),
        SessionState::Locked => "vault is locked".into(),
        _ => "stopped".into(),
    }
}

enum ConnectionEnd {
    Lost(String),
    Recycle,
    Stop,
}

/// The reconnect loop. Returns the terminal state; the caller performs the shutdown.
pub(crate) async fn supervise(
    link: &mut dyn Link,
    cell: &StateCell,
    control: &mut mpsc::UnboundedReceiver<Control>,
    cancel: &CancellationToken,
    mut backoff: Backoff,
    no_reconnect: bool,
    logs: &LogRingBuffer,
) -> SessionState {
    loop {
        let attempt = tokio::select! {
            biased;
            () = cancel.cancelled() => return SessionState::Stopped,
            attempt = link.connect() => attempt,
        };
        match attempt {
            Ok(()) => {
                drain(control);
                cell.set(SessionState::Connected);
                logs.push("connected");
                let since = Instant::now();
                let end = wait_for_end(link, control, cancel).await;
                if matches!(end, ConnectionEnd::Stop) {
                    return SessionState::Stopped;
                }
                link.disconnect().await;
                backoff.on_disconnected(since.elapsed());
                match end {
                    ConnectionEnd::Lost(reason) => {
                        logs.push(&format!("connection lost: {reason}"));
                        if no_reconnect {
                            return SessionState::Failed {
                                reason: format!("connection lost: {reason}"),
                            };
                        }
                        let network = false;
                        if let Some(stop) =
                            wait_to_retry(&mut backoff, network, cell, control, cancel).await
                        {
                            return stop;
                        }
                    }
                    ConnectionEnd::Recycle => {
                        logs.push("recycling connection after system wake");
                        cell.set(SessionState::Reconnecting {
                            attempt: backoff.attempt().max(1),
                            next_retry_secs: 0,
                        });
                    }
                    ConnectionEnd::Stop => unreachable!("returned above"),
                }
            }
            Err(LinkError::HostKey(prompt)) => {
                logs.push(&format!(
                    "unknown host key on {}:{}: {} {}",
                    prompt.host, prompt.port, prompt.algorithm, prompt.sha256
                ));
                drain(control);
                cell.set(SessionState::AwaitingHostKey(prompt));
                match wait_for_decision(control, cancel).await {
                    Decision::Approved => {
                        cell.set(SessionState::Starting);
                    }
                    Decision::Rejected => {
                        return SessionState::NeedsAttention {
                            reason: "host key rejected".into(),
                        };
                    }
                    Decision::Stop => return SessionState::Stopped,
                }
            }
            Err(LinkError::Transient { reason, network }) => {
                logs.push(&format!("connect failed: {reason}"));
                if no_reconnect {
                    return SessionState::Failed { reason };
                }
                if let Some(stop) =
                    wait_to_retry(&mut backoff, network, cell, control, cancel).await
                {
                    return stop;
                }
            }
            // Never retried: these could lock an account or bypass host-key trust.
            Err(error) => return halt_state(error),
        }
    }
}

/// Discards requests that were queued for a connection that no longer exists.
fn drain(control: &mut mpsc::UnboundedReceiver<Control>) {
    while control.try_recv().is_ok() {}
}

async fn wait_for_end(
    link: &mut dyn Link,
    control: &mut mpsc::UnboundedReceiver<Control>,
    cancel: &CancellationToken,
) -> ConnectionEnd {
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => return ConnectionEnd::Stop,
            message = control.recv() => match message {
                Some(Control::Recycle) => return ConnectionEnd::Recycle,
                Some(_) => {}
                None => return ConnectionEnd::Stop,
            },
            reason = link.lost() => return ConnectionEnd::Lost(reason),
        }
    }
}

enum Decision {
    Approved,
    Rejected,
    Stop,
}

async fn wait_for_decision(
    control: &mut mpsc::UnboundedReceiver<Control>,
    cancel: &CancellationToken,
) -> Decision {
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => return Decision::Stop,
            message = control.recv() => match message {
                Some(Control::ApproveHostKey) => return Decision::Approved,
                Some(Control::RejectHostKey) => return Decision::Rejected,
                Some(Control::Recycle) => {}
                None => return Decision::Stop,
            },
        }
    }
}

/// Publishes the retry state and waits. Returns a state only if the session must stop.
async fn wait_to_retry(
    backoff: &mut Backoff,
    network: bool,
    cell: &StateCell,
    control: &mut mpsc::UnboundedReceiver<Control>,
    cancel: &CancellationToken,
) -> Option<SessionState> {
    let delay = backoff.next_delay();
    cell.set(if network {
        SessionState::WaitingForNetwork
    } else {
        SessionState::Reconnecting {
            attempt: backoff.attempt(),
            next_retry_secs: delay.as_millis().div_ceil(1000) as u64,
        }
    });
    let timer = sleep(delay);
    tokio::pin!(timer);
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => return Some(SessionState::Stopped),
            message = control.recv() => match message {
                Some(Control::Recycle) => return None,
                Some(_) => {}
                None => return Some(SessionState::Stopped),
            },
            () = &mut timer => return None,
        }
    }
}

/// Maps an SSH failure to what the supervisor must do.
pub(crate) fn classify(error: SshError) -> LinkError {
    match error {
        SshError::HostKeyUnknown {
            hop_index,
            hop_id,
            host,
            port,
            algorithm,
            sha256,
            public_key_openssh,
        } => LinkError::HostKey(HostKeyPrompt {
            hop_index,
            hop_id,
            host,
            port,
            algorithm,
            sha256,
            public_key_openssh,
        }),
        error @ (SshError::AuthFailed { .. } | SshError::HostKeyChanged { .. }) => {
            LinkError::Attention(error.to_string())
        }
        error @ SshError::InvalidChain(_) => LinkError::Fatal(error.to_string()),
        SshError::Connect {
            hop_index,
            hop_id,
            host,
            port,
            detail,
        } => {
            let network = hop_index == 0 && is_network_failure(&detail);
            let error = SshError::Connect {
                hop_index,
                hop_id,
                host,
                port,
                detail,
            };
            LinkError::Transient {
                reason: error.to_string(),
                network,
            }
        }
        other => LinkError::Transient {
            reason: other.to_string(),
            network: false,
        },
    }
}

fn is_network_failure(detail: &str) -> bool {
    let detail = detail.to_ascii_lowercase();
    ["name resolution failed", "network is unreachable", "no route to host"]
        .iter()
        .any(|needle| detail.contains(needle))
}

pub(crate) fn classify_reverse(error: ReverseError) -> LinkError {
    match error {
        ReverseError::Duplicate(_) => LinkError::Fatal(error.to_string()),
        ReverseError::Request { .. } => LinkError::Transient {
            reason: error.to_string(),
            network: false,
        },
    }
}

pub(crate) fn vault_error(error: VaultError) -> LinkError {
    match error {
        VaultError::Locked => LinkError::Locked,
        other => LinkError::Attention(format!("cannot read vault secret: {other}")),
    }
}

/// `true` when starting this session must read the vault.
pub(crate) fn needs_secrets(profile: &SessionProfile) -> bool {
    let hop_secret = profile.hops.iter().any(|hop| {
        hop.host
            .auth
            .iter()
            .any(|m| matches!(m, AuthMethod::Key { .. } | AuthMethod::Password { .. }))
    });
    hop_secret || profile.mitm.as_ref().is_some_and(|m| m.ca.is_some())
}

/// Resolves one auth method. Returns `None` for a method this engine does not provide.
fn resolve_auth(vault: &Vault, method: &AuthMethod) -> Result<Option<HopAuth>, LinkError> {
    match method {
        AuthMethod::Key { key } => {
            let material = vault.get_secret(&key.to_string()).map_err(vault_error)?;
            let text = std::str::from_utf8(&material)
                .map_err(|_| LinkError::Attention(format!("key {key} is not valid text")))?;
            let (private, _) = import_key(text, None).map_err(vault_error)?;
            Ok(Some(HopAuth::Key(Arc::new(private))))
        }
        AuthMethod::Password { secret } => {
            let material = vault.get_secret(&secret.to_string()).map_err(vault_error)?;
            let text = std::str::from_utf8(&material)
                .map_err(|_| LinkError::Attention(format!("secret {secret} is not valid text")))?;
            Ok(Some(HopAuth::Password(Zeroizing::new(text.to_owned()))))
        }
        // `conduit-core` stores no answer references yet, so no saved answers can be sent.
        AuthMethod::KeyboardInteractive { .. } => {
            Ok(Some(HopAuth::KeyboardInteractive(Vec::new())))
        }
        // The system agent is never used, and this is not a login credential.
        AuthMethod::SystemAgentOptIn => Ok(None),
    }
}

/// Builds the hop list from the vault. `last_policy` applies to the final hop.
pub(crate) fn resolve_hops(
    profile: &SessionProfile,
    vault: &Vault,
    last_policy: ChannelPolicy,
) -> Result<Vec<HopSpec>, LinkError> {
    let last = profile.hops.len().saturating_sub(1);
    let mut last_policy = Some(last_policy);
    profile
        .hops
        .iter()
        .enumerate()
        .map(|(index, hop)| {
            let mut auth = Vec::with_capacity(hop.host.auth.len());
            for method in &hop.host.auth {
                if let Some(resolved) = resolve_auth(vault, method)? {
                    auth.push(resolved);
                }
            }
            let policy = if index == last {
                last_policy.take().unwrap_or_default()
            } else {
                ChannelPolicy::default()
            };
            Ok(HopSpec {
                hop_id: hop.hop_id.clone(),
                host: hop.host.host.clone(),
                port: hop.host.port,
                user: hop.host.user.clone(),
                auth,
                policy,
            })
        })
        .collect()
}

/// One audit log line for a signature by a hop's isolated login agent (OpenSSH engine). Holds
/// public metadata only, never key material or the signed data.
fn audit_line(event: &SignAudit) -> String {
    format!(
        "[agent-audit] hop={} fingerprint={} algorithm={} data_len={} result={}",
        event.hop_id,
        event.key_sha256,
        event.algorithm,
        event.data_len,
        if event.allowed { "allowed" } else { "refused" },
    )
}

/// The production engine. Routes each session to the SSH engine its profile selects.
#[derive(Debug, Default)]
pub(crate) struct DefaultEngine;

impl Engine for DefaultEngine {
    fn prepare(&self, ctx: SessionContext) -> BoxFut<'static, Result<Box<dyn Link>, LinkError>> {
        Box::pin(async move {
            match ctx.profile.engine {
                SshEngine::OpenSsh => {
                    let link = OpenSshLink::prepare(ctx).await?;
                    Ok(Box::new(link) as Box<dyn Link>)
                }
                _ => {
                    let link = RusshLink::prepare(ctx).await?;
                    Ok(Box::new(link) as Box<dyn Link>)
                }
            }
        })
    }
}

/// Access-log settings: no `rule` / `profile` / `upstream` fields (there is no user-visible
/// routing); each record is tagged with its `direction` by the logger clones.
pub(crate) fn access_log_config(cfg: &EngineConfig) -> AccessLogConfig {
    AccessLogConfig::new(
        cfg.log_level,
        cfg.log_format,
        cfg.http_access_log.clone(),
        cfg.socks_log.clone(),
    )
    .with_routing_fields(false)
}

/// Forward routing: every request goes to [`TUNNEL_PROFILE`] (served by `dialer`), with the
/// forward allow/block filter checked on the requested name or IP literal by the router (no
/// local DNS), the configured keepalive, and the default connect timeout.
fn forward_routing(
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

/// The proxy side of a session, shared by both SSH engines.
struct ProxyStack {
    cfg: EngineConfig,
    logger: Logger,
    access: AccessLogger,
    reverse: Option<ReverseProxy>,
    /// Forward routing: everything to the tunnel, with the forward filter.
    routing: SharedRouting,
    mitm: Option<MitmState>,
    server: Option<RunningServer>,
    listeners: SharedListeners,
    /// Dials through the tunnel with no destination filter, for the port forwards.
    tunnel: Arc<dyn UpstreamDialer>,
    local_forwards: Option<LocalForwards>,
    forward_states: SharedForwards,
    port_forwards: Vec<PortForward>,
}

impl ProxyStack {
    /// Checks the vault, then starts access logging and the reverse proxy over `base`.
    async fn start(
        profile: &SessionProfile,
        vault: &SharedVault,
        logs: &LogRingBuffer,
        stats: Arc<AtomicStats>,
        listeners: SharedListeners,
        forward_states: SharedForwards,
        base: Arc<dyn UpstreamDialer>,
    ) -> Result<Self, LinkError> {
        // In memory only, and only until the MITM states below have loaded it.
        let ca_pem: Option<Zeroizing<Vec<u8>>> = {
            let vault = vault.read().unwrap_or_else(PoisonError::into_inner);
            if needs_secrets(profile) && !vault.is_unlocked() {
                return Err(LinkError::Locked);
            }
            match profile.mitm.as_ref().and_then(|m| m.ca.as_ref()) {
                Some(ca) => Some(vault.get_secret(&ca.to_string()).map_err(vault_error)?),
                None => None,
            }
        };

        let cfg = to_engine_config(profile).map_err(|e| LinkError::Fatal(e.to_string()))?;

        let logger = Logger::with_writer(cfg.log_level, Box::new(logs.writer()));
        let access = match AccessLogger::start_with_stdout(
            access_log_config(&cfg),
            Box::new(logs.writer()),
            logger.clone(),
        )
        .await
        {
            Ok(access) => access,
            Err(e) => {
                return Err(LinkError::Fatal(format!("failed to open access log: {e}")));
            }
        };

        // Port forwards name their destination on purpose, so the proxy's filter skips them:
        // they dial the counted tunnel directly, while the proxy routes through the router.
        let tunnel: Arc<dyn UpstreamDialer> = Arc::new(StatsDialer::new(base, stats));

        let started = match forward_routing(&cfg, Arc::clone(&tunnel)) {
            Ok(routing) => {
                start_proxies(&cfg, ca_pem.as_deref().map(Vec::as_slice), &access, &logger)
                    .await
                    .map(|(reverse, mitm)| (routing.shared(), reverse, mitm))
            }
            Err(e) => Err(format!("forward routing setup failed: {e}")),
        };
        // The MITM states hold the CA now, so the vault copy goes.
        drop(ca_pem);
        let (routing, reverse, mitm) = match started {
            Ok(parts) => parts,
            Err(message) => {
                let _ = access.shutdown().await;
                logger.flush();
                return Err(LinkError::Fatal(message));
            }
        };

        Ok(Self {
            cfg,
            logger,
            access,
            reverse,
            routing,
            mitm,
            server: None,
            listeners,
            tunnel,
            local_forwards: None,
            forward_states,
            port_forwards: profile.port_forwards.clone(),
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

    /// Binds the local port forwards and the forward listeners once. They then stay bound
    /// across reconnects.
    async fn ensure_server(&mut self) -> Result<(), LinkError> {
        if self.local_forwards.is_none() {
            let local = self
                .port_forwards
                .iter()
                .filter(|f| f.enabled && f.direction == ForwardDirection::Local);
            self.local_forwards = Some(
                LocalForwards::bind(local, Arc::clone(&self.tunnel), &self.logger, &self.forward_states)
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
        *self
            .listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = bound;
        let token = server.shutdown_token();
        let reaper = self
            .mitm
            .as_ref()
            .map(|m| m.cache.spawn_reaper(token.clone(), self.logger.clone()));
        let run = tokio::spawn(server.run());
        self.server = Some(RunningServer { token, run, reaper });
        Ok(())
    }

    /// First shutdown step: close the local port forwards, then stop accepting and drain the
    /// forward listeners.
    async fn drain_server(&mut self) {
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
    }

    /// Last shutdown steps, after SSH is down: drain the reverse proxy and flush the logs.
    async fn finish(mut self) {
        if let Some(reverse) = self.reverse.take() {
            if reverse.shutdown().await.drained {
                self.logger.debug("all reverse proxy connections drained");
            }
        }
        self.logger.info("shutting down");
        if let Err(e) = self.access.shutdown().await {
            self.logger.error(format!("failed to flush access logs: {e}"));
        }
        self.logger.flush();
    }
}

struct RusshLink {
    profile: SessionProfile,
    options: ChainOptions,
    verifier: HostKeyVerifier,
    vault: SharedVault,
    stack: ProxyStack,
    dialer: Arc<RusshDialer>,
    relay: Option<ReverseRelay>,
    remote_listeners: SharedListeners,
    disconnects: Option<mpsc::UnboundedReceiver<DisconnectEvent>>,
}

impl RusshLink {
    async fn prepare(ctx: SessionContext) -> Result<Self, LinkError> {
        let SessionContext {
            profile,
            vault,
            known_hosts,
            logs,
            stats,
            listeners,
            remote_listeners,
            forwards,
        } = ctx;

        validate(&profile).map_err(|e| LinkError::Fatal(e.to_string()))?;
        let options =
            ChainOptions::from_tunnel(&profile.tunnel).map_err(|e| LinkError::Fatal(e.to_string()))?;
        let dialer = Arc::new(RusshDialer::new());
        let stack = ProxyStack::start(
            &profile,
            &vault,
            &logs,
            stats,
            listeners,
            forwards,
            Arc::clone(&dialer) as Arc<dyn UpstreamDialer>,
        )
        .await?;

        Ok(Self {
            profile,
            options,
            verifier: HostKeyVerifier::from_shared(known_hosts),
            vault,
            stack,
            dialer,
            relay: None,
            remote_listeners,
            disconnects: None,
        })
    }

    async fn drop_connection(&mut self) {
        self.disconnects = None;
        let relay = self.relay.take();
        self.remote_listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
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

/// Describes the reverse listeners bound on the target host.
///
/// `forwards` and `bound` start in the same order, because the relay binds all or nothing. The
/// role comes from the configured ports, since one port serving both is multiplexed.
pub(crate) fn remote_listener_info(
    cfg: &conduit_core::ReverseConfig,
    forwards: &[ReverseForward],
    bound: &[(String, u32)],
) -> Vec<ListenerInfo> {
    forwards
        .iter()
        .zip(bound)
        .map(|(forward, (address, port))| {
            let configured = forward.remote.port();
            let role = match (configured == cfg.reverse_http_port, configured == cfg.reverse_socks_port) {
                (true, true) => "multiplexed HTTP/HTTPS + SOCKS4/4a/5",
                (true, false) => "HTTP/HTTPS",
                (false, true) => "SOCKS4/4a/5",
                (false, false) => "reverse proxy",
            };
            let ip = address.parse().unwrap_or(forward.remote.ip());
            let port = u16::try_from(*port).unwrap_or(configured);
            ListenerInfo { role: role.to_string(), addr: SocketAddr::new(ip, port) }
        })
        .collect()
}

/// Starts the reverse proxy and loads the forward MITM state, both from the in-memory CA.
async fn start_proxies(
    cfg: &EngineConfig,
    mitm_ca_pem: Option<&[u8]>,
    access: &AccessLogger,
    logger: &Logger,
) -> Result<(Option<ReverseProxy>, Option<MitmState>), String> {
    let reverse = ReverseProxy::start(cfg, mitm_ca_pem, access, logger).await?;
    if !cfg.forward_enabled {
        return Ok((reverse, None));
    }
    let mitm = match mitm_ca_pem.filter(|_| cfg.mitm_enabled) {
        Some(pem) => MitmState::from_pem_bytes(pem, pem, &cfg.mitm_options)
            .map(Some)
            .map_err(|e| format!("MITM setup failed: {e}")),
        None => Ok(None),
    };
    match mitm {
        Ok(mitm) => {
            if let Some(m) = &mitm {
                m.cache.set_logger(logger.clone());
            }
            Ok((reverse, mitm))
        }
        Err(message) => {
            if let Some(reverse) = reverse {
                reverse.shutdown().await;
            }
            Err(message)
        }
    }
}

impl Link for RusshLink {
    fn connect(&mut self) -> BoxFut<'_, Result<(), LinkError>> {
        Box::pin(async move {
            // The relay's receiver is consumed per connection, so build a fresh pair each time.
            // The reverse proxy's listeners first, then the remote port forwards.
            let mut remote: Vec<RemoteForward> = self
                .stack
                .reverse
                .as_ref()
                .map(|reverse| reverse.forwards().iter().map(ReverseForward::to_remote_forward).collect())
                .unwrap_or_default();
            let proxy_forwards = remote.len();
            remote.extend(self.stack.remote_forwards().map(|forward| RemoteForward {
                remote: forward.listen(),
                host: forward.dest_host_unbracketed().to_string(),
                port: forward.dest_port,
            }));
            let (policy, inbound): (ChannelPolicy, Option<ReverseInbound>) =
                if !remote.is_empty() {
                    let (policy, inbound) = reverse_policy(REVERSE_CHANNEL_CAPACITY);
                    (policy, Some(inbound))
                } else {
                    (ChannelPolicy::default(), None)
                };
            let hops = {
                let vault = self.vault.read().unwrap_or_else(PoisonError::into_inner);
                if needs_secrets(&self.profile) && !vault.is_unlocked() {
                    return Err(LinkError::Locked);
                }
                resolve_hops(&self.profile, &vault, policy)?
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
                            *self
                                .remote_listeners
                                .lock()
                                .unwrap_or_else(PoisonError::into_inner) =
                                remote_listener_info(&self.profile.reverse, reverse.forwards(), proxy_bound);
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
            self.stack.ensure_server().await
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
            this.stack.drain_server().await;
            this.drop_connection().await;
            this.stack.finish().await;
        })
    }
}

/// Maps an `ssh` failure to what the supervisor must do.
pub(crate) fn classify_openssh(error: OpenSshError) -> LinkError {
    match error {
        // Never retried: these could lock an account or bypass host-key trust. Every hop was
        // pinned before `ssh` started, so an "unknown" key here is a trust failure too.
        error @ (OpenSshError::AuthFailed(_)
        | OpenSshError::HostKeyChanged(_)
        | OpenSshError::HostKeyUnknown(_)) => LinkError::Attention(error.to_string()),
        error @ OpenSshError::BinaryUnsupported(_) => LinkError::Fatal(error.to_string()),
        OpenSshError::Io(io) if is_setup_failure(io.kind()) => {
            LinkError::Fatal(format!("OpenSSH session setup failed: {io}"))
        }
        error => LinkError::Transient {
            reason: error.to_string(),
            network: false,
        },
    }
}

/// A local setup problem that retrying cannot fix, such as a bad config or a missing worker.
fn is_setup_failure(kind: std::io::ErrorKind) -> bool {
    use std::io::ErrorKind::{InvalidData, InvalidInput, NotFound, PermissionDenied};
    matches!(kind, InvalidData | InvalidInput | NotFound | PermissionDenied)
}

/// When a hop cannot be written to `known_hosts`, returns a copy of `store` for the host-key
/// probe. A pin without a usable public key is marked unapproved there, so a matching key
/// prompts (and records the key) while a different key is still a hard "changed" stop.
pub(crate) fn probe_store(store: &KnownHostsStore, profile: &SessionProfile) -> Option<KnownHostsStore> {
    let mut scratch = store.clone();
    let mut incomplete = false;
    for hop in &profile.hops {
        let (hop_id, host, port) = (hop.hop_id.as_str(), hop.host.host.as_str(), hop.host.port);
        if !render_known_hosts(store, &[(hop_id, host, port)]).is_empty() {
            continue;
        }
        incomplete = true;
        if let Some(pin) = store.get(hop_id, host, port) {
            let mut pin = pin.clone();
            pin.approved = false;
            scratch.insert(
                HostKeyLookup {
                    hop_id: hop_id.to_string(),
                    host: host.to_string(),
                    port,
                },
                pin,
            );
        }
    }
    incomplete.then_some(scratch)
}

/// Builds the supervisor's hop list from the vault. Each hop's keys go in its own scoped agent.
pub(crate) fn supervisor_hops(
    profile: &SessionProfile,
    vault: &Vault,
    logs: &LogRingBuffer,
) -> Result<Vec<SupervisorHop>, LinkError> {
    profile
        .hops
        .iter()
        .map(|hop| {
            let mut keys = Vec::new();
            let mut password = None;
            for method in &hop.host.auth {
                match resolve_auth(vault, method)? {
                    // The comment is visible to the agent client, so vault names stay out of it.
                    Some(HopAuth::Key(private)) => keys.push((private, String::new())),
                    Some(HopAuth::Password(secret)) => {
                        password.get_or_insert(secret);
                    }
                    _ => {}
                }
            }
            let agent = (!keys.is_empty()).then(|| {
                let sink = logs.clone();
                let audit: SignAuditFn =
                    Arc::new(move |event: &SignAudit| sink.push(&audit_line(event)));
                Arc::new(ScopedAgent::seal(hop.hop_id.clone(), keys, Some(audit)))
            });
            Ok(SupervisorHop {
                hop_id: hop.hop_id.clone(),
                host: hop.host.host.clone(),
                port: hop.host.port,
                user: hop.host.user.clone(),
                password,
                agent,
            })
        })
        .collect()
}

/// The opt-in engine: a supervised `ssh -N -D` process plus the embedded proxy.
struct OpenSshLink {
    profile: SessionProfile,
    options: ChainOptions,
    known_hosts: Arc<RwLock<KnownHostsStore>>,
    vault: SharedVault,
    stack: ProxyStack,
    logs: LogRingBuffer,
    /// Feeds the proxy's dialer, and outlives each `ssh` process.
    tunnel: watch::Sender<TunnelState>,
    supervisor: Option<OpenSshSupervisor>,
    supervisor_state: Option<watch::Receiver<TunnelState>>,
}

impl OpenSshLink {
    async fn prepare(ctx: SessionContext) -> Result<Self, LinkError> {
        let SessionContext {
            profile,
            vault,
            known_hosts,
            logs,
            stats,
            listeners,
            // The OpenSSH engine does not report what `ssh -R` bound, so it shows none.
            remote_listeners: _,
            forwards,
        } = ctx;

        validate(&profile).map_err(|e| LinkError::Fatal(e.to_string()))?;
        let options =
            ChainOptions::from_tunnel(&profile.tunnel).map_err(|e| LinkError::Fatal(e.to_string()))?;

        let ssh_bin = profile.openssh.ssh_bin.clone();
        let info = tokio::task::spawn_blocking(move || check_openssh_binary(&ssh_bin))
            .await
            .map_err(|e| LinkError::Fatal(format!("OpenSSH binary check failed: {e}")))?;
        if !info.supported {
            return Err(LinkError::Fatal(format!(
                "OpenSSH binary cannot be used: {}",
                info.message
            )));
        }

        let (tunnel, state) = watch::channel(TunnelState::Connecting);
        let base: Arc<dyn UpstreamDialer> = Arc::new(OpenSshDialer::new(state));
        let stack =
            ProxyStack::start(&profile, &vault, &logs, stats, listeners, forwards, base).await?;

        Ok(Self {
            profile,
            options,
            known_hosts,
            vault,
            stack,
            logs,
            tunnel,
            supervisor: None,
            supervisor_state: None,
        })
    }

    /// Surfaces the first hop that needs a host-key decision, before `ssh` is launched.
    ///
    /// Each server's key is checked before any credential is sent to it, and only hops already
    /// trusted are authenticated to reach the next one.
    async fn probe_host_keys(&self, scratch: KnownHostsStore) -> Result<(), LinkError> {
        let hops = {
            let vault = self.vault.read().unwrap_or_else(PoisonError::into_inner);
            resolve_hops(&self.profile, &vault, ChannelPolicy::default())?
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

    /// The configured SOCKS port, or a free one for this attempt.
    ///
    /// The forward listeners bind after `ssh` starts, so a free port must not be one of theirs.
    fn socks_port(&self) -> Result<u16, LinkError> {
        let configured = self.profile.openssh.ssh_socks_port;
        if configured != 0 {
            return Ok(configured);
        }
        let failed = |detail: String| LinkError::Transient {
            reason: format!("no free local port for the SSH tunnel: {detail}"),
            network: false,
        };
        let forward = &self.profile.forward;
        // Rejected listeners stay open until return, so the OS cannot offer them again.
        let mut rejected = Vec::new();
        for _ in 0..SOCKS_PORT_ATTEMPTS {
            let listener = std::net::TcpListener::bind((self.profile.openssh.ssh_socks_bind, 0))
                .map_err(|e| failed(e.to_string()))?;
            let port = listener
                .local_addr()
                .map_err(|e| failed(e.to_string()))?
                .port();
            let local_forward = self
                .profile
                .active_forwards_in(ForwardDirection::Local)
                .any(|f| f.port == port);
            if port != forward.http_port && port != forward.socks_port && !local_forward {
                return Ok(port);
            }
            rejected.push(listener);
        }
        Err(failed("every port offered is a forward or port-forward port".into()))
    }

    async fn stop_supervisor(&mut self, reason: &str) {
        self.stack.publish_remote(None);
        self.tunnel
            .send_replace(TunnelState::Disconnected(reason.to_string()));
        self.supervisor_state = None;
        if let Some(supervisor) = self.supervisor.take() {
            // Terminates and reaps `ssh` before its runtime directory is removed.
            supervisor.shutdown().await;
        }
    }
}

impl Link for OpenSshLink {
    fn connect(&mut self) -> BoxFut<'_, Result<(), LinkError>> {
        Box::pin(async move {
            {
                let vault = self.vault.read().unwrap_or_else(PoisonError::into_inner);
                if needs_secrets(&self.profile) && !vault.is_unlocked() {
                    return Err(LinkError::Locked);
                }
            }
            let scratch = {
                let store = self.known_hosts.read().unwrap_or_else(PoisonError::into_inner);
                probe_store(&store, &self.profile)
            };
            if let Some(scratch) = scratch {
                self.probe_host_keys(scratch).await?;
            }

            let hops = {
                let vault = self.vault.read().unwrap_or_else(PoisonError::into_inner);
                supervisor_hops(&self.profile, &vault, &self.logs)?
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
                .map(|reverse| reverse.forwards().iter().map(|f| f.spec()).collect())
                .unwrap_or_default();
            // Validated: each part is an IP, a port, or a host name, so `ssh` reads it as is.
            reverse_forwards.extend(self.stack.remote_forwards().map(PortForward::spec));
            let sink = self.logs.clone();
            let log: LogFn = Arc::new(move |line: &str| sink.push(line));
            let tunnel = &self.profile.tunnel;
            let options = SupervisorOptions {
                ssh_bin: self.profile.openssh.ssh_bin.clone(),
                worker_bin: None,
                hops,
                known_hosts,
                bind: self.profile.openssh.ssh_socks_bind,
                socks_port: self.socks_port()?,
                reverse_forwards,
                extra_args: self.profile.openssh.extra_args.clone(),
                ip_version: tunnel.ip_version.clone(),
                server_alive_interval: tunnel.server_alive_interval,
                server_alive_count_max: tunnel.server_alive_count_max,
                startup_timeout: tunnel.startup_timeout,
                log: Some(log),
            };

            self.tunnel.send_replace(TunnelState::Connecting);
            let supervisor = match OpenSshSupervisor::start(options).await {
                Ok(supervisor) => supervisor,
                Err(error) => {
                    self.tunnel
                        .send_replace(TunnelState::Disconnected(error.to_string()));
                    return Err(classify_openssh(error));
                }
            };
            self.tunnel
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
            self.stack.ensure_server().await
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
            self.tunnel
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
            this.stack.drain_server().await;
            this.stop_supervisor("stopped").await;
            this.stack.finish().await;
        })
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    /// Shared controls and counters for a scripted link.
    #[derive(Default)]
    pub(crate) struct Script {
        pub(crate) outcomes: Mutex<VecDeque<Result<(), LinkError>>>,
        pub(crate) connects: AtomicUsize,
        pub(crate) disconnects: AtomicUsize,
        pub(crate) shutdowns: AtomicUsize,
        pub(crate) lose: Notify,
    }

    impl Script {
        pub(crate) fn new(outcomes: Vec<Result<(), LinkError>>) -> Arc<Self> {
            Arc::new(Self {
                outcomes: Mutex::new(outcomes.into()),
                ..Self::default()
            })
        }

        pub(crate) fn connects(&self) -> usize {
            self.connects.load(Ordering::SeqCst)
        }
    }

    pub(crate) struct ScriptLink(pub(crate) Arc<Script>);

    impl Link for ScriptLink {
        fn connect(&mut self) -> BoxFut<'_, Result<(), LinkError>> {
            Box::pin(async move {
                self.0.connects.fetch_add(1, Ordering::SeqCst);
                let next = self.0.outcomes.lock().unwrap().pop_front();
                match next {
                    Some(outcome) => outcome,
                    None => std::future::pending().await,
                }
            })
        }

        fn lost(&mut self) -> BoxFut<'_, String> {
            Box::pin(async move {
                self.0.lose.notified().await;
                "scripted loss".to_string()
            })
        }

        fn disconnect(&mut self) -> BoxFut<'_, ()> {
            Box::pin(async move {
                self.0.disconnects.fetch_add(1, Ordering::SeqCst);
            })
        }

        fn shutdown(self: Box<Self>) -> BoxFut<'static, ()> {
            Box::pin(async move {
                self.0.shutdowns.fetch_add(1, Ordering::SeqCst);
            })
        }
    }

    pub(crate) fn transient() -> Result<(), LinkError> {
        Err(LinkError::Transient {
            reason: "refused".into(),
            network: false,
        })
    }

    pub(crate) fn host_key() -> HostKeyPrompt {
        HostKeyPrompt {
            hop_index: 0,
            hop_id: "hop".into(),
            host: "example.test".into(),
            port: 22,
            algorithm: "ssh-ed25519".into(),
            sha256: "SHA256:abc".into(),
            public_key_openssh: Some("ssh-ed25519 AAAAtest".into()),
        }
    }

    /// Yields virtual time until `check` passes.
    pub(crate) async fn until(mut check: impl FnMut() -> bool) {
        for _ in 0..2_000 {
            if check() {
                return;
            }
            sleep(Duration::from_millis(5)).await;
        }
        panic!("condition not reached");
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use crate::events::EventBus;
    use std::sync::atomic::Ordering;
    use uuid::Uuid;

    struct Harness {
        script: Arc<Script>,
        cell: Arc<StateCell>,
        control: mpsc::UnboundedSender<Control>,
        cancel: CancellationToken,
        task: JoinHandle<SessionState>,
    }

    fn spawn(outcomes: Vec<Result<(), LinkError>>, no_reconnect: bool) -> Harness {
        let script = Script::new(outcomes);
        let cell = Arc::new(StateCell::new(Uuid::new_v4(), EventBus::default()));
        cell.set(SessionState::Starting);
        let (control, mut receiver) = mpsc::unbounded_channel();
        let cancel = CancellationToken::new();
        let task = {
            let (script, cell, cancel) = (Arc::clone(&script), Arc::clone(&cell), cancel.clone());
            tokio::spawn(async move {
                let mut link = ScriptLink(script);
                let backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(8));
                let logs = LogRingBuffer::new(32);
                supervise(
                    &mut link,
                    &cell,
                    &mut receiver,
                    &cancel,
                    backoff,
                    no_reconnect,
                    &logs,
                )
                .await
            })
        };
        Harness {
            script,
            cell,
            control,
            cancel,
            task,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn auth_failure_halts_after_one_attempt() {
        let h = spawn(vec![Err(classify(SshError::AuthFailed {
            hop_index: 0,
            hop_id: "a".into(),
            detail: "password rejected".into(),
        }))], false);
        let state = h.task.await.unwrap();
        assert!(matches!(state, SessionState::NeedsAttention { .. }));
        sleep(Duration::from_secs(120)).await;
        assert_eq!(h.script.connects(), 1, "bad credentials must never be retried");
    }

    #[tokio::test(start_paused = true)]
    async fn changed_host_key_halts_during_reconnect() {
        let changed = SshError::HostKeyChanged {
            hop_index: 0,
            hop_id: "a".into(),
            host: "h".into(),
            port: 22,
            algorithm: "ssh-ed25519".into(),
            expected_sha256: "SHA256:old".into(),
            sha256: "SHA256:new".into(),
        };
        let h = spawn(vec![Ok(()), Err(classify(changed))], false);
        until(|| h.cell.get() == SessionState::Connected).await;
        h.script.lose.notify_one();
        let state = h.task.await.unwrap();
        assert!(matches!(state, SessionState::NeedsAttention { .. }));
        assert_eq!(h.script.connects(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn transient_failures_retry_with_growing_delay() {
        let h = spawn(vec![transient(), transient(), Ok(())], false);
        until(|| h.script.connects() == 2).await;
        until(|| {
            matches!(
                h.cell.get(),
                SessionState::Reconnecting {
                    attempt: 2,
                    next_retry_secs: 2
                }
            )
        })
        .await;
        until(|| h.cell.get() == SessionState::Connected).await;
        assert_eq!(h.script.connects(), 3);
        h.cancel.cancel();
        assert_eq!(h.task.await.unwrap(), SessionState::Stopped);
    }

    #[tokio::test(start_paused = true)]
    async fn backoff_resets_only_after_stable_connection() {
        let h = spawn(vec![transient(), transient(), Ok(()), transient()], false);
        until(|| h.cell.get() == SessionState::Connected).await;
        sleep(Duration::from_secs(6)).await;
        h.script.lose.notify_one();
        until(|| {
            matches!(
                h.cell.get(),
                SessionState::Reconnecting {
                    attempt: 1,
                    next_retry_secs: 1
                }
            )
        })
        .await;
        h.cancel.cancel();
        h.task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn backoff_keeps_growing_after_short_connection() {
        let h = spawn(vec![transient(), transient(), Ok(())], false);
        until(|| h.cell.get() == SessionState::Connected).await;
        h.script.lose.notify_one();
        until(|| {
            matches!(
                h.cell.get(),
                SessionState::Reconnecting {
                    attempt: 3,
                    next_retry_secs: 4
                }
            )
        })
        .await;
        h.cancel.cancel();
        h.task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn no_reconnect_fails_on_first_loss() {
        let h = spawn(vec![Ok(())], true);
        until(|| h.cell.get() == SessionState::Connected).await;
        h.script.lose.notify_one();
        assert!(matches!(
            h.task.await.unwrap(),
            SessionState::Failed { .. }
        ));
        assert_eq!(h.script.connects(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn host_key_approval_retries_without_backoff() {
        let h = spawn(vec![Err(LinkError::HostKey(host_key())), Ok(())], false);
        until(|| matches!(h.cell.get(), SessionState::AwaitingHostKey(_))).await;
        sleep(Duration::from_secs(60)).await;
        assert_eq!(h.script.connects(), 1, "must wait for the user");
        h.control.send(Control::ApproveHostKey).unwrap();
        until(|| h.cell.get() == SessionState::Connected).await;
        assert_eq!(h.script.connects(), 2);
        h.cancel.cancel();
        h.task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn host_key_rejection_halts() {
        let h = spawn(vec![Err(LinkError::HostKey(host_key()))], false);
        until(|| matches!(h.cell.get(), SessionState::AwaitingHostKey(_))).await;
        h.control.send(Control::RejectHostKey).unwrap();
        assert!(matches!(
            h.task.await.unwrap(),
            SessionState::NeedsAttention { .. }
        ));
        assert_eq!(h.script.connects(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn recycle_replaces_a_live_connection_immediately() {
        let h = spawn(vec![Ok(()), Ok(())], false);
        until(|| h.cell.get() == SessionState::Connected).await;
        h.control.send(Control::Recycle).unwrap();
        until(|| h.script.connects() == 2).await;
        assert_eq!(h.script.disconnects.load(Ordering::SeqCst), 1);
        until(|| h.cell.get() == SessionState::Connected).await;
        h.cancel.cancel();
        h.task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn network_failure_waits_for_network() {
        let h = spawn(
            vec![Err(classify(SshError::Connect {
                hop_index: 0,
                hop_id: "a".into(),
                host: "h".into(),
                port: 22,
                detail: "name resolution failed: no such host".into(),
            }))],
            false,
        );
        until(|| h.cell.get() == SessionState::WaitingForNetwork).await;
        h.cancel.cancel();
        assert_eq!(h.task.await.unwrap(), SessionState::Stopped);
    }

    #[test]
    fn audit_line_survives_redaction_and_reports_the_outcome() {
        let mut event = SignAudit {
            hop_id: "hop-1".into(),
            key_sha256: "SHA256:abc".into(),
            algorithm: "ssh-ed25519".into(),
            data_len: 32,
            allowed: true,
        };
        let logs = LogRingBuffer::new(4);
        logs.push(&audit_line(&event));
        event.allowed = false;
        logs.push(&audit_line(&event));
        let lines = logs.query(None);
        assert_eq!(
            lines[0].text,
            "[agent-audit] hop=hop-1 fingerprint=SHA256:abc algorithm=ssh-ed25519 data_len=32 result=allowed"
        );
        assert!(lines[1].text.ends_with("result=refused"));
    }

    #[test]
    fn classify_openssh_never_retries_trust_or_auth_failures() {
        for error in [
            OpenSshError::AuthFailed("denied".into()),
            OpenSshError::HostKeyChanged("changed".into()),
            OpenSshError::HostKeyUnknown("unknown".into()),
        ] {
            assert!(matches!(classify_openssh(error), LinkError::Attention(_)));
        }
        assert!(matches!(
            classify_openssh(OpenSshError::BinaryUnsupported("old".into())),
            LinkError::Fatal(_)
        ));
        assert!(matches!(
            classify_openssh(OpenSshError::Io(std::io::ErrorKind::NotFound.into())),
            LinkError::Fatal(_)
        ));
        assert!(matches!(
            classify_openssh(OpenSshError::Io(std::io::ErrorKind::AddrInUse.into())),
            LinkError::Transient { .. }
        ));
        assert!(matches!(
            classify_openssh(OpenSshError::ProcessExited("exit 255".into())),
            LinkError::Transient { .. }
        ));
    }

    #[test]
    fn remote_listener_info_names_roles_by_configured_port() {
        let cfg = conduit_core::ReverseConfig {
            reverse_http_port: 8080,
            reverse_socks_port: 1080,
            ..conduit_core::ReverseConfig::default()
        };
        let forward = |remote: &str| ReverseForward {
            remote: remote.parse().unwrap(),
            local: "127.0.0.1:50000".parse().unwrap(),
        };
        let forwards = [forward("127.0.0.1:8080"), forward("127.0.0.1:1080")];
        let bound = [("127.0.0.1".to_string(), 8080), ("127.0.0.1".to_string(), 1080)];
        let info = remote_listener_info(&cfg, &forwards, &bound);
        assert_eq!(info[0].role, "HTTP/HTTPS");
        assert_eq!(info[0].addr, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(info[1].role, "SOCKS4/4a/5");

        let mux = conduit_core::ReverseConfig { reverse_socks_port: 8080, ..cfg };
        let info = remote_listener_info(&mux, &forwards[..1], &bound[..1]);
        assert_eq!(info[0].role, "multiplexed HTTP/HTTPS + SOCKS4/4a/5");
    }

    #[test]
    fn probe_store_demotes_only_pins_without_a_usable_key() {
        use conduit_core::{HostKeyRecord, HostProfile, Timestamp};
        let hop = |id: &str| conduit_core::HopEntry {
            hop_id: id.into(),
            host: HostProfile {
                host: "h".into(),
                port: 22,
                ..Default::default()
            },
            ..Default::default()
        };
        let record = |key: Option<&str>| HostKeyRecord {
            algorithm: "ssh-ed25519".into(),
            fingerprint_sha256: "SHA256:abc".into(),
            first_seen: Timestamp(1),
            approved: true,
            public_key_openssh: key.map(str::to_string),
        };
        let lookup = |id: &str| HostKeyLookup {
            hop_id: id.into(),
            host: "h".into(),
            port: 22,
        };
        let mut store = KnownHostsStore::default();
        store.insert(lookup("full"), record(Some("ssh-ed25519 AAAA")));
        let complete = SessionProfile {
            hops: vec![hop("full")],
            ..Default::default()
        };
        assert!(probe_store(&store, &complete).is_none());

        store.insert(lookup("legacy"), record(None));
        let mixed = SessionProfile {
            hops: vec![hop("full"), hop("legacy"), hop("absent")],
            ..Default::default()
        };
        let scratch = probe_store(&store, &mixed).unwrap();
        assert!(scratch.get("full", "h", 22).unwrap().approved);
        assert!(!scratch.get("legacy", "h", 22).unwrap().approved);
        assert!(scratch.get("absent", "h", 22).is_none());
        assert!(store.get("legacy", "h", 22).unwrap().approved, "the real store is unchanged");
    }

    #[test]
    fn classify_routes_each_failure() {
        assert!(matches!(
            classify(SshError::HostKeyUnknown {
                hop_index: 1,
                hop_id: "b".into(),
                host: "h".into(),
                port: 22,
                algorithm: "ssh-ed25519".into(),
                sha256: "SHA256:x".into(),
                public_key_openssh: None,
            }),
            LinkError::HostKey(HostKeyPrompt { hop_index: 1, .. })
        ));
        assert!(matches!(
            classify(SshError::InvalidChain("x".into())),
            LinkError::Fatal(_)
        ));
        assert!(matches!(
            classify(SshError::Timeout {
                hop_index: 0,
                hop_id: "a".into()
            }),
            LinkError::Transient { network: false, .. }
        ));
        // A failure past the first hop says nothing about the local network.
        assert!(matches!(
            classify(SshError::Connect {
                hop_index: 1,
                hop_id: "b".into(),
                host: "h".into(),
                port: 22,
                detail: "Network is unreachable".into(),
            }),
            LinkError::Transient { network: false, .. }
        ));
    }
}
