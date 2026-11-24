//! Drives one session end to end.
//!
//! Startup: access log → reverse proxy → SSH chain → `tcpip-forward` → forward server.
//! Shutdown: drain forward server → tear down SSH → drain reverse proxy → flush access log.
//!
//! Secrets are read from the vault on every connect attempt and are not kept between attempts,
//! so locking the vault also stops future reconnects.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use conduit_core::{
    to_config, validate, AuthMethod, HopEntry, KnownHostsStore, SessionProfile, SshEngine,
};
use conduit_ssh::{
    agent_policy, connect_chain, reverse_policy, AgentForwardRelay, AgentInbound, AgentRelayError,
    AtomicStats, ChainOptions, ChannelPolicy, DisconnectEvent, HopAuth, HopSpec, HostKeyVerifier,
    ReverseError, ReverseInbound, ReverseRelay, RusshDialer, ScopedAgent, SignAudit, SignAuditFn,
    SshChain, SshError, StatsDialer,
};
use conduit_vault::{import_key, Vault, VaultError};
use rusty_conduit_ssh::build_engines;
use rusty_conduit_ssh::config::Config;
use rusty_conduit_ssh::logging::{AccessLogConfig, AccessLogger, Logger};
use rusty_conduit_ssh::mitm::MitmState;
use rusty_conduit_ssh::net::{FilteredDialer, UpstreamDialer};
use rusty_conduit_ssh::reverse::ReverseProxy;
use rusty_conduit_ssh::server::{ProtocolHandlers, Server, ShutdownReport};
use rusty_conduit_ssh::EngineHandlers;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{sleep, Instant};
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

use crate::backoff::Backoff;
use crate::logs::LogRingBuffer;
use crate::state::{HostKeyPrompt, ListenerInfo, SessionState, StateCell};

/// Queued inbound reverse channels per connection.
const REVERSE_CHANNEL_CAPACITY: usize = 64;
/// Queued inbound agent channels per opted-in hop.
const AGENT_CHANNEL_CAPACITY: usize = 16;
/// Backstop for noticing a dead chain if no disconnect event arrives.
const LIVENESS_POLL: Duration = Duration::from_secs(1);

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
    listeners
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clear();
    logs.push(&format!("session ended: {}", describe(&final_state)));
    cell.set(final_state);
}

fn halt_state(error: LinkError) -> SessionState {
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

fn describe(state: &SessionState) -> String {
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
async fn supervise(
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
        } => LinkError::HostKey(HostKeyPrompt {
            hop_index,
            hop_id,
            host,
            port,
            algorithm,
            sha256,
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

fn classify_reverse(error: ReverseError) -> LinkError {
    match error {
        ReverseError::Duplicate(_) => LinkError::Fatal(error.to_string()),
        ReverseError::Request { .. } => LinkError::Transient {
            reason: error.to_string(),
            network: false,
        },
    }
}

fn vault_error(error: VaultError) -> LinkError {
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
    hop_secret
        || profile.hops.iter().any(forwards_agent)
        || profile.mitm.as_ref().is_some_and(|m| m.passphrase.is_some())
}

/// `true` when this hop opted in and has at least one key to expose.
fn forwards_agent(hop: &HopEntry) -> bool {
    hop.agent_forward && !hop.agent_forward_keys.is_empty()
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
        // Agent forwarding is never enabled implicitly, and this is not a login credential.
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

/// An agent ready to serve one hop once the chain is up.
struct PendingAgent {
    hop_index: usize,
    agent: ScopedAgent,
    inbound: AgentInbound,
    command: Option<String>,
}

/// One audit log line. Holds public metadata only, never key material or the signed data.
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

/// Loads each opted-in hop's assigned keys and adds the agent opt-in to its channel policy.
fn attach_agents(
    profile: &SessionProfile,
    vault: &Vault,
    logs: &LogRingBuffer,
    hops: &mut [HopSpec],
) -> Result<Vec<PendingAgent>, LinkError> {
    let mut pending = Vec::new();
    for (hop_index, (entry, spec)) in profile.hops.iter().zip(hops.iter_mut()).enumerate() {
        if !forwards_agent(entry) {
            continue;
        }
        let mut keys = Vec::with_capacity(entry.agent_forward_keys.len());
        for key in &entry.agent_forward_keys {
            let method = AuthMethod::Key { key: key.clone() };
            if let Some(HopAuth::Key(private)) = resolve_auth(vault, &method)? {
                // The comment is sent to the remote host, so vault names stay out of it.
                keys.push((private, String::new()));
            }
        }
        let sink = logs.clone();
        let audit: SignAuditFn = Arc::new(move |event: &SignAudit| sink.push(&audit_line(event)));
        let agent = ScopedAgent::seal(entry.hop_id.clone(), keys, Some(audit));
        let (policy, inbound) = agent_policy(AGENT_CHANNEL_CAPACITY);
        // Only this field is set, so a reverse policy on the same hop is preserved.
        spec.policy.agent_channels = policy.agent_channels;
        pending.push(PendingAgent {
            hop_index,
            agent,
            inbound,
            command: entry.agent_forward_command.clone(),
        });
    }
    Ok(pending)
}

async fn start_agent_relays(
    chain: &SshChain,
    pending: Vec<PendingAgent>,
) -> Result<Vec<AgentForwardRelay>, LinkError> {
    let mut relays = Vec::with_capacity(pending.len());
    for item in pending {
        let handle = chain.hop(item.hop_index).ok_or_else(|| {
            LinkError::Fatal(format!("agent forwarding: no hop {}", item.hop_index))
        })?;
        let relay = AgentForwardRelay::start(
            handle,
            item.hop_index,
            item.agent,
            item.inbound,
            item.command.as_deref(),
        )
        .await
        .map_err(classify_agent)?;
        relays.push(relay);
    }
    Ok(relays)
}

fn classify_agent(error: AgentRelayError) -> LinkError {
    LinkError::Transient {
        reason: format!("agent forwarding failed: {error}"),
        network: false,
    }
}

/// The production engine: `russh` chain plus the embedded proxy.
#[derive(Debug, Default)]
pub(crate) struct RusshEngine;

impl Engine for RusshEngine {
    fn prepare(&self, ctx: SessionContext) -> BoxFut<'static, Result<Box<dyn Link>, LinkError>> {
        Box::pin(async move {
            let link = RusshLink::prepare(ctx).await?;
            Ok(Box::new(link) as Box<dyn Link>)
        })
    }
}

struct RunningServer {
    token: CancellationToken,
    run: JoinHandle<ShutdownReport>,
    reaper: Option<JoinHandle<()>>,
}

struct RusshLink {
    profile: SessionProfile,
    cfg: Config,
    options: ChainOptions,
    verifier: HostKeyVerifier,
    vault: SharedVault,
    logger: Logger,
    access: AccessLogger,
    reverse: Option<ReverseProxy>,
    dialer: Arc<RusshDialer>,
    upstream: Arc<dyn UpstreamDialer>,
    mitm: Option<MitmState>,
    server: Option<RunningServer>,
    relay: Option<ReverseRelay>,
    agent_relays: Vec<AgentForwardRelay>,
    logs: LogRingBuffer,
    disconnects: Option<mpsc::UnboundedReceiver<DisconnectEvent>>,
    listeners: SharedListeners,
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
        } = ctx;

        if profile.engine == SshEngine::OpenSsh {
            return Err(LinkError::Fatal(
                "the OpenSSH engine is not available in this build".into(),
            ));
        }
        validate(&profile).map_err(|e| LinkError::Fatal(e.to_string()))?;

        let passphrase = {
            let vault = vault.read().unwrap_or_else(PoisonError::into_inner);
            if needs_secrets(&profile) && !vault.is_unlocked() {
                return Err(LinkError::Locked);
            }
            match profile.mitm.as_ref().and_then(|m| m.passphrase.as_ref()) {
                Some(secret) => {
                    let bytes = vault.get_secret(&secret.to_string()).map_err(vault_error)?;
                    let text = std::str::from_utf8(&bytes).map_err(|_| {
                        LinkError::Attention(format!("secret {secret} is not valid text"))
                    })?;
                    Some(Zeroizing::new(text.to_owned()))
                }
                None => None,
            }
        };

        let mut cfg = to_config(&profile, passphrase.as_ref().map(|p| p.as_str()))
            .map_err(|e| LinkError::Fatal(e.to_string()))?;
        drop(passphrase);
        let options =
            ChainOptions::from_tunnel(&profile.tunnel).map_err(|e| LinkError::Fatal(e.to_string()));
        let options = match options {
            Ok(options) => options,
            Err(error) => {
                scrub_passphrase(&mut cfg);
                return Err(error);
            }
        };

        let logger = Logger::with_writer(cfg.log_level, Box::new(logs.writer()));
        let access = match AccessLogger::start_with_stdout(
            AccessLogConfig::new(
                cfg.log_level,
                cfg.log_format,
                cfg.http_access_log.clone(),
                cfg.socks_log.clone(),
            ),
            Box::new(logs.writer()),
            logger.clone(),
        )
        .await
        {
            Ok(access) => access,
            Err(e) => {
                scrub_passphrase(&mut cfg);
                return Err(LinkError::Fatal(format!("failed to open access log: {e}")));
            }
        };

        let dialer = Arc::new(RusshDialer::new());
        let counted: Arc<dyn UpstreamDialer> = Arc::new(StatsDialer::new(
            Arc::clone(&dialer) as Arc<dyn UpstreamDialer>,
            stats,
        ));
        let upstream: Arc<dyn UpstreamDialer> = match cfg.forward_filter() {
            Some(filter) => Arc::new(FilteredDialer::new(counted, Arc::new(filter))),
            None => counted,
        };

        let started = start_proxies(&cfg, &access, &logger, Arc::clone(&upstream)).await;
        // Both TLS contexts are built, so the passphrase is no longer needed.
        scrub_passphrase(&mut cfg);
        let (reverse, mitm) = match started {
            Ok(parts) => parts,
            Err(message) => {
                let _ = access.shutdown().await;
                logger.flush();
                return Err(LinkError::Fatal(message));
            }
        };

        for hop in profile.hops.iter().filter(|h| h.agent_forward && h.agent_forward_keys.is_empty()) {
            logs.push(&format!(
                "notice: agent forwarding is on for hop {} but no keys are assigned, so no agent channel will be opened",
                hop.hop_id
            ));
        }

        Ok(Self {
            profile,
            cfg,
            options,
            verifier: HostKeyVerifier::from_shared(known_hosts),
            vault,
            logger,
            access,
            reverse,
            dialer,
            upstream,
            mitm,
            server: None,
            relay: None,
            agent_relays: Vec::new(),
            logs,
            disconnects: None,
            listeners,
        })
    }

    /// Binds the forward listeners once. They then stay bound across reconnects.
    async fn ensure_server(&mut self) -> Result<(), LinkError> {
        if self.server.is_some() || !self.cfg.forward_enabled() {
            return Ok(());
        }
        let (http, socks) = build_engines(
            &self.cfg,
            self.mitm.as_ref(),
            &self.access,
            &self.logger,
            Arc::clone(&self.upstream),
        );
        let handlers: Arc<dyn ProtocolHandlers> = Arc::new(EngineHandlers::new(http, socks));
        let server = Server::from_config(&self.cfg, handlers, self.logger.clone())
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

    async fn drop_connection(&mut self) {
        self.disconnects = None;
        // Dropping a relay stops serving and closes its session channel.
        self.agent_relays.clear();
        let relay = self.relay.take();
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

fn scrub_passphrase(cfg: &mut Config) {
    if let Some(mut passphrase) = cfg.mitm_ca_passphrase.take() {
        passphrase.zeroize();
    }
}

async fn start_proxies(
    cfg: &Config,
    access: &AccessLogger,
    logger: &Logger,
    upstream: Arc<dyn UpstreamDialer>,
) -> Result<(Option<ReverseProxy>, Option<MitmState>), String> {
    let reverse = ReverseProxy::start(cfg, access, logger).await?;
    if !cfg.forward_enabled() {
        return Ok((reverse, None));
    }
    let mitm = MitmState::from_config(cfg, upstream).map_err(|e| format!("MITM setup failed: {e}"));
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
            let (policy, inbound): (ChannelPolicy, Option<ReverseInbound>) =
                if self.reverse.is_some() {
                    let (policy, inbound) = reverse_policy(REVERSE_CHANNEL_CAPACITY);
                    (policy, Some(inbound))
                } else {
                    (ChannelPolicy::default(), None)
                };
            let (hops, pending) = {
                let vault = self.vault.read().unwrap_or_else(PoisonError::into_inner);
                if needs_secrets(&self.profile) && !vault.is_unlocked() {
                    return Err(LinkError::Locked);
                }
                let mut hops = resolve_hops(&self.profile, &vault, policy)?;
                let pending = attach_agents(&self.profile, &vault, &self.logs, &mut hops)?;
                (hops, pending)
            };

            let (events, receiver) = mpsc::unbounded_channel();
            let chain = connect_chain(&hops, &self.verifier, &self.options, Some(events))
                .await
                .map_err(classify)?;
            drop(hops);

            let agent_relays = match start_agent_relays(&chain, pending).await {
                Ok(relays) => relays,
                Err(error) => {
                    chain.disconnect().await;
                    return Err(error);
                }
            };
            if let (Some(reverse), Some(inbound)) = (&self.reverse, inbound) {
                match ReverseRelay::start(&chain, reverse.forwards(), inbound).await {
                    Ok(relay) => self.relay = Some(relay),
                    Err(error) => {
                        drop(agent_relays);
                        chain.disconnect().await;
                        return Err(classify_reverse(error));
                    }
                }
            }
            self.agent_relays = agent_relays;
            self.dialer.swap(chain);
            self.disconnects = Some(receiver);
            self.ensure_server().await
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
            if let Some(server) = this.server.take() {
                server.token.cancel();
                if let Ok(report) = server.run.await {
                    if report.drained {
                        this.logger.debug("all connections drained");
                    }
                }
                if let Some(reaper) = server.reaper {
                    let _ = reaper.await;
                }
            }
            this.drop_connection().await;
            if let Some(reverse) = this.reverse.take() {
                if reverse.shutdown().await.drained {
                    this.logger.debug("all reverse proxy connections drained");
                }
            }
            this.logger.info("shutting down");
            if let Err(e) = this.access.shutdown().await {
                this.logger.error(format!("failed to flush access logs: {e}"));
            }
            this.logger.flush();
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

    fn agent_hop(agent_forward: bool, keys: Vec<conduit_core::KeyId>) -> HopEntry {
        HopEntry {
            agent_forward,
            agent_forward_keys: keys,
            ..Default::default()
        }
    }

    #[test]
    fn needs_secrets_only_for_agent_hops_with_keys() {
        let key = conduit_core::KeyId::new();
        let with = |hop| SessionProfile {
            hops: vec![hop],
            ..Default::default()
        };
        assert!(needs_secrets(&with(agent_hop(true, vec![key.clone()]))));
        assert!(!needs_secrets(&with(agent_hop(true, Vec::new()))));
        assert!(!needs_secrets(&with(agent_hop(false, vec![key]))));
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
    fn classify_routes_each_failure() {
        assert!(matches!(
            classify(SshError::HostKeyUnknown {
                hop_index: 1,
                hop_id: "b".into(),
                host: "h".into(),
                port: 22,
                algorithm: "ssh-ed25519".into(),
                sha256: "SHA256:x".into(),
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
