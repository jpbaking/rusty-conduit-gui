//! Sequential multi-hop connect: `Hop 0 → Hop 1 → … → Target` over nested `direct-tcpip`.
//!
//! Each hop authenticates end to end, so private keys never reach a jump host. Each
//! configured credential is tried at most once per attempt to protect against lockouts.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use conduit_core::TunnelConfig;
use russh::client::{self, AuthResult, Handle, KeyboardInteractiveAuthResponse, Msg};
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg};
use russh::{Channel, Disconnect};
use tokio::net::{lookup_host, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;
use zeroize::Zeroizing;

use crate::error::SshError;
use crate::handler::{ChannelPolicy, DisconnectEvent, HopHandler};
use crate::host_key::{HopIdentity, HostKeyVerifier};

/// Upper bound on keyboard-interactive rounds, so a server cannot loop the client forever.
const MAX_KEYBOARD_ROUNDS: usize = 8;

/// A saved answer for one keyboard-interactive prompt.
#[derive(Clone)]
pub struct KeyboardAnswer {
    /// Matched against the server's prompt, ignoring case and outer whitespace.
    pub prompt: String,
    pub answer: Zeroizing<String>,
}

/// A credential already unlocked from the vault, held in memory only.
#[derive(Clone)]
pub enum HopAuth {
    Key(Arc<PrivateKey>),
    Password(Zeroizing<String>),
    /// Only answers prompts it recognizes. A secret is never sent to an unexpected prompt.
    KeyboardInteractive(Vec<KeyboardAnswer>),
}

impl HopAuth {
    fn method_name(&self) -> &'static str {
        match self {
            HopAuth::Key(_) => "publickey",
            HopAuth::Password(_) => "password",
            HopAuth::KeyboardInteractive(_) => "keyboard-interactive",
        }
    }
}

impl fmt::Debug for HopAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HopAuth::{}(<redacted>)", self.method_name())
    }
}

/// One fully resolved hop. The last hop in a chain is the SSH target.
#[derive(Debug, Clone)]
pub struct HopSpec {
    pub hop_id: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    /// Tried in order.
    pub auth: Vec<HopAuth>,
    pub policy: ChannelPolicy,
}

impl HopSpec {
    fn identity(&self, hop_index: usize) -> HopIdentity {
        HopIdentity {
            hop_index,
            hop_id: self.hop_id.clone(),
            host: self.host.clone(),
            port: self.port,
        }
    }
}

/// Address family used for the first hop's TCP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpPreference {
    V4,
    V6,
    Auto,
}

impl IpPreference {
    /// Parses the stored `"4" | "6" | "auto"` value. Anything else is rejected.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "4" => Some(Self::V4),
            "6" => Some(Self::V6),
            "auto" => Some(Self::Auto),
            _ => None,
        }
    }

    fn accepts(self, addr: &SocketAddr) -> bool {
        match self {
            Self::V4 => addr.is_ipv4(),
            Self::V6 => addr.is_ipv6(),
            Self::Auto => true,
        }
    }
}

/// Transport settings applied to every hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainOptions {
    /// `ServerAliveInterval`. Zero disables keepalives.
    pub keepalive_interval: Duration,
    /// `ServerAliveCountMax`.
    pub keepalive_max: usize,
    /// Limit for connecting and authenticating one hop.
    pub connect_timeout: Duration,
    pub ip_preference: IpPreference,
}

impl ChainOptions {
    /// Builds options from a session's tunnel settings.
    pub fn from_tunnel(tunnel: &TunnelConfig) -> Result<Self, SshError> {
        let ip_preference = IpPreference::parse(&tunnel.ip_version).ok_or_else(|| {
            SshError::InvalidChain(format!("invalid ip_version {:?}", tunnel.ip_version))
        })?;
        Ok(Self {
            keepalive_interval: tunnel.server_alive_interval,
            keepalive_max: tunnel.server_alive_count_max as usize,
            connect_timeout: tunnel.startup_timeout,
            ip_preference,
        })
    }

    fn client_config(&self) -> Arc<client::Config> {
        Arc::new(client::Config {
            keepalive_interval: Some(self.keepalive_interval).filter(|d| !d.is_zero()),
            keepalive_max: self.keepalive_max,
            inactivity_timeout: None,
            nodelay: true,
            ..client::Config::default()
        })
    }
}

/// A connected, authenticated chain. Holds every hop open.
pub struct SshChain {
    /// Ordered from first hop to target.
    handles: Vec<Handle<HopHandler>>,
}

impl fmt::Debug for SshChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshChain")
            .field("hops", &self.handles.len())
            .finish()
    }
}

impl SshChain {
    pub fn hop_count(&self) -> usize {
        self.handles.len()
    }

    /// The final hop's session.
    pub fn target(&self) -> &Handle<HopHandler> {
        self.handles
            .last()
            .expect("connect_chain rejects an empty chain")
    }

    /// The session of hop `index`, counted from the first hop.
    pub fn hop(&self, index: usize) -> Option<&Handle<HopHandler>> {
        self.handles.get(index)
    }

    /// `true` once any hop's session has ended, which breaks the whole chain.
    pub fn is_closed(&self) -> bool {
        self.handles.iter().any(Handle::is_closed)
    }

    /// Opens a `direct-tcpip` channel from the target to `host:port`.
    pub async fn open_direct_tcpip(
        &self,
        host: &str,
        port: u16,
    ) -> Result<Channel<Msg>, russh::Error> {
        self.target()
            .channel_open_direct_tcpip(host, u32::from(port), "127.0.0.1", 0)
            .await
    }

    /// Disconnects from the target back to the first hop.
    pub async fn disconnect(self) {
        disconnect_all(self.handles).await;
    }
}

async fn disconnect_all(mut handles: Vec<Handle<HopHandler>>) {
    while let Some(handle) = handles.pop() {
        // The session may already be gone, and teardown continues either way.
        let _ = handle
            .disconnect(Disconnect::ByApplication, "closing", "en")
            .await;
    }
}

/// Connects and authenticates every hop in order, stopping at the first failure.
pub async fn connect_chain(
    hops: &[HopSpec],
    verifier: &HostKeyVerifier,
    options: &ChainOptions,
    disconnects: Option<mpsc::UnboundedSender<DisconnectEvent>>,
) -> Result<SshChain, SshError> {
    if hops.is_empty() {
        return Err(SshError::InvalidChain("chain has no hops".into()));
    }
    let mut handles: Vec<Handle<HopHandler>> = Vec::with_capacity(hops.len());
    for (index, spec) in hops.iter().enumerate() {
        let handler = HopHandler::new(
            spec.identity(index),
            verifier.clone(),
            spec.policy.clone(),
            disconnects.clone(),
        );
        match connect_hop(index, spec, handles.last(), handler, options).await {
            Ok(handle) => handles.push(handle),
            Err(error) => {
                disconnect_all(handles).await;
                return Err(error);
            }
        }
    }
    Ok(SshChain { handles })
}

/// Result of probing one hop.
#[derive(Debug)]
pub enum HopStatus {
    Connected,
    Failed(SshError),
    /// An earlier hop failed, so this one was not reached.
    NotAttempted,
}

/// Per-hop outcome of [`test_chain`].
#[derive(Debug)]
pub struct HopDiagnostic {
    pub hop_index: usize,
    pub hop_id: String,
    pub host: String,
    pub port: u16,
    pub status: HopStatus,
    /// Time spent on this hop. Zero if it was not attempted.
    pub elapsed: Duration,
}

/// Report from [`test_chain`], with one entry per configured hop.
#[derive(Debug)]
pub struct ChainTestReport {
    pub hops: Vec<HopDiagnostic>,
}

impl ChainTestReport {
    pub fn all_connected(&self) -> bool {
        !self.hops.is_empty()
            && self
                .hops
                .iter()
                .all(|h| matches!(h.status, HopStatus::Connected))
    }

    /// The first failed hop, which is where the chain broke.
    pub fn first_failure(&self) -> Option<&HopDiagnostic> {
        self.hops
            .iter()
            .find(|h| matches!(h.status, HopStatus::Failed(_)))
    }
}

/// Probes the chain prefix by prefix, then disconnects.
///
/// Stops at the first failure so a bad credential is not repeated. Every server-initiated
/// channel is denied during a test, whatever the hop's policy says.
pub async fn test_chain(
    hops: &[HopSpec],
    verifier: &HostKeyVerifier,
    options: &ChainOptions,
) -> ChainTestReport {
    let mut handles: Vec<Handle<HopHandler>> = Vec::with_capacity(hops.len());
    let mut diagnostics = Vec::with_capacity(hops.len());
    let mut broken = false;

    for (index, spec) in hops.iter().enumerate() {
        let started = Instant::now();
        let status = if broken {
            HopStatus::NotAttempted
        } else {
            let handler = HopHandler::new(
                spec.identity(index),
                verifier.clone(),
                ChannelPolicy::default(),
                None,
            );
            match connect_hop(index, spec, handles.last(), handler, options).await {
                Ok(handle) => {
                    handles.push(handle);
                    HopStatus::Connected
                }
                Err(error) => {
                    broken = true;
                    HopStatus::Failed(error)
                }
            }
        };
        let elapsed = if matches!(status, HopStatus::NotAttempted) {
            Duration::ZERO
        } else {
            started.elapsed()
        };
        diagnostics.push(HopDiagnostic {
            hop_index: index,
            hop_id: spec.hop_id.clone(),
            host: spec.host.clone(),
            port: spec.port,
            status,
            elapsed,
        });
    }

    disconnect_all(handles).await;
    ChainTestReport { hops: diagnostics }
}

async fn connect_hop(
    index: usize,
    spec: &HopSpec,
    previous: Option<&Handle<HopHandler>>,
    handler: HopHandler,
    options: &ChainOptions,
) -> Result<Handle<HopHandler>, SshError> {
    let attempt = async {
        let config = options.client_config();
        let connected = match previous {
            None => {
                let stream = open_tcp(index, spec, options.ip_preference).await?;
                client::connect_stream(config, stream, handler).await
            }
            Some(previous) => {
                let channel = previous
                    .channel_open_direct_tcpip(
                        spec.host.as_str(),
                        u32::from(spec.port),
                        "127.0.0.1",
                        0,
                    )
                    .await
                    .map_err(|e| SshError::TunnelOpen {
                        hop_index: index,
                        hop_id: spec.hop_id.clone(),
                        host: spec.host.clone(),
                        port: spec.port,
                        detail: e.to_string(),
                    })?;
                client::connect_stream(config, channel.into_stream(), handler).await
            }
        };
        let mut handle = connected.map_err(|e| with_hop_context(e, index, spec))?;
        authenticate(&mut handle, index, spec).await?;
        Ok(handle)
    };
    timeout(options.connect_timeout, attempt)
        .await
        .map_err(|_| SshError::Timeout {
            hop_index: index,
            hop_id: spec.hop_id.clone(),
        })?
}

/// Adds hop details to a bare protocol error. Typed errors pass through unchanged.
fn with_hop_context(error: SshError, index: usize, spec: &HopSpec) -> SshError {
    match error {
        SshError::Protocol(e) => SshError::Connect {
            hop_index: index,
            hop_id: spec.hop_id.clone(),
            host: spec.host.clone(),
            port: spec.port,
            detail: e.to_string(),
        },
        other => other,
    }
}

async fn open_tcp(
    index: usize,
    spec: &HopSpec,
    preference: IpPreference,
) -> Result<TcpStream, SshError> {
    let failed = |detail: String| SshError::Connect {
        hop_index: index,
        hop_id: spec.hop_id.clone(),
        host: spec.host.clone(),
        port: spec.port,
        detail,
    };
    let addrs = lookup_host((spec.host.as_str(), spec.port))
        .await
        .map_err(|e| failed(format!("name resolution failed: {e}")))?;

    let mut last_error = None;
    for addr in addrs.filter(|a| preference.accepts(a)) {
        match TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last_error = Some(format!("{addr}: {e}")),
        }
    }
    Err(failed(last_error.unwrap_or_else(|| {
        format!("no address matches IP preference {preference:?}")
    })))
}

/// The outcome of trying one credential.
enum AuthStep {
    Accepted,
    Rejected(String),
    /// The connection ended, so the server gave no verdict.
    ConnectionLost(String),
}

async fn authenticate(
    handle: &mut Handle<HopHandler>,
    index: usize,
    spec: &HopSpec,
) -> Result<(), SshError> {
    if spec.auth.is_empty() {
        return Err(SshError::AuthFailed {
            hop_index: index,
            hop_id: spec.hop_id.clone(),
            detail: "no authentication methods configured".into(),
        });
    }

    let mut rejected = Vec::with_capacity(spec.auth.len());
    for method in &spec.auth {
        let step = match method {
            HopAuth::Key(key) => auth_key(handle, &spec.user, key).await,
            HopAuth::Password(password) => auth_password(handle, &spec.user, password).await,
            HopAuth::KeyboardInteractive(answers) => {
                auth_keyboard(handle, &spec.user, answers).await
            }
        };
        match step {
            AuthStep::Accepted => return Ok(()),
            AuthStep::Rejected(detail) => {
                rejected.push(format!("{}: {detail}", method.method_name()));
            }
            AuthStep::ConnectionLost(detail) => {
                return Err(SshError::Disconnected {
                    hop_index: index,
                    hop_id: spec.hop_id.clone(),
                    detail,
                });
            }
        }
    }
    Err(SshError::AuthFailed {
        hop_index: index,
        hop_id: spec.hop_id.clone(),
        detail: rejected.join("; "),
    })
}

/// russh reports a dead session as a failure with no methods left. A real rejection on a
/// live or closing connection names the methods that remain, so it stays a rejection.
fn classify_failure(
    handle: &Handle<HopHandler>,
    remaining_methods_empty: bool,
    partial_success: bool,
) -> AuthStep {
    if remaining_methods_empty && !partial_success && handle.is_closed() {
        AuthStep::ConnectionLost("session closed before the server replied".into())
    } else if partial_success {
        AuthStep::Rejected("partial success, further authentication required".into())
    } else {
        AuthStep::Rejected("rejected by server".into())
    }
}

fn step_from_result(handle: &Handle<HopHandler>, result: Result<AuthResult, russh::Error>) -> AuthStep {
    match result {
        Ok(AuthResult::Success) => AuthStep::Accepted,
        Ok(AuthResult::Failure {
            remaining_methods,
            partial_success,
        }) => classify_failure(handle, remaining_methods.is_empty(), partial_success),
        Err(e) => AuthStep::ConnectionLost(e.to_string()),
    }
}

async fn auth_key(handle: &mut Handle<HopHandler>, user: &str, key: &Arc<PrivateKey>) -> AuthStep {
    let hash = if key.algorithm().is_rsa() {
        match handle.best_supported_rsa_hash().await {
            Ok(Some(Some(hash))) => Some(hash),
            Ok(None) => Some(HashAlg::Sha512),
            Ok(Some(None)) => {
                return AuthStep::Rejected("server only supports SHA-1 RSA signatures".into())
            }
            Err(e) => return AuthStep::ConnectionLost(e.to_string()),
        }
    } else {
        None
    };
    let signer = PrivateKeyWithHashAlg::new(Arc::clone(key), hash);
    let result = handle.authenticate_publickey(user, signer).await;
    step_from_result(handle, result)
}

async fn auth_password(
    handle: &mut Handle<HopHandler>,
    user: &str,
    password: &Zeroizing<String>,
) -> AuthStep {
    let result = handle
        .authenticate_password(user, password.as_str())
        .await;
    step_from_result(handle, result)
}

fn answer_for<'a>(answers: &'a [KeyboardAnswer], prompt: &str) -> Option<&'a str> {
    let prompt = prompt.trim();
    answers
        .iter()
        .find(|a| a.prompt.trim().eq_ignore_ascii_case(prompt))
        .map(|a| a.answer.as_str())
}

async fn auth_keyboard(
    handle: &mut Handle<HopHandler>,
    user: &str,
    answers: &[KeyboardAnswer],
) -> AuthStep {
    let mut reply = handle
        .authenticate_keyboard_interactive_start(user, None::<String>)
        .await;

    for _ in 0..MAX_KEYBOARD_ROUNDS {
        match reply {
            Err(e) => return AuthStep::ConnectionLost(e.to_string()),
            Ok(KeyboardInteractiveAuthResponse::Success) => return AuthStep::Accepted,
            Ok(KeyboardInteractiveAuthResponse::Failure {
                remaining_methods,
                partial_success,
            }) => return classify_failure(handle, remaining_methods.is_empty(), partial_success),
            Ok(KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. }) => {
                let mut responses = Vec::with_capacity(prompts.len());
                for prompt in &prompts {
                    match answer_for(answers, &prompt.prompt) {
                        Some(answer) => responses.push(answer.to_string()),
                        None => {
                            return AuthStep::Rejected(format!(
                                "no saved answer for prompt {:?}",
                                prompt.prompt
                            ))
                        }
                    }
                }
                reply = handle
                    .authenticate_keyboard_interactive_respond(responses)
                    .await;
            }
        }
    }
    AuthStep::Rejected("too many keyboard-interactive rounds".into())
}

#[cfg(test)]
mod tests;
