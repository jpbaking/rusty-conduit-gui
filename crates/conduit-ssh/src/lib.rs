//! `conduit-ssh` — pure-Rust (`russh` + `ring`) multi-hop chain, host-key pinning, and
//! scoped agent used to log into hops.
//!
//! Never reads `~/.ssh/config`, `~/.ssh/id_*`, `~/.ssh/known_hosts`, or `SSH_AUTH_SOCK`.

// `SshError` keeps the flat host-key fields the runtime and UI read directly. It is only built
// on connection failure, so its size has no effect on a hot path.
#![allow(clippy::result_large_err)]

pub mod agent;
pub mod agent_wire;
pub mod chain;
pub mod dialer;
pub mod error;
pub mod handler;
pub mod host_key;
mod nested;
pub mod reverse;
pub mod stats;

pub use agent::{
    AgentError, AgentIdentity, AgentRequest, AgentResponse, MutationOp, ScopedAgent, SignAudit,
    SignAuditFn,
};
pub use chain::{
    connect_chain, test_chain, ChainOptions, ChainTestReport, HopAuth, HopDiagnostic, HopSpec,
    HopStatus, IpPreference, KeyboardAnswer, SshChain,
};
pub use dialer::RusshDialer;
pub use error::SshError;
pub use handler::{ChannelPolicy, DisconnectEvent, ForwardAllowlist, HopHandler, InboundForward};
pub use host_key::{HopIdentity, HostKeyDecision, HostKeyVerifier, ObservedHostKey};
pub use reverse::{reverse_policy, RemoteForward, ReverseError, ReverseInbound, ReverseRelay};
pub use stats::{AtomicStats, StatsDialer, StatsSnapshot};
