//! Typed SSH failures, classified so the runtime can tell "retry" from "stop".

use thiserror::Error;

/// A failure while building or running a multi-hop SSH chain.
///
/// Secrets never appear in these values: `detail` fields hold method names and server
/// status only.
#[derive(Debug, Error)]
pub enum SshError {
    /// The hop presented a key with no approved pin. Requires a user decision.
    #[error(
        "unknown host key on hop {hop_index} ({hop_id}) {host}:{port}: {algorithm} {sha256}"
    )]
    HostKeyUnknown {
        hop_index: usize,
        hop_id: String,
        host: String,
        port: u16,
        algorithm: String,
        sha256: String,
    },

    /// The hop presented a key that differs from its pin. Hard stop.
    #[error(
        "host key CHANGED on hop {hop_index} ({hop_id}) {host}:{port}: \
         expected {expected_sha256}, got {algorithm} {sha256}"
    )]
    HostKeyChanged {
        hop_index: usize,
        hop_id: String,
        host: String,
        port: u16,
        algorithm: String,
        expected_sha256: String,
        sha256: String,
    },

    /// The server rejected every configured credential.
    #[error("authentication failed on hop {hop_index} ({hop_id}): {detail}")]
    AuthFailed {
        hop_index: usize,
        hop_id: String,
        detail: String,
    },

    /// The transport to this hop could not be established.
    #[error("connection to hop {hop_index} ({hop_id}) {host}:{port} failed: {detail}")]
    Connect {
        hop_index: usize,
        hop_id: String,
        host: String,
        port: u16,
        detail: String,
    },

    /// The previous hop refused to open a tunnel to this hop.
    #[error("could not open tunnel to hop {hop_index} ({hop_id}) {host}:{port}: {detail}")]
    TunnelOpen {
        hop_index: usize,
        hop_id: String,
        host: String,
        port: u16,
        detail: String,
    },

    /// The connection dropped during authentication, so no verdict was received.
    #[error("hop {hop_index} ({hop_id}) disconnected during authentication: {detail}")]
    Disconnected {
        hop_index: usize,
        hop_id: String,
        detail: String,
    },

    /// Connecting and authenticating this hop exceeded the startup timeout.
    #[error("timed out connecting to hop {hop_index} ({hop_id})")]
    Timeout { hop_index: usize, hop_id: String },

    /// The chain definition cannot be run.
    #[error("invalid chain: {0}")]
    InvalidChain(String),

    /// A lower-level SSH protocol error.
    #[error("ssh protocol error: {0}")]
    Protocol(#[from] russh::Error),
}

impl SshError {
    /// `true` when an automatic retry could lock an account or bypass host-key trust.
    /// The runtime must halt reconnects and ask the user.
    pub fn is_lockout_sensitive(&self) -> bool {
        matches!(
            self,
            SshError::AuthFailed { .. }
                | SshError::HostKeyUnknown { .. }
                | SshError::HostKeyChanged { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_key_and_auth_failures_are_lockout_sensitive() {
        let sensitive = [
            SshError::AuthFailed {
                hop_index: 0,
                hop_id: "a".into(),
                detail: "password rejected".into(),
            },
            SshError::HostKeyUnknown {
                hop_index: 0,
                hop_id: "a".into(),
                host: "h".into(),
                port: 22,
                algorithm: "ssh-ed25519".into(),
                sha256: "SHA256:x".into(),
            },
            SshError::HostKeyChanged {
                hop_index: 0,
                hop_id: "a".into(),
                host: "h".into(),
                port: 22,
                algorithm: "ssh-ed25519".into(),
                expected_sha256: "SHA256:y".into(),
                sha256: "SHA256:x".into(),
            },
        ];
        assert!(sensitive.iter().all(SshError::is_lockout_sensitive));
    }

    #[test]
    fn transient_failures_may_be_retried() {
        let transient = [
            SshError::Connect {
                hop_index: 1,
                hop_id: "b".into(),
                host: "h".into(),
                port: 22,
                detail: "refused".into(),
            },
            SshError::Disconnected {
                hop_index: 1,
                hop_id: "b".into(),
                detail: "reset".into(),
            },
            SshError::Timeout {
                hop_index: 1,
                hop_id: "b".into(),
            },
            SshError::Protocol(russh::Error::Disconnect),
        ];
        assert!(!transient.iter().any(SshError::is_lockout_sensitive));
    }
}
