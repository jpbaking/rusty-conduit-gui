//! Hardened `russh` client handler.
//!
//! russh's defaults accept every server-initiated channel. This handler denies them all,
//! except agent channels on an opted-in hop and `forwarded-tcpip` to an allowlisted address.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use russh::client::{self, ChannelOpenHandle, DisconnectReason, Msg, Session};
use russh::keys::PublicKeyOrCertificate;
use russh::{Channel, ChannelOpenFailure};
use tokio::sync::mpsc;

use crate::error::SshError;
use crate::host_key::{HopIdentity, HostKeyVerifier, ObservedHostKey};

/// The `(remote_addr, remote_port)` reverse forwards explicitly requested on a hop.
#[derive(Debug, Clone, Default)]
pub struct ForwardAllowlist {
    entries: Arc<RwLock<HashSet<(String, u32)>>>,
}

impl ForwardAllowlist {
    pub fn allow(&self, remote_addr: impl Into<String>, remote_port: u32) {
        if let Ok(mut entries) = self.entries.write() {
            entries.insert((remote_addr.into(), remote_port));
        }
    }

    pub fn revoke(&self, remote_addr: &str, remote_port: u32) {
        if let Ok(mut entries) = self.entries.write() {
            entries.remove(&(remote_addr.to_string(), remote_port));
        }
    }

    /// Exact match only. A poisoned lock denies.
    pub fn contains(&self, remote_addr: &str, remote_port: u32) -> bool {
        self.entries
            .read()
            .map(|e| e.contains(&(remote_addr.to_string(), remote_port)))
            .unwrap_or(false)
    }
}

/// An accepted inbound `forwarded-tcpip` channel.
#[derive(Debug)]
pub struct InboundForward {
    pub channel: Channel<Msg>,
    pub connected_address: String,
    pub connected_port: u32,
    pub originator_address: String,
    pub originator_port: u32,
}

/// Which server-initiated channels a hop accepts. The default denies everything.
#[derive(Debug, Clone, Default)]
pub struct ChannelPolicy {
    /// `Some` is the per-hop agent-forwarding opt-in; accepted channels are delivered here.
    pub agent_channels: Option<mpsc::Sender<Channel<Msg>>>,
    pub forward_allowlist: ForwardAllowlist,
    /// Accepted reverse forwards are delivered here. `None` denies all of them.
    pub forward_channels: Option<mpsc::Sender<InboundForward>>,
}

impl ChannelPolicy {
    pub fn allows_agent_forward(&self) -> bool {
        self.agent_channels.is_some()
    }

    pub fn allows_forward(&self, connected_address: &str, connected_port: u32) -> bool {
        self.forward_channels.is_some()
            && self
                .forward_allowlist
                .contains(connected_address, connected_port)
    }
}

/// A hop's SSH session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisconnectEvent {
    pub hop_index: usize,
    pub hop_id: String,
    pub detail: String,
}

/// The `russh` handler for one hop.
#[derive(Debug)]
pub struct HopHandler {
    hop: HopIdentity,
    verifier: HostKeyVerifier,
    policy: ChannelPolicy,
    disconnects: Option<mpsc::UnboundedSender<DisconnectEvent>>,
}

impl HopHandler {
    pub fn new(
        hop: HopIdentity,
        verifier: HostKeyVerifier,
        policy: ChannelPolicy,
        disconnects: Option<mpsc::UnboundedSender<DisconnectEvent>>,
    ) -> Self {
        Self {
            hop,
            verifier,
            policy,
            disconnects,
        }
    }
}

impl client::Handler for HopHandler {
    type Error = SshError;

    /// Runs before any credential is sent, and again on every re-key.
    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, SshError> {
        let observed = ObservedHostKey::from_server_key(server_public_key);
        self.verifier.enforce(&self.hop, &observed)?;
        Ok(true)
    }

    async fn server_channel_open_agent_forward(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), SshError> {
        let Some(sink) = &self.policy.agent_channels else {
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        };
        match sink.try_reserve() {
            Ok(permit) => {
                reply.accept().await;
                permit.send(channel);
            }
            Err(_) => reply.reject(ChannelOpenFailure::ResourceShortage).await,
        }
        Ok(())
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), SshError> {
        let sink = self
            .policy
            .forward_channels
            .as_ref()
            .filter(|_| self.policy.allows_forward(connected_address, connected_port));
        let Some(sink) = sink else {
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        };
        match sink.try_reserve() {
            Ok(permit) => {
                reply.accept().await;
                permit.send(InboundForward {
                    channel,
                    connected_address: connected_address.to_string(),
                    connected_port,
                    originator_address: originator_address.to_string(),
                    originator_port,
                });
            }
            Err(_) => reply.reject(ChannelOpenFailure::ResourceShortage).await,
        }
        Ok(())
    }

    async fn server_channel_open_forwarded_streamlocal(
        &mut self,
        _channel: Channel<Msg>,
        _socket_path: &str,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), SshError> {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn server_channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), SshError> {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn server_channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), SshError> {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn server_channel_open_direct_streamlocal(
        &mut self,
        _channel: Channel<Msg>,
        _socket_path: &str,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), SshError> {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn server_channel_open_x11(
        &mut self,
        _channel: Channel<Msg>,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), SshError> {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn disconnected(
        &mut self,
        reason: DisconnectReason<SshError>,
    ) -> Result<(), SshError> {
        let (detail, result) = match reason {
            DisconnectReason::ReceivedDisconnect(info) => (
                format!("server disconnected: {:?}: {}", info.reason_code, info.message),
                Ok(()),
            ),
            DisconnectReason::Error(e) => (e.to_string(), Err(e)),
        };
        if let Some(tx) = &self.disconnects {
            let _ = tx.send(DisconnectEvent {
                hop_index: self.hop.hop_index,
                hop_id: self.hop.hop_id.clone(),
                detail,
            });
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use conduit_core::{HostKeyLookup, HostKeyRecord, KnownHostsStore, Timestamp};
    use conduit_vault::{generate_key, KeyGenAlgorithm};
    use russh::client::Handler;
    use russh::keys::{HashAlg, PublicKey};

    fn hop() -> HopIdentity {
        HopIdentity {
            hop_index: 1,
            hop_id: "hop-b".into(),
            host: "b.test".into(),
            port: 2200,
        }
    }

    fn public_key() -> PublicKey {
        generate_key(KeyGenAlgorithm::Ed25519)
            .unwrap()
            .0
            .public_key()
            .clone()
    }

    fn pinned(key: &PublicKey) -> HostKeyVerifier {
        let mut store = KnownHostsStore::default();
        store.insert(
            HostKeyLookup {
                hop_id: "hop-b".into(),
                host: "b.test".into(),
                port: 2200,
            },
            HostKeyRecord {
                algorithm: key.algorithm().as_str().to_string(),
                fingerprint_sha256: key.fingerprint(HashAlg::Sha256).to_string(),
                first_seen: Timestamp(1),
                approved: true,
            },
        );
        HostKeyVerifier::new(store)
    }

    #[test]
    fn default_policy_denies_agent_and_forwards() {
        let policy = ChannelPolicy::default();
        assert!(!policy.allows_agent_forward());
        assert!(!policy.allows_forward("127.0.0.1", 8080));
    }

    #[test]
    fn agent_forward_requires_opt_in() {
        let (tx, _rx) = mpsc::channel(1);
        let policy = ChannelPolicy {
            agent_channels: Some(tx),
            ..ChannelPolicy::default()
        };
        assert!(policy.allows_agent_forward());
    }

    #[test]
    fn forward_requires_exact_allowlist_match_and_a_consumer() {
        let allowlist = ForwardAllowlist::default();
        allowlist.allow("127.0.0.1", 8080);

        let no_consumer = ChannelPolicy {
            forward_allowlist: allowlist.clone(),
            ..ChannelPolicy::default()
        };
        assert!(!no_consumer.allows_forward("127.0.0.1", 8080));

        let (tx, _rx) = mpsc::channel(1);
        let policy = ChannelPolicy {
            forward_allowlist: allowlist.clone(),
            forward_channels: Some(tx),
            ..ChannelPolicy::default()
        };
        assert!(policy.allows_forward("127.0.0.1", 8080));
        assert!(!policy.allows_forward("127.0.0.1", 8081));
        assert!(!policy.allows_forward("0.0.0.0", 8080));

        allowlist.revoke("127.0.0.1", 8080);
        assert!(!policy.allows_forward("127.0.0.1", 8080));
    }

    #[tokio::test]
    async fn check_server_key_accepts_only_the_pinned_key() {
        let key = public_key();
        let mut handler = HopHandler::new(hop(), pinned(&key), ChannelPolicy::default(), None);
        assert!(handler
            .check_server_key(&PublicKeyOrCertificate::from(key))
            .await
            .unwrap());

        let other = PublicKeyOrCertificate::from(public_key());
        assert!(matches!(
            handler.check_server_key(&other).await,
            Err(SshError::HostKeyChanged { hop_index: 1, .. })
        ));
    }

    #[tokio::test]
    async fn check_server_key_never_trusts_an_unknown_key() {
        let mut handler = HopHandler::new(
            hop(),
            HostKeyVerifier::default(),
            ChannelPolicy::default(),
            None,
        );
        let key = PublicKeyOrCertificate::from(public_key());
        assert!(matches!(
            handler.check_server_key(&key).await,
            Err(SshError::HostKeyUnknown { hop_index: 1, .. })
        ));
    }

    #[tokio::test]
    async fn disconnect_is_reported_and_errors_are_returned() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut handler = HopHandler::new(
            hop(),
            HostKeyVerifier::default(),
            ChannelPolicy::default(),
            Some(tx),
        );
        let result = handler
            .disconnected(DisconnectReason::Error(SshError::Protocol(
                russh::Error::Disconnect,
            )))
            .await;
        assert!(result.is_err());
        let event = rx.recv().await.unwrap();
        assert_eq!((event.hop_index, event.hop_id.as_str()), (1, "hop-b"));
    }
}
