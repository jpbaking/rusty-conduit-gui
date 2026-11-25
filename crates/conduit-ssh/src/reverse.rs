//! Reverse forwarding (`ssh -R`): publishes local `ReverseProxy` listeners on the final hop.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

use russh::client::Msg;
use russh::Channel;
use rusty_conduit_ssh::ssh::ReverseForward;
use thiserror::Error;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};

use crate::chain::SshChain;
use crate::handler::{ChannelPolicy, ForwardAllowlist, InboundForward};

/// One `tcpip-forward` to request on the final hop, and where its connections go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteForward {
    /// Address and port to listen on, on the final hop.
    pub remote: SocketAddr,
    /// Destination host, resolved by this machine. A name or an IP literal.
    pub host: String,
    pub port: u16,
}

impl From<&ReverseForward> for RemoteForward {
    fn from(forward: &ReverseForward) -> Self {
        Self {
            remote: forward.remote,
            host: forward.local.ip().to_string(),
            port: forward.local.port(),
        }
    }
}

/// A reverse forward could not be established.
#[derive(Debug, Error)]
pub enum ReverseError {
    /// The same remote address appears twice.
    #[error("duplicate reverse forward for {0}")]
    Duplicate(SocketAddr),

    /// The final hop refused the `tcpip-forward` request, or the session failed.
    #[error("reverse forward on {remote} failed: {source}")]
    Request {
        remote: SocketAddr,
        #[source]
        source: russh::Error,
    },
}

/// The receiving half of a reverse-forward [`ChannelPolicy`].
#[derive(Debug)]
pub struct ReverseInbound {
    allowlist: ForwardAllowlist,
    receiver: mpsc::Receiver<InboundForward>,
}

/// Builds the policy for the final hop and its matching receiver. Use one pair per connection.
pub fn reverse_policy(capacity: usize) -> (ChannelPolicy, ReverseInbound) {
    let (sender, receiver) = mpsc::channel(capacity.max(1));
    let allowlist = ForwardAllowlist::default();
    let policy = ChannelPolicy {
        forward_allowlist: allowlist.clone(),
        forward_channels: Some(sender),
    };
    (policy, ReverseInbound { allowlist, receiver })
}

/// Active reverse forwards on one chain. Dropping it stops relaying and revokes the allowlist.
#[derive(Debug)]
pub struct ReverseRelay {
    allowlist: ForwardAllowlist,
    /// `(remote_addr, bound_port)` as registered on the server.
    bound: Vec<(String, u32)>,
    task: JoinHandle<()>,
}

impl ReverseRelay {
    /// Requests every forward on the final hop and starts relaying accepted channels.
    ///
    /// All-or-nothing: on failure, forwards already granted are cancelled.
    pub async fn start(
        chain: &SshChain,
        forwards: &[RemoteForward],
        inbound: ReverseInbound,
    ) -> Result<Self, ReverseError> {
        let ReverseInbound {
            allowlist,
            receiver,
        } = inbound;

        let mut seen = HashSet::new();
        for forward in forwards {
            if forward.remote.port() != 0 && !seen.insert(forward.remote) {
                return Err(ReverseError::Duplicate(forward.remote));
            }
        }

        let mut routes = HashMap::with_capacity(forwards.len());
        let mut bound: Vec<(String, u32)> = Vec::with_capacity(forwards.len());
        for forward in forwards {
            let address = forward.remote.ip().to_string();
            let requested = u32::from(forward.remote.port());
            // A fixed port is allowed first, so a connection racing the reply is not rejected.
            if requested != 0 {
                allowlist.allow(address.clone(), requested);
            }
            match chain
                .target()
                .tcpip_forward(address.clone(), requested)
                .await
            {
                Ok(assigned) => {
                    let port = if requested == 0 { assigned } else { requested };
                    allowlist.allow(address.clone(), port);
                    routes.insert((address.clone(), port), (forward.host.clone(), forward.port));
                    bound.push((address, port));
                }
                Err(source) => {
                    allowlist.revoke(&address, requested);
                    cancel_all(chain, &allowlist, &bound).await;
                    return Err(ReverseError::Request {
                        remote: forward.remote,
                        source,
                    });
                }
            }
        }

        let task = tokio::spawn(relay_inbound(receiver, routes));
        Ok(Self {
            allowlist,
            bound,
            task,
        })
    }

    /// The `(remote_addr, port)` pairs bound on the final hop, with assigned ports filled in.
    pub fn bound(&self) -> &[(String, u32)] {
        &self.bound
    }

    /// Cancels the forwards on the final hop, then stops relaying.
    pub async fn stop(self, chain: &SshChain) {
        cancel_all(chain, &self.allowlist, &self.bound).await;
    }
}

impl Drop for ReverseRelay {
    fn drop(&mut self) {
        self.task.abort();
        for (address, port) in &self.bound {
            self.allowlist.revoke(address, *port);
        }
    }
}

async fn cancel_all(chain: &SshChain, allowlist: &ForwardAllowlist, bound: &[(String, u32)]) {
    for (address, port) in bound {
        allowlist.revoke(address, *port);
        // The session may already be gone, and teardown continues either way.
        let _ = chain
            .target()
            .cancel_tcpip_forward(address.clone(), *port)
            .await;
    }
}

/// Aborting this task drops the `JoinSet`, which aborts every per-connection relay.
async fn relay_inbound(
    mut receiver: mpsc::Receiver<InboundForward>,
    routes: HashMap<(String, u32), (String, u16)>,
) {
    let mut relays = JoinSet::new();
    loop {
        tokio::select! {
            inbound = receiver.recv() => {
                let Some(inbound) = inbound else { break };
                let route = (inbound.connected_address.clone(), inbound.connected_port);
                // An unrouted channel is dropped, which closes it.
                if let Some((host, port)) = routes.get(&route) {
                    relays.spawn(relay_one(inbound.channel, host.clone(), *port));
                }
            }
            Some(_) = relays.join_next(), if !relays.is_empty() => {}
        }
    }
    while relays.join_next().await.is_some() {}
}

async fn relay_one(channel: Channel<Msg>, host: String, port: u16) {
    let Ok(mut upstream) = TcpStream::connect((host.as_str(), port)).await else {
        return;
    };
    let _ = upstream.set_nodelay(true);
    let mut stream = channel.into_stream();
    let _ = copy_bidirectional(&mut stream, &mut upstream).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_policy_denies_until_a_forward_is_registered() {
        let (policy, inbound) = reverse_policy(4);
        assert!(!policy.allows_forward("127.0.0.1", 9000));
        inbound.allowlist.allow("127.0.0.1", 9000);
        assert!(policy.allows_forward("127.0.0.1", 9000));
        assert!(!policy.allows_forward("127.0.0.1", 9001));
        assert!(!policy.allows_forward("0.0.0.0", 9000));
    }

    #[test]
    fn zero_capacity_is_raised_instead_of_panicking() {
        let (policy, _inbound) = reverse_policy(0);
        assert!(policy.forward_channels.is_some());
    }

    #[tokio::test]
    async fn unrouted_channels_stop_when_the_sender_closes() {
        let (sender, receiver) = mpsc::channel::<InboundForward>(1);
        let task = tokio::spawn(relay_inbound(receiver, HashMap::new()));
        drop(sender);
        task.await.unwrap();
    }
}
