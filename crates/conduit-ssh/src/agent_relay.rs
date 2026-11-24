//! Per-hop agent forwarding: serves `auth-agent@openssh.com` channels from a [`ScopedAgent`].

use std::future::Future;
use std::time::Duration;

use russh::client::{Handle, Msg};
use russh::{Channel, ChannelMsg};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};

use crate::agent::ScopedAgent;
use crate::agent_wire;
use crate::handler::{ChannelPolicy, HopHandler};

/// How long a hop may take to answer a session request.
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);
/// Open agent channels per hop, so a hostile host cannot create unbounded tasks.
const MAX_AGENT_CHANNELS: usize = 32;

/// Agent forwarding could not be started on a hop.
#[derive(Debug, Error)]
pub enum AgentRelayError {
    #[error("hop {hop_index}: agent session failed: {source}")]
    Session {
        hop_index: usize,
        #[source]
        source: russh::Error,
    },

    #[error("hop {hop_index}: {request} request was refused")]
    Refused {
        hop_index: usize,
        request: &'static str,
    },

    #[error("hop {hop_index}: no reply to {request} request")]
    NoReply {
        hop_index: usize,
        request: &'static str,
    },
}

/// The receiving half of an agent-forwarding [`ChannelPolicy`].
#[derive(Debug)]
pub struct AgentInbound {
    receiver: mpsc::Receiver<Channel<Msg>>,
}

/// Builds the opt-in policy for one hop and its matching receiver. Use one pair per connection.
pub fn agent_policy(capacity: usize) -> (ChannelPolicy, AgentInbound) {
    let (sender, receiver) = mpsc::channel(capacity.max(1));
    let policy = ChannelPolicy {
        agent_channels: Some(sender),
        ..ChannelPolicy::default()
    };
    (policy, AgentInbound { receiver })
}

/// Active agent forwarding on one hop. Dropping it stops serving and closes the session channel.
#[derive(Debug)]
pub struct AgentForwardRelay {
    task: JoinHandle<()>,
}

impl AgentForwardRelay {
    /// Opens a session channel, requests agent forwarding, optionally runs `remote_command`,
    /// and serves every accepted agent channel from `agent`.
    pub async fn start(
        handle: &Handle<HopHandler>,
        hop_index: usize,
        agent: ScopedAgent,
        agent_channels: AgentInbound,
        remote_command: Option<&str>,
    ) -> Result<Self, AgentRelayError> {
        let session_error = |source| AgentRelayError::Session { hop_index, source };

        let mut session = handle.channel_open_session().await.map_err(session_error)?;
        session.agent_forward(true).await.map_err(session_error)?;
        await_reply(&mut session, hop_index, "agent forwarding").await?;

        if let Some(command) = remote_command {
            session.exec(true, command).await.map_err(session_error)?;
            await_reply(&mut session, hop_index, "exec").await?;
        }

        let closed = async move {
            // Holding the channel here keeps the session open for tunnel-only connections.
            while !matches!(session.wait().await, None | Some(ChannelMsg::Close)) {}
        };
        let task = tokio::spawn(relay_inbound(agent_channels.receiver, agent, closed));
        Ok(Self { task })
    }
}

impl Drop for AgentForwardRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn await_reply(
    session: &mut Channel<Msg>,
    hop_index: usize,
    request: &'static str,
) -> Result<(), AgentRelayError> {
    let reply = async {
        loop {
            match session.wait().await {
                Some(ChannelMsg::Success) => return Ok(()),
                Some(ChannelMsg::Failure) | Some(ChannelMsg::Close) | None => {
                    return Err(AgentRelayError::Refused { hop_index, request })
                }
                Some(_) => {}
            }
        }
    };
    tokio::time::timeout(REPLY_TIMEOUT, reply)
        .await
        .unwrap_or(Err(AgentRelayError::NoReply { hop_index, request }))
}

/// Returning drops the `JoinSet`, which aborts every per-channel task.
async fn relay_inbound(
    mut receiver: mpsc::Receiver<Channel<Msg>>,
    agent: ScopedAgent,
    closed: impl Future<Output = ()>,
) {
    tokio::pin!(closed);
    let mut relays = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut closed => break,
            inbound = receiver.recv() => {
                let Some(channel) = inbound else { break };
                // A channel over the limit is dropped, which closes it.
                if relays.len() < MAX_AGENT_CHANNELS {
                    relays.spawn(serve_channel(channel, agent.clone()));
                }
            }
            Some(_) = relays.join_next(), if !relays.is_empty() => {}
        }
    }
}

async fn serve_channel(channel: Channel<Msg>, agent: ScopedAgent) {
    let mut stream = channel.into_stream();
    // A protocol error from the remote host only ends this channel.
    let _ = agent_wire::serve(&mut stream, &agent).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent() -> ScopedAgent {
        ScopedAgent::seal("hop", [], None)
    }

    #[test]
    fn agent_policy_opts_in_and_raises_zero_capacity() {
        let (policy, _inbound) = agent_policy(0);
        assert!(policy.allows_agent_forward());
        assert!(!ChannelPolicy::default().allows_agent_forward());
    }

    #[tokio::test]
    async fn relay_stops_when_the_sender_closes() {
        let (sender, receiver) = mpsc::channel::<Channel<Msg>>(1);
        let task = tokio::spawn(relay_inbound(receiver, agent(), std::future::pending()));
        drop(sender);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn relay_stops_when_the_session_closes() {
        let (_sender, receiver) = mpsc::channel::<Channel<Msg>>(1);
        let task = tokio::spawn(relay_inbound(receiver, agent(), std::future::ready(())));
        task.await.unwrap();
    }
}
