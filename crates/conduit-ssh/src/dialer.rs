//! Bridges `russh` `direct-tcpip` channels into the engine's [`UpstreamDialer`].
//!
//! The engine needs a real [`TcpStream`], so each dial relays its SSH channel through a private
//! loopback TCP pair. Hostnames are passed to the SSH target unresolved, so DNS stays remote.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use russh::ChannelOpenFailure;
use rusty_conduit_ssh::net::{DialFuture, UpstreamDialer};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};

use crate::chain::SshChain;

/// Dials through the current SSH chain.
///
/// The chain can be swapped while proxy listeners stay bound, so a reconnect does not disturb
/// them. Relays do not keep a chain alive: replacing or shutting it down ends its connections.
#[derive(Debug, Default)]
pub struct RusshDialer {
    chain: RwLock<Option<Arc<SshChain>>>,
}

impl RusshDialer {
    /// Creates a dialer with no chain. Dials fail with `NotConnected` until [`Self::swap`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a dialer using `chain`.
    pub fn with_chain(chain: SshChain) -> Self {
        Self {
            chain: RwLock::new(Some(Arc::new(chain))),
        }
    }

    /// Atomically installs `chain` and returns the previous one.
    pub fn swap(&self, chain: SshChain) -> Option<Arc<SshChain>> {
        self.write_slot(Some(Arc::new(chain)))
    }

    /// Atomically removes the chain, so new dials fail with `NotConnected`.
    pub fn detach(&self) -> Option<Arc<SshChain>> {
        self.write_slot(None)
    }

    /// Removes the chain and disconnects it. A dial still in flight holds the last reference,
    /// and the chain closes when that dial finishes.
    pub async fn shutdown(&self) {
        if let Some(chain) = self.detach() {
            if let Ok(chain) = Arc::try_unwrap(chain) {
                chain.disconnect().await;
            }
        }
    }

    /// `true` when a chain is installed and all of its hops are open.
    pub fn is_connected(&self) -> bool {
        self.current().is_some_and(|chain| !chain.is_closed())
    }

    // The slot holds a single `Option`, so a poisoned lock cannot expose a partial update.
    fn current(&self) -> Option<Arc<SshChain>> {
        self.chain
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn write_slot(&self, next: Option<Arc<SshChain>>) -> Option<Arc<SshChain>> {
        let mut slot = self.chain.write().unwrap_or_else(PoisonError::into_inner);
        std::mem::replace(&mut *slot, next)
    }
}

impl UpstreamDialer for RusshDialer {
    fn connect(&self, host: &str, port: u16, timeout: Duration) -> DialFuture<'_> {
        let host = strip_brackets(host).to_owned();
        let chain = self.current();
        Box::pin(async move {
            let chain = chain
                .filter(|chain| !chain.is_closed())
                .ok_or_else(|| not_connected(&host, port))?;
            tokio::time::timeout(timeout, dial(&chain, &host, port))
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("timed out opening SSH channel to {host}:{port}"),
                    )
                })?
        })
    }
}

async fn dial(chain: &SshChain, host: &str, port: u16) -> io::Result<TcpStream> {
    let channel = chain
        .open_direct_tcpip(host, port)
        .await
        .map_err(|e| map_open_error(&e, host, port))?;
    let (client, mut bridge) = loopback_pair().await?;
    let mut remote = channel.into_stream();
    tokio::spawn(async move {
        // Either side closing ends the relay, and dropping both ends propagates the close.
        let _ = copy_bidirectional(&mut bridge, &mut remote).await;
    });
    Ok(client)
}

/// Creates a connected loopback TCP pair as `(client, server)`.
///
/// The listener only lives for this call, and any connection other than our own is dropped.
pub(crate) async fn loopback_pair() -> io::Result<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let client = TcpStream::connect(listener.local_addr()?).await?;
    let server = accept_verified(&listener, client.local_addr()?).await?;
    client.set_nodelay(true)?;
    server.set_nodelay(true)?;
    Ok((client, server))
}

async fn accept_verified(listener: &TcpListener, expected: SocketAddr) -> io::Result<TcpStream> {
    loop {
        let (stream, peer) = listener.accept().await?;
        if peer == expected {
            return Ok(stream);
        }
    }
}

/// Maps a channel-open failure to the `io::ErrorKind` the engine turns into HTTP and SOCKS
/// replies.
fn map_open_error(error: &russh::Error, host: &str, port: u16) -> io::Error {
    let kind = match error {
        russh::Error::ChannelOpenFailure(ChannelOpenFailure::ConnectFailed) => {
            io::ErrorKind::ConnectionRefused
        }
        russh::Error::ChannelOpenFailure(ChannelOpenFailure::AdministrativelyProhibited) => {
            io::ErrorKind::PermissionDenied
        }
        russh::Error::ChannelOpenFailure(_) => io::ErrorKind::Other,
        _ => io::ErrorKind::NotConnected,
    };
    io::Error::new(kind, format!("SSH channel to {host}:{port} failed: {error}"))
}

fn not_connected(host: &str, port: u16) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        format!("SSH chain is not connected, cannot reach {host}:{port}"),
    )
}

/// SSH expects a bare IPv6 literal, while the engine may pass one in brackets.
fn strip_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn kind_of(error: russh::Error) -> io::ErrorKind {
        map_open_error(&error, "example.test", 443).kind()
    }

    #[test]
    fn open_failures_map_to_exact_error_kinds() {
        use russh::Error::{ChannelOpenFailure as Open, Disconnect, SendError};
        assert_eq!(
            kind_of(Open(ChannelOpenFailure::ConnectFailed)),
            io::ErrorKind::ConnectionRefused
        );
        assert_eq!(
            kind_of(Open(ChannelOpenFailure::AdministrativelyProhibited)),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            kind_of(Open(ChannelOpenFailure::ResourceShortage)),
            io::ErrorKind::Other
        );
        assert_eq!(kind_of(Disconnect), io::ErrorKind::NotConnected);
        assert_eq!(kind_of(SendError), io::ErrorKind::NotConnected);
    }

    #[test]
    fn brackets_are_removed_only_from_a_full_literal() {
        assert_eq!(strip_brackets("[::1]"), "::1");
        assert_eq!(strip_brackets("::1"), "::1");
        assert_eq!(strip_brackets("internal.example"), "internal.example");
        assert_eq!(strip_brackets("[broken"), "[broken");
    }

    #[tokio::test]
    async fn dial_without_a_chain_is_not_connected() {
        let dialer = RusshDialer::new();
        assert!(!dialer.is_connected());
        let error = dialer
            .connect("example.test", 80, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
    }

    #[tokio::test]
    async fn loopback_pair_is_connected_both_ways() {
        let (mut client, mut server) = loopback_pair().await.unwrap();
        assert_eq!(client.local_addr().unwrap(), server.peer_addr().unwrap());
        client.write_all(b"ping").await.unwrap();
        let mut buffer = [0u8; 4];
        server.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"ping");
        server.write_all(b"pong").await.unwrap();
        client.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"pong");
    }

    #[tokio::test]
    async fn accept_skips_a_connection_from_another_socket() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _intruder = TcpStream::connect(addr).await.unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let expected = client.local_addr().unwrap();
        let accepted = accept_verified(&listener, expected).await.unwrap();
        assert_eq!(accepted.peer_addr().unwrap(), expected);
    }
}
