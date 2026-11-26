//! Tunnel state of the OpenSSH engine and the engine-facing dialer that uses it.
//!
//! [`OpenSshDialer`] follows the supervisor's [`TunnelState`]: while the `ssh -D` SOCKS
//! listener is ready it dials through it with the engine's [`Socks5Dialer`] (hostnames stay
//! unresolved, so DNS is remote); otherwise every dial fails with `NotConnected`.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use rusty_conduit_engine::upstream::{DialError, DialFuture, Socks5Dialer, UpstreamDialer};
use tokio::sync::watch;

/// Live state of the SSH dynamic tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelState {
    /// `ssh` is starting and its SOCKS listener is not yet usable.
    Connecting,
    /// The SOCKS listener at this address is accepting connections.
    Ready(SocketAddr),
    /// The tunnel is down, for the given reason.
    Disconnected(String),
}

/// Dials through the OpenSSH SOCKS listener described by the current [`TunnelState`].
#[derive(Debug, Clone)]
pub struct OpenSshDialer {
    state: watch::Receiver<TunnelState>,
}

impl OpenSshDialer {
    /// Creates a dialer that follows `state`.
    pub fn new(state: watch::Receiver<TunnelState>) -> Self {
        Self { state }
    }

    fn current(&self) -> TunnelState {
        self.state.borrow().clone()
    }
}

impl UpstreamDialer for OpenSshDialer {
    fn connect(&self, host: &str, port: u16, timeout: Duration) -> DialFuture<'_> {
        let host = host.to_owned();
        let current = self.current();
        Box::pin(async move {
            let addr = match current {
                TunnelState::Ready(addr) => addr,
                TunnelState::Connecting => {
                    return Err(not_connected("SSH tunnel is still connecting".to_string()));
                }
                TunnelState::Disconnected(reason) => {
                    return Err(not_connected(format!(
                        "SSH tunnel is disconnected: {reason}"
                    )));
                }
            };
            Socks5Dialer::new(addr.ip().to_string(), addr.port())
                .connect(&host, port, timeout)
                .await
        })
    }

    fn redacted_upstream(&self) -> String {
        match self.current() {
            TunnelState::Ready(addr) => format!("socks5://{addr}"),
            _ => "ssh-tunnel".to_string(),
        }
    }
}

fn not_connected(message: String) -> io::Error {
    DialError::NotConnected {
        kind: io::ErrorKind::NotConnected,
        message,
    }
    .into_io()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const TIMEOUT: Duration = Duration::from_secs(5);

    fn dialer(state: TunnelState) -> (watch::Sender<TunnelState>, OpenSshDialer) {
        let (tx, rx) = watch::channel(state);
        (tx, OpenSshDialer::new(rx))
    }

    #[tokio::test]
    async fn connecting_tunnel_is_not_connected() {
        let (_tx, dialer) = dialer(TunnelState::Connecting);
        let error = dialer
            .connect("example.test", 443, TIMEOUT)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        assert!(error.to_string().contains("still connecting"), "{error}");
        assert_eq!(dialer.redacted_upstream(), "ssh-tunnel");
    }

    #[tokio::test]
    async fn disconnected_tunnel_is_not_connected_with_reason() {
        let (_tx, dialer) = dialer(TunnelState::Disconnected("ssh exited".into()));
        let error = dialer
            .connect("example.test", 443, TIMEOUT)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        assert!(error.to_string().contains("ssh exited"), "{error}");
        assert_eq!(dialer.redacted_upstream(), "ssh-tunnel");
    }

    /// A one-shot SOCKS5 server that accepts no-auth, records the CONNECT request, replies
    /// success, then echoes.
    async fn spawn_socks5() -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 2];
            socket.read_exact(&mut greeting).await.unwrap();
            let mut methods = vec![0u8; usize::from(greeting[1])];
            socket.read_exact(&mut methods).await.unwrap();
            socket.write_all(&[0x05, 0x00]).await.unwrap();
            let mut head = [0u8; 5];
            socket.read_exact(&mut head).await.unwrap();
            assert_eq!(head[3], 0x03, "hostnames must be sent unresolved");
            let mut rest = vec![0u8; usize::from(head[4]) + 2];
            socket.read_exact(&mut rest).await.unwrap();
            socket
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            let mut ping = [0u8; 4];
            socket.read_exact(&mut ping).await.unwrap();
            socket.write_all(&ping).await.unwrap();
            rest
        });
        (addr, task)
    }

    #[tokio::test]
    async fn ready_tunnel_dials_through_the_socks_listener() {
        let (addr, server) = spawn_socks5().await;
        let (_tx, dialer) = dialer(TunnelState::Ready(addr));
        assert_eq!(dialer.redacted_upstream(), format!("socks5://{addr}"));

        let mut stream = dialer.connect("remote.test", 8443, TIMEOUT).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut reply = [0u8; 4];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"ping");

        let request = server.await.unwrap();
        let (name, port) = request.split_at(request.len() - 2);
        assert_eq!(name, b"remote.test");
        assert_eq!(port, 8443u16.to_be_bytes());
    }

    #[tokio::test]
    async fn dialer_follows_state_changes() {
        let (tx, dialer) = dialer(TunnelState::Connecting);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1080);
        tx.send_replace(TunnelState::Ready(addr));
        assert_eq!(dialer.redacted_upstream(), "socks5://127.0.0.1:1080");
        tx.send_replace(TunnelState::Disconnected("gone".into()));
        assert_eq!(dialer.redacted_upstream(), "ssh-tunnel");
    }
}
