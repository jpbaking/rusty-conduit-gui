//! Local port forwards (`ssh -L`), shared by both SSH engines.
//!
//! Each forward is a listener on this computer. Every accepted connection is opened through
//! the session's tunnel dialer, so it reaches the destination from the SSH target, the same
//! way the forward proxy does. The listeners are bound once and stay bound across reconnects:
//! while the tunnel is down, new connections are closed after the dial fails.

use std::sync::{Arc, PoisonError};

use conduit_core::{ForwardDirection, PortForward};
use rusty_conduit_engine::logging::Logger;
use rusty_conduit_engine::routing::DEFAULT_CONNECT_TIMEOUT;
use rusty_conduit_engine::upstream::UpstreamDialer;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::state::ForwardStatus;

pub(crate) type SharedForwards = Arc<std::sync::Mutex<Vec<ForwardStatus>>>;

/// The status of `forward` with `error`, or listening when it is `None`.
pub(crate) fn status(forward: &PortForward, error: Option<String>) -> ForwardStatus {
    ForwardStatus {
        id: forward.id,
        direction: forward.direction,
        listen: forward.listen(),
        destination: forward.destination(),
        error,
    }
}

/// Replaces the statuses in `direction`, keeping the other direction's.
pub(crate) fn publish(shared: &SharedForwards, direction: ForwardDirection, next: Vec<ForwardStatus>) {
    let mut statuses = shared.lock().unwrap_or_else(PoisonError::into_inner);
    statuses.retain(|s| s.direction != direction);
    statuses.extend(next);
}

/// The bound local forwards of one session.
pub(crate) struct LocalForwards {
    token: CancellationToken,
    tasks: JoinSet<()>,
}

impl LocalForwards {
    /// Binds every switched-on local forward in `forwards`.
    ///
    /// A forward that cannot bind is reported in its status and logged. It does not stop the
    /// session or the other forwards.
    pub(crate) async fn bind(
        forwards: impl Iterator<Item = &PortForward>,
        dialer: Arc<dyn UpstreamDialer>,
        logger: &Logger,
        shared: &SharedForwards,
    ) -> Self {
        let token = CancellationToken::new();
        let mut tasks = JoinSet::new();
        let mut statuses = Vec::new();
        for forward in forwards {
            let listen = forward.listen();
            let destination = forward.destination();
            match TcpListener::bind(listen).await {
                Ok(listener) => {
                    let listen = listener.local_addr().unwrap_or(listen);
                    logger.info(format!("port forward listening on {listen} to {destination}"));
                    statuses.push(status(forward, None));
                    tasks.spawn(accept_loop(
                        listener,
                        forward.dest_host_unbracketed().to_string(),
                        forward.dest_port,
                        Arc::clone(&dialer),
                        logger.clone(),
                        token.clone(),
                    ));
                }
                Err(error) => {
                    let message = format!("cannot listen on {listen}: {error}");
                    logger.error(format!("port forward to {destination}: {message}"));
                    statuses.push(status(forward, Some(message)));
                }
            }
        }
        publish(shared, ForwardDirection::Local, statuses);
        Self { token, tasks }
    }

    /// Closes the listeners and every open forwarded connection.
    pub(crate) async fn shutdown(mut self) {
        self.token.cancel();
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
    }
}

/// Accepts connections until cancelled. Dropping the task set aborts every relay.
async fn accept_loop(
    listener: TcpListener,
    host: String,
    port: u16,
    dialer: Arc<dyn UpstreamDialer>,
    logger: Logger,
    token: CancellationToken,
) {
    let mut relays = JoinSet::new();
    loop {
        tokio::select! {
            () = token.cancelled() => break,
            accepted = listener.accept() => {
                let Ok((client, _)) = accepted else { continue };
                relays.spawn(relay(client, host.clone(), port, Arc::clone(&dialer), logger.clone()));
            }
            Some(_) = relays.join_next(), if !relays.is_empty() => {}
        }
    }
}

async fn relay(
    mut client: TcpStream,
    host: String,
    port: u16,
    dialer: Arc<dyn UpstreamDialer>,
    logger: Logger,
) {
    let _ = client.set_nodelay(true);
    match dialer.connect(&host, port, DEFAULT_CONNECT_TIMEOUT).await {
        Ok(mut upstream) => {
            let _ = copy_bidirectional(&mut client, &mut upstream).await;
        }
        Err(error) => logger.error(format!("port forward to {host}:{port} failed: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusty_conduit_engine::logging::LogLevel;
    use rusty_conduit_engine::upstream::DirectDialer;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn forward(port: u16, dest_port: u16) -> PortForward {
        PortForward {
            id: uuid::Uuid::new_v4(),
            port,
            dest_host: "127.0.0.1".into(),
            dest_port,
            ..Default::default()
        }
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    #[tokio::test]
    async fn relays_through_the_dialer_and_reports_bind_failures() {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).await.unwrap();
            stream.write_all(&buf).await.unwrap();
        });

        let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let taken_port = taken.local_addr().unwrap().port();
        let good = forward(free_port(), echo_port);
        let bad = forward(taken_port, echo_port);
        let shared = SharedForwards::default();
        // A remote status is kept when the local ones are published.
        let mut remote = forward(9, 9);
        remote.direction = ForwardDirection::Remote;
        publish(&shared, ForwardDirection::Remote, vec![status(&remote, None)]);

        let logger = Logger::with_writer(LogLevel::Quiet, Box::new(std::io::sink()));
        let dialer: Arc<dyn UpstreamDialer> = Arc::new(DirectDialer::default());
        let forwards = LocalForwards::bind([&good, &bad].into_iter(), dialer, &logger, &shared).await;

        let statuses = shared.lock().unwrap().clone();
        assert_eq!(statuses.len(), 3);
        assert!(statuses.iter().any(|s| s.id == good.id && s.error.is_none()));
        assert!(statuses
            .iter()
            .any(|s| s.id == bad.id && s.error.as_deref().is_some_and(|e| e.contains("cannot listen"))));
        assert!(statuses.iter().any(|s| s.id == remote.id));

        let mut client = TcpStream::connect(good.listen()).await.unwrap();
        client.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        forwards.shutdown().await;
        drop(client);
        assert!(TcpStream::connect(good.listen()).await.is_err());
    }
}
