//! Live connection and byte counters for any [`UpstreamDialer`].

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use rusty_conduit_engine::upstream::{DialFuture, UpstreamDialer, UpstreamStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Counters shared between a [`StatsDialer`] and its readers.
#[derive(Debug, Default)]
pub struct AtomicStats {
    active_connections: AtomicU64,
    total_connections: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
}

/// A point-in-time copy of [`AtomicStats`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub active_connections: u64,
    pub total_connections: u64,
    /// Bytes written to the upstream.
    pub bytes_sent: u64,
    /// Bytes read from the upstream.
    pub bytes_received: u64,
}

impl AtomicStats {
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            active_connections: self.active_connections.load(Ordering::Relaxed),
            total_connections: self.total_connections.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
        }
    }
}

/// Wraps a dialer and counts every successful connection and the bytes it carries.
#[derive(Clone)]
pub struct StatsDialer {
    inner: Arc<dyn UpstreamDialer>,
    stats: Arc<AtomicStats>,
}

impl StatsDialer {
    pub fn new(inner: Arc<dyn UpstreamDialer>, stats: Arc<AtomicStats>) -> Self {
        Self { inner, stats }
    }

    pub fn stats(&self) -> &Arc<AtomicStats> {
        &self.stats
    }
}

impl UpstreamDialer for StatsDialer {
    fn connect(&self, host: &str, port: u16, timeout: Duration) -> DialFuture<'_> {
        let dial = self.inner.connect(host, port, timeout);
        let stats = Arc::clone(&self.stats);
        Box::pin(async move {
            let upstream = dial.await?;
            let guard = ActiveGuard::new(Arc::clone(&stats));
            Ok(UpstreamStream::boxed(CountingStream {
                inner: upstream,
                stats,
                _guard: guard,
            }))
        })
    }

    fn redacted_upstream(&self) -> String {
        self.inner.redacted_upstream()
    }
}

/// Holds one active-connection slot, released when the counted stream is dropped.
struct ActiveGuard(Arc<AtomicStats>);

impl ActiveGuard {
    fn new(stats: Arc<AtomicStats>) -> Self {
        stats.total_connections.fetch_add(1, Ordering::Relaxed);
        stats.active_connections.fetch_add(1, Ordering::Relaxed);
        Self(stats)
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Counts bytes as they move, so totals stay live during long transfers.
struct CountingStream {
    inner: UpstreamStream,
    stats: Arc<AtomicStats>,
    _guard: ActiveGuard,
}

impl AsyncRead for CountingStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = result {
            let read = (buf.filled().len() - before) as u64;
            this.stats.bytes_received.fetch_add(read, Ordering::Relaxed);
        }
        result
    }
}

impl AsyncWrite for CountingStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = result {
            this.stats
                .bytes_sent
                .fetch_add(written as u64, Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusty_conduit_engine::upstream::DirectDialer;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const TIMEOUT: Duration = Duration::from_secs(5);

    async fn spawn_reply_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut request = [0u8; 5];
                    if socket.read_exact(&mut request).await.is_ok() {
                        let _ = socket.write_all(b"reply-bytes").await;
                    }
                });
            }
        });
        port
    }

    fn dialer() -> StatsDialer {
        StatsDialer::new(
            Arc::new(DirectDialer::default()),
            Arc::new(AtomicStats::default()),
        )
    }

    async fn wait_until(stats: &AtomicStats, done: impl Fn(StatsSnapshot) -> bool) -> StatsSnapshot {
        tokio::time::timeout(TIMEOUT, async {
            loop {
                let snapshot = stats.snapshot();
                if done(snapshot) {
                    return snapshot;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("stats did not settle")
    }

    #[tokio::test]
    async fn counts_connections_and_bytes_in_both_directions() {
        let port = spawn_reply_server().await;
        let dialer = dialer();
        let mut stream = dialer.connect("127.0.0.1", port, TIMEOUT).await.unwrap();
        let open = dialer.stats().snapshot();
        assert_eq!((open.active_connections, open.total_connections), (1, 1));

        stream.write_all(b"hello").await.unwrap();
        let mut reply = [0u8; 11];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply-bytes");
        drop(stream);

        let done = wait_until(dialer.stats(), |s| s.active_connections == 0).await;
        assert_eq!(done.total_connections, 1);
        assert_eq!(done.bytes_sent, 5);
        assert_eq!(done.bytes_received, 11);
    }

    #[tokio::test]
    async fn failed_dial_is_not_counted() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let dialer = dialer();
        assert!(dialer.connect("127.0.0.1", port, TIMEOUT).await.is_err());
        assert_eq!(dialer.stats().snapshot(), StatsSnapshot::default());
    }
}
