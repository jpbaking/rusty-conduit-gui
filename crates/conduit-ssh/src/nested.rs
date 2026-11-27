//! Transport for a hop that runs inside the previous hop's `direct-tcpip` channel.
//!
//! A `russh` session handles network reads and writes in one loop. When hop N+1 is carried
//! by a channel of hop N, that loop must never wait on hop N's channel window. Otherwise it
//! stops reading, hop N's loop blocks delivering hop N+1's inbound data to it, and hop N can
//! no longer process the window adjust that would unblock the write: the whole chain freezes
//! under sustained upload.
//!
//! [`NestedTransport`] therefore accepts writes at once and hands them to a task that waits
//! on hop N's window. The queue stays bounded because hop N+1's session only sends channel
//! data its own peers' windows allow.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use russh::client::Msg;
use russh::{Channel, ChannelStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf};
use tokio::sync::mpsc;

/// Largest batch the writer task hands to the channel in one write.
const MAX_BATCH: usize = 256 * 1024;

/// The byte stream hop N+1 runs over.
pub struct NestedTransport {
    read: ReadHalf<ChannelStream<Msg>>,
    /// `None` once shut down.
    write: Option<mpsc::UnboundedSender<Vec<u8>>>,
}

impl NestedTransport {
    /// Wraps hop N's channel. Must be called inside a Tokio runtime.
    pub fn new(channel: Channel<Msg>) -> Self {
        let (read, mut write) = tokio::io::split(channel.into_stream());
        let (sender, mut queue) = mpsc::unbounded_channel::<Vec<u8>>();
        tokio::spawn(async move {
            while let Some(mut batch) = queue.recv().await {
                while batch.len() < MAX_BATCH {
                    match queue.try_recv() {
                        Ok(more) => batch.extend_from_slice(&more),
                        Err(_) => break,
                    }
                }
                // A failed write drops the queue, so the session sees later writes fail.
                if write.write_all(&batch).await.is_err() {
                    return;
                }
            }
            // The session shut its transport down, or dropped it.
            let _ = write.shutdown().await;
        });
        Self {
            read,
            write: Some(sender),
        }
    }
}

impl AsyncRead for NestedTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.read).poll_read(cx, buf)
    }
}

impl AsyncWrite for NestedTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let sent = self
            .write
            .as_ref()
            .is_some_and(|sender| sender.send(buf.to_vec()).is_ok());
        Poll::Ready(if sent {
            Ok(buf.len())
        } else {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "previous hop's channel is closed",
            ))
        })
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Queued bytes leave in order behind hop N's window; waiting here is the deadlock.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The writer task drains what is queued, then sends EOF.
        self.write = None;
        Poll::Ready(Ok(()))
    }
}
