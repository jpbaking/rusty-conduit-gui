//! Bounded per-session log buffers, with secrets redacted before anything is stored.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};

use conduit_core::Timestamp;
use serde::Serialize;
use tokio::io::AsyncWrite;
use tokio::sync::broadcast;

/// Default number of lines kept per session.
pub const DEFAULT_LOG_CAPACITY: usize = 2_000;

/// Longest stored line, in bytes. The rest of a longer line is dropped.
pub const MAX_LINE_BYTES: usize = 16 * 1024;

const LIVE_CHANNEL_CAPACITY: usize = 256;
const REDACTED: &str = "<redacted>";
const TRUNCATED: &str = " …[truncated]";

/// Keys whose value is a single token.
const TOKEN_KEYS: [&str; 5] = ["password", "passwd", "passphrase", "secret", "token"];
/// Keys whose value runs to the end of the line, such as `Authorization: Bearer abc`.
const LINE_KEYS: [&str; 2] = ["authorization", "cookie"];

/// One stored log line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogLine {
    /// Increases by one per line and is never reused, even after [`LogRingBuffer::clear`].
    pub seq: u64,
    pub timestamp: Timestamp,
    pub text: String,
}

#[derive(Debug)]
struct Ring {
    lines: VecDeque<LogLine>,
    next_seq: u64,
}

/// A cloneable handle to a bounded log buffer.
#[derive(Debug, Clone)]
pub struct LogRingBuffer {
    ring: Arc<Mutex<Ring>>,
    capacity: usize,
    live: broadcast::Sender<LogLine>,
}

impl LogRingBuffer {
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        let (live, _) = broadcast::channel(LIVE_CHANNEL_CAPACITY);
        Self {
            ring: Arc::new(Mutex::new(Ring {
                lines: VecDeque::with_capacity(capacity.min(256)),
                next_seq: 0,
            })),
            capacity,
            live,
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Redacts and stores one line, evicting the oldest line when full.
    pub fn push(&self, line: &str) {
        let text = redact(line.trim_end_matches(['\r', '\n']));
        let mut ring = self.lock();
        let entry = LogLine {
            seq: ring.next_seq,
            timestamp: Timestamp::now(),
            text,
        };
        ring.next_seq += 1;
        if ring.lines.len() == self.capacity {
            ring.lines.pop_front();
        }
        ring.lines.push_back(entry.clone());
        // Sent under the lock so subscribers see lines in order.
        let _ = self.live.send(entry);
    }

    /// The newest `limit` lines, oldest first. `None` returns every line.
    pub fn query(&self, limit: Option<usize>) -> Vec<LogLine> {
        let ring = self.lock();
        let skip = limit.map_or(0, |n| ring.lines.len().saturating_sub(n));
        ring.lines.iter().skip(skip).cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.lock().lines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&self) {
        self.lock().lines.clear();
    }

    /// Receives lines pushed after this call.
    pub fn subscribe(&self) -> broadcast::Receiver<LogLine> {
        self.live.subscribe()
    }

    /// A writer for `Logger::with_writer` and `AccessLogger::start_with_stdout`.
    pub fn writer(&self) -> LogWriter {
        LogWriter {
            buffer: self.clone(),
            partial: Vec::new(),
            truncated: false,
        }
    }

    // Lines are replaced whole, so a poisoned lock still holds a valid ring.
    fn lock(&self) -> std::sync::MutexGuard<'_, Ring> {
        self.ring.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Default for LogRingBuffer {
    fn default() -> Self {
        Self::new(DEFAULT_LOG_CAPACITY)
    }
}

/// Splits a byte stream into lines for a [`LogRingBuffer`]. Works as a sync and async writer.
#[derive(Debug)]
pub struct LogWriter {
    buffer: LogRingBuffer,
    partial: Vec<u8>,
    truncated: bool,
}

impl LogWriter {
    fn ingest(&mut self, mut data: &[u8]) {
        while let Some(end) = data.iter().position(|b| *b == b'\n') {
            self.append(&data[..end]);
            self.emit();
            data = &data[end + 1..];
        }
        self.append(data);
    }

    fn append(&mut self, data: &[u8]) {
        let room = MAX_LINE_BYTES.saturating_sub(self.partial.len());
        self.partial.extend_from_slice(&data[..data.len().min(room)]);
        self.truncated |= data.len() > room;
    }

    fn emit(&mut self) {
        let mut line = String::from_utf8_lossy(&self.partial).into_owned();
        if self.truncated {
            line.push_str(TRUNCATED);
        }
        self.buffer.push(&line);
        self.partial.clear();
        self.truncated = false;
    }
}

impl io::Write for LogWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.ingest(data);
        Ok(data.len())
    }

    /// Keeps an unfinished line buffered, since the engine flushes between partial writes.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsyncWrite for LogWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.ingest(data);
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.partial.is_empty() {
            this.emit();
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for LogWriter {
    fn drop(&mut self) {
        if !self.partial.is_empty() {
            self.emit();
        }
    }
}

/// Masks credential values in a log line, in `key=value`, `key: value`, and JSON forms.
pub fn redact(line: &str) -> String {
    if line.contains("PRIVATE KEY") {
        return REDACTED.to_string();
    }
    let lower = line.to_ascii_lowercase();
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut copied = 0;
    let mut pos = 0;
    while pos < bytes.len() {
        match match_secret(&lower, bytes, pos) {
            Some((value_start, value_end)) => {
                out.push_str(&line[copied..value_start]);
                out.push_str(REDACTED);
                copied = value_end;
                pos = value_end.max(pos + 1);
            }
            None => pos += 1,
        }
    }
    out.push_str(&line[copied..]);
    out
}

/// If a secret key starts at `pos`, returns the byte range of its value.
fn match_secret(lower: &str, bytes: &[u8], pos: usize) -> Option<(usize, usize)> {
    if pos > 0 && bytes[pos - 1].is_ascii_alphanumeric() {
        return None;
    }
    let rest = lower.as_bytes().get(pos..)?;
    let (key_len, to_line_end) = TOKEN_KEYS
        .iter()
        .map(|k| (k, false))
        .chain(LINE_KEYS.iter().map(|k| (k, true)))
        .find(|(k, _)| rest.starts_with(k.as_bytes()))
        .map(|(k, whole)| (k.len(), whole))?;

    let mut i = pos + key_len;
    if matches!(bytes.get(i), Some(b'"' | b'\'')) {
        i += 1;
    }
    i = skip_spaces(bytes, i);
    if !matches!(bytes.get(i), Some(b'=' | b':')) {
        return None;
    }
    i = skip_spaces(bytes, i + 1);
    if i >= bytes.len() {
        return None;
    }

    if let quote @ (b'"' | b'\'') = bytes[i] {
        let start = i + 1;
        let mut j = start;
        while j < bytes.len() && bytes[j] != quote {
            j += if bytes[j] == b'\\' { 2 } else { 1 };
        }
        return Some((start, j.min(bytes.len())));
    }
    if to_line_end {
        return Some((i, bytes.len()));
    }
    let end = bytes[i..]
        .iter()
        .position(|b| b.is_ascii_whitespace() || matches!(b, b',' | b';' | b'&'))
        .map_or(bytes.len(), |n| i + n);
    (end > i).then_some((i, end))
}

fn skip_spaces(bytes: &[u8], mut i: usize) -> usize {
    while matches!(bytes.get(i), Some(b' ' | b'\t')) {
        i += 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn logs_ring_is_bounded_and_keeps_newest() {
        let ring = LogRingBuffer::new(3);
        for i in 0..10 {
            ring.push(&format!("line {i}"));
        }
        let lines = ring.query(None);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].text, "line 7");
        assert_eq!(lines[2].text, "line 9");
        assert_eq!(lines[2].seq, 9);
    }

    #[test]
    fn logs_default_capacity_is_two_thousand() {
        let ring = LogRingBuffer::default();
        assert_eq!(ring.capacity(), 2_000);
        for i in 0..2_500 {
            ring.push(&format!("{i}"));
        }
        assert_eq!(ring.len(), 2_000);
    }

    #[test]
    fn logs_query_limit_and_clear_keep_sequence() {
        let ring = LogRingBuffer::new(10);
        ring.push("a");
        ring.push("b");
        ring.push("c");
        let last = ring.query(Some(2));
        assert_eq!(last[0].text, "b");
        assert_eq!(last[1].text, "c");
        ring.clear();
        assert!(ring.is_empty());
        ring.push("d");
        assert_eq!(ring.query(None)[0].seq, 3);
    }

    #[tokio::test]
    async fn logs_subscribe_receives_redacted_lines() {
        let ring = LogRingBuffer::new(4);
        let mut live = ring.subscribe();
        ring.push("password=hunter2");
        assert_eq!(live.recv().await.unwrap().text, "password=<redacted>");
    }

    #[test]
    fn logs_redact_common_secret_forms() {
        let cases = [
            ("login password=hunter2 ok", "login password=<redacted> ok"),
            ("PassPhrase: abc123, next", "PassPhrase: <redacted>, next"),
            (
                r#"{"password":"hu\"nter","user":"bob"}"#,
                r#"{"password":"<redacted>","user":"bob"}"#,
            ),
            ("mitm_ca_passphrase=xyz", "mitm_ca_passphrase=<redacted>"),
            (
                "Proxy-Authorization: Basic Zm9vOmJhcg==",
                "Proxy-Authorization: <redacted>",
            ),
            ("Authorization: Bearer abc def", "Authorization: <redacted>"),
            ("a=1&token=tok&b=2", "a=1&token=<redacted>&b=2"),
        ];
        for (input, expected) in cases {
            assert_eq!(redact(input), expected);
        }
    }

    #[test]
    fn logs_redact_private_key_lines_and_leave_plain_text() {
        assert_eq!(redact("-----BEGIN OPENSSH PRIVATE KEY-----"), "<redacted>");
        let plain = "connected to host: example.com tokens used 3";
        assert_eq!(redact(plain), plain);
        assert_eq!(redact("пароль password=секрет ок"), "пароль password=<redacted> ок");
    }

    #[test]
    fn logs_sync_writer_joins_partial_writes() {
        let ring = LogRingBuffer::new(8);
        let mut writer = ring.writer();
        io::Write::write_all(&mut writer, b"hel").unwrap();
        io::Write::flush(&mut writer).unwrap();
        assert!(ring.is_empty());
        io::Write::write_all(&mut writer, b"lo\nsecond\nthi").unwrap();
        assert_eq!(ring.len(), 2);
        drop(writer);
        let texts: Vec<_> = ring.query(None).into_iter().map(|l| l.text).collect();
        assert_eq!(texts, ["hello", "second", "thi"]);
    }

    #[test]
    fn logs_writer_truncates_oversized_lines() {
        let ring = LogRingBuffer::new(2);
        let mut writer = ring.writer();
        io::Write::write_all(&mut writer, &vec![b'x'; MAX_LINE_BYTES * 2]).unwrap();
        io::Write::write_all(&mut writer, b"\nnext\n").unwrap();
        let lines = ring.query(None);
        assert!(lines[0].text.ends_with(TRUNCATED));
        assert_eq!(lines[0].text.len(), MAX_LINE_BYTES + TRUNCATED.len());
        assert_eq!(lines[1].text, "next");
    }

    #[tokio::test]
    async fn logs_async_writer_stores_lines_and_flushes_on_shutdown() {
        let ring = LogRingBuffer::new(4);
        let mut writer = ring.writer();
        AsyncWriteExt::write_all(&mut writer, b"one\ntw").await.unwrap();
        AsyncWriteExt::write_all(&mut writer, b"o").await.unwrap();
        AsyncWriteExt::shutdown(&mut writer).await.unwrap();
        let texts: Vec<_> = ring.query(None).into_iter().map(|l| l.text).collect();
        assert_eq!(texts, ["one", "two"]);
    }

    #[test]
    fn logs_writer_plugs_into_the_engine_logger() {
        use rusty_conduit_engine::logging::{LogLevel, Logger};
        let ring = LogRingBuffer::new(4);
        let logger = Logger::with_writer(LogLevel::Info, Box::new(ring.writer()));
        logger.info("engine password=hunter2");
        logger.flush();
        let lines = ring.query(None);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].text.contains("password=<redacted>"));
        assert!(!lines[0].text.contains("hunter2"));
    }
}
