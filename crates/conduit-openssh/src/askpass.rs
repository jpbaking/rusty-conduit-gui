//! Authenticated local IPC that hands each hop's password to `conduit-worker askpass`.
//!
//! Passwords never appear in argv, the environment, or a file. Each is served at most once, so
//! a wrong password fails cleanly instead of being retried.
//!
//! Wire format: the client sends `<hop> <token>\n`. The server answers `+<secret>` or `-`, then
//! closes the connection.

use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ring::rand::{SecureRandom, SystemRandom};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use zeroize::{Zeroize, Zeroizing};

use crate::env::AskpassEnv;

const TOKEN_BYTES: usize = 32;
/// A hop index, a space, a hex token, and a newline all fit well inside this.
const MAX_REQUEST: usize = 128;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

struct Slot {
    token: String,
    secret: Option<Zeroizing<String>>,
}

type Slots = Arc<Mutex<Vec<Slot>>>;

/// A running askpass endpoint. Stops when shut down or dropped.
pub struct AskpassServer {
    endpoint: String,
    tokens: Vec<String>,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for AskpassServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AskpassServer")
            .field("endpoint", &self.endpoint)
            .field("hops", &self.tokens.len())
            .finish()
    }
}

impl AskpassServer {
    /// Starts serving. `secrets[n]` is hop `n`'s password, if it has one.
    pub async fn start(
        runtime_dir: &Path,
        secrets: Vec<Option<Zeroizing<String>>>,
    ) -> io::Result<Self> {
        let rng = SystemRandom::new();
        let mut tokens = Vec::with_capacity(secrets.len());
        let mut slots = Vec::with_capacity(secrets.len());
        for secret in secrets {
            let mut bytes = [0u8; TOKEN_BYTES];
            rng.fill(&mut bytes)
                .map_err(|_| io::Error::other("system random source failed"))?;
            let token = crate::hex(&bytes);
            bytes.zeroize();
            tokens.push(token.clone());
            slots.push(Slot { token, secret });
        }
        let (stop, stopped) = watch::channel(false);
        let (endpoint, task) =
            platform::spawn(runtime_dir, Arc::new(Mutex::new(slots)), stopped).await?;
        Ok(Self {
            endpoint,
            tokens,
            stop,
            task: Some(task),
        })
    }

    /// The socket path, or `127.0.0.1:<port>` on Windows.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// One token per hop, in hop order.
    pub fn tokens(&self) -> &[String] {
        &self.tokens
    }

    /// Stops accepting and removes the socket.
    pub async fn shutdown(mut self) {
        let _ = self.stop.send(true);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
        platform::cleanup(&self.endpoint);
    }
}

impl Drop for AskpassServer {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            let _ = self.stop.send(true);
            task.abort();
            platform::cleanup(&self.endpoint);
        }
    }
}

/// Compares without stopping at the first differing byte.
fn tokens_match(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .bytes()
            .zip(right.bytes())
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0
}

/// Takes the hop's secret if the request is valid. A wrong token consumes nothing.
fn take_secret(slots: &Mutex<Vec<Slot>>, request: &str) -> Option<Zeroizing<String>> {
    let (hop, token) = request.trim_end_matches('\n').split_once(' ')?;
    let hop: usize = hop.parse().ok()?;
    let mut slots = slots.lock().unwrap_or_else(|e| e.into_inner());
    let slot = slots.get_mut(hop)?;
    if !tokens_match(&slot.token, token) {
        return None;
    }
    slot.secret.take()
}

async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> Option<String> {
    let mut request = Vec::with_capacity(MAX_REQUEST);
    let mut chunk = [0u8; MAX_REQUEST];
    while !request.contains(&b'\n') {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 || request.len() + read > MAX_REQUEST {
            return None;
        }
        request.extend_from_slice(&chunk[..read]);
    }
    String::from_utf8(request).ok()
}

async fn serve_connection<S>(mut stream: S, slots: Slots)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = tokio::time::timeout(REQUEST_TIMEOUT, read_request(&mut stream)).await;
    let secret = match request {
        Ok(Some(request)) => take_secret(&slots, &request),
        _ => None,
    };
    let reply = match secret {
        Some(secret) => {
            let mut reply = Zeroizing::new(Vec::with_capacity(secret.len() + 1));
            reply.push(b'+');
            reply.extend_from_slice(secret.as_bytes());
            reply
        }
        None => Zeroizing::new(vec![b'-']),
    };
    let _ = stream.write_all(&reply).await;
    let _ = stream.shutdown().await;
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::UnixListener;

    pub(super) async fn spawn(
        runtime_dir: &Path,
        slots: Slots,
        mut stopped: watch::Receiver<bool>,
    ) -> io::Result<(String, JoinHandle<()>)> {
        let path = runtime_dir.join("askpass.sock");
        let endpoint = path
            .to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "non-UTF-8 socket path"))?
            .to_string();
        let listener = UnixListener::bind(&path)?;
        if let Err(error) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        {
            let _ = std::fs::remove_file(&path);
            return Err(error);
        }
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _ = stopped.changed() => break,
                    accepted = listener.accept() => match accepted {
                        Ok((stream, _)) => {
                            connections.spawn(serve_connection(stream, Arc::clone(&slots)));
                        }
                        Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                    },
                    Some(_) = connections.join_next(), if !connections.is_empty() => {}
                }
            }
            connections.shutdown().await;
        });
        Ok((endpoint, task))
    }

    pub(super) fn cleanup(endpoint: &str) {
        let _ = std::fs::remove_file(endpoint);
    }

    pub(super) fn connect(endpoint: &str) -> io::Result<std::os::unix::net::UnixStream> {
        let stream = std::os::unix::net::UnixStream::connect(endpoint)?;
        stream.set_read_timeout(Some(CLIENT_TIMEOUT))?;
        stream.set_write_timeout(Some(CLIENT_TIMEOUT))?;
        Ok(stream)
    }
}

#[cfg(not(unix))]
mod platform {
    use super::*;
    use tokio::net::TcpListener;

    pub(super) async fn spawn(
        _runtime_dir: &Path,
        slots: Slots,
        mut stopped: watch::Receiver<bool>,
    ) -> io::Result<(String, JoinHandle<()>)> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let endpoint = listener.local_addr()?.to_string();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _ = stopped.changed() => break,
                    accepted = listener.accept() => match accepted {
                        Ok((stream, _)) => {
                            connections.spawn(serve_connection(stream, Arc::clone(&slots)));
                        }
                        Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                    },
                    Some(_) = connections.join_next(), if !connections.is_empty() => {}
                }
            }
            connections.shutdown().await;
        });
        Ok((endpoint, task))
    }

    pub(super) fn cleanup(_endpoint: &str) {}

    pub(super) fn connect(endpoint: &str) -> io::Result<std::net::TcpStream> {
        let address: std::net::SocketAddr = endpoint
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad askpass endpoint"))?;
        if !address.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "askpass endpoint is not loopback",
            ));
        }
        let stream = std::net::TcpStream::connect_timeout(&address, CLIENT_TIMEOUT)?;
        stream.set_read_timeout(Some(CLIENT_TIMEOUT))?;
        stream.set_write_timeout(Some(CLIENT_TIMEOUT))?;
        Ok(stream)
    }
}

/// Why the askpass client produced no secret.
#[derive(Debug, Error)]
pub enum AskpassError {
    #[error("askpass environment is missing or invalid")]
    MissingEnv,
    #[error("prompt is not a password prompt")]
    NotPasswordPrompt,
    #[error("askpass request denied")]
    Denied,
    #[error("askpass IPC failed: {0}")]
    Io(#[from] io::Error),
}

/// Only password prompts are answered. A passphrase, confirmation, or one-time-code prompt must
/// not receive the password or use up its single delivery.
fn is_password_prompt(prompt: &str) -> bool {
    prompt.to_ascii_lowercase().contains("password")
}

/// Fetches this hop's secret from the server.
pub fn fetch_secret(askpass: &AskpassEnv) -> Result<Zeroizing<Vec<u8>>, AskpassError> {
    let token = askpass.token().ok_or(AskpassError::MissingEnv)?;
    let mut stream = platform::connect(&askpass.endpoint)?;
    let request = Zeroizing::new(format!("{} {token}\n", askpass.hop));
    stream.write_all(request.as_bytes())?;
    let mut reply = Zeroizing::new(Vec::new());
    stream.read_to_end(&mut reply)?;
    match reply.first() {
        Some(b'+') => Ok(Zeroizing::new(reply[1..].to_vec())),
        _ => Err(AskpassError::Denied),
    }
}

/// Answers one `ssh` prompt on stdout using the askpass variables in the environment.
pub fn run_askpass_client(prompt: Option<&str>) -> Result<(), AskpassError> {
    if prompt.is_some_and(|p| !is_password_prompt(p)) {
        return Err(AskpassError::NotPasswordPrompt);
    }
    let askpass = AskpassEnv::from_process_env().ok_or(AskpassError::MissingEnv)?;
    let secret = fetch_secret(&askpass)?;
    let mut line = Zeroizing::new(Vec::with_capacity(secret.len() + 1));
    line.extend_from_slice(&secret);
    line.push(b'\n');
    let mut stdout = io::stdout().lock();
    stdout.write_all(&line)?;
    stdout.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_dir::RuntimeDir;

    fn client(server: &AskpassServer, hop: usize, token: &str) -> AskpassEnv {
        let mut tokens = server.tokens().to_vec();
        tokens[hop] = token.to_string();
        AskpassEnv {
            worker: "/unused/worker".into(),
            endpoint: server.endpoint().to_string(),
            tokens,
            hop,
        }
    }

    async fn fetch(env: AskpassEnv) -> Result<Vec<u8>, AskpassError> {
        tokio::task::spawn_blocking(move || fetch_secret(&env).map(|s| s.to_vec()))
            .await
            .unwrap()
    }

    async fn started() -> (RuntimeDir, AskpassServer) {
        let dir = RuntimeDir::create().unwrap();
        let secrets = vec![
            Some(Zeroizing::new("first pass".to_string())),
            None,
            Some(Zeroizing::new("third pass".to_string())),
        ];
        let server = AskpassServer::start(dir.path(), secrets).await.unwrap();
        (dir, server)
    }

    #[tokio::test]
    async fn askpass_valid_token_receives_only_its_own_secret() {
        let (_dir, server) = started().await;
        let tokens = server.tokens().to_vec();
        assert_eq!(tokens.len(), 3);
        assert!(tokens.iter().all(|t| t.len() == 64));
        assert_ne!(tokens[0], tokens[2]);
        assert_eq!(
            fetch(client(&server, 2, &tokens[2])).await.unwrap(),
            b"third pass"
        );
        assert_eq!(
            fetch(client(&server, 0, &tokens[0])).await.unwrap(),
            b"first pass"
        );
        server.shutdown().await;
    }

    #[tokio::test]
    async fn askpass_wrong_token_is_rejected_without_consuming() {
        let (_dir, server) = started().await;
        let tokens = server.tokens().to_vec();
        let wrong = "0".repeat(64);
        assert!(matches!(
            fetch(client(&server, 0, &wrong)).await,
            Err(AskpassError::Denied)
        ));
        // Another hop's valid token does not unlock this hop.
        assert!(matches!(
            fetch(client(&server, 0, &tokens[2])).await,
            Err(AskpassError::Denied)
        ));
        assert_eq!(
            fetch(client(&server, 0, &tokens[0])).await.unwrap(),
            b"first pass"
        );
        server.shutdown().await;
    }

    #[tokio::test]
    async fn askpass_secret_is_served_once() {
        let (_dir, server) = started().await;
        let token = server.tokens()[0].clone();
        assert!(fetch(client(&server, 0, &token)).await.is_ok());
        assert!(matches!(
            fetch(client(&server, 0, &token)).await,
            Err(AskpassError::Denied)
        ));
        server.shutdown().await;
    }

    #[tokio::test]
    async fn askpass_hop_without_password_is_denied() {
        let (_dir, server) = started().await;
        let token = server.tokens()[1].clone();
        assert!(matches!(
            fetch(client(&server, 1, &token)).await,
            Err(AskpassError::Denied)
        ));
        server.shutdown().await;
    }

    #[test]
    fn askpass_answers_only_password_prompts() {
        assert!(is_password_prompt("alice@example.com's password: "));
        assert!(is_password_prompt("Password: "));
        assert!(!is_password_prompt("Enter passphrase for key: "));
        assert!(!is_password_prompt("Verification code: "));
        assert!(!is_password_prompt("Are you sure (yes/no)? "));
    }

    #[test]
    fn askpass_token_compare() {
        assert!(tokens_match("abcd", "abcd"));
        assert!(!tokens_match("abcd", "abce"));
        assert!(!tokens_match("abcd", "abc"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn askpass_socket_is_private_and_removed() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, server) = started().await;
        let endpoint = server.endpoint().to_string();
        let mode = std::fs::metadata(&endpoint).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        server.shutdown().await;
        assert!(!Path::new(&endpoint).exists());
    }
}
