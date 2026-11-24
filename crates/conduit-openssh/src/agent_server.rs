//! Serves one [`ScopedAgent`] on a private local endpoint for an `ssh` child process.
//!
//! The endpoint is a `0600` Unix socket inside the runtime directory, or a local-only named
//! pipe on Windows. The ambient `SSH_AUTH_SOCK` is never read.

use std::io;
use std::path::Path;
use std::sync::Arc;

use conduit_ssh::agent_wire::serve;
use conduit_ssh::ScopedAgent;
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

/// Longest endpoint name. Keeps socket paths inside the macOS 104-byte limit.
const MAX_NAME_LEN: usize = 16;

/// A running agent endpoint. Stops when shut down or dropped.
#[derive(Debug)]
pub struct IsolatedAgentServer {
    endpoint: String,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl IsolatedAgentServer {
    /// Starts serving `agent` at an endpoint named `name` inside `runtime_dir`.
    pub async fn start(
        runtime_dir: &Path,
        name: &str,
        agent: Arc<ScopedAgent>,
    ) -> io::Result<Self> {
        check_name(name)?;
        let (stop, stopped) = watch::channel(false);
        let (endpoint, task) = platform::spawn(runtime_dir, name, agent, stopped)?;
        Ok(Self {
            endpoint,
            stop,
            task: Some(task),
        })
    }

    /// The socket path or pipe name to use as `IdentityAgent`.
    pub fn endpoint_path(&self) -> String {
        self.endpoint.clone()
    }

    /// Stops accepting, closes open connections, and removes the socket.
    pub async fn shutdown(mut self) {
        let _ = self.stop.send(true);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
        platform::cleanup(&self.endpoint);
    }
}

impl Drop for IsolatedAgentServer {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            let _ = self.stop.send(true);
            task.abort();
            platform::cleanup(&self.endpoint);
        }
    }
}

fn check_name(name: &str) -> io::Result<()> {
    let valid = !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'));
    if valid {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid agent endpoint name {name:?}"),
        ))
    }
}

fn spawn_connection<S>(connections: &mut JoinSet<()>, mut stream: S, agent: Arc<ScopedAgent>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    connections.spawn(async move {
        // A client that disconnects or sends a bad frame ends only its own connection.
        let _ = serve(&mut stream, &agent).await;
    });
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;
    use tokio::net::UnixListener;

    pub(super) fn spawn(
        runtime_dir: &Path,
        name: &str,
        agent: Arc<ScopedAgent>,
        mut stopped: watch::Receiver<bool>,
    ) -> io::Result<(String, JoinHandle<()>)> {
        let path = runtime_dir.join(format!("{name}.sock"));
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
                            spawn_connection(&mut connections, stream, Arc::clone(&agent));
                        }
                        // For example out of file descriptors. Back off instead of spinning.
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
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::time::Duration;
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

    fn create(endpoint: &str, first: bool) -> io::Result<NamedPipeServer> {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create(endpoint)
    }

    pub(super) fn spawn(
        runtime_dir: &Path,
        name: &str,
        agent: Arc<ScopedAgent>,
        mut stopped: watch::Receiver<bool>,
    ) -> io::Result<(String, JoinHandle<()>)> {
        let scope = runtime_dir
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bad runtime dir"))?;
        let endpoint = format!(r"\\.\pipe\{scope}-{name}");
        let mut server = create(&endpoint, true)?;
        let pipe = endpoint.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _ = stopped.changed() => break,
                    connected = server.connect() => {
                        if connected.is_err() {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            continue;
                        }
                        let Ok(next) = create(&pipe, false) else { break };
                        let stream = std::mem::replace(&mut server, next);
                        spawn_connection(&mut connections, stream, Arc::clone(&agent));
                    },
                    Some(_) = connections.join_next(), if !connections.is_empty() => {}
                }
            }
            connections.shutdown().await;
        });
        Ok((endpoint, task))
    }

    pub(super) fn cleanup(_endpoint: &str) {}
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::runtime_dir::RuntimeDir;
    use conduit_ssh::agent_wire::{
        SSH_AGENTC_ADD_IDENTITY, SSH_AGENTC_REQUEST_IDENTITIES, SSH_AGENTC_SIGN_REQUEST,
        SSH_AGENT_FAILURE, SSH_AGENT_IDENTITIES_ANSWER, SSH_AGENT_SIGN_RESPONSE,
    };
    use conduit_vault::{generate_key, KeyGenAlgorithm};
    use russh::keys::signature::Verifier;
    use russh::keys::ssh_key::Signature;
    use russh::keys::PrivateKey;
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    fn put_string(out: &mut Vec<u8>, value: &[u8]) {
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }

    async fn roundtrip(stream: &mut UnixStream, body: &[u8]) -> Vec<u8> {
        let mut message = Vec::new();
        put_string(&mut message, body);
        stream.write_all(&message).await.unwrap();
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await.unwrap();
        let mut reply = vec![0u8; u32::from_be_bytes(header) as usize];
        stream.read_exact(&mut reply).await.unwrap();
        reply
    }

    async fn started() -> (RuntimeDir, Arc<PrivateKey>, IsolatedAgentServer) {
        let dir = RuntimeDir::create().unwrap();
        let key = Arc::new(generate_key(KeyGenAlgorithm::Ed25519).unwrap().0);
        let agent = ScopedAgent::seal("hop", [(Arc::clone(&key), "work".to_string())], None);
        let server = IsolatedAgentServer::start(dir.path(), "agent-0", Arc::new(agent))
            .await
            .unwrap();
        (dir, key, server)
    }

    #[tokio::test]
    async fn agent_server_socket_is_private() {
        let (dir, _key, server) = started().await;
        let endpoint = server.endpoint_path();
        assert!(Path::new(&endpoint).starts_with(dir.path()));
        let mode = std::fs::metadata(&endpoint).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        server.shutdown().await;
    }

    #[tokio::test]
    async fn agent_server_lists_signs_and_rejects_add_identity() {
        let (_dir, key, server) = started().await;
        let mut stream = UnixStream::connect(server.endpoint_path()).await.unwrap();
        let blob = key.public_key().to_bytes().unwrap();

        let reply = roundtrip(&mut stream, &[SSH_AGENTC_REQUEST_IDENTITIES]).await;
        let mut expected = vec![SSH_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 1];
        put_string(&mut expected, &blob);
        put_string(&mut expected, b"work");
        assert_eq!(reply, expected);

        let mut sign = vec![SSH_AGENTC_SIGN_REQUEST];
        put_string(&mut sign, &blob);
        put_string(&mut sign, b"challenge");
        sign.extend_from_slice(&0u32.to_be_bytes());
        let reply = roundtrip(&mut stream, &sign).await;
        assert_eq!(reply[0], SSH_AGENT_SIGN_RESPONSE);
        let len = u32::from_be_bytes(reply[1..5].try_into().unwrap()) as usize;
        let signature = Signature::try_from(&reply[5..5 + len]).unwrap();
        key.public_key()
            .key_data()
            .verify(b"challenge", &signature)
            .unwrap();

        let reply = roundtrip(&mut stream, &[SSH_AGENTC_ADD_IDENTITY, 1, 2, 3]).await;
        assert_eq!(reply, [SSH_AGENT_FAILURE]);

        // The connection survives a rejected request.
        let reply = roundtrip(&mut stream, &[SSH_AGENTC_REQUEST_IDENTITIES]).await;
        assert_eq!(reply[0], SSH_AGENT_IDENTITIES_ANSWER);
        server.shutdown().await;
    }

    #[tokio::test]
    async fn agent_server_handles_concurrent_clients() {
        let (_dir, _key, server) = started().await;
        let mut first = UnixStream::connect(server.endpoint_path()).await.unwrap();
        let mut second = UnixStream::connect(server.endpoint_path()).await.unwrap();
        for stream in [&mut first, &mut second] {
            let reply = roundtrip(stream, &[SSH_AGENTC_REQUEST_IDENTITIES]).await;
            assert_eq!(reply[0], SSH_AGENT_IDENTITIES_ANSWER);
        }
        server.shutdown().await;
    }

    #[tokio::test]
    async fn agent_server_shutdown_closes_clients_and_removes_socket() {
        let (_dir, _key, server) = started().await;
        let endpoint = server.endpoint_path();
        let mut stream = UnixStream::connect(&endpoint).await.unwrap();
        roundtrip(&mut stream, &[SSH_AGENTC_REQUEST_IDENTITIES]).await;
        server.shutdown().await;
        assert!(!Path::new(&endpoint).exists());
        let mut buffer = [0u8; 1];
        assert!(matches!(stream.read(&mut buffer).await, Ok(0) | Err(_)));
        assert!(UnixStream::connect(&endpoint).await.is_err());
    }

    #[tokio::test]
    async fn agent_server_drop_removes_socket() {
        let (_dir, _key, server) = started().await;
        let endpoint = server.endpoint_path();
        drop(server);
        assert!(!Path::new(&endpoint).exists());
    }

    #[tokio::test]
    async fn agent_server_rejects_unsafe_names() {
        let dir = RuntimeDir::create().unwrap();
        let agent = Arc::new(ScopedAgent::seal("hop", [], None));
        for name in [
            "",
            "../escape",
            "a/b",
            "has space",
            "name-that-is-far-too-long",
        ] {
            let error = IsolatedAgentServer::start(dir.path(), name, Arc::clone(&agent))
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{name}");
        }
    }
}
