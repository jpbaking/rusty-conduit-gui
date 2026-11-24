//! In-process `russh` server and helpers. No external `sshd`, network, or `~/.ssh` access.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use conduit_core::{HostKeyLookup, HostKeyRecord, KnownHostsStore, Timestamp};
use conduit_ssh::{ChainOptions, ChannelPolicy, HopAuth, HopSpec, HostKeyVerifier, IpPreference};
use conduit_vault::{generate_key, KeyGenAlgorithm};
use russh::keys::{HashAlg, PrivateKey, PublicKey};
use russh::server::{self, Auth, Response};
use russh::{Channel, ChannelId, ChannelOpenFailure};
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

pub const PASSWORD: &str = "correct horse";
pub const PROMPT: &str = "Verification code: ";
pub const CODE: &str = "123456";

/// Resolves only inside the harness, so a client-side DNS lookup could never reach it.
pub const REMOTE_ONLY_HOST: &str = "origin.conduit-remote.invalid";
/// The harness refuses this destination with `AdministrativelyProhibited`.
pub const FORBIDDEN_HOST: &str = "forbidden.conduit-remote.invalid";

/// What one server observed.
#[derive(Default)]
pub struct NodeState {
    pub password_attempts: AtomicUsize,
    pub key_attempts: AtomicUsize,
    pub keyboard_answers: AtomicUsize,
    /// Every `direct-tcpip` host, exactly as the client sent it.
    pub requested_hosts: Mutex<Vec<String>>,
    /// `auth-agent-req@openssh.com` requests received.
    pub agent_requests: AtomicUsize,
    /// Every `exec` command received.
    pub exec_commands: Mutex<Vec<String>>,
    session: Mutex<Option<server::Handle>>,
}

struct NodeHandler {
    allowed_key: Option<PublicKey>,
    state: Arc<NodeState>,
    forwards: Vec<JoinHandle<()>>,
    /// Accepted session channels, held open for the life of the connection.
    sessions: Vec<Channel<server::Msg>>,
}

impl Drop for NodeHandler {
    fn drop(&mut self) {
        for forward in &self.forwards {
            forward.abort();
        }
    }
}

impl server::Handler for NodeHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, _user: &str, password: &str) -> Result<Auth, russh::Error> {
        self.state.password_attempts.fetch_add(1, Ordering::SeqCst);
        Ok(if password == PASSWORD {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        key: server::VerifiedPublicKey<'_>,
    ) -> Result<Auth, russh::Error> {
        self.state.key_attempts.fetch_add(1, Ordering::SeqCst);
        Ok(if self.allowed_key.as_ref() == Some(key.public_key) {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        _user: &str,
        _submethods: &str,
        response: Option<Response<'a>>,
    ) -> Result<Auth, russh::Error> {
        match response {
            None => Ok(Auth::Partial {
                name: "".into(),
                instructions: "".into(),
                prompts: vec![(PROMPT.into(), false)].into(),
            }),
            Some(mut answers) => {
                self.state.keyboard_answers.fetch_add(1, Ordering::SeqCst);
                let ok = answers.next().is_some_and(|a| a.as_ref() == CODE.as_bytes());
                Ok(if ok { Auth::Accept } else { Auth::reject() })
            }
        }
    }

    async fn auth_succeeded(&mut self, session: &mut server::Session) -> Result<(), russh::Error> {
        *self.state.session.lock().unwrap() = Some(session.handle());
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), russh::Error> {
        reply.accept().await;
        self.sessions.push(channel);
        Ok(())
    }

    async fn agent_request(
        &mut self,
        _channel: ChannelId,
        _session: &mut server::Session,
    ) -> Result<bool, russh::Error> {
        self.state.agent_requests.fetch_add(1, Ordering::SeqCst);
        Ok(true)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> Result<(), russh::Error> {
        self.state
            .exec_commands
            .lock()
            .unwrap()
            .push(String::from_utf8_lossy(data).to_string());
        session.channel_success(channel)?;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<server::Msg>,
        host: &str,
        port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), russh::Error> {
        self.state
            .requested_hosts
            .lock()
            .unwrap()
            .push(host.to_string());
        if host == FORBIDDEN_HOST {
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        let target = if host == REMOTE_ONLY_HOST {
            "127.0.0.1"
        } else {
            host
        };
        match TcpStream::connect((target, port as u16)).await {
            Ok(mut upstream) => {
                reply.accept().await;
                tokio::spawn(async move {
                    let mut stream = channel.into_stream();
                    let _ = copy_bidirectional(&mut stream, &mut upstream).await;
                });
            }
            Err(_) => reply.reject(ChannelOpenFailure::ConnectFailed).await,
        }
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut server::Session,
    ) -> Result<bool, russh::Error> {
        let Ok(listener) = TcpListener::bind((address, *port as u16)).await else {
            return Ok(false);
        };
        let bound = u32::from(listener.local_addr()?.port());
        *port = bound;
        let handle = session.handle();
        let connected = address.to_string();
        self.forwards.push(tokio::spawn(async move {
            while let Ok((mut socket, peer)) = listener.accept().await {
                let handle = handle.clone();
                let connected = connected.clone();
                tokio::spawn(async move {
                    let opened = handle
                        .channel_open_forwarded_tcpip(
                            connected,
                            bound,
                            peer.ip().to_string(),
                            u32::from(peer.port()),
                        )
                        .await;
                    if let Ok(channel) = opened {
                        let mut stream = channel.into_stream();
                        let _ = copy_bidirectional(&mut socket, &mut stream).await;
                    }
                });
            }
        }));
        Ok(true)
    }
}

/// A running in-process SSH server.
pub struct Node {
    pub port: u16,
    pub host_key: PublicKey,
    pub state: Arc<NodeState>,
}

impl Node {
    pub fn hosts(&self) -> Vec<String> {
        self.state.requested_hosts.lock().unwrap().clone()
    }

    /// Opens an `auth-agent@openssh.com` channel back to the client, as a remote `ssh` would.
    pub async fn open_agent_channel(&self) -> Result<Channel<server::Msg>, russh::Error> {
        let handle = self
            .state
            .session
            .lock()
            .unwrap()
            .clone()
            .expect("client authenticated");
        handle.channel_open_agent().await
    }

    /// Ends the authenticated client's session from the server side.
    pub async fn drop_session(&self) {
        let handle = self
            .state
            .session
            .lock()
            .unwrap()
            .clone()
            .expect("client authenticated");
        handle
            .disconnect(
                russh::Disconnect::ByApplication,
                "test drop".into(),
                "en".into(),
            )
            .await
            .expect("disconnect sent");
    }
}

pub async fn spawn_node(allowed_key: Option<PublicKey>) -> Node {
    let (host_key, _) = generate_key(KeyGenAlgorithm::Ed25519).unwrap();
    let public = host_key.public_key().clone();
    let config = Arc::new(server::Config {
        keys: vec![host_key],
        auth_rejection_time: Duration::from_millis(1),
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..server::Config::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let state = Arc::new(NodeState::default());
    let accept_state = Arc::clone(&state);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let handler = NodeHandler {
                allowed_key: allowed_key.clone(),
                state: Arc::clone(&accept_state),
                forwards: Vec::new(),
                sessions: Vec::new(),
            };
            let config = Arc::clone(&config);
            tokio::spawn(async move {
                if let Ok(session) = server::run_stream(config, socket, handler).await {
                    let _ = session.await;
                }
            });
        }
    });
    Node {
        port,
        host_key: public,
        state,
    }
}

pub fn new_user_key() -> PrivateKey {
    generate_key(KeyGenAlgorithm::Ed25519).unwrap().0
}

pub fn key_auth(key: &PrivateKey) -> HopAuth {
    HopAuth::Key(Arc::new(key.clone()))
}

pub fn password_auth(value: &str) -> HopAuth {
    HopAuth::Password(Zeroizing::new(value.to_string()))
}

pub fn spec(index: usize, node: &Node, auth: Vec<HopAuth>) -> HopSpec {
    HopSpec {
        hop_id: format!("hop-{index}"),
        host: "127.0.0.1".into(),
        port: node.port,
        user: "tester".into(),
        auth,
        policy: ChannelPolicy::default(),
    }
}

pub fn options() -> ChainOptions {
    ChainOptions {
        keepalive_interval: Duration::from_secs(15),
        keepalive_max: 3,
        connect_timeout: Duration::from_secs(10),
        ip_preference: IpPreference::V4,
    }
}

/// Pins `keys[i]` for hop `i` of `nodes`.
pub fn verifier_with(nodes: &[&Node], keys: &[&PublicKey]) -> HostKeyVerifier {
    let mut store = KnownHostsStore::default();
    for (index, (node, key)) in nodes.iter().zip(keys).enumerate() {
        store.insert(
            HostKeyLookup {
                hop_id: format!("hop-{index}"),
                host: "127.0.0.1".into(),
                port: node.port,
            },
            HostKeyRecord {
                algorithm: key.algorithm().as_str().to_string(),
                fingerprint_sha256: key.fingerprint(HashAlg::Sha256).to_string(),
                public_key_openssh: None,
                first_seen: Timestamp(1),
                approved: true,
            },
        );
    }
    HostKeyVerifier::new(store)
}

pub fn pin_all(nodes: &[&Node]) -> HostKeyVerifier {
    let keys: Vec<&PublicKey> = nodes.iter().map(|n| &n.host_key).collect();
    verifier_with(nodes, &keys)
}

/// A deterministic payload that exposes reordered, dropped, or corrupted bytes.
pub fn payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(31) ^ (i >> 8)) as u8)
        .collect()
}

pub async fn spawn_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut read, mut write) = socket.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    port
}

/// Minimal HTTP origin that answers every request with `body`.
pub async fn spawn_origin(body: Vec<u8>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let body = Arc::new(body);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let body = Arc::clone(&body);
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match socket.read(&mut chunk).await {
                        Ok(n) if n > 0 => request.extend_from_slice(&chunk[..n]),
                        _ => return,
                    }
                }
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(&body).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    port
}

/// Reserves a loopback port number for a listener the SSH server will bind.
pub async fn free_port() -> u16 {
    let listener = TcpListener::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await
        .unwrap();
    listener.local_addr().unwrap().port()
}

/// Sends an HTTP proxy `GET` and returns `(status_line, body)`.
pub async fn http_get(proxy: SocketAddr, host: &str, port: u16) -> (String, Vec<u8>) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let request = format!(
        "GET http://{host}:{port}/payload HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response has a header block");
    let head = String::from_utf8_lossy(&response[..split]).to_string();
    let status = head.lines().next().unwrap_or_default().to_string();
    (status, response[split + 4..].to_vec())
}

/// Performs a SOCKS5 `CONNECT` with an unresolved domain (`ATYP=3`) and returns the reply code
/// with the stream.
pub async fn socks5h_connect(proxy: SocketAddr, host: &str, port: u16) -> (u8, TcpStream) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut selected = [0u8; 2];
    stream.read_exact(&mut selected).await.unwrap();
    assert_eq!(selected, [5, 0]);

    let mut request = vec![5, 1, 0, 3, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await.unwrap();

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.unwrap();
    let address_len = match head[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.unwrap();
            usize::from(len[0])
        }
        other => panic!("invalid ATYP {other}"),
    };
    let mut rest = vec![0u8; address_len + 2];
    stream.read_exact(&mut rest).await.unwrap();
    (head[1], stream)
}

/// Writes `data` and reads it back concurrently, so large payloads cannot deadlock.
pub async fn echo_roundtrip(stream: TcpStream, data: &[u8]) -> Vec<u8> {
    let (mut read, mut write) = stream.into_split();
    let outgoing = data.to_vec();
    let writer = tokio::spawn(async move {
        write.write_all(&outgoing).await.unwrap();
        write
    });
    let mut received = vec![0u8; data.len()];
    read.read_exact(&mut received).await.unwrap();
    drop(writer.await.unwrap());
    received
}
