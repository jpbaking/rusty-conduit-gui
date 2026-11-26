//! Real `/usr/bin/ssh` against in-process `russh` servers. No `sshd`, network, or `~/.ssh`.
#![cfg(unix)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use conduit_core::{HostKeyLookup, HostKeyRecord, KnownHostsStore, Timestamp};
use conduit_openssh::{
    LogFn, OpenSshError, OpenSshSupervisor, SupervisorHop, SupervisorOptions, TunnelState,
};
use conduit_ssh::ScopedAgent;
use conduit_vault::{generate_key, KeyGenAlgorithm};
use russh::keys::{HashAlg, PrivateKey, PublicKey};
use russh::server::{self, Auth};
use russh::{Channel, ChannelOpenFailure};
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zeroize::Zeroizing;

const SSH: &str = "/usr/bin/ssh";
const PASSWORD: &str = "correct horse";

#[derive(Default)]
struct NodeState {
    password_attempts: AtomicUsize,
    key_accepts: AtomicUsize,
    forwards: AtomicUsize,
}

struct NodeHandler {
    allowed_key: Option<PublicKey>,
    state: Arc<NodeState>,
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
        Ok(if self.allowed_key.as_ref() == Some(key.public_key) {
            self.state.key_accepts.fetch_add(1, Ordering::SeqCst);
            Auth::Accept
        } else {
            Auth::reject()
        })
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
        self.state.forwards.fetch_add(1, Ordering::SeqCst);
        match TcpStream::connect((host, port as u16)).await {
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
}

struct Node {
    port: u16,
    host_key: PublicKey,
    state: Arc<NodeState>,
}

async fn spawn_node(allowed_key: Option<PublicKey>) -> Node {
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

async fn spawn_echo() -> u16 {
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

fn user_key() -> Arc<PrivateKey> {
    Arc::new(generate_key(KeyGenAlgorithm::Ed25519).unwrap().0)
}

fn key_hop(index: usize, node: &Node, key: &Arc<PrivateKey>) -> SupervisorHop {
    let hop_id = format!("hop-{index}");
    let agent = ScopedAgent::seal(
        hop_id.clone(),
        [(Arc::clone(key), "test".to_string())],
        None,
    );
    SupervisorHop {
        hop_id,
        host: "127.0.0.1".into(),
        port: node.port,
        user: "tester".into(),
        password: None,
        agent: Some(Arc::new(agent)),
    }
}

fn password_hop(index: usize, node: &Node, password: &str) -> SupervisorHop {
    SupervisorHop {
        hop_id: format!("hop-{index}"),
        host: "127.0.0.1".into(),
        port: node.port,
        user: "tester".into(),
        password: Some(Zeroizing::new(password.to_string())),
        agent: None,
    }
}

fn pin(store: &mut KnownHostsStore, index: usize, port: u16, key: &PublicKey) {
    let text = key.to_openssh().unwrap();
    let openssh = text.split(' ').take(2).collect::<Vec<_>>().join(" ");
    store.insert(
        HostKeyLookup {
            hop_id: format!("hop-{index}"),
            host: "127.0.0.1".into(),
            port,
        },
        HostKeyRecord {
            algorithm: key.algorithm().as_str().to_string(),
            fingerprint_sha256: key.fingerprint(HashAlg::Sha256).to_string(),
            first_seen: Timestamp(1),
            approved: true,
            public_key_openssh: Some(openssh),
        },
    );
}

fn pin_all(nodes: &[&Node]) -> KnownHostsStore {
    let mut store = KnownHostsStore::default();
    for (index, node) in nodes.iter().enumerate() {
        pin(&mut store, index, node.port, &node.host_key);
    }
    store
}

async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

async fn options(hops: Vec<SupervisorHop>, known_hosts: KnownHostsStore) -> SupervisorOptions {
    SupervisorOptions {
        ssh_bin: SSH.into(),
        worker_bin: Some(PathBuf::from(env!("CARGO_BIN_EXE_conduit-worker"))),
        hops,
        known_hosts,
        bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        socks_port: free_port().await,
        reverse_forwards: Vec::new(),
        extra_args: Vec::new(),
        ip_version: "4".into(),
        server_alive_interval: Duration::from_secs(15),
        server_alive_count_max: 3,
        startup_timeout: Duration::from_secs(20),
        log: None,
    }
}

/// SOCKS5 `CONNECT` to `127.0.0.1:port`, then an echo roundtrip.
async fn assert_socks_echo(proxy: SocketAddr, port: u16) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut selected = [0u8; 2];
    stream.read_exact(&mut selected).await.unwrap();
    assert_eq!(selected, [5, 0]);

    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "SOCKS reply {reply:?}");

    let payload: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
    let (mut read, mut write) = stream.into_split();
    let outgoing = payload.clone();
    let writer = tokio::spawn(async move {
        write.write_all(&outgoing).await.unwrap();
        write
    });
    let mut received = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(15), read.read_exact(&mut received))
        .await
        .expect("echo timed out")
        .unwrap();
    drop(writer.await.unwrap());
    assert_eq!(received, payload);
}

#[tokio::test(flavor = "multi_thread")]
async fn single_hop_key_auth_via_isolated_agent() {
    let key = user_key();
    let node = spawn_node(Some(key.public_key().clone())).await;
    let echo = spawn_echo().await;
    let hops = vec![key_hop(0, &node, &key)];
    let supervisor = OpenSshSupervisor::start(options(hops, pin_all(&[&node])).await)
        .await
        .unwrap();
    assert_eq!(
        *supervisor.state().borrow(),
        TunnelState::Ready(supervisor.socks_addr())
    );
    assert_socks_echo(supervisor.socks_addr(), echo).await;
    assert_eq!(node.state.key_accepts.load(Ordering::SeqCst), 1);
    assert_eq!(node.state.password_attempts.load(Ordering::SeqCst), 0);
    supervisor.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn single_hop_password_auth_via_askpass() {
    let node = spawn_node(None).await;
    let echo = spawn_echo().await;
    let hops = vec![password_hop(0, &node, PASSWORD)];
    let supervisor = OpenSshSupervisor::start(options(hops, pin_all(&[&node])).await)
        .await
        .unwrap();
    assert_socks_echo(supervisor.socks_addr(), echo).await;
    assert_eq!(node.state.password_attempts.load(Ordering::SeqCst), 1);
    supervisor.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn two_hop_chain_with_mixed_auth_via_hop_proxy() {
    let key = user_key();
    let first = spawn_node(Some(key.public_key().clone())).await;
    let second = spawn_node(None).await;
    let echo = spawn_echo().await;
    let hops = vec![key_hop(0, &first, &key), password_hop(1, &second, PASSWORD)];
    let supervisor = OpenSshSupervisor::start(options(hops, pin_all(&[&first, &second])).await)
        .await
        .unwrap();
    assert_socks_echo(supervisor.socks_addr(), echo).await;
    assert_eq!(first.state.key_accepts.load(Ordering::SeqCst), 1);
    assert_eq!(first.state.forwards.load(Ordering::SeqCst), 1);
    assert_eq!(second.state.password_attempts.load(Ordering::SeqCst), 1);
    assert_eq!(second.state.forwards.load(Ordering::SeqCst), 1);
    supervisor.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_password_is_auth_failed_and_tried_once() {
    let node = spawn_node(None).await;
    let hops = vec![password_hop(0, &node, "wrong password")];
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    let log: LogFn = Arc::new(move |line| sink.lock().unwrap().push(line.to_string()));
    let mut options = options(hops, pin_all(&[&node])).await;
    options.log = Some(log);
    let error = OpenSshSupervisor::start(options).await.unwrap_err();
    assert!(matches!(error, OpenSshError::AuthFailed(_)), "{error}");
    assert_eq!(node.state.password_attempts.load(Ordering::SeqCst), 1);
    let lines = lines.lock().unwrap();
    assert!(lines.iter().any(|l| l.contains("Permission denied")));
    assert!(!lines.iter().any(|l| l.contains("wrong password")));
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_pinned_host_key_is_a_hard_stop() {
    let node = spawn_node(None).await;
    let (other, _) = generate_key(KeyGenAlgorithm::Ed25519).unwrap();
    let mut store = KnownHostsStore::default();
    pin(&mut store, 0, node.port, other.public_key());
    let hops = vec![password_hop(0, &node, PASSWORD)];
    let error = OpenSshSupervisor::start(options(hops, store).await)
        .await
        .unwrap_err();
    assert!(matches!(error, OpenSshError::HostKeyChanged(_)), "{error}");
    assert_eq!(node.state.password_attempts.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn runtime_dir_is_removed_and_ssh_stops_on_drop() {
    let node = spawn_node(None).await;
    let hops = vec![password_hop(0, &node, PASSWORD)];
    let supervisor = OpenSshSupervisor::start(options(hops, pin_all(&[&node])).await)
        .await
        .unwrap();
    let path = supervisor.runtime_path().to_path_buf();
    let socks = supervisor.socks_addr();
    assert!(path.is_dir());
    drop(supervisor);
    assert!(!path.exists());

    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(socks).await.is_ok() {
        assert!(Instant::now() < deadline, "ssh still listening after drop");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
