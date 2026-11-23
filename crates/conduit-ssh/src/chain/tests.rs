//! Loopback tests against in-process `russh` servers. No network or `~/.ssh` access.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use conduit_core::{HostKeyLookup, HostKeyRecord, KnownHostsStore, Timestamp};
use conduit_vault::{generate_key, KeyGenAlgorithm};
use russh::keys::{PublicKey, ssh_key};
use russh::server::{self, Auth, Response, Server as _};
use russh::ChannelOpenFailure;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::handler::{ForwardAllowlist, InboundForward};

const PASSWORD: &str = "correct horse";
const PROMPT: &str = "Verification code: ";

#[derive(Default)]
struct Stats {
    password_attempts: AtomicUsize,
    key_attempts: AtomicUsize,
    keyboard_answers: AtomicUsize,
    session: Mutex<Option<server::Handle>>,
}

#[derive(Clone)]
struct TestServer {
    allowed_key: Option<ssh_key::PublicKey>,
    stats: Arc<Stats>,
}

impl server::Server for TestServer {
    type Handler = Self;
    fn new_client(&mut self, _: Option<SocketAddr>) -> Self {
        self.clone()
    }
}

impl server::Handler for TestServer {
    type Error = russh::Error;

    async fn auth_password(&mut self, _user: &str, password: &str) -> Result<Auth, russh::Error> {
        self.stats.password_attempts.fetch_add(1, Ordering::SeqCst);
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
        self.stats.key_attempts.fetch_add(1, Ordering::SeqCst);
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
                self.stats.keyboard_answers.fetch_add(1, Ordering::SeqCst);
                let ok = answers.next().is_some_and(|a| a.as_ref() == b"123456");
                Ok(if ok { Auth::Accept } else { Auth::reject() })
            }
        }
    }

    async fn auth_succeeded(&mut self, session: &mut server::Session) -> Result<(), russh::Error> {
        *self.stats.session.lock().unwrap() = Some(session.handle());
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
    stats: Arc<Stats>,
}

impl Node {
    fn session(&self) -> server::Handle {
        self.stats
            .session
            .lock()
            .unwrap()
            .clone()
            .expect("client authenticated")
    }
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
    let stats = Arc::new(Stats::default());
    let mut factory = TestServer {
        allowed_key,
        stats: Arc::clone(&stats),
    };
    tokio::spawn(async move {
        while let Ok((socket, peer)) = listener.accept().await {
            let handler = factory.new_client(Some(peer));
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
        stats,
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

fn pin(store: &mut KnownHostsStore, index: usize, node: &Node, key: &PublicKey) {
    store.insert(
        HostKeyLookup {
            hop_id: format!("hop-{index}"),
            host: "127.0.0.1".into(),
            port: node.port,
        },
        HostKeyRecord {
            algorithm: key.algorithm().as_str().to_string(),
            fingerprint_sha256: key.fingerprint(HashAlg::Sha256).to_string(),
            first_seen: Timestamp(1),
            approved: true,
        },
    );
}

fn pin_all(nodes: &[&Node]) -> HostKeyVerifier {
    let mut store = KnownHostsStore::default();
    for (index, node) in nodes.iter().enumerate() {
        pin(&mut store, index, node, &node.host_key);
    }
    HostKeyVerifier::new(store)
}

fn password(value: &str) -> HopAuth {
    HopAuth::Password(Zeroizing::new(value.to_string()))
}

fn spec(index: usize, node: &Node, auth: Vec<HopAuth>) -> HopSpec {
    HopSpec {
        hop_id: format!("hop-{index}"),
        host: "127.0.0.1".into(),
        port: node.port,
        user: "tester".into(),
        auth,
        policy: ChannelPolicy::default(),
    }
}

fn options() -> ChainOptions {
    ChainOptions {
        keepalive_interval: Duration::from_secs(15),
        keepalive_max: 3,
        connect_timeout: Duration::from_secs(10),
        ip_preference: IpPreference::V4,
    }
}

async fn assert_echo(chain: &SshChain, port: u16) {
    let mut stream = chain
        .open_direct_tcpip("127.0.0.1", port)
        .await
        .unwrap()
        .into_stream();
    stream.write_all(b"through the chain").await.unwrap();
    let mut buffer = [0u8; 17];
    stream.read_exact(&mut buffer).await.unwrap();
    assert_eq!(&buffer, b"through the chain");
}

#[tokio::test]
async fn three_hop_chain_tunnels_traffic() {
    let (a, b, c) = (
        spawn_node(None).await,
        spawn_node(None).await,
        spawn_node(None).await,
    );
    let echo = spawn_echo().await;
    let hops = vec![
        spec(0, &a, vec![password(PASSWORD)]),
        spec(1, &b, vec![password(PASSWORD)]),
        spec(2, &c, vec![password(PASSWORD)]),
    ];
    let chain = connect_chain(&hops, &pin_all(&[&a, &b, &c]), &options(), None)
        .await
        .unwrap();
    assert_eq!(chain.hop_count(), 3);
    assert!(!chain.is_closed());
    assert_echo(&chain, echo).await;
    chain.disconnect().await;
}

#[tokio::test]
async fn chain_future_is_send() {
    let a = spawn_node(None).await;
    let echo = spawn_echo().await;
    let hops = vec![spec(0, &a, vec![password(PASSWORD)])];
    let verifier = pin_all(&[&a]);
    let task = tokio::spawn(async move {
        let chain = connect_chain(&hops, &verifier, &options(), None)
            .await
            .unwrap();
        assert_echo(&chain, echo).await;
        chain.disconnect().await;
    });
    task.await.unwrap();
}

#[tokio::test]
async fn empty_chain_is_rejected() {
    let result = connect_chain(&[], &HostKeyVerifier::default(), &options(), None).await;
    assert!(matches!(result, Err(SshError::InvalidChain(_))));
}

#[tokio::test]
async fn unknown_host_key_stops_before_credentials_are_sent() {
    let (a, b) = (spawn_node(None).await, spawn_node(None).await);
    let hops = vec![
        spec(0, &a, vec![password(PASSWORD)]),
        spec(1, &b, vec![password(PASSWORD)]),
    ];
    let error = connect_chain(&hops, &pin_all(&[&a]), &options(), None)
        .await
        .unwrap_err();
    match &error {
        SshError::HostKeyUnknown {
            hop_index, sha256, ..
        } => {
            assert_eq!(*hop_index, 1);
            assert_eq!(
                sha256,
                &b.host_key.fingerprint(HashAlg::Sha256).to_string()
            );
        }
        other => panic!("expected HostKeyUnknown, got {other:?}"),
    }
    assert!(error.is_lockout_sensitive());
    assert_eq!(a.stats.password_attempts.load(Ordering::SeqCst), 1);
    assert_eq!(b.stats.password_attempts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn changed_host_key_stops_before_credentials_are_sent() {
    let a = spawn_node(None).await;
    let wrong = generate_key(KeyGenAlgorithm::Ed25519).unwrap().0;
    let mut store = KnownHostsStore::default();
    pin(&mut store, 0, &a, wrong.public_key());
    let hops = vec![spec(0, &a, vec![password(PASSWORD)])];
    let error = connect_chain(&hops, &HostKeyVerifier::new(store), &options(), None)
        .await
        .unwrap_err();
    assert!(matches!(error, SshError::HostKeyChanged { hop_index: 0, .. }));
    assert_eq!(a.stats.password_attempts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn wrong_password_is_auth_failed_after_one_attempt() {
    let a = spawn_node(None).await;
    let hops = vec![spec(0, &a, vec![password("wrong")])];
    let error = connect_chain(&hops, &pin_all(&[&a]), &options(), None)
        .await
        .unwrap_err();
    assert!(matches!(error, SshError::AuthFailed { hop_index: 0, .. }));
    assert!(error.is_lockout_sensitive());
    assert!(!error.to_string().contains("wrong"));
    assert_eq!(a.stats.password_attempts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn no_auth_methods_is_auth_failed() {
    let a = spawn_node(None).await;
    let hops = vec![spec(0, &a, Vec::new())];
    let error = connect_chain(&hops, &pin_all(&[&a]), &options(), None)
        .await
        .unwrap_err();
    assert!(matches!(error, SshError::AuthFailed { .. }));
}

#[tokio::test]
async fn methods_are_tried_in_order_once_each() {
    let key = Arc::new(generate_key(KeyGenAlgorithm::Ed25519).unwrap().0);
    let a = spawn_node(Some(key.public_key().clone())).await;
    let hops = vec![spec(0, &a, vec![password("wrong"), HopAuth::Key(key)])];
    let chain = connect_chain(&hops, &pin_all(&[&a]), &options(), None)
        .await
        .unwrap();
    assert_eq!(a.stats.password_attempts.load(Ordering::SeqCst), 1);
    assert_eq!(a.stats.key_attempts.load(Ordering::SeqCst), 1);
    chain.disconnect().await;
}

#[tokio::test]
async fn ecdsa_key_authenticates() {
    let key = Arc::new(generate_key(KeyGenAlgorithm::EcdsaP256).unwrap().0);
    let a = spawn_node(Some(key.public_key().clone())).await;
    let hops = vec![spec(0, &a, vec![HopAuth::Key(key)])];
    connect_chain(&hops, &pin_all(&[&a]), &options(), None)
        .await
        .unwrap()
        .disconnect()
        .await;
}

#[tokio::test]
async fn keyboard_interactive_answers_known_prompt() {
    let a = spawn_node(None).await;
    let auth = HopAuth::KeyboardInteractive(vec![KeyboardAnswer {
        prompt: "verification code:".into(),
        answer: Zeroizing::new("123456".into()),
    }]);
    let hops = vec![spec(0, &a, vec![auth])];
    connect_chain(&hops, &pin_all(&[&a]), &options(), None)
        .await
        .unwrap()
        .disconnect()
        .await;
    assert_eq!(a.stats.keyboard_answers.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn keyboard_interactive_never_answers_unknown_prompt() {
    let a = spawn_node(None).await;
    let auth = HopAuth::KeyboardInteractive(vec![KeyboardAnswer {
        prompt: "Password:".into(),
        answer: Zeroizing::new("123456".into()),
    }]);
    let hops = vec![spec(0, &a, vec![auth])];
    let error = connect_chain(&hops, &pin_all(&[&a]), &options(), None)
        .await
        .unwrap_err();
    assert!(matches!(error, SshError::AuthFailed { .. }));
    assert_eq!(a.stats.keyboard_answers.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn refused_tcp_is_a_retryable_connect_error() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let hop = HopSpec {
        hop_id: "hop-0".into(),
        host: "127.0.0.1".into(),
        port,
        user: "tester".into(),
        auth: vec![password(PASSWORD)],
        policy: ChannelPolicy::default(),
    };
    let error = connect_chain(&[hop], &HostKeyVerifier::default(), &options(), None)
        .await
        .unwrap_err();
    assert!(matches!(error, SshError::Connect { hop_index: 0, .. }));
    assert!(!error.is_lockout_sensitive());
}

#[tokio::test]
async fn silent_server_times_out_as_retryable() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hop = HopSpec {
        hop_id: "hop-0".into(),
        host: "127.0.0.1".into(),
        port,
        user: "tester".into(),
        auth: vec![password(PASSWORD)],
        policy: ChannelPolicy::default(),
    };
    let short = ChainOptions {
        connect_timeout: Duration::from_millis(100),
        ..options()
    };
    let error = connect_chain(&[hop], &HostKeyVerifier::default(), &short, None)
        .await
        .unwrap_err();
    assert!(matches!(error, SshError::Timeout { hop_index: 0, .. }));
    assert!(!error.is_lockout_sensitive());
    drop(listener);
}

#[tokio::test]
async fn test_chain_reports_each_hop() {
    let (a, b, c) = (
        spawn_node(None).await,
        spawn_node(None).await,
        spawn_node(None).await,
    );
    let hops = vec![
        spec(0, &a, vec![password(PASSWORD)]),
        spec(1, &b, vec![password("wrong")]),
        spec(2, &c, vec![password(PASSWORD)]),
    ];
    let report = test_chain(&hops, &pin_all(&[&a, &b, &c]), &options()).await;
    assert!(!report.all_connected());
    assert!(matches!(report.hops[0].status, HopStatus::Connected));
    assert!(matches!(
        report.hops[1].status,
        HopStatus::Failed(SshError::AuthFailed { hop_index: 1, .. })
    ));
    assert!(matches!(report.hops[2].status, HopStatus::NotAttempted));
    assert_eq!(report.hops[2].elapsed, Duration::ZERO);
    assert_eq!(report.first_failure().unwrap().hop_index, 1);
    assert_eq!(c.stats.password_attempts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn test_chain_passes_on_a_healthy_chain() {
    let (a, b) = (spawn_node(None).await, spawn_node(None).await);
    let hops = vec![
        spec(0, &a, vec![password(PASSWORD)]),
        spec(1, &b, vec![password(PASSWORD)]),
    ];
    let report = test_chain(&hops, &pin_all(&[&a, &b]), &options()).await;
    assert!(report.all_connected());
    assert!(report.first_failure().is_none());
}

#[tokio::test]
async fn server_initiated_channels_are_denied_by_default() {
    let a = spawn_node(None).await;
    let hops = vec![spec(0, &a, vec![password(PASSWORD)])];
    let chain = connect_chain(&hops, &pin_all(&[&a]), &options(), None)
        .await
        .unwrap();
    let session = a.session();
    assert!(session.channel_open_agent().await.is_err());
    assert!(session.channel_open_session().await.is_err());
    assert!(session.channel_open_x11("127.0.0.1", 6000).await.is_err());
    assert!(session
        .channel_open_direct_tcpip("127.0.0.1", 22, "127.0.0.1", 1)
        .await
        .is_err());
    assert!(session
        .channel_open_direct_streamlocal("/tmp/conduit-test.sock")
        .await
        .is_err());
    assert!(session
        .channel_open_forwarded_streamlocal("/tmp/conduit-test.sock")
        .await
        .is_err());
    assert!(session
        .channel_open_forwarded_tcpip("127.0.0.1", 8080, "127.0.0.1", 1)
        .await
        .is_err());
    assert!(!chain.is_closed(), "denials must not break the session");
    chain.disconnect().await;
}

#[tokio::test]
async fn only_allowlisted_reverse_forwards_are_accepted() {
    let a = spawn_node(None).await;
    let allowlist = ForwardAllowlist::default();
    allowlist.allow("127.0.0.1", 8080);
    let (tx, mut rx) = mpsc::channel::<InboundForward>(4);
    let mut hop = spec(0, &a, vec![password(PASSWORD)]);
    hop.policy = ChannelPolicy {
        forward_allowlist: allowlist,
        forward_channels: Some(tx),
        ..ChannelPolicy::default()
    };
    let chain = connect_chain(&[hop], &pin_all(&[&a]), &options(), None)
        .await
        .unwrap();
    let session = a.session();
    assert!(session
        .channel_open_forwarded_tcpip("127.0.0.1", 9090, "127.0.0.1", 1)
        .await
        .is_err());
    session
        .channel_open_forwarded_tcpip("127.0.0.1", 8080, "10.0.0.9", 4242)
        .await
        .unwrap();
    let inbound = rx.recv().await.unwrap();
    assert_eq!(inbound.connected_port, 8080);
    assert_eq!(inbound.originator_address, "10.0.0.9");
    assert!(rx.try_recv().is_err());
    chain.disconnect().await;
}

#[tokio::test]
async fn opted_in_hop_accepts_agent_channel() {
    let a = spawn_node(None).await;
    let (tx, mut rx) = mpsc::channel(1);
    let mut hop = spec(0, &a, vec![password(PASSWORD)]);
    hop.policy.agent_channels = Some(tx);
    let chain = connect_chain(&[hop], &pin_all(&[&a]), &options(), None)
        .await
        .unwrap();
    a.session().channel_open_agent().await.unwrap();
    assert!(rx.recv().await.is_some());
    chain.disconnect().await;
}

#[tokio::test]
async fn server_disconnect_is_notified() {
    let a = spawn_node(None).await;
    let hops = vec![spec(0, &a, vec![password(PASSWORD)])];
    let (tx, mut rx) = mpsc::unbounded_channel();
    let chain = connect_chain(&hops, &pin_all(&[&a]), &options(), Some(tx))
        .await
        .unwrap();
    a.session()
        .disconnect(Disconnect::ByApplication, "bye".into(), "en".into())
        .await
        .unwrap();
    let event = timeout(Duration::from_secs(5), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!((event.hop_index, event.hop_id.as_str()), (0, "hop-0"));
    assert!(event.detail.contains("bye"));
    drop(chain);
}

#[test]
fn options_map_from_tunnel_config() {
    let tunnel = TunnelConfig::default();
    let mapped = ChainOptions::from_tunnel(&tunnel).unwrap();
    assert_eq!(mapped.keepalive_interval, tunnel.server_alive_interval);
    assert_eq!(mapped.keepalive_max, 3);
    assert_eq!(mapped.ip_preference, IpPreference::V4);

    let config = mapped.client_config();
    assert_eq!(config.keepalive_interval, Some(Duration::from_secs(15)));
    assert_eq!(config.keepalive_max, 3);

    let disabled = ChainOptions {
        keepalive_interval: Duration::ZERO,
        ..mapped
    };
    assert_eq!(disabled.client_config().keepalive_interval, None);

    let bad = TunnelConfig {
        ip_version: "5".into(),
        ..TunnelConfig::default()
    };
    assert!(matches!(
        ChainOptions::from_tunnel(&bad),
        Err(SshError::InvalidChain(_))
    ));
}

#[test]
fn credentials_are_redacted_in_debug() {
    let auth = password("hunter2");
    assert!(!format!("{auth:?}").contains("hunter2"));
    let kbd = HopAuth::KeyboardInteractive(vec![KeyboardAnswer {
        prompt: "code".into(),
        answer: Zeroizing::new("hunter2".into()),
    }]);
    assert!(!format!("{kbd:?}").contains("hunter2"));
}
