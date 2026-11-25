//! End-to-end loopback tests: real `rusty_conduit_ssh` engines over in-process SSH servers.

// Each test binary uses a different subset of the shared helpers.
#[allow(dead_code)]
mod common;

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use conduit_ssh::{
    connect_chain, reverse_policy, AtomicStats, HopAuth, HopSpec, KeyboardAnswer, RemoteForward, ReverseRelay,
    RusshDialer, SshChain, SshError, StatsDialer,
};
use russh::keys::PrivateKey;
use rusty_conduit_ssh::config::Config;
use rusty_conduit_ssh::http::HttpProxy;
use rusty_conduit_ssh::logging::{AccessLogConfig, AccessLogger, LogFormat, LogLevel, Logger};
use rusty_conduit_ssh::net::UpstreamDialer;
use rusty_conduit_ssh::reverse::ReverseProxy;
use rusty_conduit_ssh::server::{ListenPlan, ProtocolHandlers, Server, ShutdownReport};
use rusty_conduit_ssh::socks::SocksProxy;
use rusty_conduit_ssh::EngineHandlers;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

const PAYLOAD_LEN: usize = 256 * 1024;
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
const SOCKS_CONNECTION_REFUSED: u8 = 0x05;

fn quiet_logger() -> Logger {
    Logger::with_writer(LogLevel::Quiet, Box::new(io::sink()))
}

async fn quiet_access(logger: &Logger) -> AccessLogger {
    let config = AccessLogConfig::new(LogLevel::Quiet, LogFormat::Text, None, None);
    AccessLogger::start(config, logger.clone()).await.unwrap()
}

/// Real forward HTTP and SOCKS engines on ephemeral loopback ports.
struct Engines {
    http: SocketAddr,
    socks: SocketAddr,
    /// Cancels the server, without naming the engine's `tokio-util` token type here.
    cancel: Box<dyn FnOnce() + Send>,
    run: JoinHandle<ShutdownReport>,
}

impl Engines {
    async fn start(dialer: Arc<dyn UpstreamDialer>) -> Self {
        let logger = quiet_logger();
        let access = quiet_access(&logger).await;
        let handlers: Arc<dyn ProtocolHandlers> = Arc::new(EngineHandlers::new(
            HttpProxy::new(access.clone(), logger.clone(), Arc::clone(&dialer)),
            SocksProxy::new(access, logger.clone(), dialer),
        ));
        let ephemeral = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let plan = ListenPlan::Separate {
            http: Some(ephemeral),
            socks: Some(ephemeral),
        };
        let server = Server::bind(plan, handlers, logger).await.unwrap();
        let http = server.local_http_addr().unwrap();
        let socks = server.local_socks_addr().unwrap();
        let token = server.shutdown_token();
        let run = tokio::spawn(server.run());
        Self {
            http,
            socks,
            cancel: Box::new(move || token.cancel()),
            run,
        }
    }

    async fn stop(self) {
        (self.cancel)();
        self.run.await.unwrap();
    }
}

/// Three servers authenticated as `key → password → key`.
struct ThreeHops {
    nodes: [Node; 3],
    hops: Vec<HopSpec>,
}

async fn three_hops() -> ThreeHops {
    let first_key: PrivateKey = new_user_key();
    let last_key: PrivateKey = new_user_key();
    let a = spawn_node(Some(first_key.public_key().clone())).await;
    let b = spawn_node(None).await;
    let c = spawn_node(Some(last_key.public_key().clone())).await;
    let hops = vec![
        spec(0, &a, vec![key_auth(&first_key)]),
        spec(1, &b, vec![password_auth(PASSWORD)]),
        spec(2, &c, vec![key_auth(&last_key)]),
    ];
    ThreeHops {
        nodes: [a, b, c],
        hops,
    }
}

impl ThreeHops {
    fn refs(&self) -> [&Node; 3] {
        [&self.nodes[0], &self.nodes[1], &self.nodes[2]]
    }

    async fn connect(&self) -> SshChain {
        connect_chain(&self.hops, &pin_all(&self.refs()), &options(), None)
            .await
            .unwrap()
    }
}

/// Drives HTTP and SOCKS5h through `dialer` and checks every payload byte.
async fn assert_proxies_carry_payload(dialer: Arc<dyn UpstreamDialer>) {
    let data = payload(PAYLOAD_LEN);
    let origin = spawn_origin(data.clone()).await;
    let echo = spawn_echo().await;
    let engines = Engines::start(dialer).await;

    let (status, body) = http_get(engines.http, REMOTE_ONLY_HOST, origin).await;
    assert!(status.contains("200"), "{status}");
    assert!(body == data, "HTTP payload was corrupted");

    let (reply, stream) = socks5h_connect(engines.socks, REMOTE_ONLY_HOST, echo).await;
    assert_eq!(reply, 0);
    assert!(
        echo_roundtrip(stream, &data).await == data,
        "SOCKS5h payload was corrupted"
    );

    engines.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_hop_drives_http_and_socks5h_engines() {
    let key = new_user_key();
    let node = spawn_node(Some(key.public_key().clone())).await;
    let hops = vec![spec(0, &node, vec![key_auth(&key)])];
    let chain = connect_chain(&hops, &pin_all(&[&node]), &options(), None)
        .await
        .unwrap();
    assert_proxies_carry_payload(Arc::new(RusshDialer::with_chain(chain))).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_hop_chain_drives_http_and_socks5h_with_stats() {
    let setup = three_hops().await;
    let chain = setup.connect().await;
    let stats = Arc::new(AtomicStats::default());
    let dialer = StatsDialer::new(
        Arc::new(RusshDialer::with_chain(chain)),
        Arc::clone(&stats),
    );
    assert_proxies_carry_payload(Arc::new(dialer)).await;

    let snapshot = stats.snapshot();
    assert_eq!(snapshot.total_connections, 2);
    assert!(snapshot.bytes_received >= PAYLOAD_LEN as u64 * 2);
    assert!(snapshot.bytes_sent >= PAYLOAD_LEN as u64);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hostnames_reach_only_the_final_hop_unresolved() {
    let setup = three_hops().await;
    let chain = setup.connect().await;
    let echo = spawn_echo().await;
    let engines = Engines::start(Arc::new(RusshDialer::with_chain(chain))).await;

    let (reply, stream) = socks5h_connect(engines.socks, REMOTE_ONLY_HOST, echo).await;
    assert_eq!(reply, 0);
    assert_eq!(echo_roundtrip(stream, b"dns").await, b"dns");

    assert!(setup.nodes[2].hosts().iter().any(|h| h == REMOTE_ONLY_HOST));
    for node in &setup.nodes[..2] {
        assert!(!node.hosts().iter().any(|h| h == REMOTE_ONLY_HOST));
    }
    engines.stop().await;
}

async fn assert_reverse_roundtrip(hops: &mut [HopSpec], verifier: &conduit_ssh::HostKeyVerifier, node: &Node) {
    let data = payload(PAYLOAD_LEN);
    let origin = spawn_origin(data.clone()).await;
    let echo = spawn_echo().await;
    let remote_port = free_port().await;

    let logger = quiet_logger();
    let access = quiet_access(&logger).await;
    let config = Config {
        reverse_bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        reverse_http_port: remote_port,
        reverse_socks_port: remote_port,
        ..Config::default()
    };
    let proxy = ReverseProxy::start(&config, &access, &logger)
        .await
        .unwrap()
        .expect("reverse proxy is enabled");

    let (policy, inbound) = reverse_policy(16);
    hops.last_mut().unwrap().policy = policy;
    let chain = connect_chain(hops, verifier, &options(), None).await.unwrap();
    let remote: Vec<RemoteForward> = proxy.forwards().iter().map(RemoteForward::from).collect();
    let relay = ReverseRelay::start(&chain, &remote, inbound)
        .await
        .unwrap();
    assert_eq!(relay.bound(), [("127.0.0.1".to_string(), u32::from(remote_port))]);

    // Clients connect on the SSH target and egress through this machine.
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), remote_port);
    let (status, body) = http_get(remote, "127.0.0.1", origin).await;
    assert!(status.contains("200"), "{status}");
    assert!(body == data, "reverse HTTP payload was corrupted");

    let (reply, stream) = socks5h_connect(remote, "localhost", echo).await;
    assert_eq!(reply, 0);
    assert!(echo_roundtrip(stream, &data).await == data);

    assert!(node.state.requested_hosts.lock().unwrap().is_empty());
    relay.stop(&chain).await;
    chain.disconnect().await;
    proxy.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_proxy_roundtrip_over_one_hop() {
    let node = spawn_node(None).await;
    let mut hops = vec![spec(0, &node, vec![password_auth(PASSWORD)])];
    let verifier = pin_all(&[&node]);
    assert_reverse_roundtrip(&mut hops, &verifier, &node).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_proxy_roundtrip_over_three_hops() {
    let mut setup = three_hops().await;
    let verifier = pin_all(&setup.refs());
    let ThreeHops { nodes, hops } = &mut setup;
    assert_reverse_roundtrip(hops, &verifier, &nodes[2]).await;
}

#[tokio::test]
async fn keyboard_interactive_hop_carries_traffic() {
    let node = spawn_node(None).await;
    let auth = HopAuth::KeyboardInteractive(vec![KeyboardAnswer {
        prompt: PROMPT.into(),
        answer: Zeroizing::new(CODE.to_string()),
    }]);
    let hops = vec![spec(0, &node, vec![auth])];
    let chain = connect_chain(&hops, &pin_all(&[&node]), &options(), None)
        .await
        .unwrap();
    assert_eq!(node.state.keyboard_answers.load(Ordering::SeqCst), 1);

    let echo = spawn_echo().await;
    let dialer = RusshDialer::with_chain(chain);
    let stream = dialer.connect("127.0.0.1", echo, DIAL_TIMEOUT).await.unwrap();
    assert_eq!(echo_roundtrip(stream, b"kbd").await, b"kbd");
}

#[tokio::test]
async fn unknown_host_key_is_rejected_before_credentials() {
    let a = spawn_node(None).await;
    let b = spawn_node(None).await;
    let hops = vec![
        spec(0, &a, vec![password_auth(PASSWORD)]),
        spec(1, &b, vec![password_auth(PASSWORD)]),
    ];
    // Only hop 0 is pinned.
    let error = connect_chain(&hops, &pin_all(&[&a]), &options(), None)
        .await
        .unwrap_err();
    assert!(
        matches!(error, SshError::HostKeyUnknown { hop_index: 1, .. }),
        "{error:?}"
    );
    assert!(error.is_lockout_sensitive());
    assert_eq!(b.state.password_attempts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn changed_host_key_is_rejected_before_credentials() {
    let a = spawn_node(None).await;
    let b = spawn_node(None).await;
    let impostor = new_user_key().public_key().clone();
    let hops = vec![
        spec(0, &a, vec![password_auth(PASSWORD)]),
        spec(1, &b, vec![password_auth(PASSWORD)]),
    ];
    let verifier = verifier_with(&[&a, &b], &[&a.host_key, &impostor]);
    let error = connect_chain(&hops, &verifier, &options(), None)
        .await
        .unwrap_err();
    assert!(
        matches!(error, SshError::HostKeyChanged { hop_index: 1, .. }),
        "{error:?}"
    );
    assert!(error.is_lockout_sensitive());
    assert_eq!(b.state.password_attempts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn bad_password_is_auth_failed_after_one_attempt() {
    let node = spawn_node(None).await;
    let hops = vec![spec(0, &node, vec![password_auth("wrong")])];
    let error = connect_chain(&hops, &pin_all(&[&node]), &options(), None)
        .await
        .unwrap_err();
    assert!(
        matches!(error, SshError::AuthFailed { hop_index: 0, .. }),
        "{error:?}"
    );
    assert!(error.is_lockout_sensitive());
    assert_eq!(node.state.password_attempts.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropping_hop_one_is_detected() {
    let setup = three_hops().await;
    let (events, mut receiver) = mpsc::unbounded_channel();
    let chain = connect_chain(
        &setup.hops,
        &pin_all(&setup.refs()),
        &options(),
        Some(events),
    )
    .await
    .unwrap();
    let dialer = RusshDialer::with_chain(chain);
    assert!(dialer.is_connected());

    setup.nodes[1].drop_session().await;

    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let event = receiver.recv().await.expect("disconnect event");
            if event.hop_index == 1 {
                break;
            }
        }
        while dialer.is_connected() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("hop 1 drop was not detected");

    let error = dialer
        .connect("127.0.0.1", 80, DIAL_TIMEOUT)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotConnected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn listeners_survive_a_chain_swap() {
    let setup = three_hops().await;
    let dialer = Arc::new(RusshDialer::with_chain(setup.connect().await));
    let echo = spawn_echo().await;
    let engines = Engines::start(Arc::clone(&dialer) as Arc<dyn UpstreamDialer>).await;

    let (reply, stream) = socks5h_connect(engines.socks, REMOTE_ONLY_HOST, echo).await;
    assert_eq!(reply, 0);
    assert_eq!(echo_roundtrip(stream, b"before").await, b"before");

    dialer.shutdown().await;
    assert!(!dialer.is_connected());
    let (reply, _stream) = socks5h_connect(engines.socks, REMOTE_ONLY_HOST, echo).await;
    assert_ne!(reply, 0, "a detached dialer must not connect");

    assert!(dialer.swap(setup.connect().await).is_none());
    let (reply, stream) = socks5h_connect(engines.socks, REMOTE_ONLY_HOST, echo).await;
    assert_eq!(reply, 0);
    assert_eq!(echo_roundtrip(stream, b"after").await, b"after");

    engines.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn channel_failures_keep_their_error_kind_through_the_engine() {
    let node = spawn_node(None).await;
    let hops = vec![spec(0, &node, vec![password_auth(PASSWORD)])];
    let chain = connect_chain(&hops, &pin_all(&[&node]), &options(), None)
        .await
        .unwrap();
    let dialer = Arc::new(RusshDialer::with_chain(chain));
    let closed = free_port().await;

    let refused = dialer
        .connect("127.0.0.1", closed, DIAL_TIMEOUT)
        .await
        .unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::ConnectionRefused);
    let denied = dialer
        .connect(FORBIDDEN_HOST, 443, DIAL_TIMEOUT)
        .await
        .unwrap_err();
    assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);

    let engines = Engines::start(Arc::clone(&dialer) as Arc<dyn UpstreamDialer>).await;
    let (reply, _stream) = socks5h_connect(engines.socks, "127.0.0.1", closed).await;
    assert_eq!(reply, SOCKS_CONNECTION_REFUSED);
    engines.stop().await;
}
