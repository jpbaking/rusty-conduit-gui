//! Headless U2 integration tests: `TunnelManager` and `ProxyManager` driving real `russh`
//! Tunnels and the embedded proxy engine against in-process SSH servers, echo origins, and a
//! minimal upstream HTTP `CONNECT` proxy, all on loopback (`docs/MASTER-PLAN.md` §10 U2).
//!
//! The process runs with `HOME` set to an empty temp directory, so nothing touches `~/.ssh`.

#[allow(dead_code)]
#[path = "../../conduit-ssh/tests/common/mod.rs"]
mod common;

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use common::{
    http_get, payload, socks5h_connect, spawn_echo, spawn_node, spawn_origin, Node, PASSWORD,
    REMOTE_ONLY_HOST,
};
use conduit_core::{
    load_or_migrate_app_config, AppConfig, AuthMethod, ForwardConfig, HopEntry, HostKeyLookup,
    HostKeyRecord, HostProfile, KnownHostsStore, ListenerConfig, Proxy, ProxyId, ReverseConfig,
    RouteInbound, RouteOneOrMany, RoutePortSpec, RoutingRule, SecretRef, SessionProfile,
    Timestamp, Tunnel, TunnelConfig, TunnelId, TunnelStartMode, UpstreamKind, UpstreamProfile,
    CURRENT_SCHEMA_VERSION, V1_BACKUP_FILE_NAME,
};
use conduit_runtime::{
    ManagerConfig, ProxyError, ProxyEvent, ProxyManager, ProxyState, ProxyTrafficSnapshot,
    SessionState, TunnelManager,
};
use conduit_vault::{Argon2Params, Vault};
use russh::keys::HashAlg;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

const TEST_TIMEOUT: Duration = Duration::from_secs(90);
const STATE_TIMEOUT: Duration = Duration::from_secs(20);
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
const VAULT_PASSWORD: &[u8] = b"u2-vault-password";
const HOP_ID: &str = "hop-0";
const DIRECT: &str = "direct";
const UPSTREAM: &str = "upstream";
const BASTION: &str = "bastion";

// ---------------------------------------------------------------------- environment

static HOME: OnceLock<PathBuf> = OnceLock::new();

/// Points `HOME` at an empty directory once, before any test starts a runtime.
fn hermetic_home() -> &'static PathBuf {
    HOME.get_or_init(|| {
        let home = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("conduit-u2-{}", std::process::id()))
            .join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::env::set_var("HOME", &home);
        std::env::remove_var("SSH_AUTH_SOCK");
        home
    })
}

/// Runs one test on its own runtime, with the hermetic environment and a hard timeout.
fn run(test: impl Future<Output = ()>) {
    hermetic_home();
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::timeout(TEST_TIMEOUT, test)
                .await
                .expect("test timed out");
        });
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

/// Below the OS ephemeral ranges, so a `:0` bind by a parallel test never takes a port
/// reserved here (same scheme as `e2e_runtime.rs`).
const TEST_PORT_BASE: u32 = 30_000;
const TEST_PORT_SPAN: u32 = 2_700;

async fn free_port() -> u16 {
    static NEXT: OnceLock<AtomicU32> = OnceLock::new();
    let next = NEXT.get_or_init(|| AtomicU32::new(std::process::id() % TEST_PORT_SPAN));
    for _ in 0..TEST_PORT_SPAN {
        let offset = next.fetch_add(1, Ordering::Relaxed) % TEST_PORT_SPAN;
        let port = (TEST_PORT_BASE + offset) as u16;
        if TcpListener::bind(loopback(port)).await.is_ok() {
            return port;
        }
    }
    panic!("no free loopback port in the test range");
}

/// Polls `check` until it returns `Ok`, failing with its last message.
async fn eventually(what: &str, check: impl Fn() -> Result<(), String>) {
    let deadline = tokio::time::Instant::now() + STATE_TIMEOUT;
    loop {
        match check() {
            Ok(()) => return,
            Err(why) => assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for {what}: {why}"
            ),
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ---------------------------------------------------------------------- traffic helpers

/// A minimal upstream HTTP proxy that serves only `CONNECT`, counting tunnels it opened.
async fn spawn_upstream_http() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind(loopback(0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let served = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&served);
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let Some(head) = read_head(&mut client).await else { return };
                let line = head.lines().next().unwrap_or_default().to_string();
                let mut parts = line.split_whitespace();
                let (Some("CONNECT"), Some(authority)) = (parts.next(), parts.next()) else {
                    let _ = client
                        .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    return;
                };
                let Ok(mut target) = TcpStream::connect(authority).await else {
                    let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                    return;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                if client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                let _ = copy_bidirectional(&mut client, &mut target).await;
            });
        }
    });
    (port, served)
}

/// Reads an HTTP header block byte by byte, so no tunneled bytes are consumed.
async fn read_head(stream: &mut TcpStream) -> Option<String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read_exact(&mut byte).await.is_err() || head.len() > 16 * 1024 {
            return None;
        }
        head.push(byte[0]);
    }
    Some(String::from_utf8_lossy(&head).into_owned())
}

/// Opens an HTTP `CONNECT` tunnel through `proxy` and checks for `200`.
async fn http_connect(proxy: SocketAddr, host: &str, port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let request = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let head = read_head(&mut stream).await.expect("CONNECT response head");
    assert!(head.starts_with("HTTP/1.1 200"), "CONNECT via {proxy} refused: {head}");
    stream
}

/// Opens a SOCKS5 tunnel through `proxy` and checks for success.
async fn socks_connect(proxy: SocketAddr, host: &str, port: u16) -> TcpStream {
    let (reply, stream) = socks5h_connect(proxy, host, port).await;
    assert_eq!(reply, 0, "SOCKS5 CONNECT via {proxy} refused");
    stream
}

/// Writes `data` and reads the echo back.
async fn roundtrip(stream: &mut TcpStream, data: &[u8]) {
    stream.write_all(data).await.unwrap();
    let mut back = vec![0u8; data.len()];
    tokio::time::timeout(DIAL_TIMEOUT, stream.read_exact(&mut back))
        .await
        .expect("echo timed out")
        .unwrap();
    assert!(back == data, "echo corrupted");
}

/// One CONNECT round trip on a fresh connection.
async fn connect_once(proxy: SocketAddr, port: u16, data: &[u8]) {
    let mut stream = http_connect(proxy, "127.0.0.1", port).await;
    roundtrip(&mut stream, data).await;
}

// ---------------------------------------------------------------------- model builders

fn port_rule(name: &str, port: u16, target: &str) -> RoutingRule {
    let mut rule = RoutingRule::to_target(RouteOneOrMany::One(target.into()));
    rule.name = Some(name.into());
    rule.port = Some(RouteOneOrMany::One(RoutePortSpec::Port(port)));
    rule
}

fn http_upstream(name: &str, host: &str, port: u16) -> UpstreamProfile {
    UpstreamProfile {
        name: name.into(),
        kind: UpstreamKind::Http,
        host: Some(host.into()),
        port: Some(port),
        username: None,
        password: None,
        bypass: Vec::new(),
        color: None,
    }
}

fn tunnel_upstream(name: &str, tunnel_id: TunnelId) -> UpstreamProfile {
    UpstreamProfile {
        name: name.into(),
        kind: UpstreamKind::Tunnel { tunnel_id },
        host: None,
        port: None,
        username: None,
        password: None,
        bypass: Vec::new(),
        color: None,
    }
}

/// A loopback Proxy routing everything `direct`. `0` turns a listener off.
fn proxy(name: &str, http_port: u16, socks_port: u16) -> Proxy {
    Proxy {
        id: ProxyId::new(),
        name: name.into(),
        listeners: ListenerConfig {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            http_port,
            socks_port,
            ..ListenerConfig::default()
        },
        ..Proxy::default()
    }
}

fn counter(map: &std::collections::BTreeMap<String, ProxyTrafficSnapshot>, key: &str) -> ProxyTrafficSnapshot {
    map.get(key).copied().unwrap_or_default()
}

fn fast_keepalive() -> TunnelConfig {
    TunnelConfig {
        reconnect_initial_delay: Duration::from_secs(1),
        reconnect_max_delay: Duration::from_secs(2),
        ..TunnelConfig::default()
    }
}

// ---------------------------------------------------------------------- fixture

/// One isolated app data directory with its vault, pins, and both managers.
struct Fixture {
    app_data: PathBuf,
    vault: Arc<RwLock<Vault>>,
    known_hosts: Arc<RwLock<KnownHostsStore>>,
    tunnels: Arc<TunnelManager>,
    proxies: ProxyManager,
}

impl Fixture {
    fn new() -> Self {
        let app_data = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("conduit-u2-app-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&app_data).unwrap();
        let params = Argon2Params {
            memory_kib: 8 * 1024,
            time_cost: 1,
            parallelism: 1,
            derived_key_len: 32,
        };
        let vault = Vault::create_with_password(app_data.join("vault.bin"), VAULT_PASSWORD, params)
            .unwrap();
        let vault = Arc::new(RwLock::new(vault));
        let known_hosts = Arc::new(RwLock::new(KnownHostsStore::default()));
        let config = ManagerConfig {
            autostart_stagger: Duration::from_millis(1),
            ..ManagerConfig::default()
        };
        let tunnels = Arc::new(TunnelManager::new(
            Arc::clone(&vault),
            Arc::clone(&known_hosts),
            config.clone(),
        ));
        let proxies = ProxyManager::new(Arc::clone(&tunnels), Arc::clone(&vault), config);
        Self {
            app_data,
            vault,
            known_hosts,
            tunnels,
            proxies,
        }
    }

    fn password(&self) -> AuthMethod {
        let id = self
            .vault
            .write()
            .unwrap()
            .put_secret("password", PASSWORD.as_bytes())
            .unwrap();
        let secret: SecretRef = serde_json::from_value(serde_json::Value::String(id)).unwrap();
        AuthMethod::Password { secret }
    }

    fn pin(&self, node: &Node) {
        self.known_hosts.write().unwrap().insert(
            HostKeyLookup {
                hop_id: HOP_ID.into(),
                host: "127.0.0.1".into(),
                port: node.port,
            },
            HostKeyRecord {
                algorithm: node.host_key.algorithm().as_str().to_string(),
                fingerprint_sha256: node.host_key.fingerprint(HashAlg::Sha256).to_string(),
                public_key_openssh: None,
                first_seen: Timestamp(1),
                approved: true,
            },
        );
    }

    fn hop(&self, node: &Node) -> HopEntry {
        HopEntry {
            hop_id: HOP_ID.into(),
            name: HOP_ID.into(),
            host: HostProfile {
                host: "127.0.0.1".into(),
                port: node.port,
                user: "tester".into(),
                auth: vec![self.password()],
                ..Default::default()
            },
        }
    }

    /// A single-hop Tunnel to a pinned `node`, registered with the Tunnel manager.
    fn add_tunnel(&self, name: &str, node: &Node, start_mode: TunnelStartMode) -> TunnelId {
        self.pin(node);
        let tunnel = Tunnel {
            id: TunnelId::new(),
            name: name.into(),
            start_mode,
            hops: vec![self.hop(node)],
            keepalive: fast_keepalive(),
            ..Tunnel::default()
        };
        let id = tunnel.id;
        self.tunnels.upsert_tunnel(tunnel);
        id
    }

    async fn add_proxy(&self, proxy: &Proxy) -> ProxyId {
        self.proxies.upsert_proxy(proxy.clone()).await.unwrap();
        proxy.id
    }

    fn tunnel_state(&self, id: TunnelId) -> SessionState {
        self.tunnels.snapshot(id).unwrap().state
    }

    fn tunnel_log(&self, id: TunnelId) -> String {
        self.tunnels
            .logs(id)
            .unwrap()
            .query(None)
            .into_iter()
            .map(|line| line.text)
            .collect::<Vec<_>>()
            .join("\n")
    }

    async fn until_tunnel(&self, id: TunnelId, wanted: SessionState) {
        eventually(&format!("tunnel {wanted:?}"), || {
            let state = self.tunnel_state(id);
            if state == wanted {
                Ok(())
            } else {
                Err(format!("state {state:?}; logs:\n{}", self.tunnel_log(id)))
            }
        })
        .await;
    }

    /// The first bound listener of a running Proxy.
    fn listener(&self, id: ProxyId, role_contains: &str) -> SocketAddr {
        let snapshot = self.proxies.snapshot(id).unwrap();
        snapshot
            .listeners
            .iter()
            .find(|l| l.role.to_ascii_lowercase().contains(role_contains))
            .unwrap_or_else(|| panic!("no {role_contains} listener: {:?}", snapshot.listeners))
            .addr
    }

    /// Waits until a Proxy's counters satisfy `check` (connections are counted as they close).
    async fn until_counters(
        &self,
        id: ProxyId,
        what: &str,
        check: impl Fn(
            &std::collections::BTreeMap<String, ProxyTrafficSnapshot>,
            &std::collections::BTreeMap<String, ProxyTrafficSnapshot>,
        ) -> bool,
    ) {
        eventually(what, || {
            let snapshot = self.proxies.snapshot(id).unwrap();
            if check(&snapshot.profile_counters, &snapshot.rule_counters) {
                Ok(())
            } else {
                Err(format!(
                    "profiles {:?}; rules {:?}",
                    snapshot.profile_counters, snapshot.rule_counters
                ))
            }
        })
        .await;
    }

    /// Stops everything and checks that nothing created `~/.ssh`.
    async fn finish(self) {
        self.proxies.stop_all().await;
        self.tunnels.stop_all().await;
        assert!(
            !hermetic_home().join(".ssh").exists(),
            "the runtime must never create ~/.ssh"
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.app_data);
    }
}

fn requested(node: &Node) -> usize {
    node.hosts().len()
}

// ---------------------------------------------------------------------- (1) multi-Proxy

#[test]
fn two_proxies_route_concurrently_and_count_per_profile_and_rule() {
    run(async {
        let f = Fixture::new();
        let node = spawn_node(None).await;
        let bastion = f.add_tunnel(BASTION, &node, TunnelStartMode::Linked);
        let (upstream_port, upstream_served) = spawn_upstream_http().await;
        let (via_upstream, via_tunnel, via_direct) =
            (spawn_echo().await, spawn_echo().await, spawn_echo().await);

        // A plain Proxy: everything direct.
        let plain = proxy("plain", free_port().await, free_port().await);
        // An Auto Switch Proxy: one port to the upstream proxy, one to the Tunnel, rest direct.
        let mut auto = proxy("auto", free_port().await, free_port().await);
        auto.profiles = vec![
            http_upstream(UPSTREAM, "127.0.0.1", upstream_port),
            tunnel_upstream(BASTION, bastion),
        ];
        auto.routing.rules = vec![
            port_rule("to-upstream", via_upstream, UPSTREAM),
            port_rule("to-bastion", via_tunnel, BASTION),
        ];
        let plain_id = f.add_proxy(&plain).await;
        let auto_id = f.add_proxy(&auto).await;
        assert_eq!(f.tunnel_state(bastion), SessionState::Stopped);

        f.proxies.start(plain_id).await.unwrap();
        f.proxies.start(auto_id).await.unwrap();
        // The Linked Tunnel started with the Proxy that routes through it.
        assert_eq!(f.tunnels.snapshot(bastion).unwrap().linked_holders, 1);
        f.until_tunnel(bastion, SessionState::Connected).await;

        let data = payload(32 * 1024);
        let auto_http = f.listener(auto_id, "http");
        let auto_socks = f.listener(auto_id, "socks");
        let plain_http = f.listener(plain_id, "http");
        let plain_socks = f.listener(plain_id, "socks");

        // Both Proxies carry traffic at the same time.
        let a = async {
            let mut s = http_connect(auto_http, "127.0.0.1", via_upstream).await;
            roundtrip(&mut s, &data).await;
        };
        let b = async {
            let mut s = socks_connect(auto_socks, "127.0.0.1", via_tunnel).await;
            roundtrip(&mut s, &data).await;
        };
        let c = async {
            let mut s = http_connect(auto_http, "127.0.0.1", via_direct).await;
            roundtrip(&mut s, &data).await;
        };
        let d = async {
            let mut s = socks_connect(plain_socks, "127.0.0.1", via_direct).await;
            roundtrip(&mut s, &data).await;
        };
        // The plain Proxy sends the upstream-ruled port direct.
        let e = async {
            let mut s = http_connect(plain_http, "127.0.0.1", via_upstream).await;
            roundtrip(&mut s, &data).await;
        };
        tokio::join!(a, b, c, d, e);

        assert_eq!(upstream_served.load(Ordering::SeqCst), 1, "only auto's rule uses upstream");
        assert_eq!(node.hosts(), vec!["127.0.0.1".to_string()], "only auto's rule uses the Tunnel");

        let len = data.len() as u64;
        let carried = move |c: ProxyTrafficSnapshot, hits: u64| {
            c.hits == hits && c.active == 0 && c.bytes_in >= len * hits && c.bytes_out >= len * hits
        };
        f.until_counters(auto_id, "auto counters", |profiles, rules| {
            carried(counter(profiles, UPSTREAM), 1)
                && carried(counter(profiles, BASTION), 1)
                && carried(counter(profiles, DIRECT), 1)
                && carried(counter(rules, "to-upstream"), 1)
                && carried(counter(rules, "to-bastion"), 1)
        })
        .await;
        f.until_counters(plain_id, "plain counters", |profiles, _| {
            carried(counter(profiles, DIRECT), 2)
                && !profiles.contains_key(UPSTREAM)
                && !profiles.contains_key(BASTION)
        })
        .await;
        assert!(f.tunnels.snapshot(bastion).unwrap().stats.total_connections >= 1);

        // Stopping the only holder stops the Linked Tunnel.
        f.proxies.stop(auto_id).await.unwrap();
        assert_eq!(f.tunnels.snapshot(bastion).unwrap().linked_holders, 0);
        assert_eq!(f.tunnel_state(bastion), SessionState::Stopped);
        // The other Proxy is unaffected.
        connect_once(plain_http, via_direct, b"still up").await;
        f.finish().await;
    });
}

// ---------------------------------------------------------------------- (2) failover

#[test]
fn failover_chain_falls_through_to_direct_while_the_tunnel_is_down() {
    run(async {
        let f = Fixture::new();
        let node = spawn_node(None).await;
        let bastion = f.add_tunnel(BASTION, &node, TunnelStartMode::Linked);
        let echo = spawn_echo().await;

        let mut p = proxy("failover", free_port().await, 0);
        p.profiles = vec![tunnel_upstream(BASTION, bastion)];
        p.routing.default = RouteOneOrMany::Many(vec![BASTION.into(), DIRECT.into()]);
        let id = f.add_proxy(&p).await;
        assert_eq!(f.tunnels.snapshot(bastion).unwrap().linked_holders, 0);

        // Linked start: the Proxy brings the Tunnel up.
        f.proxies.start(id).await.unwrap();
        assert_eq!(f.tunnels.snapshot(bastion).unwrap().linked_holders, 1);
        assert_eq!(f.proxies.snapshot(id).unwrap().referenced_tunnels, vec![bastion]);
        f.until_tunnel(bastion, SessionState::Connected).await;
        let listen = f.listener(id, "http");

        connect_once(listen, echo, b"through bastion").await;
        assert_eq!(requested(&node), 1, "first choice is the Tunnel");
        f.until_counters(id, "bastion hit", |profiles, _| {
            counter(profiles, BASTION).hits == 1 && counter(profiles, DIRECT).hits == 0
        })
        .await;

        // Tunnel down: the chain falls through to direct.
        f.tunnels.stop(bastion).await.unwrap();
        assert_eq!(f.tunnel_state(bastion), SessionState::Stopped);
        connect_once(listen, echo, b"fell through to direct").await;
        assert_eq!(requested(&node), 1, "a down Tunnel is never dialed");
        f.until_counters(id, "direct fallback", |profiles, _| {
            counter(profiles, BASTION).hits == 1 && counter(profiles, DIRECT).hits == 1
        })
        .await;

        // Tunnel back: routes through it again.
        f.tunnels.start(bastion).await.unwrap();
        f.until_tunnel(bastion, SessionState::Connected).await;
        connect_once(listen, echo, b"bastion again").await;
        assert_eq!(requested(&node), 2);
        f.until_counters(id, "bastion again", |profiles, _| {
            counter(profiles, BASTION).hits == 2 && counter(profiles, DIRECT).hits == 1
        })
        .await;

        // Linked stop: the last holder going away stops the Tunnel.
        f.proxies.stop(id).await.unwrap();
        assert_eq!(f.tunnels.snapshot(bastion).unwrap().linked_holders, 0);
        assert_eq!(f.tunnel_state(bastion), SessionState::Stopped);
        f.finish().await;
    });
}

// ---------------------------------------------------------------------- (3) hot reload

#[test]
fn hot_reload_keeps_live_connect_and_socks_tunnels_and_counters() {
    run(async {
        let f = Fixture::new();
        let (upstream_port, upstream_served) = spawn_upstream_http().await;
        let echo = spawn_echo().await;

        let mut p = proxy("reload", free_port().await, free_port().await);
        p.profiles = vec![http_upstream(UPSTREAM, "127.0.0.1", upstream_port)];
        let id = f.add_proxy(&p).await;
        f.proxies.start(id).await.unwrap();
        let http = f.listener(id, "http");
        let socks = f.listener(id, "socks");

        // Two live tunnels, both direct under generation 0.
        let mut live_http = http_connect(http, "127.0.0.1", echo).await;
        let mut live_socks = socks_connect(socks, "127.0.0.1", echo).await;
        roundtrip(&mut live_http, b"http before").await;
        roundtrip(&mut live_socks, b"socks before").await;
        assert_eq!(f.proxies.snapshot(id).unwrap().config_generation, 0);

        // Hot reload: the echo port now goes to the upstream proxy.
        let mut next = p.clone();
        next.routing.rules = vec![port_rule("to-upstream", echo, UPSTREAM)];
        let mut events = f.proxies.subscribe_events();
        f.proxies.upsert_proxy(next).await.unwrap();
        let snapshot = f.proxies.snapshot(id).unwrap();
        assert_eq!(snapshot.config_generation, 1);
        assert!(!snapshot.restart_required);
        assert_eq!(
            snapshot.state,
            ProxyState::Running {
                override_profile: None,
                config_generation: 1,
                restart_required: false,
            }
        );
        let mut saw_reload = false;
        while let Ok(event) = events.try_recv() {
            if matches!(event, ProxyEvent::Reloaded { config_generation: 1, .. }) {
                saw_reload = true;
            }
        }
        assert!(saw_reload, "reload is announced");
        assert_eq!(f.listener(id, "http"), http, "listeners are untouched");

        // In-flight tunnels keep exchanging data on their old route.
        let big = payload(64 * 1024);
        roundtrip(&mut live_http, &big).await;
        roundtrip(&mut live_socks, &big).await;
        assert_eq!(upstream_served.load(Ordering::SeqCst), 0);

        // New connections follow the new rule.
        connect_once(http, echo, b"new http").await;
        let mut new_socks = socks_connect(socks, "127.0.0.1", echo).await;
        roundtrip(&mut new_socks, b"new socks").await;
        drop(new_socks);
        assert_eq!(upstream_served.load(Ordering::SeqCst), 2);

        // The old tunnels still work after new traffic, then close.
        roundtrip(&mut live_http, b"http after").await;
        roundtrip(&mut live_socks, b"socks after").await;
        drop(live_http);
        drop(live_socks);

        // Counters kept across the swap and kept accumulating.
        let big_len = big.len() as u64;
        f.until_counters(id, "counters across reload", |profiles, rules| {
            let direct = counter(profiles, DIRECT);
            let upstream = counter(profiles, UPSTREAM);
            direct.hits == 2
                && direct.active == 0
                && direct.bytes_in >= big_len * 2
                && direct.bytes_out >= big_len * 2
                && upstream.hits == 2
                && upstream.active == 0
                && counter(rules, "to-upstream").hits == 2
        })
        .await;
        f.finish().await;
    });
}

// ---------------------------------------------------------------------- (4) overrides

#[test]
fn tray_override_swaps_and_auto_switch_restores_rules() {
    run(async {
        let f = Fixture::new();
        let (upstream_port, served) = spawn_upstream_http().await;
        let (ruled, other) = (spawn_echo().await, spawn_echo().await);

        let mut p = proxy("override", free_port().await, 0);
        p.profiles = vec![http_upstream(UPSTREAM, "127.0.0.1", upstream_port)];
        p.routing.rules = vec![port_rule("to-upstream", ruled, UPSTREAM)];
        let id = f.add_proxy(&p).await;
        f.proxies.start(id).await.unwrap();
        let listen = f.listener(id, "http");
        let mut events = f.proxies.subscribe_events();
        let served_now = || served.load(Ordering::SeqCst);

        // Auto Switch: the rule applies.
        connect_once(listen, ruled, b"auto ruled").await;
        connect_once(listen, other, b"auto other").await;
        assert_eq!(served_now(), 1);

        // Force Direct: the rule is bypassed.
        f.proxies.set_override(id, Some(DIRECT.into())).await.unwrap();
        let snapshot = f.proxies.snapshot(id).unwrap();
        assert_eq!(snapshot.override_profile.as_deref(), Some(DIRECT));
        assert!(matches!(
            snapshot.state,
            ProxyState::Running { override_profile: Some(ref o), .. } if o == DIRECT
        ));
        connect_once(listen, ruled, b"forced direct").await;
        assert_eq!(served_now(), 1, "Force Direct must not use the upstream");

        // Force <profile>: everything goes to the upstream.
        f.proxies.set_override(id, Some(UPSTREAM.into())).await.unwrap();
        connect_once(listen, other, b"forced upstream").await;
        assert_eq!(served_now(), 2, "Force upstream sends unruled traffic upstream");

        // Unknown profiles are refused and the override stays.
        assert_eq!(
            f.proxies.set_override(id, Some("missing".into())).await,
            Err(ProxyError::UnknownProfile("missing".into()))
        );
        assert_eq!(
            f.proxies.snapshot(id).unwrap().override_profile.as_deref(),
            Some(UPSTREAM)
        );

        // Auto Switch restores the saved rules.
        f.proxies.set_override(id, None).await.unwrap();
        assert_eq!(f.proxies.snapshot(id).unwrap().override_profile, None);
        connect_once(listen, other, b"auto other again").await;
        assert_eq!(served_now(), 2);
        connect_once(listen, ruled, b"auto ruled again").await;
        assert_eq!(served_now(), 3);

        let mut overrides = Vec::new();
        while let Ok(event) = events.try_recv() {
            if let ProxyEvent::OverrideChanged { override_profile, .. } = event {
                overrides.push(override_profile);
            }
        }
        assert_eq!(
            overrides,
            vec![Some(DIRECT.to_string()), Some(UPSTREAM.to_string()), None]
        );
        f.until_counters(id, "override counters", |profiles, rules| {
            counter(profiles, UPSTREAM).hits == 3
                && counter(profiles, DIRECT).hits == 3
                && counter(rules, "to-upstream").hits == 2
        })
        .await;
        f.finish().await;
    });
}

// ---------------------------------------------------------------------- (5) self-loops

fn assert_self_loop(result: Result<impl std::fmt::Debug, ProxyError>, what: &str) {
    match result {
        Err(ProxyError::Invalid(message)) => {
            assert!(message.contains("self-loop"), "{what}: {message}")
        }
        other => panic!("{what}: expected a self-loop rejection, got {other:?}"),
    }
}

#[test]
fn self_loops_to_other_proxies_and_reverse_listeners_are_rejected() {
    run(async {
        let f = Fixture::new();
        let node = spawn_node(None).await;
        let echo = spawn_echo().await;

        // A running Proxy and a running Tunnel with a reverse proxy.
        let first = proxy("first", free_port().await, 0);
        let first_id = f.add_proxy(&first).await;
        f.proxies.start(first_id).await.unwrap();
        let first_listen = f.listener(first_id, "http");

        let reverse = f.add_tunnel("reverse", &node, TunnelStartMode::Manual { autostart: false });
        let reverse_port = free_port().await;
        {
            // Turn the reverse proxy on for this Tunnel.
            let mut tunnel = Tunnel {
                id: reverse,
                name: "reverse".into(),
                start_mode: TunnelStartMode::Manual { autostart: false },
                hops: vec![f.hop(&node)],
                keepalive: fast_keepalive(),
                ..Tunnel::default()
            };
            tunnel.reverse = ReverseConfig {
                enabled: true,
                reverse_bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
                reverse_http_port: reverse_port,
                reverse_socks_port: reverse_port,
                ..ReverseConfig::default()
            };
            f.tunnels.upsert_tunnel(tunnel);
        }
        f.tunnels.start(reverse).await.unwrap();
        f.until_tunnel(reverse, SessionState::Connected).await;
        let reverse_listen = f.tunnels.reverse_listeners();
        assert_eq!(reverse_listen.len(), 1, "{reverse_listen:?}");
        let reverse_listen = reverse_listen[0];

        // At start: an upstream pointing at another running Proxy's listener.
        let mut to_proxy = proxy("to-proxy", free_port().await, 0);
        to_proxy.profiles = vec![http_upstream("loop", "127.0.0.1", first_listen.port())];
        to_proxy.routing.rules = vec![port_rule("looping", echo, "loop")];
        let to_proxy_id = f.add_proxy(&to_proxy).await;
        assert_self_loop(f.proxies.start(to_proxy_id).await, "cross-Proxy at start");
        assert!(matches!(
            f.proxies.snapshot(to_proxy_id).unwrap().state,
            ProxyState::NeedsAttention { .. }
        ));
        // `localhost` counts as loopback too.
        to_proxy.profiles = vec![http_upstream("loop", "localhost", first_listen.port())];
        f.proxies.upsert_proxy(to_proxy.clone()).await.unwrap();
        assert_self_loop(f.proxies.start(to_proxy_id).await, "cross-Proxy via localhost");

        // At start: an upstream pointing at a Tunnel's local reverse-proxy listener.
        let mut to_reverse = proxy("to-reverse", free_port().await, 0);
        to_reverse.profiles = vec![http_upstream(
            "loop",
            &reverse_listen.ip().to_string(),
            reverse_listen.port(),
        )];
        to_reverse.routing.rules = vec![port_rule("looping", echo, "loop")];
        let to_reverse_id = f.add_proxy(&to_reverse).await;
        assert_self_loop(f.proxies.start(to_reverse_id).await, "reverse listener at start");

        // On hot reload: both loops are rejected and the running routing stays.
        let steady = proxy("steady", free_port().await, 0);
        let steady_id = f.add_proxy(&steady).await;
        f.proxies.start(steady_id).await.unwrap();
        let steady_listen = f.listener(steady_id, "http");
        connect_once(steady_listen, echo, b"before").await;

        for (what, bad) in [
            ("cross-Proxy on reload", to_proxy.profiles.clone()),
            ("reverse listener on reload", to_reverse.profiles.clone()),
        ] {
            let mut next = steady.clone();
            next.profiles = bad;
            next.routing.rules = vec![port_rule("looping", echo, "loop")];
            assert_self_loop(f.proxies.upsert_proxy(next).await, what);
            let snapshot = f.proxies.snapshot(steady_id).unwrap();
            assert_eq!(snapshot.config_generation, 0, "{what}");
            assert!(
                matches!(snapshot.state, ProxyState::Running { config_generation: 0, .. }),
                "{what}: {:?}",
                snapshot.state
            );
            let routing = f.proxies.current_routing(steady_id).unwrap().unwrap();
            assert_eq!(routing.router.rule_count(), 0, "{what}: previous routing kept");
            // Traffic still flows on the previous routing (direct).
            connect_once(steady_listen, echo, what.as_bytes()).await;
        }
        f.until_counters(steady_id, "steady direct", |profiles, _| {
            counter(profiles, DIRECT).hits == 3
        })
        .await;
        f.finish().await;
    });
}

// ---------------------------------------------------------------------- (6) migration

#[test]
fn v1_config_migrates_and_the_migrated_proxy_serves_traffic() {
    run(async {
        let f = Fixture::new();
        let node = spawn_node(None).await;
        f.pin(&node);
        let echo = spawn_echo().await;
        let body = payload(16 * 1024);
        let origin = spawn_origin(body.clone()).await;
        let http_port = free_port().await;

        // A v0.1.0 config.json with one session forwarding HTTP through one hop.
        let session = SessionProfile {
            id: Uuid::new_v4(),
            name: "legacy".into(),
            hops: vec![f.hop(&node)],
            forward: ForwardConfig {
                http_port,
                socks_port: 0,
                ..Default::default()
            },
            tunnel: fast_keepalive(),
            ..Default::default()
        };
        let v1 = AppConfig {
            schema_version: 1,
            sessions: vec![session.clone()],
            ..AppConfig::default()
        };
        let path = f.app_data.join("config.json");
        let original = serde_json::to_vec_pretty(&v1).unwrap();
        std::fs::write(&path, &original).unwrap();

        let (config, report) = load_or_migrate_app_config(&path).unwrap();
        let backup = f.app_data.join(V1_BACKUP_FILE_NAME);
        assert_eq!(report.migrated_sessions, 1);
        assert_eq!(report.backup_path.as_deref(), Some(backup.as_path()));
        assert_eq!(std::fs::read(&backup).unwrap(), original, "backup is the v1 file unchanged");
        assert_eq!(config.schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(config.schema_version, 2);
        assert!(config.sessions.is_empty());
        assert_eq!(config.tunnels.len(), 1);
        assert_eq!(config.proxies.len(), 1);
        let tunnel = config.tunnels[0].clone();
        let migrated = config.proxies[0].clone();
        assert_eq!(tunnel.name, "legacy");
        assert_eq!(tunnel.start_mode, TunnelStartMode::Linked);
        assert_eq!(tunnel.hops, session.hops);
        assert_eq!(migrated.name, "legacy");
        assert_eq!(migrated.listeners.http_port, http_port);
        assert_eq!(migrated.listeners.socks_port, 0);
        assert_eq!(
            migrated.profiles[0].kind,
            UpstreamKind::Tunnel { tunnel_id: tunnel.id }
        );
        assert_eq!(
            migrated.routing.default,
            RouteOneOrMany::One(migrated.profiles[0].name.clone())
        );

        // The rewritten file is v2 on disk and is not migrated twice.
        let (again, report) = load_or_migrate_app_config(&path).unwrap();
        assert_eq!(report.migrated_sessions, 0);
        assert_eq!(again, config);

        // Start the migrated Proxy: its Linked Tunnel comes up and carries real traffic.
        f.tunnels.upsert_tunnel(tunnel.clone());
        let id = f.add_proxy(&migrated).await;
        f.proxies.start(id).await.unwrap();
        assert_eq!(f.tunnels.snapshot(tunnel.id).unwrap().linked_holders, 1);
        f.until_tunnel(tunnel.id, SessionState::Connected).await;
        let listen = f.listener(id, "http");
        assert_eq!(listen, loopback(http_port));

        // Only the SSH target resolves this name, so traffic went through the Tunnel.
        let mut stream = http_connect(listen, REMOTE_ONLY_HOST, echo).await;
        roundtrip(&mut stream, b"migrated CONNECT").await;
        drop(stream);
        let (status, received) = http_get(listen, REMOTE_ONLY_HOST, origin).await;
        assert!(status.contains("200"), "{status}");
        assert!(received == body, "HTTP payload corrupted");
        assert!(node.hosts().iter().all(|h| h == REMOTE_ONLY_HOST), "{:?}", node.hosts());
        assert_eq!(node.hosts().len(), 2);

        f.proxies.stop(id).await.unwrap();
        assert_eq!(f.tunnel_state(tunnel.id), SessionState::Stopped);
        f.finish().await;
    });
}

// ---------------------------------------------------------------------- (7) testers

#[test]
fn route_tester_and_test_upstream_against_live_listeners() {
    run(async {
        let f = Fixture::new();
        let node = spawn_node(None).await;
        let bastion = f.add_tunnel(BASTION, &node, TunnelStartMode::Manual { autostart: false });
        let (upstream_port, served) = spawn_upstream_http().await;
        let (ruled, tunneled, other) = (spawn_echo().await, spawn_echo().await, spawn_echo().await);

        let mut p = proxy("testers", free_port().await, 0);
        p.profiles = vec![
            http_upstream(UPSTREAM, "127.0.0.1", upstream_port),
            tunnel_upstream(BASTION, bastion),
        ];
        p.routing.rules = vec![
            port_rule("to-upstream", ruled, UPSTREAM),
            port_rule("to-bastion", tunneled, BASTION),
        ];
        p.routing.default = RouteOneOrMany::Many(vec![BASTION.into(), DIRECT.into()]);

        // Route Tester: rule hits, the failover default, and the inbound table.
        let hit = ProxyManager::test_route(&p, &format!("127.0.0.1:{ruled}"), RouteInbound::Http)
            .unwrap();
        assert_eq!(hit.table.as_deref(), Some("[routing]"));
        assert_eq!(hit.matched_rule.as_deref(), Some("to-upstream"));
        assert!(!hit.blocked_by_filter);
        assert_eq!(hit.targets.len(), 1);
        assert_eq!(hit.targets[0].profile, UPSTREAM);
        assert_eq!(
            hit.targets[0].redacted_upstream,
            format!("http://127.0.0.1:{upstream_port}")
        );
        let via_tunnel =
            ProxyManager::test_route(&p, &format!("127.0.0.1:{tunneled}"), RouteInbound::Socks)
                .unwrap();
        assert_eq!(via_tunnel.matched_rule.as_deref(), Some("to-bastion"));
        assert_eq!(via_tunnel.targets[0].redacted_upstream, format!("tunnel {bastion}"));
        let fallback =
            ProxyManager::test_route(&p, &format!("http://127.0.0.1:{other}/x"), RouteInbound::Http)
                .unwrap();
        assert_eq!(fallback.matched_rule, None);
        let chain: Vec<&str> = fallback.targets.iter().map(|t| t.profile.as_str()).collect();
        assert_eq!(chain, vec![BASTION, DIRECT]);

        // Test Upstream through the live upstream proxy and direct.
        let up = f
            .proxies
            .test_upstream(&p, UPSTREAM, "127.0.0.1", ruled, DIAL_TIMEOUT)
            .await
            .unwrap();
        assert!(up.ok, "{up:?}");
        assert_eq!(up.redacted_upstream, format!("http://127.0.0.1:{upstream_port}"));
        eventually("upstream probe served", || {
            (served.load(Ordering::SeqCst) == 1)
                .then_some(())
                .ok_or_else(|| "not yet".to_string())
        })
        .await;
        let direct = f
            .proxies
            .test_upstream(&p, DIRECT, "127.0.0.1", other, DIAL_TIMEOUT)
            .await
            .unwrap();
        assert!(direct.ok, "{direct:?}");
        let closed = free_port().await;
        let refused = f
            .proxies
            .test_upstream(&p, DIRECT, "127.0.0.1", closed, DIAL_TIMEOUT)
            .await
            .unwrap();
        assert!(!refused.ok);
        assert!(refused.error.is_some());

        // Test Upstream through the Tunnel: refused while down, ok once connected.
        let down = f
            .proxies
            .test_upstream(&p, BASTION, "127.0.0.1", tunneled, DIAL_TIMEOUT)
            .await
            .unwrap();
        assert!(!down.ok, "{down:?}");
        assert_eq!(requested(&node), 0);
        f.tunnels.start(bastion).await.unwrap();
        f.until_tunnel(bastion, SessionState::Connected).await;
        let through = f
            .proxies
            .test_upstream(&p, BASTION, "127.0.0.1", tunneled, DIAL_TIMEOUT)
            .await
            .unwrap();
        assert!(through.ok, "{through:?}");
        assert_eq!(node.hosts(), vec!["127.0.0.1".to_string()]);
        assert_eq!(
            f.proxies
                .test_upstream(&p, "nope", "127.0.0.1", other, DIAL_TIMEOUT)
                .await,
            Err(ProxyError::UnknownProfile("nope".into()))
        );
        f.finish().await;
    });
}
