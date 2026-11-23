//! End-to-end tests of the headless stack: `SessionManager` driving real `russh` chains and the
//! embedded proxy engine against in-process SSH servers on loopback.
//!
//! The process runs with `HOME` set to an empty temp directory, and `SSL_CERT_FILE` set to a
//! throwaway origin CA so the MITM upstream check passes without touching OS trust.

#[allow(dead_code)]
#[path = "../../conduit-ssh/tests/common/mod.rs"]
mod common;

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use common::{
    echo_roundtrip, free_port, http_get, new_user_key, payload, socks5h_connect, spawn_echo,
    spawn_node, spawn_origin, Node, PASSWORD, REMOTE_ONLY_HOST,
};
use conduit_core::{
    AuthMethod, ForwardConfig, HopEntry, HostKeyLookup, HostKeyRecord, HostProfile, KeyId,
    KnownHostsStore, LoggingConfig, MitmCaMode, MitmConfig, SecretRef, SessionProfile, Timestamp, TunnelConfig,
};
use conduit_runtime::{ManagerConfig, RuntimeError, RuntimeEvent, SessionManager, SessionState};
use conduit_vault::{Argon2Params, Vault};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use russh::keys::ssh_key::LineEnding;
use russh::keys::{HashAlg, PrivateKey, PublicKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use uuid::Uuid;

const TEST_TIMEOUT: Duration = Duration::from_secs(90);
const STATE_TIMEOUT: Duration = Duration::from_secs(20);
const VAULT_PASSWORD: &[u8] = b"e2e-vault-password";

/// Process-wide hermetic environment.
struct Hermetic {
    home: PathBuf,
    origin_leaf_der: Vec<u8>,
    origin_key_der: Vec<u8>,
}

static HERMETIC: OnceLock<Hermetic> = OnceLock::new();

/// Builds the environment once, before any test starts a runtime.
fn hermetic() -> &'static Hermetic {
    HERMETIC.get_or_init(|| {
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("conduit-e2e-{}", std::process::id()));
        let home = root.join("home");
        std::fs::create_dir_all(&home).unwrap();

        let (origin_ca_pem, origin_leaf_der, origin_key_der) = origin_certificates();
        let ca_file = root.join("origin-ca.pem");
        std::fs::write(&ca_file, &origin_ca_pem).unwrap();

        std::env::set_var("HOME", &home);
        std::env::set_var("SSL_CERT_FILE", &ca_file);
        std::env::remove_var("SSL_CERT_DIR");
        std::env::remove_var("SSH_AUTH_SOCK");

        Hermetic {
            home,
            origin_leaf_der,
            origin_key_der,
        }
    })
}

fn ca_params(common_name: &str) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
}

/// An origin CA plus a leaf for the harness's remote-only hostname.
fn origin_certificates() -> (String, Vec<u8>, Vec<u8>) {
    let ca_key = KeyPair::generate().unwrap();
    let params = ca_params("Conduit E2E Origin CA");
    let ca_cert = params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(params, ca_key);

    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![REMOTE_ONLY_HOST.to_string()])
        .unwrap()
        .signed_by(&leaf_key, &issuer)
        .unwrap();
    (ca_cert.pem(), leaf.der().to_vec(), leaf_key.serialize_der())
}

/// Runs one test on its own runtime, with the hermetic environment in place and a hard timeout.
fn e2e(test: impl Future<Output = ()>) {
    hermetic();
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

/// One isolated app data directory with its vault, pins, and manager.
struct Fixture {
    app_data: PathBuf,
    vault: Arc<RwLock<Vault>>,
    known_hosts: Arc<RwLock<KnownHostsStore>>,
    manager: SessionManager,
}

impl Fixture {
    fn new() -> Self {
        let app_data = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("conduit-e2e-app-{}", Uuid::new_v4()));
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
        let manager = SessionManager::new(
            Arc::clone(&vault),
            Arc::clone(&known_hosts),
            ManagerConfig::default(),
        );
        Self {
            app_data,
            vault,
            known_hosts,
            manager,
        }
    }

    fn put(&self, kind: &str, value: &[u8]) -> String {
        self.vault.write().unwrap().put_secret(kind, value).unwrap()
    }

    fn password(&self, value: &str) -> AuthMethod {
        let id = self.put("password", value.as_bytes());
        let secret: SecretRef = serde_json::from_value(serde_json::Value::String(id)).unwrap();
        AuthMethod::Password { secret }
    }

    fn key(&self, key: &PrivateKey) -> AuthMethod {
        let text = key.to_openssh(LineEnding::LF).unwrap();
        let id = self.put("private_key", text.as_bytes());
        let key: KeyId = serde_json::from_value(serde_json::Value::String(id)).unwrap();
        AuthMethod::Key { key }
    }

    fn pin(&self, index: usize, node: &Node, key: &PublicKey) {
        self.known_hosts.write().unwrap().insert(
            HostKeyLookup {
                hop_id: hop_id(index),
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

    fn add(&self, profile: SessionProfile) -> Uuid {
        let id = profile.id;
        self.manager.upsert_profile(profile);
        id
    }

    fn state(&self, id: Uuid) -> SessionState {
        self.manager.snapshot(id).unwrap().state
    }

    fn log_text(&self, id: Uuid) -> String {
        self.manager
            .logs(id)
            .unwrap()
            .query(None)
            .into_iter()
            .map(|line| line.text)
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Polls until `check` passes, failing with the state and logs.
    async fn until(&self, id: Uuid, what: &str, check: impl Fn(&SessionState) -> bool) {
        let deadline = tokio::time::Instant::now() + STATE_TIMEOUT;
        loop {
            let state = self.state(id);
            if check(&state) {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for {what}; state {state:?}; logs:\n{}",
                self.log_text(id)
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn until_connected(&self, id: Uuid) {
        self.until(id, "Connected", |s| *s == SessionState::Connected)
            .await;
    }

    /// Stops everything and checks that nothing created `~/.ssh`.
    async fn finish(self) {
        self.manager.stop_all().await;
        assert!(
            !hermetic().home.join(".ssh").exists(),
            "the runtime must never create ~/.ssh"
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.app_data);
    }
}

fn hop_id(index: usize) -> String {
    format!("hop-{index}")
}

fn hop(index: usize, node: &Node, auth: Vec<AuthMethod>) -> HopEntry {
    HopEntry {
        hop_id: hop_id(index),
        name: hop_id(index),
        host: HostProfile {
            host: "127.0.0.1".into(),
            port: node.port,
            user: "tester".into(),
            auth,
            ..Default::default()
        },
        ..Default::default()
    }
}

/// A profile with no listeners yet. `VERBOSE` sends access records to the session log.
fn profile(name: &str, hops: Vec<HopEntry>) -> SessionProfile {
    SessionProfile {
        id: Uuid::new_v4(),
        name: name.into(),
        hops,
        forward: ForwardConfig {
            http_port: 0,
            socks_port: 0,
            ..Default::default()
        },
        tunnel: TunnelConfig {
            reconnect_initial_delay: Duration::from_secs(1),
            reconnect_max_delay: Duration::from_secs(2),
            ..Default::default()
        },
        logging: LoggingConfig {
            level: "VERBOSE".into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

/// Three pinned servers authenticated as `key → password → key`, with secrets in the vault.
async fn three_hops(f: &Fixture) -> ([Node; 3], Vec<HopEntry>) {
    let first = new_user_key();
    let last = new_user_key();
    let a = spawn_node(Some(first.public_key().clone())).await;
    let b = spawn_node(None).await;
    let c = spawn_node(Some(last.public_key().clone())).await;
    let hops = vec![
        hop(0, &a, vec![f.key(&first)]),
        hop(1, &b, vec![f.password(PASSWORD)]),
        hop(2, &c, vec![f.key(&last)]),
    ];
    for (index, node) in [&a, &b, &c].into_iter().enumerate() {
        f.pin(index, node, &node.host_key);
    }
    ([a, b, c], hops)
}

const BLOCKED_HOST: &str = "blocked.conduit-remote.invalid";
const PAYLOAD_LEN: usize = 128 * 1024;

#[test]
fn concurrent_sessions_stay_isolated() {
    e2e(async {
        let f = Fixture::new();

        // Session A: three hops, forward HTTP + SOCKS5h, allowlisted to one hostname.
        let (nodes, hops) = three_hops(&f).await;
        let http_port = free_port().await;
        let socks_port = free_port().await;
        let mut forward = profile("a-forward", hops);
        forward.forward.http_port = http_port;
        forward.forward.socks_port = socks_port;
        forward.forward.allow = vec![REMOTE_ONLY_HOST.into()];
        let forward_id = f.add(forward);

        // Session B: one hop, reverse proxy multiplexed on one remote port.
        let reverse_node = spawn_node(None).await;
        f.pin(0, &reverse_node, &reverse_node.host_key);
        let remote_port = free_port().await;
        let mut reverse = profile(
            "b-reverse",
            vec![hop(0, &reverse_node, vec![f.password(PASSWORD)])],
        );
        reverse.reverse.reverse_http_port = remote_port;
        reverse.reverse.reverse_socks_port = remote_port;
        let reverse_id = f.add(reverse);

        f.manager.start_all().await;
        f.until_connected(forward_id).await;
        f.until_connected(reverse_id).await;

        let forward_body = payload(PAYLOAD_LEN);
        let reverse_body: Vec<u8> = forward_body.iter().rev().copied().collect();
        let forward_origin = spawn_origin(forward_body.clone()).await;
        let reverse_origin = spawn_origin(reverse_body.clone()).await;
        let echo = spawn_echo().await;

        // Both sessions carry traffic at the same time.
        let forward_http = http_get(loopback(http_port), REMOTE_ONLY_HOST, forward_origin);
        let reverse_http = http_get(loopback(remote_port), "127.0.0.1", reverse_origin);
        let forward_socks = async {
            let (reply, stream) =
                socks5h_connect(loopback(socks_port), REMOTE_ONLY_HOST, echo).await;
            assert_eq!(reply, 0);
            echo_roundtrip(stream, &forward_body).await
        };
        let reverse_socks = async {
            let (reply, stream) = socks5h_connect(loopback(remote_port), "localhost", echo).await;
            assert_eq!(reply, 0);
            echo_roundtrip(stream, &reverse_body).await
        };
        let (a_http, b_http, a_socks, b_socks) =
            tokio::join!(forward_http, reverse_http, forward_socks, reverse_socks);
        assert!(a_http.0.contains("200"), "{}", a_http.0);
        assert!(b_http.0.contains("200"), "{}", b_http.0);
        assert!(a_http.1 == forward_body, "forward HTTP payload corrupted");
        assert!(b_http.1 == reverse_body, "reverse HTTP payload corrupted");
        assert!(a_socks == forward_body, "forward SOCKS payload corrupted");
        assert!(b_socks == reverse_body, "reverse SOCKS payload corrupted");

        // The allowlist refuses other hosts before anything reaches the tunnel.
        let (status, _) = http_get(loopback(http_port), BLOCKED_HOST, forward_origin).await;
        assert!(status.contains("403"), "{status}");
        let (reply, _stream) = socks5h_connect(loopback(socks_port), BLOCKED_HOST, echo).await;
        assert_ne!(reply, 0, "SOCKS must refuse a filtered host");

        // Hostnames reach only session A's final hop, and never session B's server.
        assert!(nodes[2].hosts().iter().any(|h| h == REMOTE_ONLY_HOST));
        for node in &nodes {
            assert!(!node.hosts().iter().any(|h| h == BLOCKED_HOST));
        }
        for node in &nodes[..2] {
            assert!(!node.hosts().iter().any(|h| h == REMOTE_ONLY_HOST));
        }
        assert!(reverse_node.hosts().is_empty(), "reverse egress is local");

        // Live counters belong to the session that carried the traffic.
        let deadline = tokio::time::Instant::now() + STATE_TIMEOUT;
        loop {
            let stats = f.manager.snapshot(forward_id).unwrap().stats;
            if stats.total_connections == 2
                && stats.active_connections == 0
                && stats.bytes_received >= PAYLOAD_LEN as u64 * 2
                && stats.bytes_sent >= PAYLOAD_LEN as u64
            {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "stats: {stats:?}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let reverse_stats = f.manager.snapshot(reverse_id).unwrap().stats;
        assert_eq!(reverse_stats.total_connections, 0);
        assert_eq!(reverse_stats.bytes_received, 0);
        assert_eq!(f.manager.snapshot(forward_id).unwrap().listeners.len(), 2);

        // Stopping flushes the access logs into each session's own ring buffer.
        f.manager.stop_all().await;
        let forward_log = f.log_text(forward_id);
        let reverse_log = f.log_text(reverse_id);
        assert!(forward_log.contains(REMOTE_ONLY_HOST), "{forward_log}");
        assert!(forward_log.contains(&forward_origin.to_string()), "{forward_log}");
        assert!(reverse_log.contains(&reverse_origin.to_string()), "{reverse_log}");
        assert!(!forward_log.contains(&reverse_origin.to_string()), "{forward_log}");
        assert!(!reverse_log.contains(&forward_origin.to_string()), "{reverse_log}");
        assert!(!reverse_log.contains(REMOTE_ONLY_HOST), "{reverse_log}");
        f.finish().await;
    });
}

#[test]
fn reconnect_after_drop_recovers_on_the_same_listeners() {
    e2e(async {
        let f = Fixture::new();
        let (nodes, hops) = three_hops(&f).await;
        let http_port = free_port().await;
        let socks_port = free_port().await;
        let mut session = profile("reconnect", hops);
        session.forward.http_port = http_port;
        session.forward.socks_port = socks_port;
        let id = f.add(session);
        let mut events = f.manager.subscribe_events();

        f.manager.start(id).await.unwrap();
        f.until_connected(id).await;
        let listeners = f.manager.snapshot(id).unwrap().listeners;
        assert_eq!(listeners.len(), 2);

        let body = payload(PAYLOAD_LEN);
        let origin = spawn_origin(body.clone()).await;
        let (status, received) = http_get(loopback(http_port), REMOTE_ONLY_HOST, origin).await;
        assert!(status.contains("200"), "{status}");
        assert!(received == body, "payload corrupted before the drop");

        // Drain the startup transitions, then drop the intermediate hop.
        while events.try_recv().is_ok() {}
        nodes[1].drop_session().await;

        // Every transition is observed in order, so a short Reconnecting cannot be missed.
        let mut saw_reconnecting = false;
        loop {
            match events.recv().await.expect("event bus open") {
                RuntimeEvent::StateChanged { session_id, state } if session_id == id => {
                    match state {
                        SessionState::Reconnecting { .. } => {
                            saw_reconnecting = true;
                            // The local listener stays bound during the outage.
                            TcpStream::connect(loopback(http_port))
                                .await
                                .expect("listener stays bound while reconnecting");
                        }
                        SessionState::Connected => break,
                        SessionState::Starting | SessionState::WaitingForNetwork => {}
                        other => panic!("unexpected state {other:?}:\n{}", f.log_text(id)),
                    }
                }
                _ => {}
            }
        }
        assert!(saw_reconnecting, "the session must pass through Reconnecting");
        assert_eq!(f.manager.snapshot(id).unwrap().listeners, listeners);
        assert_eq!(nodes[1].state.password_attempts.load(Ordering::SeqCst), 2);

        let (status, received) = http_get(loopback(http_port), REMOTE_ONLY_HOST, origin).await;
        assert!(status.contains("200"), "{status}");
        assert!(received == body, "payload corrupted after the reconnect");
        let echo = spawn_echo().await;
        let (reply, stream) = socks5h_connect(loopback(socks_port), REMOTE_ONLY_HOST, echo).await;
        assert_eq!(reply, 0);
        assert_eq!(echo_roundtrip(stream, b"after").await, b"after");

        assert!(f.log_text(id).contains("connection lost"));
        f.finish().await;
    });
}

/// Longer than the reconnect delay, so a wrongly scheduled retry would be observed.
const RETRY_WINDOW: Duration = Duration::from_secs(3);

/// A one-hop SOCKS session authenticating with `password`.
async fn password_session(f: &Fixture, node: &Node, password: &str) -> (Uuid, u16) {
    let socks_port = free_port().await;
    let mut session = profile("gate", vec![hop(0, node, vec![f.password(password)])]);
    session.forward.socks_port = socks_port;
    (f.add(session), socks_port)
}

async fn assert_tunnel_works(socks_port: u16) {
    let echo = spawn_echo().await;
    let (reply, stream) = socks5h_connect(loopback(socks_port), "127.0.0.1", echo).await;
    assert_eq!(reply, 0);
    assert_eq!(echo_roundtrip(stream, b"gate").await, b"gate");
}

fn password_attempts(node: &Node) -> usize {
    node.state.password_attempts.load(Ordering::SeqCst)
}

fn needs_attention(state: &SessionState) -> bool {
    matches!(state, SessionState::NeedsAttention { .. })
}

#[test]
fn security_gates_bad_password_halts_after_one_attempt() {
    e2e(async {
        let f = Fixture::new();
        let node = spawn_node(None).await;
        f.pin(0, &node, &node.host_key);
        let (id, _) = password_session(&f, &node, "wrong password").await;

        f.manager.start(id).await.unwrap();
        f.until(id, "NeedsAttention", needs_attention).await;
        tokio::time::sleep(RETRY_WINDOW).await;

        assert!(needs_attention(&f.state(id)), "{:?}", f.state(id));
        assert_eq!(password_attempts(&node), 1, "a bad password is never retried");
        assert!(!f.log_text(id).contains("wrong password"), "secret leaked to logs");
        f.finish().await;
    });
}

#[test]
fn security_gates_unknown_host_key_waits_for_approval() {
    e2e(async {
        let f = Fixture::new();
        let node = spawn_node(None).await;
        let (id, socks_port) = password_session(&f, &node, PASSWORD).await;

        f.manager.start(id).await.unwrap();
        f.until(id, "AwaitingHostKey", |s| {
            matches!(s, SessionState::AwaitingHostKey(_))
        })
        .await;
        tokio::time::sleep(RETRY_WINDOW).await;
        let SessionState::AwaitingHostKey(prompt) = f.state(id) else {
            panic!("expected a host-key prompt, got {:?}", f.state(id));
        };
        let expected = node.host_key.fingerprint(HashAlg::Sha256).to_string();
        assert_eq!(prompt.sha256, expected);
        assert_eq!(password_attempts(&node), 0, "no credentials before trust");
        assert_eq!(
            f.manager.approve_host_key(id, "SHA256:not-the-key"),
            Err(RuntimeError::FingerprintMismatch)
        );
        assert!(f.known_hosts.read().unwrap().entries.is_empty());

        f.manager.approve_host_key(id, &prompt.sha256).unwrap();
        f.until_connected(id).await;
        let pin = f
            .known_hosts
            .read()
            .unwrap()
            .get(&hop_id(0), "127.0.0.1", node.port)
            .cloned()
            .expect("approval is pinned");
        assert!(pin.approved);
        assert_eq!(pin.fingerprint_sha256, expected);
        assert_eq!(password_attempts(&node), 1);
        assert_tunnel_works(socks_port).await;
        f.finish().await;
    });
}

#[test]
fn security_gates_changed_host_key_halts() {
    e2e(async {
        let f = Fixture::new();
        let node = spawn_node(None).await;
        let impostor = new_user_key().public_key().clone();
        f.pin(0, &node, &impostor);
        let pinned = impostor.fingerprint(HashAlg::Sha256).to_string();
        let (id, _) = password_session(&f, &node, PASSWORD).await;

        f.manager.start(id).await.unwrap();
        f.until(id, "NeedsAttention", needs_attention).await;
        tokio::time::sleep(RETRY_WINDOW).await;

        assert!(needs_attention(&f.state(id)), "{:?}", f.state(id));
        assert_eq!(password_attempts(&node), 0, "no credentials to a changed key");
        assert_eq!(
            f.manager.approve_host_key(id, &pinned),
            Err(RuntimeError::NoPendingHostKey(id))
        );
        let stored = f
            .known_hosts
            .read()
            .unwrap()
            .get(&hop_id(0), "127.0.0.1", node.port)
            .map(|pin| pin.fingerprint_sha256.clone());
        assert_eq!(stored.as_deref(), Some(pinned.as_str()), "pin is untouched");
        f.finish().await;
    });
}

#[test]
fn security_gates_locked_vault_holds_until_unlocked() {
    e2e(async {
        let f = Fixture::new();
        let node = spawn_node(None).await;
        f.pin(0, &node, &node.host_key);
        let (id, socks_port) = password_session(&f, &node, PASSWORD).await;
        f.vault.write().unwrap().lock();

        f.manager.start(id).await.unwrap();
        f.until(id, "Locked", |s| *s == SessionState::Locked).await;
        f.manager.on_vault_unlocked().await;
        tokio::time::sleep(RETRY_WINDOW).await;
        assert_eq!(f.state(id), SessionState::Locked, "the vault is still locked");
        assert_eq!(password_attempts(&node), 0);

        f.vault
            .write()
            .unwrap()
            .unlock_with_password(VAULT_PASSWORD)
            .unwrap();
        f.manager.on_vault_unlocked().await;
        f.until_connected(id).await;
        assert_eq!(password_attempts(&node), 1);
        assert_tunnel_works(socks_port).await;
        f.finish().await;
    });
}

const MITM_PASSPHRASE: &str = "e2e-mitm-ca-passphrase";
const MITM_BODY: &[u8] = b"decrypted origin response";
const MITM_PATH: &str = "/inspected/path";

fn tls_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A TLS origin using the leaf issued by the CA in `SSL_CERT_FILE`.
async fn spawn_tls_origin() -> u16 {
    let env = hermetic();
    let key = PrivateKeyDer::try_from(env.origin_key_der.clone()).unwrap();
    let mut config = rustls::ServerConfig::builder_with_provider(tls_provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(env.origin_leaf_der.clone())], key)
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(loopback(0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(socket).await else {
                    return;
                };
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut chunk).await {
                        Ok(n) if n > 0 => request.extend_from_slice(&chunk[..n]),
                        _ => return,
                    }
                }
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    MITM_BODY.len()
                );
                let _ = tls.write_all(head.as_bytes()).await;
                let _ = tls.write_all(MITM_BODY).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    port
}

/// Writes a passphrase-protected PKCS#12 CA and returns its path and certificate.
fn write_mitm_ca(f: &Fixture) -> (PathBuf, Vec<u8>) {
    let key = KeyPair::generate().unwrap();
    let cert = ca_params("Conduit E2E MITM CA").self_signed(&key).unwrap();
    let cert_der = cert.der().to_vec();
    let chain = p12_keystore::PrivateKeyChain::new(
        b"e2e-ca".to_vec(),
        p12_keystore::PrivateKey::from_der(&key.serialize_der()).unwrap(),
        [p12_keystore::Certificate::from_der(&cert_der).unwrap()],
    );
    let mut store = p12_keystore::KeyStore::new();
    store.add_entry("ca", p12_keystore::KeyStoreEntry::PrivateKeyChain(chain));
    let bytes = store.writer(MITM_PASSPHRASE).write().unwrap();
    let path = f.app_data.join("mitm-ca.p12");
    std::fs::write(&path, bytes).unwrap();
    (path, cert_der)
}

/// Sends `CONNECT` and reads exactly the response head, leaving TLS bytes unread.
async fn http_connect(proxy: SocketAddr, host: &str, port: u16) -> (String, TcpStream) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let request = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await.unwrap());
    }
    let text = String::from_utf8_lossy(&head);
    (text.lines().next().unwrap_or_default().to_string(), stream)
}

#[test]
fn mitm_through_runtime_intercepts_https() {
    e2e(async {
        let f = Fixture::new();
        let node = spawn_node(None).await;
        f.pin(0, &node, &node.host_key);
        let (ca_path, ca_der) = write_mitm_ca(&f);
        let passphrase_id = f.put("mitm_passphrase", MITM_PASSPHRASE.as_bytes());
        let passphrase: SecretRef =
            serde_json::from_value(serde_json::Value::String(passphrase_id)).unwrap();

        let http_port = free_port().await;
        let mut session = profile("mitm", vec![hop(0, &node, vec![f.password(PASSWORD)])]);
        session.forward.http_port = http_port;
        session.mitm = Some(MitmConfig {
            ca_mode: MitmCaMode::Pkcs12 { path: ca_path },
            passphrase: Some(passphrase),
            ..Default::default()
        });
        let id = f.add(session);
        f.manager.start(id).await.unwrap();
        f.until_connected(id).await;

        let origin = spawn_tls_origin().await;
        let (status, stream) = http_connect(loopback(http_port), REMOTE_ONLY_HOST, origin).await;
        assert!(status.contains("200"), "{status}");

        // The client trusts only the MITM CA, so this handshake proves the minted leaf.
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(ca_der.clone())).unwrap();
        let mut client = rustls::ClientConfig::builder_with_provider(tls_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![b"http/1.1".to_vec()];
        let name = ServerName::try_from(REMOTE_ONLY_HOST).unwrap();
        let mut tls = TlsConnector::from(Arc::new(client))
            .connect(name, stream)
            .await
            .expect("client trusts the minted leaf");

        let chain = tls.get_ref().1.peer_certificates().unwrap().to_vec();
        assert_ne!(
            chain[0].as_ref(),
            hermetic().origin_leaf_der.as_slice(),
            "the proxy must present its own leaf"
        );
        assert_eq!(chain[1].as_ref(), ca_der.as_slice(), "leaf chains to the test CA");

        let request = format!(
            "GET {MITM_PATH} HTTP/1.1\r\nHost: {REMOTE_ONLY_HOST}:{origin}\r\nConnection: close\r\n\r\n"
        );
        tls.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        match tls.read_to_end(&mut response).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
            Err(e) => panic!("reading the intercepted response failed: {e}"),
        }
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        assert!(response.ends_with(MITM_BODY), "{text}");
        drop(tls);
        assert!(node.hosts().iter().any(|h| h == REMOTE_ONLY_HOST));

        // Stopping flushes the access record into the session's ring buffer.
        f.manager.stop(id).await.unwrap();
        let log = f.log_text(id);
        let record = log
            .lines()
            .find(|line| line.contains("mitm=true") && line.contains(MITM_PATH))
            .unwrap_or_else(|| panic!("no MITM access record:\n{log}"));
        assert!(record.contains("proto=https"), "{record}");
        assert!(record.contains("method=GET"), "{record}");
        assert!(record.contains("status=200"), "{record}");
        assert!(!log.contains(MITM_PASSPHRASE), "passphrase leaked to logs");
        f.finish().await;
    });
}
