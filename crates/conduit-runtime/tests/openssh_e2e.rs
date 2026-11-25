//! `SessionManager` driving the real `/usr/bin/ssh` against in-process SSH servers on loopback.
//!
//! The process runs with `HOME` set to an empty temp directory and no `SSH_AUTH_SOCK`.
#![cfg(unix)]

#[allow(dead_code)]
#[path = "../../conduit-ssh/tests/common/mod.rs"]
mod common;

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Once, OnceLock, RwLock};
use std::time::Duration;

use common::{
    echo_roundtrip, http_get, new_user_key, payload, socks5h_connect, spawn_echo,
    spawn_node, spawn_origin, Node, PASSWORD, REMOTE_ONLY_HOST,
};
use conduit_core::{
    AuthMethod, ForwardConfig, ForwardDirection, HopEntry, PortForward, HostKeyLookup, HostKeyRecord, HostProfile, KeyId,
    KnownHostsStore, LoggingConfig, OpenSshOptions, SecretRef, SessionProfile, SshEngine,
    Timestamp, TunnelConfig,
};
use conduit_openssh::host_key_alias;
use conduit_runtime::{ManagerConfig, SessionManager, SessionState};
use conduit_vault::{generate_key, Argon2Params, KeyGenAlgorithm, Vault};
use russh::keys::ssh_key::LineEnding;
use russh::keys::{HashAlg, PrivateKey, PublicKey};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

const TEST_TIMEOUT: Duration = Duration::from_secs(90);
const STATE_TIMEOUT: Duration = Duration::from_secs(30);
const VAULT_PASSWORD: &[u8] = b"openssh-e2e-vault-password";
const PAYLOAD_LEN: usize = 64 * 1024;

/// Builds the worker and isolates the environment, once per process.
///
/// Cargo does not build a dependency's binaries for this test target, and this test binary may
/// not sit near them. So the worker is built here and its reported path is handed to discovery.
fn prepare_process() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let output = Command::new(cargo)
            .args([
                "build",
                "-p",
                "conduit-openssh",
                "--bin",
                "conduit-worker",
                "--message-format=json",
            ])
            .stderr(std::process::Stdio::inherit())
            .output()
            .expect("cargo runs");
        assert!(output.status.success(), "conduit-worker failed to build");
        let worker = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|message| message["target"]["name"] == "conduit-worker")
            .find_map(|message| message["executable"].as_str().map(PathBuf::from))
            .expect("cargo reports the conduit-worker path");
        std::env::set_var("CARGO_BIN_EXE_conduit-worker", worker);

        let home = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("conduit-openssh-e2e-{}", std::process::id()));
        std::fs::create_dir_all(&home).unwrap();
        std::env::set_var("HOME", &home);
        std::env::remove_var("SSH_AUTH_SOCK");
    });
}

fn e2e(test: impl Future<Output = ()>) {
    prepare_process();
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

struct Fixture {
    app_data: PathBuf,
    vault: Arc<RwLock<Vault>>,
    known_hosts: Arc<RwLock<KnownHostsStore>>,
    manager: SessionManager,
}

impl Fixture {
    fn new() -> Self {
        let app_data = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("conduit-openssh-app-{}", Uuid::new_v4()));
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

    fn pin_record(&self, index: usize, node: &Node, key: &PublicKey, with_text: bool) {
        let text = key.to_openssh().unwrap();
        let openssh = text.split(' ').take(2).collect::<Vec<_>>().join(" ");
        self.known_hosts.write().unwrap().insert(
            HostKeyLookup {
                hop_id: hop_id(index),
                host: "127.0.0.1".into(),
                port: node.port,
            },
            HostKeyRecord {
                algorithm: key.algorithm().as_str().to_string(),
                fingerprint_sha256: key.fingerprint(HashAlg::Sha256).to_string(),
                public_key_openssh: with_text.then_some(openssh),
                first_seen: Timestamp(1),
                approved: true,
            },
        );
    }

    fn pin(&self, index: usize, node: &Node, key: &PublicKey) {
        self.pin_record(index, node, key, true);
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
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn until_connected(&self, id: Uuid) {
        self.until(id, "Connected", |s| *s == SessionState::Connected)
            .await;
    }

    async fn until_attention(&self, id: Uuid) -> String {
        self.until(id, "NeedsAttention", |s| {
            matches!(s, SessionState::NeedsAttention { .. })
        })
        .await;
        match self.state(id) {
            SessionState::NeedsAttention { reason } => reason,
            other => panic!("unexpected state {other:?}"),
        }
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
    }
}

/// Below the OS ephemeral ranges, so a `:0` bind (including this engine's own SOCKS port) can
/// never be handed a port reserved here. Separate from the range `e2e_runtime` uses.
const TEST_PORT_BASE: u32 = 30_000;
const TEST_PORT_SPAN: u32 = 2_000;

/// Picks a loopback port for a listener the session binds later.
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

async fn profile(name: &str, hops: Vec<HopEntry>) -> (SessionProfile, u16, u16) {
    let http_port = free_port().await;
    let socks_port = free_port().await;
    let profile = SessionProfile {
        id: Uuid::new_v4(),
        name: name.into(),
        engine: SshEngine::OpenSsh,
        hops,
        forward: ForwardConfig {
            http_port,
            socks_port,
            ..Default::default()
        },
        tunnel: TunnelConfig {
            ip_version: "4".into(),
            reconnect_initial_delay: Duration::from_millis(200),
            reconnect_max_delay: Duration::from_secs(1),
            startup_timeout: Duration::from_secs(20),
            ..Default::default()
        },
        logging: LoggingConfig {
            level: "VERBOSE".into(),
            ..Default::default()
        },
        openssh: OpenSshOptions {
            ssh_bin: "/usr/bin/ssh".into(),
            ..Default::default()
        },
        ..Default::default()
    };
    (profile, http_port, socks_port)
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

/// The process IDs of `ssh` commands for this hop. Its alias is unique to the node's port.
fn ssh_pids(index: usize, node: &Node) -> Vec<String> {
    let alias = host_key_alias(&hop_id(index), "127.0.0.1", node.port);
    let output = Command::new("ps")
        .args(["-axww", "-o", "pid=,command="])
        .output()
        .expect("ps runs");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.contains(&alias) && line.contains("ssh"))
        .filter_map(|line| line.split_whitespace().next().map(str::to_string))
        .collect()
}

/// `ps -p` still lists an unreaped zombie, so this also proves the child was reaped.
fn pid_exists(pid: &str) -> bool {
    Command::new("ps")
        .args(["-o", "pid=", "-p", pid])
        .output()
        .is_ok_and(|output| !output.stdout.is_empty())
}

async fn assert_http_roundtrip(http_port: u16, body: &[u8]) {
    let origin = spawn_origin(body.to_vec()).await;
    let (status, received) = http_get(loopback(http_port), REMOTE_ONLY_HOST, origin).await;
    assert!(status.contains("200"), "{status}");
    assert!(received == body, "HTTP payload corrupted");
}

#[test]
fn key_auth_carries_http_and_socks_with_stats_and_logs() {
    e2e(async {
        let f = Fixture::new();
        let user = new_user_key();
        let node = spawn_node(Some(user.public_key().clone())).await;
        f.pin(0, &node, &node.host_key);
        let (session, http_port, socks_port) =
            profile("key", vec![hop(0, &node, vec![f.key(&user)])]).await;
        let id = f.add(session);

        f.manager.start(id).await.unwrap();
        f.until_connected(id).await;

        let body = payload(PAYLOAD_LEN);
        assert_http_roundtrip(http_port, &body).await;
        let echo = spawn_echo().await;
        let (reply, stream) = socks5h_connect(loopback(socks_port), REMOTE_ONLY_HOST, echo).await;
        assert_eq!(reply, 0);
        assert!(echo_roundtrip(stream, &body).await == body, "SOCKS payload corrupted");

        // The hostname reached the server unresolved, through the real `ssh` tunnel.
        assert!(node.hosts().iter().filter(|h| *h == REMOTE_ONLY_HOST).count() >= 2);
        assert_eq!(node.state.password_attempts.load(Ordering::SeqCst), 0);

        let deadline = tokio::time::Instant::now() + STATE_TIMEOUT;
        loop {
            let stats = f.manager.snapshot(id).unwrap().stats;
            if stats.total_connections >= 2
                && stats.active_connections == 0
                && stats.bytes_received >= PAYLOAD_LEN as u64 * 2
                && stats.bytes_sent >= PAYLOAD_LEN as u64
            {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "stats: {stats:?}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let logs = f.log_text(id);
        assert!(logs.contains("connected"), "{logs}");
        assert!(logs.contains("proxy listening"), "{logs}");
        f.manager.stop(id).await.unwrap();
    });
}

#[test]
fn password_auth_uses_the_askpass_worker() {
    e2e(async {
        let f = Fixture::new();
        let node = spawn_node(None).await;
        f.pin(0, &node, &node.host_key);
        let (session, http_port, _) =
            profile("password", vec![hop(0, &node, vec![f.password(PASSWORD)])]).await;
        let id = f.add(session);

        f.manager.start(id).await.unwrap();
        f.until_connected(id).await;
        assert_http_roundtrip(http_port, &payload(PAYLOAD_LEN)).await;
        assert_eq!(node.state.password_attempts.load(Ordering::SeqCst), 1);
        assert!(!f.log_text(id).contains(PASSWORD), "the password reached the logs");
        f.manager.stop(id).await.unwrap();
    });
}

#[test]
fn bad_password_needs_attention_with_zero_retries() {
    e2e(async {
        let f = Fixture::new();
        let node = spawn_node(None).await;
        f.pin(0, &node, &node.host_key);
        let wrong = "definitely wrong password";
        let (session, _, _) = profile("bad", vec![hop(0, &node, vec![f.password(wrong)])]).await;
        let id = f.add(session);

        f.manager.start(id).await.unwrap();
        let reason = f.until_attention(id).await;
        assert!(reason.contains("authentication failed"), "{reason}");

        // Longer than the reconnect delays, so a retry would have been counted.
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(node.state.password_attempts.load(Ordering::SeqCst), 1);
        assert!(matches!(f.state(id), SessionState::NeedsAttention { .. }));
        assert!(!f.log_text(id).contains(wrong), "the password reached the logs");
    });
}

#[test]
fn changed_host_key_needs_attention_before_any_credential() {
    e2e(async {
        let f = Fixture::new();
        let node = spawn_node(None).await;
        let (other, _) = generate_key(KeyGenAlgorithm::Ed25519).unwrap();
        f.pin(0, &node, other.public_key());
        let (session, _, _) =
            profile("changed", vec![hop(0, &node, vec![f.password(PASSWORD)])]).await;
        let id = f.add(session);

        f.manager.start(id).await.unwrap();
        let reason = f.until_attention(id).await;
        assert!(reason.contains("host key changed"), "{reason}");
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(node.state.password_attempts.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn stop_leaves_no_ssh_process() {
    e2e(async {
        let f = Fixture::new();
        let node = spawn_node(None).await;
        f.pin(0, &node, &node.host_key);
        let (session, http_port, _) =
            profile("stop", vec![hop(0, &node, vec![f.password(PASSWORD)])]).await;
        let id = f.add(session);

        f.manager.start(id).await.unwrap();
        f.until_connected(id).await;
        let pids = ssh_pids(0, &node);
        assert_eq!(pids.len(), 1, "expected one ssh process: {pids:?}");

        f.manager.stop(id).await.unwrap();
        f.until(id, "Stopped", |s| *s == SessionState::Stopped).await;
        assert!(!pid_exists(&pids[0]), "ssh {} is still running", pids[0]);
        assert!(ssh_pids(0, &node).is_empty());
        assert!(
            tokio::net::TcpStream::connect(loopback(http_port)).await.is_err(),
            "the forward listener must be closed"
        );
    });
}

#[test]
fn unknown_host_key_prompts_then_connects_after_approval() {
    e2e(async {
        let f = Fixture::new();
        let node = spawn_node(None).await;
        let (session, http_port, _) =
            profile("tofu", vec![hop(0, &node, vec![f.password(PASSWORD)])]).await;
        let id = f.add(session);

        f.manager.start(id).await.unwrap();
        f.until(id, "AwaitingHostKey", |s| {
            matches!(s, SessionState::AwaitingHostKey(_))
        })
        .await;
        let SessionState::AwaitingHostKey(prompt) = f.state(id) else {
            panic!("expected a host key prompt");
        };
        assert_eq!(
            prompt.sha256,
            node.host_key.fingerprint(HashAlg::Sha256).to_string()
        );
        assert_eq!(
            node.state.password_attempts.load(Ordering::SeqCst),
            0,
            "no credential may be sent to an unverified host"
        );

        f.manager.approve_host_key(id, &prompt.sha256).unwrap();
        f.until_connected(id).await;
        assert_http_roundtrip(http_port, &payload(PAYLOAD_LEN)).await;
        f.manager.stop(id).await.unwrap();
    });
}

#[test]
fn pin_without_key_text_prompts_and_is_upgraded_on_approval() {
    e2e(async {
        let f = Fixture::new();
        let node = spawn_node(None).await;
        f.pin_record(0, &node, &node.host_key, false);
        let (session, _, _) =
            profile("legacy", vec![hop(0, &node, vec![f.password(PASSWORD)])]).await;
        let id = f.add(session);

        f.manager.start(id).await.unwrap();
        f.until(id, "AwaitingHostKey", |s| {
            matches!(s, SessionState::AwaitingHostKey(_))
        })
        .await;
        let SessionState::AwaitingHostKey(prompt) = f.state(id) else {
            panic!("expected a host key prompt");
        };
        f.manager.approve_host_key(id, &prompt.sha256).unwrap();
        f.until_connected(id).await;
        let stored = f
            .known_hosts
            .read()
            .unwrap()
            .get(&hop_id(0), "127.0.0.1", node.port)
            .cloned()
            .unwrap();
        assert!(stored.public_key_openssh.is_some());
        f.manager.stop(id).await.unwrap();
    });
}

#[test]
fn reconnect_keeps_the_forward_listeners_bound() {
    e2e(async {
        let f = Fixture::new();
        let node = spawn_node(None).await;
        f.pin(0, &node, &node.host_key);
        let (session, http_port, _) =
            profile("reconnect", vec![hop(0, &node, vec![f.password(PASSWORD)])]).await;
        let id = f.add(session);

        f.manager.start(id).await.unwrap();
        f.until_connected(id).await;
        let before = f.manager.snapshot(id).unwrap().listeners;
        let first = ssh_pids(0, &node);
        assert_eq!(first.len(), 1);

        node.drop_session().await;
        let deadline = tokio::time::Instant::now() + STATE_TIMEOUT;
        while node.state.password_attempts.load(Ordering::SeqCst) < 2
            || f.state(id) != SessionState::Connected
        {
            assert!(
                tokio::time::Instant::now() < deadline,
                "no reconnect; state {:?}; logs:\n{}",
                f.state(id),
                f.log_text(id)
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        assert_eq!(f.manager.snapshot(id).unwrap().listeners, before);
        assert!(!pid_exists(&first[0]), "the old ssh must be gone");
        assert_http_roundtrip(http_port, &payload(PAYLOAD_LEN)).await;
        f.manager.stop(id).await.unwrap();
    });
}

#[test]
fn port_forwards_carry_traffic_both_ways() {
    e2e(async {
        let f = Fixture::new();
        let node = spawn_node(None).await;
        f.pin(0, &node, &node.host_key);
        let echo = spawn_echo().await;
        let local_port = free_port().await;
        let remote_port = free_port().await;
        let (mut session, _, _) =
            profile("forwards", vec![hop(0, &node, vec![f.password(PASSWORD)])]).await;
        session.forward.enabled = false;
        let local = PortForward {
            id: Uuid::new_v4(),
            direction: ForwardDirection::Local,
            port: local_port,
            // Only the target resolves this name, so the connection went through `ssh`.
            dest_host: REMOTE_ONLY_HOST.into(),
            dest_port: echo,
            ..Default::default()
        };
        let remote = PortForward {
            id: Uuid::new_v4(),
            direction: ForwardDirection::Remote,
            port: remote_port,
            dest_host: "127.0.0.1".into(),
            dest_port: echo,
            ..Default::default()
        };
        session.port_forwards = vec![local.clone(), remote.clone()];
        let id = f.add(session);

        f.manager.start(id).await.unwrap();
        f.until_connected(id).await;

        let body = payload(PAYLOAD_LEN);
        let through_local = TcpStream::connect(loopback(local_port)).await.unwrap();
        assert!(echo_roundtrip(through_local, &body).await == body, "-L payload corrupted");
        assert!(node.hosts().iter().any(|h| h == REMOTE_ONLY_HOST));
        // `ssh -R` is set up after the SOCKS port answers, so give it a moment.
        let deadline = tokio::time::Instant::now() + STATE_TIMEOUT;
        let through_remote = loop {
            if let Ok(stream) = TcpStream::connect(loopback(remote_port)).await {
                break stream;
            }
            assert!(tokio::time::Instant::now() < deadline, "logs:\n{}", f.log_text(id));
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert!(echo_roundtrip(through_remote, &body).await == body, "-R payload corrupted");

        let statuses = f.manager.snapshot(id).unwrap().port_forwards;
        assert_eq!(statuses.len(), 2, "{statuses:?}");
        assert!(statuses.iter().all(|s| s.error.is_none()), "{statuses:?}");

        f.manager.stop(id).await.unwrap();
        assert!(f.manager.snapshot(id).unwrap().port_forwards.is_empty());
    });
}
