//! Scans everything the app writes or reports for sentinel secrets: exports, session, Proxy, and
//! Tunnel logs, Route Tester and Test Upstream results, error messages, app data files, and the
//! generated OpenSSH files.

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use conduit_core::{
    AuthMethod, ForwardConfig, HopEntry, HostKeyLookup, HostKeyRecord, HostProfile, KeyId,
    KeySource, KnownHostsStore, ListenerConfig, MitmCaId, MitmConfig, Proxy, RouteInbound,
    RouteOneOrMany, RoutingRule, RoutingTablesConfig, SecretRef, SessionProfile, Timestamp, Tunnel,
    UpstreamKind, UpstreamPasswordSource, UpstreamProfile,
};
use conduit_openssh::{write_config, write_known_hosts, ConfigHop, SessionConfig};
use conduit_runtime::{ManagerConfig, SessionState};
use conduit_vault::{generate_key, Argon2Params, KeyGenAlgorithm, MemoryKeyringBackend};
use russh::keys::ssh_key::LineEnding;
use russh::keys::PrivateKey;
use russh::server::{self, Auth};
use rusty_conduit_gui_lib::controller::mitm_ca::MitmCaUpload;
use rusty_conduit_gui_lib::controller::{AppController, ControllerOptions, SecretInput};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use uuid::Uuid;

const MASTER: &str = "Leakscan-Master-Password-5b1e";
const PASSWORD: &str = "leakscan-hop-password-c7d2";
const MITM: &str = "leakscan-mitm-passphrase-19fa";
const KEY_PASS: &str = "leakscan-key-passphrase-e04c";
const EXPORT_PASS: &str = "Leakscan-Export-Passphrase-a83b";
const UPSTREAM: &str = "leakscan-upstream-password-3d9e";
const UPSTREAM_USER: &str = "leakscan-user";

const FAST_ARGON: Argon2Params = Argon2Params {
    memory_kib: 8 * 1024,
    time_cost: 1,
    parallelism: 1,
    derived_key_len: 32,
};

/// A directory removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("conduit-leak-scan-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn options() -> ControllerOptions {
    ControllerOptions {
        argon: FAST_ARGON,
        manager: ManagerConfig::default(),
        keyring: Arc::new(MemoryKeyringBackend::new()),
    }
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// Reports only the label, so a failing test never prints the secret it found.
fn assert_clean(label: &str, bytes: &[u8], forbidden: &[String]) {
    for (index, fragment) in forbidden.iter().enumerate() {
        let found = bytes
            .windows(fragment.len())
            .any(|window| window == fragment.as_bytes());
        assert!(!found, "{label} leaked forbidden fragment #{index}");
    }
}

/// Scans every file under `dir`, including `config.json`, `known_hosts.json`, and `vault.bin`.
fn assert_tree_clean(dir: &Path, forbidden: &[String]) -> usize {
    let mut scanned = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            scanned += assert_tree_clean(&path, forbidden);
        } else {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            assert_clean(&name, &std::fs::read(&path).unwrap(), forbidden);
            scanned += 1;
        }
    }
    scanned
}

/// A vault holding one of every secret type, plus the fragments that must never appear.
struct Fixture {
    dir: TempDir,
    controller: AppController,
    forbidden: Vec<String>,
    key: KeyId,
    password: SecretRef,
    ca: MitmCaId,
}

impl Fixture {
    async fn new() -> Self {
        let dir = TempDir::new();
        let controller = AppController::open(dir.path().join("data"), options()).unwrap();
        controller
            .create_vault(SecretInput::new(MASTER), false)
            .await
            .unwrap();

        let (plain, _) = generate_key(KeyGenAlgorithm::Ed25519).unwrap();
        let plain_pem = plain.to_openssh(LineEnding::LF).unwrap().to_string();
        let (protected, _) = generate_key(KeyGenAlgorithm::Ed25519).unwrap();
        let protected_plain_pem = protected.to_openssh(LineEnding::LF).unwrap().to_string();
        let protected_pem = protected
            .encrypt(&mut getrandom::SysRng, KEY_PASS)
            .unwrap()
            .to_openssh(LineEnding::LF)
            .unwrap()
            .to_string();

        let key = controller
            .import_key_pem("plain", SecretInput::new(plain_pem.as_str()), None, KeySource::Pasted)
            .unwrap()
            .id;
        controller
            .import_key_pem(
                "protected",
                SecretInput::new(protected_pem.as_str()),
                Some(SecretInput::new(KEY_PASS)),
                KeySource::Uploaded,
            )
            .unwrap();
        let password = controller
            .set_password_secret(None, SecretInput::new(PASSWORD))
            .unwrap()
            .secret_ref;
        let (ca_p12, ca_key_pem) = mitm_ca_p12();
        let upload = MitmCaUpload::Pkcs12 { data: SecretInput::new(base64_encode(&ca_p12)) };
        let ca = controller
            .import_mitm_ca("mitm", upload, Some(SecretInput::new(MITM)))
            .unwrap()
            .id;

        let mut forbidden: Vec<String> = [MASTER, PASSWORD, MITM, KEY_PASS, EXPORT_PASS, UPSTREAM]
            .map(String::from)
            .to_vec();
        forbidden.push("PRIVATE KEY".into());
        for pem in [&plain_pem, &protected_plain_pem, &protected_pem, &ca_key_pem] {
            let body = pem
                .lines()
                .filter(|line| !line.starts_with("-----") && line.len() >= 16)
                .map(String::from);
            forbidden.extend(body);
        }
        assert!(forbidden.len() > 8, "the key bodies must be part of the scan");

        Self { dir, controller, forbidden, key, password, ca }
    }

    fn data_dir(&self) -> PathBuf {
        self.dir.path().join("data")
    }

    /// Saves a session that authenticates with the vault key, then the vault password.
    fn add_session(&self, name: &str, ssh_port: u16, with_mitm: bool) -> Uuid {
        let auth = vec![
            AuthMethod::Key { key: self.key.clone() },
            AuthMethod::Password { secret: self.password.clone() },
        ];
        let profile = SessionProfile {
            id: Uuid::new_v4(),
            name: name.into(),
            hops: vec![HopEntry {
                hop_id: "hop-0".into(),
                name: "hop-0".into(),
                host: HostProfile {
                    id: Uuid::nil(),
                    name: "hop-0".into(),
                    host: "127.0.0.1".into(),
                    port: ssh_port,
                    user: "tester".into(),
                    auth,
                    host_key_pin: None,
                },
            }],
            forward: ForwardConfig {
                http_port: free_port(),
                socks_port: 0,
                ..ForwardConfig::default()
            },
            mitm: with_mitm.then(|| MitmConfig { ca: Some(self.ca.clone()), ..MitmConfig::default() }),
            ..SessionProfile::default()
        };
        self.controller.upsert_session(profile).unwrap().id
    }

    fn state(&self, id: Uuid) -> SessionState {
        self.controller
            .list_sessions()
            .unwrap()
            .into_iter()
            .find(|view| view.profile.id == id)
            .unwrap()
            .runtime
            .state
    }

    /// Polls until `pick` accepts the session state.
    async fn wait_for<T>(&self, id: Uuid, pick: impl Fn(&SessionState) -> Option<T>) -> T {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            let state = self.state(id);
            if let Some(value) = pick(&state) {
                return value;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for a session state"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Scans a session's logs and everything the UI can read about it.
    fn assert_session_clean(&self, id: Uuid) -> usize {
        let logs = self.controller.get_session_logs(id, None).unwrap();
        for line in &logs {
            assert_clean("session log", line.text.as_bytes(), &self.forbidden);
        }
        let views = serde_json::to_vec(&self.controller.list_sessions().unwrap()).unwrap();
        assert_clean("session list", &views, &self.forbidden);
        let summary = serde_json::to_vec(&self.controller.get_state_summary()).unwrap();
        assert_clean("state summary", &summary, &self.forbidden);
        logs.len()
    }
}

#[derive(Clone)]
struct RejectingServer;

impl server::Handler for RejectingServer {
    type Error = russh::Error;

    async fn auth_password(&mut self, _user: &str, _password: &str) -> Result<Auth, russh::Error> {
        Ok(Auth::reject())
    }
}

/// A PKCS#12 CA protected by [`MITM`], and its private key PEM.
fn mitm_ca_p12() -> (Vec<u8>, String) {
    use p12_keystore::{Certificate, KeyStore, KeyStoreEntry, PrivateKey, PrivateKeyChain};
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, "Leak Scan CA");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(30);
    let cert = params.self_signed(&key).unwrap();
    let chain = PrivateKeyChain::new(
        b"ca".to_vec(),
        PrivateKey::from_der(&key.serialize_der()).unwrap(),
        [Certificate::from_der(cert.der()).unwrap()],
    );
    let mut store = KeyStore::new();
    store.add_entry("ca", KeyStoreEntry::PrivateKeyChain(chain));
    (store.writer(MITM).write().unwrap(), key.serialize_pem())
}

/// An upstream HTTP proxy that answers every request with `407`, after reading its headers
/// (which carry the `Proxy-Authorization` credentials).
async fn spawn_auth_rejecting_upstream() -> (u16, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut seen = Vec::new();
                let mut buf = [0u8; 1024];
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => seen.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                          Proxy-Authenticate: Basic realm=\"leakscan\"\r\n\
                          Content-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
            });
        }
    });
    (port, task)
}

/// Sends one `CONNECT` through a local Proxy and returns the response head.
async fn connect_through(proxy_port: u16, target: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];
    let read = tokio::time::timeout(Duration::from_secs(10), async {
        while !response.windows(4).any(|w| w == b"\r\n\r\n") {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => response.extend_from_slice(&buf[..n]),
            }
        }
    })
    .await;
    assert!(read.is_ok(), "the Proxy did not answer the CONNECT");
    String::from_utf8_lossy(&response).into_owned()
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A loopback SSH server that rejects every login. Each connection uses the current host key,
/// so a test can simulate a changed key on the same port.
async fn spawn_rejecting_server(host_key: Arc<Mutex<PrivateKey>>) -> (u16, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let key = host_key.lock().unwrap().clone();
            let config = Arc::new(server::Config {
                keys: vec![key],
                auth_rejection_time: Duration::from_millis(1),
                auth_rejection_time_initial: Some(Duration::ZERO),
                ..server::Config::default()
            });
            tokio::spawn(async move {
                if let Ok(session) = server::run_stream(config, socket, RejectingServer).await {
                    let _ = session.await;
                }
            });
        }
    });
    (port, task)
}

#[tokio::test(flavor = "multi_thread")]
async fn plain_export_and_app_data_hold_no_secrets() {
    let fx = Fixture::new().await;
    fx.add_session("export", free_port(), true);

    let path = fx.data_dir().join("plain-export.json");
    let summary = fx.controller.export_config(&path, false, None).unwrap();
    assert!(!summary.encrypted);
    assert_eq!(summary.session_count, 1);
    assert_eq!(summary.secret_count, 0);

    let text = std::fs::read(&path).unwrap();
    assert!(!text.is_empty());
    assert_clean("plain export", &text, &fx.forbidden);
    assert!(assert_tree_clean(&fx.data_dir(), &fx.forbidden) >= 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_export_seals_every_secret() {
    let fx = Fixture::new().await;
    fx.add_session("export", free_port(), true);

    let path = fx.data_dir().join("encrypted-export.json");
    let summary = fx
        .controller
        .export_config(&path, true, Some(SecretInput::new(EXPORT_PASS)))
        .unwrap();
    assert!(summary.encrypted);
    assert!(summary.secret_count >= 3, "key, password, and MITM passphrase are sealed");

    let bytes = std::fs::read(&path).unwrap();
    assert_clean("encrypted export", &bytes, &fx.forbidden);

    // The payload is stored as a JSON number array, which a text scan alone would not read.
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let payload: Vec<u8> = serde_json::from_value(parsed["payload"].clone()).unwrap();
    assert!(!payload.is_empty());
    assert_clean("encrypted payload", &payload, &fx.forbidden);

    // Import proves the scanned file really does carry the secrets, in sealed form.
    let other = TempDir::new();
    let restored = AppController::open(other.path(), options()).unwrap();
    restored
        .create_vault(SecretInput::new(MASTER), false)
        .await
        .unwrap();
    let imported = restored
        .import_config(&path, Some(SecretInput::new(EXPORT_PASS)), false)
        .unwrap();
    assert!(imported.encrypted);
    assert!(imported.secrets_added + imported.keys_added >= 3);
    assert_tree_clean(other.path(), &fx.forbidden);
}

#[tokio::test(flavor = "multi_thread")]
async fn session_logs_and_failure_states_hold_no_secrets() {
    let fx = Fixture::new().await;
    let (first_key, _) = generate_key(KeyGenAlgorithm::Ed25519).unwrap();
    let host_key = Arc::new(Mutex::new(first_key));
    let (port, server) = spawn_rejecting_server(Arc::clone(&host_key)).await;
    let id = fx.add_session("rejected", port, false);

    // Rejected credentials, after the first host key is approved.
    fx.controller.start_session(id).await.unwrap();
    let sha256 = fx
        .wait_for(id, |state| match state {
            SessionState::AwaitingHostKey(prompt) => Some(prompt.sha256.clone()),
            _ => None,
        })
        .await;
    fx.assert_session_clean(id);
    fx.controller.approve_host_key(id, &sha256).unwrap();
    let auth_reason = fx
        .wait_for(id, |state| match state {
            SessionState::NeedsAttention { reason } | SessionState::Failed { reason } => {
                Some(reason.clone())
            }
            _ => None,
        })
        .await;
    assert_clean("auth failure", auth_reason.as_bytes(), &fx.forbidden);
    assert!(fx.assert_session_clean(id) > 0, "the failed attempt must be logged");

    // The same port now presents a different host key.
    fx.controller.stop_session(id).await.unwrap();
    *host_key.lock().unwrap() = generate_key(KeyGenAlgorithm::Ed25519).unwrap().0;
    fx.controller.start_session(id).await.unwrap();
    let changed_reason = fx
        .wait_for(id, |state| match state {
            SessionState::NeedsAttention { reason } | SessionState::Failed { reason }
                if *reason != auth_reason =>
            {
                Some(reason.clone())
            }
            _ => None,
        })
        .await;
    assert_clean("host key failure", changed_reason.as_bytes(), &fx.forbidden);
    fx.assert_session_clean(id);
    fx.controller.stop_session(id).await.unwrap();

    // A MITM session stages its CA from the vault, then fails to log in. Nothing of the CA may
    // show in its logs or state, and the staged file must be gone.
    let mitm = fx.add_session("mitm", port, true);
    fx.controller.start_session(mitm).await.unwrap();
    let mitm_reason = fx
        .wait_for(mitm, |state| match state {
            SessionState::NeedsAttention { reason } | SessionState::Failed { reason } => {
                Some(reason.clone())
            }
            _ => None,
        })
        .await;
    assert_clean("MITM failure", mitm_reason.as_bytes(), &fx.forbidden);
    fx.assert_session_clean(mitm);
    fx.controller.stop_all().await;
    server.abort();

    assert_tree_clean(&fx.data_dir(), &fx.forbidden);
}

#[tokio::test(flavor = "multi_thread")]
async fn rejected_inputs_are_not_echoed_in_errors() {
    let fx = Fixture::new().await;

    let truncated = format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{PASSWORD}\n");
    for pem in [PASSWORD, truncated.as_str()] {
        let error = fx
            .controller
            .import_key_pem("bad", SecretInput::new(pem), None, KeySource::Pasted)
            .unwrap_err();
        assert_clean("import error", error.to_string().as_bytes(), &fx.forbidden);
        assert_clean("import error", &serde_json::to_vec(&error).unwrap(), &fx.forbidden);
    }

    fx.controller.lock_vault();
    let error = fx
        .controller
        .unlock_vault_with_password(SecretInput::new(PASSWORD))
        .await
        .unwrap_err();
    assert_clean("unlock error", error.to_string().as_bytes(), &fx.forbidden);
    assert_clean("unlock error", format!("{error:?}").as_bytes(), &fx.forbidden);
    assert_clean(
        "secret debug output",
        format!("{:?}", SecretInput::new(PASSWORD)).as_bytes(),
        &fx.forbidden,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn generated_openssh_files_hold_no_secrets() {
    let fx = Fixture::new().await;
    let runtime = fx.dir.path().join("openssh");
    std::fs::create_dir_all(&runtime).unwrap();
    let path_text = |name: &str| runtime.join(name).to_str().unwrap().to_owned();

    let config = SessionConfig {
        hops: vec![
            ConfigHop {
                hop_id: "hop-0".into(),
                host: "jump.example.test".into(),
                port: 22,
                user: "tester".into(),
                identity_agent: Some(path_text("agent.sock")),
                identity_files: vec![path_text("hop-0.pub")],
            },
            ConfigHop {
                hop_id: "hop-1".into(),
                host: "target.example.test".into(),
                port: 2222,
                user: "tester".into(),
                identity_agent: None,
                identity_files: Vec::new(),
            },
        ],
        config_path: path_text("ssh_config"),
        known_hosts_path: path_text("known_hosts"),
        worker_path: path_text("conduit-worker"),
        ssh_bin: path_text("ssh"),
        ip_version: "auto".into(),
        server_alive_interval: Duration::from_secs(15),
        server_alive_count_max: 3,
    };
    write_config(&config).unwrap();

    let (host_key, _) = generate_key(KeyGenAlgorithm::Ed25519).unwrap();
    let public = host_key.public_key().to_openssh().unwrap();
    let public = public.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
    let mut store = KnownHostsStore::default();
    store.insert(
        HostKeyLookup { hop_id: "hop-0".into(), host: "jump.example.test".into(), port: 22 },
        HostKeyRecord {
            algorithm: "ssh-ed25519".into(),
            fingerprint_sha256: "SHA256:leakscan".into(),
            first_seen: Timestamp(1),
            approved: true,
            public_key_openssh: Some(public.clone()),
        },
    );
    let known_hosts = runtime.join("known_hosts");
    write_known_hosts(&known_hosts, &store, &[("hop-0", "jump.example.test", 22)]).unwrap();

    let config_bytes = std::fs::read(runtime.join("ssh_config")).unwrap();
    assert!(String::from_utf8_lossy(&config_bytes).contains("IdentitiesOnly yes"));
    assert_clean("ssh config", &config_bytes, &fx.forbidden);

    let host_bytes = std::fs::read(&known_hosts).unwrap();
    assert!(String::from_utf8_lossy(&host_bytes).contains(&public));
    assert_clean("known_hosts", &host_bytes, &fx.forbidden);
    assert_eq!(assert_tree_clean(&runtime, &fx.forbidden), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn v2_proxies_tunnels_and_upstream_passwords_hold_no_secrets() {
    let mut fx = Fixture::new().await;
    // The upstream credentials as an HTTP Basic header would carry them.
    fx.forbidden.push(base64_encode(format!("{UPSTREAM_USER}:{UPSTREAM}").as_bytes()));

    let upstream_secret = fx
        .controller
        .set_upstream_password(None, SecretInput::new(UPSTREAM))
        .await
        .unwrap()
        .secret_ref;
    let (upstream_port, upstream) = spawn_auth_rejecting_upstream().await;
    let closed_port = free_port();

    // A Tunnel that logs in with the vault key, then the vault hop password, and is rejected.
    let (host_key, _) = generate_key(KeyGenAlgorithm::Ed25519).unwrap();
    let (ssh_port, ssh_server) = spawn_rejecting_server(Arc::new(Mutex::new(host_key))).await;
    let tunnel = fx
        .controller
        .upsert_tunnel(Tunnel {
            name: "leaky-tunnel".into(),
            hops: vec![HopEntry {
                hop_id: String::new(),
                name: "hop-0".into(),
                host: HostProfile {
                    id: Uuid::nil(),
                    name: "hop-0".into(),
                    host: "127.0.0.1".into(),
                    port: ssh_port,
                    user: "tester".into(),
                    auth: vec![
                        AuthMethod::Key { key: fx.key.clone() },
                        AuthMethod::Password { secret: fx.password.clone() },
                    ],
                    host_key_pin: None,
                },
            }],
            ..Tunnel::default()
        })
        .unwrap()
        .id;

    // A Proxy whose `corp` profile authenticates with the vaulted upstream password, and whose
    // `ssh` profile dials through the Tunnel.
    let vaulted = |name: &str, port: u16| UpstreamProfile {
        name: name.into(),
        kind: UpstreamKind::Http,
        host: Some("127.0.0.1".into()),
        port: Some(port),
        username: Some(UPSTREAM_USER.into()),
        password: Some(UpstreamPasswordSource::Vault(upstream_secret.clone())),
        bypass: Vec::new(),
        color: None,
    };
    let proxy_port = free_port();
    let draft = Proxy {
        name: "leaky-proxy".into(),
        listeners: ListenerConfig {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            http_port: proxy_port,
            socks_port: 0,
            ..ListenerConfig::default()
        },
        profiles: vec![
            vaulted("corp", upstream_port),
            vaulted("dead", closed_port),
            UpstreamProfile {
                name: "ssh".into(),
                kind: UpstreamKind::Tunnel { tunnel_id: tunnel },
                host: None,
                port: None,
                username: None,
                password: None,
                bypass: Vec::new(),
                color: None,
            },
        ],
        routing: RoutingTablesConfig {
            default: RouteOneOrMany::One("direct".into()),
            rules: vec![RoutingRule {
                name: Some("corp-rule".into()),
                host: Some(RouteOneOrMany::One("intranet.example".into())),
                ..RoutingRule::to_target(RouteOneOrMany::One("corp".into()))
            }],
            ..RoutingTablesConfig::default()
        },
        ..Proxy::default()
    };
    let saved = fx.controller.upsert_proxy(draft).await.unwrap().profile;
    let proxy = saved.id;

    // config.json names the vault record, never the password.
    let config = std::fs::read(fx.data_dir().join("config.json")).unwrap();
    let config_text = String::from_utf8_lossy(&config);
    assert!(config_text.contains("leaky-proxy") && config_text.contains("leaky-tunnel"));
    assert!(config_text.contains(&upstream_secret.to_string()));
    assert_clean("config.json", &config, &fx.forbidden);

    // Route Tester, hit and miss, and a rejected target.
    for (target, inbound) in [
        ("intranet.example:443", RouteInbound::Http),
        ("http://other.example/", RouteInbound::Socks),
    ] {
        let result = AppController::test_route(&saved, target, inbound).unwrap();
        assert_clean("route test", &serde_json::to_vec(&result).unwrap(), &fx.forbidden);
    }
    let error = AppController::test_route(&saved, "", RouteInbound::Http).unwrap_err();
    assert_clean("route test error", error.to_string().as_bytes(), &fx.forbidden);
    assert_clean("route test error", &serde_json::to_vec(&error).unwrap(), &fx.forbidden);

    // Test Upstream: rejected credentials, a closed port, a stopped Tunnel, and an unknown
    // profile. Every result and error is scanned.
    let mut probe_errors = 0;
    for profile in ["corp", "dead", "ssh", "missing"] {
        match fx.controller.test_upstream(&saved, profile, "intranet.example", 443, 3_000).await {
            Ok(probe) => {
                assert!(!probe.ok, "the {profile} probe cannot succeed");
                assert_clean("upstream probe", &serde_json::to_vec(&probe).unwrap(), &fx.forbidden);
                probe_errors += usize::from(probe.error.is_some());
            }
            Err(error) => {
                assert_clean("upstream error", error.to_string().as_bytes(), &fx.forbidden);
                assert_clean("upstream error", &serde_json::to_vec(&error).unwrap(), &fx.forbidden);
                probe_errors += 1;
            }
        }
    }
    assert_eq!(probe_errors, 4, "every probe must fail");

    // A running Proxy sends a CONNECT to the upstream, which rejects the credentials.
    fx.controller.start_proxy(proxy).await.unwrap();
    let response = connect_through(proxy_port, "intranet.example:443").await;
    assert!(!response.starts_with("HTTP/1.1 200"), "the upstream must reject the CONNECT");
    assert_clean("proxy response", response.as_bytes(), &fx.forbidden);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while fx.controller.get_proxy_access_records(proxy, None).unwrap().is_empty()
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let records = fx.controller.get_proxy_access_records(proxy, None).unwrap();
    assert!(!records.is_empty(), "the CONNECT must be recorded");
    assert_clean("access records", &serde_json::to_vec(&records).unwrap(), &fx.forbidden);
    let proxy_logs = fx.controller.get_proxy_logs(proxy, None).unwrap();
    assert!(!proxy_logs.is_empty(), "the Proxy must log its start");
    for line in &proxy_logs {
        assert_clean("proxy log", line.text.as_bytes(), &fx.forbidden);
    }
    assert_clean(
        "proxy list",
        &serde_json::to_vec(&fx.controller.list_proxies().unwrap()).unwrap(),
        &fx.forbidden,
    );

    // The Tunnel asks for its host key, then fails to log in.
    let tunnel_state = |fx: &Fixture| {
        fx.controller
            .list_tunnels()
            .unwrap()
            .into_iter()
            .find(|view| view.profile.id == tunnel)
            .unwrap()
            .snapshot
            .state
    };
    let wait_tunnel = |pick: fn(&SessionState) -> Option<String>| {
        let fx = &fx;
        async move {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
            loop {
                if let Some(value) = pick(&tunnel_state(fx)) {
                    return value;
                }
                assert!(tokio::time::Instant::now() < deadline, "timed out waiting for the Tunnel");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    };
    fx.controller.start_tunnel(tunnel).await.unwrap();
    let sha256 = wait_tunnel(|state| match state {
        SessionState::AwaitingHostKey(prompt) => Some(prompt.sha256.clone()),
        _ => None,
    })
    .await;
    fx.controller.approve_tunnel_host_key(tunnel, &sha256).unwrap();
    let reason = wait_tunnel(|state| match state {
        SessionState::NeedsAttention { reason } | SessionState::Failed { reason } => {
            Some(reason.clone())
        }
        _ => None,
    })
    .await;
    assert_clean("tunnel failure", reason.as_bytes(), &fx.forbidden);
    let tunnel_logs = fx.controller.get_tunnel_logs(tunnel, None).unwrap();
    assert!(!tunnel_logs.is_empty(), "the failed Tunnel attempt must be logged");
    for line in &tunnel_logs {
        assert_clean("tunnel log", line.text.as_bytes(), &fx.forbidden);
    }
    assert_clean(
        "tunnel list",
        &serde_json::to_vec(&fx.controller.list_tunnels().unwrap()).unwrap(),
        &fx.forbidden,
    );
    assert_clean(
        "state summary",
        &serde_json::to_vec(&fx.controller.get_state_summary()).unwrap(),
        &fx.forbidden,
    );

    fx.controller.stop_all_v2().await;
    upstream.abort();
    ssh_server.abort();

    // Exports: the plain one holds no secrets; the encrypted one seals them.
    let plain = fx.data_dir().join("v2-plain-export.json");
    fx.controller.export_config(&plain, false, None).unwrap();
    let plain_bytes = std::fs::read(&plain).unwrap();
    assert!(String::from_utf8_lossy(&plain_bytes).contains("leaky-proxy"));
    assert_clean("v2 plain export", &plain_bytes, &fx.forbidden);

    let sealed = fx.data_dir().join("v2-encrypted-export.json");
    let summary = fx
        .controller
        .export_config(&sealed, true, Some(SecretInput::new(EXPORT_PASS)))
        .unwrap();
    assert!(summary.encrypted && summary.secret_count >= 3, "keys and the MITM CA are sealed");
    let sealed_bytes = std::fs::read(&sealed).unwrap();
    assert_clean("v2 encrypted export", &sealed_bytes, &fx.forbidden);
    let parsed: serde_json::Value = serde_json::from_slice(&sealed_bytes).unwrap();
    let payload: Vec<u8> = serde_json::from_value(parsed["payload"].clone()).unwrap();
    assert_clean("v2 encrypted payload", &payload, &fx.forbidden);

    // config.json, known_hosts.json, and the raw vault.bin bytes.
    assert!(assert_tree_clean(&fx.data_dir(), &fx.forbidden) >= 3);
}
