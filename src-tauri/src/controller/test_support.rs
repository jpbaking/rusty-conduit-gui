//! Shared test fixtures: temp directories, cheap controllers, and a loopback SSH server.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use conduit_core::{AuthMethod, ForwardConfig, HopEntry, HostProfile, SessionProfile};
use conduit_runtime::{HostKeyPrompt, ManagerConfig, SessionState};
use conduit_vault::{generate_key, Argon2Params, KeyGenAlgorithm, KeyringBackend, MemoryKeyringBackend};
use russh::keys::{HashAlg, PublicKey};
use russh::server::{self, Auth, Server as _};
use russh::{Channel, ChannelOpenFailure};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

use super::{AppController, ControllerOptions};

pub const SERVER_PASSWORD: &str = "server-password-canary-7f3a";

pub const FAST_ARGON: Argon2Params = Argon2Params {
    memory_kib: 8 * 1024,
    time_cost: 1,
    parallelism: 1,
    derived_key_len: 32,
};

/// A directory removed on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new() -> Self {
        let path = std::env::temp_dir().join(format!("conduit-gui-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn test_options() -> ControllerOptions {
    ControllerOptions {
        argon: FAST_ARGON,
        manager: ManagerConfig::default(),
        keyring: Arc::new(MemoryKeyringBackend::new()),
    }
}

pub fn controller(dir: &TempDir) -> AppController {
    AppController::open(dir.path(), test_options()).unwrap()
}

pub fn controller_with_keyring(
    dir: &TempDir,
    keyring: Arc<dyn KeyringBackend + Send + Sync>,
) -> AppController {
    let options = ControllerOptions { keyring, ..test_options() };
    AppController::open(dir.path(), options).unwrap()
}

/// An unlocked controller.
pub async fn unlocked(dir: &TempDir) -> AppController {
    let c = controller(dir);
    c.create_vault(super::SecretInput::new("master"), false).await.unwrap();
    c
}

pub fn host(name: &str, port: u16, auth: Vec<AuthMethod>) -> HostProfile {
    HostProfile {
        id: Uuid::nil(),
        name: name.into(),
        host: "127.0.0.1".into(),
        port,
        user: "tester".into(),
        auth,
        host_key_pin: None,
    }
}

pub fn hop(hop_id: &str, port: u16, auth: Vec<AuthMethod>) -> HopEntry {
    HopEntry {
        hop_id: hop_id.into(),
        name: hop_id.into(),
        host: host(hop_id, port, auth),
        agent_forward: false,
    }
}

/// A valid single-hop profile, for tests that never bind its listener.
pub fn profile(name: &str, port: u16) -> SessionProfile {
    SessionProfile {
        id: Uuid::new_v4(),
        name: name.into(),
        hops: vec![hop("hop-0", port, Vec::new())],
        forward: ForwardConfig {
            http_port: 1,
            socks_port: 0,
            ..ForwardConfig::default()
        },
        ..SessionProfile::default()
    }
}

#[derive(Clone)]
struct TestServer;

impl server::Server for TestServer {
    type Handler = Self;
    fn new_client(&mut self, _: Option<SocketAddr>) -> Self {
        self.clone()
    }
}

impl server::Handler for TestServer {
    type Error = russh::Error;

    async fn auth_password(&mut self, _user: &str, password: &str) -> Result<Auth, russh::Error> {
        Ok(if password == SERVER_PASSWORD {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    /// Relays a tunnel, so a chain can hop through this server.
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

/// A loopback SSH server that accepts [`SERVER_PASSWORD`].
pub struct Node {
    pub port: u16,
    pub host_key: PublicKey,
}

impl Node {
    pub fn fingerprint(&self) -> String {
        self.host_key.fingerprint(HashAlg::Sha256).to_string()
    }

    /// A profile targeting this node with no credentials.
    pub fn session(&self, name: &str) -> SessionProfile {
        let mut session = profile(name, self.port);
        // Bind the proxy to a free port so parallel tests never collide.
        session.forward.http_port = free_port();
        session
    }
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

pub async fn spawn_node() -> Node {
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
    let mut factory = TestServer;
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
    Node { port, host_key: public }
}

/// Waits until `id` is asking for a host-key decision.
pub async fn wait_for_prompt(c: &AppController, id: Uuid) -> HostKeyPrompt {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let state = c.manager().snapshot(id).unwrap().state;
        if let SessionState::AwaitingHostKey(prompt) = state {
            return prompt;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no host-key prompt, state: {state:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Waits until `id` reaches `wanted`.
pub async fn wait_for_state(c: &AppController, id: Uuid, wanted: SessionState) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let state = c.manager().snapshot(id).unwrap().state;
        if state == wanted {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "wanted {wanted:?}, state: {state:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
