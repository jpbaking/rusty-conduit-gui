//! Runs one `ssh -N -D` session with app-owned config, keys, and passwords.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use conduit_core::KnownHostsStore;
use conduit_ssh::ScopedAgent;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::agent_server::IsolatedAgentServer;
use crate::dialer::TunnelState;
use crate::askpass::AskpassServer;
use crate::binary::check_openssh_binary;
use crate::config::{hop_alias, write_config, ConfigHop, SessionConfig, WriteConfigError};
use crate::env::{build_child_env, AskpassEnv};
use crate::known_hosts::{write_known_hosts, HopKey};
use crate::orphan;
use crate::runtime_dir::{write_private_file, RuntimeDir};

const WORKER_NAME: &str = "conduit-worker";
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const PROBE_TIMEOUT: Duration = Duration::from_millis(500);
const STDERR_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
/// A longer stderr line is split, so a child cannot grow this buffer without limit.
const MAX_STDERR_LINE: u64 = 8 * 1024;

/// Receives each `ssh` stderr line.
pub type LogFn = Arc<dyn Fn(&str) + Send + Sync>;

/// Why a session failed.
#[derive(Debug, Error)]
pub enum OpenSshError {
    #[error("authentication failed: {0}")]
    AuthFailed(String),
    #[error("the server's host key changed: {0}")]
    HostKeyChanged(String),
    #[error("the server's host key is not trusted: {0}")]
    HostKeyUnknown(String),
    #[error("OpenSSH binary cannot be used: {0}")]
    BinaryUnsupported(String),
    #[error("ssh was not ready within {0:?}")]
    StartupTimeout(Duration),
    #[error("ssh exited: {0}")]
    ProcessExited(String),
    #[error("OpenSSH session I/O failed: {0}")]
    Io(#[from] io::Error),
}

impl From<WriteConfigError> for OpenSshError {
    fn from(error: WriteConfigError) -> Self {
        match error {
            WriteConfigError::Invalid(invalid) => {
                Self::Io(io::Error::new(io::ErrorKind::InvalidInput, invalid))
            }
            WriteConfigError::Io(error) => Self::Io(error),
        }
    }
}

/// One hop's connection details and credentials.
pub struct SupervisorHop {
    pub hop_id: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: Option<Zeroizing<String>>,
    pub agent: Option<Arc<ScopedAgent>>,
}

/// Everything needed to start a session. The last hop is the target.
pub struct SupervisorOptions {
    pub ssh_bin: String,
    /// Overrides [`resolve_worker_bin`] discovery.
    pub worker_bin: Option<PathBuf>,
    pub hops: Vec<SupervisorHop>,
    pub known_hosts: KnownHostsStore,
    pub bind: IpAddr,
    pub socks_port: u16,
    /// Each value is passed as `-R <spec>`.
    pub reverse_forwards: Vec<String>,
    pub extra_args: Vec<String>,
    /// `4`, `6`, or `auto`.
    pub ip_version: String,
    pub server_alive_interval: Duration,
    pub server_alive_count_max: u32,
    pub startup_timeout: Duration,
    pub log: Option<LogFn>,
}

/// Failure kinds, ordered so the most specific one seen wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum FailureKind {
    Auth,
    HostKeyUnknown,
    HostKeyChanged,
}

type Failure = Arc<Mutex<Option<(FailureKind, String)>>>;

fn classify_line(line: &str) -> Option<FailureKind> {
    if line.contains("REMOTE HOST IDENTIFICATION HAS CHANGED") {
        Some(FailureKind::HostKeyChanged)
    } else if line.contains("Host key verification failed")
        || line.contains("host key is known for")
    {
        Some(FailureKind::HostKeyUnknown)
    } else if line.contains("Permission denied (")
        || line.contains("Too many authentication failures")
    {
        // The parenthesis separates an SSH auth failure from `bind: Permission denied`.
        Some(FailureKind::Auth)
    } else {
        None
    }
}

fn record_line(failure: &Failure, line: &str) {
    let Some(kind) = classify_line(line) else {
        return;
    };
    let mut current = failure.lock().unwrap_or_else(|e| e.into_inner());
    if current.as_ref().is_none_or(|(seen, _)| kind > *seen) {
        *current = Some((kind, line.to_string()));
    }
}

fn failure_error(failure: &Failure) -> Option<OpenSshError> {
    let current = failure.lock().unwrap_or_else(|e| e.into_inner());
    current.as_ref().map(|(kind, line)| match kind {
        FailureKind::Auth => OpenSshError::AuthFailed(line.clone()),
        FailureKind::HostKeyUnknown => OpenSshError::HostKeyUnknown(line.clone()),
        FailureKind::HostKeyChanged => OpenSshError::HostKeyChanged(line.clone()),
    })
}

/// Finds `conduit-worker`: `explicit`, then `CARGO_BIN_EXE_conduit-worker`, then next to this
/// executable or one directory up (Cargo puts test binaries in `deps/`).
pub fn resolve_worker_bin(explicit: Option<&Path>) -> io::Result<PathBuf> {
    if let Some(path) = explicit {
        return existing_file(path);
    }
    if let Some(path) = std::env::var_os("CARGO_BIN_EXE_conduit-worker") {
        return existing_file(Path::new(&path));
    }
    let exe = std::env::current_exe()?;
    let name = format!("{WORKER_NAME}{}", std::env::consts::EXE_SUFFIX);
    exe.ancestors()
        .skip(1)
        .take(2)
        .map(|dir| dir.join(&name))
        .find(|path| path.is_file())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{WORKER_NAME} was not found near {}", exe.display()),
            )
        })
}

fn existing_file(path: &Path) -> io::Result<PathBuf> {
    if path.is_file() {
        Ok(path.to_path_buf())
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{WORKER_NAME} was not found at {}", path.display()),
        ))
    }
}

fn utf8_path(path: &Path) -> io::Result<String> {
    path.to_str().map(str::to_string).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path {} is not UTF-8", path.display()),
        )
    })
}

/// Reads stderr line by line, classifying and logging each one.
async fn pump_stderr<R>(stderr: R, failure: Failure, log: Option<LogFn>)
where
    R: AsyncRead + Unpin,
{
    let mut reader = BufReader::new(stderr);
    let mut buffer = Vec::new();
    loop {
        buffer.clear();
        match (&mut reader)
            .take(MAX_STDERR_LINE)
            .read_until(b'\n', &mut buffer)
            .await
        {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let text = String::from_utf8_lossy(&buffer);
        let line = text.trim_end();
        if line.is_empty() {
            continue;
        }
        record_line(&failure, line);
        if let Some(log) = &log {
            log(line);
        }
    }
}

/// Whether a SOCKS5 server answers a no-auth greeting at `address`.
async fn probe_socks(address: SocketAddr) -> bool {
    let attempt = async {
        let mut stream = TcpStream::connect(address).await?;
        stream.write_all(&[5, 1, 0]).await?;
        let mut reply = [0u8; 2];
        stream.read_exact(&mut reply).await?;
        io::Result::Ok(reply == [5, 0])
    };
    matches!(
        tokio::time::timeout(PROBE_TIMEOUT, attempt).await,
        Ok(Ok(true))
    )
}

/// Spawns `command` on a thread that stays alive until the returned sender is dropped.
///
/// Linux sends `PR_SET_PDEATHSIG` when the spawning *thread* exits, and a Tokio blocking-pool
/// thread can exit at any time. This thread lasts as long as the child needs it.
async fn spawn_guarded(mut command: Command) -> io::Result<(Child, mpsc::Sender<()>)> {
    let runtime = tokio::runtime::Handle::current();
    let (result_tx, result_rx) = oneshot::channel();
    let (keep_tx, keep_rx) = mpsc::channel::<()>();
    std::thread::Builder::new()
        .name("conduit-ssh-parent".into())
        .spawn(move || {
            let spawned = {
                let _entered = runtime.enter();
                command.spawn()
            };
            let started = spawned.is_ok();
            if result_tx.send(spawned).is_ok() && started {
                // Returns once the sender is dropped.
                let _ = keep_rx.recv();
            }
        })?;
    let child = result_rx
        .await
        .map_err(|_| io::Error::other("ssh spawn thread ended early"))??;
    Ok((child, keep_tx))
}

/// A running session. Dropping it stops `ssh` and deletes the runtime directory.
pub struct OpenSshSupervisor {
    state: watch::Receiver<TunnelState>,
    socks_addr: SocketAddr,
    runtime_path: PathBuf,
    stop: Option<oneshot::Sender<()>>,
    monitor: Option<JoinHandle<()>>,
    // Dropped in this order, after the child has been told to stop.
    agents: Vec<IsolatedAgentServer>,
    askpass: Option<AskpassServer>,
    runtime_dir: Option<RuntimeDir>,
    #[cfg(windows)]
    _job: orphan::JobGuard,
}

impl std::fmt::Debug for OpenSshSupervisor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenSshSupervisor")
            .field("socks_addr", &self.socks_addr)
            .field("runtime_path", &self.runtime_path)
            .finish()
    }
}

impl OpenSshSupervisor {
    /// Starts `ssh` and returns once its SOCKS5 listener answers.
    pub async fn start(options: SupervisorOptions) -> Result<Self, OpenSshError> {
        let SupervisorOptions {
            ssh_bin,
            worker_bin,
            hops,
            known_hosts,
            bind,
            socks_port,
            reverse_forwards,
            extra_args,
            ip_version,
            server_alive_interval,
            server_alive_count_max,
            startup_timeout,
            log,
        } = options;

        let info = tokio::task::spawn_blocking(move || check_openssh_binary(&ssh_bin))
            .await
            .map_err(io::Error::other)?;
        let ssh_path = match (info.supported, info.resolved_path) {
            (true, Some(path)) => path,
            _ => return Err(OpenSshError::BinaryUnsupported(info.message)),
        };
        let worker = resolve_worker_bin(worker_bin.as_deref())?;
        let worker_path = utf8_path(&worker)?;

        // `ssh` would exit on a busy port, but a probe could first reach the other listener.
        let socks_addr = SocketAddr::new(bind, socks_port);
        drop(std::net::TcpListener::bind(socks_addr)?);

        let runtime_dir = RuntimeDir::create()?;
        let dir = runtime_dir.path().to_path_buf();

        let hop_keys: Vec<HopKey<'_>> = hops
            .iter()
            .map(|hop| (hop.hop_id.as_str(), hop.host.as_str(), hop.port))
            .collect();
        let known_hosts_path = dir.join("known_hosts");
        write_known_hosts(&known_hosts_path, &known_hosts, &hop_keys)?;

        let mut agents = Vec::new();
        let mut config_hops = Vec::with_capacity(hops.len());
        let mut secrets = Vec::with_capacity(hops.len());
        for (index, hop) in hops.into_iter().enumerate() {
            let mut identity_agent = None;
            let mut identity_files = Vec::new();
            if let Some(agent) = hop.agent {
                // `IdentitiesOnly yes` offers an agent key only if its public file is listed.
                for (key_index, identity) in agent.list_identities().iter().enumerate() {
                    let text = identity
                        .public_key
                        .to_openssh()
                        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                    let path = dir.join(format!("hop-{index}-key-{key_index}.pub"));
                    write_private_file(&path, format!("{text}\n").as_bytes())?;
                    identity_files.push(utf8_path(&path)?);
                }
                let server =
                    IsolatedAgentServer::start(&dir, &format!("agent-{index}"), agent).await?;
                identity_agent = Some(server.endpoint_path());
                agents.push(server);
            }
            secrets.push(hop.password);
            config_hops.push(ConfigHop {
                hop_id: hop.hop_id,
                host: hop.host,
                port: hop.port,
                user: hop.user,
                identity_agent,
                identity_files,
            });
        }
        let target_hop = config_hops
            .len()
            .checked_sub(1)
            .ok_or(crate::config::ConfigError::NoHops)
            .map_err(WriteConfigError::from)?;
        let target_alias = hop_alias(&config_hops[target_hop]);

        let askpass = AskpassServer::start(&dir, secrets).await?;
        let config_path = utf8_path(&dir.join("config"))?;
        write_config(&SessionConfig {
            hops: config_hops,
            config_path: config_path.clone(),
            known_hosts_path: utf8_path(&known_hosts_path)?,
            worker_path: worker_path.clone(),
            ssh_bin: ssh_path.clone(),
            ip_version,
            server_alive_interval,
            server_alive_count_max,
        })?;

        let child_env = build_child_env(
            std::env::vars_os(),
            &AskpassEnv {
                worker: worker_path.into(),
                endpoint: askpass.endpoint().to_string(),
                tokens: askpass.tokens().to_vec(),
                hop: target_hop,
            },
        );
        let mut command = Command::new(&ssh_path);
        command
            .arg("-F")
            .arg(&config_path)
            .arg("-N")
            .arg("-D")
            .arg(socks_addr.to_string())
            .args(["-o", "ExitOnForwardFailure=yes"]);
        for spec in &reverse_forwards {
            command.arg("-R").arg(spec);
        }
        command
            .args(&extra_args)
            .arg(&target_alias)
            .env_clear()
            .envs(child_env)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        orphan::guard_command(command.as_std_mut());

        let (mut child, keep_parent) = spawn_guarded(command).await?;
        #[cfg(windows)]
        let job = {
            let handle = child
                .raw_handle()
                .ok_or_else(|| io::Error::other("ssh exited before it could be guarded"))?;
            orphan::JobGuard::assign(handle)?
        };

        let failure: Failure = Arc::new(Mutex::new(None));
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("ssh stderr was not captured"))?;
        let mut stderr_task = tokio::spawn(pump_stderr(stderr, Arc::clone(&failure), log));

        let (state_tx, state) = watch::channel(TunnelState::Connecting);
        let deadline = Instant::now() + startup_timeout;
        loop {
            if let Some(status) = child.try_wait()? {
                let _ = tokio::time::timeout(STDERR_DRAIN_TIMEOUT, &mut stderr_task).await;
                let error = failure_error(&failure)
                    .unwrap_or_else(|| OpenSshError::ProcessExited(status.to_string()));
                let _ = state_tx.send(TunnelState::Disconnected(error.to_string()));
                return Err(error);
            }
            if probe_socks(socks_addr).await {
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill().await;
                let _ = tokio::time::timeout(STDERR_DRAIN_TIMEOUT, &mut stderr_task).await;
                let error = failure_error(&failure)
                    .unwrap_or(OpenSshError::StartupTimeout(startup_timeout));
                let _ = state_tx.send(TunnelState::Disconnected(error.to_string()));
                return Err(error);
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
        let _ = state_tx.send(TunnelState::Ready(socks_addr));

        let (stop, stop_rx) = oneshot::channel();
        let monitor = tokio::spawn(monitor_child(
            child,
            stop_rx,
            state_tx,
            stderr_task,
            failure,
            keep_parent,
        ));
        Ok(Self {
            state,
            socks_addr,
            runtime_path: dir,
            stop: Some(stop),
            monitor: Some(monitor),
            agents,
            askpass: Some(askpass),
            runtime_dir: Some(runtime_dir),
            #[cfg(windows)]
            _job: job,
        })
    }

    /// Live tunnel state.
    pub fn state(&self) -> watch::Receiver<TunnelState> {
        self.state.clone()
    }

    /// The local SOCKS5 address.
    pub fn socks_addr(&self) -> SocketAddr {
        self.socks_addr
    }

    /// The session's private directory. It is deleted on shutdown or drop.
    pub fn runtime_path(&self) -> &Path {
        &self.runtime_path
    }

    /// Stops and reaps `ssh`, then removes the endpoints and runtime directory.
    pub async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(monitor) = self.monitor.take() {
            let _ = monitor.await;
        }
        for agent in std::mem::take(&mut self.agents) {
            agent.shutdown().await;
        }
        if let Some(askpass) = self.askpass.take() {
            askpass.shutdown().await;
        }
        self.runtime_dir.take();
    }
}

impl Drop for OpenSshSupervisor {
    fn drop(&mut self) {
        // Aborting drops the `Child`, and `kill_on_drop` then stops `ssh`.
        if let Some(monitor) = self.monitor.take() {
            monitor.abort();
        }
    }
}

async fn monitor_child(
    mut child: Child,
    stop: oneshot::Receiver<()>,
    state: watch::Sender<TunnelState>,
    stderr_task: JoinHandle<()>,
    failure: Failure,
    keep_parent: mpsc::Sender<()>,
) {
    let reason = tokio::select! {
        _ = stop => {
            let _ = child.kill().await;
            "stopped".to_string()
        }
        status = child.wait() => match status {
            Ok(status) => format!("ssh exited: {status}"),
            Err(error) => format!("could not wait for ssh: {error}"),
        },
    };
    let _ = tokio::time::timeout(STDERR_DRAIN_TIMEOUT, stderr_task).await;
    let reason = failure_error(&failure).map_or(reason, |error| error.to_string());
    let _ = state.send(TunnelState::Disconnected(reason));
    // The child has been reaped, so its parent thread may now exit.
    drop(keep_parent);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn options(ssh_bin: &str) -> SupervisorOptions {
        SupervisorOptions {
            ssh_bin: ssh_bin.into(),
            worker_bin: None,
            hops: Vec::new(),
            known_hosts: KnownHostsStore::default(),
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            socks_port: 0,
            reverse_forwards: Vec::new(),
            extra_args: Vec::new(),
            ip_version: "4".into(),
            server_alive_interval: Duration::from_secs(15),
            server_alive_count_max: 3,
            startup_timeout: Duration::from_secs(5),
            log: None,
        }
    }

    #[test]
    fn supervisor_classifies_stderr_lines() {
        for (line, expected) in [
            (
                "alice@127.0.0.1: Permission denied (publickey,password).",
                Some(FailureKind::Auth),
            ),
            (
                "Received disconnect: Too many authentication failures",
                Some(FailureKind::Auth),
            ),
            (
                "Host key verification failed.",
                Some(FailureKind::HostKeyUnknown),
            ),
            (
                "No ED25519 host key is known for rc-abc and you have requested strict checking.",
                Some(FailureKind::HostKeyUnknown),
            ),
            (
                "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @",
                Some(FailureKind::HostKeyChanged),
            ),
            ("bind [127.0.0.1]:80: Permission denied", None),
            ("Connection closed by 127.0.0.1", None),
        ] {
            assert_eq!(classify_line(line), expected, "{line}");
        }
    }

    #[test]
    fn supervisor_changed_key_outranks_the_generic_failure_line() {
        let failure: Failure = Arc::new(Mutex::new(None));
        record_line(
            &failure,
            "@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @",
        );
        record_line(&failure, "Host key verification failed.");
        assert!(matches!(
            failure_error(&failure),
            Some(OpenSshError::HostKeyChanged(_))
        ));
    }

    #[tokio::test]
    async fn supervisor_stderr_pump_logs_and_bounds_lines() {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&lines);
        let log: LogFn = Arc::new(move |line| sink.lock().unwrap().push(line.len()));
        let failure: Failure = Arc::new(Mutex::new(None));
        let mut input = vec![b'x'; MAX_STDERR_LINE as usize + 10];
        input.extend_from_slice(b"\nu@h: Permission denied (password).\n");
        pump_stderr(input.as_slice(), Arc::clone(&failure), Some(log)).await;
        let lines = lines.lock().unwrap();
        assert_eq!(lines[0], MAX_STDERR_LINE as usize);
        assert_eq!(lines.len(), 3);
        assert!(matches!(
            failure_error(&failure),
            Some(OpenSshError::AuthFailed(_))
        ));
    }

    #[test]
    fn supervisor_worker_lookup_honors_an_explicit_path() {
        let dir = RuntimeDir::create().unwrap();
        let path = dir.path().join("conduit-worker");
        std::fs::write(&path, b"x").unwrap();
        assert_eq!(resolve_worker_bin(Some(&path)).unwrap(), path);
        let missing = dir.path().join("missing");
        assert_eq!(
            resolve_worker_bin(Some(&missing)).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[tokio::test]
    async fn supervisor_rejects_a_missing_binary() {
        let error = OpenSshSupervisor::start(options("/nonexistent/ssh"))
            .await
            .unwrap_err();
        assert!(
            matches!(error, OpenSshError::BinaryUnsupported(_)),
            "{error}"
        );
    }
}
