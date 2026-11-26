//! `conduit-core` — UI-agnostic data models.
//!
//! Every session, host, and vault data model lives here so future UI shells
//! (Tauri v2 + Svelte 5) stay thin adapters. Filter rules, the SSH IP version, and the log
//! settings are stored as human-friendly strings and parsed/validated in `validate` and
//! `mapping`; this keeps the `rusty-conduit-engine` types that lack `serde` (`FilterRule`,
//! `LogLevel`, `LogFormat`) and this crate's `SshIpVersion` out of the stored model.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Duration <-> u64 seconds (serde can't serialize `Duration` directly).
// ---------------------------------------------------------------------------

mod serde_duration {
    use super::Duration;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let secs = u64::deserialize(d)?;
        Ok(Duration::from_secs(secs))
    }
}

// ---------------------------------------------------------------------------
// Identifiers, sources, timestamps.
// ---------------------------------------------------------------------------

/// Opaque identifier of a private-key record inside `vault.bin`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId(Uuid);

impl KeyId {
    pub fn new() -> Self {
        KeyId(Uuid::new_v4())
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Default for KeyId {
    fn default() -> Self {
        KeyId(Uuid::nil())
    }
}

/// Opaque reference to any encrypted secret record (password, key material, passphrase) in
/// `vault.bin`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SecretRef(Uuid);

impl SecretRef {
    pub fn new() -> Self {
        SecretRef(Uuid::new_v4())
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl std::fmt::Display for SecretRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Default for SecretRef {
    fn default() -> Self {
        SecretRef(Uuid::nil())
    }
}

/// Opaque identifier of a MITM CA record inside `vault.bin`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MitmCaId(Uuid);

impl MitmCaId {
    pub fn new() -> Self {
        MitmCaId(Uuid::new_v4())
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl std::fmt::Display for MitmCaId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Default for MitmCaId {
    fn default() -> Self {
        MitmCaId(Uuid::nil())
    }
}

/// How a private-key record entered the vault (write-only in the UI).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeySource {
    Uploaded,
    Pasted,
    Generated,
}

/// Unix epoch seconds. Stored as a JSON number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
pub struct Timestamp(pub i64);

impl Timestamp {
    pub fn now() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        Timestamp(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
        )
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Vault key metadata.
// ---------------------------------------------------------------------------

/// Metadata for one private-key record. The private key bytes live only in `vault.bin`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultKeyMeta {
    pub id: KeyId,
    pub name: String,
    pub algorithm: String,
    pub fingerprint_sha256: String,
    /// Safe to display & copy into `authorized_keys`.
    pub public_key_openssh: String,
    pub source: KeySource,
    #[serde(default)]
    pub created_at: Timestamp,
}

/// Metadata for one MITM CA record. The certificate chain and private key live only in
/// `vault.bin`, stored decrypted inside the vault as normalized PEM, so the files it was
/// uploaded from are no longer needed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultCaMeta {
    pub id: MitmCaId,
    pub name: String,
    /// The signing certificate's subject.
    pub subject: String,
    /// When the signing certificate expires.
    pub not_after: Timestamp,
    /// SHA-256 of the signing certificate's DER (`SHA256:<base64>`).
    pub fingerprint_sha256: String,
    #[serde(default)]
    pub created_at: Timestamp,
}

// ---------------------------------------------------------------------------
// Host profiles & host-key pins.
// ---------------------------------------------------------------------------

/// A pinned host key for one hop/host/port (first-trust-until-approved).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostKeyPin {
    /// e.g. `ssh-ed25519`, `ecdsa-sha2-nistp256`, `rsa-sha2-512`.
    pub algorithm: String,
    pub fingerprint_sha256: String,
    #[serde(default)]
    pub first_seen: Timestamp,
    /// `false` until the user approves the fingerprint in the verification modal.
    pub approved: bool,
}

/// Ordered per-hop authentication methods.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthMethod {
    Key { key: KeyId },
    Password { secret: SecretRef },
    KeyboardInteractive { prompts: Vec<String> },
    /// Explicit, never-on-by-default opt-in to scoped agent forwarding.
    SystemAgentOptIn,
}

/// A reusable host profile: connection details shared across sessions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostProfile {
    #[serde(default)]
    pub id: Uuid,
    pub name: String,
    pub host: String,
    #[serde(default = "default_host_port")]
    pub port: u16,
    pub user: String,
    /// Ordered: keys first, then passwords / keyboard-interactive.
    pub auth: Vec<AuthMethod>,
    #[serde(default)]
    pub host_key_pin: Option<HostKeyPin>,
}

impl Default for HostProfile {
    fn default() -> Self {
        Self {
            id: Uuid::nil(),
            name: String::new(),
            host: String::new(),
            port: default_host_port(),
            user: String::new(),
            auth: Vec::new(),
            host_key_pin: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Engines, hops, and the multi-hop chain.
// ---------------------------------------------------------------------------

/// SSH engine for a session. `Russh` is the pure-Rust default (native multi-hop); `OpenSsh`
/// is an opt-in Phase 4 engine for raw `extra_args` / `ProxyCommand` / FIDO2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SshEngine {
    #[default]
    Russh,
    OpenSsh,
}

/// One hop in a session's multi-hop chain.
///
/// Carries a fully resolved inline [`HostProfile`] so the session is self-contained;
/// `hop_id` is the stable key for app-owned known_hosts (`known_hosts.json`). The last hop is
/// the SSH target. Jumphosts are traversed by the russh engine, not by `ssh -J`.
///
/// No agent is ever forwarded to a hop: the app logs into every hop itself, so a proxy never
/// needs one. Profiles saved with the old `agent_forward*` fields still load; they are ignored.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HopEntry {
    pub hop_id: String,
    pub name: String,
    pub host: HostProfile,
}

// ---------------------------------------------------------------------------
// Forward / reverse proxy configuration.
// ---------------------------------------------------------------------------

fn default_bind() -> IpAddr {
    IpAddr::V4("127.0.0.1".parse().unwrap())
}

fn default_reverse_bind() -> IpAddr {
    IpAddr::V4("127.0.0.1".parse().unwrap())
}

fn default_http_port() -> u16 {
    3128
}

fn default_socks_port() -> u16 {
    1080
}

fn default_max_connections() -> usize {
    4096
}

/// Forward (`ssh -D`) listener configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "wire::ForwardConfig")]
pub struct ForwardConfig {
    /// Whether the forward proxy runs. Off keeps the ports below for when it is turned back on;
    /// the engine then sees both ports as `0`.
    pub enabled: bool,
    #[serde(default = "default_bind")]
    pub bind: IpAddr,
    #[serde(default = "default_http_port")]
    pub http_port: u16,
    #[serde(default = "default_socks_port")]
    pub socks_port: u16,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Destination allowlist rules in `rusty-conduit-engine` filter syntax.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Destination blocklist rules in `rusty-conduit-engine` filter syntax.
    #[serde(default)]
    pub block: Vec<String>,
}

impl Default for ForwardConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind: default_bind(),
            http_port: default_http_port(),
            socks_port: default_socks_port(),
            max_connections: default_max_connections(),
            allow: Vec::new(),
            block: Vec::new(),
        }
    }
}

/// Reverse (`ssh -R`) listener configuration. Ports default to `0` (disabled).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "wire::ReverseConfig")]
pub struct ReverseConfig {
    /// Whether the reverse proxy runs. Off keeps the ports below for when it is turned back on;
    /// the engine then sees both ports as `0`.
    pub enabled: bool,
    #[serde(default = "default_reverse_bind")]
    pub reverse_bind: IpAddr,
    #[serde(default)]
    pub reverse_http_port: u16,
    #[serde(default)]
    pub reverse_socks_port: u16,
    /// Concurrent reverse proxy clients (`0` = unlimited). `None` uses the forward cap.
    #[serde(default)]
    pub reverse_max_connections: Option<usize>,
    #[serde(default)]
    pub reverse_allow: Vec<String>,
    #[serde(default)]
    pub reverse_block: Vec<String>,
}

impl Default for ReverseConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            reverse_bind: default_reverse_bind(),
            reverse_http_port: 0,
            reverse_socks_port: 0,
            reverse_max_connections: None,
            reverse_allow: Vec::new(),
            reverse_block: Vec::new(),
        }
    }
}

impl ForwardConfig {
    /// The ports the engine listens on: both `0` while the forward proxy is off.
    pub fn effective_ports(&self) -> (u16, u16) {
        if self.enabled { (self.http_port, self.socks_port) } else { (0, 0) }
    }
}

impl ReverseConfig {
    /// The ports opened on the target: both `0` while the reverse proxy is off.
    pub fn effective_ports(&self) -> (u16, u16) {
        if self.enabled {
            (self.reverse_http_port, self.reverse_socks_port)
        } else {
            (0, 0)
        }
    }
}

// ---------------------------------------------------------------------------
// Port forwards (`ssh -L` / `ssh -R`).
// ---------------------------------------------------------------------------

/// Which side listens for a [`PortForward`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForwardDirection {
    /// `ssh -L`: listens on this machine, connects from the SSH target.
    Local,
    /// `ssh -R`: listens on the SSH target, connects from this machine.
    Remote,
}

/// One fixed TCP port forward, like `ssh -L` or `ssh -R`.
///
/// Both engines run it the same way. A local forward listens here and opens each connection
/// through the tunnel, and a remote forward asks the target to listen and relays each
/// connection to the destination from this machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortForward {
    /// Stable id, so the runtime can report each forward's state.
    #[serde(default)]
    pub id: Uuid,
    /// Off keeps the forward saved without running it.
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    pub direction: ForwardDirection,
    /// Free-text label shown in the UI.
    #[serde(default)]
    pub name: String,
    /// Listen address: on this machine for `Local`, on the target for `Remote`.
    #[serde(default = "default_bind")]
    pub bind: IpAddr,
    /// Listen port, `1..=65535`.
    pub port: u16,
    /// Host connected to: resolved by the target for `Local`, by this machine for `Remote`.
    pub dest_host: String,
    pub dest_port: u16,
}

impl Default for PortForward {
    fn default() -> Self {
        Self {
            id: Uuid::nil(),
            enabled: true,
            direction: ForwardDirection::Local,
            name: String::new(),
            bind: default_bind(),
            port: 0,
            dest_host: String::new(),
            dest_port: 0,
        }
    }
}

impl PortForward {
    /// The destination as `host:port`, with an IPv6 literal in brackets.
    pub fn destination(&self) -> String {
        let host = self.dest_host_unbracketed();
        if host.contains(':') {
            format!("[{host}]:{}", self.dest_port)
        } else {
            format!("{host}:{}", self.dest_port)
        }
    }

    /// The destination host without IPv6 brackets.
    pub fn dest_host_unbracketed(&self) -> &str {
        let host = self.dest_host.trim();
        host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host)
    }

    /// The listen address.
    pub fn listen(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::new(self.bind, self.port)
    }

    /// The equivalent `ssh` argument value, such as `127.0.0.1:8080:db.internal:5432`.
    pub fn spec(&self) -> String {
        format!("{}:{}", self.listen(), self.destination())
    }
}

/// A reusable template for a [`PortForward`], kept app-wide in [`AppConfig`].
///
/// Adding one to a session copies its values, so later edits to the preset do not change
/// forwards already added. An empty `dest_host` is filled in by the user after adding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardPreset {
    #[serde(default)]
    pub id: Uuid,
    pub name: String,
    pub direction: ForwardDirection,
    /// Listen address. `None` uses 127.0.0.1.
    #[serde(default)]
    pub bind: Option<IpAddr>,
    pub port: u16,
    #[serde(default)]
    pub dest_host: String,
    pub dest_port: u16,
}

/// The presets a new install starts with. Their ids are fixed, so restoring them is idempotent.
pub fn builtin_forward_presets() -> Vec<ForwardPreset> {
    let local = |n: u128, name: &str, port: u16, dest_port: u16| ForwardPreset {
        id: Uuid::from_u128(0x5f0d_0000_0000_4000_8000_0000_0000_0000 | n),
        name: name.into(),
        direction: ForwardDirection::Local,
        bind: None,
        port,
        dest_host: String::new(),
        dest_port,
    };
    vec![
        local(1, "PostgreSQL", 15432, 5432),
        local(2, "MySQL", 13306, 3306),
        local(3, "Redis", 16379, 6379),
        local(4, "Remote Desktop", 13389, 3389),
        local(5, "Web UI (HTTPS)", 18443, 443),
        ForwardPreset {
            direction: ForwardDirection::Remote,
            dest_host: "localhost".into(),
            ..local(6, "Share a local dev server", 8000, 3000)
        },
    ]
}

/// On-disk shapes. Profiles saved before the on/off switch have no `enabled`, so it is inferred
/// from the ports: a proxy with any non-zero port was running.
mod wire {
    use super::*;

    #[derive(Deserialize)]
    pub(super) struct ForwardConfig {
        #[serde(default)]
        enabled: Option<bool>,
        #[serde(default = "default_bind")]
        bind: IpAddr,
        #[serde(default = "default_http_port")]
        http_port: u16,
        #[serde(default = "default_socks_port")]
        socks_port: u16,
        #[serde(default = "default_max_connections")]
        max_connections: usize,
        #[serde(default)]
        allow: Vec<String>,
        #[serde(default)]
        block: Vec<String>,
    }

    impl From<ForwardConfig> for super::ForwardConfig {
        fn from(w: ForwardConfig) -> Self {
            Self {
                enabled: w.enabled.unwrap_or(w.http_port != 0 || w.socks_port != 0),
                bind: w.bind,
                http_port: w.http_port,
                socks_port: w.socks_port,
                max_connections: w.max_connections,
                allow: w.allow,
                block: w.block,
            }
        }
    }

    #[derive(Deserialize)]
    pub(super) struct ReverseConfig {
        #[serde(default)]
        enabled: Option<bool>,
        #[serde(default = "default_reverse_bind")]
        reverse_bind: IpAddr,
        #[serde(default)]
        reverse_http_port: u16,
        #[serde(default)]
        reverse_socks_port: u16,
        #[serde(default)]
        reverse_max_connections: Option<usize>,
        #[serde(default)]
        reverse_allow: Vec<String>,
        #[serde(default)]
        reverse_block: Vec<String>,
    }

    impl From<ReverseConfig> for super::ReverseConfig {
        fn from(w: ReverseConfig) -> Self {
            Self {
                enabled: w
                    .enabled
                    .unwrap_or(w.reverse_http_port != 0 || w.reverse_socks_port != 0),
                reverse_bind: w.reverse_bind,
                reverse_http_port: w.reverse_http_port,
                reverse_socks_port: w.reverse_socks_port,
                reverse_max_connections: w.reverse_max_connections,
                reverse_allow: w.reverse_allow,
                reverse_block: w.reverse_block,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MITM, keepalive/reconnect, logging, advanced SSH options.
// ---------------------------------------------------------------------------

fn default_cert_ttl() -> Duration {
    Duration::from_secs(60 * 60)
}

fn default_cert_cache_max_entries() -> usize {
    10_000
}

fn default_server_alive_interval() -> Duration {
    Duration::from_secs(15)
}

fn default_server_alive_count_max() -> u32 {
    3
}

fn default_tcp_keepalive() -> Duration {
    Duration::from_secs(60)
}

fn default_tcp_keepalive_interval() -> Duration {
    Duration::from_secs(10)
}

fn default_tcp_keepalive_retries() -> u32 {
    5
}

fn default_reconnect_initial() -> Duration {
    Duration::from_secs(1)
}

fn default_reconnect_max() -> Duration {
    Duration::from_secs(30)
}

fn default_startup_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_ip_version() -> String {
    "4".to_string()
}

fn default_log_level() -> String {
    "INFO".to_string()
}

fn default_log_format() -> String {
    "text".to_string()
}

fn default_ssh_bin() -> String {
    "ssh".to_string()
}

/// HTTPS MITM inspection configuration. `None` disables MITM.
///
/// The CA lives in the vault ([`VaultCaMeta`]); a session only refers to it. Sessions saved
/// by earlier betas named CA files by path (`ca_mode`, `passphrase`, `ca_passphrase_file`).
/// Those fields are ignored when loading, so such a session has no CA until one is chosen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MitmConfig {
    #[serde(default)]
    pub ca: Option<MitmCaId>,
    #[serde(default = "default_cert_ttl", with = "serde_duration")]
    pub cert_ttl: Duration,
    #[serde(default = "default_cert_cache_max_entries")]
    pub cert_cache_max_entries: usize,
    #[serde(default)]
    pub socks_block_web: bool,
}

impl Default for MitmConfig {
    fn default() -> Self {
        Self {
            ca: None,
            cert_ttl: default_cert_ttl(),
            cert_cache_max_entries: default_cert_cache_max_entries(),
            socks_block_web: false,
        }
    }
}

/// Keepalive & reconnect backoff configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelConfig {
    /// "4" | "6" | "auto"; parsed to `SshIpVersion` in `validate`/`mapping`.
    #[serde(default = "default_ip_version")]
    pub ip_version: String,
    #[serde(default = "default_server_alive_interval", with = "serde_duration")]
    pub server_alive_interval: Duration,
    #[serde(default = "default_server_alive_count_max")]
    pub server_alive_count_max: u32,
    /// Idle time before TCP keepalive probes start on proxy client sockets and reverse proxy
    /// upstream sockets (`0` = TCP keepalive off). One setting covers forward and reverse.
    #[serde(default = "default_tcp_keepalive", with = "serde_duration")]
    pub tcp_keepalive: Duration,
    /// Time between unanswered TCP keepalive probes.
    #[serde(default = "default_tcp_keepalive_interval", with = "serde_duration")]
    pub tcp_keepalive_interval: Duration,
    /// Unanswered TCP keepalive probes before the OS closes the connection.
    #[serde(default = "default_tcp_keepalive_retries")]
    pub tcp_keepalive_retries: u32,
    #[serde(default)]
    pub no_reconnect: bool,
    #[serde(default = "default_reconnect_initial", with = "serde_duration")]
    pub reconnect_initial_delay: Duration,
    #[serde(default = "default_reconnect_max", with = "serde_duration")]
    pub reconnect_max_delay: Duration,
    #[serde(default = "default_startup_timeout", with = "serde_duration")]
    pub startup_timeout: Duration,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            ip_version: default_ip_version(),
            server_alive_interval: default_server_alive_interval(),
            server_alive_count_max: default_server_alive_count_max(),
            tcp_keepalive: default_tcp_keepalive(),
            tcp_keepalive_interval: default_tcp_keepalive_interval(),
            tcp_keepalive_retries: default_tcp_keepalive_retries(),
            no_reconnect: false,
            reconnect_initial_delay: default_reconnect_initial(),
            reconnect_max_delay: default_reconnect_max(),
            startup_timeout: default_startup_timeout(),
        }
    }
}

/// Logging configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// "QUIET".."VERBOSE"; parsed to `LogLevel` in `validate`/`mapping`.
    #[serde(default = "default_log_level")]
    pub level: String,
    /// "text" | "json"; parsed to `LogFormat` in `validate`/`mapping`.
    #[serde(default = "default_log_format")]
    pub format: String,
    #[serde(default)]
    pub http_access_log: Option<PathBuf>,
    #[serde(default)]
    pub socks_log: Option<PathBuf>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
            http_access_log: None,
            socks_log: None,
        }
    }
}

/// OpenSSH-only advanced options. Present whenever `engine = OpenSsh`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenSshOptions {
    #[serde(default = "default_ssh_bin")]
    pub ssh_bin: String,
    #[serde(default = "default_bind")]
    pub ssh_socks_bind: IpAddr,
    #[serde(default)]
    pub ssh_socks_port: u16,
    /// Passed to `ssh` verbatim; validated against the isolation denylist in `validate`.
    #[serde(default)]
    pub extra_args: Vec<String>,
}

impl Default for OpenSshOptions {
    fn default() -> Self {
        Self {
            ssh_bin: default_ssh_bin(),
            ssh_socks_bind: default_bind(),
            ssh_socks_port: 0,
            extra_args: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Session profile — the top-level per-session document.
// ---------------------------------------------------------------------------

/// A saved, runnable session. The last [`HopEntry`] is the SSH target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionProfile {
    #[serde(default)]
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub autostart: bool,
    /// `false` leaves the session out of Start All and autostart. It can still be started alone.
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    #[serde(default)]
    pub engine: SshEngine,
    pub hops: Vec<HopEntry>,
    pub forward: ForwardConfig,
    pub reverse: ReverseConfig,
    /// Fixed `-L` / `-R` port forwards, run by either engine.
    #[serde(default)]
    pub port_forwards: Vec<PortForward>,
    #[serde(default)]
    pub mitm: Option<MitmConfig>,
    #[serde(default)]
    pub tunnel: TunnelConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub openssh: OpenSshOptions,
}

fn enabled_by_default() -> bool {
    true
}

impl Default for SessionProfile {
    fn default() -> Self {
        Self {
            id: Uuid::nil(),
            name: String::new(),
            autostart: false,
            enabled: true,
            engine: SshEngine::default(),
            hops: Vec::new(),
            forward: ForwardConfig::default(),
            reverse: ReverseConfig::default(),
            port_forwards: Vec::new(),
            mitm: None,
            tunnel: TunnelConfig::default(),
            logging: LoggingConfig::default(),
            openssh: OpenSshOptions::default(),
        }
    }
}

impl SessionProfile {
    /// The port forwards that are switched on.
    pub fn active_forwards(&self) -> impl Iterator<Item = &PortForward> {
        self.port_forwards.iter().filter(|f| f.enabled)
    }

    /// The switched-on forwards in one direction.
    pub fn active_forwards_in(
        &self,
        direction: ForwardDirection,
    ) -> impl Iterator<Item = &PortForward> {
        self.active_forwards().filter(move |f| f.direction == direction)
    }
}

// ---------------------------------------------------------------------------
// App document (config.json) and app-owned known_hosts (known_hosts.json).
// ---------------------------------------------------------------------------

/// The top-level application document persisted to `config.json`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub sessions: Vec<SessionProfile>,
    #[serde(default)]
    pub hosts: Vec<HostProfile>,
    #[serde(default)]
    pub keys: Vec<VaultKeyMeta>,
    #[serde(default)]
    pub mitm_cas: Vec<VaultCaMeta>,
    /// Port forward templates, shared by every session.
    #[serde(default)]
    pub forward_presets: Vec<ForwardPreset>,
    /// Set once the built-in presets were added, so deleting one is not undone on next start.
    #[serde(default)]
    pub forward_presets_seeded: bool,
    /// v2 SSH tunnels (U2). Empty in v1 documents.
    #[serde(default)]
    pub tunnels: Vec<crate::v2_model::Tunnel>,
    /// v2 proxies (U2). Empty in v1 documents.
    #[serde(default)]
    pub proxies: Vec<crate::v2_model::Proxy>,
    /// Shared upstream profiles any Proxy can reference.
    #[serde(default)]
    pub profile_library: Vec<crate::v2_model::UpstreamProfile>,
}

impl AppConfig {
    /// Adds the built-in presets on first use. Returns whether anything changed.
    pub fn seed_forward_presets(&mut self) -> bool {
        if self.forward_presets_seeded {
            return false;
        }
        self.forward_presets_seeded = true;
        self.restore_forward_presets();
        true
    }

    /// Adds back every built-in preset whose id is missing, keeping the user's own. Returns how
    /// many were added.
    pub fn restore_forward_presets(&mut self) -> usize {
        let missing: Vec<ForwardPreset> = builtin_forward_presets()
            .into_iter()
            .filter(|b| !self.forward_presets.iter().any(|p| p.id == b.id))
            .collect();
        let added = missing.len();
        self.forward_presets.extend(missing);
        added
    }
}

/// Composite key for an app-owned known_hosts entry: a specific hop, host, and port.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct HostKeyLookup {
    pub hop_id: String,
    pub host: String,
    pub port: u16,
}

/// One app-owned known_hosts record. Never touches `~/.ssh/known_hosts`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostKeyRecord {
    pub algorithm: String,
    pub fingerprint_sha256: String,
    #[serde(default)]
    pub first_seen: Timestamp,
    pub approved: bool,
    /// `<algorithm> <base64>`, for rendering an OpenSSH `known_hosts` line. Absent on pins
    /// recorded before this field existed.
    #[serde(default)]
    pub public_key_openssh: Option<String>,
}

/// One app-owned known_hosts entry: the `(hop_id, host, port)` key and its record.
///
/// Stored as a JSON array rather than a map because `serde_json` cannot use a struct as a
/// map key; lookups are provided by [`KnownHostsStore::get`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostKeyEntry {
    pub key: HostKeyLookup,
    pub record: HostKeyRecord,
}

/// App-owned known_hosts, keyed by `(hop_id, host, port)`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct KnownHostsStore {
    #[serde(default)]
    pub entries: Vec<HostKeyEntry>,
}

impl KnownHostsStore {
    /// Look up a record by `(hop_id, host, port)`.
    pub fn get(&self, hop_id: &str, host: &str, port: u16) -> Option<&HostKeyRecord> {
        self.entries
            .iter()
            .find(|e| e.key.hop_id == hop_id && e.key.host == host && e.key.port == port)
            .map(|e| &e.record)
    }

    /// Whether an entry exists for `(hop_id, host, port)`.
    pub fn contains_key(&self, hop_id: &str, host: &str, port: u16) -> bool {
        self.get(hop_id, host, port).is_some()
    }

    /// Insert or overwrite the record for `(hop_id, host, port)`.
    pub fn insert(&mut self, key: HostKeyLookup, record: HostKeyRecord) {
        match self.entries.iter_mut().find(|e| e.key == key) {
            Some(e) => e.record = record,
            None => self.entries.push(HostKeyEntry { key, record }),
        }
    }
}

fn default_host_port() -> u16 {
    22
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_enabled_is_inferred_from_ports_when_absent() {
        let forward: ForwardConfig =
            serde_json::from_str(r#"{"http_port": 0, "socks_port": 0}"#).unwrap();
        assert!(!forward.enabled);
        let forward: ForwardConfig = serde_json::from_str(r#"{"http_port": 3128}"#).unwrap();
        assert!(forward.enabled);
        // Missing ports take their defaults, which are on.
        assert!(serde_json::from_str::<ForwardConfig>("{}").unwrap().enabled);

        let reverse: ReverseConfig = serde_json::from_str("{}").unwrap();
        assert!(!reverse.enabled);
        let reverse: ReverseConfig =
            serde_json::from_str(r#"{"reverse_socks_port": 1081}"#).unwrap();
        assert!(reverse.enabled);
    }

    #[test]
    fn proxy_enabled_round_trips_and_keeps_ports_while_off() {
        let forward = ForwardConfig { enabled: false, ..ForwardConfig::default() };
        let json = serde_json::to_string(&forward).unwrap();
        let back: ForwardConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, forward);
        assert_eq!(back.http_port, 3128);
        assert_eq!(back.effective_ports(), (0, 0));

        let reverse = ReverseConfig {
            enabled: true,
            reverse_http_port: 8888,
            ..ReverseConfig::default()
        };
        let json = serde_json::to_string(&reverse).unwrap();
        assert_eq!(serde_json::from_str::<ReverseConfig>(&json).unwrap(), reverse);
        assert_eq!(reverse.effective_ports(), (8888, 0));
    }

    #[test]
    fn host_key_record_without_public_key_deserializes() {
        let json = r#"{
            "algorithm": "ssh-ed25519",
            "fingerprint_sha256": "SHA256:abc",
            "first_seen": 1,
            "approved": true
        }"#;
        let record: HostKeyRecord = serde_json::from_str(json).unwrap();
        assert!(record.approved);
        assert_eq!(record.public_key_openssh, None);
    }

    #[test]
    fn host_key_record_public_key_round_trips() {
        let record = HostKeyRecord {
            algorithm: "ssh-ed25519".into(),
            fingerprint_sha256: "SHA256:abc".into(),
            first_seen: Timestamp(1),
            approved: true,
            public_key_openssh: Some("ssh-ed25519 AAAAtest".into()),
        };
        let json = serde_json::to_string(&record).unwrap();
        assert_eq!(serde_json::from_str::<HostKeyRecord>(&json).unwrap(), record);
    }

    #[test]
    fn mitm_saved_with_ca_file_paths_loads_without_a_ca() {
        let json = r#"{
            "ca_mode": { "Pkcs12": { "path": "/home/u/ca.p12" } },
            "passphrase": "00000000-0000-0000-0000-000000000001",
            "ca_passphrase_file": null,
            "cert_ttl": 3600,
            "cert_cache_max_entries": 50,
            "socks_block_web": true
        }"#;
        let mitm: MitmConfig = serde_json::from_str(json).unwrap();
        assert_eq!(mitm.ca, None);
        assert_eq!((mitm.cert_ttl.as_secs(), mitm.socks_block_web), (3600, true));
        let saved = serde_json::to_string(&mitm).unwrap();
        assert!(!saved.contains("ca_mode") && !saved.contains("passphrase"), "{saved}");
    }

    #[test]
    fn hop_entry_saved_with_agent_forwarding_still_loads_and_drops_it() {
        let json = r#"{
            "hop_id": "target",
            "name": "target",
            "host": { "name": "h", "host": "10.0.0.1", "user": "root", "auth": [] },
            "agent_forward": true,
            "agent_forward_keys": ["00000000-0000-0000-0000-000000000001"],
            "agent_forward_command": "sleep infinity"
        }"#;
        let hop: HopEntry = serde_json::from_str(json).unwrap();
        assert_eq!(hop.hop_id, "target");
        let saved = serde_json::to_string(&hop).unwrap();
        assert!(!saved.contains("agent_forward"), "{saved}");
    }

    #[test]
    fn v1_app_config_loads_with_empty_v2_collections() {
        let json = r#"{
            "schema_version": 1,
            "sessions": [{
                "name": "legacy",
                "hops": [],
                "forward": { "enabled": true, "http_port": 3128, "socks_port": 1080 },
                "reverse": {}
            }],
            "hosts": [],
            "keys": [],
            "mitm_cas": [],
            "forward_presets": [],
            "forward_presets_seeded": true
        }"#;
        let config: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.sessions.len(), 1);
        assert_eq!(config.sessions[0].name, "legacy");
        assert!(config.tunnels.is_empty());
        assert!(config.proxies.is_empty());
        assert!(config.profile_library.is_empty());
        let reloaded: AppConfig =
            serde_json::from_str(&serde_json::to_string(&config).unwrap()).unwrap();
        assert_eq!(reloaded, config);
    }
}
