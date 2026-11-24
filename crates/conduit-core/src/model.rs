//! `conduit-core` — UI-agnostic data models.
//!
//! Every session, host, and vault data model lives here so future UI shells
//! (Tauri v2 + Svelte 5) stay thin adapters. Filter rules, the SSH IP version, and the log
//! settings are stored as human-friendly strings and parsed/validated in `validate` and
//! `mapping`; this keeps the `rusty-conduit-ssh` types that lack `serde` (`FilterRule`,
//! `SshIpVersion`, `LogLevel`, `LogFormat`) from needing any upstream change.

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
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HopEntry {
    pub hop_id: String,
    pub name: String,
    pub host: HostProfile,
    #[serde(default)]
    pub agent_forward: bool,
    /// Vault keys exposed to this hop when `agent_forward` is on. Nothing else is ever exposed.
    #[serde(default)]
    pub agent_forward_keys: Vec<KeyId>,
    /// Optional command run on this hop's agent-forwarding session channel.
    #[serde(default)]
    pub agent_forward_command: Option<String>,
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
pub struct ForwardConfig {
    #[serde(default = "default_bind")]
    pub bind: IpAddr,
    #[serde(default = "default_http_port")]
    pub http_port: u16,
    #[serde(default = "default_socks_port")]
    pub socks_port: u16,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Destination allowlist rules in `rusty-conduit-ssh` filter syntax.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Destination blocklist rules in `rusty-conduit-ssh` filter syntax.
    #[serde(default)]
    pub block: Vec<String>,
}

impl Default for ForwardConfig {
    fn default() -> Self {
        Self {
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
pub struct ReverseConfig {
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
            reverse_bind: default_reverse_bind(),
            reverse_http_port: 0,
            reverse_socks_port: 0,
            reverse_max_connections: None,
            reverse_allow: Vec::new(),
            reverse_block: Vec::new(),
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

/// Where the MITM CA certificate comes from. Mutually exclusive by construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MitmCaMode {
    /// PEM certificate + key pair.
    Pem { cert: PathBuf, key: PathBuf },
    /// Single PKCS#12 bundle.
    Pkcs12 { path: PathBuf },
}

/// HTTPS MITM inspection configuration. `None` disables MITM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MitmConfig {
    pub ca_mode: MitmCaMode,
    /// Opaque reference to the encrypted CA passphrase in `vault.bin` (resolved at runtime).
    pub passphrase: Option<SecretRef>,
    #[serde(default)]
    pub ca_passphrase_file: Option<PathBuf>,
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
            // A placeholder mode; `ca_mode` is always set explicitly in production since the
            // session-level `mitm: Option<MitmConfig>` is `None` when MITM is disabled.
            ca_mode: MitmCaMode::Pkcs12 {
                path: PathBuf::new(),
            },
            passphrase: None,
            ca_passphrase_file: None,
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
            mitm: None,
            tunnel: TunnelConfig::default(),
            logging: LoggingConfig::default(),
            openssh: OpenSshOptions::default(),
        }
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
    fn hop_entry_without_agent_forward_fields_deserializes() {
        let json = r#"{
            "hop_id": "target",
            "name": "target",
            "host": { "name": "h", "host": "10.0.0.1", "user": "root", "auth": [] },
            "agent_forward": true
        }"#;
        let hop: HopEntry = serde_json::from_str(json).unwrap();
        assert!(hop.agent_forward);
        assert!(hop.agent_forward_keys.is_empty());
        assert_eq!(hop.agent_forward_command, None);
    }
}
