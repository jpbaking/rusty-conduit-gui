//! `conduit-core` — import and export of the three CLIs' `config.toml` files.
//!
//! The file shapes mirror each CLI's `FileConfig`
//! (unknown keys are rejected, as the CLIs do):
//!
//! | CLI | Import | Export |
//! | :--- | :--- | :--- |
//! | `rusty-conduit` | [`Proxy`] (direct) | Proxies with no rules that only go `direct` |
//! | `rusty-conduit-ssh` | [`Tunnel`] + [`Proxy`] routed to it | Proxies routing only to one Tunnel |
//! | `rusty-conduit-switch` | [`Proxy`]; inline passwords → [`ExtractedSecret`] | Any Proxy |
//!
//! Secrets are never written. A vaulted upstream password is exported as
//! `password_env = "CONDUIT_UPSTREAM_<PROFILE>_PASSWORD"`; vault keys, SSH passwords, and jump
//! hosts are listed as `~/.ssh/config` setup notes; MITM CAs (kept in the Vault) are listed as
//! notes too. Imported inline passwords never stay in the [`Proxy`].

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::airswitch_import::ExtractedSecret;
use crate::model::{
    AuthMethod, ForwardProxyProtocol, HopEntry, HostProfile, LoggingConfig, MitmConfig,
    MitmUpstreamTlsMode, OpenSshOptions, ReverseConfig, TunnelConfig,
};
use crate::v2_model::{
    GlobalFilterConfig, ListenerConfig, NetworkConfig, Proxy, RouteOneOrMany, RouteTarget,
    RoutingTablesConfig, TargetRef, Tunnel, TunnelId, UpstreamKind, UpstreamPasswordSource,
    UpstreamProfile,
};

const DIRECT: &str = "direct";
const BLOCK: &str = "block";
/// Name of the Tunnel profile an imported `rusty-conduit-ssh` Proxy routes to.
const SSH_TUNNEL_PROFILE: &str = "tunnel";

/// Which CLI a `config.toml` belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CliTomlFormat {
    RustyConduit,
    RustyConduitSsh,
    RustyConduitSwitch,
}

impl CliTomlFormat {
    /// The CLI's binary name.
    pub fn cli_name(self) -> &'static str {
        match self {
            Self::RustyConduit => "rusty-conduit",
            Self::RustyConduitSsh => "rusty-conduit-ssh",
            Self::RustyConduitSwitch => "rusty-conduit-switch",
        }
    }
}

/// Guess which CLI a `config.toml` is for from its keys: `[ssh]` / `[reverse]` mean
/// `rusty-conduit-ssh`; `[profiles]`, `[routing]`, `[filter]`, `[tcp_keepalive]`,
/// `connect_timeout`, or `watch_*` mean `rusty-conduit-switch`; anything else (including text
/// that does not parse) is `rusty-conduit`.
pub fn detect_cli_toml_format(toml_str: &str) -> CliTomlFormat {
    let Ok(table) = toml_str.parse::<toml::Table>() else {
        return CliTomlFormat::RustyConduit;
    };
    if table.contains_key("ssh") || table.contains_key("reverse") {
        return CliTomlFormat::RustyConduitSsh;
    }
    let switch_keys = ["profiles", "routing", "filter", "connect_timeout", "watch_config", "watch_debounce"];
    let switch_mitm = table
        .get("mitm")
        .and_then(toml::Value::as_table)
        .is_some_and(|m| m.contains_key("cert_cache_max"));
    if switch_keys.iter().any(|k| table.contains_key(*k))
        || table.get("tcp_keepalive").is_some_and(toml::Value::is_table)
        || switch_mitm
    {
        return CliTomlFormat::RustyConduitSwitch;
    }
    CliTomlFormat::RustyConduit
}

/// Errors that stop a TOML import.
#[derive(Debug, Error)]
pub enum TomlImportError {
    #[error("not a valid {cli} config.toml: {message}")]
    Parse { cli: &'static str, message: String },
    #[error("invalid {cli} config.toml: {message}")]
    Invalid { cli: &'static str, message: String },
    #[error("invalid rusty-conduit-ssh config.toml: `[ssh] target` is required")]
    MissingSshTarget,
}

/// Errors that stop a TOML export.
#[derive(Debug, Error)]
pub enum TomlExportError {
    #[error("this Proxy cannot be exported as a {cli} config.toml: {reason}")]
    Unsupported { cli: &'static str, reason: String },
    #[error("could not write the config.toml: {0}")]
    Serialize(String),
}

/// A `rusty-conduit` import: one direct Proxy.
#[derive(Debug, Clone)]
pub struct ConduitTomlImport {
    pub proxy: Proxy,
    pub warnings: Vec<String>,
}

/// A `rusty-conduit-ssh` import: the Tunnel, plus a Proxy routed to it when the file has
/// forward listeners.
#[derive(Debug, Clone)]
pub struct SshTomlImport {
    pub tunnel: Tunnel,
    /// Routes everything to the profile `tunnel`, which points at [`SshTomlImport::tunnel`].
    pub proxy: Option<Proxy>,
    /// What must be completed by hand (hops, auth, `~/.ssh/config` settings).
    pub notes: Vec<String>,
    pub warnings: Vec<String>,
}

/// A `rusty-conduit-switch` import: a Proxy plus the inline passwords taken out of it.
#[derive(Debug, Clone)]
pub struct SwitchTomlImport {
    pub proxy: Proxy,
    /// Inline `password` values, for the Vault. Never left in `proxy`.
    pub extracted_secrets: Vec<ExtractedSecret>,
    pub warnings: Vec<String>,
}

/// The result of [`import_cli_toml`].
#[derive(Debug, Clone)]
pub enum CliTomlImport {
    RustyConduit(Box<ConduitTomlImport>),
    RustyConduitSsh(Box<SshTomlImport>),
    RustyConduitSwitch(Box<SwitchTomlImport>),
}

/// An exported `config.toml` and the setup notes for what could not be written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TomlExport {
    pub toml: String,
    pub notes: Vec<String>,
}

// ---------------------------------------------------------------------------
// File shapes (each CLI's `FileConfig`).
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MitmFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ca_cert: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ca_key: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ca_p12: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ca_passphrase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ca_passphrase_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cert_ttl: Option<String>,
    /// Every CLI writes `cert_cache_max_entries`; `cert_cache_max` is `-switch`'s deprecated
    /// name, still read on import.
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "cert_cache_max")]
    cert_cache_max_entries: Option<usize>,
    /// Upstream hosts (domain, `*.domain`, IP, or CIDR) whose certificates are not verified.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    insecure_hosts: Vec<String>,
    /// Hosts (domain, `*.domain`, IP, or CIDR) that are never intercepted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    bypass_hosts: Vec<String>,
    /// Blind trust: no upstream certificate is verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    insecure: Option<bool>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LoggingFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    http_access_log: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    socks_log: Option<PathBuf>,
}

/// `rusty-conduit` `config.toml`.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConduitFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bind: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    http_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    socks_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_connections: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tcp_keepalive: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tcp_keepalive_interval: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tcp_keepalive_retries: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allow: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    block: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    socks_block_web: Option<bool>,
    /// Custom error page template; accepted on import, never written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error_page: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mitm: Option<MitmFile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    logging: Option<LoggingFile>,
}

/// `ip_version = 4`, `"4"`, or `"auto"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum IpVersionValue {
    Int(i64),
    Str(String),
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SshSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bin: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    socks_bind: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    socks_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ip_version: Option<IpVersionValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    config: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    jump: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    server_alive_interval: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    server_alive_count_max: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    no_reconnect: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reconnect_initial_delay: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reconnect_max_delay: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    startup_timeout: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    extra_args: Option<Vec<String>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReverseSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bind: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    http_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    socks_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_connections: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allow: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    block: Option<Vec<String>>,
}

/// `rusty-conduit-ssh` `config.toml`.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SshFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bind: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    http_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    socks_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_connections: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tcp_keepalive: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tcp_keepalive_interval: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tcp_keepalive_retries: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allow: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    block: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    socks_block_web: Option<bool>,
    /// Custom error page template; accepted on import, never written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error_page: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ssh: Option<SshSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reverse: Option<ReverseSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mitm: Option<MitmFile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    logging: Option<LoggingFile>,
}

/// `tcp_keepalive` in a `-switch` file: a duration (current) or the deprecated
/// `[tcp_keepalive]` table with `idle`, `interval`, and `retries`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum SwitchKeepaliveField {
    Idle(String),
    Table(SwitchKeepalive),
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SwitchKeepalive {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    idle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    interval: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retries: Option<u32>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SwitchFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allow: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    block: Option<Vec<String>>,
}

/// One `[profiles.<name>]` table (engine `ProfileConfig`).
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SwitchProfileFile {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    password_env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    password_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    bypass: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    tls_insecure_skip_verify: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    http_proxy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    https_proxy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fallback_proxy: Option<String>,
}

impl std::fmt::Debug for SwitchProfileFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SwitchProfileFile")
            .field("kind", &self.kind)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

/// `rusty-conduit-switch` `config.toml`.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SwitchFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bind: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    http_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    socks_block_web: Option<bool>,
    /// Custom error page template; accepted on import, never written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error_page: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    socks_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    watch_config: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    watch_debounce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    connect_timeout: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_connections: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tcp_keepalive: Option<SwitchKeepaliveField>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tcp_keepalive_interval: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tcp_keepalive_retries: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allow: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    block: Option<Vec<String>>,
    /// Deprecated `[filter]` table; read on import, never written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    filter: Option<SwitchFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mitm: Option<MitmFile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    logging: Option<LoggingFile>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    profiles: BTreeMap<String, SwitchProfileFile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    routing: Option<RoutingTablesConfig>,
}

// ---------------------------------------------------------------------------
// Shared helpers.
// ---------------------------------------------------------------------------

fn parse_file<T: for<'de> Deserialize<'de>>(
    cli: &'static str,
    toml_str: &str,
) -> Result<T, TomlImportError> {
    toml::from_str(toml_str)
        .map_err(|e| TomlImportError::Parse { cli, message: e.to_string().trim().to_string() })
}

fn parse_duration(cli: &'static str, field: &str, value: &str) -> Result<Duration, TomlImportError> {
    let v = value.trim();
    if v == "0" {
        return Ok(Duration::ZERO);
    }
    humantime::parse_duration(v).map_err(|e| TomlImportError::Invalid {
        cli,
        message: format!("`{field}` = {value:?} is not a duration ({e})"),
    })
}

fn opt_duration(
    cli: &'static str,
    field: &str,
    value: &Option<String>,
    default: Duration,
) -> Result<Duration, TomlImportError> {
    match value {
        Some(v) => parse_duration(cli, field, v),
        None => Ok(default),
    }
}

fn format_duration(d: Duration) -> String {
    humantime::format_duration(d).to_string()
}

fn filter_of(
    _cli: &'static str,
    allow: Option<Vec<String>>,
    block: Option<Vec<String>>,
) -> Result<GlobalFilterConfig, TomlImportError> {
    let allow = allow.filter(|a| !a.is_empty());
    let block = block.filter(|b| !b.is_empty());
    match (allow, block) {
        (Some(allow), Some(block)) => Ok(GlobalFilterConfig::BlockExcept { block, allow }),
        (Some(a), None) => Ok(GlobalFilterConfig::Allow(a)),
        (None, Some(b)) => Ok(GlobalFilterConfig::Block(b)),
        (None, None) => Ok(GlobalFilterConfig::Off),
    }
}

fn filter_to_file(filter: &GlobalFilterConfig) -> (Option<Vec<String>>, Option<Vec<String>>) {
    match filter {
        GlobalFilterConfig::Off => (None, None),
        GlobalFilterConfig::Allow(a) => (Some(a.clone()), None),
        GlobalFilterConfig::Block(b) => (None, Some(b.clone())),
        GlobalFilterConfig::BlockExcept { block, allow } => {
            (Some(allow.clone()), Some(block.clone()))
        }
    }
}

fn logging_of(file: Option<LoggingFile>) -> LoggingConfig {
    let file = file.unwrap_or_default();
    let defaults = LoggingConfig::default();
    LoggingConfig {
        level: file.level.unwrap_or(defaults.level),
        format: file.format.unwrap_or(defaults.format),
        http_access_log: file.http_access_log,
        socks_log: file.socks_log,
    }
}

fn logging_to_file(logging: &LoggingConfig) -> LoggingFile {
    LoggingFile {
        level: Some(logging.level.clone()),
        format: Some(logging.format.clone()),
        http_access_log: logging.http_access_log.clone(),
        socks_log: logging.socks_log.clone(),
    }
}

/// Read a `[mitm]` table. The app keeps MITM CAs in the Vault, so a CA file cannot be
/// imported: MITM is left off and the settings are listed in `warnings`.
fn mitm_of(file: Option<MitmFile>, warnings: &mut Vec<String>) -> Option<MitmConfig> {
    let m = file?;
    if m.ca_passphrase.is_some() {
        warnings.push(
            "[mitm] ca_passphrase was not imported: passphrases are never stored outside the \
             Vault"
                .into(),
        );
    }
    let ca = [&m.ca_cert, &m.ca_key, &m.ca_p12]
        .into_iter()
        .flatten()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>();
    if !ca.is_empty() {
        warnings.push(format!(
            "[mitm] was not turned on: upload the CA ({}) in the Vault, then choose it in the \
             HTTPS MITM tab",
            ca.join(", ")
        ));
    }
    match upstream_tls_of(&m) {
        (MitmUpstreamTlsMode::Strict, _) => {}
        (MitmUpstreamTlsMode::InsecureAll, _) => warnings.push(
            "[mitm] insecure = true (blind trust) was not applied because MITM is off: choose \
             \"Blind trust\" under Upstream TLS certificates in the HTTPS MITM tab if you need it"
                .into(),
        ),
        (MitmUpstreamTlsMode::Allowlist, hosts) => warnings.push(format!(
            "[mitm] insecure_hosts ({}) was not applied because MITM is off: choose \
             \"Allowlist\" under Upstream TLS certificates in the HTTPS MITM tab and list them",
            hosts.join(", ")
        )),
    }
    if !m.bypass_hosts.is_empty() {
        warnings.push(format!(
            "[mitm] bypass_hosts ({}) was not applied because MITM is off: list them under \
             \"Bypass MITM hosts\" in the HTTPS MITM tab after choosing a CA",
            m.bypass_hosts.join(", ")
        ));
    }
    None
}

/// The upstream TLS mode a `[mitm]` table asks for, as the CLIs read it: `insecure = true`
/// wins, then a non-empty `insecure_hosts`, else strict.
fn upstream_tls_of(m: &MitmFile) -> (MitmUpstreamTlsMode, Vec<String>) {
    if m.insecure == Some(true) {
        (MitmUpstreamTlsMode::InsecureAll, Vec::new())
    } else if !m.insecure_hosts.is_empty() {
        (MitmUpstreamTlsMode::Allowlist, m.insecure_hosts.clone())
    } else {
        (MitmUpstreamTlsMode::Strict, Vec::new())
    }
}

/// Write a `[mitm]` table for an exported Proxy, with the CA left for the user.
fn mitm_to_file(mitm: &MitmConfig, notes: &mut Vec<String>) -> MitmFile {
    notes.push(
        "MITM: the CA lives in the Vault and is not exported; export it as PEM and set \
         `ca_cert` and `ca_key` under [mitm]"
            .into(),
    );
    MitmFile {
        cert_ttl: Some(format_duration(mitm.cert_ttl)),
        cert_cache_max_entries: Some(mitm.cert_cache_max_entries),
        insecure_hosts: match mitm.upstream_tls_mode {
            MitmUpstreamTlsMode::Allowlist => mitm.insecure_hosts.clone(),
            _ => Vec::new(),
        },
        insecure: (mitm.upstream_tls_mode == MitmUpstreamTlsMode::InsecureAll).then_some(true),
        bypass_hosts: mitm.bypass_hosts.clone(),
        ..MitmFile::default()
    }
}

fn listeners_of(
    bind: Option<IpAddr>,
    http_port: Option<u16>,
    socks_port: Option<u16>,
    max_connections: Option<usize>,
) -> ListenerConfig {
    let d = ListenerConfig::default();
    ListenerConfig {
        bind: bind.unwrap_or(d.bind),
        http_port: http_port.unwrap_or(d.http_port),
        socks_port: socks_port.unwrap_or(d.socks_port),
        max_connections: max_connections.unwrap_or(d.max_connections),
    }
}

fn network_of(
    cli: &'static str,
    connect_timeout: &Option<String>,
    idle: &Option<String>,
    interval: &Option<String>,
    retries: Option<u32>,
) -> Result<NetworkConfig, TomlImportError> {
    let d = NetworkConfig::default();
    Ok(NetworkConfig {
        connect_timeout: opt_duration(cli, "connect_timeout", connect_timeout, d.connect_timeout)?,
        tcp_keepalive: opt_duration(cli, "tcp_keepalive", idle, d.tcp_keepalive)?,
        tcp_keepalive_interval: opt_duration(
            cli,
            "tcp_keepalive_interval",
            interval,
            d.tcp_keepalive_interval,
        )?,
        tcp_keepalive_retries: retries.unwrap_or(d.tcp_keepalive_retries),
    })
}

/// The app always serves its built-in error page, so an imported `error_page` is only reported.
fn warn_error_page(error_page: &Option<PathBuf>, warnings: &mut Vec<String>) {
    if let Some(path) = error_page {
        warnings.push(format!(
            "error_page {} was not imported: the app serves the built-in error page",
            path.display()
        ));
    }
}

fn header(cli: &str, proxy: &Proxy) -> String {
    format!(
        "# {cli} config.toml exported by Rusty Conduit from Proxy {:?}.\n\
         # Secrets are never written: see the setup notes at the end of this file.\n\n",
        proxy.name
    )
}

/// Append the notes to the TOML as comments.
fn finish(mut toml: String, notes: Vec<String>) -> TomlExport {
    if !notes.is_empty() {
        toml.push_str("\n# Setup notes:\n");
        for note in &notes {
            toml.push_str(&format!("# - {note}\n"));
        }
    }
    TomlExport { toml, notes }
}

fn to_toml<T: Serialize>(value: &T) -> Result<String, TomlExportError> {
    toml::to_string(value).map_err(|e| TomlExportError::Serialize(e.to_string()))
}

/// Whether the Proxy has any routing rule or split table.
fn has_rules(proxy: &Proxy) -> bool {
    let r = &proxy.routing;
    !r.rules.is_empty() || r.http.is_some() || r.socks.is_some()
}

fn only_target(target: &RouteTarget) -> Option<&str> {
    match target.as_slice() {
        [one] => Some(one.as_str()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// rusty-conduit
// ---------------------------------------------------------------------------

/// Import a `rusty-conduit` `config.toml` as a direct Proxy named `name`.
pub fn import_rusty_conduit_toml(
    toml_str: &str,
    name: &str,
) -> Result<ConduitTomlImport, TomlImportError> {
    const CLI: &str = "rusty-conduit";
    let f: ConduitFile = parse_file(CLI, toml_str)?;
    let mut warnings = Vec::new();
    warn_error_page(&f.error_page, &mut warnings);
    let socks_block_web = f.socks_block_web.unwrap_or(false);
    let proxy = Proxy {
        name: name.to_string(),
        listeners: listeners_of(f.bind, f.http_port, f.socks_port, f.max_connections),
        network: network_of(CLI, &None, &f.tcp_keepalive, &f.tcp_keepalive_interval, f.tcp_keepalive_retries)?,
        filter: filter_of(CLI, f.allow, f.block)?,
        socks_block_web,
        mitm: mitm_of(f.mitm, &mut warnings),
        logging: logging_of(f.logging),
        ..Proxy::default()
    };
    Ok(ConduitTomlImport { proxy, warnings })
}

/// Export a Proxy as a `rusty-conduit` `config.toml`. Only Proxies with no rules whose
/// default is `direct` can be exported; others need `rusty-conduit-switch`.
pub fn export_rusty_conduit_toml(proxy: &Proxy) -> Result<TomlExport, TomlExportError> {
    const CLI: &str = "rusty-conduit";
    let unsupported = |reason: String| TomlExportError::Unsupported { cli: CLI, reason };
    if has_rules(proxy) {
        return Err(unsupported(
            "it has routing rules, and rusty-conduit only connects directly; export it for \
             rusty-conduit-switch instead"
                .into(),
        ));
    }
    if only_target(&proxy.routing.default) != Some(DIRECT) {
        return Err(unsupported(format!(
            "its default target is {:?}, not `direct`, and rusty-conduit only connects \
             directly; export it for rusty-conduit-switch instead",
            proxy.routing.default.as_slice()
        )));
    }
    let mut notes = Vec::new();
    let (allow, block) = filter_to_file(&proxy.filter);
    let l = &proxy.listeners;
    let n = &proxy.network;
    let file = ConduitFile {
        bind: Some(l.bind),
        http_port: Some(l.http_port),
        socks_port: Some(l.socks_port),
        max_connections: Some(l.max_connections),
        tcp_keepalive: Some(format_duration(n.tcp_keepalive)),
        tcp_keepalive_interval: Some(format_duration(n.tcp_keepalive_interval)),
        tcp_keepalive_retries: Some(n.tcp_keepalive_retries),
        allow,
        block,
        socks_block_web: (proxy.socks_block_web
            || proxy.mitm.as_ref().is_some_and(|m| m.socks_block_web))
            .then_some(true),
        error_page: None,
        mitm: proxy.mitm.as_ref().map(|m| mitm_to_file(m, &mut notes)),
        logging: Some(logging_to_file(&proxy.logging)),
    };
    if n.connect_timeout != NetworkConfig::default().connect_timeout {
        notes.push(format!(
            "connect timeout {} is not configurable in rusty-conduit and was not exported",
            format_duration(n.connect_timeout)
        ));
    }
    let toml = header(CLI, proxy) + &to_toml(&file)?;
    Ok(finish(toml, notes))
}

// ---------------------------------------------------------------------------
// rusty-conduit-ssh
// ---------------------------------------------------------------------------

/// Split an `ssh` destination (`host`, `user@host`, or `ssh://user@host:port`).
fn split_destination(target: &str) -> (String, String, Option<u16>) {
    let t = target.trim();
    if let Some(rest) = t.strip_prefix("ssh://") {
        let (user, hostport) = match rest.rsplit_once('@') {
            Some((u, h)) => (u.to_string(), h),
            None => (String::new(), rest),
        };
        let hostport = hostport.trim_end_matches('/');
        if let Some(inner) = hostport.strip_prefix('[') {
            if let Some((host, after)) = inner.split_once(']') {
                let port = after.strip_prefix(':').and_then(|p| p.parse().ok());
                return (user, host.to_string(), port);
            }
        }
        return match hostport.rsplit_once(':') {
            Some((h, p)) if p.parse::<u16>().is_ok() => (user, h.to_string(), p.parse().ok()),
            _ => (user, hostport.to_string(), None),
        };
    }
    match t.rsplit_once('@') {
        Some((u, h)) => (u.to_string(), h.to_string(), None),
        None => (String::new(), t.to_string(), None),
    }
}

fn ip_version_of(v: &Option<IpVersionValue>) -> Result<String, TomlImportError> {
    let s = match v {
        None => return Ok(TunnelConfig::default().ip_version),
        Some(IpVersionValue::Int(i)) => i.to_string(),
        Some(IpVersionValue::Str(s)) => s.trim().to_ascii_lowercase(),
    };
    match s.as_str() {
        "4" | "6" | "auto" => Ok(s),
        _ => Err(TomlImportError::Invalid {
            cli: "rusty-conduit-ssh",
            message: format!("`[ssh] ip_version` = {s:?} (expected 4, 6, or \"auto\")"),
        }),
    }
}

/// Import a `rusty-conduit-ssh` `config.toml` as a Tunnel named `name` plus, when forward
/// listeners are on, a Proxy of the same name routed to it.
///
/// The CLI's destination may be a `~/.ssh/config` alias, which the app never reads, so the
/// Tunnel gets one placeholder hop and [`SshTomlImport::notes`] lists what to complete.
pub fn import_rusty_conduit_ssh_toml(
    toml_str: &str,
    name: &str,
) -> Result<SshTomlImport, TomlImportError> {
    const CLI: &str = "rusty-conduit-ssh";
    let f: SshFile = parse_file(CLI, toml_str)?;
    let mut warnings = Vec::new();
    warn_error_page(&f.error_page, &mut warnings);
    let mut notes = vec![
        "The SSH destination may be a ~/.ssh/config alias, which the app does not read: check \
         the hop's host, port, and user, and add its authentication (key or password) by hand"
            .to_string(),
    ];
    let ssh = f.ssh.unwrap_or_default();
    let target = ssh
        .target
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or(TomlImportError::MissingSshTarget)?;
    let (user, host, url_port) = split_destination(target);
    if user.is_empty() {
        notes.push(format!("No user in destination {target:?}: set the hop's user"));
    }
    if let Some(identity) = &ssh.identity {
        notes.push(format!(
            "Identity file {}: import the key into the Vault and add it to the hop's \
             authentication",
            identity.display()
        ));
    }
    if let Some(config) = &ssh.config {
        notes.push(format!(
            "ssh config file {} is not read: copy any settings it holds into the Tunnel",
            config.display()
        ));
    }
    if let Some(jump) = ssh.jump.as_deref().filter(|j| !j.trim().is_empty()) {
        notes.push(format!(
            "Jump hosts {jump:?}: add each as a hop before the target in the jump chain"
        ));
    }
    let hop_name = if host.is_empty() { target.to_string() } else { host.clone() };
    let hop = HopEntry {
        hop_id: Uuid::new_v4().to_string(),
        name: hop_name.clone(),
        host: HostProfile {
            name: hop_name,
            host,
            port: ssh.port.or(url_port).unwrap_or(22),
            user,
            ..HostProfile::default()
        },
    };

    let td = TunnelConfig::default();
    let keepalive = TunnelConfig {
        ip_version: ip_version_of(&ssh.ip_version)?,
        server_alive_interval: opt_duration(
            CLI,
            "server_alive_interval",
            &ssh.server_alive_interval,
            td.server_alive_interval,
        )?,
        server_alive_count_max: ssh.server_alive_count_max.unwrap_or(td.server_alive_count_max),
        tcp_keepalive: opt_duration(CLI, "tcp_keepalive", &f.tcp_keepalive, td.tcp_keepalive)?,
        tcp_keepalive_interval: opt_duration(
            CLI,
            "tcp_keepalive_interval",
            &f.tcp_keepalive_interval,
            td.tcp_keepalive_interval,
        )?,
        tcp_keepalive_retries: f.tcp_keepalive_retries.unwrap_or(td.tcp_keepalive_retries),
        no_reconnect: ssh.no_reconnect.unwrap_or(td.no_reconnect),
        reconnect_initial_delay: opt_duration(
            CLI,
            "reconnect_initial_delay",
            &ssh.reconnect_initial_delay,
            td.reconnect_initial_delay,
        )?,
        reconnect_max_delay: opt_duration(
            CLI,
            "reconnect_max_delay",
            &ssh.reconnect_max_delay,
            td.reconnect_max_delay,
        )?,
        startup_timeout: opt_duration(CLI, "startup_timeout", &ssh.startup_timeout, td.startup_timeout)?,
    };

    let r = f.reverse.unwrap_or_default();
    let rd = ReverseConfig::default();
    let (http, socks) = (r.http_port.unwrap_or(0), r.socks_port.unwrap_or(0));
    let reverse = ReverseConfig {
        enabled: http != 0 || socks != 0,
        reverse_bind: r.bind.unwrap_or(rd.reverse_bind),
        reverse_http_port: http,
        reverse_socks_port: socks,
        reverse_max_connections: r.max_connections,
        reverse_allow: r.allow.unwrap_or_default(),
        reverse_block: r.block.unwrap_or_default(),
    };

    let od = OpenSshOptions::default();
    let openssh = OpenSshOptions {
        ssh_bin: ssh.bin.map(|b| b.display().to_string()).unwrap_or(od.ssh_bin),
        ssh_socks_bind: ssh.socks_bind.unwrap_or(od.ssh_socks_bind),
        ssh_socks_port: ssh.socks_port.unwrap_or(od.ssh_socks_port),
        extra_args: ssh.extra_args.unwrap_or_default(),
    };
    if !openssh.extra_args.is_empty() {
        notes.push(
            "extra ssh arguments were kept for the OpenSSH engine; the default engine ignores \
             them"
                .into(),
        );
    }

    let logging = logging_of(f.logging);
    let tunnel = Tunnel {
        id: TunnelId::new(),
        name: name.to_string(),
        hops: vec![hop],
        reverse,
        keepalive,
        logging: logging.clone(),
        openssh,
        ..Tunnel::default()
    };

    let listeners = listeners_of(f.bind, f.http_port, f.socks_port, f.max_connections);
    let filter = filter_of(CLI, f.allow, f.block)?;
    let socks_block_web = f.socks_block_web.unwrap_or(false);
    let mitm = mitm_of(f.mitm, &mut warnings);
    let proxy = if listeners.http_port == 0 && listeners.socks_port == 0 {
        if !filter_is_off(&filter) || mitm.is_some() {
            warnings.push("forward listeners are off: the forward filter was not imported".into());
        }
        None
    } else {
        let network = NetworkConfig {
            tcp_keepalive: tunnel.keepalive.tcp_keepalive,
            tcp_keepalive_interval: tunnel.keepalive.tcp_keepalive_interval,
            tcp_keepalive_retries: tunnel.keepalive.tcp_keepalive_retries,
            ..NetworkConfig::default()
        };
        Some(Proxy {
            name: name.to_string(),
            listeners,
            network,
            profiles: vec![UpstreamProfile {
                name: SSH_TUNNEL_PROFILE.to_string(),
                kind: UpstreamKind::Tunnel { tunnel_id: tunnel.id },
                host: None,
                port: None,
                username: None,
                password: None,
                bypass: Vec::new(),
                color: None,
            }],
            routing: RoutingTablesConfig {
                default: RouteOneOrMany::One(SSH_TUNNEL_PROFILE.to_string()),
                ..RoutingTablesConfig::default()
            },
            filter,
            socks_block_web,
            mitm,
            logging,
            ..Proxy::default()
        })
    };
    Ok(SshTomlImport { tunnel, proxy, notes, warnings })
}

fn filter_is_off(filter: &GlobalFilterConfig) -> bool {
    matches!(filter, GlobalFilterConfig::Off)
}

/// `user@host` for a hop (just `host` with no user).
fn destination_of(host: &HostProfile) -> String {
    if host.user.trim().is_empty() {
        host.host.clone()
    } else {
        format!("{}@{}", host.user, host.host)
    }
}

fn hop_label(h: &HostProfile) -> String {
    format!("{}:{}", destination_of(h), h.port)
}

/// Export a Proxy that routes only to one Tunnel as a `rusty-conduit-ssh` `config.toml`. The
/// Tunnel's target hop becomes the destination. Vault keys, passwords, jump hosts, and port
/// forwards cannot be written and are returned as `~/.ssh/config` setup notes.
pub fn export_rusty_conduit_ssh_toml(
    proxy: &Proxy,
    tunnels: &[Tunnel],
) -> Result<TomlExport, TomlExportError> {
    const CLI: &str = "rusty-conduit-ssh";
    let unsupported = |reason: String| TomlExportError::Unsupported { cli: CLI, reason };
    if has_rules(proxy) {
        return Err(unsupported(
            "it has routing rules; rusty-conduit-ssh sends everything through one tunnel. \
             Export it for rusty-conduit-switch instead"
                .into(),
        ));
    }
    // A v2 Proxy routes to `@tunnel:<id>`; an older one to a legacy `tunnel` profile.
    let tunnel_id = only_target(&proxy.routing.default)
        .and_then(|t| match TargetRef::parse(t) {
            TargetRef::Tunnel(tunnel_id) => Some(tunnel_id),
            _ => proxy.profiles.iter().find(|p| p.name == t).and_then(|p| match p.kind {
                UpstreamKind::Tunnel { tunnel_id } => Some(tunnel_id),
                _ => None,
            }),
        })
        .ok_or_else(|| {
            unsupported(
                "its default target is not a single `tunnel` profile or `@tunnel:` target; \
                 rusty-conduit-ssh sends everything through one tunnel"
                    .into(),
            )
        })?;
    let tunnel = tunnels
        .iter()
        .find(|t| t.id == tunnel_id)
        .ok_or_else(|| unsupported(format!("its tunnel {tunnel_id} does not exist")))?;
    let (target, jumps) = tunnel
        .hops
        .split_last()
        .ok_or_else(|| unsupported(format!("tunnel {:?} has no SSH target", tunnel.name)))?;

    let mut notes = Vec::new();
    if !jumps.is_empty() {
        let chain: Vec<String> = jumps.iter().map(|h| hop_label(&h.host)).collect();
        notes.push(format!(
            "Jump hosts are not exported: add `ProxyJump {}` for {} in ~/.ssh/config",
            chain.join(","),
            target.host.host
        ));
    }
    for hop in &tunnel.hops {
        for auth in &hop.host.auth {
            let what = match auth {
                AuthMethod::Key { key } => format!(
                    "uses Vault key {}: export it to a file and add `IdentityFile <path>`",
                    key.as_uuid()
                ),
                AuthMethod::Password { .. } => {
                    "uses a Vault password: ssh will ask for it, or use a key instead".to_string()
                }
                AuthMethod::KeyboardInteractive { .. } => {
                    "uses keyboard-interactive login: ssh will prompt for it".to_string()
                }
                AuthMethod::SystemAgentOptIn => {
                    "uses the system SSH agent: make sure the agent holds its key".to_string()
                }
            };
            notes.push(format!("Host {} {what} in ~/.ssh/config", hop_label(&hop.host)));
        }
        if let Some(pin) = &hop.host.host_key_pin {
            notes.push(format!(
                "Host {} has a pinned {} host key (SHA256:{}): add it to ~/.ssh/known_hosts",
                hop_label(&hop.host),
                pin.algorithm,
                pin.fingerprint_sha256
            ));
        }
    }
    for fwd in tunnel.active_forwards() {
        let kind = match fwd.direction {
            crate::model::ForwardDirection::Local => "LocalForward",
            crate::model::ForwardDirection::Remote => "RemoteForward",
        };
        notes.push(format!(
            "Port forward {}: rusty-conduit-ssh has no port forwards; add `{kind} {} {}` in \
             ~/.ssh/config",
            fwd.spec(),
            fwd.listen(),
            fwd.destination()
        ));
    }

    let k = &tunnel.keepalive;
    let od = OpenSshOptions::default();
    let o = &tunnel.openssh;
    let ip_version = match k.ip_version.as_str() {
        "4" => IpVersionValue::Int(4),
        "6" => IpVersionValue::Int(6),
        other => IpVersionValue::Str(other.to_string()),
    };
    let ssh = SshSection {
        target: Some(destination_of(&target.host)),
        port: Some(target.host.port),
        bin: (o.ssh_bin != od.ssh_bin).then(|| PathBuf::from(&o.ssh_bin)),
        socks_bind: (o.ssh_socks_bind != od.ssh_socks_bind).then_some(o.ssh_socks_bind),
        socks_port: (o.ssh_socks_port != od.ssh_socks_port).then_some(o.ssh_socks_port),
        ip_version: Some(ip_version),
        server_alive_interval: Some(format_duration(k.server_alive_interval)),
        server_alive_count_max: Some(k.server_alive_count_max),
        no_reconnect: Some(k.no_reconnect),
        reconnect_initial_delay: Some(format_duration(k.reconnect_initial_delay)),
        reconnect_max_delay: Some(format_duration(k.reconnect_max_delay)),
        startup_timeout: Some(format_duration(k.startup_timeout)),
        extra_args: (!o.extra_args.is_empty()).then(|| o.extra_args.clone()),
        ..SshSection::default()
    };
    let r = &tunnel.reverse;
    let reverse = r.enabled.then(|| ReverseSection {
        bind: Some(r.reverse_bind),
        http_port: Some(r.reverse_http_port),
        socks_port: Some(r.reverse_socks_port),
        max_connections: r.reverse_max_connections,
        allow: (!r.reverse_allow.is_empty()).then(|| r.reverse_allow.clone()),
        block: (!r.reverse_block.is_empty()).then(|| r.reverse_block.clone()),
    });

    let (allow, block) = filter_to_file(&proxy.filter);
    let l = &proxy.listeners;
    let n = &proxy.network;
    let file = SshFile {
        bind: Some(l.bind),
        http_port: Some(l.http_port),
        socks_port: Some(l.socks_port),
        max_connections: Some(l.max_connections),
        tcp_keepalive: Some(format_duration(n.tcp_keepalive)),
        tcp_keepalive_interval: Some(format_duration(n.tcp_keepalive_interval)),
        tcp_keepalive_retries: Some(n.tcp_keepalive_retries),
        allow,
        block,
        socks_block_web: (proxy.socks_block_web
            || proxy.mitm.as_ref().is_some_and(|m| m.socks_block_web))
            .then_some(true),
        error_page: None,
        ssh: Some(ssh),
        reverse,
        mitm: proxy.mitm.as_ref().map(|m| mitm_to_file(m, &mut notes)),
        logging: Some(logging_to_file(&proxy.logging)),
    };
    let toml = header(CLI, proxy) + &to_toml(&file)?;
    Ok(finish(toml, notes))
}

// ---------------------------------------------------------------------------
// rusty-conduit-switch
// ---------------------------------------------------------------------------

/// The environment variable an exported vaulted password is read from.
pub fn upstream_password_env_var(profile: &str) -> String {
    let upper: String = profile
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' })
        .collect();
    format!("CONDUIT_UPSTREAM_{upper}_PASSWORD")
}

fn rewrite_target(target: &mut RouteTarget, aliases: &BTreeMap<String, String>) {
    let map = |s: &mut String| {
        if let Some(to) = aliases.get(s.as_str()) {
            *s = to.clone();
        }
    };
    match target {
        RouteOneOrMany::One(s) => map(s),
        RouteOneOrMany::Many(v) => v.iter_mut().for_each(map),
    }
}

fn rewrite_routing(routing: &mut RoutingTablesConfig, aliases: &BTreeMap<String, String>) {
    if aliases.is_empty() {
        return;
    }
    rewrite_target(&mut routing.default, aliases);
    for rule in &mut routing.rules {
        rewrite_target(&mut rule.target, aliases);
    }
    for table in [routing.http.as_mut(), routing.socks.as_mut()].into_iter().flatten() {
        if let Some(d) = table.default.as_mut() {
            rewrite_target(d, aliases);
        }
        for rule in &mut table.rules {
            rewrite_target(&mut rule.target, aliases);
        }
    }
}

/// Import a `rusty-conduit-switch` `config.toml` as a Proxy named `name`. Inline `password`
/// values are moved into [`SwitchTomlImport::extracted_secrets`]; `password_env` and
/// `password_file` are kept.
pub fn import_rusty_conduit_switch_toml(
    toml_str: &str,
    name: &str,
) -> Result<SwitchTomlImport, TomlImportError> {
    const CLI: &str = "rusty-conduit-switch";
    let invalid = |message: String| TomlImportError::Invalid { cli: CLI, message };
    let f: SwitchFile = parse_file(CLI, toml_str)?;
    let mut warnings = Vec::new();
    warn_error_page(&f.error_page, &mut warnings);
    if f.watch_config.is_some() || f.watch_debounce.is_some() {
        warnings.push(
            "`watch_config` / `watch_debounce` were ignored: use External TOML link mode to \
             follow a file"
                .into(),
        );
    }
    // Current top-level keys win over the deprecated tables, as in rusty-conduit-switch.
    let mut deprecated = Vec::new();
    let (idle, table_interval, table_retries) = match f.tcp_keepalive {
        Some(SwitchKeepaliveField::Idle(idle)) => (Some(idle), None, None),
        Some(SwitchKeepaliveField::Table(t)) => {
            deprecated.push("`[tcp_keepalive]`");
            (t.idle, t.interval, t.retries)
        }
        None => (None, None, None),
    };
    let interval = f.tcp_keepalive_interval.or(table_interval);
    let retries = f.tcp_keepalive_retries.or(table_retries);
    let network = network_of(CLI, &f.connect_timeout, &idle, &interval, retries)?;
    let legacy_filter = f.filter.unwrap_or_default();
    if legacy_filter.allow.is_some() || legacy_filter.block.is_some() {
        deprecated.push("`[filter]`");
    }
    let filter =
        filter_of(CLI, f.allow.or(legacy_filter.allow), f.block.or(legacy_filter.block))?;
    let socks_block_web = f.socks_block_web.unwrap_or(false);
    if switch_uses_cert_cache_max(toml_str) {
        deprecated.push("`mitm.cert_cache_max`");
    }
    if !deprecated.is_empty() {
        warnings.push(format!(
            "{} {} deprecated in rusty-conduit-switch; exports write the current names \
             (top-level tcp_keepalive, tcp_keepalive_interval, tcp_keepalive_retries, allow, \
             block, and mitm.cert_cache_max_entries)",
            deprecated.join(", "),
            if deprecated.len() == 1 { "is" } else { "are" },
        ));
    }
    let mitm = mitm_of(f.mitm, &mut warnings);

    let mut aliases = BTreeMap::new();
    let mut profiles = Vec::new();
    let mut secrets = Vec::new();
    for (key, mut p) in f.profiles {
        if key == DIRECT || key == BLOCK {
            return Err(invalid(format!("`{key}` is a built-in profile and cannot be redefined")));
        }
        let password = p.password.take().map(Zeroizing::new);
        let kind = match p.kind.to_ascii_lowercase().as_str() {
            "direct" | "block" => {
                let builtin = p.kind.to_ascii_lowercase();
                warnings.push(format!(
                    "profile `{key}` (type {builtin}) was replaced by the built-in `{builtin}`"
                ));
                aliases.insert(key, builtin);
                continue;
            }
            "http" => UpstreamKind::Http,
            "https" => UpstreamKind::Https { tls_insecure_skip_verify: p.tls_insecure_skip_verify },
            "socks5" => UpstreamKind::Socks5,
            "socks4a" => UpstreamKind::Socks4a,
            "composite" | "fixed" => UpstreamKind::Composite {
                http: p.http_proxy.clone().unwrap_or_default(),
                https: p.https_proxy.clone().unwrap_or_default(),
                fallback: p.fallback_proxy.clone().unwrap_or_default(),
            },
            other => return Err(invalid(format!("profile `{key}` has unknown type {other:?}"))),
        };
        let sources = [password.is_some(), p.password_env.is_some(), p.password_file.is_some()];
        if sources.iter().filter(|s| **s).count() > 1 {
            return Err(invalid(format!(
                "profile `{key}` sets more than one of password, password_env, password_file"
            )));
        }
        let password_source = match (&p.password_env, &p.password_file) {
            (Some(env), _) => Some(UpstreamPasswordSource::Env(env.clone())),
            (_, Some(file)) => Some(UpstreamPasswordSource::File(file.clone())),
            _ => None,
        };
        if let Some(pw) = password {
            warnings.push(format!("profile `{key}`: inline password moved to the Vault"));
            secrets.push(ExtractedSecret { profile_name: key.clone(), password: pw });
        }
        profiles.push(UpstreamProfile {
            name: key,
            kind,
            host: p.host,
            port: p.port,
            username: p.username,
            password: password_source,
            bypass: p.bypass,
            color: None,
        });
    }
    // Composite parts that named a direct/block alias.
    for p in &mut profiles {
        if let UpstreamKind::Composite { http, https, fallback } = &mut p.kind {
            for part in [http, https, fallback] {
                if let Some(to) = aliases.get(part.as_str()) {
                    *part = to.clone();
                }
            }
        }
    }
    let mut routing = f.routing.unwrap_or_default();
    rewrite_routing(&mut routing, &aliases);

    let proxy = Proxy {
        name: name.to_string(),
        listeners: listeners_of(f.bind, f.http_port, f.socks_port, f.max_connections),
        network,
        profiles,
        routing,
        filter,
        socks_block_web,
        mitm,
        logging: logging_of(f.logging),
        ..Proxy::default()
    };
    Ok(SwitchTomlImport { proxy, extracted_secrets: secrets, warnings })
}

/// Whether a `-switch` file uses the deprecated `mitm.cert_cache_max` key, which serde reads
/// through an alias.
fn switch_uses_cert_cache_max(toml_str: &str) -> bool {
    toml_str.parse::<toml::Table>().ok().is_some_and(|t| {
        t.get("mitm")
            .and_then(toml::Value::as_table)
            .is_some_and(|m| m.contains_key("cert_cache_max"))
    })
}

fn non_empty(s: &str) -> Option<String> {
    (!s.trim().is_empty()).then(|| s.to_string())
}

/// Append a commented `[profiles.<name>]` block, preceded by `prose` as comment lines.
fn push_placeholder(
    placeholders: &mut String,
    name: &str,
    block: SwitchProfileFile,
    prose: &str,
) -> Result<(), TomlExportError> {
    let mut table = BTreeMap::new();
    table.insert(name.to_string(), block);
    let mut wrapper = BTreeMap::new();
    wrapper.insert("profiles", table);
    let body = to_toml(&wrapper)?;
    placeholders.push('\n');
    for line in prose.lines() {
        placeholders.push_str(&format!("# {line}\n"));
    }
    for line in body.lines() {
        placeholders.push_str(&format!("# {line}\n").replace("# \n", "#\n"));
    }
    Ok(())
}

fn tunnel_label(tunnels: &[Tunnel], tunnel_id: TunnelId) -> String {
    tunnels
        .iter()
        .find(|t| t.id == tunnel_id)
        .map(|t| format!("{:?}", t.name))
        .unwrap_or_else(|| tunnel_id.to_string())
}

fn local_socks5_placeholder() -> SwitchProfileFile {
    SwitchProfileFile {
        kind: "socks5".into(),
        host: Some("127.0.0.1".into()),
        port: Some(1080),
        ..SwitchProfileFile::default()
    }
}

/// Every `@tunnel:` / `@forward:` target the Proxy routes to (routing tables and composite
/// slots), mapped to the profile name it is exported as.
fn synthetic_target_names(proxy: &Proxy) -> BTreeMap<String, String> {
    let mut names = BTreeMap::new();
    let mut add = |raw: &str| match TargetRef::parse(raw) {
        TargetRef::Tunnel(tunnel_id) => {
            names.insert(raw.to_string(), format!("tunnel-{tunnel_id}"));
        }
        TargetRef::TunnelForward { forward_id, .. } => {
            names.insert(raw.to_string(), format!("forward-{forward_id}"));
        }
        _ => {}
    };
    let r = &proxy.routing;
    r.default.as_slice().iter().for_each(|t| add(t));
    for rule in &r.rules {
        rule.target.as_slice().iter().for_each(|t| add(t));
    }
    for table in [r.http.as_ref(), r.socks.as_ref()].into_iter().flatten() {
        if let Some(d) = &table.default {
            d.as_slice().iter().for_each(|t| add(t));
        }
        for rule in &table.rules {
            rule.target.as_slice().iter().for_each(|t| add(t));
        }
    }
    for p in &proxy.profiles {
        if let UpstreamKind::Composite { http, https, fallback } = &p.kind {
            [http, https, fallback].into_iter().for_each(|t| add(t));
        }
    }
    names
}

/// Export any Proxy as a `rusty-conduit-switch` `config.toml`. Legacy `tunnel` profiles and
/// `@tunnel:` / `@forward:` targets become commented placeholder profiles (synthetic targets
/// are renamed `tunnel-<tunnel id>` / `forward-<forward id>` everywhere they are used), and
/// vaulted passwords become `password_env` references. `tunnels` names the Tunnels and finds
/// each forward's listener for the placeholders.
pub fn export_rusty_conduit_switch_toml(
    proxy: &Proxy,
    tunnels: &[Tunnel],
) -> Result<TomlExport, TomlExportError> {
    const CLI: &str = "rusty-conduit-switch";
    let mut notes = Vec::new();
    let mut profiles = BTreeMap::new();
    let mut placeholders = String::new();
    let synthetic = synthetic_target_names(proxy);
    let renamed = |slot: &str| synthetic.get(slot).cloned().unwrap_or_else(|| slot.to_string());
    for p in &proxy.profiles {
        let mut out = SwitchProfileFile {
            host: p.host.clone(),
            port: p.port,
            username: p.username.clone(),
            bypass: p.bypass.clone(),
            ..SwitchProfileFile::default()
        };
        match &p.kind {
            UpstreamKind::Http => out.kind = "http".into(),
            UpstreamKind::Https { tls_insecure_skip_verify } => {
                out.kind = "https".into();
                out.tls_insecure_skip_verify = *tls_insecure_skip_verify;
            }
            UpstreamKind::Socks5 => out.kind = "socks5".into(),
            UpstreamKind::Socks4a => out.kind = "socks4a".into(),
            UpstreamKind::Composite { http, https, fallback } => {
                out = SwitchProfileFile {
                    kind: "composite".into(),
                    bypass: p.bypass.clone(),
                    http_proxy: non_empty(&renamed(http)),
                    https_proxy: non_empty(&renamed(https)),
                    fallback_proxy: non_empty(&renamed(fallback)),
                    ..SwitchProfileFile::default()
                };
            }
            UpstreamKind::Tunnel { tunnel_id } => {
                let tunnel_name = tunnel_label(tunnels, *tunnel_id);
                let block = SwitchProfileFile {
                    bypass: p.bypass.clone(),
                    ..local_socks5_placeholder()
                };
                push_placeholder(
                    &mut placeholders,
                    &p.name,
                    block,
                    &format!(
                        "Profile `{}` routes through the app's SSH Tunnel {tunnel_name}. Run \
                         rusty-conduit-ssh (or ssh -D) for it,\nthen uncomment this block and \
                         point it at that SOCKS5 port.",
                        p.name
                    ),
                )?;
                notes.push(format!(
                    "Profile `{}` is an SSH Tunnel ({tunnel_name}): it is written as a \
                     commented socks5 placeholder; until it is uncommented, rules that target \
                     it are rejected",
                    p.name
                ));
                continue;
            }
        }
        if !matches!(p.kind, UpstreamKind::Composite { .. }) {
            match &p.password {
                None => {}
                Some(UpstreamPasswordSource::Env(var)) => out.password_env = Some(var.clone()),
                Some(UpstreamPasswordSource::File(path)) => out.password_file = Some(path.clone()),
                Some(UpstreamPasswordSource::Vault(_)) => {
                    let var = upstream_password_env_var(&p.name);
                    notes.push(format!(
                        "Profile `{}`: its password is in the Vault; set the environment \
                         variable {var} before starting rusty-conduit-switch",
                        p.name
                    ));
                    out.password_env = Some(var);
                }
            }
        }
        profiles.insert(p.name.clone(), out);
    }

    for (raw, name) in &synthetic {
        match TargetRef::parse(raw) {
            TargetRef::Tunnel(tunnel_id) => {
                let tunnel_name = tunnel_label(tunnels, tunnel_id);
                push_placeholder(
                    &mut placeholders,
                    name,
                    local_socks5_placeholder(),
                    &format!(
                        "Profile `{name}` stands for `{raw}`, the app's SSH Tunnel {tunnel_name}. \
                         Run rusty-conduit-ssh (or ssh -D) for it,\nthen uncomment this block \
                         and point it at that SOCKS5 port."
                    ),
                )?;
                notes.push(format!(
                    "Target `{raw}` is an SSH Tunnel ({tunnel_name}): it is written as profile \
                     `{name}`, a commented socks5 placeholder; until it is uncommented, rules \
                     that target it are rejected"
                ));
            }
            TargetRef::TunnelForward { tunnel_id, forward_id } => {
                let tunnel_name = tunnel_label(tunnels, tunnel_id);
                let forward = tunnels
                    .iter()
                    .find(|t| t.id == tunnel_id)
                    .and_then(|t| t.port_forwards.iter().find(|f| f.id == forward_id));
                let kind = forward.and_then(|f| match f.proxy_protocol {
                    ForwardProxyProtocol::Http => Some("http"),
                    ForwardProxyProtocol::Socks5 => Some("socks5"),
                    ForwardProxyProtocol::None => None,
                });
                let (block, prose) = match (forward, kind) {
                    (Some(f), Some(kind)) => (
                        SwitchProfileFile {
                            kind: kind.into(),
                            host: Some(f.bind.to_string()),
                            port: Some(f.port),
                            ..SwitchProfileFile::default()
                        },
                        format!(
                            "Profile `{name}` stands for `{raw}`, a local forward on the app's \
                             SSH Tunnel {tunnel_name}. Run\n`ssh -L {}:{}` for it, then \
                             uncomment this block.",
                            f.listen(),
                            f.destination()
                        ),
                    ),
                    _ => (
                        local_socks5_placeholder(),
                        format!(
                            "Profile `{name}` stands for `{raw}`, a forward on the app's SSH \
                             Tunnel {tunnel_name} that\nwas not found or speaks no proxy \
                             protocol: point this block at a proxy that reaches it, then \
                             uncomment it."
                        ),
                    ),
                };
                push_placeholder(&mut placeholders, name, block, &prose)?;
                notes.push(format!(
                    "Target `{raw}` is a port forward on SSH Tunnel {tunnel_name}: it is written \
                     as profile `{name}`, a commented placeholder; until it is uncommented, \
                     rules that target it are rejected"
                ));
            }
            _ => {}
        }
    }

    let mut routing = proxy.routing.clone();
    rewrite_routing(&mut routing, &synthetic);

    let (allow, block) = filter_to_file(&proxy.filter);
    let l = &proxy.listeners;
    let n = &proxy.network;
    let file = SwitchFile {
        bind: Some(l.bind),
        http_port: Some(l.http_port),
        socks_port: Some(l.socks_port),
        connect_timeout: Some(format_duration(n.connect_timeout)),
        max_connections: Some(l.max_connections),
        tcp_keepalive: Some(SwitchKeepaliveField::Idle(format_duration(n.tcp_keepalive))),
        tcp_keepalive_interval: Some(format_duration(n.tcp_keepalive_interval)),
        tcp_keepalive_retries: Some(n.tcp_keepalive_retries),
        allow,
        block,
        socks_block_web: (proxy.socks_block_web
            || proxy.mitm.as_ref().is_some_and(|m| m.socks_block_web))
            .then_some(true),
        mitm: proxy.mitm.as_ref().map(|m| mitm_to_file(m, &mut notes)),
        logging: Some(logging_to_file(&proxy.logging)),
        profiles,
        routing: Some(routing),
        ..SwitchFile::default()
    };
    let toml = header(CLI, proxy) + &to_toml(&file)? + &placeholders;
    Ok(finish(toml, notes))
}

// ---------------------------------------------------------------------------
// Dispatch.
// ---------------------------------------------------------------------------

/// Import a `config.toml` of the given CLI format (see [`detect_cli_toml_format`]).
pub fn import_cli_toml(
    toml_str: &str,
    format: CliTomlFormat,
    name: &str,
) -> Result<CliTomlImport, TomlImportError> {
    Ok(match format {
        CliTomlFormat::RustyConduit => {
            CliTomlImport::RustyConduit(Box::new(import_rusty_conduit_toml(toml_str, name)?))
        }
        CliTomlFormat::RustyConduitSsh => {
            CliTomlImport::RustyConduitSsh(Box::new(import_rusty_conduit_ssh_toml(toml_str, name)?))
        }
        CliTomlFormat::RustyConduitSwitch => {
            CliTomlImport::RustyConduitSwitch(Box::new(import_rusty_conduit_switch_toml(
                toml_str, name,
            )?))
        }
    })
}

/// Export a Proxy as a `config.toml` of the given CLI format.
pub fn export_cli_toml(
    format: CliTomlFormat,
    proxy: &Proxy,
    tunnels: &[Tunnel],
) -> Result<TomlExport, TomlExportError> {
    match format {
        CliTomlFormat::RustyConduit => export_rusty_conduit_toml(proxy),
        CliTomlFormat::RustyConduitSsh => export_rusty_conduit_ssh_toml(proxy, tunnels),
        CliTomlFormat::RustyConduitSwitch => export_rusty_conduit_switch_toml(proxy, tunnels),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ForwardDirection, KeyId, MitmCaId, PortForward};
    use crate::v2_model::{RoutingRule, RoutingTable};
    use crate::v2_validate::{validate_proxy, validate_tunnel};
    use crate::SecretRef;

    const CONDUIT_TOML: &str = r#"
bind = "0.0.0.0"
http_port = 8080
socks_port = 1090
max_connections = 64
tcp_keepalive = "30s"
tcp_keepalive_interval = "5s"
tcp_keepalive_retries = 3
block = ["*.ads.example"]

[mitm]
ca_cert = "/etc/ca.pem"
ca_key = "/etc/ca.key"
ca_passphrase = "toml-ca-secret"
cert_ttl = "1h"

[logging]
level = "DEBUG"
format = "json"
"#;

    const SSH_TOML: &str = r#"
http_port = 3129
socks_port = 1081
tcp_keepalive = "0"
allow = ["*.corp.example"]

[ssh]
target = "alice@bastion.example"
port = 2222
ip_version = 4
identity = "/home/alice/.ssh/id_ed25519"
jump = "jump.example"
server_alive_interval = "15s"
server_alive_count_max = 3
reconnect_initial_delay = "2s"
reconnect_max_delay = "1m"
startup_timeout = "45s"

[reverse]
http_port = 8888
socks_port = 0

[logging]
level = "INFO"
"#;

    const SWITCH_TOML: &str = r#"
bind = "127.0.0.1"
http_port = 3130
socks_port = 1082
connect_timeout = "7s"
watch_config = true

[tcp_keepalive]
idle = "45s"
interval = "9s"
retries = 4

[filter]
allow = ["*.example.com"]

[profiles.corp]
type = "http"
host = "10.0.0.2"
port = 3128
username = "alice"
password = "switch-inline-secret"
bypass = ["<local>"]

[profiles.envy]
type = "socks5"
host = "10.0.0.3"
port = 1080
username = "bob"
password_env = "BOB_PW"

[profiles.filey]
type = "https"
host = "proxy.example"
port = 443
password_file = "/run/secrets/pw"
tls_insecure_skip_verify = true

[profiles.split]
type = "composite"
http_proxy = "corp"
fallback_proxy = "nothing"

[profiles.nothing]
type = "direct"

[routing]
default = ["corp", "direct"]

[[routing.rules]]
name = "intranet"
host_wildcard = ["*.corp.example"]
target = "split"

[[routing.rules]]
cidr = "10.0.0.0/8"
port = [22, "8000-8080"]
target = "nothing"

[routing.socks]
default = "envy"
inherit = true
"#;

    #[test]
    fn toml_io_detects_formats() {
        assert_eq!(detect_cli_toml_format(CONDUIT_TOML), CliTomlFormat::RustyConduit);
        assert_eq!(detect_cli_toml_format(SSH_TOML), CliTomlFormat::RustyConduitSsh);
        assert_eq!(detect_cli_toml_format(SWITCH_TOML), CliTomlFormat::RustyConduitSwitch);
        assert_eq!(detect_cli_toml_format("[tcp_keepalive]\nidle = \"1s\""), CliTomlFormat::RustyConduitSwitch);
        assert_eq!(detect_cli_toml_format("not = [toml"), CliTomlFormat::RustyConduit);
        assert_eq!(detect_cli_toml_format(""), CliTomlFormat::RustyConduit);
    }

    #[test]
    fn toml_io_imports_rusty_conduit() {
        let out = import_rusty_conduit_toml(CONDUIT_TOML, "plain").unwrap();
        let p = &out.proxy;
        assert_eq!(p.name, "plain");
        assert_eq!(p.listeners.bind.to_string(), "0.0.0.0");
        assert_eq!((p.listeners.http_port, p.listeners.socks_port), (8080, 1090));
        assert_eq!(p.listeners.max_connections, 64);
        assert_eq!(p.network.tcp_keepalive, Duration::from_secs(30));
        assert_eq!(p.network.tcp_keepalive_interval, Duration::from_secs(5));
        assert_eq!(p.network.tcp_keepalive_retries, 3);
        assert_eq!(p.filter, GlobalFilterConfig::Block(vec!["*.ads.example".into()]));
        assert_eq!(p.logging.level, "DEBUG");
        assert_eq!(p.logging.format, "json");
        assert!(p.profiles.is_empty() && p.routing.rules.is_empty());
        assert_eq!(p.routing.default.as_slice(), ["direct".to_string()]);
        // MITM CA files cannot be imported: MITM stays off, with warnings, and the CA
        // passphrase is never kept.
        assert!(p.mitm.is_none());
        let all = out.warnings.join("\n");
        assert!(all.contains("/etc/ca.pem") && all.contains("ca_passphrase"));
        assert!(!format!("{out:?}").contains("toml-ca-secret"));
        validate_proxy(p, &[], &[]).unwrap();
    }

    #[test]
    fn toml_io_rejects_bad_rusty_conduit_files() {
        let unknown = import_rusty_conduit_toml("bogus = 1", "x").unwrap_err();
        assert!(matches!(unknown, TomlImportError::Parse { .. }), "{unknown}");
        let both = import_rusty_conduit_toml("allow = [\"test.domain.net\"]\nblock = [\"*.domain.net\"]", "x").unwrap();
        assert_eq!(
            both.proxy.filter,
            GlobalFilterConfig::BlockExcept {
                block: vec!["*.domain.net".into()],
                allow: vec!["test.domain.net".into()],
            }
        );
        let dur = import_rusty_conduit_toml("tcp_keepalive = \"soon\"", "x").unwrap_err();
        assert!(dur.to_string().contains("tcp_keepalive"));
    }

    fn direct_proxy() -> Proxy {
        Proxy {
            name: "direct one".into(),
            listeners: ListenerConfig {
                bind: "127.0.0.2".parse().unwrap(),
                http_port: 18080,
                socks_port: 11080,
                max_connections: 99,
            },
            network: NetworkConfig {
                tcp_keepalive: Duration::from_secs(90),
                tcp_keepalive_interval: Duration::from_secs(7),
                tcp_keepalive_retries: 2,
                ..NetworkConfig::default()
            },
            filter: GlobalFilterConfig::Allow(vec!["*.example.org".into(), "10.0.0.0/8".into()]),
            logging: LoggingConfig {
                level: "VERBOSE".into(),
                format: "json".into(),
                http_access_log: Some("/tmp/access.log".into()),
                socks_log: None,
            },
            ..Proxy::default()
        }
    }

    #[test]
    fn toml_io_rusty_conduit_round_trips() {
        let proxy = direct_proxy();
        let out = export_rusty_conduit_toml(&proxy).unwrap();
        assert!(out.toml.starts_with("# rusty-conduit config.toml exported"));
        assert!(out.notes.is_empty());
        let back = import_rusty_conduit_toml(&out.toml, &proxy.name).unwrap();
        assert_eq!(back.proxy, proxy);
        assert_eq!(detect_cli_toml_format(&out.toml), CliTomlFormat::RustyConduit);
    }

    #[test]
    fn toml_io_rusty_conduit_export_refuses_rules_and_non_direct() {
        let mut proxy = direct_proxy();
        proxy.routing.rules.push(RoutingRule::to_target(RouteOneOrMany::One("block".into())));
        let err = export_rusty_conduit_toml(&proxy).unwrap_err().to_string();
        assert!(err.contains("routing rules") && err.contains("rusty-conduit-switch"), "{err}");
        let mut proxy = direct_proxy();
        proxy.routing.default = RouteOneOrMany::One("block".into());
        let err = export_rusty_conduit_toml(&proxy).unwrap_err().to_string();
        assert!(err.contains("not `direct`") && err.contains("rusty-conduit-switch"), "{err}");
    }

    #[test]
    fn toml_io_rusty_conduit_export_lists_mitm_ca_as_a_note() {
        let mut proxy = direct_proxy();
        proxy.mitm = Some(MitmConfig { ca: Some(MitmCaId::new()), ..MitmConfig::default() });
        let out = export_rusty_conduit_toml(&proxy).unwrap();
        assert!(out.toml.contains("[mitm]") && out.toml.contains("cert_ttl = \"1h\""));
        assert!(!out.toml.contains("\nca_cert"));
        assert!(out.notes.iter().any(|n| n.contains("MITM")));
        assert!(out.toml.contains("# Setup notes:"));
    }

    #[test]
    fn toml_io_mitm_upstream_tls_round_trips_for_every_cli() {
        let (tunnel, ssh_proxy) = ssh_pair();
        let hosts = vec!["localhost".to_string(), "*.corp.local".into(), "10.0.0.0/8".into()];
        for format in [
            CliTomlFormat::RustyConduit,
            CliTomlFormat::RustyConduitSsh,
            CliTomlFormat::RustyConduitSwitch,
        ] {
            for mode in [
                MitmUpstreamTlsMode::Strict,
                MitmUpstreamTlsMode::Allowlist,
                MitmUpstreamTlsMode::InsecureAll,
            ] {
                let mut proxy =
                    if format == CliTomlFormat::RustyConduit { direct_proxy() } else { ssh_proxy.clone() };
                proxy.mitm = Some(MitmConfig {
                    ca: Some(MitmCaId::new()),
                    upstream_tls_mode: mode,
                    insecure_hosts: hosts.clone(),
                    bypass_hosts: vec!["*.bank.example".into(), "192.0.2.0/24".into()],
                    ..MitmConfig::default()
                });
                let out = export_cli_toml(format, &proxy, std::slice::from_ref(&tunnel)).unwrap();
                let toml = &out.toml;
                assert!(toml.contains("bypass_hosts = [\"*.bank.example\", \"192.0.2.0/24\"]"), "{toml}");
                assert_eq!(toml.contains("insecure = true"), mode == MitmUpstreamTlsMode::InsecureAll, "{toml}");
                assert_eq!(
                    toml.contains("insecure_hosts = [\"localhost\", \"*.corp.local\", \"10.0.0.0/8\"]"),
                    mode == MitmUpstreamTlsMode::Allowlist,
                    "{toml}"
                );

                // The `[mitm]` table reads back as the same mode, as each CLI reads it.
                let table: toml::Table = toml.parse().unwrap();
                let file: MitmFile = table["mitm"].clone().try_into().unwrap();
                let expected_hosts =
                    if mode == MitmUpstreamTlsMode::Allowlist { hosts.clone() } else { Vec::new() };
                assert_eq!(upstream_tls_of(&file), (mode, expected_hosts));

                // Import keeps MITM off (the CA is in the Vault) and says what was not applied.
                let back = import_cli_toml(toml, format, "x").unwrap();
                let warnings = match back {
                    CliTomlImport::RustyConduit(i) => (i.proxy.mitm, i.warnings),
                    CliTomlImport::RustyConduitSsh(i) => (i.proxy.and_then(|p| p.mitm), i.warnings),
                    CliTomlImport::RustyConduitSwitch(i) => (i.proxy.mitm, i.warnings),
                };
                assert!(warnings.0.is_none());
                let notice = warnings.1.iter().any(|w| w.contains("Upstream TLS certificates"));
                assert_eq!(notice, mode != MitmUpstreamTlsMode::Strict, "{:?}", warnings.1);
                assert!(
                    warnings.1.iter().any(|w| w.contains("bypass_hosts (*.bank.example, 192.0.2.0/24)")),
                    "{:?}",
                    warnings.1
                );
            }
        }
    }

    #[test]
    fn toml_io_mitm_insecure_wins_over_insecure_hosts_on_import() {
        let file: MitmFile =
            toml::from_str("insecure = true\ninsecure_hosts = [\"a.example\"]\n").unwrap();
        assert_eq!(upstream_tls_of(&file), (MitmUpstreamTlsMode::InsecureAll, Vec::new()));
        let file: MitmFile = toml::from_str("insecure = false\ninsecure_hosts = [\"a.example\"]\n").unwrap();
        assert_eq!(upstream_tls_of(&file), (MitmUpstreamTlsMode::Allowlist, vec!["a.example".into()]));
        let file: MitmFile = toml::from_str("insecure = false\n").unwrap();
        assert_eq!(upstream_tls_of(&file), (MitmUpstreamTlsMode::Strict, Vec::new()));
        // Every CLI's `[mitm]` accepts these keys.
        let keys = "insecure = true\ninsecure_hosts = [\"a.example\"]\nbypass_hosts = [\"*.bank.example\"]\n";
        let conduit = CONDUIT_TOML.replacen("[mitm]\n", &format!("[mitm]\n{keys}"), 1);
        assert_ne!(conduit, CONDUIT_TOML);
        for (cli_toml, format) in [
            (conduit, CliTomlFormat::RustyConduit),
            (format!("{SSH_TOML}\n[mitm]\n{keys}"), CliTomlFormat::RustyConduitSsh),
            (format!("{SWITCH_TOML}\n[mitm]\n{keys}"), CliTomlFormat::RustyConduitSwitch),
        ] {
            assert_eq!(detect_cli_toml_format(&cli_toml), format);
            import_cli_toml(&cli_toml, format, "x").unwrap();
        }
    }

    #[test]
    fn toml_io_socks_block_web_is_top_level_only() {
        let mut proxy = direct_proxy();
        proxy.mitm = Some(MitmConfig { socks_block_web: true, ..MitmConfig::default() });
        let out = export_rusty_conduit_toml(&proxy).unwrap();
        let table: toml::Table = out.toml.parse().unwrap();
        assert_eq!(table.get("socks_block_web"), Some(&toml::Value::Boolean(true)));
        let mitm = table.get("mitm").and_then(toml::Value::as_table).unwrap();
        assert!(!mitm.contains_key("socks_block_web"), "{}", out.toml);
        // The CLIs retired `[mitm] socks_block_web`; importing it is an error, as in the CLIs.
        let legacy =
            CONDUIT_TOML.replace("cert_ttl = \"1h\"\n", "cert_ttl = \"1h\"\nsocks_block_web = true\n");
        assert_ne!(legacy, CONDUIT_TOML);
        let err = import_rusty_conduit_toml(&legacy, "legacy").unwrap_err().to_string();
        assert!(err.contains("socks_block_web"), "{err}");
    }

    #[test]
    fn toml_io_imports_rusty_conduit_ssh() {
        let out = import_rusty_conduit_ssh_toml(SSH_TOML, "bastion").unwrap();
        let t = &out.tunnel;
        assert_eq!(t.name, "bastion");
        assert_ne!(t.id, TunnelId::default());
        assert_eq!(t.hops.len(), 1);
        let h = &t.hops[0].host;
        assert_eq!((h.user.as_str(), h.host.as_str(), h.port), ("alice", "bastion.example", 2222));
        assert!(h.auth.is_empty());
        assert_eq!(t.keepalive.ip_version, "4");
        assert_eq!(t.keepalive.server_alive_interval, Duration::from_secs(15));
        assert_eq!(t.keepalive.server_alive_count_max, 3);
        assert_eq!(t.keepalive.tcp_keepalive, Duration::ZERO);
        assert_eq!(t.keepalive.reconnect_max_delay, Duration::from_secs(60));
        assert_eq!(t.keepalive.startup_timeout, Duration::from_secs(45));
        assert!(t.reverse.enabled);
        assert_eq!(t.reverse.effective_ports(), (8888, 0));
        validate_tunnel(t).unwrap();

        let p = out.proxy.as_ref().unwrap();
        assert_eq!((p.listeners.http_port, p.listeners.socks_port), (3129, 1081));
        assert_eq!(p.filter, GlobalFilterConfig::Allow(vec!["*.corp.example".into()]));
        assert_eq!(p.routing.default.as_slice(), ["tunnel".to_string()]);
        assert_eq!(p.profiles[0].kind, UpstreamKind::Tunnel { tunnel_id: t.id });
        assert_eq!(p.network.tcp_keepalive, Duration::ZERO);
        validate_proxy(p, &[t.id], &[]).unwrap();

        let notes = out.notes.join("\n");
        assert!(notes.contains("~/.ssh/config alias"));
        assert!(notes.contains("id_ed25519"));
        assert!(notes.contains("jump.example"));
    }

    #[test]
    fn toml_io_ssh_import_needs_a_target_and_may_have_no_proxy() {
        assert!(matches!(
            import_rusty_conduit_ssh_toml("http_port = 1", "x"),
            Err(TomlImportError::MissingSshTarget)
        ));
        let out = import_rusty_conduit_ssh_toml(
            "http_port = 0\nsocks_port = 0\n[ssh]\ntarget = \"ssh://bob@[::1]:2200\"\n[reverse]\nsocks_port = 1080",
            "rev",
        )
        .unwrap();
        assert!(out.proxy.is_none());
        let h = &out.tunnel.hops[0].host;
        assert_eq!((h.user.as_str(), h.host.as_str(), h.port), ("bob", "::1", 2200));
        let alias = import_rusty_conduit_ssh_toml("[ssh]\ntarget = \"my-alias\"", "a").unwrap();
        assert_eq!(alias.tunnel.hops[0].host.host, "my-alias");
        assert!(alias.notes.iter().any(|n| n.contains("No user")));
        let bad_ip = import_rusty_conduit_ssh_toml("[ssh]\ntarget = \"h\"\nip_version = 5", "a");
        assert!(matches!(bad_ip, Err(TomlImportError::Invalid { .. })));
    }

    fn ssh_pair() -> (Tunnel, Proxy) {
        let target = HopEntry {
            hop_id: "t".into(),
            name: "target".into(),
            host: HostProfile {
                name: "target".into(),
                host: "target.example".into(),
                port: 2022,
                user: "carol".into(),
                auth: vec![
                    AuthMethod::Key { key: KeyId::new() },
                    AuthMethod::Password { secret: SecretRef::new() },
                ],
                ..HostProfile::default()
            },
        };
        let jump = HopEntry {
            hop_id: "j".into(),
            name: "jump".into(),
            host: HostProfile {
                name: "jump".into(),
                host: "jump.example".into(),
                user: "carol".into(),
                ..HostProfile::default()
            },
        };
        let tunnel = Tunnel {
            id: TunnelId::new(),
            name: "corp".into(),
            hops: vec![jump, target],
            reverse: ReverseConfig {
                enabled: true,
                reverse_http_port: 9999,
                reverse_socks_port: 9998,
                reverse_max_connections: Some(5),
                reverse_block: vec!["*.bad".into()],
                ..ReverseConfig::default()
            },
            port_forwards: vec![PortForward {
                direction: ForwardDirection::Local,
                port: 15432,
                dest_host: "db.internal".into(),
                dest_port: 5432,
                ..PortForward::default()
            }],
            keepalive: TunnelConfig {
                ip_version: "auto".into(),
                server_alive_interval: Duration::from_secs(20),
                no_reconnect: true,
                ..TunnelConfig::default()
            },
            ..Tunnel::default()
        };
        let proxy = Proxy {
            name: "corp".into(),
            profiles: vec![UpstreamProfile {
                name: "ssh".into(),
                kind: UpstreamKind::Tunnel { tunnel_id: tunnel.id },
                host: None,
                port: None,
                username: None,
                password: None,
                bypass: Vec::new(),
                color: None,
            }],
            routing: RoutingTablesConfig {
                default: RouteOneOrMany::One("ssh".into()),
                ..RoutingTablesConfig::default()
            },
            filter: GlobalFilterConfig::Block(vec!["*.ads".into()]),
            ..Proxy::default()
        };
        (tunnel, proxy)
    }

    #[test]
    fn toml_io_rusty_conduit_ssh_round_trips_with_setup_notes() {
        let (tunnel, proxy) = ssh_pair();
        let out = export_rusty_conduit_ssh_toml(&proxy, std::slice::from_ref(&tunnel)).unwrap();
        assert!(out.toml.contains("target = \"carol@target.example\""), "{}", out.toml);
        assert!(out.toml.contains("port = 2022"));
        let notes = out.notes.join("\n");
        assert!(notes.contains("ProxyJump carol@jump.example:22"), "{notes}");
        assert!(notes.contains("IdentityFile"));
        assert!(notes.contains("Vault password"));
        assert!(notes.contains("LocalForward 127.0.0.1:15432 db.internal:5432"));
        assert_eq!(detect_cli_toml_format(&out.toml), CliTomlFormat::RustyConduitSsh);

        let back = import_rusty_conduit_ssh_toml(&out.toml, "corp").unwrap();
        let t = &back.tunnel;
        let h = &t.hops[0].host;
        assert_eq!((h.user.as_str(), h.host.as_str(), h.port), ("carol", "target.example", 2022));
        assert_eq!(t.reverse, tunnel.reverse);
        assert_eq!(t.keepalive, tunnel.keepalive);
        let p = back.proxy.unwrap();
        assert_eq!(p.listeners, proxy.listeners);
        assert_eq!(p.network, proxy.network);
        assert_eq!(p.filter, proxy.filter);
        assert_eq!(p.logging, proxy.logging);
    }

    #[test]
    fn toml_io_ssh_export_requires_one_tunnel_and_no_rules() {
        let (tunnel, mut proxy) = ssh_pair();
        assert!(export_rusty_conduit_ssh_toml(&proxy, &[]).unwrap_err().to_string().contains("does not exist"));
        proxy.routing.default = RouteOneOrMany::Many(vec!["ssh".into(), "direct".into()]);
        let err = export_rusty_conduit_ssh_toml(&proxy, std::slice::from_ref(&tunnel)).unwrap_err();
        assert!(err.to_string().contains("single `tunnel` profile"));
        let (tunnel, mut proxy) = ssh_pair();
        proxy.routing.http = Some(RoutingTable::default());
        let err = export_rusty_conduit_ssh_toml(&proxy, std::slice::from_ref(&tunnel)).unwrap_err();
        assert!(err.to_string().contains("routing rules"));
    }

    #[test]
    fn toml_io_imports_rusty_conduit_switch_and_extracts_secrets() {
        let out = import_rusty_conduit_switch_toml(SWITCH_TOML, "auto").unwrap();
        let p = &out.proxy;
        assert_eq!(p.name, "auto");
        assert_eq!((p.listeners.http_port, p.listeners.socks_port), (3130, 1082));
        assert_eq!(p.network.connect_timeout, Duration::from_secs(7));
        assert_eq!(p.network.tcp_keepalive, Duration::from_secs(45));
        assert_eq!(p.network.tcp_keepalive_retries, 4);
        assert_eq!(p.filter, GlobalFilterConfig::Allow(vec!["*.example.com".into()]));

        let corp = p.profiles.iter().find(|x| x.name == "corp").unwrap();
        assert_eq!(corp.kind, UpstreamKind::Http);
        assert_eq!(corp.password, None);
        assert_eq!(corp.bypass, vec!["<local>".to_string()]);
        let envy = p.profiles.iter().find(|x| x.name == "envy").unwrap();
        assert_eq!(envy.password, Some(UpstreamPasswordSource::Env("BOB_PW".into())));
        let filey = p.profiles.iter().find(|x| x.name == "filey").unwrap();
        assert_eq!(filey.password, Some(UpstreamPasswordSource::File("/run/secrets/pw".into())));
        assert_eq!(filey.kind, UpstreamKind::Https { tls_insecure_skip_verify: true });
        let split = p.profiles.iter().find(|x| x.name == "split").unwrap();
        assert_eq!(
            split.kind,
            UpstreamKind::Composite { http: "corp".into(), https: String::new(), fallback: "direct".into() }
        );
        assert!(p.profiles.iter().all(|x| x.name != "nothing"));
        assert_eq!(p.routing.rules[1].target.as_slice(), ["direct".to_string()]);
        assert_eq!(p.routing.rules[0].name.as_deref(), Some("intranet"));
        assert_eq!(p.routing.default.as_slice(), ["corp".to_string(), "direct".to_string()]);
        assert!(p.routing.socks.as_ref().unwrap().inherit);

        assert_eq!(out.extracted_secrets.len(), 1);
        assert_eq!(out.extracted_secrets[0].profile_name, "corp");
        assert_eq!(out.extracted_secrets[0].password.as_str(), "switch-inline-secret");
        assert!(!serde_json::to_string(p).unwrap().contains("switch-inline-secret"));
        assert!(!format!("{out:?}").contains("switch-inline-secret"));
        let all = out.warnings.join("\n");
        assert!(all.contains("watch_config") && all.contains("moved to the Vault"));
        assert!(all.contains("`nothing` (type direct)"));
        validate_proxy(p, &[], &[]).unwrap();
    }

    #[test]
    fn toml_io_switch_imports_current_names_and_flags_deprecated_ones() {
        let current = "tcp_keepalive = \"30s\"\ntcp_keepalive_interval = \"5s\"\n\
                       tcp_keepalive_retries = 3\nblock = [\"*.ads.example\"]\n\
                       allow = [\"ok.ads.example\"]\n\n[mitm]\ncert_cache_max_entries = 99\n\n\
                       [routing]\ndefault = \"direct\"\n";
        let out = import_rusty_conduit_switch_toml(current, "now").unwrap();
        let n = &out.proxy.network;
        assert_eq!(
            (n.tcp_keepalive, n.tcp_keepalive_interval, n.tcp_keepalive_retries),
            (Duration::from_secs(30), Duration::from_secs(5), 3)
        );
        assert!(matches!(&out.proxy.filter, GlobalFilterConfig::BlockExcept { .. }), "{:?}", out.proxy.filter);
        assert!(!out.warnings.iter().any(|w| w.contains("deprecated")), "{:?}", out.warnings);

        let old = import_rusty_conduit_switch_toml(SWITCH_TOML, "auto").unwrap();
        assert!(
            old.warnings.iter().any(|w| w.starts_with("`[tcp_keepalive]`, `[filter]` are deprecated")),
            "{:?}",
            old.warnings
        );
        let cache = import_rusty_conduit_switch_toml("[mitm]\ncert_cache_max = 5\n", "x").unwrap();
        assert!(cache.warnings.iter().any(|w| w.starts_with("`mitm.cert_cache_max` is deprecated")));

        // As in rusty-conduit-switch, a top-level key wins over the deprecated table.
        let both = "tcp_keepalive_retries = 7\nallow = [\"a.example\"]\n\n[tcp_keepalive]\nretries = 2\n\n\
                    [filter]\nallow = [\"b.example\"]\n";
        let p = import_rusty_conduit_switch_toml(both, "x").unwrap().proxy;
        assert_eq!(p.network.tcp_keepalive_retries, 7);
        assert_eq!(p.filter, GlobalFilterConfig::Allow(vec!["a.example".into()]));
    }

    #[test]
    fn toml_io_switch_import_rejects_conflicts() {
        let two = "[profiles.a]\ntype = \"http\"\nhost = \"h\"\nport = 1\npassword = \"x\"\npassword_env = \"Y\"";
        assert!(matches!(import_rusty_conduit_switch_toml(two, "x"), Err(TomlImportError::Invalid { .. })));
        let builtin = "[profiles.direct]\ntype = \"http\"";
        assert!(matches!(import_rusty_conduit_switch_toml(builtin, "x"), Err(TomlImportError::Invalid { .. })));
        let kind = "[profiles.a]\ntype = \"socks4\"";
        assert!(matches!(import_rusty_conduit_switch_toml(kind, "x"), Err(TomlImportError::Invalid { .. })));
    }

    #[test]
    fn toml_io_switch_export_uses_password_env_and_tunnel_placeholders() {
        let (tunnel, _) = ssh_pair();
        let mut imported = import_rusty_conduit_switch_toml(SWITCH_TOML, "auto").unwrap().proxy;
        // As the controller does after storing the extracted secret in the Vault.
        let corp = imported.profiles.iter_mut().find(|x| x.name == "corp").unwrap();
        corp.password = Some(UpstreamPasswordSource::Vault(SecretRef::new()));
        imported.profiles.push(UpstreamProfile {
            name: "ssh-hop".into(),
            kind: UpstreamKind::Tunnel { tunnel_id: tunnel.id },
            host: None,
            port: None,
            username: None,
            password: None,
            bypass: Vec::new(),
            color: None,
        });
        imported.mitm = Some(MitmConfig { ca: Some(MitmCaId::new()), ..MitmConfig::default() });

        let out = export_rusty_conduit_switch_toml(&imported, std::slice::from_ref(&tunnel)).unwrap();
        let toml = &out.toml;
        assert!(toml.contains("password_env = \"CONDUIT_UPSTREAM_CORP_PASSWORD\""), "{toml}");
        assert!(!toml.contains("switch-inline-secret"));
        assert!(!toml.lines().any(|l| l.trim_start().starts_with("password =")));
        assert!(toml.contains("# [profiles.ssh-hop]") || toml.contains("# [profiles.\"ssh-hop\"]"), "{toml}");
        assert!(toml.contains("# type = \"socks5\""));
        assert!(toml.contains("Tunnel \"corp\""));
        assert!(toml.contains("cert_cache_max_entries = "), "{toml}");
        for old in ["[tcp_keepalive]", "[filter]", "cert_cache_max = "] {
            assert!(!toml.contains(old), "export still writes the deprecated {old}: {toml}");
        }
        assert!(toml.contains("tcp_keepalive = \"45s\"") && toml.contains("tcp_keepalive_retries = 4"), "{toml}");
        assert!(toml.contains("allow = [\"*.example.com\"]"), "{toml}");
        let notes = out.notes.join("\n");
        assert!(notes.contains("CONDUIT_UPSTREAM_CORP_PASSWORD") && notes.contains("ssh-hop"));
        assert_eq!(upstream_password_env_var("my-proxy.1"), "CONDUIT_UPSTREAM_MY_PROXY_1_PASSWORD");

        // Round trip: everything but the vaulted password (now an env var) and the tunnel
        // placeholder comes back unchanged.
        assert_eq!(detect_cli_toml_format(toml), CliTomlFormat::RustyConduitSwitch);
        let back = import_rusty_conduit_switch_toml(toml, "auto").unwrap();
        assert!(back.extracted_secrets.is_empty());
        let mut expected = imported.clone();
        expected.profiles.retain(|p| p.name != "ssh-hop");
        expected.profiles.sort_by(|a, b| a.name.cmp(&b.name));
        expected.mitm = None;
        let corp = expected.profiles.iter_mut().find(|x| x.name == "corp").unwrap();
        corp.password = Some(UpstreamPasswordSource::Env("CONDUIT_UPSTREAM_CORP_PASSWORD".into()));
        assert_eq!(back.proxy, expected);
    }

    #[test]
    fn error_page_is_accepted_with_a_warning_and_never_exported() {
        let line = "error_page = \"/etc/conduit/error.html\"\n";
        let warned = |w: &[String]| {
            w.iter().any(|w| w.contains("error_page /etc/conduit/error.html was not imported"))
        };
        let conduit = import_rusty_conduit_toml(&format!("{line}{CONDUIT_TOML}"), "c").unwrap();
        assert!(warned(&conduit.warnings), "{:?}", conduit.warnings);
        let ssh = import_rusty_conduit_ssh_toml(&format!("{line}{SSH_TOML}"), "s").unwrap();
        assert!(warned(&ssh.warnings), "{:?}", ssh.warnings);
        let switch = import_rusty_conduit_switch_toml(&format!("{line}{SWITCH_TOML}"), "w").unwrap();
        assert!(warned(&switch.warnings), "{:?}", switch.warnings);

        let exports = [
            export_rusty_conduit_toml(&conduit.proxy).unwrap().toml,
            export_rusty_conduit_ssh_toml(ssh.proxy.as_ref().unwrap(), std::slice::from_ref(&ssh.tunnel))
                .unwrap()
                .toml,
            export_rusty_conduit_switch_toml(&switch.proxy, &[]).unwrap().toml,
        ];
        for toml in exports {
            assert!(!toml.contains("error_page"), "{toml}");
        }
    }

    #[test]
    fn ssh_export_v2_tunnel_target_round_trips() {
        let (tunnel, mut proxy) = ssh_pair();
        assert!(crate::v2_model::migrate_tunnel_profiles(&mut proxy));
        let wire = crate::v2_model::tunnel_target_name(tunnel.id);
        assert_eq!(only_target(&proxy.routing.default), Some(wire.as_str()));
        assert!(proxy.profiles.is_empty());

        let out = export_rusty_conduit_ssh_toml(&proxy, std::slice::from_ref(&tunnel)).unwrap();
        assert!(out.toml.contains("target = \"carol@target.example\""), "{}", out.toml);
        assert!(!out.toml.contains("@tunnel:"), "{}", out.toml);

        let back = import_rusty_conduit_ssh_toml(&out.toml, "corp").unwrap();
        let hops: Vec<_> = back.tunnel.hops.iter().map(|h| hop_label(&h.host)).collect();
        assert_eq!(hops, ["carol@target.example:2022"]);
        let mut p = back.proxy.unwrap();
        assert!(crate::v2_model::migrate_tunnel_profiles(&mut p));
        let back_wire = crate::v2_model::tunnel_target_name(back.tunnel.id);
        assert_eq!(only_target(&p.routing.default), Some(back_wire.as_str()));
        assert_eq!(p.filter, proxy.filter);
    }

    /// The commented placeholder blocks, uncommented. Prose and setup notes stay comments.
    fn uncomment_placeholders(toml: &str) -> String {
        toml.lines()
            .map(|l| match l.strip_prefix("# ") {
                Some(rest) if rest.starts_with("[profiles.") || (rest.contains(" = ") && !rest.starts_with("- ")) => rest,
                _ => l,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn switch_export_synthetic_targets_become_named_placeholders() {
        let tunnel_id = TunnelId::new();
        let forward_id = Uuid::new_v4();
        let tunnel = Tunnel {
            id: tunnel_id,
            name: "corp".into(),
            port_forwards: vec![PortForward {
                id: forward_id,
                direction: ForwardDirection::Local,
                port: 18080,
                dest_host: "proxy.internal".into(),
                dest_port: 3128,
                proxy_protocol: ForwardProxyProtocol::Http,
                ..PortForward::default()
            }],
            ..Tunnel::default()
        };
        let tunnel_wire = crate::v2_model::tunnel_target_name(tunnel_id);
        let forward_wire = crate::v2_model::forward_target_name(tunnel_id, forward_id);
        let mut proxy = import_rusty_conduit_switch_toml(SWITCH_TOML, "v2").unwrap().proxy;
        proxy.routing.default = RouteOneOrMany::Many(vec![tunnel_wire.clone(), "direct".into()]);
        proxy.routing.rules[0].target = RouteOneOrMany::One(tunnel_wire.clone());
        proxy.routing.rules[1].target = RouteOneOrMany::One(forward_wire.clone());
        let split = proxy.profiles.iter_mut().find(|p| p.name == "split").unwrap();
        split.kind = UpstreamKind::Composite {
            http: forward_wire.clone(),
            https: String::new(),
            fallback: tunnel_wire.clone(),
        };

        let out = export_rusty_conduit_switch_toml(&proxy, std::slice::from_ref(&tunnel)).unwrap();
        let live: String = out.toml.lines().filter(|l| !l.starts_with('#')).collect::<Vec<_>>().join("\n");
        assert!(!live.contains("@tunnel:") && !live.contains("@forward:"), "{}", out.toml);
        let tunnel_name = format!("tunnel-{tunnel_id}");
        let forward_name = format!("forward-{forward_id}");
        assert!(out.toml.contains("ssh -L 127.0.0.1:18080:proxy.internal:3128"), "{}", out.toml);
        let notes = out.notes.join("\n");
        assert!(notes.contains(&tunnel_name) && notes.contains(&forward_name), "{notes}");

        let back = import_rusty_conduit_switch_toml(&uncomment_placeholders(&out.toml), "v2").unwrap();
        let p = back.proxy;
        let tunnel_profile = p.profiles.iter().find(|x| x.name == tunnel_name).unwrap();
        assert_eq!(tunnel_profile.kind, UpstreamKind::Socks5);
        assert_eq!((tunnel_profile.host.as_deref(), tunnel_profile.port), (Some("127.0.0.1"), Some(1080)));
        let forward_profile = p.profiles.iter().find(|x| x.name == forward_name).unwrap();
        assert_eq!(forward_profile.kind, UpstreamKind::Http);
        assert_eq!((forward_profile.host.as_deref(), forward_profile.port), (Some("127.0.0.1"), Some(18080)));
        assert_eq!(p.routing.default.as_slice(), [tunnel_name.as_str(), "direct"]);
        assert_eq!(only_target(&p.routing.rules[0].target), Some(tunnel_name.as_str()));
        assert_eq!(only_target(&p.routing.rules[1].target), Some(forward_name.as_str()));
        let split = p.profiles.iter().find(|x| x.name == "split").unwrap();
        assert_eq!(
            split.kind,
            UpstreamKind::Composite { http: forward_name.clone(), https: String::new(), fallback: tunnel_name.clone() }
        );
    }

    #[test]
    fn toml_io_dispatch_matches_formats() {
        let (tunnel, proxy) = ssh_pair();
        for format in [
            CliTomlFormat::RustyConduit,
            CliTomlFormat::RustyConduitSsh,
            CliTomlFormat::RustyConduitSwitch,
        ] {
            let p = if format == CliTomlFormat::RustyConduit { direct_proxy() } else { proxy.clone() };
            let out = export_cli_toml(format, &p, std::slice::from_ref(&tunnel)).unwrap();
            assert_eq!(detect_cli_toml_format(&out.toml), format, "{}", format.cli_name());
            let imported = import_cli_toml(&out.toml, format, "x").unwrap();
            let ok = matches!(
                (format, imported),
                (CliTomlFormat::RustyConduit, CliTomlImport::RustyConduit(_))
                    | (CliTomlFormat::RustyConduitSsh, CliTomlImport::RustyConduitSsh(_))
                    | (CliTomlFormat::RustyConduitSwitch, CliTomlImport::RustyConduitSwitch(_))
            );
            assert!(ok);
        }
    }

    #[test]
    fn toml_io_switch_export_round_trips_bypass_mitm() {
        let mut imported = import_rusty_conduit_switch_toml(SWITCH_TOML, "auto").unwrap().proxy;
        imported.routing.rules[0].bypass_mitm = true;
        let out = export_rusty_conduit_switch_toml(&imported, &[]).unwrap();
        assert!(out.toml.contains("bypass_mitm = true"), "export must write bypass_mitm: {}", out.toml);
        assert!(
            !out.notes.iter().any(|n| n.contains("MITM bypass")),
            "no MITM bypass note expected, got {:?}",
            out.notes
        );
        let back = import_rusty_conduit_switch_toml(&out.toml, "auto").unwrap();
        assert!(back.proxy.routing.rules[0].bypass_mitm);
        assert!(!back.proxy.routing.rules[1].bypass_mitm);
    }
}
