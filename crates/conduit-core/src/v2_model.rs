//! `conduit-core` — the v2 data model: [`Tunnel`], [`Proxy`], [`UpstreamProfile`], and routing.
//!
//! The v1 [`SessionProfile`](crate::SessionProfile) bundles an SSH connection and a proxy in one
//! document. U2 splits it: a [`Tunnel`] is the SSH half (hops, reverse proxy, port forwards,
//! keepalive) and a [`Proxy`] is the proxy half (listeners, upstream profiles, routing, filter,
//! MITM). An [`UpstreamKind::Tunnel`] profile lets a Proxy route through a Tunnel.
//!
//! The routing types mirror `rusty_conduit_engine::routing` (`RuleConfig`, `RoutingTableConfig`,
//! `RoutingConfig`) field for field, but add `Serialize` so they can be stored in `config.json`.
//! The v1 types stay in place until U3 switches the runtime and UI over.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::model::{
    ForwardConfig, ForwardDirection, HopEntry, LoggingConfig, MitmConfig, OpenSshOptions,
    PortForward, ReverseConfig, SecretRef, SshEngine, TunnelConfig,
};

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

fn enabled_by_default() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Identifiers.
// ---------------------------------------------------------------------------

/// Stable identifier of a [`Tunnel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TunnelId(Uuid);

impl TunnelId {
    pub fn new() -> Self {
        TunnelId(Uuid::new_v4())
    }

    pub fn from_uuid(uuid: Uuid) -> Self {
        TunnelId(uuid)
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl std::fmt::Display for TunnelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Default for TunnelId {
    fn default() -> Self {
        TunnelId(Uuid::nil())
    }
}

/// Stable identifier of a [`Proxy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProxyId(Uuid);

impl ProxyId {
    pub fn new() -> Self {
        ProxyId(Uuid::new_v4())
    }

    pub fn from_uuid(uuid: Uuid) -> Self {
        ProxyId(uuid)
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl std::fmt::Display for ProxyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Default for ProxyId {
    fn default() -> Self {
        ProxyId(Uuid::nil())
    }
}

// ---------------------------------------------------------------------------
// Tunnel — the SSH half of a v1 session.
// ---------------------------------------------------------------------------

/// When a [`Tunnel`] runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelStartMode {
    /// Runs while a running Proxy routes through it (the default).
    #[default]
    Linked,
    /// Started and stopped by the user; `autostart` starts it with the app.
    Manual {
        #[serde(default)]
        autostart: bool,
    },
}

fn default_tunnel_forward() -> ForwardConfig {
    ForwardConfig { enabled: false, ..ForwardConfig::default() }
}

/// A saved SSH tunnel: hops, optional forward proxy, reverse proxy, port forwards, MITM, and
/// keepalive. The last [`HopEntry`] is the SSH target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tunnel {
    #[serde(default)]
    pub id: TunnelId,
    pub name: String,
    /// `false` keeps the tunnel out of Start All, autostart, and Linked starts.
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    #[serde(default)]
    pub start_mode: TunnelStartMode,
    #[serde(default)]
    pub engine: SshEngine,
    #[serde(default)]
    pub hops: Vec<HopEntry>,
    #[serde(default = "default_tunnel_forward")]
    pub forward: ForwardConfig,
    #[serde(default)]
    pub reverse: ReverseConfig,
    #[serde(default)]
    pub port_forwards: Vec<PortForward>,
    #[serde(default)]
    pub mitm: Option<MitmConfig>,
    #[serde(default)]
    pub socks_block_web: bool,
    #[serde(default)]
    pub keepalive: TunnelConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub openssh: OpenSshOptions,
}

impl Default for Tunnel {
    fn default() -> Self {
        Self {
            id: TunnelId::default(),
            name: String::new(),
            enabled: true,
            start_mode: TunnelStartMode::default(),
            engine: SshEngine::default(),
            hops: Vec::new(),
            forward: default_tunnel_forward(),
            reverse: ReverseConfig::default(),
            port_forwards: Vec::new(),
            mitm: None,
            socks_block_web: false,
            keepalive: TunnelConfig::default(),
            logging: LoggingConfig::default(),
            openssh: OpenSshOptions::default(),
        }
    }
}

impl Tunnel {
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
// Proxy — the proxy half of a v1 session.
// ---------------------------------------------------------------------------

/// Where a [`Proxy`] gets its configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceMode {
    /// Edited in the app and stored in `config.json` (the default).
    #[default]
    Managed,
    /// Read from an external engine TOML file, reloaded on change after `debounce_ms`.
    ExternalToml { path: PathBuf, debounce_ms: u64 },
}

fn default_bind() -> IpAddr {
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

/// A Proxy's local listeners. Equal ports share one muxed listener; `0` turns one off.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerConfig {
    #[serde(default = "default_bind")]
    pub bind: IpAddr,
    #[serde(default = "default_http_port")]
    pub http_port: u16,
    #[serde(default = "default_socks_port")]
    pub socks_port: u16,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            http_port: default_http_port(),
            socks_port: default_socks_port(),
            max_connections: default_max_connections(),
        }
    }
}

fn default_connect_timeout() -> Duration {
    Duration::from_secs(10)
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

/// A Proxy's outbound socket settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(default = "default_connect_timeout", with = "serde_duration")]
    pub connect_timeout: Duration,
    /// Idle time before TCP keepalive probes start (`0` = off).
    #[serde(default = "default_tcp_keepalive", with = "serde_duration")]
    pub tcp_keepalive: Duration,
    #[serde(default = "default_tcp_keepalive_interval", with = "serde_duration")]
    pub tcp_keepalive_interval: Duration,
    #[serde(default = "default_tcp_keepalive_retries")]
    pub tcp_keepalive_retries: u32,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            connect_timeout: default_connect_timeout(),
            tcp_keepalive: default_tcp_keepalive(),
            tcp_keepalive_interval: default_tcp_keepalive_interval(),
            tcp_keepalive_retries: default_tcp_keepalive_retries(),
        }
    }
}

/// A Proxy-wide allow or block list, applied before routing. Rules are stored as strings and
/// parsed in `validate`/`mapping`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GlobalFilterConfig {
    #[default]
    Off,
    Allow(Vec<String>),
    Block(Vec<String>),
    BlockExcept {
        #[serde(default)]
        block: Vec<String>,
        #[serde(default)]
        allow: Vec<String>,
    },
}

/// Where an upstream proxy's password comes from. Never stored inline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamPasswordSource {
    /// An `upstream_password` record in `vault.bin`.
    Vault(SecretRef),
    /// The named environment variable.
    Env(String),
    /// The first line of this file.
    File(PathBuf),
}

/// The type of an [`UpstreamProfile`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UpstreamKind {
    Http,
    Https {
        #[serde(default)]
        tls_insecure_skip_verify: bool,
    },
    Socks5,
    Socks4a,
    /// Per-scheme selection: each field names another profile.
    Composite {
        http: String,
        https: String,
        fallback: String,
    },
    /// An SSH [`Tunnel`] as the upstream.
    Tunnel { tunnel_id: TunnelId },
}

/// A named upstream a Proxy's routing rules can target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamProfile {
    pub name: String,
    pub kind: UpstreamKind,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<UpstreamPasswordSource>,
    /// Targets matching this list go `direct` instead.
    #[serde(default)]
    pub bypass: Vec<String>,
    /// UI accent color (e.g. `#3b82f6`).
    #[serde(default)]
    pub color: Option<String>,
}

// ---------------------------------------------------------------------------
// Routing — mirrors `rusty_conduit_engine::routing`, with `Serialize`.
// ---------------------------------------------------------------------------

/// Inbound protocol family a rule can match (engine `Inbound`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteInbound {
    Http,
    Socks,
}

/// A value written as one item or a list (engine `OneOrMany`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RouteOneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> RouteOneOrMany<T> {
    /// All values as a slice (one element for the single form).
    pub fn as_slice(&self) -> &[T] {
        match self {
            Self::One(v) => std::slice::from_ref(v),
            Self::Many(v) => v,
        }
    }
}

/// A routing target: one profile name or an ordered failover chain (engine `Target`).
pub type RouteTarget = RouteOneOrMany<String>;

/// The built-in `direct` profile name.
const ROUTE_DIRECT: &str = "direct";

fn default_route_target() -> RouteTarget {
    RouteOneOrMany::One(ROUTE_DIRECT.to_string())
}

/// One `port` matcher entry: a number or an inclusive range string (engine `PortSpec`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RoutePortSpec {
    Port(u16),
    Range(String),
}

/// `host_levels` matcher (engine `HostLevels`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteHostLevels {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<u32>,
}

/// One routing rule (engine `RuleConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound: Option<RouteInbound>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<RouteOneOrMany<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_wildcard: Option<RouteOneOrMany<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_regex: Option<RouteOneOrMany<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<RouteOneOrMany<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<RouteOneOrMany<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<RouteOneOrMany<RoutePortSpec>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_levels: Option<RouteHostLevels>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bypass: Option<RouteOneOrMany<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weekday: Option<RouteOneOrMany<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<RouteOneOrMany<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_wildcard: Option<RouteOneOrMany<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_regex: Option<RouteOneOrMany<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyword: Option<RouteOneOrMany<String>>,
    /// Matches unconditionally.
    #[serde(default)]
    pub match_all: bool,
    /// Skips the rule.
    #[serde(default)]
    pub disabled: bool,
    /// Per-rule override of [`RoutingTablesConfig::resolve_dns`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolve_dns: Option<bool>,
    pub target: RouteTarget,
}

impl RoutingRule {
    /// A rule with no matchers set, sending traffic to `target`.
    pub fn to_target(target: RouteTarget) -> Self {
        Self {
            name: None,
            inbound: None,
            host: None,
            host_wildcard: None,
            host_regex: None,
            cidr: None,
            ip: None,
            port: None,
            host_levels: None,
            bypass: None,
            weekday: None,
            time: None,
            url_wildcard: None,
            url_regex: None,
            keyword: None,
            match_all: false,
            disabled: false,
            resolve_dns: None,
            target,
        }
    }
}

/// A split `http` / `socks` override table (engine `RoutingTableConfig`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingTable {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<RouteTarget>,
    /// Fall back to the unified table when no override rule matches.
    #[serde(default)]
    pub inherit: bool,
    #[serde(default)]
    pub rules: Vec<RoutingRule>,
}

/// The unified routing table plus optional split overrides (engine `RoutingConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingTablesConfig {
    #[serde(default = "default_route_target")]
    pub default: RouteTarget,
    /// Match hostnames against IP/CIDR rules via local DNS (off by default: no DNS leaks).
    #[serde(default)]
    pub resolve_dns: bool,
    #[serde(default)]
    pub rules: Vec<RoutingRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<RoutingTable>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks: Option<RoutingTable>,
}

impl Default for RoutingTablesConfig {
    fn default() -> Self {
        Self {
            default: default_route_target(),
            resolve_dns: false,
            rules: Vec::new(),
            http: None,
            socks: None,
        }
    }
}

/// A saved proxy: listeners, upstream profiles, routing, filter, and MITM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proxy {
    #[serde(default)]
    pub id: ProxyId,
    pub name: String,
    /// `false` keeps the proxy out of Start All and autostart.
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    #[serde(default)]
    pub autostart: bool,
    #[serde(default)]
    pub source: SourceMode,
    #[serde(default)]
    pub listeners: ListenerConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub profiles: Vec<UpstreamProfile>,
    #[serde(default)]
    pub routing: RoutingTablesConfig,
    #[serde(default)]
    pub filter: GlobalFilterConfig,
    /// Block HTTP/HTTPS traffic over SOCKS4/4a/5 (works with or without MITM).
    #[serde(default)]
    pub socks_block_web: bool,
    #[serde(default)]
    pub mitm: Option<MitmConfig>,
    #[serde(default)]
    pub logging: LoggingConfig,
}

impl Default for Proxy {
    fn default() -> Self {
        Self {
            id: ProxyId::default(),
            name: String::new(),
            enabled: true,
            autostart: false,
            source: SourceMode::default(),
            listeners: ListenerConfig::default(),
            network: NetworkConfig::default(),
            profiles: Vec::new(),
            routing: RoutingTablesConfig::default(),
            filter: GlobalFilterConfig::default(),
            socks_block_web: false,
            mitm: None,
            logging: LoggingConfig::default(),
        }
    }
}

/// Prefix for synthetic routing targets pointing directly at an SSH [`Tunnel`].
pub const TUNNEL_TARGET_PREFIX: &str = "@tunnel:";

/// Prefix for synthetic routing targets pointing at a tagged local (`-L`) [`PortForward`] on a
/// [`Tunnel`].
pub const FORWARD_TARGET_PREFIX: &str = "@forward:";

/// Build the wire target string for routing directly through a [`Tunnel`].
pub fn tunnel_target_name(tunnel_id: TunnelId) -> String {
    format!("{TUNNEL_TARGET_PREFIX}{tunnel_id}")
}

/// Build the wire target string for routing through a tagged local (`-L`) [`PortForward`] on a
/// [`Tunnel`].
pub fn forward_target_name(tunnel_id: TunnelId, forward_id: Uuid) -> String {
    format!("{FORWARD_TARGET_PREFIX}{tunnel_id}:{forward_id}")
}

/// Parsed form of one routing target string in a [`RouteTarget`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TargetRef {
    Direct,
    Block,
    Tunnel(TunnelId),
    TunnelForward { tunnel_id: TunnelId, forward_id: Uuid },
    Profile(String),
}

impl TargetRef {
    /// Parse a wire target name into its structured form.
    pub fn parse(raw: &str) -> Self {
        if raw == ROUTE_DIRECT {
            return Self::Direct;
        }
        if raw == "block" {
            return Self::Block;
        }
        if let Some(rest) = raw.strip_prefix(TUNNEL_TARGET_PREFIX) {
            if let Ok(uuid) = Uuid::parse_str(rest) {
                return Self::Tunnel(TunnelId::from_uuid(uuid));
            }
        }
        if let Some(rest) = raw.strip_prefix(FORWARD_TARGET_PREFIX) {
            if let Some((t_str, f_str)) = rest.split_once(':') {
                if let (Ok(tunnel_uuid), Ok(forward_id)) =
                    (Uuid::parse_str(t_str), Uuid::parse_str(f_str))
                {
                    return Self::TunnelForward {
                        tunnel_id: TunnelId::from_uuid(tunnel_uuid),
                        forward_id,
                    };
                }
            }
        }
        Self::Profile(raw.to_string())
    }

    /// Format this target back to its wire string.
    pub fn to_wire(&self) -> String {
        match self {
            Self::Direct => ROUTE_DIRECT.to_string(),
            Self::Block => "block".to_string(),
            Self::Tunnel(id) => tunnel_target_name(*id),
            Self::TunnelForward { tunnel_id, forward_id } => {
                forward_target_name(*tunnel_id, *forward_id)
            }
            Self::Profile(name) => name.clone(),
        }
    }
}

fn rewrite_target(target: &mut RouteTarget, rewrites: &BTreeMap<String, String>) {
    match target {
        RouteOneOrMany::One(name) => {
            if let Some(replacement) = rewrites.get(name.as_str()) {
                *name = replacement.clone();
            }
        }
        RouteOneOrMany::Many(names) => {
            for name in names {
                if let Some(replacement) = rewrites.get(name.as_str()) {
                    *name = replacement.clone();
                }
            }
        }
    }
}

fn rewrite_table(table: &mut RoutingTable, rewrites: &BTreeMap<String, String>) {
    if let Some(default) = &mut table.default {
        rewrite_target(default, rewrites);
    }
    for rule in &mut table.rules {
        rewrite_target(&mut rule.target, rewrites);
    }
}

/// Rewrite references to any [`UpstreamKind::Tunnel`] profile in `proxy.routing` and composite
/// profiles to `@tunnel:<id>`, then remove the redundant [`UpstreamKind::Tunnel`] entries from
/// `proxy.profiles`. Returns `true` if the proxy was modified.
pub fn migrate_tunnel_profiles(proxy: &mut Proxy) -> bool {
    let mut rewrites: BTreeMap<String, String> = BTreeMap::new();
    for profile in &proxy.profiles {
        if let UpstreamKind::Tunnel { tunnel_id } = profile.kind {
            rewrites.insert(profile.name.clone(), tunnel_target_name(tunnel_id));
        }
    }
    if rewrites.is_empty() {
        return false;
    }

    rewrite_target(&mut proxy.routing.default, &rewrites);
    for rule in &mut proxy.routing.rules {
        rewrite_target(&mut rule.target, &rewrites);
    }
    if let Some(http) = &mut proxy.routing.http {
        rewrite_table(http, &rewrites);
    }
    if let Some(socks) = &mut proxy.routing.socks {
        rewrite_table(socks, &rewrites);
    }
    for profile in &mut proxy.profiles {
        if let UpstreamKind::Composite { http, https, fallback } = &mut profile.kind {
            for slot in [http, https, fallback] {
                if let Some(replacement) = rewrites.get(slot.as_str()) {
                    *slot = replacement.clone();
                }
            }
        }
    }
    proxy.profiles.retain(|p| !matches!(p.kind, UpstreamKind::Tunnel { .. }));
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn round_trip<T>(value: &T) -> T
    where
        T: Serialize + for<'de> Deserialize<'de>,
    {
        let text = serde_json::to_string(value).unwrap();
        serde_json::from_str(&text).unwrap()
    }

    #[test]
    fn ids_follow_the_newtype_pattern() {
        assert_eq!(TunnelId::default().as_uuid(), Uuid::nil());
        assert_eq!(ProxyId::default().as_uuid(), Uuid::nil());
        let uuid = Uuid::new_v4();
        let id = TunnelId::from_uuid(uuid);
        assert_eq!(id.as_uuid(), uuid);
        assert_eq!(id.to_string(), uuid.to_string());
        assert_ne!(TunnelId::new(), TunnelId::new());
        assert_eq!(ProxyId::from_uuid(uuid).to_string(), uuid.to_string());
        let copied = id;
        assert_eq!(copied, id);
        assert_eq!(round_trip(&id), id);
        assert_eq!(serde_json::to_value(id).unwrap(), json!(uuid.to_string()));
    }

    #[test]
    fn tunnel_defaults_to_linked_and_enabled() {
        let tunnel: Tunnel = serde_json::from_value(json!({ "name": "corp" })).unwrap();
        assert_eq!(tunnel.start_mode, TunnelStartMode::Linked);
        assert!(tunnel.enabled);
        assert!(!tunnel.forward.enabled);
        assert_eq!(tunnel.mitm, None);
        assert!(!tunnel.socks_block_web);
        assert_eq!(tunnel.id, TunnelId::default());
        assert_eq!(tunnel, Tunnel { name: "corp".into(), ..Tunnel::default() });
    }

    #[test]
    fn tunnel_round_trips() {
        let tunnel = Tunnel {
            id: TunnelId::new(),
            name: "bastion".into(),
            enabled: false,
            start_mode: TunnelStartMode::Manual { autostart: true },
            port_forwards: vec![PortForward::default()],
            ..Tunnel::default()
        };
        assert_eq!(round_trip(&tunnel), tunnel);
        let manual: TunnelStartMode = serde_json::from_value(json!({ "manual": {} })).unwrap();
        assert_eq!(manual, TunnelStartMode::Manual { autostart: false });
        assert_eq!(serde_json::to_value(TunnelStartMode::Linked).unwrap(), json!("linked"));
    }

    #[test]
    fn tunnel_active_forwards_filter_enabled_and_direction() {
        let on_local = PortForward {
            enabled: true,
            direction: ForwardDirection::Local,
            ..PortForward::default()
        };
        let on_remote = PortForward {
            enabled: true,
            direction: ForwardDirection::Remote,
            ..PortForward::default()
        };
        let off = PortForward { enabled: false, ..PortForward::default() };
        let tunnel = Tunnel {
            port_forwards: vec![on_local, on_remote, off],
            ..Tunnel::default()
        };
        assert_eq!(tunnel.active_forwards().count(), 2);
        assert_eq!(tunnel.active_forwards_in(ForwardDirection::Local).count(), 1);
        assert_eq!(tunnel.active_forwards_in(ForwardDirection::Remote).count(), 1);
    }

    #[test]
    fn proxy_defaults() {
        let proxy: Proxy = serde_json::from_value(json!({ "name": "main" })).unwrap();
        assert!(proxy.enabled);
        assert!(!proxy.autostart);
        assert_eq!(proxy.source, SourceMode::Managed);
        assert_eq!(proxy.listeners.bind, IpAddr::V4("127.0.0.1".parse().unwrap()));
        assert_eq!(proxy.listeners.http_port, 3128);
        assert_eq!(proxy.listeners.socks_port, 1080);
        assert_eq!(proxy.listeners.max_connections, 4096);
        assert_eq!(proxy.network.connect_timeout, Duration::from_secs(10));
        assert_eq!(proxy.network.tcp_keepalive, Duration::from_secs(60));
        assert_eq!(proxy.network.tcp_keepalive_interval, Duration::from_secs(10));
        assert_eq!(proxy.network.tcp_keepalive_retries, 5);
        assert_eq!(proxy.routing.default.as_slice(), ["direct".to_string()]);
        assert!(!proxy.routing.resolve_dns);
        assert_eq!(proxy.filter, GlobalFilterConfig::Off);
        assert!(proxy.mitm.is_none());
        assert_eq!(proxy, Proxy { name: "main".into(), ..Proxy::default() });
    }

    #[test]
    fn network_durations_are_seconds() {
        let value = serde_json::to_value(NetworkConfig::default()).unwrap();
        assert_eq!(value["connect_timeout"], json!(10));
        assert_eq!(value["tcp_keepalive"], json!(60));
    }

    #[test]
    fn proxy_round_trips() {
        let tunnel_id = TunnelId::new();
        let mut proxy = Proxy {
            id: ProxyId::new(),
            name: "work".into(),
            autostart: true,
            source: SourceMode::ExternalToml {
                path: PathBuf::from("/etc/conduit/proxy.toml"),
                debounce_ms: 250,
            },
            filter: GlobalFilterConfig::Block(vec!["*.ads.example".into()]),
            mitm: Some(MitmConfig::default()),
            ..Proxy::default()
        };
        proxy.profiles = vec![
            UpstreamProfile {
                name: "corp".into(),
                kind: UpstreamKind::Https { tls_insecure_skip_verify: true },
                host: Some("proxy.corp.example".into()),
                port: Some(8443),
                username: Some("me".into()),
                password: Some(UpstreamPasswordSource::Vault(SecretRef::new())),
                bypass: vec!["localhost".into()],
                color: Some("#3b82f6".into()),
            },
            UpstreamProfile {
                name: "ssh".into(),
                kind: UpstreamKind::Tunnel { tunnel_id },
                host: None,
                port: None,
                username: None,
                password: None,
                bypass: Vec::new(),
                color: None,
            },
            UpstreamProfile {
                name: "split".into(),
                kind: UpstreamKind::Composite {
                    http: "corp".into(),
                    https: "ssh".into(),
                    fallback: "direct".into(),
                },
                host: None,
                port: None,
                username: None,
                password: Some(UpstreamPasswordSource::Env("PROXY_PW".into())),
                bypass: Vec::new(),
                color: None,
            },
        ];
        let mut rule = RoutingRule::to_target(RouteOneOrMany::Many(vec![
            "corp".into(),
            "ssh".into(),
        ]));
        rule.name = Some("intranet".into());
        rule.inbound = Some(RouteInbound::Http);
        rule.host_wildcard = Some(RouteOneOrMany::One("*.corp.example".into()));
        rule.port = Some(RouteOneOrMany::Many(vec![
            RoutePortSpec::Port(443),
            RoutePortSpec::Range("8000-8080".into()),
        ]));
        rule.host_levels = Some(RouteHostLevels { min: Some(2), max: None });
        rule.resolve_dns = Some(true);
        proxy.routing.rules.push(rule);
        proxy.routing.socks = Some(RoutingTable {
            default: Some(RouteOneOrMany::One("ssh".into())),
            inherit: true,
            rules: vec![RoutingRule::to_target(RouteOneOrMany::One("block".into()))],
        });
        assert_eq!(round_trip(&proxy), proxy);
    }

    #[test]
    fn upstream_kind_wire_shape() {
        assert_eq!(serde_json::to_value(UpstreamKind::Socks5).unwrap(), json!({ "type": "socks5" }));
        let https: UpstreamKind = serde_json::from_value(json!({ "type": "https" })).unwrap();
        assert_eq!(https, UpstreamKind::Https { tls_insecure_skip_verify: false });
        for kind in [UpstreamKind::Http, UpstreamKind::Socks4a] {
            assert_eq!(round_trip(&kind), kind);
        }
        let file = UpstreamPasswordSource::File(PathBuf::from("/run/secrets/pw"));
        assert_eq!(round_trip(&file), file);
    }

    #[test]
    fn routing_rule_reads_engine_shaped_json() {
        let rule: RoutingRule = serde_json::from_value(json!({
            "host": ["a.example", "b.example"],
            "cidr": "10.0.0.0/8",
            "port": 443,
            "inbound": "socks",
            "match_all": true,
            "target": "corp",
        }))
        .unwrap();
        assert_eq!(rule.host.as_ref().unwrap().as_slice().len(), 2);
        assert_eq!(rule.cidr.as_ref().unwrap().as_slice(), ["10.0.0.0/8".to_string()]);
        assert_eq!(rule.port.as_ref().unwrap().as_slice(), [RoutePortSpec::Port(443)]);
        assert_eq!(rule.inbound, Some(RouteInbound::Socks));
        assert!(rule.match_all);
        assert!(!rule.disabled);
        assert_eq!(rule.target.as_slice(), ["corp".to_string()]);
        // Unset matchers are left out when written.
        let written = serde_json::to_value(&rule).unwrap();
        assert!(written.get("keyword").is_none());
    }

    #[test]
    fn global_filter_round_trips() {
        for filter in [
            GlobalFilterConfig::Off,
            GlobalFilterConfig::Allow(vec!["example.com".into()]),
            GlobalFilterConfig::Block(vec![]),
        ] {
            assert_eq!(round_trip(&filter), filter);
        }
    }

    #[test]
    fn target_ref_parses_and_formats_all_variants() {
        let tid = TunnelId::new();
        let fid = Uuid::new_v4();
        let cases = [
            ("direct".to_string(), TargetRef::Direct),
            ("block".to_string(), TargetRef::Block),
            (tunnel_target_name(tid), TargetRef::Tunnel(tid)),
            (forward_target_name(tid, fid), TargetRef::TunnelForward { tunnel_id: tid, forward_id: fid }),
            ("corp".to_string(), TargetRef::Profile("corp".into())),
            ("@tunnel:not-a-uuid".to_string(), TargetRef::Profile("@tunnel:not-a-uuid".into())),
            ("@forward:not-a-uuid".to_string(), TargetRef::Profile("@forward:not-a-uuid".into())),
        ];
        for (wire, parsed) in cases {
            assert_eq!(TargetRef::parse(&wire), parsed);
            assert_eq!(parsed.to_wire(), wire);
        }
    }

    #[test]
    fn migrate_tunnel_profiles_rewrites_all_refs_and_removes_tunnel_entries() {
        let tid = TunnelId::new();
        let wire = tunnel_target_name(tid);
        let mut proxy = Proxy {
            name: "work".into(),
            profiles: vec![
                UpstreamProfile {
                    name: "corp".into(),
                    kind: UpstreamKind::Http,
                    host: Some("127.0.0.1".into()),
                    port: Some(8080),
                    username: None,
                    password: None,
                    bypass: Vec::new(),
                    color: None,
                },
                UpstreamProfile {
                    name: "ssh".into(),
                    kind: UpstreamKind::Tunnel { tunnel_id: tid },
                    host: None,
                    port: None,
                    username: None,
                    password: None,
                    bypass: Vec::new(),
                    color: None,
                },
                UpstreamProfile {
                    name: "split".into(),
                    kind: UpstreamKind::Composite {
                        http: "corp".into(),
                        https: "ssh".into(),
                        fallback: "ssh".into(),
                    },
                    host: None,
                    port: None,
                    username: None,
                    password: None,
                    bypass: Vec::new(),
                    color: None,
                },
            ],
            routing: RoutingTablesConfig {
                default: RouteOneOrMany::One("ssh".into()),
                resolve_dns: false,
                rules: vec![RoutingRule::to_target(RouteOneOrMany::Many(vec![
                    "corp".into(),
                    "ssh".into(),
                ]))],
                http: Some(RoutingTable {
                    default: Some(RouteOneOrMany::One("ssh".into())),
                    inherit: true,
                    rules: vec![RoutingRule::to_target(RouteOneOrMany::One("ssh".into()))],
                }),
                socks: Some(RoutingTable {
                    default: Some(RouteOneOrMany::Many(vec!["ssh".into(), "direct".into()])),
                    inherit: false,
                    rules: vec![RoutingRule::to_target(RouteOneOrMany::One("direct".into()))],
                }),
            },
            ..Proxy::default()
        };

        assert!(migrate_tunnel_profiles(&mut proxy));
        assert!(!migrate_tunnel_profiles(&mut proxy));
        assert_eq!(proxy.profiles.len(), 2);
        assert!(proxy.profiles.iter().all(|p| !matches!(p.kind, UpstreamKind::Tunnel { .. })));
        assert_eq!(proxy.routing.default, RouteOneOrMany::One(wire.clone()));
        assert_eq!(
            proxy.routing.rules[0].target,
            RouteOneOrMany::Many(vec!["corp".into(), wire.clone()])
        );
        let http = proxy.routing.http.as_ref().unwrap();
        assert_eq!(http.default, Some(RouteOneOrMany::One(wire.clone())));
        assert_eq!(http.rules[0].target, RouteOneOrMany::One(wire.clone()));
        let socks = proxy.routing.socks.as_ref().unwrap();
        assert_eq!(socks.default, Some(RouteOneOrMany::Many(vec![wire.clone(), "direct".into()])));
        assert_eq!(
            proxy.profiles[1].kind,
            UpstreamKind::Composite {
                http: "corp".into(),
                https: wire.clone(),
                fallback: wire,
            }
        );
    }
}
