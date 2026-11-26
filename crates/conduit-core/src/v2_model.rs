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

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::model::{
    ForwardDirection, HopEntry, LoggingConfig, MitmConfig, OpenSshOptions, PortForward,
    ReverseConfig, SecretRef, SshEngine, TunnelConfig,
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

/// A saved SSH tunnel: hops, reverse proxy, port forwards, and keepalive. The last
/// [`HopEntry`] is the SSH target.
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
    #[serde(default)]
    pub reverse: ReverseConfig,
    #[serde(default)]
    pub port_forwards: Vec<PortForward>,
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
            reverse: ReverseConfig::default(),
            port_forwards: Vec::new(),
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
}
