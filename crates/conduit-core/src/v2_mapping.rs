//! `conduit-core` — mapping a v2 [`Tunnel`] / [`Proxy`] into engine option types.
//!
//! A [`Tunnel`] maps into the same [`EngineConfig`] the v1 session path uses, with the forward
//! listener switched off. A [`Proxy`] maps into a [`RoutingInput`] (profiles, routing tables,
//! global filter, listeners, keepalive, connect timeout), [`ServerOptions`] for its listeners,
//! and optional [`MitmOptions`]. An [`UpstreamKind::Tunnel`] profile becomes
//! [`ProfileType::External`]: the runtime registers the Tunnel's dialer under that name.
//! Vaulted upstream passwords are resolved by the runtime and passed in; this crate never
//! touches the vault.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::str::FromStr;

use rusty_conduit_engine::logging::{LogFormat, LogLevel};
use rusty_conduit_engine::mitm::{MitmOptions, UpstreamTlsVerification};
use rusty_conduit_engine::net::KeepaliveSettings;
use rusty_conduit_engine::routing::{
    HostLevels, Inbound, OneOrMany, PortSpec, ProfileConfig, ProfileType, RoutingConfig,
    RoutingInput, RoutingTableConfig, RuleConfig,
};
use rusty_conduit_engine::server::ServerOptions;
use rusty_conduit_engine::filter::HostFilter;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::mapping::{host_filter, mitm_bypass_hosts, mitm_upstream_tls, parse_rules};
use crate::model::SecretRef;
use crate::v2_model::{
    GlobalFilterConfig, Proxy, RouteHostLevels, RouteInbound, RouteOneOrMany, RoutePortSpec,
    RoutingRule, RoutingTable, RoutingTablesConfig, TargetRef, Tunnel, TunnelId, UpstreamKind,
    UpstreamPasswordSource, UpstreamProfile,
};
use crate::{EngineConfig, MappingError, SshIpVersion};

/// Compile a [`Tunnel`]'s forward allow/block rules into a [`HostFilter`]. Always active even
/// when `tunnel.forward.enabled == false` so Proxy traffic routed through the tunnel is filtered.
pub fn tunnel_forward_filter(tunnel: &Tunnel) -> Result<Option<HostFilter>, MappingError> {
    Ok(host_filter(
        parse_rules("forward", &tunnel.forward.allow)?,
        parse_rules("forward", &tunnel.forward.block)?,
    ))
}

/// Map a [`Tunnel`] into an [`EngineConfig`]: forward listener (when enabled), always-compiled
/// forward filter, conditional MITM (only when `forward.enabled && tunnel.mitm.is_some()`),
/// reverse listeners, keepalive, logging, and SSH IP version.
pub fn tunnel_to_engine_config(tunnel: &Tunnel) -> Result<EngineConfig, MappingError> {
    if tunnel.hops.is_empty() {
        return Err(MappingError::NoHops);
    }
    let forward = &tunnel.forward;
    let forward_filter = tunnel_forward_filter(tunnel)?;
    let reverse = &tunnel.reverse;
    let reverse_filter = host_filter(
        parse_rules("reverse", &reverse.reverse_allow)?,
        parse_rules("reverse", &reverse.reverse_block)?,
    );
    let ssh_ip_version = SshIpVersion::from_str(&tunnel.keepalive.ip_version)
        .map_err(MappingError::InvalidIpVersion)?;
    let log_level =
        LogLevel::from_str(&tunnel.logging.level).map_err(MappingError::InvalidLogLevel)?;
    let log_format =
        LogFormat::from_str(&tunnel.logging.format).map_err(MappingError::InvalidLogFormat)?;

    let k = &tunnel.keepalive;
    let keepalive = (!k.tcp_keepalive.is_zero()).then_some(KeepaliveSettings {
        idle: k.tcp_keepalive,
        interval: k.tcp_keepalive_interval,
        retries: k.tcp_keepalive_retries,
    });
    let (http_port, socks_port) = forward.effective_ports();
    let (reverse_http_port, reverse_socks_port) = reverse.effective_ports();
    let mitm_enabled = forward.enabled && tunnel.mitm.is_some();
    let defaults = MitmOptions::default();
    let mitm_options = MitmOptions {
        ca: None,
        passphrase: None,
        passphrase_file: None,
        cert_ttl: if mitm_enabled {
            tunnel.mitm.as_ref().map_or(defaults.cert_ttl, |m| m.cert_ttl)
        } else {
            defaults.cert_ttl
        },
        cert_cache_max: if mitm_enabled {
            tunnel.mitm.as_ref().map_or(defaults.cert_cache_max, |m| m.cert_cache_max_entries)
        } else {
            defaults.cert_cache_max
        },
        upstream_tls: match &tunnel.mitm {
            Some(m) if mitm_enabled => mitm_upstream_tls(m)?,
            _ => UpstreamTlsVerification::Strict,
        },
        bypass_hosts: match &tunnel.mitm {
            Some(m) if mitm_enabled => mitm_bypass_hosts(m)?,
            _ => Vec::new(),
        },
    };
    let socks_block_web_in_mitm = tunnel.socks_block_web
        || (mitm_enabled && tunnel.mitm.as_ref().is_some_and(|m| m.socks_block_web));

    Ok(EngineConfig {
        forward_server: ServerOptions {
            bind: forward.bind,
            http_port,
            socks_port,
            max_connections: forward.max_connections,
            keepalive,
        },
        forward_enabled: http_port != 0 || socks_port != 0,
        forward_filter,
        reverse_bind: reverse.reverse_bind,
        reverse_http_port,
        reverse_socks_port,
        reverse_max_connections: reverse
            .reverse_max_connections
            .unwrap_or(forward.max_connections),
        reverse_enabled: reverse_http_port != 0 || reverse_socks_port != 0,
        reverse_filter,
        keepalive,
        mitm_enabled,
        mitm_options,
        socks_block_web_in_mitm,
        log_level,
        log_format,
        http_access_log: tunnel.logging.http_access_log.clone(),
        socks_log: tunnel.logging.socks_log.clone(),
        ssh_ip_version,
    })
}

/// The Proxy's TCP keepalive (`None` when `tcp_keepalive` is `0`).
fn proxy_keepalive(proxy: &Proxy) -> Option<KeepaliveSettings> {
    let n = &proxy.network;
    (!n.tcp_keepalive.is_zero()).then_some(KeepaliveSettings {
        idle: n.tcp_keepalive,
        interval: n.tcp_keepalive_interval,
        retries: n.tcp_keepalive_retries,
    })
}

/// Map a Proxy's listeners and network keepalive into engine [`ServerOptions`].
pub fn proxy_server_options(proxy: &Proxy) -> ServerOptions {
    let l = &proxy.listeners;
    ServerOptions {
        bind: l.bind,
        http_port: l.http_port,
        socks_port: l.socks_port,
        max_connections: l.max_connections,
        keepalive: proxy_keepalive(proxy),
    }
}

/// Map a Proxy's MITM settings into [`MitmOptions`] (`Ok(None)` when MITM is off). `ca` is
/// always `None`: the runtime loads the CA in memory from the vault. Fails on a malformed
/// `insecure_hosts` rule in `Allowlist` mode or a malformed `bypass_hosts` rule.
pub fn proxy_mitm_options(proxy: &Proxy) -> Result<Option<MitmOptions>, MappingError> {
    proxy
        .mitm
        .as_ref()
        .map(|m| {
            Ok(MitmOptions {
                ca: None,
                passphrase: None,
                passphrase_file: None,
                cert_ttl: m.cert_ttl,
                cert_cache_max: m.cert_cache_max_entries,
                upstream_tls: mitm_upstream_tls(m)?,
                bypass_hosts: mitm_bypass_hosts(m)?,
            })
        })
        .transpose()
}

fn push_target_refs(target: &RouteOneOrMany<String>, out: &mut Vec<TargetRef>) {
    for raw in target.as_slice() {
        let parsed = TargetRef::parse(raw);
        if !out.contains(&parsed) {
            out.push(parsed);
        }
    }
}

fn push_table_refs(table: &RoutingTable, out: &mut Vec<TargetRef>) {
    if let Some(default) = &table.default {
        push_target_refs(default, out);
    }
    for rule in &table.rules {
        push_target_refs(&rule.target, out);
    }
}

/// Every distinct [`TargetRef`] referenced by a Proxy's routing tables (unified, HTTP, and SOCKS
/// defaults and rules) and composite upstream profiles, in encounter order.
pub fn proxy_referenced_targets(proxy: &Proxy) -> Vec<TargetRef> {
    let mut out = Vec::new();
    push_target_refs(&proxy.routing.default, &mut out);
    for rule in &proxy.routing.rules {
        push_target_refs(&rule.target, &mut out);
    }
    if let Some(http) = &proxy.routing.http {
        push_table_refs(http, &mut out);
    }
    if let Some(socks) = &proxy.routing.socks {
        push_table_refs(socks, &mut out);
    }
    for p in &proxy.profiles {
        if let UpstreamKind::Composite { http, https, fallback } = &p.kind {
            for slot in [http, https, fallback] {
                if !slot.is_empty() {
                    let parsed = TargetRef::parse(slot);
                    if !out.contains(&parsed) {
                        out.push(parsed);
                    }
                }
            }
        }
    }
    out
}

/// Every distinct Tunnel the Proxy routes through (via `UpstreamKind::Tunnel` profiles or
/// `@tunnel:<id>` / `@forward:<tid>:<fid>` routing targets), in encounter order.
pub fn proxy_referenced_tunnels(proxy: &Proxy) -> Vec<TunnelId> {
    let mut out = Vec::new();
    for p in &proxy.profiles {
        if let UpstreamKind::Tunnel { tunnel_id } = p.kind {
            if !out.contains(&tunnel_id) {
                out.push(tunnel_id);
            }
        }
    }
    for target in proxy_referenced_targets(proxy) {
        let tunnel_id = match target {
            TargetRef::Tunnel(id) | TargetRef::TunnelForward { tunnel_id: id, .. } => id,
            _ => continue,
        };
        if !out.contains(&tunnel_id) {
            out.push(tunnel_id);
        }
    }
    out
}

/// Every distinct `(TunnelId, forward Uuid)` referenced via `@forward:<tid>:<fid>` in `proxy`.
pub fn proxy_referenced_forwards(proxy: &Proxy) -> Vec<(TunnelId, Uuid)> {
    let mut out = Vec::new();
    for target in proxy_referenced_targets(proxy) {
        if let TargetRef::TunnelForward { tunnel_id, forward_id } = target {
            let pair = (tunnel_id, forward_id);
            if !out.contains(&pair) {
                out.push(pair);
            }
        }
    }
    out
}

/// `(profile name, vault SecretRef)` for every profile whose password lives in the vault.
pub fn proxy_vault_secret_refs(proxy: &Proxy) -> Vec<(String, SecretRef)> {
    proxy
        .profiles
        .iter()
        .filter_map(|p| match &p.password {
            Some(UpstreamPasswordSource::Vault(secret)) => Some((p.name.clone(), secret.clone())),
            _ => None,
        })
        .collect()
}

fn one_or_many<T: Clone>(v: &RouteOneOrMany<T>) -> OneOrMany<T> {
    match v {
        RouteOneOrMany::One(x) => OneOrMany::One(x.clone()),
        RouteOneOrMany::Many(x) => OneOrMany::Many(x.clone()),
    }
}

fn port_spec(p: &RoutePortSpec) -> PortSpec {
    match p {
        RoutePortSpec::Port(n) => PortSpec::Port(*n),
        RoutePortSpec::Range(r) => PortSpec::Range(r.clone()),
    }
}

fn inbound(i: RouteInbound) -> Inbound {
    match i {
        RouteInbound::Http => Inbound::Http,
        RouteInbound::Socks => Inbound::Socks,
    }
}

fn host_levels(h: RouteHostLevels) -> HostLevels {
    HostLevels { min: h.min, max: h.max }
}

/// Convert one stored [`RoutingRule`] into an engine [`RuleConfig`].
pub(crate) fn rule_config(r: &RoutingRule) -> RuleConfig {
    let strings = |v: &Option<RouteOneOrMany<String>>| v.as_ref().map(one_or_many);
    RuleConfig {
        name: r.name.clone(),
        inbound: r.inbound.map(inbound),
        host: strings(&r.host),
        host_wildcard: strings(&r.host_wildcard),
        host_regex: strings(&r.host_regex),
        cidr: strings(&r.cidr),
        ip: strings(&r.ip),
        port: r.port.as_ref().map(|p| match p {
            RouteOneOrMany::One(x) => OneOrMany::One(port_spec(x)),
            RouteOneOrMany::Many(x) => OneOrMany::Many(x.iter().map(port_spec).collect()),
        }),
        host_levels: r.host_levels.map(host_levels),
        bypass: strings(&r.bypass),
        weekday: strings(&r.weekday),
        time: strings(&r.time),
        url_wildcard: strings(&r.url_wildcard),
        url_regex: strings(&r.url_regex),
        keyword: strings(&r.keyword),
        match_all: r.match_all,
        disabled: r.disabled,
        resolve_dns: r.resolve_dns,
        bypass_mitm: r.bypass_mitm,
        target: one_or_many(&r.target),
    }
}

fn table_config(t: &RoutingTable) -> RoutingTableConfig {
    RoutingTableConfig {
        default: t.default.as_ref().map(one_or_many),
        inherit: t.inherit,
        rules: t.rules.iter().map(rule_config).collect(),
    }
}

/// Convert stored [`RoutingTablesConfig`] into an engine [`RoutingConfig`].
pub fn routing_config(r: &RoutingTablesConfig) -> RoutingConfig {
    RoutingConfig {
        default: one_or_many(&r.default),
        resolve_dns: r.resolve_dns,
        rules: r.rules.iter().map(rule_config).collect(),
        http: r.http.as_ref().map(table_config),
        socks: r.socks.as_ref().map(table_config),
    }
}

/// Convert a Proxy's [`GlobalFilterConfig`] into an engine [`HostFilter`].
pub fn global_filter(filter: &GlobalFilterConfig) -> Result<Option<HostFilter>, MappingError> {
    Ok(match filter {
        GlobalFilterConfig::Off => None,
        GlobalFilterConfig::Allow(rules) => {
            HostFilter::from_lists(parse_rules("filter", rules)?, Vec::new())
        }
        GlobalFilterConfig::Block(rules) => {
            HostFilter::from_lists(Vec::new(), parse_rules("filter", rules)?)
        }
        GlobalFilterConfig::BlockExcept { block, allow } => HostFilter::from_lists(
            parse_rules("filter_allow", allow)?,
            parse_rules("filter_block", block)?,
        ),
    })
}

fn non_empty(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_string())
}

/// Convert one [`UpstreamProfile`] into an engine [`ProfileConfig`]. With `passwords = None`
/// (validation), vaulted passwords are left unset instead of required.
fn profile_config(
    p: &UpstreamProfile,
    passwords: Option<&BTreeMap<String, Zeroizing<String>>>,
) -> Result<ProfileConfig, MappingError> {
    let kind = match &p.kind {
        UpstreamKind::Http => ProfileType::Http,
        UpstreamKind::Https { .. } => ProfileType::Https,
        UpstreamKind::Socks5 => ProfileType::Socks5,
        UpstreamKind::Socks4a => ProfileType::Socks4a,
        UpstreamKind::Composite { .. } => ProfileType::Composite,
        UpstreamKind::Tunnel { .. } => ProfileType::External,
    };
    let mut cfg = ProfileConfig::of_kind(kind);
    cfg.bypass = p.bypass.clone();
    match &p.kind {
        UpstreamKind::Tunnel { .. } => return Ok(cfg),
        UpstreamKind::Composite { http, https, fallback } => {
            cfg.http_proxy = non_empty(http);
            cfg.https_proxy = non_empty(https);
            cfg.fallback_proxy = non_empty(fallback);
            return Ok(cfg);
        }
        UpstreamKind::Https { tls_insecure_skip_verify } => {
            cfg.tls_insecure_skip_verify = *tls_insecure_skip_verify;
        }
        _ => {}
    }
    cfg.host = p.host.clone();
    cfg.port = p.port;
    cfg.username = p.username.clone();
    match &p.password {
        None => {}
        Some(UpstreamPasswordSource::Env(var)) => cfg.password_env = Some(var.clone()),
        Some(UpstreamPasswordSource::File(path)) => cfg.password_file = Some(path.clone()),
        Some(UpstreamPasswordSource::Vault(_)) => {
            if let Some(passwords) = passwords {
                let pw = passwords.get(&p.name).ok_or_else(|| {
                    MappingError::MissingUpstreamPassword { profile: p.name.clone() }
                })?;
                cfg.password = Some(pw.as_str().to_string());
            }
        }
    }
    Ok(cfg)
}

/// Shared builder for [`proxy_to_routing_input`] and `validate_proxy`.
pub(crate) fn build_routing_input(
    proxy: &Proxy,
    passwords: Option<&BTreeMap<String, Zeroizing<String>>>,
    extra_listeners: &[SocketAddr],
) -> Result<RoutingInput, MappingError> {
    let mut profiles = BTreeMap::new();
    for p in &proxy.profiles {
        profiles.insert(p.name.clone(), profile_config(p, passwords)?);
    }
    for target in proxy_referenced_targets(proxy) {
        if matches!(target, TargetRef::Tunnel(_) | TargetRef::TunnelForward { .. }) {
            profiles
                .entry(target.to_wire())
                .or_insert_with(|| ProfileConfig::of_kind(ProfileType::External));
        }
    }
    let mut listeners = proxy_server_options(proxy).listeners();
    listeners.extend_from_slice(extra_listeners);
    Ok(RoutingInput {
        profiles,
        routing: routing_config(&proxy.routing),
        filter: global_filter(&proxy.filter)?,
        mitm_enabled: proxy.mitm.is_some(),
        listeners,
        keepalive: proxy_keepalive(proxy),
        connect_timeout: proxy.network.connect_timeout,
    })
}

/// Map a [`Proxy`] into an engine [`RoutingInput`].
///
/// `resolved_passwords` maps profile name → password for every profile whose password is
/// vaulted (see [`proxy_vault_secret_refs`]); a missing entry is
/// [`MappingError::MissingUpstreamPassword`]. `extra_listeners` (other Proxies' listeners and
/// Tunnel reverse listeners) join the Proxy's own listeners for self-loop detection.
pub fn proxy_to_routing_input(
    proxy: &Proxy,
    resolved_passwords: &BTreeMap<String, Zeroizing<String>>,
    extra_listeners: &[SocketAddr],
) -> Result<RoutingInput, MappingError> {
    build_routing_input(proxy, Some(resolved_passwords), extra_listeners)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{HopEntry, HostProfile, MitmConfig, MitmUpstreamTlsMode, ReverseConfig};
    use rusty_conduit_engine::filter::FilterRule;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
    use std::time::Duration;

    fn hop() -> HopEntry {
        HopEntry {
            hop_id: "t".into(),
            name: "t".into(),
            host: HostProfile { host: "10.0.0.1".into(), user: "root".into(), ..Default::default() },
        }
    }

    fn upstream(name: &str, kind: UpstreamKind) -> UpstreamProfile {
        UpstreamProfile {
            name: name.into(),
            kind,
            host: Some("proxy.example".into()),
            port: Some(8080),
            username: Some("me".into()),
            password: None,
            bypass: Vec::new(),
            color: None,
        }
    }

    #[test]
    fn tunnel_maps_reverse_with_forward_off() {
        let tunnel = Tunnel {
            name: "t".into(),
            hops: vec![hop()],
            reverse: ReverseConfig {
                enabled: true,
                reverse_http_port: 8888,
                reverse_socks_port: 8888,
                reverse_block: vec!["evil.example".into()],
                ..ReverseConfig::default()
            },
            ..Tunnel::default()
        };
        let cfg = tunnel_to_engine_config(&tunnel).unwrap();
        assert!(!cfg.forward_enabled);
        assert_eq!((cfg.forward_server.http_port, cfg.forward_server.socks_port), (0, 0));
        assert!(cfg.reverse_enabled);
        assert!(cfg.is_reverse_multiplexed());
        assert_eq!(
            cfg.reverse_filter,
            Some(HostFilter::Block(vec![FilterRule::from_str("evil.example").unwrap()]))
        );
        assert!(!cfg.mitm_enabled);
        assert!(cfg.mitm_options.ca.is_none());
        assert_eq!(cfg.ssh_ip_version, SshIpVersion::from_str(&tunnel.keepalive.ip_version).unwrap());
        assert!(cfg.keepalive.is_some());
    }

    #[test]
    fn tunnel_without_hops_is_rejected() {
        assert!(matches!(tunnel_to_engine_config(&Tunnel::default()), Err(MappingError::NoHops)));
    }

    #[test]
    fn tunnel_bad_ip_version_is_rejected() {
        let mut tunnel = Tunnel { hops: vec![hop()], ..Tunnel::default() };
        tunnel.keepalive.ip_version = "7".into();
        assert!(matches!(
            tunnel_to_engine_config(&tunnel),
            Err(MappingError::InvalidIpVersion(_))
        ));
    }

    #[test]
    fn server_and_mitm_options() {
        let mut proxy = Proxy::default();
        proxy.listeners.http_port = 8080;
        proxy.listeners.socks_port = 8080;
        let opts = proxy_server_options(&proxy);
        assert!(opts.is_multiplexed());
        assert_eq!(opts.listeners(), vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)]);
        assert_eq!(opts.keepalive.unwrap().idle, Duration::from_secs(60));
        proxy.network.tcp_keepalive = Duration::ZERO;
        assert!(proxy_server_options(&proxy).keepalive.is_none());

        assert!(proxy_mitm_options(&proxy).unwrap().is_none());
        proxy.mitm = Some(MitmConfig {
            cert_ttl: Duration::from_secs(3600),
            cert_cache_max_entries: 7,
            ..MitmConfig::default()
        });
        let mitm = proxy_mitm_options(&proxy).unwrap().unwrap();
        assert!(mitm.ca.is_none());
        assert_eq!(mitm.cert_ttl, Duration::from_secs(3600));
        assert_eq!(mitm.cert_cache_max, 7);
        assert_eq!(mitm.upstream_tls, UpstreamTlsVerification::Strict);
    }

    #[test]
    fn proxy_mitm_options_map_each_upstream_tls_mode() {
        let mut proxy = Proxy::default();
        let base = MitmConfig {
            insecure_hosts: vec!["localhost".into(), "*.corp.local".into(), "10.0.0.0/8".into()],
            ..MitmConfig::default()
        };
        let tls = |proxy: &Proxy| proxy_mitm_options(proxy).unwrap().unwrap().upstream_tls;

        proxy.mitm = Some(MitmConfig { upstream_tls_mode: MitmUpstreamTlsMode::Allowlist, ..base.clone() });
        assert_eq!(
            tls(&proxy),
            UpstreamTlsVerification::AllowInsecureHosts(vec![
                FilterRule::from_str("localhost").unwrap(),
                FilterRule::from_str("*.corp.local").unwrap(),
                FilterRule::from_str("10.0.0.0/8").unwrap(),
            ])
        );
        proxy.mitm = Some(MitmConfig {
            upstream_tls_mode: MitmUpstreamTlsMode::Allowlist,
            insecure_hosts: Vec::new(),
            ..base.clone()
        });
        assert_eq!(tls(&proxy), UpstreamTlsVerification::Strict);
        proxy.mitm = Some(MitmConfig { upstream_tls_mode: MitmUpstreamTlsMode::InsecureAll, ..base.clone() });
        assert_eq!(tls(&proxy), UpstreamTlsVerification::InsecureAll);
        // Strict ignores a leftover list.
        proxy.mitm = Some(base.clone());
        assert_eq!(tls(&proxy), UpstreamTlsVerification::Strict);

        proxy.mitm = Some(MitmConfig {
            upstream_tls_mode: MitmUpstreamTlsMode::Allowlist,
            insecure_hosts: vec!["bad rule with spaces".into()],
            ..base
        });
        assert!(matches!(
            proxy_mitm_options(&proxy),
            Err(MappingError::InvalidFilterRule { scope: "mitm_insecure_hosts", .. })
        ));
    }

    #[test]
    fn tunnel_maps_upstream_tls_only_while_mitm_is_active() {
        let mut tunnel = Tunnel {
            name: "t".into(),
            hops: vec![hop()],
            mitm: Some(MitmConfig {
                upstream_tls_mode: MitmUpstreamTlsMode::InsecureAll,
                ..MitmConfig::default()
            }),
            ..Tunnel::default()
        };
        tunnel.mitm.as_mut().unwrap().bypass_hosts = vec!["*.bank.example".into()];
        tunnel.forward.enabled = false;
        let cfg = tunnel_to_engine_config(&tunnel).unwrap();
        assert_eq!(cfg.mitm_options.upstream_tls, UpstreamTlsVerification::Strict);
        assert!(cfg.mitm_options.bypass_hosts.is_empty());
        tunnel.forward.enabled = true;
        tunnel.forward.http_port = 8128;
        let cfg = tunnel_to_engine_config(&tunnel).unwrap();
        assert_eq!(cfg.mitm_options.upstream_tls, UpstreamTlsVerification::InsecureAll);
        assert_eq!(cfg.mitm_options.bypass_hosts, vec![FilterRule::from_str("*.bank.example").unwrap()]);
    }

    #[test]
    fn proxy_maps_mitm_bypass_hosts() {
        let mut proxy = Proxy { name: "p".into(), ..Proxy::default() };
        proxy.mitm = Some(MitmConfig {
            bypass_hosts: vec!["*.bank.example".into(), "10.0.0.0/8".into()],
            ..MitmConfig::default()
        });
        assert_eq!(
            proxy_mitm_options(&proxy).unwrap().unwrap().bypass_hosts,
            vec![FilterRule::from_str("*.bank.example").unwrap(), FilterRule::from_str("10.0.0.0/8").unwrap()]
        );
        proxy.mitm.as_mut().unwrap().bypass_hosts.push("bad rule".into());
        assert!(matches!(
            proxy_mitm_options(&proxy),
            Err(MappingError::InvalidFilterRule { scope: "mitm_bypass_hosts", .. })
        ));
    }

    fn full_proxy() -> (Proxy, TunnelId, SecretRef) {
        let tunnel_id = TunnelId::new();
        let secret = SecretRef::new();
        let mut vaulted = upstream("vaulted", UpstreamKind::Http);
        vaulted.password = Some(UpstreamPasswordSource::Vault(secret.clone()));
        let mut env = upstream("env", UpstreamKind::Socks5);
        env.password = Some(UpstreamPasswordSource::Env("PW".into()));
        let mut file = upstream("file", UpstreamKind::Socks4a);
        file.password = Some(UpstreamPasswordSource::File(PathBuf::from("/run/pw")));
        let mut https = upstream("https", UpstreamKind::Https { tls_insecure_skip_verify: true });
        https.bypass = vec!["localhost".into()];
        let ssh = upstream("ssh", UpstreamKind::Tunnel { tunnel_id });
        let ssh2 = upstream("ssh2", UpstreamKind::Tunnel { tunnel_id });
        let composite = upstream(
            "split",
            UpstreamKind::Composite { http: "vaulted".into(), https: "".into(), fallback: "ssh".into() },
        );
        let proxy = Proxy {
            name: "p".into(),
            profiles: vec![vaulted, env, file, https, ssh, ssh2, composite],
            filter: GlobalFilterConfig::Allow(vec!["example.com".into()]),
            ..Proxy::default()
        };
        (proxy, tunnel_id, secret)
    }

    #[test]
    fn maps_every_upstream_kind() {
        let (proxy, tunnel_id, secret) = full_proxy();
        let mut pw = BTreeMap::new();
        pw.insert("vaulted".to_string(), Zeroizing::new("s3cret".to_string()));
        let input = proxy_to_routing_input(&proxy, &pw, &[]).unwrap();
        let p = &input.profiles;
        assert_eq!(p["vaulted"].kind, ProfileType::Http);
        assert_eq!(p["vaulted"].password.as_deref(), Some("s3cret"));
        assert_eq!(p["vaulted"].host.as_deref(), Some("proxy.example"));
        assert_eq!(p["vaulted"].port, Some(8080));
        assert_eq!(p["vaulted"].username.as_deref(), Some("me"));
        assert_eq!(p["env"].kind, ProfileType::Socks5);
        assert_eq!(p["env"].password_env.as_deref(), Some("PW"));
        assert_eq!(p["file"].kind, ProfileType::Socks4a);
        assert_eq!(p["file"].password_file, Some(PathBuf::from("/run/pw")));
        assert_eq!(p["https"].kind, ProfileType::Https);
        assert!(p["https"].tls_insecure_skip_verify);
        assert_eq!(p["https"].bypass, vec!["localhost".to_string()]);
        assert_eq!(p["ssh"].kind, ProfileType::External);
        assert!(p["ssh"].host.is_none() && p["ssh"].port.is_none());
        assert_eq!(p["split"].kind, ProfileType::Composite);
        assert_eq!(p["split"].http_proxy.as_deref(), Some("vaulted"));
        assert_eq!(p["split"].https_proxy, None);
        assert_eq!(p["split"].fallback_proxy.as_deref(), Some("ssh"));
        assert!(p["split"].host.is_none());
        assert!(input.validate().is_ok());

        assert_eq!(proxy_referenced_tunnels(&proxy), vec![tunnel_id]);
        assert_eq!(proxy_vault_secret_refs(&proxy), vec![("vaulted".to_string(), secret)]);
    }

    #[test]
    fn missing_vault_password_is_an_error() {
        let (proxy, _, _) = full_proxy();
        assert!(matches!(
            proxy_to_routing_input(&proxy, &BTreeMap::new(), &[]),
            Err(MappingError::MissingUpstreamPassword { profile }) if profile == "vaulted"
        ));
    }

    #[test]
    fn listeners_keepalive_timeout_and_mitm_flag() {
        let mut proxy = Proxy::default();
        proxy.network.connect_timeout = Duration::from_secs(3);
        proxy.mitm = Some(MitmConfig::default());
        let extra = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999);
        let input = proxy_to_routing_input(&proxy, &BTreeMap::new(), &[extra]).unwrap();
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(
            input.listeners,
            vec![SocketAddr::new(lo, 3128), SocketAddr::new(lo, 1080), extra]
        );
        assert_eq!(input.connect_timeout, Duration::from_secs(3));
        assert!(input.mitm_enabled);
        assert_eq!(input.keepalive.unwrap().retries, 5);
        assert_eq!(input.filter, None);
    }

    #[test]
    fn routing_tables_convert_field_for_field() {
        let mut rule = RoutingRule::to_target(RouteOneOrMany::Many(vec!["a".into(), "direct".into()]));
        rule.name = Some("r".into());
        rule.inbound = Some(RouteInbound::Socks);
        rule.host = Some(RouteOneOrMany::One("h.example".into()));
        rule.host_wildcard = Some(RouteOneOrMany::One("*.w.example".into()));
        rule.host_regex = Some(RouteOneOrMany::One("^x$".into()));
        rule.cidr = Some(RouteOneOrMany::One("10.0.0.0/8".into()));
        rule.ip = Some(RouteOneOrMany::One("10.0.0.1".into()));
        rule.port = Some(RouteOneOrMany::Many(vec![
            RoutePortSpec::Port(443),
            RoutePortSpec::Range("8000-8080".into()),
        ]));
        rule.host_levels = Some(RouteHostLevels { min: Some(1), max: Some(3) });
        rule.bypass = Some(RouteOneOrMany::One("b.example".into()));
        rule.weekday = Some(RouteOneOrMany::One("mon".into()));
        rule.time = Some(RouteOneOrMany::One("09:00-17:00".into()));
        rule.url_wildcard = Some(RouteOneOrMany::One("*/x".into()));
        rule.url_regex = Some(RouteOneOrMany::One("x".into()));
        rule.keyword = Some(RouteOneOrMany::One("k".into()));
        rule.match_all = true;
        rule.disabled = true;
        rule.resolve_dns = Some(false);
        let tables = RoutingTablesConfig {
            default: RouteOneOrMany::One("a".into()),
            resolve_dns: true,
            rules: vec![rule],
            http: Some(RoutingTable {
                default: Some(RouteOneOrMany::One("block".into())),
                inherit: true,
                rules: vec![],
            }),
            socks: None,
        };
        let cfg = routing_config(&tables);
        assert_eq!(cfg.default, OneOrMany::One("a".into()));
        assert!(cfg.resolve_dns);
        let r = &cfg.rules[0];
        assert_eq!(r.name.as_deref(), Some("r"));
        assert_eq!(r.inbound, Some(Inbound::Socks));
        assert_eq!(r.host, Some(OneOrMany::One("h.example".into())));
        assert_eq!(r.host_wildcard, Some(OneOrMany::One("*.w.example".into())));
        assert_eq!(r.host_regex, Some(OneOrMany::One("^x$".into())));
        assert_eq!(r.cidr, Some(OneOrMany::One("10.0.0.0/8".into())));
        assert_eq!(r.ip, Some(OneOrMany::One("10.0.0.1".into())));
        assert_eq!(
            r.port,
            Some(OneOrMany::Many(vec![PortSpec::Port(443), PortSpec::Range("8000-8080".into())]))
        );
        assert_eq!(r.host_levels, Some(HostLevels { min: Some(1), max: Some(3) }));
        assert_eq!(r.bypass, Some(OneOrMany::One("b.example".into())));
        assert_eq!(r.weekday, Some(OneOrMany::One("mon".into())));
        assert_eq!(r.time, Some(OneOrMany::One("09:00-17:00".into())));
        assert_eq!(r.url_wildcard, Some(OneOrMany::One("*/x".into())));
        assert_eq!(r.url_regex, Some(OneOrMany::One("x".into())));
        assert_eq!(r.keyword, Some(OneOrMany::One("k".into())));
        assert!(r.match_all && r.disabled);
        assert_eq!(r.resolve_dns, Some(false));
        assert_eq!(r.target, OneOrMany::Many(vec!["a".into(), "direct".into()]));
        let http = cfg.http.as_ref().unwrap();
        assert_eq!(http.default, Some(OneOrMany::One("block".into())));
        assert!(http.inherit);
        assert!(cfg.socks.is_none());
    }

    #[test]
    fn global_filter_mapping() {
        assert_eq!(global_filter(&GlobalFilterConfig::Off).unwrap(), None);
        assert_eq!(
            global_filter(&GlobalFilterConfig::Allow(vec!["example.com".into()])).unwrap(),
            Some(HostFilter::Allow(vec![FilterRule::from_str("example.com").unwrap()]))
        );
        assert_eq!(
            global_filter(&GlobalFilterConfig::Block(vec!["ads.example".into()])).unwrap(),
            Some(HostFilter::Block(vec![FilterRule::from_str("ads.example").unwrap()]))
        );
        assert!(matches!(
            global_filter(&GlobalFilterConfig::Block(vec!["".into()])),
            Err(MappingError::InvalidFilterRule { scope: "filter", .. })
        ));
    }

    #[test]
    fn tunnel_maps_forward_off_with_filter_always_compiled_and_mitm_inactive() {
        let mut tunnel = Tunnel {
            name: "t".into(),
            hops: vec![hop()],
            mitm: Some(MitmConfig {
                cert_ttl: Duration::from_secs(600),
                cert_cache_max_entries: 42,
                ..MitmConfig::default()
            }),
            socks_block_web: true,
            ..Tunnel::default()
        };
        tunnel.forward.enabled = false;
        tunnel.forward.allow = vec!["allowed.example".into()];
        tunnel.forward.block = vec!["*.example".into()];

        let filter = tunnel_forward_filter(&tunnel).unwrap();
        assert!(filter.is_some());

        let cfg = tunnel_to_engine_config(&tunnel).unwrap();
        assert!(!cfg.forward_enabled);
        assert_eq!((cfg.forward_server.http_port, cfg.forward_server.socks_port), (0, 0));
        assert_eq!(cfg.forward_filter, filter);
        assert!(!cfg.mitm_enabled);
        assert!(cfg.socks_block_web_in_mitm);
    }

    #[test]
    fn tunnel_maps_forward_on_with_mitm_and_filter() {
        let mut tunnel = Tunnel {
            name: "t".into(),
            hops: vec![hop()],
            mitm: Some(MitmConfig {
                cert_ttl: Duration::from_secs(600),
                cert_cache_max_entries: 42,
                socks_block_web: false,
                ..MitmConfig::default()
            }),
            socks_block_web: true,
            ..Tunnel::default()
        };
        tunnel.forward.enabled = true;
        tunnel.forward.bind = IpAddr::V4(Ipv4Addr::LOCALHOST);
        tunnel.forward.http_port = 8128;
        tunnel.forward.socks_port = 1180;
        tunnel.forward.max_connections = 512;
        tunnel.forward.block = vec!["ads.example".into()];

        let cfg = tunnel_to_engine_config(&tunnel).unwrap();
        assert!(cfg.forward_enabled);
        assert_eq!(cfg.forward_server.http_port, 8128);
        assert_eq!(cfg.forward_server.socks_port, 1180);
        assert_eq!(cfg.forward_server.max_connections, 512);
        assert_eq!(cfg.reverse_max_connections, 512);
        assert_eq!(
            cfg.forward_filter,
            Some(HostFilter::Block(vec![FilterRule::from_str("ads.example").unwrap()]))
        );
        assert!(cfg.mitm_enabled);
        assert_eq!(cfg.mitm_options.cert_ttl, Duration::from_secs(600));
        assert_eq!(cfg.mitm_options.cert_cache_max, 42);
        assert!(cfg.socks_block_web_in_mitm);
    }

    #[test]
    fn proxy_compiles_synthetic_tunnel_and_forward_targets_without_manual_profiles() {
        use crate::v2_model::{forward_target_name, tunnel_target_name};
        use rusty_conduit_engine::router::Router;

        let t1 = TunnelId::new();
        let t2 = TunnelId::new();
        let f1 = Uuid::new_v4();
        let t1_wire = tunnel_target_name(t1);
        let f1_wire = forward_target_name(t2, f1);

        let mut rule = RoutingRule::to_target(RouteOneOrMany::Many(vec![
            f1_wire.clone(),
            "direct".into(),
        ]));
        rule.host_wildcard = Some(RouteOneOrMany::One("*.corp.example".into()));

        let mut proxy = Proxy {
            name: "p".into(),
            profiles: Vec::new(),
            routing: RoutingTablesConfig {
                default: RouteOneOrMany::One(t1_wire.clone()),
                resolve_dns: false,
                rules: vec![rule],
                http: Some(RoutingTable {
                    default: Some(RouteOneOrMany::One(f1_wire.clone())),
                    inherit: true,
                    rules: Vec::new(),
                }),
                socks: None,
            },
            ..Proxy::default()
        };

        assert_eq!(proxy_referenced_tunnels(&proxy), vec![t1, t2]);
        assert_eq!(proxy_referenced_forwards(&proxy), vec![(t2, f1)]);
        assert_eq!(
            proxy_referenced_targets(&proxy),
            vec![
                TargetRef::Tunnel(t1),
                TargetRef::TunnelForward { tunnel_id: t2, forward_id: f1 },
                TargetRef::Direct,
            ]
        );

        let input = proxy_to_routing_input(&proxy, &BTreeMap::new(), &[]).unwrap();
        assert_eq!(input.profiles[&t1_wire].kind, ProfileType::External);
        assert_eq!(input.profiles[&f1_wire].kind, ProfileType::External);
        input.validate().unwrap();
        Router::from_input(&input).unwrap();

        // Also ensure no duplicate entries if referenced again.
        proxy.routing.socks = Some(RoutingTable {
            default: Some(RouteOneOrMany::One(t1_wire)),
            inherit: false,
            rules: Vec::new(),
        });
        assert_eq!(proxy_referenced_tunnels(&proxy), vec![t1, t2]);
    }
}
