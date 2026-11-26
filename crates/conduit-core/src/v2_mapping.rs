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
use rusty_conduit_engine::mitm::MitmOptions;
use rusty_conduit_engine::net::KeepaliveSettings;
use rusty_conduit_engine::routing::{
    HostLevels, Inbound, OneOrMany, PortSpec, ProfileConfig, ProfileType, RoutingConfig,
    RoutingInput, RoutingTableConfig, RuleConfig,
};
use rusty_conduit_engine::server::ServerOptions;
use rusty_conduit_engine::filter::HostFilter;
use zeroize::Zeroizing;

use crate::mapping::{host_filter, parse_rules};
use crate::model::{ForwardConfig, SecretRef};
use crate::v2_model::{
    GlobalFilterConfig, Proxy, RouteHostLevels, RouteInbound, RouteOneOrMany, RoutePortSpec,
    RoutingRule, RoutingTable, RoutingTablesConfig, Tunnel, TunnelId, UpstreamKind,
    UpstreamPasswordSource, UpstreamProfile,
};
use crate::{EngineConfig, MappingError, SshIpVersion};

/// Map a [`Tunnel`] into an [`EngineConfig`]: reverse listeners, keepalive, logging, and SSH IP
/// version come from the tunnel; the forward listener is off (ports `0`) and MITM is off.
pub fn tunnel_to_engine_config(tunnel: &Tunnel) -> Result<EngineConfig, MappingError> {
    if tunnel.hops.is_empty() {
        return Err(MappingError::NoHops);
    }
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
    let (reverse_http_port, reverse_socks_port) = reverse.effective_ports();
    let forward_defaults = ForwardConfig::default();
    let mitm_options = MitmOptions { ca: None, passphrase: None, passphrase_file: None, ..MitmOptions::default() };

    Ok(EngineConfig {
        forward_server: ServerOptions {
            bind: forward_defaults.bind,
            http_port: 0,
            socks_port: 0,
            max_connections: forward_defaults.max_connections,
            keepalive,
        },
        forward_enabled: false,
        forward_filter: None,
        reverse_bind: reverse.reverse_bind,
        reverse_http_port,
        reverse_socks_port,
        reverse_max_connections: reverse
            .reverse_max_connections
            .unwrap_or(forward_defaults.max_connections),
        reverse_enabled: reverse_http_port != 0 || reverse_socks_port != 0,
        reverse_filter,
        keepalive,
        mitm_enabled: false,
        mitm_options,
        socks_block_web_in_mitm: false,
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

/// Map a Proxy's MITM settings into [`MitmOptions`] (`None` when MITM is off). `ca` is always
/// `None`: the runtime loads the CA in memory from the vault.
pub fn proxy_mitm_options(proxy: &Proxy) -> Option<MitmOptions> {
    proxy.mitm.as_ref().map(|m| MitmOptions {
        ca: None,
        passphrase: None,
        passphrase_file: None,
        cert_ttl: m.cert_ttl,
        cert_cache_max: m.cert_cache_max_entries,
    })
}

/// Every distinct Tunnel the Proxy's profiles route through, in profile order.
pub fn proxy_referenced_tunnels(proxy: &Proxy) -> Vec<TunnelId> {
    let mut out = Vec::new();
    for p in &proxy.profiles {
        if let UpstreamKind::Tunnel { tunnel_id } = p.kind {
            if !out.contains(&tunnel_id) {
                out.push(tunnel_id);
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
        GlobalFilterConfig::Allow(rules) => Some(HostFilter::Allow(parse_rules("filter", rules)?)),
        GlobalFilterConfig::Block(rules) => Some(HostFilter::Block(parse_rules("filter", rules)?)),
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
    use crate::model::{HopEntry, HostProfile, MitmConfig, ReverseConfig};
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

        assert!(proxy_mitm_options(&proxy).is_none());
        proxy.mitm = Some(MitmConfig {
            cert_ttl: Duration::from_secs(3600),
            cert_cache_max_entries: 7,
            ..MitmConfig::default()
        });
        let mitm = proxy_mitm_options(&proxy).unwrap();
        assert!(mitm.ca.is_none());
        assert_eq!(mitm.cert_ttl, Duration::from_secs(3600));
        assert_eq!(mitm.cert_cache_max, 7);
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
}
