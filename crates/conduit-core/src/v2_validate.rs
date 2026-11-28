//! `conduit-core` — validation of a v2 [`Tunnel`] and [`Proxy`].
//!
//! [`validate_tunnel`] applies the SSH-side rules of the v1 [`validate`](crate::validate) to a
//! Tunnel. Unlike a v1 session, a Tunnel needs no listener of its own: it may exist only to
//! serve Proxies through [`UpstreamKind::Tunnel`].
//!
//! [`validate_proxy`] checks the Proxy's own fields, then builds the engine [`RoutingInput`]
//! and lets the engine check every profile, rule, target, composite reference, and self-loop
//! exactly as it will compile them.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use rusty_conduit_engine::filter::FilterRule;
use rusty_conduit_engine::logging::{LogFormat, LogLevel};
use rusty_conduit_engine::mitm::MIN_MITM_CERT_TTL;
use rusty_conduit_engine::router::Router;
use rusty_conduit_engine::routing::{RoutingError, PROFILE_BLOCK, PROFILE_DIRECT};
use thiserror::Error;
use uuid::Uuid;

use crate::model::{ForwardDirection, ForwardProxyProtocol, LoggingConfig};
use crate::v2_mapping::{build_routing_input, proxy_referenced_targets};
use crate::v2_model::{GlobalFilterConfig, Proxy, TargetRef, Tunnel, TunnelId, UpstreamKind};
use crate::validate::{denylisted_flag, keepalive_problem, port_forward_problem_in};
use crate::{MappingError, SshIpVersion, ValidateError};

/// Errors raised when a [`Proxy`] fails validation. Every variant is `FATAL`.
#[derive(Debug, Error)]
pub enum ProxyValidateError {
    #[error("no listeners: set a non-zero HTTP or SOCKS port")]
    NoListeners,
    #[error("MITM is on but no CA is selected: upload a CA in the Key Vault and choose it")]
    MissingMitmCa,
    #[error("--mitm-cert-ttl must be at least 10s (got {})", humantime::format_duration(*.0))]
    CertTtlTooShort(Duration),
    #[error("invalid TCP keepalive setting: {0}")]
    InvalidKeepalive(String),
    #[error("the connect timeout must be greater than 0")]
    ZeroConnectTimeout,
    #[error("invalid filter rule in `{scope}`: {rule} ({message})")]
    InvalidFilterRule {
        scope: &'static str,
        rule: String,
        message: String,
    },
    #[error("{0}")]
    InvalidLogLevel(String),
    #[error("{0}")]
    InvalidLogFormat(String),
    #[error("two upstream profiles are named `{0}`: profile names must be unique")]
    DuplicateProfile(String),
    #[error("`{0}` is a reserved profile name and cannot be used for an upstream profile")]
    ReservedProfileName(String),
    #[error("profile `{profile}` routes through tunnel {tunnel_id}, which does not exist")]
    UnknownTunnel { profile: String, tunnel_id: TunnelId },
    #[error(
        "routing target references tunnel {tunnel_id} forward {forward_id}, which does not exist or is not a local proxy forward"
    )]
    UnknownTunnelForward { tunnel_id: TunnelId, forward_id: Uuid },
    #[error(transparent)]
    Mapping(#[from] MappingError),
    #[error(transparent)]
    Routing(#[from] RoutingError),
}

fn filter_rules<E>(
    scope: &'static str,
    rules: &[String],
    err: impl Fn(&'static str, String, String) -> E,
) -> Result<(), E> {
    for rule in rules {
        if let Err(message) = FilterRule::from_str(rule) {
            return Err(err(scope, rule.clone(), message));
        }
    }
    Ok(())
}

fn logging_problem(logging: &LoggingConfig) -> Option<Result<String, String>> {
    if let Err(message) = LogLevel::from_str(&logging.level) {
        return Some(Ok(message));
    }
    if let Err(message) = LogFormat::from_str(&logging.format) {
        return Some(Err(message));
    }
    None
}

/// Validate a [`Tunnel`], returning the first `FATAL` problem found.
pub fn validate_tunnel(tunnel: &Tunnel) -> Result<(), ValidateError> {
    match tunnel.hops.last() {
        None => return Err(ValidateError::MissingSshTarget),
        Some(last) if last.host.host.trim().is_empty() => {
            return Err(ValidateError::EmptySshTarget)
        }
        Some(_) => {}
    }

    if tunnel.forward.enabled {
        if tunnel.forward.effective_ports() == (0, 0) {
            return Err(ValidateError::NoListeners);
        }
        if let Some(mitm) = &tunnel.mitm {
            if mitm.ca.is_none() {
                return Err(ValidateError::MissingMitmCa);
            }
            if mitm.cert_ttl < MIN_MITM_CERT_TTL {
                return Err(ValidateError::CertTtlTooShort(mitm.cert_ttl));
            }
            filter_rules("mitm_insecure_hosts", &mitm.insecure_hosts, |scope, rule, message| {
                ValidateError::InvalidFilterRule { scope, rule, message }
            })?;
            filter_rules("mitm_bypass_hosts", &mitm.bypass_hosts, |scope, rule, message| {
                ValidateError::InvalidFilterRule { scope, rule, message }
            })?;
        }
    }

    let local_proxy = tunnel
        .forward
        .enabled
        .then_some((tunnel.forward.bind, tunnel.forward.effective_ports()));
    let reverse = (tunnel.reverse.reverse_bind, tunnel.reverse.effective_ports());
    for (index, forward) in tunnel.port_forwards.iter().enumerate() {
        if forward.direction == ForwardDirection::Remote
            && forward.proxy_protocol != ForwardProxyProtocol::None
        {
            return Err(ValidateError::InvalidPortForward {
                index,
                spec: forward.spec(),
                message: "proxy protocol is only supported on local (-L) port forwards".into(),
            });
        }
        if let Some(message) =
            port_forward_problem_in(&tunnel.port_forwards, index, forward, local_proxy, reverse)
        {
            return Err(ValidateError::InvalidPortForward {
                index,
                spec: forward.spec(),
                message,
            });
        }
    }

    for arg in &tunnel.openssh.extra_args {
        if let Some(flag) = denylisted_flag(arg) {
            return Err(ValidateError::IsolationDenylist { flag, arg: arg.clone() });
        }
    }

    let k = &tunnel.keepalive;
    if k.reconnect_initial_delay > k.reconnect_max_delay {
        return Err(ValidateError::ReconnectDelayOrder {
            initial: k.reconnect_initial_delay,
            max: k.reconnect_max_delay,
        });
    }
    keepalive_problem(k.tcp_keepalive, k.tcp_keepalive_interval, k.tcp_keepalive_retries)?;

    let invalid = |scope, rule, message| ValidateError::InvalidFilterRule { scope, rule, message };
    filter_rules("forward_allow", &tunnel.forward.allow, invalid)?;
    filter_rules("forward_block", &tunnel.forward.block, invalid)?;
    let r = &tunnel.reverse;
    filter_rules("reverse_allow", &r.reverse_allow, invalid)?;
    filter_rules("reverse_block", &r.reverse_block, invalid)?;

    if let Err(message) = SshIpVersion::from_str(&k.ip_version) {
        return Err(ValidateError::InvalidIpVersion(message));
    }
    match logging_problem(&tunnel.logging) {
        Some(Ok(message)) => Err(ValidateError::InvalidLogLevel(message)),
        Some(Err(message)) => Err(ValidateError::InvalidLogFormat(message)),
        None => Ok(()),
    }
}

/// Validate a [`Proxy`], returning the first `FATAL` problem found.
///
/// `known_tunnels` are the Tunnels an [`UpstreamKind::Tunnel`] profile or `@tunnel:` /
/// `@forward:` target may name. `extra_listeners` (other Proxies' listeners and Tunnel reverse
/// listeners) join the Proxy's own listeners for self-loop detection.
pub fn validate_proxy(
    proxy: &Proxy,
    known_tunnels: &[TunnelId],
    extra_listeners: &[SocketAddr],
) -> Result<(), ProxyValidateError> {
    validate_proxy_inner(proxy, known_tunnels, None, extra_listeners)
}

/// Validate a [`Proxy`] against full [`Tunnel`] definitions, additionally verifying that every
/// `@forward:<tid>:<fid>` target names an existing local (`-L`) port forward with a proxy
/// protocol (`http` or `socks5`).
pub fn validate_proxy_with_tunnels(
    proxy: &Proxy,
    known_tunnels: &[Tunnel],
    extra_listeners: &[SocketAddr],
) -> Result<(), ProxyValidateError> {
    let ids: Vec<TunnelId> = known_tunnels.iter().map(|t| t.id).collect();
    validate_proxy_inner(proxy, &ids, Some(known_tunnels), extra_listeners)
}

fn validate_proxy_inner(
    proxy: &Proxy,
    known_tunnel_ids: &[TunnelId],
    known_tunnels: Option<&[Tunnel]>,
    extra_listeners: &[SocketAddr],
) -> Result<(), ProxyValidateError> {
    if proxy.listeners.http_port == 0 && proxy.listeners.socks_port == 0 {
        return Err(ProxyValidateError::NoListeners);
    }

    if let Some(mitm) = &proxy.mitm {
        if mitm.ca.is_none() {
            return Err(ProxyValidateError::MissingMitmCa);
        }
        if mitm.cert_ttl < MIN_MITM_CERT_TTL {
            return Err(ProxyValidateError::CertTtlTooShort(mitm.cert_ttl));
        }
        filter_rules("mitm_insecure_hosts", &mitm.insecure_hosts, |scope, rule, message| {
            ProxyValidateError::InvalidFilterRule { scope, rule, message }
        })?;
        filter_rules("mitm_bypass_hosts", &mitm.bypass_hosts, |scope, rule, message| {
            ProxyValidateError::InvalidFilterRule { scope, rule, message }
        })?;
    }

    let n = &proxy.network;
    keepalive_problem(n.tcp_keepalive, n.tcp_keepalive_interval, n.tcp_keepalive_retries)
        .map_err(|e| match e {
            ValidateError::InvalidKeepalive(message) => {
                ProxyValidateError::InvalidKeepalive(message)
            }
            other => ProxyValidateError::InvalidKeepalive(other.to_string()),
        })?;
    if n.connect_timeout.is_zero() {
        return Err(ProxyValidateError::ZeroConnectTimeout);
    }

    let invalid =
        |scope, rule, message| ProxyValidateError::InvalidFilterRule { scope, rule, message };
    match &proxy.filter {
        GlobalFilterConfig::Off => {}
        GlobalFilterConfig::Allow(rules) => filter_rules("filter_allow", rules, invalid)?,
        GlobalFilterConfig::Block(rules) => filter_rules("filter_block", rules, invalid)?,
        GlobalFilterConfig::BlockExcept { block, allow } => {
            filter_rules("filter_allow", allow, invalid)?;
            filter_rules("filter_block", block, invalid)?;
        }
    }

    match logging_problem(&proxy.logging) {
        Some(Ok(message)) => return Err(ProxyValidateError::InvalidLogLevel(message)),
        Some(Err(message)) => return Err(ProxyValidateError::InvalidLogFormat(message)),
        None => {}
    }

    let mut names = BTreeSet::new();
    for p in &proxy.profiles {
        if p.name == PROFILE_DIRECT || p.name == PROFILE_BLOCK || p.name.starts_with('@') {
            return Err(ProxyValidateError::ReservedProfileName(p.name.clone()));
        }
        if !names.insert(p.name.as_str()) {
            return Err(ProxyValidateError::DuplicateProfile(p.name.clone()));
        }
        if let UpstreamKind::Tunnel { tunnel_id } = p.kind {
            if !known_tunnel_ids.contains(&tunnel_id) {
                return Err(ProxyValidateError::UnknownTunnel {
                    profile: p.name.clone(),
                    tunnel_id,
                });
            }
        }
    }

    for target in proxy_referenced_targets(proxy) {
        match &target {
            TargetRef::Tunnel(tunnel_id) => {
                if !known_tunnel_ids.contains(tunnel_id) {
                    return Err(ProxyValidateError::UnknownTunnel {
                        profile: target.to_wire(),
                        tunnel_id: *tunnel_id,
                    });
                }
            }
            TargetRef::TunnelForward { tunnel_id, forward_id } => {
                if !known_tunnel_ids.contains(tunnel_id) {
                    return Err(ProxyValidateError::UnknownTunnel {
                        profile: target.to_wire(),
                        tunnel_id: *tunnel_id,
                    });
                }
                if let Some(tunnels) = known_tunnels {
                    let valid = tunnels.iter().find(|t| t.id == *tunnel_id).is_some_and(|t| {
                        t.port_forwards.iter().any(|f| {
                            f.id == *forward_id
                                && f.direction == ForwardDirection::Local
                                && f.proxy_protocol != ForwardProxyProtocol::None
                        })
                    });
                    if !valid {
                        return Err(ProxyValidateError::UnknownTunnelForward {
                            tunnel_id: *tunnel_id,
                            forward_id: *forward_id,
                        });
                    }
                }
            }
            _ => {}
        }
    }

    let input = build_routing_input(proxy, None, extra_listeners)?;
    input.validate()?;
    input.validate_no_self_loop()?;
    Router::from_input(&input).map_err(RoutingError::from)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        ForwardDirection, HopEntry, HostProfile, MitmCaId, MitmConfig, MitmUpstreamTlsMode, PortForward,
        ReverseConfig,
    };
    use crate::v2_model::{
        RouteOneOrMany, RoutingRule, UpstreamPasswordSource, UpstreamProfile,
    };
    use crate::SecretRef;
    use std::net::{IpAddr, Ipv4Addr};

    fn hop() -> HopEntry {
        HopEntry {
            hop_id: "t".into(),
            name: "t".into(),
            host: HostProfile { host: "10.0.0.1".into(), user: "root".into(), ..Default::default() },
        }
    }

    fn tunnel() -> Tunnel {
        Tunnel { name: "t".into(), hops: vec![hop()], ..Tunnel::default() }
    }

    fn upstream(name: &str, kind: UpstreamKind, port: u16) -> UpstreamProfile {
        UpstreamProfile {
            name: name.into(),
            kind,
            host: Some("127.0.0.1".into()),
            port: Some(port),
            username: None,
            password: None,
            bypass: Vec::new(),
            color: None,
        }
    }

    fn proxy(tunnel_id: TunnelId) -> Proxy {
        let mut corp = upstream("corp", UpstreamKind::Http, 8080);
        corp.password = Some(UpstreamPasswordSource::Vault(SecretRef::new()));
        let mut p = Proxy {
            name: "p".into(),
            profiles: vec![corp, upstream("ssh", UpstreamKind::Tunnel { tunnel_id }, 0)],
            ..Proxy::default()
        };
        p.routing.default = RouteOneOrMany::One("ssh".into());
        let mut rule = RoutingRule::to_target(RouteOneOrMany::Many(vec!["corp".into(), "direct".into()]));
        rule.host_wildcard = Some(RouteOneOrMany::One("*.corp.example".into()));
        p.routing.rules.push(rule);
        p
    }

    // ---- Tunnel ----

    #[test]
    fn accepts_a_tunnel_without_listeners() {
        assert!(validate_tunnel(&tunnel()).is_ok());
    }

    #[test]
    fn tunnel_hop_checks() {
        let mut t = tunnel();
        t.hops[0].host.host = " ".into();
        assert!(matches!(validate_tunnel(&t), Err(ValidateError::EmptySshTarget)));
        t.hops.clear();
        assert!(matches!(validate_tunnel(&t), Err(ValidateError::MissingSshTarget)));
    }

    #[test]
    fn tunnel_denylist_and_reconnect_and_keepalive() {
        let mut t = tunnel();
        t.openssh.extra_args = vec!["-oProxyCommand=nc".into()];
        assert!(matches!(validate_tunnel(&t), Err(ValidateError::IsolationDenylist { .. })));

        let mut t = tunnel();
        t.keepalive.reconnect_initial_delay = Duration::from_secs(100);
        t.keepalive.reconnect_max_delay = Duration::from_secs(1);
        assert!(matches!(validate_tunnel(&t), Err(ValidateError::ReconnectDelayOrder { .. })));

        let mut t = tunnel();
        t.keepalive.tcp_keepalive_retries = 0;
        assert!(matches!(validate_tunnel(&t), Err(ValidateError::InvalidKeepalive(_))));
    }

    #[test]
    fn tunnel_reverse_filters() {
        let mut t = tunnel();
        t.reverse.reverse_allow = vec!["test.domain.net".into()];
        t.reverse.reverse_block = vec!["*.domain.net".into()];
        validate_tunnel(&t).unwrap();
        t.reverse.reverse_allow.clear();
        t.reverse.reverse_block = vec!["".into()];
        assert!(matches!(
            validate_tunnel(&t),
            Err(ValidateError::InvalidFilterRule { scope: "reverse_block", .. })
        ));
    }

    #[test]
    fn tunnel_port_forwards() {
        let mut t = tunnel();
        t.reverse = ReverseConfig {
            enabled: true,
            reverse_http_port: 9000,
            reverse_socks_port: 9000,
            ..ReverseConfig::default()
        };
        let fwd = |direction, port| PortForward {
            enabled: true,
            direction,
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            dest_host: "db.internal".into(),
            dest_port: 5432,
            ..PortForward::default()
        };
        // A local forward may use any port: a Tunnel has no forward proxy.
        t.port_forwards = vec![fwd(ForwardDirection::Local, 3128)];
        assert!(validate_tunnel(&t).is_ok());
        t.port_forwards.push(fwd(ForwardDirection::Remote, 9000));
        assert!(matches!(
            validate_tunnel(&t),
            Err(ValidateError::InvalidPortForward { index: 1, .. })
        ));
        t.port_forwards[1].port = 9001;
        t.port_forwards.push(fwd(ForwardDirection::Local, 3128));
        assert!(matches!(
            validate_tunnel(&t),
            Err(ValidateError::InvalidPortForward { index: 2, .. })
        ));
    }

    #[test]
    fn tunnel_string_enums() {
        let mut t = tunnel();
        t.keepalive.ip_version = "5".into();
        assert!(matches!(validate_tunnel(&t), Err(ValidateError::InvalidIpVersion(_))));
        let mut t = tunnel();
        t.logging.level = "loud".into();
        assert!(matches!(validate_tunnel(&t), Err(ValidateError::InvalidLogLevel(_))));
        let mut t = tunnel();
        t.logging.format = "xml".into();
        assert!(matches!(validate_tunnel(&t), Err(ValidateError::InvalidLogFormat(_))));
    }

    // ---- Proxy ----

    #[test]
    fn accepts_a_valid_proxy() {
        let id = TunnelId::new();
        validate_proxy(&proxy(id), &[id], &[]).unwrap();
    }

    #[test]
    fn proxy_needs_a_listener() {
        let id = TunnelId::new();
        let mut p = proxy(id);
        p.listeners.http_port = 0;
        p.listeners.socks_port = 0;
        assert!(matches!(validate_proxy(&p, &[id], &[]), Err(ProxyValidateError::NoListeners)));
        p.listeners.socks_port = 1081;
        assert!(validate_proxy(&p, &[id], &[]).is_ok());
    }

    #[test]
    fn proxy_mitm_checks() {
        let id = TunnelId::new();
        let mut p = proxy(id);
        p.mitm = Some(MitmConfig { ca: None, ..MitmConfig::default() });
        assert!(matches!(validate_proxy(&p, &[id], &[]), Err(ProxyValidateError::MissingMitmCa)));
        p.mitm = Some(MitmConfig {
            ca: Some(MitmCaId::new()),
            cert_ttl: Duration::from_secs(1),
            ..MitmConfig::default()
        });
        assert!(matches!(
            validate_proxy(&p, &[id], &[]),
            Err(ProxyValidateError::CertTtlTooShort(_))
        ));
        p.mitm = Some(MitmConfig {
            ca: Some(MitmCaId::new()),
            upstream_tls_mode: MitmUpstreamTlsMode::Allowlist,
            insecure_hosts: vec!["localhost".into(), "*.corp.local".into(), "10.0.0.0/8".into()],
            ..MitmConfig::default()
        });
        assert!(validate_proxy(&p, &[id], &[]).is_ok());
        p.mitm.as_mut().unwrap().bypass_hosts = vec!["*.bank.example".into(), "bad rule".into()];
        assert!(matches!(
            validate_proxy(&p, &[id], &[]),
            Err(ProxyValidateError::InvalidFilterRule { scope: "mitm_bypass_hosts", .. })
        ));
        p.mitm.as_mut().unwrap().bypass_hosts = vec!["*.bank.example".into()];
        p.mitm.as_mut().unwrap().insecure_hosts.push("bad rule with spaces".into());
        assert!(matches!(
            validate_proxy(&p, &[id], &[]),
            Err(ProxyValidateError::InvalidFilterRule { scope: "mitm_insecure_hosts", .. })
        ));
    }

    #[test]
    fn proxy_network_checks() {
        let id = TunnelId::new();
        let mut p = proxy(id);
        p.network.tcp_keepalive_interval = Duration::ZERO;
        assert!(matches!(
            validate_proxy(&p, &[id], &[]),
            Err(ProxyValidateError::InvalidKeepalive(_))
        ));
        let mut p = proxy(id);
        p.network.connect_timeout = Duration::ZERO;
        assert!(matches!(
            validate_proxy(&p, &[id], &[]),
            Err(ProxyValidateError::ZeroConnectTimeout)
        ));
    }

    #[test]
    fn proxy_filter_and_logging_checks() {
        let id = TunnelId::new();
        let mut p = proxy(id);
        p.filter = GlobalFilterConfig::Allow(vec!["".into()]);
        assert!(matches!(
            validate_proxy(&p, &[id], &[]),
            Err(ProxyValidateError::InvalidFilterRule { scope: "filter_allow", .. })
        ));
        let mut p = proxy(id);
        p.logging.level = "loud".into();
        assert!(matches!(
            validate_proxy(&p, &[id], &[]),
            Err(ProxyValidateError::InvalidLogLevel(_))
        ));
        let mut p = proxy(id);
        p.logging.format = "xml".into();
        assert!(matches!(
            validate_proxy(&p, &[id], &[]),
            Err(ProxyValidateError::InvalidLogFormat(_))
        ));
    }

    #[test]
    fn proxy_profile_names() {
        let id = TunnelId::new();
        let mut p = proxy(id);
        p.profiles.push(upstream("corp", UpstreamKind::Socks5, 1081));
        assert!(matches!(
            validate_proxy(&p, &[id], &[]),
            Err(ProxyValidateError::DuplicateProfile(n)) if n == "corp"
        ));
        for reserved in ["direct", "block"] {
            let mut p = proxy(id);
            p.profiles.push(upstream(reserved, UpstreamKind::Http, 1081));
            assert!(matches!(
                validate_proxy(&p, &[id], &[]),
                Err(ProxyValidateError::ReservedProfileName(n)) if n == reserved
            ));
        }
    }

    #[test]
    fn proxy_unknown_tunnel() {
        let id = TunnelId::new();
        assert!(matches!(
            validate_proxy(&proxy(id), &[TunnelId::new()], &[]),
            Err(ProxyValidateError::UnknownTunnel { profile, tunnel_id })
                if profile == "ssh" && tunnel_id == id
        ));
    }

    #[test]
    fn proxy_self_loop_on_own_and_extra_listeners() {
        let id = TunnelId::new();
        let mut p = proxy(id);
        p.profiles[0].port = Some(3128);
        assert!(matches!(
            validate_proxy(&p, &[id], &[]),
            Err(ProxyValidateError::Routing(RoutingError::SelfLoop { .. }))
        ));
        let extra = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        assert!(validate_proxy(&proxy(id), &[id], &[]).is_ok());
        assert!(matches!(
            validate_proxy(&proxy(id), &[id], &[extra]),
            Err(ProxyValidateError::Routing(RoutingError::SelfLoop { profile, .. })) if profile == "corp"
        ));
    }

    #[test]
    fn proxy_bad_rules_are_caught_by_the_engine() {
        let id = TunnelId::new();
        let mut p = proxy(id);
        p.routing.rules[0].target = RouteOneOrMany::One("nope".into());
        assert!(matches!(
            validate_proxy(&p, &[id], &[]),
            Err(ProxyValidateError::Routing(RoutingError::UnknownProfile { .. }))
        ));
        let mut p = proxy(id);
        p.routing.rules[0].cidr = Some(RouteOneOrMany::One("not-a-cidr".into()));
        assert!(matches!(
            validate_proxy(&p, &[id], &[]),
            Err(ProxyValidateError::Routing(_))
        ));
        let mut p = proxy(id);
        p.routing.rules[0].host_regex = Some(RouteOneOrMany::One("(".into()));
        assert!(matches!(
            validate_proxy(&p, &[id], &[]),
            Err(ProxyValidateError::Routing(_))
        ));
        let mut p = proxy(id);
        p.profiles.push(upstream(
            "split",
            UpstreamKind::Composite { http: "missing".into(), https: "".into(), fallback: "".into() },
            0,
        ));
        assert!(matches!(
            validate_proxy(&p, &[id], &[]),
            Err(ProxyValidateError::Routing(RoutingError::UnknownProfile { .. }))
        ));
    }

    #[test]
    fn proxy_profile_shape_is_checked_by_the_engine() {
        let id = TunnelId::new();
        let mut p = proxy(id);
        p.profiles[0].host = None;
        assert!(matches!(
            validate_proxy(&p, &[id], &[]),
            Err(ProxyValidateError::Routing(RoutingError::InvalidProfile { .. }))
        ));
    }

    #[test]
    fn tunnel_forward_filters_are_always_validated() {
        let mut t = tunnel();
        assert!(!t.forward.enabled);
        t.forward.allow = vec!["allowed.example".into()];
        t.forward.block = vec!["*.example".into()];
        validate_tunnel(&t).unwrap();

        t.forward.allow = vec!["bad*rule".into()];
        assert!(matches!(
            validate_tunnel(&t),
            Err(ValidateError::InvalidFilterRule { scope: "forward_allow", .. })
        ));

        let mut t = tunnel();
        t.forward.block = vec!["".into()];
        assert!(matches!(
            validate_tunnel(&t),
            Err(ValidateError::InvalidFilterRule { scope: "forward_block", .. })
        ));
    }

    #[test]
    fn tunnel_forward_enabled_checks_ports_collisions_and_mitm() {
        // Inactive MITM when forward is off does not fail validation.
        let mut t = tunnel();
        t.mitm = Some(MitmConfig { ca: None, ..MitmConfig::default() });
        validate_tunnel(&t).unwrap();

        // Forward on with both ports 0 is rejected.
        t.forward.enabled = true;
        t.forward.http_port = 0;
        t.forward.socks_port = 0;
        assert!(matches!(validate_tunnel(&t), Err(ValidateError::NoListeners)));

        // Forward on checks MITM CA and cert_ttl.
        t.forward.http_port = 3128;
        assert!(matches!(validate_tunnel(&t), Err(ValidateError::MissingMitmCa)));
        t.mitm = Some(MitmConfig {
            ca: Some(MitmCaId::new()),
            cert_ttl: Duration::from_secs(1),
            ..MitmConfig::default()
        });
        assert!(matches!(validate_tunnel(&t), Err(ValidateError::CertTtlTooShort(_))));
        t.mitm = Some(MitmConfig {
            ca: Some(MitmCaId::new()),
            cert_ttl: Duration::from_secs(60),
            ..MitmConfig::default()
        });
        validate_tunnel(&t).unwrap();

        // Forward on checks every MITM insecure host rule; forward off does not.
        t.mitm.as_mut().unwrap().insecure_hosts = vec!["*.corp.local".into(), "bad rule".into()];
        assert!(matches!(
            validate_tunnel(&t),
            Err(ValidateError::InvalidFilterRule { scope: "mitm_insecure_hosts", .. })
        ));
        t.forward.enabled = false;
        validate_tunnel(&t).unwrap();
        t.forward.enabled = true;
        t.mitm.as_mut().unwrap().insecure_hosts = vec!["10.0.0.0/8".into()];
        validate_tunnel(&t).unwrap();
        t.mitm.as_mut().unwrap().bypass_hosts = vec!["bad rule".into()];
        assert!(matches!(
            validate_tunnel(&t),
            Err(ValidateError::InvalidFilterRule { scope: "mitm_bypass_hosts", .. })
        ));
        t.forward.enabled = false;
        validate_tunnel(&t).unwrap();
        t.forward.enabled = true;
        t.mitm.as_mut().unwrap().bypass_hosts = vec!["*.bank.example".into()];
        validate_tunnel(&t).unwrap();

        // Local port forward colliding with active forward proxy port is rejected.
        t.port_forwards.push(PortForward {
            enabled: true,
            direction: ForwardDirection::Local,
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 3128,
            dest_host: "db.internal".into(),
            dest_port: 5432,
            ..PortForward::default()
        });
        assert!(matches!(
            validate_tunnel(&t),
            Err(ValidateError::InvalidPortForward { index: 0, .. })
        ));
    }

    #[test]
    fn tunnel_rejects_proxy_protocol_on_remote_port_forward() {
        let mut t = tunnel();
        t.port_forwards.push(PortForward {
            enabled: true,
            direction: ForwardDirection::Local,
            port: 18080,
            dest_host: "proxy.internal".into(),
            dest_port: 1080,
            proxy_protocol: ForwardProxyProtocol::Socks5,
            ..PortForward::default()
        });
        validate_tunnel(&t).unwrap();

        t.port_forwards.push(PortForward {
            enabled: true,
            direction: ForwardDirection::Remote,
            port: 19090,
            dest_host: "127.0.0.1".into(),
            dest_port: 8080,
            proxy_protocol: ForwardProxyProtocol::Http,
            ..PortForward::default()
        });
        assert!(matches!(
            validate_tunnel(&t),
            Err(ValidateError::InvalidPortForward { index: 1, .. })
        ));
    }

    #[test]
    fn proxy_rejects_at_prefixed_user_profile_names() {
        let id = TunnelId::new();
        let mut p = proxy(id);
        p.profiles.push(upstream("@custom", UpstreamKind::Http, 1081));
        assert!(matches!(
            validate_proxy(&p, &[id], &[]),
            Err(ProxyValidateError::ReservedProfileName(n)) if n == "@custom"
        ));
    }

    #[test]
    fn proxy_with_tunnels_validates_synthetic_tunnel_and_forward_targets() {
        use crate::v2_model::{forward_target_name, tunnel_target_name};

        let fwd_ok = Uuid::new_v4();
        let fwd_plain = Uuid::new_v4();
        let fwd_remote = Uuid::new_v4();
        let mut t = tunnel();
        t.id = TunnelId::new();
        t.port_forwards = vec![
            PortForward {
                id: fwd_ok,
                direction: ForwardDirection::Local,
                port: 18080,
                dest_host: "proxy.internal".into(),
                dest_port: 3128,
                proxy_protocol: ForwardProxyProtocol::Http,
                ..PortForward::default()
            },
            PortForward {
                id: fwd_plain,
                direction: ForwardDirection::Local,
                port: 15432,
                dest_host: "db.internal".into(),
                dest_port: 5432,
                proxy_protocol: ForwardProxyProtocol::None,
                ..PortForward::default()
            },
            PortForward {
                id: fwd_remote,
                direction: ForwardDirection::Remote,
                port: 19090,
                dest_host: "127.0.0.1".into(),
                dest_port: 8080,
                proxy_protocol: ForwardProxyProtocol::None,
                ..PortForward::default()
            },
        ];

        // Valid @tunnel and @forward targets with zero manual UpstreamProfiles.
        let mut p = Proxy { name: "p".into(), ..Proxy::default() };
        p.routing.default = RouteOneOrMany::One(tunnel_target_name(t.id));
        let mut rule = RoutingRule::to_target(RouteOneOrMany::One(forward_target_name(t.id, fwd_ok)));
        rule.host_wildcard = Some(RouteOneOrMany::One("*.corp.example".into()));
        p.routing.rules.push(rule);
        validate_proxy_with_tunnels(&p, std::slice::from_ref(&t), &[]).unwrap();

        // Unknown @tunnel target.
        let unknown_tid = TunnelId::new();
        let mut bad_t = p.clone();
        bad_t.routing.default = RouteOneOrMany::One(tunnel_target_name(unknown_tid));
        assert!(matches!(
            validate_proxy_with_tunnels(&bad_t, std::slice::from_ref(&t), &[]),
            Err(ProxyValidateError::UnknownTunnel { tunnel_id, .. }) if tunnel_id == unknown_tid
        ));

        // @forward targeting a non-proxy local forward, a remote forward, or a missing forward.
        for bad_fid in [fwd_plain, fwd_remote, Uuid::new_v4()] {
            let mut bad_f = p.clone();
            bad_f.routing.rules[0].target =
                RouteOneOrMany::One(forward_target_name(t.id, bad_fid));
            assert!(matches!(
                validate_proxy_with_tunnels(&bad_f, std::slice::from_ref(&t), &[]),
                Err(ProxyValidateError::UnknownTunnelForward { tunnel_id, forward_id })
                    if tunnel_id == t.id && forward_id == bad_fid
            ));
        }
    }
}
