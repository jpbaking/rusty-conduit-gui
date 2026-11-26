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

use crate::model::LoggingConfig;
use crate::v2_mapping::build_routing_input;
use crate::v2_model::{GlobalFilterConfig, Proxy, Tunnel, TunnelId, UpstreamKind};
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
    #[error("`{0}` is a built-in profile name and cannot be used for an upstream profile")]
    ReservedProfileName(String),
    #[error("profile `{profile}` routes through tunnel {tunnel_id}, which does not exist")]
    UnknownTunnel { profile: String, tunnel_id: TunnelId },
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

    let reverse = (tunnel.reverse.reverse_bind, tunnel.reverse.effective_ports());
    for (index, forward) in tunnel.port_forwards.iter().enumerate() {
        if let Some(message) =
            port_forward_problem_in(&tunnel.port_forwards, index, forward, None, reverse)
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

    let r = &tunnel.reverse;
    let invalid = |scope, rule, message| ValidateError::InvalidFilterRule { scope, rule, message };
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
/// `known_tunnels` are the Tunnels an [`UpstreamKind::Tunnel`] profile may name.
/// `extra_listeners` (other Proxies' listeners and Tunnel reverse listeners) join the Proxy's
/// own listeners for self-loop detection.
pub fn validate_proxy(
    proxy: &Proxy,
    known_tunnels: &[TunnelId],
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
        if p.name == PROFILE_DIRECT || p.name == PROFILE_BLOCK {
            return Err(ProxyValidateError::ReservedProfileName(p.name.clone()));
        }
        if !names.insert(p.name.as_str()) {
            return Err(ProxyValidateError::DuplicateProfile(p.name.clone()));
        }
        if let UpstreamKind::Tunnel { tunnel_id } = p.kind {
            if !known_tunnels.contains(&tunnel_id) {
                return Err(ProxyValidateError::UnknownTunnel {
                    profile: p.name.clone(),
                    tunnel_id,
                });
            }
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
        ForwardDirection, HopEntry, HostProfile, MitmCaId, MitmConfig, PortForward,
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
}
