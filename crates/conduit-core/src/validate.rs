//! `conduit-core` — validation of a [`SessionProfile`] before it is mapped into an
//! [`crate::EngineConfig`] for `rusty_conduit_engine`.
//!
//! This mirrors the `FATAL` rules the `rusty-conduit` CLI family applies to its configuration,
//! plus parsing of the human-friendly string fields (`ip_version`, `level`, `format`) and the
//! `rusty-conduit-engine` filter syntax that this crate stores as strings.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use rusty_conduit_engine::filter::FilterRule;
use rusty_conduit_engine::logging::{LogFormat, LogLevel};
use rusty_conduit_engine::mitm::MIN_MITM_CERT_TTL;
use thiserror::Error;

use crate::{ForwardDirection, ForwardPreset, PortForward, SessionProfile};

/// Largest accepted TCP keepalive idle time / probe interval (Linux caps both at 32767s).
pub(crate) const MAX_TCP_KEEPALIVE_DURATION: Duration = Duration::from_secs(32_767);
/// Largest accepted TCP keepalive probe count (Linux caps `TCP_KEEPCNT` at 127).
pub(crate) const MAX_TCP_KEEPALIVE_RETRIES: u32 = 127;

/// IP family used to reach the SSH target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SshIpVersion {
    /// Force IPv4.
    V4,
    /// Force IPv6.
    V6,
    /// Let the resolver choose.
    Auto,
}

impl SshIpVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V4 => "4",
            Self::V6 => "6",
            Self::Auto => "auto",
        }
    }
}

impl fmt::Display for SshIpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SshIpVersion {
    type Err = String;

    /// Case-insensitive: `4`/`v4`/`ipv4`, `6`/`v6`/`ipv6`, or `auto`/`any`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "4" | "v4" | "ipv4" => Ok(Self::V4),
            "6" | "v6" | "ipv6" => Ok(Self::V6),
            "auto" | "any" => Ok(Self::Auto),
            _ => Err(format!(
                "invalid SSH IP version {s:?} (expected 4, 6, or auto)"
            )),
        }
    }
}

/// Errors raised when a [`SessionProfile`] fails validation. Every variant is `FATAL`.
#[derive(Debug, Error)]
pub enum ValidateError {
    #[error(
        "no listeners: turn on the forward or reverse proxy with at least one non-zero port, or a port forward"
    )]
    NoListeners,
    #[error("MITM is on but no CA is selected: upload a CA in the Key Vault and choose it")]
    MissingMitmCa,
    #[error("--mitm-cert-ttl must be at least 10s (got {})", humantime::format_duration(*.0))]
    CertTtlTooShort(Duration),
    #[error("missing SSH target: the session must have at least one hop")]
    MissingSshTarget,
    #[error("SSH target host must not be empty")]
    EmptySshTarget,
    #[error(
        "--reconnect-initial-delay ({}) must not exceed --reconnect-max-delay ({})",
        humantime::format_duration(*.initial),
        humantime::format_duration(*.max)
    )]
    ReconnectDelayOrder {
        initial: Duration,
        max: Duration,
    },
    #[error("invalid TCP keepalive setting: {0}")]
    InvalidKeepalive(String),
    #[error("both an allowlist and a blocklist are set for `{scope}` filters: choose one")]
    ConflictingFilter { scope: &'static str },
    #[error("invalid filter rule in `{scope}`: {rule} ({message})")]
    InvalidFilterRule {
        scope: &'static str,
        rule: String,
        message: String,
    },
    #[error("invalid SSH IP version {0:?} (expected 4, 6, or auto)")]
    InvalidIpVersion(String),
    #[error("{0}")]
    InvalidLogLevel(String),
    #[error("{0}")]
    InvalidLogFormat(String),
    #[error(
        "forbidden ssh flag `{flag}` in extra_args ({arg}): these flags break tunnel isolation and are not permitted"
    )]
    IsolationDenylist {
        flag: &'static str,
        arg: String,
    },
    #[error("port forward {} ({spec}): {message}", .index + 1)]
    InvalidPortForward {
        index: usize,
        spec: String,
        message: String,
    },
}

/// Whether the forward (`ssh -D`) proxy is on with at least one listener.
fn forward_enabled(profile: &SessionProfile) -> bool {
    profile.forward.effective_ports() != (0, 0)
}

/// Whether the reverse (`ssh -R`) proxy is on with at least one listener.
fn reverse_enabled(profile: &SessionProfile) -> bool {
    profile.reverse.effective_ports() != (0, 0)
}

/// Longest DNS name, as in RFC 1035.
const MAX_HOST_LEN: usize = 253;

/// A forward destination is an IP literal (IPv6 with or without brackets) or a DNS name. Only
/// name characters are allowed, so the value cannot change how `ssh` reads a `-R` argument.
fn forward_host_problem(host: &str) -> Option<&'static str> {
    if host.is_empty() {
        return Some("enter a destination host");
    }
    let bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    if bare.parse::<IpAddr>().is_ok() {
        return None;
    }
    if host.len() > MAX_HOST_LEN {
        return Some("the destination host name is too long");
    }
    let valid = host
        .split('.')
        .all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    if valid { None } else { Some("the destination host must be a host name or an IP address") }
}

/// Checks a [`ForwardPreset`]. Its destination host may be empty, to be filled in per session.
pub fn validate_forward_preset(preset: &ForwardPreset) -> Result<(), String> {
    if preset.name.trim().is_empty() {
        return Err("enter a preset name".into());
    }
    if preset.port == 0 {
        return Err("choose a listen port from 1 to 65535".into());
    }
    if preset.dest_port == 0 {
        return Err("choose a destination port from 1 to 65535".into());
    }
    let host = preset.dest_host.trim();
    match forward_host_problem(host) {
        Some(problem) if !host.is_empty() => Err(problem.into()),
        _ => Ok(()),
    }
}

/// Two binds collide on the same IP, or when either listens on all interfaces.
fn binds_overlap(a: IpAddr, b: IpAddr) -> bool {
    a == b || a.is_unspecified() || b.is_unspecified()
}

/// What makes forward `index` unusable, given the rest of the profile.
fn port_forward_problem(profile: &SessionProfile, index: usize, forward: &PortForward) -> Option<String> {
    port_forward_problem_in(
        &profile.port_forwards,
        index,
        forward,
        Some((profile.forward.bind, profile.forward.effective_ports())),
        (profile.reverse.reverse_bind, profile.reverse.effective_ports()),
    )
}

/// What makes `forwards[index]` unusable. `local_proxy` / `remote_proxy` are the `(bind,
/// (http, socks))` listeners a forward in that direction must not collide with; a `Tunnel`
/// has no local proxy, so it passes `None`.
pub(crate) fn port_forward_problem_in(
    forwards: &[PortForward],
    index: usize,
    forward: &PortForward,
    local_proxy: Option<(IpAddr, (u16, u16))>,
    remote_proxy: (IpAddr, (u16, u16)),
) -> Option<String> {
    if forward.port == 0 {
        return Some("choose a listen port from 1 to 65535".into());
    }
    if forward.dest_port == 0 {
        return Some("choose a destination port from 1 to 65535".into());
    }
    if let Some(problem) = forward_host_problem(forward.dest_host.trim()) {
        return Some(problem.into());
    }
    if !forward.enabled {
        return None;
    }
    let proxy = match forward.direction {
        ForwardDirection::Local => local_proxy.map(|p| (p, "forward")),
        ForwardDirection::Remote => Some((remote_proxy, "reverse")),
    };
    if let Some(((proxy_bind, (http, socks)), side)) = proxy {
        if binds_overlap(forward.bind, proxy_bind) && [http, socks].contains(&forward.port) {
            return Some(format!("port {} is already used by the {side} proxy", forward.port));
        }
    }
    let earlier = forwards[..index].iter().any(|other| {
        other.enabled
            && other.direction == forward.direction
            && other.port == forward.port
            && binds_overlap(other.bind, forward.bind)
    });
    if earlier {
        return Some(format!("another forward already listens on port {}", forward.port));
    }
    None
}

/// Short `ssh` flags that break tunnel isolation. Case-sensitive, as `ssh` treats them.
const DENIED_SHORT_FLAGS: &[&str] = &["F", "J", "i", "O", "S", "A", "a", "W"];

/// `ssh_config` options that break tunnel isolation. Matched case-insensitively, as `ssh` does.
const DENIED_OPTIONS: &[&str] = &[
    "ProxyCommand", "ProxyJump", "IdentityAgent", "IdentityFile", "UserKnownHostsFile",
    "GlobalKnownHostsFile", "StrictHostKeyChecking", "ControlPath", "ControlMaster",
    "ControlPersist", "ForwardAgent", "Include", "LocalCommand", "PermitLocalCommand",
    "RemoteCommand", "KnownHostsCommand", "UpdateHostKeys", "Host", "Match",
];

/// Short flags that consume the rest of their token as a value, from `ssh`'s getopt string.
const VALUE_FLAGS: &str = "bceilmopBDEFIJLOPQRSwW";

/// The denied option named by `text`, read the way `ssh_config` reads a keyword: leading
/// space or quotes are skipped, and it ends at whitespace, `=`, or a quote.
fn denied_option(text: &str) -> Option<&'static str> {
    let keyword = text
        .trim_start_matches([' ', '\t', '\r', '\n', '"'])
        .split([' ', '\t', '\r', '\n', '=', '"'])
        .next()
        .unwrap_or("");
    DENIED_OPTIONS.iter().copied().find(|o| o.eq_ignore_ascii_case(keyword))
}

/// Return the denylisted flag or option a token refers to, if any.
///
/// Every token is checked as a possible option, so the value after a separate `-o` is caught
/// without tracking position. Short flags are walked like getopt, so `-Fconfig`, `-i/path`,
/// and clusters such as `-vA` or `-voProxyCommand=x` all match.
pub(crate) fn denylisted_flag(token: &str) -> Option<&'static str> {
    let undashed = token
        .strip_prefix("--")
        .or_else(|| token.strip_prefix('-'))
        .unwrap_or(token);
    if let Some(option) = denied_option(undashed) {
        return Some(option);
    }
    let name = undashed.split('=').next().unwrap_or("");
    if let Some(flag) = DENIED_SHORT_FLAGS.iter().copied().find(|f| *f == name) {
        return Some(flag);
    }
    let cluster = token.strip_prefix('-')?;
    for (index, c) in cluster.char_indices() {
        if let Some(flag) = DENIED_SHORT_FLAGS.iter().copied().find(|f| f.starts_with(c)) {
            return Some(flag);
        }
        if c == 'o' {
            return denied_option(&cluster[index + 1..]);
        }
        if VALUE_FLAGS.contains(c) {
            return None;
        }
    }
    None
}

/// Mirror of the TCP keepalive range checks in `Config::validate` (Linux kernel limits).
fn tcp_keepalive(profile: &SessionProfile) -> Result<(), ValidateError> {
    let t = &profile.tunnel;
    keepalive_problem(t.tcp_keepalive, t.tcp_keepalive_interval, t.tcp_keepalive_retries)
}

/// TCP keepalive range checks (interval / retries only while keepalive is on).
pub(crate) fn keepalive_problem(
    idle: Duration,
    interval: Duration,
    retries: u32,
) -> Result<(), ValidateError> {
    if idle.is_zero() {
        return Ok(());
    }
    let range = Duration::from_secs(1)..=MAX_TCP_KEEPALIVE_DURATION;
    let max = MAX_TCP_KEEPALIVE_DURATION.as_secs();
    let fmt = |d: Duration| humantime::format_duration(d).to_string();
    if !range.contains(&idle) {
        return Err(ValidateError::InvalidKeepalive(format!(
            "--tcp-keepalive must be 0 (disabled) or between 1s and {max}s (got {})",
            fmt(idle)
        )));
    }
    if !range.contains(&interval) {
        return Err(ValidateError::InvalidKeepalive(format!(
            "--tcp-keepalive-interval must be between 1s and {max}s (got {})",
            fmt(interval)
        )));
    }
    if !(1..=MAX_TCP_KEEPALIVE_RETRIES).contains(&retries) {
        return Err(ValidateError::InvalidKeepalive(format!(
            "--tcp-keepalive-retries must be between 1 and {MAX_TCP_KEEPALIVE_RETRIES} (got {})",
            retries
        )));
    }
    Ok(())
}

/// Validate a [`SessionProfile`], returning the first `FATAL` problem found.
///
/// The rules here are a faithful port of the `rusty-conduit` CLI family's configuration
/// validation, extended to parse the string-encoded fields this crate stores (`ip_version`,
/// `level`, `format`) and the `rusty-conduit-engine` filter syntax.
pub fn validate(profile: &SessionProfile) -> Result<(), ValidateError> {
    // At least one listener must be enabled.
    if !forward_enabled(profile)
        && !reverse_enabled(profile)
        && profile.active_forwards().next().is_none()
    {
        return Err(ValidateError::NoListeners);
    }

    for (index, forward) in profile.port_forwards.iter().enumerate() {
        if let Some(message) = port_forward_problem(profile, index, forward) {
            return Err(ValidateError::InvalidPortForward {
                index,
                spec: forward.spec(),
                message,
            });
        }
    }

    // MITM: a CA must be chosen, and the cert TTL must be long enough.
    if let Some(mitm) = &profile.mitm {
        if mitm.ca.is_none() {
            return Err(ValidateError::MissingMitmCa);
        }
        if mitm.cert_ttl < MIN_MITM_CERT_TTL {
            return Err(ValidateError::CertTtlTooShort(mitm.cert_ttl));
        }
        for rule in &mitm.insecure_hosts {
            if let Err(message) = FilterRule::from_str(rule) {
                return Err(ValidateError::InvalidFilterRule {
                    scope: "mitm_insecure_hosts",
                    rule: rule.clone(),
                    message,
                });
            }
        }
        for rule in &mitm.bypass_hosts {
            if let Err(message) = FilterRule::from_str(rule) {
                return Err(ValidateError::InvalidFilterRule {
                    scope: "mitm_bypass_hosts",
                    rule: rule.clone(),
                    message,
                });
            }
        }
    }

    // SSH target is derived from the last hop.
    match profile.hops.last() {
        None => return Err(ValidateError::MissingSshTarget),
        Some(last) if last.host.host.trim().is_empty() => return Err(ValidateError::EmptySshTarget),
        Some(_) => {}
    }

    // OpenSSH isolation: `extra_args` must not carry flags that let a compromised target or
    // the remote break out of the sandbox. This GUI-owned denylist sits on top of the engine.
    for arg in &profile.openssh.extra_args {
        if let Some(flag) = denylisted_flag(arg) {
            return Err(ValidateError::IsolationDenylist {
                flag,
                arg: arg.clone(),
            });
        }
    }

    // Reconnect backoff ordering.
    if profile.tunnel.reconnect_initial_delay > profile.tunnel.reconnect_max_delay {
        return Err(ValidateError::ReconnectDelayOrder {
            initial: profile.tunnel.reconnect_initial_delay,
            max: profile.tunnel.reconnect_max_delay,
        });
    }

    // TCP keepalive ranges (interval / retries are only checked while keepalive is on).
    tcp_keepalive(profile)?;

    // Every filter rule must parse as a `rusty-conduit-engine` `FilterRule`.
    for rule in &profile.forward.allow {
        if let Err(message) = FilterRule::from_str(rule) {
            return Err(ValidateError::InvalidFilterRule {
                scope: "forward_allow",
                rule: rule.clone(),
                message,
            });
        }
    }
    for rule in &profile.forward.block {
        if let Err(message) = FilterRule::from_str(rule) {
            return Err(ValidateError::InvalidFilterRule {
                scope: "forward_block",
                rule: rule.clone(),
                message,
            });
        }
    }
    for rule in &profile.reverse.reverse_allow {
        if let Err(message) = FilterRule::from_str(rule) {
            return Err(ValidateError::InvalidFilterRule {
                scope: "reverse_allow",
                rule: rule.clone(),
                message,
            });
        }
    }
    for rule in &profile.reverse.reverse_block {
        if let Err(message) = FilterRule::from_str(rule) {
            return Err(ValidateError::InvalidFilterRule {
                scope: "reverse_block",
                rule: rule.clone(),
                message,
            });
        }
    }

    // String-encoded enums must parse.
    if let Err(message) = SshIpVersion::from_str(&profile.tunnel.ip_version) {
        return Err(ValidateError::InvalidIpVersion(message));
    }
    if let Err(message) = LogLevel::from_str(&profile.logging.level) {
        return Err(ValidateError::InvalidLogLevel(message));
    }
    if let Err(message) = LogFormat::from_str(&profile.logging.format) {
        return Err(ValidateError::InvalidLogFormat(message));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ForwardConfig, ForwardDirection, HopEntry, HostProfile, MitmCaId, PortForward,
        ReverseConfig, SessionProfile,
    };

    fn target_hop() -> HopEntry {
        HopEntry {
            hop_id: "target".into(),
            name: "target".into(),
            host: HostProfile {
                host: "10.0.0.1".into(),
                port: 22,
                user: "root".into(),
                ..Default::default()
            },
        }
    }

    fn forward_profile() -> SessionProfile {
        SessionProfile {
            name: "forward".into(),
            hops: vec![target_hop()],
            forward: ForwardConfig::default(),
            reverse: ReverseConfig::default(),
            ..Default::default()
        }
    }

    #[test]
    fn accepts_a_valid_forward_session() {
        assert!(validate(&forward_profile()).is_ok());
    }

    #[test]
    fn no_listeners_is_rejected() {
        let mut p = forward_profile();
        p.forward.http_port = 0;
        p.forward.socks_port = 0;
        assert!(matches!(validate(&p), Err(ValidateError::NoListeners)));
    }

    #[test]
    fn switched_off_proxies_do_not_count_as_listeners() {
        let mut p = forward_profile();
        p.forward.enabled = false;
        p.reverse.reverse_http_port = 8888;
        // Reverse ports set but switched off: nothing listens.
        assert!(matches!(validate(&p), Err(ValidateError::NoListeners)));
        p.reverse.enabled = true;
        assert!(validate(&p).is_ok());
    }

    #[test]
    fn missing_hop_is_rejected() {
        let mut p = forward_profile();
        p.hops.clear();
        assert!(matches!(
            validate(&p),
            Err(ValidateError::MissingSshTarget)
        ));
    }

    #[test]
    fn empty_target_host_is_rejected() {
        let mut p = forward_profile();
        p.hops[0].host.host = "   ".into();
        assert!(matches!(
            validate(&p),
            Err(ValidateError::EmptySshTarget)
        ));
    }

    #[test]
    fn isolation_denylist_short_flag_is_rejected() {
        let mut p = forward_profile();
        p.openssh.extra_args = vec!["-J".into(), "jump.example.com".into()];
        assert!(matches!(
            validate(&p),
            Err(ValidateError::IsolationDenylist { .. })
        ));
    }

    #[test]
    fn isolation_denylist_long_flag_with_value_is_rejected() {
        let mut p = forward_profile();
        p.openssh.extra_args = vec!["--IdentityFile=/tmp/id".into()];
        assert!(matches!(
            validate(&p),
            Err(ValidateError::IsolationDenylist { .. })
        ));
    }

    #[test]
    fn bare_long_flag_is_rejected() {
        let mut p = forward_profile();
        p.openssh.extra_args = vec!["ForwardAgent".into()];
        assert!(matches!(
            validate(&p),
            Err(ValidateError::IsolationDenylist { .. })
        ));
    }

    #[test]
    fn allowed_extra_args_pass() {
        let mut p = forward_profile();
        p.openssh.extra_args = vec!["-o".into(), "Compression=yes".into()];
        assert!(validate(&p).is_ok());
    }

    fn denied(args: &[&str]) -> bool {
        let mut p = forward_profile();
        p.openssh.extra_args = args.iter().map(ToString::to_string).collect();
        matches!(validate(&p), Err(ValidateError::IsolationDenylist { .. }))
    }

    #[test]
    fn denylist_rejects_short_flags_standalone_and_attached() {
        for arg in [
            "-F", "-Fconfig", "-J", "-Jjump", "-i", "-i/path", "-O", "-Ocheck", "-S",
            "-S/tmp/ctl", "-A", "-a", "-W", "-Whost:22",
        ] {
            assert!(denied(&[arg]), "{arg} must be rejected");
        }
    }

    #[test]
    fn denylist_rejects_flags_inside_a_cluster() {
        for arg in ["-vA", "-qa", "-vFconfig", "-vvi/path", "-CS/tmp/ctl", "-voProxyCommand=x"] {
            assert!(denied(&[arg]), "{arg} must be rejected");
        }
    }

    #[test]
    fn denylist_rejects_every_option_in_every_form() {
        for option in DENIED_OPTIONS {
            let lower = option.to_lowercase();
            let upper = option.to_uppercase();
            for name in [*option, lower.as_str(), upper.as_str()] {
                for arg in [
                    format!("-o{name}=x"),
                    format!("-o{name} x"),
                    format!("-o {name}=x"),
                    format!("-o\"{name}\" x"),
                    name.to_string(),
                    format!("{name}=x"),
                    format!("-{name}"),
                    format!("--{name}=x"),
                ] {
                    assert!(denied(&[&arg]), "{arg} must be rejected");
                }
                assert!(denied(&["-o", &format!("{name}=x")]), "-o {name}=x must be rejected");
                assert!(denied(&["-o", &format!("{name} x")]), "-o '{name} x' must be rejected");
                assert!(denied(&["-o", &format!(" {name}\t=x")]), "spaced {name} must be rejected");
            }
        }
    }

    #[test]
    fn denylist_error_names_the_canonical_option() {
        let mut p = forward_profile();
        p.openssh.extra_args = vec!["-o".into(), "proxycommand=nc %h %p".into()];
        assert!(matches!(
            validate(&p),
            Err(ValidateError::IsolationDenylist { flag: "ProxyCommand", .. })
        ));
    }

    #[test]
    fn denylist_allows_safe_arguments() {
        for args in [
            &["-o", "Compression=yes"][..],
            &["-oCompression=yes"],
            &["-o", "ServerAliveInterval 30"],
            &["-v"],
            &["-vvv"],
            &["-C"],
            &["-4"],
            &["-p", "2222"],
            &["-p2222"],
            &["-lFoo"],
            &["-c", "aes256-gcm@openssh.com"],
        ] {
            assert!(!denied(args), "{args:?} must be allowed");
        }
    }

    #[test]
    fn mitm_without_a_ca_is_rejected() {
        let mut p = forward_profile();
        p.mitm = Some(crate::MitmConfig::default());
        assert!(matches!(validate(&p), Err(ValidateError::MissingMitmCa)));
        p.mitm.as_mut().unwrap().ca = Some(MitmCaId::new());
        assert!(validate(&p).is_ok());
    }

    #[test]
    fn mitm_insecure_hosts_must_be_filter_rules() {
        let mut p = forward_profile();
        p.mitm = Some(crate::MitmConfig {
            ca: Some(MitmCaId::new()),
            upstream_tls_mode: crate::MitmUpstreamTlsMode::Allowlist,
            insecure_hosts: vec!["localhost".into(), "*.corp.local".into(), "10.0.0.0/8".into()],
            ..Default::default()
        });
        assert!(validate(&p).is_ok());
        p.mitm.as_mut().unwrap().insecure_hosts.push("bad rule".into());
        assert!(matches!(
            validate(&p),
            Err(ValidateError::InvalidFilterRule { scope: "mitm_insecure_hosts", .. })
        ));
    }

    #[test]
    fn mitm_bypass_hosts_must_be_filter_rules() {
        let mut p = forward_profile();
        p.mitm = Some(crate::MitmConfig {
            ca: Some(MitmCaId::new()),
            bypass_hosts: vec!["*.bank.example".into(), "192.0.2.0/24".into()],
            ..Default::default()
        });
        assert!(validate(&p).is_ok());
        assert_eq!(crate::to_engine_config(&p).unwrap().mitm_options.bypass_hosts.len(), 2);
        p.mitm.as_mut().unwrap().bypass_hosts.push("bad rule".into());
        assert!(matches!(
            validate(&p),
            Err(ValidateError::InvalidFilterRule { scope: "mitm_bypass_hosts", .. })
        ));
    }

    #[test]
    fn short_cert_ttl_is_rejected() {
        let mut p = forward_profile();
        p.mitm = Some(crate::MitmConfig {
            ca: Some(MitmCaId::new()),
            cert_ttl: Duration::from_secs(1),
            ..Default::default()
        });
        assert!(matches!(
            validate(&p),
            Err(ValidateError::CertTtlTooShort(_))
        ));
    }

    #[test]
    fn reconnect_order_is_rejected() {
        let mut p = forward_profile();
        p.tunnel.reconnect_initial_delay = Duration::from_secs(60);
        p.tunnel.reconnect_max_delay = Duration::from_secs(30);
        assert!(matches!(
            validate(&p),
            Err(ValidateError::ReconnectDelayOrder { .. })
        ));
    }

    #[test]
    fn tcp_keepalive_ranges() {
        let secs = Duration::from_secs;
        assert!(validate(&forward_profile()).is_ok());
        for (idle, interval, retries) in [
            (secs(32_768), secs(10), 5),
            (Duration::from_millis(500), secs(10), 5),
            (secs(60), Duration::ZERO, 5),
            (secs(60), secs(32_768), 5),
            (secs(60), secs(10), 0),
            (secs(60), secs(10), 128),
        ] {
            let mut p = forward_profile();
            p.tunnel.tcp_keepalive = idle;
            p.tunnel.tcp_keepalive_interval = interval;
            p.tunnel.tcp_keepalive_retries = retries;
            assert!(
                matches!(validate(&p), Err(ValidateError::InvalidKeepalive(_))),
                "{idle:?}/{interval:?}x{retries}"
            );
        }
        // Off: interval and retries are not checked.
        let mut p = forward_profile();
        p.tunnel.tcp_keepalive = Duration::ZERO;
        p.tunnel.tcp_keepalive_interval = Duration::ZERO;
        p.tunnel.tcp_keepalive_retries = 0;
        assert!(validate(&p).is_ok());
        // Upper bounds are inclusive.
        p.tunnel.tcp_keepalive = secs(32_767);
        p.tunnel.tcp_keepalive_interval = secs(32_767);
        p.tunnel.tcp_keepalive_retries = 127;
        assert!(validate(&p).is_ok());
    }

    #[test]
    fn combined_forward_filters_are_allowed() {
        let mut p = forward_profile();
        p.forward.allow = vec!["test.domain.net".into()];
        p.forward.block = vec!["*.domain.net".into()];
        assert!(validate(&p).is_ok());
    }

    #[test]
    fn invalid_filter_rule_is_rejected() {
        let mut p = forward_profile();
        p.forward.allow = vec!["bad*domain".into()];
        assert!(matches!(
            validate(&p),
            Err(ValidateError::InvalidFilterRule { .. })
        ));
    }

    #[test]
    fn invalid_ip_version_is_rejected() {
        let mut p = forward_profile();
        p.tunnel.ip_version = "5".into();
        assert!(matches!(
            validate(&p),
            Err(ValidateError::InvalidIpVersion(_))
        ));
    }

    #[test]
    fn invalid_log_level_is_rejected() {
        let mut p = forward_profile();
        p.logging.level = "SUPER".into();
        assert!(matches!(
            validate(&p),
            Err(ValidateError::InvalidLogLevel(_))
        ));
    }

    #[test]
    fn valid_filter_rules_and_enums_pass() {
        let mut p = forward_profile();
        p.forward.allow = vec!["example.com".into(), "10.0.0.0/8".into(), "*.cdn.net".into()];
        p.tunnel.ip_version = "auto".into();
        p.logging.level = "debug".into();
        p.logging.format = "json".into();
        assert!(validate(&p).is_ok());
    }

    fn local_forward(port: u16, dest: &str, dest_port: u16) -> PortForward {
        PortForward {
            direction: ForwardDirection::Local,
            port,
            dest_host: dest.into(),
            dest_port,
            ..Default::default()
        }
    }

    #[test]
    fn a_port_forward_alone_counts_as_a_listener() {
        let mut p = forward_profile();
        p.forward.enabled = false;
        p.port_forwards = vec![local_forward(15432, "db.internal", 5432)];
        assert!(validate(&p).is_ok());
        p.port_forwards[0].enabled = false;
        assert!(matches!(validate(&p), Err(ValidateError::NoListeners)));
    }

    #[test]
    fn port_forward_ports_and_hosts_are_checked() {
        let cases = [
            (local_forward(0, "db", 5432), "listen port"),
            (local_forward(15432, "db", 0), "destination port"),
            (local_forward(15432, " ", 5432), "destination host"),
            (local_forward(15432, "db:5432", 5432), "host name or an IP"),
            (local_forward(15432, "-oProxyCommand=x", 5432), "host name or an IP"),
            (local_forward(15432, "db host", 5432), "host name or an IP"),
        ];
        for (forward, expected) in cases {
            let mut p = forward_profile();
            p.port_forwards = vec![forward];
            match validate(&p) {
                Err(ValidateError::InvalidPortForward { index: 0, message, .. }) => {
                    assert!(message.contains(expected), "{message}");
                }
                other => panic!("expected an invalid forward, got {other:?}"),
            }
        }
    }

    #[test]
    fn port_forward_accepts_names_and_ip_literals() {
        for host in ["db.internal", "10.0.0.5", "::1", "[fe80::1]", "my_host-1"] {
            let mut p = forward_profile();
            p.port_forwards = vec![local_forward(15432, host, 5432)];
            assert!(validate(&p).is_ok(), "{host}");
        }
    }

    #[test]
    fn port_forwards_must_not_collide() {
        let mut p = forward_profile();
        // The forward proxy's HTTP port on an overlapping bind.
        let mut clash = local_forward(3128, "db", 5432);
        clash.bind = "0.0.0.0".parse().unwrap();
        p.port_forwards = vec![clash.clone()];
        assert!(matches!(validate(&p), Err(ValidateError::InvalidPortForward { .. })));
        // A remote forward on the same number is on another machine.
        clash.direction = ForwardDirection::Remote;
        p.port_forwards = vec![clash];
        assert!(validate(&p).is_ok());

        p.port_forwards = vec![local_forward(9000, "a", 1), local_forward(9000, "b", 2)];
        assert!(matches!(
            validate(&p),
            Err(ValidateError::InvalidPortForward { index: 1, .. })
        ));
        // Switched off, a duplicate is kept but does not clash.
        p.port_forwards[1].enabled = false;
        assert!(validate(&p).is_ok());
    }

    #[test]
    fn port_forward_spec_brackets_ipv6() {
        let mut f = local_forward(9000, "fe80::1", 22);
        f.bind = "::1".parse().unwrap();
        assert_eq!(f.spec(), "[::1]:9000:[fe80::1]:22");
        assert_eq!(local_forward(15432, "db", 5432).spec(), "127.0.0.1:15432:db:5432");
    }

    #[test]
    fn forward_presets_allow_an_empty_host_but_check_the_rest() {
        let mut preset = crate::builtin_forward_presets().remove(0);
        assert!(validate_forward_preset(&preset).is_ok());
        preset.dest_host = "db:1".into();
        assert!(validate_forward_preset(&preset).is_err());
        preset.dest_host = String::new();
        preset.name = " ".into();
        assert!(validate_forward_preset(&preset).is_err());
    }

    #[test]
    fn built_in_presets_seed_once_and_restore_only_what_is_missing() {
        let mut config = crate::AppConfig::default();
        assert!(config.seed_forward_presets());
        let count = config.forward_presets.len();
        assert!(count > 0);
        let removed = config.forward_presets.remove(0);
        assert!(!config.seed_forward_presets(), "seeding happens once");
        assert_eq!(config.forward_presets.len(), count - 1);
        assert_eq!(config.restore_forward_presets(), 1);
        assert!(config.forward_presets.iter().any(|p| p.id == removed.id));
        assert_eq!(config.restore_forward_presets(), 0);
    }
}
