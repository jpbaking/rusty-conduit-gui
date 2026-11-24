//! `conduit-core` — validation of a [`SessionProfile`] before it is mapped into a
//! `rusty_conduit_ssh::config::Config`.
//!
//! This mirrors the `FATAL` rules in [`rusty_conduit_ssh::config::Config::validate`], plus
//! parsing of the human-friendly string fields (`ip_version`, `level`, `format`) and the
//! `rusty-conduit-ssh` filter syntax that this crate stores as strings.

use std::str::FromStr;
use std::time::Duration;

use rusty_conduit_ssh::config::{
    MAX_TCP_KEEPALIVE_DURATION, MAX_TCP_KEEPALIVE_RETRIES, MIN_MITM_CERT_TTL, SshIpVersion,
};
use rusty_conduit_ssh::filter::FilterRule;
use rusty_conduit_ssh::logging::{LogFormat, LogLevel};
use thiserror::Error;

use crate::{MitmCaMode, SessionProfile};

/// Errors raised when a [`SessionProfile`] fails validation. Every variant is `FATAL`.
#[derive(Debug, Error)]
pub enum ValidateError {
    #[error(
        "no listeners: turn on the forward or reverse proxy with at least one non-zero port"
    )]
    NoListeners,
    // Structural: `MitmCaMode` is an enum, so a PKCS#12 bundle and a PEM pair can never coexist.
    // Kept for parity with the upstream `Config` which stored these as independent optionals.
    #[error("ambiguous MITM CA source: a PKCS#12 bundle cannot be combined with a PEM cert/key")]
    AmbiguousCaSource,
    #[error("incomplete PEM MITM CA: both cert and key must be provided")]
    IncompletePemCa,
    #[error(
        "conflicting passphrase sources: use only one of an inline passphrase or a passphrase file"
    )]
    ConflictingPassphrase,
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
}

/// Whether the forward (`ssh -D`) proxy is on with at least one listener.
fn forward_enabled(profile: &SessionProfile) -> bool {
    profile.forward.effective_ports() != (0, 0)
}

/// Whether the reverse (`ssh -R`) proxy is on with at least one listener.
fn reverse_enabled(profile: &SessionProfile) -> bool {
    profile.reverse.effective_ports() != (0, 0)
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
fn denylisted_flag(token: &str) -> Option<&'static str> {
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
    if t.tcp_keepalive.is_zero() {
        return Ok(());
    }
    let range = Duration::from_secs(1)..=MAX_TCP_KEEPALIVE_DURATION;
    let max = MAX_TCP_KEEPALIVE_DURATION.as_secs();
    let fmt = |d: Duration| humantime::format_duration(d).to_string();
    if !range.contains(&t.tcp_keepalive) {
        return Err(ValidateError::InvalidKeepalive(format!(
            "--tcp-keepalive must be 0 (disabled) or between 1s and {max}s (got {})",
            fmt(t.tcp_keepalive)
        )));
    }
    if !range.contains(&t.tcp_keepalive_interval) {
        return Err(ValidateError::InvalidKeepalive(format!(
            "--tcp-keepalive-interval must be between 1s and {max}s (got {})",
            fmt(t.tcp_keepalive_interval)
        )));
    }
    if !(1..=MAX_TCP_KEEPALIVE_RETRIES).contains(&t.tcp_keepalive_retries) {
        return Err(ValidateError::InvalidKeepalive(format!(
            "--tcp-keepalive-retries must be between 1 and {MAX_TCP_KEEPALIVE_RETRIES} (got {})",
            t.tcp_keepalive_retries
        )));
    }
    Ok(())
}

/// Validate a [`SessionProfile`], returning the first `FATAL` problem found.
///
/// The rules here are a faithful port of [`rusty_conduit_ssh::config::Config::validate`],
/// extended to parse the string-encoded fields this crate stores (`ip_version`, `level`,
/// `format`) and the `rusty-conduit-ssh` filter syntax.
pub fn validate(profile: &SessionProfile) -> Result<(), ValidateError> {
    // At least one listener must be enabled.
    if !forward_enabled(profile) && !reverse_enabled(profile) {
        return Err(ValidateError::NoListeners);
    }

    // MITM: structural completeness, conflicting passphrase source, and cert TTL.
    if let Some(mitm) = &profile.mitm {
        match &mitm.ca_mode {
            MitmCaMode::Pkcs12 { .. } => {}
            MitmCaMode::Pem { cert, key } => {
                if cert.to_str().map(|s| s.is_empty()).unwrap_or(true)
                    || key.to_str().map(|s| s.is_empty()).unwrap_or(true)
                {
                    return Err(ValidateError::IncompletePemCa);
                }
            }
        }
        if mitm.passphrase.is_some() && mitm.ca_passphrase_file.is_some() {
            return Err(ValidateError::ConflictingPassphrase);
        }
        if mitm.cert_ttl < MIN_MITM_CERT_TTL {
            return Err(ValidateError::CertTtlTooShort(mitm.cert_ttl));
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

    // Forward and reverse filters are each mutually exclusive allow/block.
    if !profile.forward.allow.is_empty() && !profile.forward.block.is_empty() {
        return Err(ValidateError::ConflictingFilter { scope: "forward" });
    }
    if !profile.reverse.reverse_allow.is_empty() && !profile.reverse.reverse_block.is_empty() {
        return Err(ValidateError::ConflictingFilter { scope: "reverse" });
    }

    // Every filter rule must parse as a `rusty-conduit-ssh` `FilterRule`.
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
        ForwardConfig, HopEntry, HostProfile, MitmCaMode, ReverseConfig, SessionProfile,
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
            ..Default::default()
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
    fn conflicting_passphrase_is_rejected() {
        let mut p = forward_profile();
        p.mitm = Some(crate::MitmConfig {
            ca_mode: MitmCaMode::Pkcs12 {
                path: "/tmp/ca.p12".into(),
            },
            passphrase: Some(crate::SecretRef::new()),
            ca_passphrase_file: Some("/tmp/ca.txt".into()),
            ..Default::default()
        });
        assert!(matches!(
            validate(&p),
            Err(ValidateError::ConflictingPassphrase)
        ));
    }

    #[test]
    fn short_cert_ttl_is_rejected() {
        let mut p = forward_profile();
        p.mitm = Some(crate::MitmConfig {
            ca_mode: MitmCaMode::Pkcs12 {
                path: "/tmp/ca.p12".into(),
            },
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
    fn conflicting_forward_filters_are_rejected() {
        let mut p = forward_profile();
        p.forward.allow = vec!["example.com".into()];
        p.forward.block = vec!["10.0.0.0/8".into()];
        assert!(matches!(
            validate(&p),
            Err(ValidateError::ConflictingFilter { scope: "forward" })
        ));
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
}
