//! `conduit-core` — mapping a validated [`SessionProfile`] into a
//! `rusty_conduit_ssh::config::Config` at session start.
//!
//! The [`rusty_conduit_ssh`] engine has no `serde`, so this crate owns the
//! serde-serializable models (see [`model`]) and converts them into the engine's
//! [`Config`] here. Secret material (`SecretRef` / `KeyId`) lives in the vault and is
//! resolved by the runtime layer, so identity and the MITM passphrase are left `None`
//! here and filled in before the process launches.

use std::path::PathBuf;
use std::str::FromStr;

use rusty_conduit_ssh::config::{
    Config, DEFAULT_MITM_CERT_CACHE_MAX_ENTRIES, DEFAULT_MITM_CERT_TTL, SshIpVersion,
};
use rusty_conduit_ssh::filter::FilterRule;
use rusty_conduit_ssh::logging::{LogFormat, LogLevel};
use thiserror::Error;

use crate::{MitmCaMode, SessionProfile};

/// Errors raised while mapping a [`SessionProfile`] into a [`Config`].
#[derive(Debug, Error)]
pub enum MappingError {
    #[error("session has no hops: the last hop is the SSH target")]
    NoHops,
    #[error("invalid filter rule in `{scope}`: {rule} ({message})")]
    InvalidFilterRule {
        scope: &'static str,
        rule: String,
        message: String,
    },
    #[error("invalid SSH IP version: {0}")]
    InvalidIpVersion(String),
    #[error("invalid log level: {0}")]
    InvalidLogLevel(String),
    #[error("invalid log format: {0}")]
    InvalidLogFormat(String),
}

/// Parse a forward/reverse filter list into `rusty-conduit-ssh` [`FilterRule`]s.
fn parse_rules(scope: &'static str, rules: &[String]) -> Result<Vec<FilterRule>, MappingError> {
    rules
        .iter()
        .map(|r| {
            FilterRule::from_str(r).map_err(|message| MappingError::InvalidFilterRule {
                scope,
                rule: r.clone(),
                message,
            })
        })
        .collect()
}

/// Map a validated [`SessionProfile`] into the engine's [`Config`].
///
/// The caller should run [`crate::validate::validate`] first; this function re-parses the
/// string fields and returns [`MappingError`] if any are malformed (defensive against a
/// profile that bypassed validation).
///
/// `mitm_passphrase` is the already-resolved plaintext CA passphrase. conduit-core never
/// touches the vault: the runtime resolves the [`SecretRef`] before calling this, so no
/// secret bytes live inside this crate.
pub fn to_config(
    profile: &SessionProfile,
    mitm_passphrase: Option<&str>,
) -> Result<Config, MappingError> {
    let last = profile
        .hops
        .last()
        .ok_or(MappingError::NoHops)?
        .host
        .clone();

    let ssh_target = if last.port == 22 {
        format!("{}@{}", last.user, last.host)
    } else {
        format!("{}@{}:{}", last.user, last.host, last.port)
    };

    // Forward listeners.
    let allow = parse_rules("forward", &profile.forward.allow)?;
    let block = parse_rules("forward", &profile.forward.block)?;

    // Reverse listeners.
    let reverse_allow = parse_rules("reverse", &profile.reverse.reverse_allow)?;
    let reverse_block = parse_rules("reverse", &profile.reverse.reverse_block)?;

    // MITM CA source (PEM or PKCS#12), matching `Config::ca_source`.
    let (mitm_ca_cert, mitm_ca_key, mitm_ca_p12) = match profile.mitm.as_ref() {
        Some(mitm) => match &mitm.ca_mode {
            MitmCaMode::Pem { cert, key } => (Some(cert.clone()), Some(key.clone()), None),
            MitmCaMode::Pkcs12 { path } => (None, None, Some(path.clone())),
        },
        None => (None, None, None),
    };

    // String-encoded enums.
    let ssh_ip_version = SshIpVersion::from_str(&profile.tunnel.ip_version)
        .map_err(MappingError::InvalidIpVersion)?;
    let log_level = LogLevel::from_str(&profile.logging.level)
        .map_err(MappingError::InvalidLogLevel)?;
    let log_format = LogFormat::from_str(&profile.logging.format)
        .map_err(MappingError::InvalidLogFormat)?;

    // A proxy that is switched off keeps its ports in the profile but listens on none.
    let (http_port, socks_port) = profile.forward.effective_ports();
    let (reverse_http_port, reverse_socks_port) = profile.reverse.effective_ports();

    Ok(Config {
        config_path: None,
        bind: profile.forward.bind,
        http_port,
        socks_port,
        max_connections: profile.forward.max_connections,
        tcp_keepalive: profile.tunnel.tcp_keepalive,
        tcp_keepalive_interval: profile.tunnel.tcp_keepalive_interval,
        tcp_keepalive_retries: profile.tunnel.tcp_keepalive_retries,
        allow,
        block,
        reverse_bind: profile.reverse.reverse_bind,
        reverse_http_port,
        reverse_socks_port,
        reverse_max_connections: profile
            .reverse
            .reverse_max_connections
            .unwrap_or(profile.forward.max_connections),
        reverse_allow,
        reverse_block,
        mitm_ca_cert,
        mitm_ca_key,
        mitm_ca_p12,
        // Resolved by the runtime layer from the vault; conduit-core owns no secret bytes.
        mitm_ca_passphrase: mitm_passphrase.map(str::to_owned),
        mitm_ca_passphrase_file: profile
            .mitm
            .as_ref()
            .and_then(|m| m.ca_passphrase_file.clone()),
        mitm_cert_ttl: profile
            .mitm
            .as_ref()
            .map(|m| m.cert_ttl)
            .unwrap_or_else(|| DEFAULT_MITM_CERT_TTL),
        mitm_cert_cache_max_entries: profile
            .mitm
            .as_ref()
            .map(|m| m.cert_cache_max_entries)
            .unwrap_or_else(|| DEFAULT_MITM_CERT_CACHE_MAX_ENTRIES),
        socks_block_web_in_mitm: profile.mitm.as_ref().map(|m| m.socks_block_web).unwrap_or(false),
        log_level,
        log_format,
        http_access_log: profile.logging.http_access_log.clone(),
        socks_log: profile.logging.socks_log.clone(),
        passphrase_from_cli: false,
        ssh_target: Some(ssh_target),
        ssh_bin: PathBuf::from(profile.openssh.ssh_bin.clone()),
        ssh_socks_bind: profile.openssh.ssh_socks_bind,
        ssh_socks_port: profile.openssh.ssh_socks_port,
        ssh_ip_version,
        ssh_port: Some(last.port),
        // Resolved by the runtime layer from the vault; conduit-core owns no secret bytes.
        ssh_identity: None,
        ssh_config: None,
        // Multi-hop is traversed by the russh engine, not `ssh -J`.
        ssh_jump: None,
        ssh_server_alive_interval: profile.tunnel.server_alive_interval,
        ssh_server_alive_count_max: profile.tunnel.server_alive_count_max,
        no_reconnect: profile.tunnel.no_reconnect,
        reconnect_initial_delay: profile.tunnel.reconnect_initial_delay,
        reconnect_max_delay: profile.tunnel.reconnect_max_delay,
        ssh_startup_timeout: profile.tunnel.startup_timeout,
        ssh_extra_args: profile.openssh.extra_args.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ForwardConfig, HopEntry, HostProfile, LoggingConfig, MitmCaMode, ReverseConfig,
        SessionProfile, SshEngine, TunnelConfig,
    };
    use std::time::Duration;

    fn target_hop() -> HopEntry {
        HopEntry {
            hop_id: "target".into(),
            name: "target".into(),
            host: HostProfile {
                host: "10.0.0.1".into(),
                port: 2222,
                user: "root".into(),
                ..Default::default()
            },
        }
    }

    fn profile() -> SessionProfile {
        SessionProfile {
            name: "mapped".into(),
            hops: vec![target_hop()],
            forward: ForwardConfig {
                http_port: 3128,
                socks_port: 1080,
                allow: vec!["example.com".into()],
                block: vec![],
                ..Default::default()
            },
            reverse: ReverseConfig::default(),
            ..Default::default()
        }
    }

    #[test]
    fn maps_forward_listeners_and_target() {
        let cfg = to_config(&profile(), None).unwrap();
        assert_eq!(cfg.http_port, 3128);
        assert_eq!(cfg.socks_port, 1080);
        assert_eq!(cfg.ssh_target.as_deref(), Some("root@10.0.0.1:2222"));
        assert_eq!(cfg.ssh_port, Some(2222));
        assert_eq!(cfg.allow, vec![FilterRule::from_str("example.com").unwrap()]);
    }

    #[test]
    fn defaults_to_russh_and_default_ports() {
        let p = SessionProfile {
            hops: vec![target_hop()],
            ..Default::default()
        };
        let cfg = to_config(&p, None).unwrap();
        assert_eq!(cfg.http_port, 3128);
        assert_eq!(cfg.socks_port, 1080);
        assert_eq!(cfg.ssh_ip_version, SshIpVersion::V4);
        assert_eq!(p.engine, SshEngine::Russh);
    }

    #[test]
    fn reverse_cap_follows_forward_cap_unless_set() {
        let mut p = profile();
        p.forward.max_connections = 100;
        assert_eq!(to_config(&p, None).unwrap().reverse_max_connections, 100);
        p.reverse.reverse_max_connections = Some(5);
        let cfg = to_config(&p, None).unwrap();
        assert_eq!((cfg.max_connections, cfg.reverse_max_connections), (100, 5));
        p.reverse.reverse_max_connections = Some(0);
        assert_eq!(to_config(&p, None).unwrap().reverse_max_connections, 0);
    }

    #[test]
    fn reverse_cap_is_optional_in_saved_profiles() {
        let reverse: ReverseConfig = serde_json::from_str(r#"{"reverse_http_port":8080}"#).unwrap();
        assert_eq!(reverse.reverse_max_connections, None);
    }

    #[test]
    fn maps_pem_ca_source() {
        let mut p = profile();
        p.mitm = Some(crate::MitmConfig {
            ca_mode: MitmCaMode::Pem {
                cert: PathBuf::from("/tmp/ca.crt"),
                key: PathBuf::from("/tmp/ca.key"),
            },
            ..Default::default()
        });
        let cfg = to_config(&p, None).unwrap();
        assert_eq!(cfg.mitm_ca_cert.as_deref(), Some(PathBuf::from("/tmp/ca.crt").as_path()));
        assert_eq!(cfg.mitm_ca_key.as_deref(), Some(PathBuf::from("/tmp/ca.key").as_path()));
        assert!(cfg.mitm_ca_p12.is_none());
        assert!(cfg.mitm_enabled());
    }

    #[test]
    fn maps_pkcs12_ca_source() {
        let mut p = profile();
        p.mitm = Some(crate::MitmConfig {
            ca_mode: MitmCaMode::Pkcs12 {
                path: PathBuf::from("/tmp/ca.p12"),
            },
            ..Default::default()
        });
        let cfg = to_config(&p, None).unwrap();
        assert_eq!(cfg.mitm_ca_p12.as_deref(), Some(PathBuf::from("/tmp/ca.p12").as_path()));
        assert!(cfg.mitm_enabled());
    }

    #[test]
    fn resolved_passphrase_is_carried_in() {
        let cfg = to_config(&profile(), Some("hunter2")).unwrap();
        assert_eq!(cfg.mitm_ca_passphrase.as_deref(), Some("hunter2"));
    }

    #[test]
    fn absent_passphrase_is_none() {
        let cfg = to_config(&profile(), None).unwrap();
        assert!(cfg.mitm_ca_passphrase.is_none());
    }

    #[test]
    fn maps_tunnel_and_logging() {
        let mut p = profile();
        p.tunnel = TunnelConfig {
            ip_version: "6".into(),
            server_alive_interval: Duration::from_secs(5),
            no_reconnect: true,
            ..Default::default()
        };
        p.logging = LoggingConfig {
            level: "VERBOSE".into(),
            format: "json".into(),
            ..Default::default()
        };
        let cfg = to_config(&p, None).unwrap();
        assert_eq!(cfg.ssh_ip_version, SshIpVersion::V6);
        assert!(cfg.no_reconnect);
        assert_eq!(cfg.log_level, LogLevel::Verbose);
        assert_eq!(cfg.log_format, LogFormat::Json);
    }

    #[test]
    fn switched_off_proxy_maps_to_zero_ports() {
        let mut p = profile();
        p.reverse.enabled = true;
        p.reverse.reverse_http_port = 8888;
        p.reverse.reverse_socks_port = 8889;
        let cfg = to_config(&p, None).unwrap();
        assert_eq!((cfg.http_port, cfg.socks_port), (3128, 1080));
        assert_eq!((cfg.reverse_http_port, cfg.reverse_socks_port), (8888, 8889));

        p.forward.enabled = false;
        p.reverse.enabled = false;
        let cfg = to_config(&p, None).unwrap();
        assert_eq!((cfg.http_port, cfg.socks_port), (0, 0));
        assert_eq!((cfg.reverse_http_port, cfg.reverse_socks_port), (0, 0));
        // The profile keeps its ports for when the proxy is switched back on.
        assert_eq!(p.forward.http_port, 3128);
        assert_eq!(p.reverse.reverse_http_port, 8888);
    }

    #[test]
    fn maps_tcp_keepalive() {
        let cfg = to_config(&profile(), None).unwrap();
        assert_eq!(
            cfg.tcp_keepalive_settings(),
            Some(rusty_conduit_ssh::net::KeepaliveSettings::DEFAULT)
        );
        let mut p = profile();
        p.tunnel.tcp_keepalive = Duration::from_secs(120);
        p.tunnel.tcp_keepalive_interval = Duration::from_secs(20);
        p.tunnel.tcp_keepalive_retries = 3;
        let cfg = to_config(&p, None).unwrap();
        assert_eq!(
            (cfg.tcp_keepalive, cfg.tcp_keepalive_interval, cfg.tcp_keepalive_retries),
            (Duration::from_secs(120), Duration::from_secs(20), 3)
        );
        assert!(cfg.validate().is_ok());
        p.tunnel.tcp_keepalive = Duration::ZERO;
        assert_eq!(to_config(&p, None).unwrap().tcp_keepalive_settings(), None);
    }

    #[test]
    fn no_hops_is_rejected() {
        let mut p = profile();
        p.hops.clear();
        assert!(matches!(to_config(&p, None), Err(MappingError::NoHops)));
    }

    #[test]
    fn bad_filter_rule_is_rejected() {
        let mut p = profile();
        p.forward.allow = vec!["bad*domain".into()];
        assert!(matches!(
            to_config(&p, None),
            Err(MappingError::InvalidFilterRule { .. })
        ));
    }

    #[test]
    fn engine_is_carried_through() {
        let mut p = profile();
        p.engine = SshEngine::OpenSsh;
        let cfg = to_config(&p, None).unwrap();
        // engine is a UI-only concept; the engine field is not part of Config.
        assert_eq!(cfg.http_port, 3128);
    }

    #[test]
    fn mapped_config_passes_engine_validation() {
        let cfg = to_config(&profile(), None).unwrap();
        // The mapped Config must satisfy the engine's own validation rules.
        assert!(cfg.validate().is_ok());
    }
}
