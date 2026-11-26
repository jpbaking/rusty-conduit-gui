//! `conduit-core` — mapping a validated [`SessionProfile`] into an [`EngineConfig`] at
//! session start.
//!
//! The [`rusty_conduit_engine`] crate has no `serde` and no configuration-file model, so this
//! crate owns the serde-serializable models (see [`model`](crate)) and converts them into the
//! engine's option types here. Secret material (`SecretRef` / `KeyId` / `MitmCaId`) lives in the
//! vault and is resolved by the runtime layer: the SSH identity is not carried here, and the
//! MITM CA is loaded in memory from vault bytes by the runtime, so [`MitmOptions::ca`] is always
//! `None` in the mapped config.

use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

use rusty_conduit_engine::filter::{FilterRule, HostFilter};
use rusty_conduit_engine::logging::{LogFormat, LogLevel};
use rusty_conduit_engine::mitm::MitmOptions;
use rusty_conduit_engine::net::KeepaliveSettings;
use rusty_conduit_engine::server::ServerOptions;
use thiserror::Error;

use crate::{SessionProfile, SshIpVersion};

/// Errors raised while mapping a [`SessionProfile`] into an [`EngineConfig`].
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

/// Engine-facing settings for one session, built by [`to_engine_config`].
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Forward (local) listener settings; a switched-off proxy has both ports `0`.
    pub forward_server: ServerOptions,
    /// Whether at least one forward listener is enabled.
    pub forward_enabled: bool,
    /// Forward destination filter, or `None` when unfiltered.
    pub forward_filter: Option<HostFilter>,
    /// Bind address of the reverse listeners on the SSH target.
    pub reverse_bind: IpAddr,
    /// Reverse HTTP/HTTPS port (`0` disables it).
    pub reverse_http_port: u16,
    /// Reverse SOCKS port (`0` disables it; equal to `reverse_http_port` multiplexes).
    pub reverse_socks_port: u16,
    /// Maximum concurrent reverse connections (`0` = unlimited).
    pub reverse_max_connections: usize,
    /// Whether at least one reverse listener is enabled.
    pub reverse_enabled: bool,
    /// Reverse destination filter, or `None` when unfiltered.
    pub reverse_filter: Option<HostFilter>,
    /// TCP keepalive for client and upstream sockets (`None` = disabled).
    pub keepalive: Option<KeepaliveSettings>,
    /// Whether HTTPS MITM inspection is on for this session.
    pub mitm_enabled: bool,
    /// MITM leaf settings; `ca` is always `None` (the runtime loads the CA from the vault).
    pub mitm_options: MitmOptions,
    /// Block plain web traffic over SOCKS while MITM is on.
    pub socks_block_web_in_mitm: bool,
    pub log_level: LogLevel,
    pub log_format: LogFormat,
    pub http_access_log: Option<PathBuf>,
    pub socks_log: Option<PathBuf>,
    /// IP family used to reach the SSH target.
    pub ssh_ip_version: SshIpVersion,
}

impl EngineConfig {
    /// Whether both reverse listeners share one port (first-byte multiplexing).
    pub fn is_reverse_multiplexed(&self) -> bool {
        self.reverse_http_port > 0 && self.reverse_http_port == self.reverse_socks_port
    }
}

/// Parse a forward/reverse filter list into `rusty-conduit-engine` [`FilterRule`]s.
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

/// Build the mutually exclusive filter: allow rules win, then block rules, else unfiltered.
fn host_filter(allow: Vec<FilterRule>, block: Vec<FilterRule>) -> Option<HostFilter> {
    if !allow.is_empty() {
        Some(HostFilter::Allow(allow))
    } else if !block.is_empty() {
        Some(HostFilter::Block(block))
    } else {
        None
    }
}

/// Map a validated [`SessionProfile`] into an [`EngineConfig`].
///
/// The caller should run [`crate::validate::validate`] first; this function re-parses the
/// string fields and returns [`MappingError`] if any are malformed (defensive against a
/// profile that bypassed validation). conduit-core never touches the vault.
pub fn to_engine_config(profile: &SessionProfile) -> Result<EngineConfig, MappingError> {
    if profile.hops.is_empty() {
        return Err(MappingError::NoHops);
    }

    // Destination filters.
    let forward_filter = host_filter(
        parse_rules("forward", &profile.forward.allow)?,
        parse_rules("forward", &profile.forward.block)?,
    );
    let reverse_filter = host_filter(
        parse_rules("reverse", &profile.reverse.reverse_allow)?,
        parse_rules("reverse", &profile.reverse.reverse_block)?,
    );

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

    let tunnel = &profile.tunnel;
    let keepalive = (!tunnel.tcp_keepalive.is_zero()).then_some(KeepaliveSettings {
        idle: tunnel.tcp_keepalive,
        interval: tunnel.tcp_keepalive_interval,
        retries: tunnel.tcp_keepalive_retries,
    });

    let defaults = MitmOptions::default();
    let mitm_options = MitmOptions {
        // The runtime loads the CA in memory from the vault; no passphrase is ever needed.
        ca: None,
        passphrase: None,
        passphrase_file: None,
        cert_ttl: profile.mitm.as_ref().map_or(defaults.cert_ttl, |m| m.cert_ttl),
        cert_cache_max: profile
            .mitm
            .as_ref()
            .map_or(defaults.cert_cache_max, |m| m.cert_cache_max_entries),
    };

    Ok(EngineConfig {
        forward_server: ServerOptions {
            bind: profile.forward.bind,
            http_port,
            socks_port,
            max_connections: profile.forward.max_connections,
            keepalive,
        },
        forward_enabled: http_port != 0 || socks_port != 0,
        forward_filter,
        reverse_bind: profile.reverse.reverse_bind,
        reverse_http_port,
        reverse_socks_port,
        reverse_max_connections: profile
            .reverse
            .reverse_max_connections
            .unwrap_or(profile.forward.max_connections),
        reverse_enabled: reverse_http_port != 0 || reverse_socks_port != 0,
        reverse_filter,
        keepalive,
        mitm_enabled: profile.mitm.is_some(),
        mitm_options,
        socks_block_web_in_mitm: profile.mitm.as_ref().is_some_and(|m| m.socks_block_web),
        log_level,
        log_format,
        http_access_log: profile.logging.http_access_log.clone(),
        socks_log: profile.logging.socks_log.clone(),
        ssh_ip_version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ForwardConfig, HopEntry, HostProfile, LoggingConfig, MitmCaId, ReverseConfig,
        SessionProfile, SshEngine, TunnelConfig,
    };
    use rusty_conduit_engine::mitm::{DEFAULT_MITM_CERT_CACHE_MAX, DEFAULT_MITM_CERT_TTL};
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
    fn maps_forward_listeners_and_filter() {
        let cfg = to_engine_config(&profile()).unwrap();
        assert_eq!(cfg.forward_server.http_port, 3128);
        assert_eq!(cfg.forward_server.socks_port, 1080);
        assert!(cfg.forward_enabled);
        assert_eq!(
            cfg.forward_filter,
            Some(HostFilter::Allow(vec![FilterRule::from_str("example.com").unwrap()]))
        );
        assert_eq!(cfg.reverse_filter, None);
    }

    #[test]
    fn block_rules_map_to_a_block_filter() {
        let mut p = profile();
        p.forward.allow.clear();
        p.forward.block = vec!["*.ads.example".into()];
        p.reverse.reverse_block = vec!["10.0.0.0/8".into()];
        let cfg = to_engine_config(&p).unwrap();
        assert_eq!(cfg.forward_filter.as_ref().map(HostFilter::mode_str), Some("block"));
        assert_eq!(cfg.reverse_filter.as_ref().map(HostFilter::mode_str), Some("block"));
    }

    #[test]
    fn defaults_to_russh_and_default_ports() {
        let p = SessionProfile {
            hops: vec![target_hop()],
            ..Default::default()
        };
        let cfg = to_engine_config(&p).unwrap();
        assert_eq!(cfg.forward_server.http_port, 3128);
        assert_eq!(cfg.forward_server.socks_port, 1080);
        assert_eq!(cfg.ssh_ip_version, SshIpVersion::V4);
        assert_eq!(p.engine, SshEngine::Russh);
    }

    #[test]
    fn reverse_cap_follows_forward_cap_unless_set() {
        let mut p = profile();
        p.forward.max_connections = 100;
        assert_eq!(to_engine_config(&p).unwrap().reverse_max_connections, 100);
        p.reverse.reverse_max_connections = Some(5);
        let cfg = to_engine_config(&p).unwrap();
        assert_eq!(
            (cfg.forward_server.max_connections, cfg.reverse_max_connections),
            (100, 5)
        );
        p.reverse.reverse_max_connections = Some(0);
        assert_eq!(to_engine_config(&p).unwrap().reverse_max_connections, 0);
    }

    #[test]
    fn reverse_cap_is_optional_in_saved_profiles() {
        let reverse: ReverseConfig = serde_json::from_str(r#"{"reverse_http_port":8080}"#).unwrap();
        assert_eq!(reverse.reverse_max_connections, None);
    }

    #[test]
    fn mitm_maps_leaf_settings_without_a_ca_source() {
        let mut p = profile();
        p.mitm = Some(crate::MitmConfig {
            ca: Some(MitmCaId::new()),
            cert_ttl: Duration::from_secs(600),
            cert_cache_max_entries: 50,
            socks_block_web: true,
        });
        let cfg = to_engine_config(&p).unwrap();
        assert!(cfg.mitm_enabled);
        assert!(cfg.socks_block_web_in_mitm);
        // The CA is loaded in memory by the runtime, never from a path.
        assert!(cfg.mitm_options.ca.is_none());
        assert!(cfg.mitm_options.passphrase.is_none());
        assert!(cfg.mitm_options.passphrase_file.is_none());
        assert_eq!(cfg.mitm_options.cert_ttl, Duration::from_secs(600));
        assert_eq!(cfg.mitm_options.cert_cache_max, 50);
    }

    #[test]
    fn mitm_is_off_without_a_mitm_config() {
        let cfg = to_engine_config(&profile()).unwrap();
        assert!(!cfg.mitm_enabled);
        assert!(!cfg.socks_block_web_in_mitm);
        assert!(cfg.mitm_options.ca.is_none());
        assert_eq!(cfg.mitm_options.cert_ttl, DEFAULT_MITM_CERT_TTL);
        assert_eq!(cfg.mitm_options.cert_cache_max, DEFAULT_MITM_CERT_CACHE_MAX);
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
        let cfg = to_engine_config(&p).unwrap();
        assert_eq!(cfg.ssh_ip_version, SshIpVersion::V6);
        assert_eq!(cfg.log_level, LogLevel::Verbose);
        assert_eq!(cfg.log_format, LogFormat::Json);
    }

    #[test]
    fn ip_version_accepts_aliases_case_insensitively() {
        for (raw, want) in [
            ("4", SshIpVersion::V4),
            ("v4", SshIpVersion::V4),
            ("IPv4", SshIpVersion::V4),
            ("6", SshIpVersion::V6),
            ("V6", SshIpVersion::V6),
            ("ipv6", SshIpVersion::V6),
            ("auto", SshIpVersion::Auto),
            ("ANY", SshIpVersion::Auto),
        ] {
            assert_eq!(SshIpVersion::from_str(raw), Ok(want), "{raw}");
        }
        assert!(SshIpVersion::from_str("5").is_err());
    }

    #[test]
    fn switched_off_proxy_maps_to_zero_ports() {
        let mut p = profile();
        p.reverse.enabled = true;
        p.reverse.reverse_http_port = 8888;
        p.reverse.reverse_socks_port = 8889;
        let cfg = to_engine_config(&p).unwrap();
        assert_eq!(
            (cfg.forward_server.http_port, cfg.forward_server.socks_port),
            (3128, 1080)
        );
        assert_eq!((cfg.reverse_http_port, cfg.reverse_socks_port), (8888, 8889));
        assert!(cfg.forward_enabled && cfg.reverse_enabled);
        assert!(!cfg.is_reverse_multiplexed());

        p.forward.enabled = false;
        p.reverse.enabled = false;
        let cfg = to_engine_config(&p).unwrap();
        assert_eq!(
            (cfg.forward_server.http_port, cfg.forward_server.socks_port),
            (0, 0)
        );
        assert_eq!((cfg.reverse_http_port, cfg.reverse_socks_port), (0, 0));
        assert!(!cfg.forward_enabled && !cfg.reverse_enabled);
        // The profile keeps its ports for when the proxy is switched back on.
        assert_eq!(p.forward.http_port, 3128);
        assert_eq!(p.reverse.reverse_http_port, 8888);
    }

    #[test]
    fn reverse_multiplexing_is_detected() {
        let mut p = profile();
        p.reverse.enabled = true;
        p.reverse.reverse_http_port = 8888;
        p.reverse.reverse_socks_port = 8888;
        assert!(to_engine_config(&p).unwrap().is_reverse_multiplexed());
    }

    #[test]
    fn maps_tcp_keepalive() {
        let cfg = to_engine_config(&profile()).unwrap();
        assert_eq!(cfg.keepalive, Some(KeepaliveSettings::DEFAULT));
        assert_eq!(cfg.forward_server.keepalive, cfg.keepalive);
        let mut p = profile();
        p.tunnel.tcp_keepalive = Duration::from_secs(120);
        p.tunnel.tcp_keepalive_interval = Duration::from_secs(20);
        p.tunnel.tcp_keepalive_retries = 3;
        let cfg = to_engine_config(&p).unwrap();
        assert_eq!(
            cfg.keepalive,
            Some(KeepaliveSettings {
                idle: Duration::from_secs(120),
                interval: Duration::from_secs(20),
                retries: 3,
            })
        );
        p.tunnel.tcp_keepalive = Duration::ZERO;
        let cfg = to_engine_config(&p).unwrap();
        assert_eq!(cfg.keepalive, None);
        assert_eq!(cfg.forward_server.keepalive, None);
    }

    #[test]
    fn no_hops_is_rejected() {
        let mut p = profile();
        p.hops.clear();
        assert!(matches!(to_engine_config(&p), Err(MappingError::NoHops)));
    }

    #[test]
    fn bad_filter_rule_is_rejected() {
        let mut p = profile();
        p.forward.allow = vec!["bad*domain".into()];
        assert!(matches!(
            to_engine_config(&p),
            Err(MappingError::InvalidFilterRule { .. })
        ));
    }

    #[test]
    fn engine_is_carried_through() {
        let mut p = profile();
        p.engine = SshEngine::OpenSsh;
        let cfg = to_engine_config(&p).unwrap();
        // engine is a UI-only concept; it is not part of EngineConfig.
        assert_eq!(cfg.forward_server.http_port, 3128);
    }

    #[test]
    fn mapped_profile_passes_validation() {
        let p = profile();
        assert!(crate::validate(&p).is_ok());
        assert!(to_engine_config(&p).is_ok());
    }
}
