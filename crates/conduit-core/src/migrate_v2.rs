//! `conduit-core` — the one-way §6.4 migration of v0.1.0 sessions into Tunnels and Proxies.
//!
//! Each [`SessionProfile`] becomes a [`Tunnel`] (the SSH half) and, when its forward proxy
//! listens on a port, a [`Proxy`] with the same name whose routing default is a `tunnel`
//! profile for that Tunnel. A session without forward listeners (reverse-only or port-forward-only)
//! becomes only a Tunnel in `Manual` start mode, so autostart still starts it.
//!
//! [`load_or_migrate_app_config`] keeps a copy of the old `config.json` as `config.v1.bak.json`
//! next to it before rewriting it, and never overwrites an existing backup.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::model::{AppConfig, SessionProfile};
use crate::storage::{load_app_config, save_app_config, StorageError};
use crate::v2_model::{
    GlobalFilterConfig, ListenerConfig, NetworkConfig, Proxy, ProxyId, RouteOneOrMany,
    RoutingTablesConfig, SourceMode, Tunnel, TunnelId, TunnelStartMode, UpstreamKind,
    UpstreamProfile,
};

/// The `config.json` schema version written by this build.
pub const CURRENT_SCHEMA_VERSION: u32 = 2;

/// File name of the v1 backup written next to `config.json`.
pub const V1_BACKUP_FILE_NAME: &str = "config.v1.bak.json";

/// Name of the upstream profile a migrated Proxy uses to reach its Tunnel.
const MIGRATED_TUNNEL_PROFILE: &str = "tunnel";

/// What [`load_or_migrate_app_config`] did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MigrationReport {
    /// Number of v1 sessions converted (`0` when nothing was migrated).
    pub migrated_sessions: usize,
    /// The v1 backup copy, when a migration ran.
    pub backup_path: Option<PathBuf>,
}

fn migrate_session(session: &SessionProfile) -> (Tunnel, Option<Proxy>) {
    let tunnel_id = TunnelId::new();
    let (http_port, socks_port) = session.forward.effective_ports();
    let has_proxy = (http_port, socks_port) != (0, 0);

    let tunnel = Tunnel {
        id: tunnel_id,
        name: session.name.clone(),
        enabled: session.enabled,
        start_mode: if has_proxy {
            TunnelStartMode::Linked
        } else {
            TunnelStartMode::Manual { autostart: session.autostart }
        },
        engine: session.engine,
        hops: session.hops.clone(),
        reverse: session.reverse.clone(),
        port_forwards: session.port_forwards.clone(),
        keepalive: session.tunnel.clone(),
        logging: session.logging.clone(),
        openssh: session.openssh.clone(),
        ..Tunnel::default()
    };
    if !has_proxy {
        return (tunnel, None);
    }

    let forward = &session.forward;
    let filter = match (forward.allow.is_empty(), forward.block.is_empty()) {
        (true, true) => GlobalFilterConfig::Off,
        (false, true) => GlobalFilterConfig::Allow(forward.allow.clone()),
        (true, false) => GlobalFilterConfig::Block(forward.block.clone()),
        (false, false) => GlobalFilterConfig::BlockExcept {
            block: forward.block.clone(),
            allow: forward.allow.clone(),
        },
    };
    let proxy = Proxy {
        id: ProxyId::new(),
        name: session.name.clone(),
        enabled: session.enabled,
        autostart: session.autostart,
        source: SourceMode::Managed,
        listeners: ListenerConfig {
            bind: forward.bind,
            http_port,
            socks_port,
            max_connections: forward.max_connections,
        },
        network: NetworkConfig {
            connect_timeout: Duration::from_secs(10),
            tcp_keepalive: session.tunnel.tcp_keepalive,
            tcp_keepalive_interval: session.tunnel.tcp_keepalive_interval,
            tcp_keepalive_retries: session.tunnel.tcp_keepalive_retries,
        },
        profiles: vec![UpstreamProfile {
            name: MIGRATED_TUNNEL_PROFILE.into(),
            kind: UpstreamKind::Tunnel { tunnel_id },
            host: None,
            port: None,
            username: None,
            password: None,
            bypass: Vec::new(),
            color: None,
        }],
        routing: RoutingTablesConfig {
            default: RouteOneOrMany::One(MIGRATED_TUNNEL_PROFILE.into()),
            ..RoutingTablesConfig::default()
        },
        filter,
        socks_block_web: session.mitm.as_ref().is_some_and(|m| m.socks_block_web),
        mitm: session.mitm.clone(),
        logging: session.logging.clone(),
    };
    (tunnel, Some(proxy))
}

/// Convert every v1 session in `config` into Tunnels and Proxies, clear `config.sessions`, and
/// set `schema_version` to [`CURRENT_SCHEMA_VERSION`]. Returns the number of sessions migrated.
///
/// A document already at schema 2, or one with no sessions but some Tunnels or Proxies, is only
/// stamped with the current schema version.
pub fn migrate_v1_sessions(config: &mut AppConfig) -> usize {
    if config.schema_version >= CURRENT_SCHEMA_VERSION
        || (config.sessions.is_empty()
            && (!config.tunnels.is_empty() || !config.proxies.is_empty()))
    {
        config.schema_version = CURRENT_SCHEMA_VERSION;
        return 0;
    }
    let sessions = std::mem::take(&mut config.sessions);
    for session in &sessions {
        let (tunnel, proxy) = migrate_session(session);
        config.tunnels.push(tunnel);
        config.proxies.extend(proxy);
    }
    config.schema_version = CURRENT_SCHEMA_VERSION;
    sessions.len()
}

/// Write `bytes` to `path` with `0600` permissions on Unix, failing if `path` exists.
fn write_backup(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    let err = |source| StorageError::WriteFile { path: path.to_path_buf(), source };
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(err)?;
    file.write_all(bytes).map_err(err)?;
    file.sync_all().map_err(err)?;
    Ok(())
}

/// Load `config.json` from `path`, running the §6.4 migration when it holds v1 sessions.
///
/// Before migrating, the file is copied unchanged to `config.v1.bak.json` in the same
/// directory (`0600` on Unix); an existing backup is kept as it is. The migrated document is
/// then saved atomically over `path`.
pub fn load_or_migrate_app_config(
    path: &Path,
) -> Result<(AppConfig, MigrationReport), StorageError> {
    let mut config = load_app_config(path)?;
    if config.schema_version >= CURRENT_SCHEMA_VERSION || config.sessions.is_empty() {
        return Ok((config, MigrationReport::default()));
    }

    let original = fs::read(path)
        .map_err(|source| StorageError::ReadFile { path: path.to_path_buf(), source })?;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let backup = dir.join(V1_BACKUP_FILE_NAME);
    if !backup.exists() {
        write_backup(&backup, &original)?;
    }

    let migrated_sessions = migrate_v1_sessions(&mut config);
    save_app_config(path, &config)?;
    Ok((config, MigrationReport { migrated_sessions, backup_path: Some(backup) }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        ForwardConfig, HopEntry, HostProfile, MitmCaId, MitmConfig, PortForward, ReverseConfig,
    };
    use crate::{validate_proxy, validate_tunnel};
    use uuid::Uuid;

    fn tmp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("conduit-core-migrate-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn hop() -> HopEntry {
        HopEntry {
            hop_id: "t".into(),
            name: "t".into(),
            host: HostProfile { host: "10.0.0.1".into(), user: "root".into(), ..Default::default() },
        }
    }

    fn forward_session() -> SessionProfile {
        let mut s = SessionProfile {
            name: "work".into(),
            autostart: true,
            hops: vec![hop()],
            forward: ForwardConfig {
                http_port: 3129,
                socks_port: 1081,
                max_connections: 77,
                block: vec!["ads.example".into()],
                ..ForwardConfig::default()
            },
            mitm: Some(MitmConfig { ca: Some(MitmCaId::new()), ..MitmConfig::default() }),
            ..SessionProfile::default()
        };
        s.tunnel.tcp_keepalive = Duration::from_secs(30);
        s.logging.level = "debug".into();
        s.openssh.extra_args = vec!["-v".into()];
        s
    }

    fn reverse_only_session() -> SessionProfile {
        SessionProfile {
            name: "rev".into(),
            autostart: true,
            hops: vec![hop()],
            forward: ForwardConfig { enabled: false, ..ForwardConfig::default() },
            reverse: ReverseConfig {
                enabled: true,
                reverse_http_port: 8888,
                reverse_socks_port: 8888,
                ..ReverseConfig::default()
            },
            port_forwards: vec![PortForward::default()],
            ..SessionProfile::default()
        }
    }

    #[test]
    fn forward_session_becomes_tunnel_and_proxy() {
        let session = forward_session();
        let mut config = AppConfig { schema_version: 1, sessions: vec![session.clone()], ..AppConfig::default() };
        assert_eq!(migrate_v1_sessions(&mut config), 1);
        assert_eq!(config.schema_version, CURRENT_SCHEMA_VERSION);
        assert!(config.sessions.is_empty());

        let tunnel = &config.tunnels[0];
        assert_ne!(tunnel.id, TunnelId::default());
        assert_eq!(tunnel.name, "work");
        assert!(tunnel.enabled);
        assert_eq!(tunnel.start_mode, TunnelStartMode::Linked);
        assert_eq!(tunnel.hops, session.hops);
        assert_eq!(tunnel.reverse, session.reverse);
        assert_eq!(tunnel.port_forwards, session.port_forwards);
        assert_eq!(tunnel.keepalive, session.tunnel);
        assert_eq!(tunnel.logging, session.logging);
        assert_eq!(tunnel.openssh, session.openssh);
        assert_eq!(tunnel.engine, session.engine);

        let proxy = &config.proxies[0];
        assert_eq!(proxy.name, "work");
        assert!(proxy.enabled && proxy.autostart);
        assert_eq!(proxy.source, SourceMode::Managed);
        assert_eq!(proxy.listeners.bind, session.forward.bind);
        assert_eq!((proxy.listeners.http_port, proxy.listeners.socks_port), (3129, 1081));
        assert_eq!(proxy.listeners.max_connections, 77);
        assert_eq!(proxy.network.connect_timeout, Duration::from_secs(10));
        assert_eq!(proxy.network.tcp_keepalive, Duration::from_secs(30));
        assert_eq!(proxy.profiles.len(), 1);
        assert_eq!(proxy.profiles[0].name, "tunnel");
        assert_eq!(proxy.profiles[0].kind, UpstreamKind::Tunnel { tunnel_id: tunnel.id });
        assert_eq!(proxy.routing.default, RouteOneOrMany::One("tunnel".into()));
        assert!(proxy.routing.rules.is_empty());
        assert_eq!(proxy.filter, GlobalFilterConfig::Block(vec!["ads.example".into()]));
        assert_eq!(proxy.mitm, session.mitm);
        assert_eq!(proxy.logging, session.logging);

        // The migrated pair is valid v2 data.
        validate_tunnel(tunnel).unwrap();
        validate_proxy(proxy, &[tunnel.id], &[]).unwrap();
    }

    #[test]
    fn allow_and_block_combine_into_block_except_and_switched_off_ports_are_dropped() {
        let mut s = forward_session();
        s.forward.allow = vec!["ok.example".into()];
        s.forward.socks_port = 0;
        let mut config = AppConfig { sessions: vec![s], ..AppConfig::default() };
        migrate_v1_sessions(&mut config);
        let proxy = &config.proxies[0];
        assert_eq!(
            proxy.filter,
            GlobalFilterConfig::BlockExcept {
                block: vec!["ads.example".into()],
                allow: vec!["ok.example".into()],
            }
        );
        assert_eq!((proxy.listeners.http_port, proxy.listeners.socks_port), (3129, 0));
    }

    #[test]
    fn reverse_only_session_becomes_a_manual_tunnel() {
        let mut config = AppConfig { schema_version: 1, sessions: vec![reverse_only_session()], ..AppConfig::default() };
        assert_eq!(migrate_v1_sessions(&mut config), 1);
        assert!(config.proxies.is_empty());
        assert_eq!(config.tunnels.len(), 1);
        assert_eq!(config.tunnels[0].start_mode, TunnelStartMode::Manual { autostart: true });
        assert_eq!(config.tunnels[0].reverse.reverse_http_port, 8888);
        assert_eq!(config.tunnels[0].port_forwards.len(), 1);
    }

    #[test]
    fn migration_is_idempotent() {
        let mut config = AppConfig {
            schema_version: 1,
            sessions: vec![forward_session(), reverse_only_session()],
            ..AppConfig::default()
        };
        assert_eq!(migrate_v1_sessions(&mut config), 2);
        let once = config.clone();
        assert_eq!(migrate_v1_sessions(&mut config), 0);
        assert_eq!(config, once);

        // v1 stamp but already split: only the version is bumped.
        let mut split = once.clone();
        split.schema_version = 1;
        assert_eq!(migrate_v1_sessions(&mut split), 0);
        assert_eq!(split, once);
    }

    #[test]
    fn load_or_migrate_round_trip_with_backup() {
        let dir = tmp_dir();
        let path = dir.join("config.json");
        let v1 = AppConfig {
            schema_version: 1,
            sessions: vec![forward_session(), reverse_only_session()],
            ..AppConfig::default()
        };
        save_app_config(&path, &v1).unwrap();
        let original = fs::read(&path).unwrap();

        let (config, report) = load_or_migrate_app_config(&path).unwrap();
        assert_eq!(report.migrated_sessions, 2);
        let backup = dir.join(V1_BACKUP_FILE_NAME);
        assert_eq!(report.backup_path.as_deref(), Some(backup.as_path()));
        assert_eq!(fs::read(&backup).unwrap(), original);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&backup).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert_eq!(config.schema_version, 2);
        assert_eq!((config.tunnels.len(), config.proxies.len()), (2, 1));
        assert!(config.sessions.is_empty());

        // The saved document is the migrated one and the backup still decodes as v1.
        assert_eq!(load_app_config(&path).unwrap(), config);
        assert_eq!(load_app_config(&backup).unwrap(), v1);

        // A second load migrates nothing and keeps the document as it is.
        let (again, report) = load_or_migrate_app_config(&path).unwrap();
        assert_eq!(report, MigrationReport::default());
        assert_eq!(again, config);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn existing_backup_is_never_overwritten() {
        let dir = tmp_dir();
        let path = dir.join("config.json");
        let backup = dir.join(V1_BACKUP_FILE_NAME);
        fs::write(&backup, b"older backup").unwrap();
        let v1 = AppConfig { schema_version: 1, sessions: vec![forward_session()], ..AppConfig::default() };
        save_app_config(&path, &v1).unwrap();

        let (_, report) = load_or_migrate_app_config(&path).unwrap();
        assert_eq!(report.migrated_sessions, 1);
        assert_eq!(report.backup_path.as_deref(), Some(backup.as_path()));
        assert_eq!(fs::read(&backup).unwrap(), b"older backup");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_v1_document_is_not_backed_up() {
        let dir = tmp_dir();
        let path = dir.join("config.json");
        save_app_config(&path, &AppConfig { schema_version: 1, ..AppConfig::default() }).unwrap();
        let (_, report) = load_or_migrate_app_config(&path).unwrap();
        assert_eq!(report, MigrationReport::default());
        assert!(!dir.join(V1_BACKUP_FILE_NAME).exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
