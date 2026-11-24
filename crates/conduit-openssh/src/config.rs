//! Generates the hardened per-session `ssh -F` file.
//!
//! Every value comes from a profile, so each one is validated or quoted here. A newline in a
//! host name must never become a new directive.

use std::collections::HashSet;
use std::io;
use std::path::Path;
use std::time::Duration;

use thiserror::Error;

use crate::known_hosts::host_key_alias;
use crate::runtime_dir::write_private_file;

/// One hop in the chain. The last hop is the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigHop {
    pub hop_id: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    /// Isolated agent endpoint. `None` renders `IdentityAgent none`.
    pub identity_agent: Option<String>,
    /// Public key files naming the agent keys this hop may use. Because `IdentitiesOnly yes`
    /// is set, `ssh` offers an agent key only when it is listed here. Empty renders
    /// `IdentityFile none`, which also stops `ssh` trying its default `~/.ssh/id_*` files.
    pub identity_files: Vec<String>,
    /// Agent endpoint forwarded to this hop. `None` renders `ForwardAgent no`.
    pub forward_agent: Option<String>,
}

/// Everything needed to render one session's config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionConfig {
    pub hops: Vec<ConfigHop>,
    /// Where this file will live. `hop-proxy` reads it again for inner hops.
    pub config_path: String,
    pub known_hosts_path: String,
    pub worker_path: String,
    pub ssh_bin: String,
    /// `4`, `6`, or `auto`.
    pub ip_version: String,
    pub server_alive_interval: Duration,
    pub server_alive_count_max: u32,
}

/// A value that cannot be written safely into the config.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("a session needs at least one hop")]
    NoHops,
    #[error("hop {0:?} appears more than once in the chain")]
    DuplicateHop(String),
    #[error("invalid host name {0:?}")]
    InvalidHost(String),
    #[error("invalid user name {0:?}")]
    InvalidUser(String),
    #[error("invalid path {0:?}: it must be a literal path with a directory")]
    InvalidPath(String),
    #[error("invalid IP version {0:?} (expected 4, 6, or auto)")]
    InvalidIpVersion(String),
}

/// Renders the config for the current platform.
pub fn render_config(config: &SessionConfig) -> Result<String, ConfigError> {
    render_config_for(config, cfg!(windows))
}

/// Renders the config and writes it with mode `0600`.
pub fn write_config(config: &SessionConfig) -> Result<(), WriteConfigError> {
    let text = render_config(config)?;
    write_private_file(Path::new(&config.config_path), text.as_bytes())?;
    Ok(())
}

/// Why a config could not be written.
#[derive(Debug, Error)]
pub enum WriteConfigError {
    #[error(transparent)]
    Invalid(#[from] ConfigError),
    #[error("could not write the OpenSSH config: {0}")]
    Io(#[from] io::Error),
}

/// The `Host` alias to pass to `ssh` for this hop.
pub fn hop_alias(hop: &ConfigHop) -> String {
    host_key_alias(&hop.hop_id, &hop.host, hop.port)
}

fn render_config_for(config: &SessionConfig, windows: bool) -> Result<String, ConfigError> {
    if config.hops.is_empty() {
        return Err(ConfigError::NoHops);
    }
    let address_family = match config.ip_version.trim().to_ascii_lowercase().as_str() {
        "4" => "inet",
        "6" => "inet6",
        "auto" => "any",
        _ => return Err(ConfigError::InvalidIpVersion(config.ip_version.clone())),
    };
    let known_hosts = quote_path(&config.known_hosts_path)?;
    let alive_secs = config
        .server_alive_interval
        .as_secs()
        .saturating_add(u64::from(config.server_alive_interval.subsec_nanos() > 0));

    let mut aliases = HashSet::new();
    let mut out = String::new();
    for (index, hop) in config.hops.iter().enumerate() {
        check_host(&hop.host)?;
        check_user(&hop.user)?;
        let alias = hop_alias(hop);
        if !aliases.insert(alias.clone()) {
            return Err(ConfigError::DuplicateHop(hop.hop_id.clone()));
        }
        let identity_agent = optional_path(hop.identity_agent.as_deref())?;
        let forward_agent = optional_path(hop.forward_agent.as_deref())?;

        out.push_str(&format!("Host {alias}\n"));
        let mut directive = |name: &str, value: &str| {
            out.push_str(&format!("    {name} {value}\n"));
        };
        directive("HostName", &hop.host);
        directive("Port", &hop.port.to_string());
        directive("User", &quote(&hop.user));
        directive("HostKeyAlias", &alias);
        directive("UserKnownHostsFile", &known_hosts);
        directive("GlobalKnownHostsFile", "none");
        directive("StrictHostKeyChecking", "yes");
        directive("IdentitiesOnly", "yes");
        directive("IdentityAgent", identity_agent.as_deref().unwrap_or("none"));
        if hop.identity_files.is_empty() {
            directive("IdentityFile", "none");
        }
        for file in &hop.identity_files {
            directive("IdentityFile", &quote_path(file)?);
        }
        directive("ControlMaster", "no");
        directive("ControlPath", "none");
        directive("UpdateHostKeys", "no");
        directive("NumberOfPasswordPrompts", "1");
        directive("ServerAliveInterval", &alive_secs.to_string());
        directive(
            "ServerAliveCountMax",
            &config.server_alive_count_max.to_string(),
        );
        directive("AddressFamily", address_family);
        directive("ForwardAgent", forward_agent.as_deref().unwrap_or("no"));
        if index > 0 {
            directive("ProxyCommand", &proxy_command(config, index - 1, windows)?);
        }
        out.push('\n');
    }
    Ok(out)
}

/// `ssh` runs this through a shell on Unix, so its arguments use shell quoting.
fn proxy_command(
    config: &SessionConfig,
    previous_hop: usize,
    windows: bool,
) -> Result<String, ConfigError> {
    let arg = |value: &str| -> Result<String, ConfigError> {
        check_path(value)?;
        let quoted = if windows {
            format!("\"{value}\"")
        } else {
            format!("'{}'", value.replace('\'', r"'\''"))
        };
        Ok(quoted.replace('%', "%%"))
    };
    Ok(format!(
        "{} hop-proxy --config {} --ssh-bin {} --hop {previous_hop} -- %h %p",
        arg(&config.worker_path)?,
        arg(&config.config_path)?,
        arg(&config.ssh_bin)?,
    ))
}

fn optional_path(path: Option<&str>) -> Result<Option<String>, ConfigError> {
    path.map(quote_path).transpose()
}

fn quote_path(path: &str) -> Result<String, ConfigError> {
    check_path(path)?;
    Ok(quote(&path.replace('%', "%%")))
}

/// Double-quotes a value. `ssh` eats single backslashes, so a named pipe needs them doubled.
fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', r"\\"))
}

/// Rejects anything `ssh` would expand instead of reading literally: `~`, `$VAR`, `${VAR}`, and
/// the bare `SSH_AUTH_SOCK` keyword, which has no directory separator.
fn check_path(path: &str) -> Result<(), ConfigError> {
    let literal = path.contains(['/', '\\'])
        && !path.starts_with('~')
        && !path.contains(['"', '$'])
        && !path.chars().any(char::is_control);
    if literal {
        Ok(())
    } else {
        Err(ConfigError::InvalidPath(path.to_string()))
    }
}

fn check_host(host: &str) -> Result<(), ConfigError> {
    let valid = !host.is_empty()
        && !host.starts_with('-')
        && host
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'));
    if valid {
        Ok(())
    } else {
        Err(ConfigError::InvalidHost(host.to_string()))
    }
}

fn check_user(user: &str) -> Result<(), ConfigError> {
    let valid = !user.is_empty()
        && !user.starts_with('-')
        && !user.contains(['"', '%'])
        && !user.chars().any(char::is_control);
    if valid {
        Ok(())
    } else {
        Err(ConfigError::InvalidUser(user.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use crate::runtime_dir::RuntimeDir;

    fn hop(id: &str, host: &str) -> ConfigHop {
        ConfigHop {
            hop_id: id.into(),
            host: host.into(),
            port: 2222,
            user: "alice".into(),
            identity_agent: None,
            identity_files: Vec::new(),
            forward_agent: None,
        }
    }

    fn session(hops: Vec<ConfigHop>) -> SessionConfig {
        SessionConfig {
            hops,
            config_path: "/run/rc-1/config".into(),
            known_hosts_path: "/run/rc-1/known_hosts".into(),
            worker_path: "/opt/conduit/conduit-worker".into(),
            ssh_bin: "/usr/bin/ssh".into(),
            ip_version: "4".into(),
            server_alive_interval: Duration::from_secs(30),
            server_alive_count_max: 3,
        }
    }

    #[test]
    fn config_single_hop_has_every_hardening_directive() {
        let mut target = hop("target", "example.com");
        target.identity_agent = Some("/run/rc-1/a.sock".into());
        let alias = hop_alias(&target);
        let text = render_config_for(&session(vec![target]), false).unwrap();
        for line in [
            format!("Host {alias}"),
            "HostName example.com".to_string(),
            "Port 2222".to_string(),
            "User \"alice\"".to_string(),
            format!("HostKeyAlias {alias}"),
            "UserKnownHostsFile \"/run/rc-1/known_hosts\"".to_string(),
            "GlobalKnownHostsFile none".to_string(),
            "StrictHostKeyChecking yes".to_string(),
            "IdentitiesOnly yes".to_string(),
            "IdentityAgent \"/run/rc-1/a.sock\"".to_string(),
            "IdentityFile none".to_string(),
            "ControlMaster no".to_string(),
            "ControlPath none".to_string(),
            "UpdateHostKeys no".to_string(),
            "NumberOfPasswordPrompts 1".to_string(),
            "ServerAliveInterval 30".to_string(),
            "ServerAliveCountMax 3".to_string(),
            "AddressFamily inet".to_string(),
            "ForwardAgent no".to_string(),
        ] {
            assert!(
                text.lines().any(|l| l.trim() == line),
                "missing {line}\n{text}"
            );
        }
        assert!(!text.contains("ProxyCommand"));
        assert!(!text.contains("ProxyJump"));
        assert!(!text.contains("~"));
        assert!(!text.contains(".ssh"));
    }

    #[test]
    fn config_multi_hop_chains_through_the_worker() {
        let hops = vec![hop("a", "a.test"), hop("b", "b.test"), hop("c", "c.test")];
        let aliases: Vec<_> = hops.iter().map(hop_alias).collect();
        let text = render_config_for(&session(hops), false).unwrap();
        let stanzas: Vec<_> = text.split("Host rc-").skip(1).collect();
        assert_eq!(stanzas.len(), 3);
        assert!(!stanzas[0].contains("ProxyCommand"));
        for (index, stanza) in stanzas.iter().enumerate().skip(1) {
            let expected = format!(
                "ProxyCommand '/opt/conduit/conduit-worker' hop-proxy --config \
                 '/run/rc-1/config' --ssh-bin '/usr/bin/ssh' --hop {} -- %h %p",
                index - 1
            );
            assert!(stanza.contains(&expected), "{stanza}");
            assert!(stanza.contains(&format!("HostKeyAlias {}", aliases[index])));
        }
        assert!(!text.contains("ProxyJump"));
        assert!(!text.contains(".ssh"));
    }

    #[test]
    fn config_address_family_and_alive_values() {
        for (version, family) in [("4", "inet"), ("6", "inet6"), ("auto", "any")] {
            let mut config = session(vec![hop("a", "a.test")]);
            config.ip_version = version.into();
            config.server_alive_interval = Duration::from_millis(1500);
            let text = render_config_for(&config, false).unwrap();
            assert!(text.contains(&format!("AddressFamily {family}\n")));
            assert!(text.contains("ServerAliveInterval 2\n"));
        }
        let mut config = session(vec![hop("a", "a.test")]);
        config.ip_version = "5".into();
        assert_eq!(
            render_config_for(&config, false),
            Err(ConfigError::InvalidIpVersion("5".into()))
        );
    }

    #[test]
    fn config_escapes_windows_named_pipes() {
        let mut target = hop("a", "a.test");
        target.identity_agent = Some(r"\\.\pipe\rc-1-agent".into());
        let mut config = session(vec![target]);
        config.known_hosts_path = r"C:\Temp\rc-1\known_hosts".into();
        let text = render_config_for(&config, true).unwrap();
        assert!(
            text.contains(r#"IdentityAgent "\\\\.\\pipe\\rc-1-agent""#),
            "{text}"
        );
        assert!(text.contains(r#"UserKnownHostsFile "C:\\Temp\\rc-1\\known_hosts""#));
    }

    #[test]
    fn config_windows_proxy_command_uses_double_quotes() {
        let mut config = session(vec![hop("a", "a.test"), hop("b", "b.test")]);
        config.worker_path = r"C:\Program Files\Conduit\conduit-worker.exe".into();
        config.config_path = r"C:\Temp\rc-1\config".into();
        config.ssh_bin = r"C:\Windows\System32\OpenSSH\ssh.exe".into();
        let text = render_config_for(&config, true).unwrap();
        assert!(text.contains(
            r#"ProxyCommand "C:\Program Files\Conduit\conduit-worker.exe" hop-proxy --config "C:\Temp\rc-1\config""#
        ), "{text}");
    }

    #[test]
    fn config_quotes_shell_and_token_characters_in_paths() {
        let mut config = session(vec![hop("a", "a.test"), hop("b", "b.test")]);
        config.worker_path = "/opt/it's 100%/conduit-worker".into();
        let text = render_config_for(&config, false).unwrap();
        assert!(text.contains(r"ProxyCommand '/opt/it'\''s 100%%/conduit-worker' hop-proxy"));
    }

    #[test]
    fn config_rejects_directive_injection() {
        for host in [
            "a\nProxyCommand evil",
            "a b",
            "-oProxyCommand=x",
            "",
            "a%h",
            "a\"b",
        ] {
            let config = session(vec![hop("a", host)]);
            assert_eq!(
                render_config_for(&config, false),
                Err(ConfigError::InvalidHost(host.into()))
            );
        }
        for user in ["a\nProxyCommand evil", "a\"b", "-x", "", "a%n"] {
            let mut target = hop("a", "a.test");
            target.user = user.into();
            assert_eq!(
                render_config_for(&session(vec![target]), false),
                Err(ConfigError::InvalidUser(user.into()))
            );
        }
    }

    #[test]
    fn config_rejects_paths_ssh_would_expand() {
        for path in [
            "SSH_AUTH_SOCK",
            "$SSH_AUTH_SOCK",
            "/run/${HOME}/a",
            "~/.ssh/agent",
            "/run/a\nProxyCommand evil",
            "/run/a\"b",
        ] {
            let mut target = hop("a", "a.test");
            target.identity_agent = Some(path.into());
            assert_eq!(
                render_config_for(&session(vec![target]), false),
                Err(ConfigError::InvalidPath(path.into())),
            );
        }
    }

    #[test]
    fn config_rejects_empty_and_duplicate_chains() {
        assert_eq!(
            render_config_for(&session(Vec::new()), false),
            Err(ConfigError::NoHops)
        );
        let config = session(vec![hop("a", "a.test"), hop("a", "a.test")]);
        assert_eq!(
            render_config_for(&config, false),
            Err(ConfigError::DuplicateHop("a".into()))
        );
    }

    #[cfg(unix)]
    #[test]
    fn config_file_is_private_and_real_ssh_parses_it() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;

        let dir = RuntimeDir::create().unwrap();
        let path = dir.path().join("config");
        let known_hosts = dir.path().join("known_hosts");
        let agent = dir.path().join("a.sock");
        let forward = dir.path().join("f.sock");
        let first = hop("a", "127.0.0.1");
        let mut second = hop("b", "127.0.0.2");
        second.identity_agent = Some(agent.to_str().unwrap().into());
        second.forward_agent = Some(forward.to_str().unwrap().into());
        let alias = hop_alias(&second);
        let mut config = session(vec![first, second]);
        config.config_path = path.to_str().unwrap().into();
        config.known_hosts_path = known_hosts.to_str().unwrap().into();
        write_config(&config).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        let output = Command::new("/usr/bin/ssh")
            .args(["-G", "-F", path.to_str().unwrap(), &alias])
            .env_remove("SSH_AUTH_SOCK")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let effective = String::from_utf8(output.stdout).unwrap();
        for line in [
            "hostname 127.0.0.2".to_string(),
            "port 2222".to_string(),
            "user alice".to_string(),
            format!("hostkeyalias {alias}"),
            format!("userknownhostsfile {}", known_hosts.display()),
            "globalknownhostsfile none".to_string(),
            "stricthostkeychecking true".to_string(),
            "identitiesonly yes".to_string(),
            format!("identityagent {}", agent.display()),
            format!("forwardagent {}", forward.display()),
            "identityfile none".to_string(),
            "controlmaster false".to_string(),
            "updatehostkeys false".to_string(),
            "numberofpasswordprompts 1".to_string(),
            "serveraliveinterval 30".to_string(),
            "serveralivecountmax 3".to_string(),
            "addressfamily inet".to_string(),
        ] {
            assert!(
                effective.lines().any(|l| l == line),
                "missing {line}\n{effective}"
            );
        }
        let proxy = effective
            .lines()
            .find(|l| l.starts_with("proxycommand "))
            .unwrap();
        assert!(proxy.contains("hop-proxy") && proxy.contains("--hop 0"));
        assert!(!effective.lines().any(|l| l.starts_with("proxyjump ")));
        assert!(!effective.contains("/.ssh/"), "{effective}");
    }
}
