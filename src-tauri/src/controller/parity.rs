//! Session-editor helpers: port-conflict detection, the filter tester, and the OpenSSH check.

use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::net::{IpAddr, TcpListener};
use std::str::FromStr;

use conduit_openssh::OpenSshBinaryInfo;
use rusty_conduit_ssh::filter::{FilterRule, HostFilter};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::AppController;

/// `kind` of a conflict with another saved session's forward port.
const CONFLICT_SESSION: &str = "session";
/// `kind` of a conflict with a socket already bound on this machine.
const CONFLICT_OS_SOCKET: &str = "os_socket";
/// The program used when a session does not name one.
const DEFAULT_SSH_BIN: &str = "ssh";

/// One reason a port cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PortConflict {
    pub port: u16,
    /// `session` | `os_socket`.
    pub kind: &'static str,
    pub detail: String,
}

/// Every conflict found for the requested ports.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PortConflictReport {
    pub conflicts: Vec<PortConflict>,
}

/// Whether the tested rules form an allowlist or a blocklist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FilterMode {
    Allow,
    Block,
}

/// A rule that failed to parse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleError {
    pub index: usize,
    pub rule: String,
    pub message: String,
}

/// Outcome of testing a destination against a rule list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FilterTestResult {
    /// Every rule parsed and the target is non-empty.
    pub valid: bool,
    /// `None` when the input is not valid.
    pub allowed: Option<bool>,
    pub reason: String,
    pub rule_errors: Vec<RuleError>,
}

/// Checks the configured `ssh` program. A missing or blank value means the default, `ssh`.
pub fn check_openssh_binary(ssh_bin: Option<String>) -> OpenSshBinaryInfo {
    let requested = ssh_bin
        .as_deref()
        .map(str::trim)
        .filter(|bin| !bin.is_empty())
        .unwrap_or(DEFAULT_SSH_BIN);
    conduit_openssh::check_openssh_binary(requested)
}

/// Two binds collide on the same IP, or when either listens on all interfaces.
fn binds_overlap(a: IpAddr, b: IpAddr) -> bool {
    a == b || a.is_unspecified() || b.is_unspecified()
}

/// Tests `target` the way the engine does: an empty rule list means no filter is active.
pub fn test_filter_rules(mode: FilterMode, rules: &[String], target: &str) -> FilterTestResult {
    let mut parsed = Vec::with_capacity(rules.len());
    let mut rule_errors = Vec::new();
    for (index, rule) in rules.iter().enumerate() {
        match FilterRule::from_str(rule) {
            Ok(rule) => parsed.push(rule),
            Err(message) => rule_errors.push(RuleError { index, rule: rule.clone(), message }),
        }
    }
    let invalid = |reason: String, rule_errors| FilterTestResult {
        valid: false,
        allowed: None,
        reason,
        rule_errors,
    };
    if !rule_errors.is_empty() {
        let reason = format!("{} rule(s) could not be parsed", rule_errors.len());
        return invalid(reason, rule_errors);
    }
    let target = target.trim();
    if target.is_empty() {
        return invalid("enter an IP address or domain to test".into(), rule_errors);
    }
    if parsed.is_empty() {
        return FilterTestResult {
            valid: true,
            allowed: Some(true),
            reason: "no rules are set, so every destination is allowed".into(),
            rule_errors,
        };
    }
    let filter = match mode {
        FilterMode::Allow => HostFilter::Allow(parsed),
        FilterMode::Block => HostFilter::Block(parsed),
    };
    let (allowed, reason) = match filter.check_host(target) {
        Ok(()) => {
            let reason = match mode {
                FilterMode::Allow => format!("destination {target} is in the allowlist"),
                FilterMode::Block => format!("destination {target} is not in the blocklist"),
            };
            (true, reason)
        }
        Err(denied) => (false, denied.0),
    };
    FilterTestResult { valid: true, allowed: Some(allowed), reason, rule_errors }
}

impl AppController {
    /// Checks each non-zero port against other saved sessions and the live OS socket table.
    /// A listener held by `session_id` itself is not a conflict.
    pub fn check_port_conflicts(
        &self,
        session_id: Option<Uuid>,
        bind: IpAddr,
        http_port: u16,
        socks_port: u16,
    ) -> PortConflictReport {
        let config = self.config_snapshot();
        let own_listeners = session_id
            .and_then(|id| self.manager().snapshot(id).ok())
            .map(|snapshot| snapshot.listeners)
            .unwrap_or_default();
        let ports: BTreeSet<u16> = [http_port, socks_port].into_iter().filter(|p| *p != 0).collect();

        let mut conflicts = Vec::new();
        for port in ports {
            for other in config.sessions.iter().filter(|s| Some(s.id) != session_id) {
                if !binds_overlap(bind, other.forward.bind) {
                    continue;
                }
                // A session whose forward proxy is switched off holds no forward ports.
                let (other_http, other_socks) = other.forward.effective_ports();
                let roles = [("HTTP", other_http), ("SOCKS", other_socks)];
                for (role, _) in roles.iter().filter(|(_, p)| *p == port) {
                    conflicts.push(PortConflict {
                        port,
                        kind: CONFLICT_SESSION,
                        detail: format!(
                            "session \"{}\" uses {}:{port} for {role}",
                            other.name, other.forward.bind
                        ),
                    });
                }
            }
            let owned = own_listeners
                .iter()
                .any(|l| l.addr.port() == port && binds_overlap(bind, l.addr.ip()));
            if owned {
                continue;
            }
            if let Err(error) = TcpListener::bind((bind, port)) {
                if error.kind() == ErrorKind::AddrInUse {
                    conflicts.push(PortConflict {
                        port,
                        kind: CONFLICT_OS_SOCKET,
                        detail: format!("{bind}:{port} is already in use on this machine"),
                    });
                }
            }
        }
        PortConflictReport { conflicts }
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::*;

    fn rules(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn add_session(c: &AppController, name: &str, bind: &str, http: u16, socks: u16) -> Uuid {
        let mut s = profile(name, 22);
        s.forward.bind = bind.parse().unwrap();
        s.forward.http_port = http;
        s.forward.socks_port = socks;
        let id = s.id;
        c.mutate_config(|config| {
            config.sessions.push(s.clone());
            Ok(())
        })
        .unwrap();
        c.sync_profiles([s]);
        id
    }

    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    const LOOPBACK: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

    #[tokio::test]
    async fn parity_port_conflict_with_other_session_respects_bind_overlap() {
        let dir = TempDir::new();
        let c = controller(&dir);
        let port = free_port();
        add_session(&c, "same", "127.0.0.1", port, 0);
        add_session(&c, "wildcard", "0.0.0.0", 0, port);
        add_session(&c, "elsewhere", "127.0.0.2", port, 0);

        let report = c.check_port_conflicts(None, LOOPBACK, port, 0);
        let details: Vec<&str> = report.conflicts.iter().map(|x| x.detail.as_str()).collect();
        assert_eq!(report.conflicts.len(), 2, "{details:?}");
        assert!(report.conflicts.iter().all(|x| x.kind == "session" && x.port == port));
        assert!(details.iter().any(|d| d.contains("\"same\"") && d.contains("HTTP")));
        assert!(details.iter().any(|d| d.contains("\"wildcard\"") && d.contains("SOCKS")));
    }

    #[tokio::test]
    async fn parity_port_check_ignores_the_edited_session_and_zero_ports() {
        let dir = TempDir::new();
        let c = controller(&dir);
        let port = free_port();
        let id = add_session(&c, "self", "127.0.0.1", port, 0);
        assert!(c.check_port_conflicts(Some(id), LOOPBACK, port, 0).conflicts.is_empty());
        assert!(c.check_port_conflicts(None, LOOPBACK, 0, 0).conflicts.is_empty());
    }

    #[tokio::test]
    async fn parity_port_check_ignores_a_session_with_forward_switched_off() {
        let dir = TempDir::new();
        let c = controller(&dir);
        let port = free_port();
        let mut off = profile("off", 22);
        off.forward.http_port = port;
        off.forward.enabled = false;
        off.reverse.enabled = true;
        off.reverse.reverse_http_port = 8888;
        c.mutate_config(|config| {
            config.sessions.push(off.clone());
            Ok(())
        })
        .unwrap();
        assert!(c.check_port_conflicts(None, LOOPBACK, port, 0).conflicts.is_empty());
    }

    #[tokio::test]
    async fn parity_port_check_reports_a_busy_os_socket_once() {
        let dir = TempDir::new();
        let c = controller(&dir);
        let held = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = held.local_addr().unwrap().port();
        let report = c.check_port_conflicts(None, LOOPBACK, port, port);
        assert_eq!(report.conflicts.len(), 1);
        assert_eq!(report.conflicts[0].kind, "os_socket");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn parity_running_session_does_not_conflict_with_its_own_listener() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        let node = spawn_node().await;
        let mut session = node.session("own");
        let secret = c
            .set_password_secret(None, crate::controller::SecretInput::new(SERVER_PASSWORD))
            .unwrap();
        session.hops[0].host.auth =
            vec![conduit_core::AuthMethod::Password { secret: secret.secret_ref }];
        let port = session.forward.http_port;
        let id = session.id;
        c.upsert_session(session).unwrap();
        c.start_session(id).await.unwrap();
        let prompt = wait_for_prompt(&c, id).await;
        c.approve_host_key(id, &prompt.sha256).unwrap();
        wait_for_state(&c, id, conduit_runtime::SessionState::Connected).await;

        assert!(c.check_port_conflicts(Some(id), LOOPBACK, port, 0).conflicts.is_empty());
        let other = c.check_port_conflicts(None, LOOPBACK, port, 0);
        assert!(other.conflicts.iter().any(|x| x.kind == "session"));
        assert!(other.conflicts.iter().any(|x| x.kind == "os_socket"));
        c.stop_session(id).await.unwrap();
    }

    #[test]
    fn parity_filter_allow_and_block_modes() {
        let list = rules(&["10.0.0.0/8", "*.example.com"]);
        let check = |mode, target| test_filter_rules(mode, &list, target).allowed;
        assert_eq!(check(FilterMode::Allow, "10.1.2.3"), Some(true));
        assert_eq!(check(FilterMode::Allow, "api.example.com"), Some(true));
        assert_eq!(check(FilterMode::Allow, "example.com"), Some(false));
        assert_eq!(check(FilterMode::Block, "10.1.2.3"), Some(false));
        assert_eq!(check(FilterMode::Block, "8.8.8.8"), Some(true));
    }

    #[test]
    fn parity_filter_reports_every_bad_rule_with_its_index() {
        let result = test_filter_rules(FilterMode::Allow, &rules(&["ok.example", "10.0.0.0/99", "a*b"]), "x");
        assert!(!result.valid);
        assert_eq!(result.allowed, None);
        let indexes: Vec<usize> = result.rule_errors.iter().map(|e| e.index).collect();
        assert_eq!(indexes, [1, 2]);
    }

    #[test]
    fn parity_filter_empty_rules_and_empty_target() {
        let none = test_filter_rules(FilterMode::Allow, &[], "anything.example");
        assert!(none.valid);
        assert_eq!(none.allowed, Some(true));
        let blank = test_filter_rules(FilterMode::Block, &rules(&["a.example"]), "  ");
        assert!(!blank.valid);
        assert_eq!(blank.allowed, None);
    }
}
