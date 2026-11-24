//! Builds the minimal environment for `ssh` and worker child processes.
//!
//! Children start from an empty environment. Only the names in [`ALLOWED`] are copied, so
//! `SSH_AUTH_SOCK`, `WEBKIT_*`, `__NV_*`, and the desktop `DISPLAY` never reach them.

use std::ffi::{OsStr, OsString};
use std::fmt;

/// Askpass IPC endpoint.
pub const ENV_ENDPOINT: &str = "CONDUIT_ASKPASS_ENDPOINT";
/// Comma-separated tokens for hops `0..=CONDUIT_ASKPASS_HOP`.
pub const ENV_TOKENS: &str = "CONDUIT_ASKPASS_TOKENS";
/// The hop this process authenticates as.
pub const ENV_HOP: &str = "CONDUIT_ASKPASS_HOP";

/// `ssh` needs a `DISPLAY` value to consider askpass on older versions. Nothing connects to it.
pub const ASKPASS_DISPLAY: &str = "conduit:0";

#[cfg(not(windows))]
const ALLOWED: &[&str] = &["PATH", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR"];

#[cfg(windows)]
const ALLOWED: &[&str] = &[
    "PATH",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "USERNAME",
    "PROGRAMDATA",
    "COMSPEC",
    "PATHEXT",
];

/// What a child needs to reach the askpass server as one hop.
///
/// A hop's process holds its own token and those of the hops before it, because it starts their
/// `hop-proxy` chain. It never holds a token for a later hop.
#[derive(Clone, PartialEq, Eq)]
pub struct AskpassEnv {
    pub worker: OsString,
    pub endpoint: String,
    pub tokens: Vec<String>,
    pub hop: usize,
}

impl fmt::Debug for AskpassEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AskpassEnv")
            .field("worker", &self.worker)
            .field("endpoint", &self.endpoint)
            .field("tokens", &self.tokens.len())
            .field("hop", &self.hop)
            .finish()
    }
}

impl AskpassEnv {
    /// Reads the values set by the parent process.
    pub fn from_process_env() -> Option<Self> {
        Some(Self {
            worker: std::env::var_os("SSH_ASKPASS")?,
            endpoint: std::env::var(ENV_ENDPOINT).ok()?,
            tokens: std::env::var(ENV_TOKENS)
                .ok()?
                .split(',')
                .map(str::to_string)
                .collect(),
            hop: std::env::var(ENV_HOP).ok()?.parse().ok()?,
        })
    }

    /// The same endpoint narrowed to `hop`, dropping every later hop's token.
    pub fn for_hop(&self, hop: usize) -> Option<Self> {
        if hop >= self.tokens.len() {
            return None;
        }
        Some(Self {
            worker: self.worker.clone(),
            endpoint: self.endpoint.clone(),
            tokens: self.tokens[..=hop].to_vec(),
            hop,
        })
    }

    /// This hop's own token.
    pub fn token(&self) -> Option<&str> {
        self.tokens.get(self.hop).map(String::as_str)
    }
}

/// The allowlisted part of `ambient` plus the askpass variables.
pub fn build_child_env<I>(ambient: I, askpass: &AskpassEnv) -> Vec<(OsString, OsString)>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    let mut env: Vec<(OsString, OsString)> = ambient
        .into_iter()
        .filter(|(name, _)| is_allowed(name))
        .collect();
    env.push(("SSH_ASKPASS".into(), askpass.worker.clone()));
    env.push(("SSH_ASKPASS_REQUIRE".into(), "force".into()));
    env.push(("DISPLAY".into(), ASKPASS_DISPLAY.into()));
    env.push((ENV_ENDPOINT.into(), askpass.endpoint.clone().into()));
    env.push((ENV_TOKENS.into(), askpass.tokens.join(",").into()));
    env.push((ENV_HOP.into(), askpass.hop.to_string().into()));
    env
}

fn is_allowed(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    ALLOWED.iter().any(|allowed| {
        if cfg!(windows) {
            allowed.eq_ignore_ascii_case(name)
        } else {
            *allowed == name
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn askpass() -> AskpassEnv {
        AskpassEnv {
            worker: "/opt/conduit-worker".into(),
            endpoint: "/run/rc-1/askpass.sock".into(),
            tokens: vec!["t0".into(), "t1".into(), "t2".into()],
            hop: 2,
        }
    }

    fn value<'a>(env: &'a [(OsString, OsString)], name: &str) -> Option<&'a OsStr> {
        env.iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_os_str())
    }

    #[test]
    fn env_strips_everything_outside_the_allowlist() {
        let ambient = [
            ("PATH", "/usr/bin"),
            ("SSH_AUTH_SOCK", "/run/user/agent"),
            ("SSH_AGENT_PID", "12"),
            ("DISPLAY", ":0"),
            ("WAYLAND_DISPLAY", "wayland-0"),
            ("WEBKIT_DISABLE_COMPOSITING_MODE", "1"),
            ("__NV_PRIME_RENDER_OFFLOAD", "1"),
            ("LD_PRELOAD", "/tmp/evil.so"),
            ("HOME", "/home/me"),
        ]
        .map(|(k, v)| (OsString::from(k), OsString::from(v)));
        let env = build_child_env(ambient, &askpass());

        assert_eq!(value(&env, "PATH"), Some(OsStr::new("/usr/bin")));
        for name in [
            "SSH_AUTH_SOCK",
            "SSH_AGENT_PID",
            "WAYLAND_DISPLAY",
            "WEBKIT_DISABLE_COMPOSITING_MODE",
            "__NV_PRIME_RENDER_OFFLOAD",
            "LD_PRELOAD",
            "HOME",
        ] {
            assert_eq!(value(&env, name), None, "{name}");
        }
    }

    #[test]
    fn env_sets_askpass_variables_and_replaces_display() {
        let ambient = [(OsString::from("DISPLAY"), OsString::from(":0"))];
        let env = build_child_env(ambient, &askpass());
        for (name, expected) in [
            ("SSH_ASKPASS", "/opt/conduit-worker"),
            ("SSH_ASKPASS_REQUIRE", "force"),
            ("DISPLAY", "conduit:0"),
            (ENV_ENDPOINT, "/run/rc-1/askpass.sock"),
            (ENV_TOKENS, "t0,t1,t2"),
            (ENV_HOP, "2"),
        ] {
            assert_eq!(value(&env, name), Some(OsStr::new(expected)), "{name}");
        }
        assert_eq!(env.iter().filter(|(k, _)| k == "DISPLAY").count(), 1);
    }

    #[test]
    fn env_narrowing_drops_later_hop_tokens() {
        let inner = askpass().for_hop(1).unwrap();
        assert_eq!(inner.tokens, ["t0", "t1"]);
        assert_eq!(inner.token(), Some("t1"));
        assert!(askpass().for_hop(3).is_none());
    }

    #[test]
    fn env_debug_never_prints_tokens() {
        let text = format!("{:?}", askpass());
        assert!(!text.contains("t0") && !text.contains("t2"), "{text}");
    }
}
