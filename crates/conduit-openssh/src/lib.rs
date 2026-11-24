//! `conduit-openssh` — the opt-in OpenSSH engine, isolated from the user's SSH setup.
//!
//! Never reads `~/.ssh/config`, `/etc/ssh/ssh_config`, `~/.ssh/id_*`, `~/.ssh/known_hosts`, or
//! the ambient `SSH_AUTH_SOCK`.

pub mod agent_server;
pub mod askpass;
pub mod binary;
pub mod config;
pub mod env;
pub mod known_hosts;
pub mod orphan;
pub mod runtime_dir;
pub mod supervisor;

pub use agent_server::IsolatedAgentServer;
pub use askpass::{run_askpass_client, AskpassError, AskpassServer};
pub use binary::{
    check_openssh_binary, check_version_for_platform, parse_openssh_version, version_note,
    OpenSshBinaryInfo, FORCED_ASKPASS_VERSION, MIN_VERSION, MIN_WINDOWS_VERSION,
};
pub use config::{
    hop_alias, render_config, write_config, ConfigError, ConfigHop, SessionConfig, WriteConfigError,
};
pub use known_hosts::{host_key_alias, render_known_hosts, write_known_hosts, HopKey};
pub use runtime_dir::{write_private_file, RuntimeDir};
pub use supervisor::{
    resolve_worker_bin, LogFn, OpenSshError, OpenSshSupervisor, SupervisorHop, SupervisorOptions,
};

/// Lowercase hex for short identifiers.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}
