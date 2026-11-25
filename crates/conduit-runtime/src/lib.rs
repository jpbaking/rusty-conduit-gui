//! `conduit-runtime` — the UI-agnostic session supervisor.
//!
//! Tauri commands and the system tray drive [`SessionManager`]. It owns the session state
//! machine, reconnect backoff, per-session logs and stats, vault gating, and host-key approval.

// `SshError` is large by design (see `conduit-ssh`) and is only built on connection failure.
#![allow(clippy::result_large_err)]

pub mod backoff;
pub mod events;
pub mod hardening;
pub mod logs;
pub mod manager;
mod mitm_ca_file;
pub(crate) mod runner;
pub mod state;
pub mod wake;

pub use backoff::{Backoff, STABLE_UPTIME};
pub use events::{EventBus, RuntimeEvent};
pub use hardening::disable_core_dumps;
pub use manager::{ManagerConfig, RuntimeError, SessionManager};
pub use wake::{spawn_wake_listener, WakeCallback, WakeHandle};
pub use logs::{redact, LogLine, LogRingBuffer, LogWriter, DEFAULT_LOG_CAPACITY};
pub use state::{
    HostKeyPrompt, ListenerInfo, SessionSnapshot, SessionState, SessionStatsSnapshot,
};
