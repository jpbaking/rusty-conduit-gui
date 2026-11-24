//! `conduit-core` — UI-agnostic data model, validation, config mapping, and persistence.
//!
//! Every session, host, and vault data model lives here so future UI shells
//! (Tauri v2 + Svelte 5) stay thin adapters. Models are validated ([`validate`]) and then
//! mapped ([`to_config`]) into `rusty_conduit_ssh::config::Config` at session start.
//!
//! See `docs/MASTER-PLAN.md` section 7 for the full data model.

mod known_hosts_import;
mod mapping;
mod model;
mod storage;
mod validate;

pub use known_hosts_import::{parse_openssh_known_hosts_for_host, ImportedHostKey};
pub use mapping::{to_config, MappingError};
pub use model::*;
pub use storage::{
    load_app_config, load_known_hosts, save_app_config, save_known_hosts, StorageError,
};
pub use validate::{validate, ValidateError};
