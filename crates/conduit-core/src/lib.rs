//! `conduit-core` — UI-agnostic data model, validation, config mapping, and persistence.
//!
//! Every session, host, and vault data model lives here so future UI shells
//! (Tauri v2 + Svelte 5) stay thin adapters. Models are validated ([`validate`]) and then
//! mapped ([`to_engine_config`]) into an [`EngineConfig`] for `rusty_conduit_engine` at
//! session start.
//!
//! See `docs/MASTER-PLAN.md` section 7 for the full data model.

mod known_hosts_import;
mod mapping;
mod migrate_v2;
mod model;
mod storage;
mod v2_mapping;
mod v2_model;
mod v2_validate;
mod validate;

pub use known_hosts_import::{parse_openssh_known_hosts_for_host, ImportedHostKey};
pub use mapping::{to_engine_config, EngineConfig, MappingError};
pub use migrate_v2::{
    load_or_migrate_app_config, migrate_v1_sessions, MigrationReport, CURRENT_SCHEMA_VERSION,
    V1_BACKUP_FILE_NAME,
};
pub use model::*;
pub use storage::{
    load_app_config, load_known_hosts, save_app_config, save_known_hosts, StorageError,
};
pub use v2_mapping::{
    global_filter, proxy_mitm_options, proxy_referenced_tunnels, proxy_server_options,
    proxy_to_routing_input, proxy_vault_secret_refs, routing_config, tunnel_to_engine_config,
};
pub use v2_model::*;
pub use v2_validate::{validate_proxy, validate_tunnel, ProxyValidateError};
pub use validate::{validate, validate_forward_preset, SshIpVersion, ValidateError};
