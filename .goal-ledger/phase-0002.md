# phase-0002 — Add Tunnel/Proxy validation, engine mapping, and §6.4 v0.1.0 migration in conduit-core

- Status: done
- Owner: executor
- Depends on: phase-0001
- Goal: Implement `validate_tunnel`, `validate_proxy`, `tunnel_to_engine_config`, `proxy_to_routing_input` / `proxy_server_options`, and §6.4 one-way `v0.1.0` session migration (with backup copy) in `conduit-core`.
- Done when: `conduit-core` passes all existing and new unit tests and `clippy -D warnings`, including migration round-trip and backup-file verification.
- Pattern to follow: `crates/conduit-core/src/validate.rs:263-379`, `crates/conduit-core/src/mapping.rs:66-170`, `crates/conduit-core/src/storage.rs:106-122`, `docs/MASTER-PLAN.md:189-195`

## Context
- Keep existing `validate(&SessionProfile)` and `to_engine_config(&SessionProfile)` intact so `conduit-runtime` and `src-tauri` continue compiling until U3.
- Create `crates/conduit-core/src/v2_validate.rs` (re-exported from `lib.rs`):
  - `validate_tunnel(tunnel: &Tunnel) -> Result<(), ValidateError>`: validates hops (non-empty, non-empty target host), OpenSSH `extra_args` denylist, reconnect delay ordering, TCP keepalive ranges, reverse allow/block mutual exclusion & `FilterRule` syntax, `port_forwards` (reusing existing `port_forward_problem` logic adapted for `Tunnel`), `ip_version`, `logging.level`, `logging.format`. Note: unlike v1 `SessionProfile`, a `Tunnel` does NOT require reverse proxy or port forwards to be enabled (a Tunnel may exist purely to serve Proxies via `UpstreamKind::Tunnel`).
  - `validate_proxy(proxy: &Proxy, known_tunnels: &[TunnelId], extra_listeners: &[SocketAddr]) -> Result<(), ProxyValidateError>`: validates at least one non-zero listener port (`http_port > 0 || socks_port > 0`), MITM CA presence & `cert_ttl >= MIN_MITM_CERT_TTL`, `network` TCP keepalive ranges & `connect_timeout > 0`, `GlobalFilterConfig` `FilterRule` syntax, `logging.level` & `logging.format`, no duplicate profile names or reserved names (`"direct"`, `"block"`), every `UpstreamKind::Tunnel { tunnel_id }` references a tunnel in `known_tunnels`, builds a `RoutingInput` (with `all_listeners = proxy_listeners + extra_listeners`, mapping `UpstreamKind::Tunnel` to `ProfileType::External`) and runs `RoutingInput::validate()` + `RoutingInput::validate_no_self_loop()` + `Router::from_input(&input)` so every rule, target, composite ref, and self-loop is checked by the engine itself!
- Create `crates/conduit-core/src/v2_mapping.rs` (re-exported from `lib.rs`):
  - `tunnel_to_engine_config(tunnel: &Tunnel) -> Result<EngineConfig, MappingError>`: maps a `Tunnel` into `EngineConfig` (with `forward_enabled: false`, `forward_server` ports `0`, `reverse_*` and `keepalive` and `logging` and `ssh_ip_version` populated from `tunnel`).
  - `proxy_server_options(proxy: &Proxy) -> ServerOptions`: maps `proxy.listeners` and `proxy.network` keepalive to `rusty_conduit_engine::server::ServerOptions`.
  - `proxy_mitm_options(proxy: &Proxy) -> Option<MitmOptions>`: maps `proxy.mitm` to `MitmOptions` (`ca: None`, `cert_ttl`, `cert_cache_max`).
  - `proxy_to_routing_input(proxy: &Proxy, resolved_passwords: &BTreeMap<String, Zeroizing<String>>, extra_listeners: &[SocketAddr]) -> Result<RoutingInput, MappingError>`: converts `Proxy` profiles (with `UpstreamKind::Tunnel` → `ProfileType::External`, and vaulted passwords injected from `resolved_passwords` into `ProfileConfig.password`), `RoutingTablesConfig` → `rusty_conduit_engine::routing::RoutingConfig`, `GlobalFilterConfig` → `Option<HostFilter>`, `listeners = proxy_server_options(proxy).listeners() + extra_listeners`, `keepalive`, `connect_timeout`.
  - Helper `proxy_referenced_tunnels(proxy: &Proxy) -> Vec<TunnelId>` and `proxy_vault_secret_refs(proxy: &Proxy) -> Vec<(String, SecretRef)>` (profile name → vaulted password `SecretRef`).
- Create `crates/conduit-core/src/migrate_v2.rs` (re-exported from `lib.rs`):
  - `pub const CURRENT_SCHEMA_VERSION: u32 = 2;`
  - `pub struct MigrationReport { pub migrated_sessions: usize, pub backup_path: Option<PathBuf> }`
  - `pub fn migrate_v1_sessions(config: &mut AppConfig) -> usize`: if `config.schema_version >= 2` or (`config.sessions.is_empty()` and (!config.tunnels.is_empty() || !config.proxies.is_empty())), sets `schema_version = 2` and returns `0`. Otherwise, for each `SessionProfile` in `config.sessions`:
    - Creates a `Tunnel` (same `name`, `enabled`, `start_mode: TunnelStartMode::Linked`, `engine`, `hops`, `reverse`, `port_forwards`, `keepalive: session.tunnel`, `logging`, `openssh`), with a fresh `TunnelId`.
    - Creates a `Proxy` (same `name`, `enabled`, `autostart`, `source: SourceMode::Managed`, `listeners` from `session.forward` using `effective_ports()`, `network` with keepalive from `session.tunnel` and `connect_timeout = 10s`, one `UpstreamProfile` named `"tunnel"` of kind `UpstreamKind::Tunnel { tunnel_id }`, `routing` default = `"tunnel"` with no rules, `filter` mapped from `session.forward.allow` / `block`, `mitm`, `logging`) — only if `session.forward.effective_ports() != (0, 0)` (a reverse-only or port-forward-only session creates only a `Tunnel` with `Manual { autostart: session.autostart }` so it still starts on autostart!).
    - Leaves `config.sessions` untouched only if requested? No: per §6.4, migration is one-way and keeps a backup copy of the old `config.json` in the data directory; `migrate_v1_sessions` populates `config.tunnels` and `config.proxies`, clears `config.sessions`, and sets `config.schema_version = 2`.
  - `pub fn load_or_migrate_app_config(path: &Path) -> Result<(AppConfig, MigrationReport), StorageError>`: loads `config.json`; if `schema_version < 2 && !sessions.is_empty()`, writes a backup copy `config.v1.bak.json` in the same directory (`0600` on Unix, never overwriting an existing backup), runs `migrate_v1_sessions`, atomically saves the migrated `config.json`, and returns `(config, report)`.
- Always use `CARGO_NET_GIT_FETCH_WITH_CLI=true` when running cargo commands.

## Scope
- In: `crates/conduit-core/Cargo.toml` (only if `zeroize` is needed), `crates/conduit-core/src/lib.rs`, `crates/conduit-core/src/validate.rs` (make helper functions `pub(crate)` if reused), `crates/conduit-core/src/mapping.rs` (make helper functions `pub(crate)` if reused), `crates/conduit-core/src/v2_validate.rs` (create), `crates/conduit-core/src/v2_mapping.rs` (create), `crates/conduit-core/src/migrate_v2.rs` (create), `Cargo.lock`
- Out: `Cargo.toml`, `crates/conduit-vault/`, `crates/conduit-runtime/`, `crates/conduit-ssh/`, `crates/conduit-openssh/`, `crates/conduit-tray/`, `src-tauri/`

## Sub-tasks
1. [done] Create `crates/conduit-core/src/v2_mapping.rs` implementing `tunnel_to_engine_config`, `proxy_server_options`, `proxy_mitm_options`, `proxy_to_routing_input`, `proxy_referenced_tunnels`, and `proxy_vault_secret_refs`, plus unit tests covering all `UpstreamKind` variants, `RoutingTablesConfig` conversion, and `GlobalFilterConfig` mapping — done when: `v2_mapping.rs` compiles and tests pass.
2. [done] Create `crates/conduit-core/src/v2_validate.rs` implementing `validate_tunnel` and `validate_proxy` (delegating profile/rule/self-loop validation to `RoutingInput::validate`, `validate_no_self_loop`, and `Router::from_input`), plus unit tests for valid/invalid tunnels, proxies, unknown tunnel refs, self-loops (including `extra_listeners`), and bad rules — done when: `v2_validate.rs` compiles and tests pass.
3. [done] Create `crates/conduit-core/src/migrate_v2.rs` implementing `CURRENT_SCHEMA_VERSION`, `MigrationReport`, `migrate_v1_sessions`, and `load_or_migrate_app_config` (creating `config.v1.bak.json` with `0600` permissions on Unix), plus unit tests for forward+tunnel migration, reverse-only migration, idempotency, and backup preservation — done when: `migrate_v2.rs` compiles and tests pass.
4. [done] Re-export the new modules' public items from `crates/conduit-core/src/lib.rs` and run `## Verify` — done when: `## Verify` exits 0.

## Verify
```sh
CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p conduit-core && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo clippy -p conduit-core --all-targets -- -D warnings
```

## Escalate when
- `rusty_conduit_engine::routing::ProfileConfig` or `RuleConfig` has a private field or constructor mismatch that prevents constructing `RoutingInput` directly → stop, set Status: needs-human — reason: document the exact private field or missing constructor

## Log
- (append-only, one line per event)
- sub-task 1: created v2_mapping.rs (tunnel_to_engine_config, proxy_server_options, proxy_mitm_options, proxy_to_routing_input, proxy_referenced_tunnels, proxy_vault_secret_refs, plus routing_config/global_filter helpers); made mapping.rs parse_rules/host_filter pub(crate); added MappingError::MissingUpstreamPassword; added zeroize dep to conduit-core- sub-task 2: created v2_validate.rs (validate_tunnel, validate_proxy, ProxyValidateError); generalized validate.rs port_forward_problem into pub(crate) port_forward_problem_in, tcp_keepalive into pub(crate) keepalive_problem, made denylisted_flag pub(crate) (v1 behaviour unchanged)
- sub-task 3: created migrate_v2.rs (CURRENT_SCHEMA_VERSION, V1_BACKUP_FILE_NAME, MigrationReport, migrate_v1_sessions, load_or_migrate_app_config with create_new 0600 backup)
- sub-task 4: re-exported v2_mapping/v2_validate/migrate_v2 items from lib.rs; first Verify run failed on clippy `clone_on_copy` (SshEngine) in migrate_v2.rs, fixed, Verify re-run exit 0

## Evidence
- (append-only: command → observed result)
- `cargo test -p conduit-core v2_mapping` → test result: ok. 9 passed; 0 failed
- `cargo test -p conduit-core v2_validate` → test result: ok. 16 passed; 0 failed
- `cargo test -p conduit-core migrate_v2` → test result: ok. 7 passed; 0 failed
- Verify (1st run) → EXIT=101: clippy `using clone on type SshEngine which implements the Copy trait`
- Verify `cargo test -p conduit-core && cargo clippy -p conduit-core --all-targets -- -D warnings` → EXIT=0; test result: ok. 112 passed; 0 failed; clippy Finished with no warnings
- `cargo check --workspace --all-targets` → Finished, no errors or warnings (runtime/src-tauri still compile)
