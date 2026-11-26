# phase-0001 — Add Tunnel, Proxy, UpstreamProfile, and routing models to conduit-core and upstream-password record to conduit-vault

- Status: done
- Owner: executor
- Depends on: none
- Goal: Add the v2 data model (`Tunnel`, `Proxy`, `UpstreamProfile`, routing tables/rules) to `conduit-core` alongside legacy `SessionProfile`, and add upstream-password record support to `conduit-vault`.
- Done when: `conduit-core` and `conduit-vault` export the new types and pass `cargo test -p conduit-core -p conduit-vault` and `cargo clippy -p conduit-core -p conduit-vault --all-targets -- -D warnings`.
- Pattern to follow: `crates/conduit-core/src/model.rs:38-115` (ID newtypes), `crates/conduit-core/src/model.rs:771-863` (`SessionProfile`, `AppConfig`), `../rusty-conduit-engine/src/routing.rs:112-340` (`RuleConfig`, `RoutingTableConfig`, `RoutingConfig`, `ProfileConfig`), `docs/MASTER-PLAN.md:230-265`

## Context
- Keep all existing v1 types (`SessionProfile`, `AppConfig.sessions`, `ForwardConfig`, `ReverseConfig`, `TunnelConfig`, `LoggingConfig`, `MitmConfig`, `OpenSshOptions`, `to_engine_config`, `validate`) intact and unchanged in signature so `conduit-runtime`, `src-tauri`, and UI keep compiling until U3 switches them over.
- Create `crates/conduit-core/src/v2_model.rs` (re-exported from `crates/conduit-core/src/lib.rs`) defining:
  - `TunnelId(Uuid)` and `ProxyId(Uuid)` (matching `KeyId`/`SecretRef`/`MitmCaId` pattern: `new()`, `from_uuid(Uuid)`, `as_uuid()`, `Display`, `Default` nil, `Debug`, `Clone`, `Copy`, `PartialEq`, `Eq`, `Hash`, `Serialize`, `Deserialize`).
  - `TunnelStartMode`: `Linked` (default, per Gate A) | `Manual { autostart: bool }`.
  - `Tunnel`: `id: TunnelId`, `name: String`, `enabled: bool`, `start_mode: TunnelStartMode`, `engine: SshEngine`, `hops: Vec<HopEntry>`, `reverse: ReverseConfig`, `port_forwards: Vec<PortForward>`, `keepalive: TunnelConfig`, `logging: LoggingConfig`, `openssh: OpenSshOptions` (plus `active_forwards()` / `active_forwards_in()` helpers matching `SessionProfile`).
  - `SourceMode`: `Managed` (default) | `ExternalToml { path: PathBuf, debounce_ms: u64 }`.
  - `ListenerConfig`: `bind: IpAddr` (default `127.0.0.1`), `http_port: u16` (default `3128`), `socks_port: u16` (default `1080`), `max_connections: usize` (default `4096`).
  - `NetworkConfig`: `connect_timeout: Duration` (default `10s`, serde u64 secs), `tcp_keepalive: Duration` (default `60s`), `tcp_keepalive_interval: Duration` (default `10s`), `tcp_keepalive_retries: u32` (default `5`).
  - `GlobalFilterConfig`: `Off` (default) | `Allow(Vec<String>)` | `Block(Vec<String>)`.
  - `UpstreamPasswordSource`: `Vault(SecretRef)` | `Env(String)` | `File(PathBuf)`.
  - `UpstreamKind`: `Http` | `Https { #[serde(default)] tls_insecure_skip_verify: bool }` | `Socks5` | `Socks4a` | `Composite { http: String, https: String, fallback: String }` | `Tunnel { tunnel_id: TunnelId }`.
  - `UpstreamProfile`: `name: String`, `kind: UpstreamKind`, `host: Option<String>`, `port: Option<u16>`, `username: Option<String>`, `password: Option<UpstreamPasswordSource>`, `bypass: Vec<String>`, `color: Option<String>`.
  - Routing config types (serde `Serialize` + `Deserialize`, matching `rusty_conduit_engine::routing` shapes): `RouteInbound` (`Http` | `Socks`), `RouteTarget` (`One(String)` | `Many(Vec<String>)` with `as_slice(&self) -> &[String]`), `RoutePortSpec` (`Port(u16)` | `Range(String)`), `RouteHostLevels` (`min: Option<u32>`, `max: Option<u32>`), `RoutingRule` (all 18 fields of engine `RuleConfig`: `name`, `inbound`, `host`, `host_wildcard`, `host_regex`, `cidr`, `ip`, `port`, `host_levels`, `bypass`, `weekday`, `time`, `url_wildcard`, `url_regex`, `keyword`, `match_all`, `disabled`, `resolve_dns`, `target`), `RoutingTable` (`default: Option<RouteTarget>`, `inherit: bool`, `rules: Vec<RoutingRule>`), `RoutingTablesConfig` (`default: RouteTarget` defaulting to `"direct"`, `resolve_dns: bool`, `rules: Vec<RoutingRule>`, `http: Option<RoutingTable>`, `socks: Option<RoutingTable>`).
  - `Proxy`: `id: ProxyId`, `name: String`, `enabled: bool`, `autostart: bool`, `source: SourceMode`, `listeners: ListenerConfig`, `network: NetworkConfig`, `profiles: Vec<UpstreamProfile>`, `routing: RoutingTablesConfig`, `filter: GlobalFilterConfig`, `mitm: Option<MitmConfig>`, `logging: LoggingConfig`.
- Extend `AppConfig` in `crates/conduit-core/src/model.rs` with `#[serde(default)] pub tunnels: Vec<Tunnel>`, `#[serde(default)] pub proxies: Vec<Proxy>`, and `#[serde(default)] pub profile_library: Vec<UpstreamProfile>` (existing v1 JSON files deserialize with empty vecs).
- In `crates/conduit-vault`: add `pub const UPSTREAM_PASSWORD_RECORD: &str = "upstream_password";` and helper methods `Vault::put_upstream_password(&mut self, password: &[u8]) -> Result<String, VaultError>` and `Vault::get_upstream_password(&self, ref_id: &str) -> Result<Zeroizing<Vec<u8>>, VaultError>` (checking the record type is `UPSTREAM_PASSWORD_RECORD` or delegating cleanly to `put_secret`/`get_secret` with AAD bound to `UPSTREAM_PASSWORD_RECORD`), exported from `conduit-vault/src/lib.rs`, with unit tests.
- Always use `CARGO_NET_GIT_FETCH_WITH_CLI=true` when running cargo commands.

## Scope
- In: `crates/conduit-core/src/lib.rs`, `crates/conduit-core/src/model.rs`, `crates/conduit-core/src/v2_model.rs` (create), `crates/conduit-vault/src/lib.rs`, `crates/conduit-vault/src/store.rs`
- Out: `crates/conduit-core/src/validate.rs`, `crates/conduit-core/src/mapping.rs`, `crates/conduit-core/src/storage.rs`, `crates/conduit-runtime/`, `crates/conduit-ssh/`, `crates/conduit-openssh/`, `crates/conduit-tray/`, `src-tauri/`

## Sub-tasks
1. [done] Create `crates/conduit-core/src/v2_model.rs` with `TunnelId`, `ProxyId`, `TunnelStartMode` (default `Linked`), `Tunnel`, `SourceMode`, `ListenerConfig`, `NetworkConfig`, `GlobalFilterConfig`, `UpstreamPasswordSource`, `UpstreamKind`, `UpstreamProfile`, `RouteInbound`, `RouteTarget`, `RoutePortSpec`, `RouteHostLevels`, `RoutingRule`, `RoutingTable`, `RoutingTablesConfig`, and `Proxy`, plus serde round-trip and default unit tests — done when: `v2_model.rs` compiles and all its unit tests pass.
2. [done] Export `v2_model::*` from `crates/conduit-core/src/lib.rs` and add `#[serde(default)]` `tunnels`, `proxies`, and `profile_library` fields to `AppConfig` in `crates/conduit-core/src/model.rs` (with a unit test verifying v1 `AppConfig` JSON still deserializes cleanly) — done when: `cargo test -p conduit-core` passes.
3. [done] Add `UPSTREAM_PASSWORD_RECORD` and `Vault::put_upstream_password` / `Vault::get_upstream_password` in `crates/conduit-vault/src/store.rs`, export `UPSTREAM_PASSWORD_RECORD` from `crates/conduit-vault/src/lib.rs`, and add unit tests (round-trip, locked vault refused, wrong record type rejected) — done when: `cargo test -p conduit-vault` passes.
4. [done] Run `## Verify` and record observed results in `## Evidence` — done when: `## Verify` exits 0.

## Verify
```sh
CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p conduit-core -p conduit-vault && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo clippy -p conduit-core -p conduit-vault --all-targets -- -D warnings
```

## Escalate when
- Adding `tunnels`/`proxies`/`profile_library` to `AppConfig` breaks a struct literal in another crate (e.g. `src-tauri`) → stop, set Status: needs-human — reason: list the exact call sites outside Scope
- Any `rusty_conduit_engine::routing` rule field is missing or named differently from what is specified in Context → stop, set Status: needs-human — reason: document the field discrepancy

## Log
- (append-only, one line per event)
- began phase (commit 732dd11); preconditions checked: branch matches, Depends on none, Goal status executing
- pre-check: only `AppConfig` literals outside scope (`src-tauri/src/controller.rs:269`, `crates/conduit-core/src/storage.rs:153`) use `..Default`, so no escalation; engine `RuleConfig` (v0.2.0, `routing.rs`) field names match Context exactly (19 names incl. `target`; Context says "18" — wording only)
- sub-task 1: created `crates/conduit-core/src/v2_model.rs` with all listed types (+ generic `RouteOneOrMany<T>` mirroring engine `OneOrMany`, `RouteTarget` is its `String` alias; local `serde_duration` copy since model.rs one is private) and 10 unit tests
- sub-task 2: `pub use v2_model::*` in lib.rs; added `tunnels`, `proxies`, `profile_library` (`#[serde(default)]`) to `AppConfig`; test `v1_app_config_loads_with_empty_v2_collections`
- sub-task 3: added `UPSTREAM_PASSWORD_RECORD`, `Vault::put_upstream_password` (delegates to `put_secret`), `Vault::get_upstream_password` (filters by record type; wrong type → `SecretNotFound`); exported const; 3 unit tests
- sub-task 4: ran `## Verify` → exit 0

## Evidence
- (append-only: command → observed result)
- `cargo test -p conduit-core v2_model` → 10 passed; 0 failed
- `cargo test -p conduit-core` → 80 passed; 0 failed
- `cargo check --workspace --all-targets` → Finished, no errors/warnings (other crates unaffected)
- `cargo test -p conduit-vault` → 44 passed, 1 ignored (unit) + 6 passed (vault_security); new `upstream_password_*` tests ok
- `## Verify` command → EXIT=0; tests: core 80 passed, vault 44 passed/1 ignored + 6 passed; clippy `-D warnings` Finished with no warnings
