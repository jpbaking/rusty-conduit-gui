# phase-0001 — Add rusty-conduit-engine v0.2.0 and port conduit-core

- Status: done
- Owner: executor
- Depends on: none
- Goal: Add `rusty-conduit-engine` `v0.2.0` (pinned git tag) to the workspace and port `conduit-core` from `rusty-conduit-ssh` to `rusty-conduit-engine`.
- Done when: `conduit-core` builds and passes `cargo test -p conduit-core` and `cargo clippy -p conduit-core --all-targets -- -D warnings` with zero `rusty-conduit-ssh` imports.
- Pattern to follow: `crates/conduit-core/src/mapping.rs:66` and `crates/conduit-core/src/validate.rs:263`

## Context
- Gate A confirmed pinning `rusty-conduit-engine = { git = "https://github.com/jpbaking/rusty-conduit-engine", tag = "v0.2.0" }` in root `Cargo.toml`.
- Keep `rusty-conduit-ssh` in root `Cargo.toml` `[workspace.dependencies]` for now so other workspace members still parse until phase-0003 removes the last consumer.
- `rusty_conduit_engine` has no `config::Config` and no `SshIpVersion`: those were CLI-specific in `rusty-conduit-ssh`. Define `SshIpVersion` (`V4`, `V6`, `Auto` with case-insensitive `FromStr`: `"4"|"v4"|"ipv4"`, `"6"|"v6"|"ipv6"`, `"auto"|"any"`) and keepalive bounds (`MAX_TCP_KEEPALIVE_DURATION = Duration::from_secs(32_767)`, `MAX_TCP_KEEPALIVE_RETRIES = 127`) inside `conduit-core`.
- Replace `to_config(profile, mitm_ca_pem: Option<&Path>)` with `to_engine_config(profile: &SessionProfile) -> Result<EngineConfig, MappingError>` (dropping `MappingError::MitmCaNotLoaded`, since MITM CAs are now loaded in memory from vault bytes in `conduit-runtime`, not from temp file paths).
- Always use `CARGO_NET_GIT_FETCH_WITH_CLI=true` when running cargo commands.

## Scope
- In: `Cargo.toml`, `Cargo.lock`, `crates/conduit-core/Cargo.toml`, `crates/conduit-core/src/lib.rs`, `crates/conduit-core/src/mapping.rs`, `crates/conduit-core/src/validate.rs`, `crates/conduit-core/src/model.rs`
- Out: `crates/conduit-ssh/`, `crates/conduit-openssh/`, `crates/conduit-runtime/`, `crates/conduit-tray/`, `crates/conduit-vault/`, `src-tauri/`, `.github/`, `scripts/`, `docs/`

## Sub-tasks
1. [done] Add `rusty-conduit-engine = { git = "https://github.com/jpbaking/rusty-conduit-engine", tag = "v0.2.0" }` to `[workspace.dependencies]` in `Cargo.toml` (keeping `rusty-conduit-ssh` until phase-0003) and switch `crates/conduit-core/Cargo.toml` from `rusty-conduit-ssh` to `rusty-conduit-engine` — done when: `crates/conduit-core/Cargo.toml` references `rusty-conduit-engine = { workspace = true }` and not `rusty-conduit-ssh`.
2. [done] Port `crates/conduit-core/src/validate.rs` to `rusty_conduit_engine` (`filter::FilterRule`, `logging::{LogFormat, LogLevel}`, `mitm::MIN_MITM_CERT_TTL`), defining `SshIpVersion`, `MAX_TCP_KEEPALIVE_DURATION`, and `MAX_TCP_KEEPALIVE_RETRIES` locally in `conduit-core` and re-exporting `SshIpVersion` from `lib.rs` — done when: `validate.rs` has zero `rusty_conduit_ssh` references and all existing validation rules remain identical.
3. [done] Port `crates/conduit-core/src/mapping.rs` and `crates/conduit-core/src/lib.rs` (and doc comments in `model.rs`): define `pub struct EngineConfig` holding `forward_server: ServerOptions`, `forward_enabled: bool`, `forward_filter: Option<HostFilter>`, `reverse_bind: IpAddr`, `reverse_http_port: u16`, `reverse_socks_port: u16`, `reverse_max_connections: usize`, `reverse_enabled: bool`, `reverse_filter: Option<HostFilter>`, `keepalive: Option<KeepaliveSettings>`, `mitm_enabled: bool`, `mitm_options: MitmOptions` (`ca: None`, `cert_ttl`, `cert_cache_max`), `socks_block_web_in_mitm: bool`, `log_level: LogLevel`, `log_format: LogFormat`, `http_access_log: Option<PathBuf>`, `socks_log: Option<PathBuf>`, `ssh_ip_version: SshIpVersion`, plus `is_reverse_multiplexed(&self) -> bool`; implement `pub fn to_engine_config(profile: &SessionProfile) -> Result<EngineConfig, MappingError>` and update unit tests — done when: `conduit-core` has zero `rusty_conduit_ssh` references and all unit tests pass.
4. [done] Run `## Verify` and record observed output in `## Evidence` — done when: both `cargo test -p conduit-core` and `cargo clippy -p conduit-core --all-targets -- -D warnings` exit 0.

## Verify
```sh
CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p conduit-core && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo clippy -p conduit-core --all-targets -- -D warnings && ! git grep -n "rusty.conduit.ssh" -- crates/conduit-core/
```

## Escalate when
- `rusty-conduit-engine` `v0.2.0` cannot be fetched over git even with `CARGO_NET_GIT_FETCH_WITH_CLI=true` → stop, set Status: needs-human — reason: cannot fetch rusty-conduit-engine v0.2.0 from GitHub
- An expected type or constant in `rusty_conduit_engine` differs in signature from what is specified in Context → stop, set Status: needs-human — reason: document the exact API mismatch

## Log
- (append-only, one line per event)
- began phase (commit 6255a5d)
- sub-task 1: added `rusty-conduit-engine` v0.2.0 (git tag) to `[workspace.dependencies]` beside `rusty-conduit-ssh`; switched `crates/conduit-core/Cargo.toml` to `rusty-conduit-engine = { workspace = true }`; `Cargo.lock` gained `rusty-conduit-engine v0.2.0 (#bc05012d)` and `num_threads`
- sub-task 2: `validate.rs` now imports `filter::FilterRule`, `logging::{LogFormat, LogLevel}`, `mitm::MIN_MITM_CERT_TTL` from the engine; defined `SshIpVersion` (case-insensitive aliases per Context) and `MAX_TCP_KEEPALIVE_DURATION`/`MAX_TCP_KEEPALIVE_RETRIES` locally; re-exported `SshIpVersion` from `lib.rs`; rule bodies untouched (only imports, docs, and the new definitions changed)
- sub-task 3: replaced `to_config` with `to_engine_config(&SessionProfile) -> Result<EngineConfig, MappingError>`; added `EngineConfig` with the specified fields and `is_reverse_multiplexed`; dropped `MappingError::MitmCaNotLoaded`; `forward_server.keepalive` mirrors `keepalive`; rewrote unit tests (16 mapping tests); updated `lib.rs` and `model.rs` doc comments
- verify: first clippy run failed on `clippy::needless_update` in a new test (`mapping.rs:300`); removed the redundant `..Default::default()` and re-ran — pass

## Evidence
- (append-only: command → observed result)
- `CARGO_NET_GIT_FETCH_WITH_CLI=true cargo fetch` → `Adding rusty-conduit-engine v0.2.0 (https://github.com/jpbaking/rusty-conduit-engine?tag=v0.2.0#bc05012d)`
- `grep -n rusty crates/conduit-core/Cargo.toml` → `9:rusty-conduit-engine = { workspace = true }` only
- `grep -n "rusty.conduit.ssh" crates/conduit-core/src/validate.rs` → no matches (rc=1)
- `CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p conduit-core` → `test result: ok. 69 passed; 0 failed` (+ doc-tests 0/0)
- `CARGO_NET_GIT_FETCH_WITH_CLI=true cargo clippy -p conduit-core --all-targets -- -D warnings` → `Finished dev profile` (no warnings) after fix-up
- `## Verify` block verbatim → exit 0 (`git grep -n "rusty.conduit.ssh" -- crates/conduit-core/` finds nothing)
- `git grep -n to_config -- crates src-tauri` outside conduit-core → `crates/conduit-runtime/src/runner.rs:16,598` still call the removed `to_config`; expected to be ported in phase-0003 (workspace-wide build is broken until then)
