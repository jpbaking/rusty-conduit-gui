# phase-0003 — Port conduit-runtime and src-tauri, remove rusty-conduit-ssh

- Status: done
- Owner: executor
- Depends on: phase-0002
- Goal: Port `conduit-runtime` (engine `Server`-backed `ReverseProxy` with direct egress, in-memory `MitmState::from_pem_bytes`, delete `mitm_ca_file.rs`, `RoutingState` external tunnel profile, `OpenSshDialer`) and `src-tauri` onto `rusty-conduit-engine`, and remove `rusty-conduit-ssh` from workspace `Cargo.toml`.
- Done when: `rusty-conduit-ssh` is gone from `Cargo.toml`, `crates/`, and `src-tauri/src/` (except intentional U0 migration/legacy constants), and all Rust workspace clippy, tests, `secret_leak_scan`, and Linux tray compile check pass.
- Pattern to follow: `../rusty-conduit-ssh/src/reverse.rs:32-144` (engine `Server` reverse proxy with direct egress) and `../rusty-conduit-ssh/src/lib.rs:52-89` (`forward_routing` + `access_log_config`)

## Context
- Keep the v1 data model: each `SessionProfile` maps via `conduit_core::to_engine_config` to one forward engine `Server` (routing every request to external profile `"ssh-tunnel"` backed by `StatsDialer(base)`, with `cfg.forward_filter` enforced by the router — no `FilteredDialer`) plus an optional direct-egress `ReverseProxy` `Server`.
- Delete `crates/conduit-runtime/src/mitm_ca_file.rs` and remove `mod mitm_ca_file;` from `crates/conduit-runtime/src/lib.rs`. In `runner.rs`, read the MITM CA PEM bytes from the vault into `Option<Zeroizing<Vec<u8>>>` and pass them directly to `MitmState::from_pem_bytes(&pem, &pem, &cfg.mitm_options)` (for both forward and reverse MITM states; no temp files ever written).
- Create `crates/conduit-runtime/src/reverse.rs` (declared `mod reverse;` in `lib.rs`):
  - `pub(crate) struct ReverseForward { pub remote: SocketAddr, pub local: SocketAddr }` with `pub(crate) fn spec(&self) -> String` (format `ssh -R` spec, bracketing IPv6 addresses, e.g. `127.0.0.1:8080:127.0.0.1:50000` or `[::1]:8080:127.0.0.1:50000`) and `pub(crate) fn to_remote_forward(&self) -> RemoteForward`.
  - `ReverseProxy::start(cfg: &EngineConfig, mitm_ca_pem: Option<&[u8]>, access: &AccessLogger, logger: &Logger) -> Result<Option<Self>, String>`: builds `RoutingInput` with `filter: None`, `mitm_enabled: cfg.mitm_enabled`, `keepalive: cfg.keepalive`, `connect_timeout: DEFAULT_CONNECT_TIMEOUT`, and `DialerOptions { filter: cfg.reverse_filter.clone().map(Arc::new), .. }` (so direct egress checks both hostname and locally resolved IPs), optional `MitmState::from_pem_bytes`, `AccessLogger` tagged with `ProxyDirection::Reverse` and `with_routing_fields(false)`, `EngineHandlers::from_routing` + optional `.with_mitm(...)`, `Server::bind` on ephemeral loopback ports (`127.0.0.1:0`) with `.with_max_connections(cfg.reverse_max_connections)` and `.with_tcp_keepalive(cfg.keepalive)`.
- In `runner.rs`: build `AccessLogConfig::new(cfg.log_level, cfg.log_format, cfg.http_access_log.clone(), cfg.socks_log.clone()).with_routing_fields(false)`; tag forward access logger with `.with_direction(ProxyDirection::Forward)`; wire `OpenSshLink` with `conduit_openssh::{OpenSshDialer, TunnelState}`.
- In `src-tauri/src/controller/mitm_ca.rs` and `src-tauri/src/controller/parity.rs`: switch `rusty_conduit_ssh` imports to `rusty_conduit_engine`.
- Remove `rusty-conduit-ssh` from root `Cargo.toml` `[workspace.dependencies]`.
- Always use `CARGO_NET_GIT_FETCH_WITH_CLI=true` when running cargo commands.

## Scope
- In: `Cargo.toml`, `Cargo.lock`, `crates/conduit-runtime/Cargo.toml`, `crates/conduit-runtime/src/lib.rs`, `crates/conduit-runtime/src/mitm_ca_file.rs` (delete), `crates/conduit-runtime/src/reverse.rs` (create), `crates/conduit-runtime/src/runner.rs`, `crates/conduit-runtime/src/port_forward.rs`, `crates/conduit-runtime/src/logs.rs`, `crates/conduit-runtime/tests/e2e_runtime.rs`, `src-tauri/Cargo.toml`, `src-tauri/src/controller/mitm_ca.rs`, `src-tauri/src/controller/parity.rs`
- Out: `crates/conduit-core/`, `crates/conduit-ssh/`, `crates/conduit-openssh/`, `crates/conduit-tray/`, `crates/conduit-vault/`, `src-tauri/src/migration.rs`, `src-tauri/ui/`, `.github/`, `scripts/`, `docs/`

## Sub-tasks
1. [done] Switch `crates/conduit-runtime/Cargo.toml` and `src-tauri/Cargo.toml` from `rusty-conduit-ssh` to `rusty-conduit-engine = { workspace = true }`, and remove `rusty-conduit-ssh` from root `Cargo.toml` `[workspace.dependencies]` — done when: no `Cargo.toml` in the workspace references `rusty-conduit-ssh`.
2. [done] Delete `crates/conduit-runtime/src/mitm_ca_file.rs`, remove `mod mitm_ca_file;` from `crates/conduit-runtime/src/lib.rs`, and create `crates/conduit-runtime/src/reverse.rs` implementing `ReverseProxy` on `rusty_conduit_engine::server::Server` with direct egress, `DialerOptions.filter`, in-memory `MitmState::from_pem_bytes`, and unit tests — done when: `mitm_ca_file.rs` is deleted and `reverse.rs` compiles and tests direct-egress filtering & listen plans.
3. [done] Port `crates/conduit-runtime/src/runner.rs`, `crates/conduit-runtime/src/port_forward.rs`, `crates/conduit-runtime/src/logs.rs`, and `crates/conduit-runtime/tests/e2e_runtime.rs` to `rusty_conduit_engine`, `conduit_core::to_engine_config`, `MitmState::from_pem_bytes`, `crate::reverse::ReverseProxy`, and `conduit_openssh::{OpenSshDialer, TunnelState}` — done when: `CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p conduit-runtime` passes all unit and E2E tests.
4. [done] Port `src-tauri/src/controller/mitm_ca.rs` and `src-tauri/src/controller/parity.rs` imports to `rusty_conduit_engine` — done when: `src-tauri` compiles and passes all tests including `secret_leak_scan` and `conduit_check_tauri_tray`.
5. [done] Run `## Verify` and record observed results in `## Evidence` — done when: every command in `## Verify` exits 0.
6. [done] Fix-up: `## Verify` clippy failed with `wrong_self_convention` on `ReverseForward::to_remote_forward(&self)` because the struct derived `Copy`; drop `Copy` from the derive to keep the specified `&self` signature — done when: `cargo clippy --workspace --all-targets -- -D warnings` passes.

## Verify
```sh
CARGO_NET_GIT_FETCH_WITH_CLI=true cargo clippy --workspace --all-targets -- -D warnings && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test --workspace && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p rusty-conduit-gui --test secret_leak_scan && CARGO_NET_GIT_FETCH_WITH_CLI=true RUSTFLAGS="--cfg conduit_check_tauri_tray" cargo check -p rusty-conduit-gui --tests --features tauri/tray-icon && ! git grep -n "rusty_conduit_ssh" -- crates/ src-tauri/ && ! git grep -n "rusty-conduit-ssh" -- Cargo.toml crates/*/Cargo.toml src-tauri/Cargo.toml
```

## Escalate when
- `e2e_runtime.rs` MITM or reverse proxy or OpenSSH E2E tests fail due to behavioral differences in `rusty-conduit-engine` `v0.2.0` → stop, set Status: needs-human — reason: report the exact failing test and assertion diff
- `check-pure-rust-crypto.py` or `secret_leak_scan` flags a new crate or dependency issue → stop, set Status: needs-human — reason: report the exact scan failure

## Log
- (append-only, one line per event)
- sub-task 1: switched conduit-runtime and src-tauri Cargo.toml to `rusty-conduit-engine = { workspace = true }`; removed `rusty-conduit-ssh` from root `[workspace.dependencies]`
- sub-task 2: deleted `mitm_ca_file.rs`, swapped `mod mitm_ca_file;` for `mod reverse;`, created `reverse.rs` (`ReverseForward` with `spec`/`to_remote_forward`, `reverse_listen_plan`, `reverse_routing` with `DialerOptions.filter`, `ReverseProxy::start` with in-memory `MitmState::from_pem_bytes`) plus 4 unit tests
- sub-task 3: ported `runner.rs` (`to_engine_config`, `forward_routing` to external `ssh-tunnel` profile over `StatsDialer`, no `FilteredDialer`, `access_log_config` with routing fields off, Forward/Reverse direction tags, CA PEM held as `Zeroizing<Vec<u8>>` and passed to `from_pem_bytes`, `OpenSshDialer`/`TunnelState`), `port_forward.rs`, `logs.rs`, and the `e2e_runtime.rs` comment
- sub-task 4: switched `src-tauri/src/controller/mitm_ca.rs` (`mitm::ca::{CaError, CaMaterial}`) and `parity.rs` (`filter::{FilterRule, HostFilter}`) imports to `rusty_conduit_engine`
- sub-task 5: first `## Verify` run failed at clippy (`wrong_self_convention` in `reverse.rs`); added fix-up sub-task 6
- sub-task 6: removed `Copy` from `ReverseForward` derive; clippy clean
- sub-task 5: re-ran `## Verify` → exit 0

## Evidence
- (append-only: command → observed result)
- `git grep -n "rusty-conduit-ssh" -- Cargo.toml crates/*/Cargo.toml src-tauri/Cargo.toml` → no matches (rc=1)
- `cargo test -p conduit-runtime --lib reverse` → 4 passed (spec_brackets_ipv6_and_maps_to_remote_forward, reverse_plan_uses_ephemeral_loopback, start_binds_loopback_listeners_and_reports_forwards, reverse_filter_checks_resolved_ips_for_hostnames)
- `CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p conduit-runtime` → lib 63 passed, e2e_runtime 9 passed, openssh_e2e 9 passed, 0 failed
- `git grep -n rusty_conduit_ssh -- crates/ src-tauri/` → no matches; `cargo build -p rusty-conduit-gui --all-targets` → exit 0, no warnings
- `## Verify` run 1 → FAILED at clippy: `error: methods with the following characteristics: (to_* and self type is Copy) usually take self by value` (conduit-runtime lib)
- `cargo clippy -p conduit-runtime --all-targets -- -D warnings` (after fix-up 6) → Finished, no warnings
- `## Verify` run 2 → VERIFY_RC=0: clippy OK; `cargo test --workspace` all pass (conduit-core 69, conduit-openssh 57+6, conduit-runtime 63+9+9, conduit-ssh 58+12, conduit-tray 23+1, conduit-vault 41 (1 ignored)+6, rusty-conduit-gui 132 + secret_leak_scan 5); secret_leak_scan 5 passed; tray check OK; both `git grep` guards empty
- extra: `grep -c rusty-conduit-ssh Cargo.lock` → 0; `python3 scripts/check-pure-rust-crypto.py` → PURE_RUST_CRYPTO_OK
