# phase-0001 — Wire AppController and Tauri commands to TunnelManager and ProxyManager

- Status: done
- Owner: executor
- Depends on: none
- Goal: Wire `AppController` (`src-tauri/src/controller*`) and IPC `src-tauri/src/commands.rs` to `TunnelManager` + `ProxyManager` + `load_or_migrate_app_config`, exposing full Proxy, Tunnel, Profile Library, upstream-password, hot-reload, tray override, Route Tester, Test Upstream, and access-log operations.
- Done when: `src-tauri` builds and passes `cargo test -p rusty-conduit-gui --lib` and `cargo clippy -p rusty-conduit-gui --all-targets -- -D warnings` with new controller unit tests covering Proxies, Tunnels, Profile Library, upstream passwords, hot-reload, overrides, Route Tester, and safe deletion.
- Pattern to follow: `src-tauri/src/controller.rs:210-370`, `src-tauri/src/controller/sessions.rs:1-270`, `src-tauri/src/commands.rs:164-365`, `docs/MASTER-PLAN.md:134-185`

## Context
- Disk constraint: ALWAYS pass `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true` on every `cargo` command so `target/` stays under ~4 GB.
- Keep `src-tauri/src/tray_bridge.rs` compiling in this phase (phase-0002 upgrades tray_bridge and conduit-tray); if `AppController` still exposes legacy `SessionManager` / v1 session helpers temporarily OR adapts `tray_bridge.rs` minimally, keep `cargo check -p rusty-conduit-gui --tests` green. Prefer adding `tunnels: Arc<TunnelManager>` and `proxies: Arc<ProxyManager>` on `AppController` alongside legacy `SessionManager` (or migrating `AppController` cleanly while leaving v1 session methods delegated/preserved until phase-0002/0006 removes unused ones).
- On `AppController::open`: run `conduit_core::load_or_migrate_app_config` on `config.json` so v0.1.0 `sessions` automatically migrate into `tunnels` + `proxies` (with `config.v1.bak.json` backup); load every `Tunnel` into `TunnelManager` and every `Proxy` into `ProxyManager`.
- Add controller methods and Tauri IPC commands in `src-tauri/src/commands.rs` (registered in `src-tauri/src/lib.rs` `invoke_handler!`) for:
  - **Proxies:** `list_proxies` (`Vec<ProxyView { profile: Proxy, snapshot: ProxySnapshot }>`), `upsert_proxy` (validates via `validate_proxy`, saves config, calls `proxies.upsert_proxy` returning hot-reload/restart status), `delete_proxy`, `duplicate_proxy`, `start_proxy`, `stop_proxy`, `restart_proxy`, `set_proxy_override(id, override_profile: Option<String>)`, `get_proxy_logs(id, limit)`, `clear_proxy_logs(id)`, `get_proxy_access_records(id, limit)`, `test_route(proxy, raw_target, inbound)`, `test_upstream(proxy, profile_name, host, port, timeout_ms)`.
  - **Tunnels:** `list_tunnels` (`Vec<TunnelView { profile: Tunnel, snapshot: TunnelSnapshot, used_by: Vec<UsageRef> }>`), `upsert_tunnel`, `delete_tunnel(id, force)` (refuses without `force` if referenced by Proxies, returning `DeleteResult` with `used_by` / `usage`; with `force`, stops affected running Proxies and deletes tunnel), `duplicate_tunnel`, `start_tunnel`, `stop_tunnel`, `restart_tunnel`, `get_tunnel_logs`, `clear_tunnel_logs`, `approve_tunnel_host_key`, `reject_tunnel_host_key`, `test_tunnel_chain(id)`.
  - **Profile Library:** `list_profile_library`, `upsert_library_profile`, `delete_library_profile(name)`.
  - **Vault upstream passwords:** `set_upstream_password(existing: Option<SecretRef>, value: SecretInput) -> SecretMeta` (stores via `vault.put_upstream_password`), plus include Proxy `UpstreamPasswordSource::Vault(ref)` and Proxy `mitm.ca` in `delete_secret` and `delete_mitm_ca` usage checks and force-delete cleanup!
  - **Global lifecycle & events:** `start_all_v2` / `stop_all_v2` (and wire `start_all` / `stop_all` / `on_system_wake` to cover Proxies + Manual Tunnels), forward `ProxyEvent` and `TunnelEvent` through `src-tauri/src/window.rs` to the WebView (`proxy-state-changed`, `proxy-reloaded`, `proxy-override-changed`, `tunnel-state-changed`).
- Also add `check_proxy_port_conflicts` (checking against other saved Proxies, Tunnels' local port forwards, and OS sockets).
- **Planner decision on `SCHEMA_VERSION`:** Change `const SCHEMA_VERSION: u32 = conduit_core::CURRENT_SCHEMA_VERSION;` (2) in `src-tauri/src/controller.rs`. Fresh v2 configs are stamped schema 2 (so existing v1 controller/session tests keep passing without touching `sessions.rs`), real v0.1.0 `config.json` files (schema 1) migrate cleanly via `load_or_migrate_app_config`, and `export.rs` already tests `SCHEMA_VERSION + 1`. Add a controller unit test verifying that a real schema-1 `config.json` on disk migrates into `tunnels` + `proxies` + `config.v1.bak.json` on `AppController::open`.

## Scope
- In: `src-tauri/src/controller.rs`, `src-tauri/src/controller/proxies.rs` (create), `src-tauri/src/controller/tunnels.rs` (create), `src-tauri/src/controller/keys.rs`, `src-tauri/src/controller/mitm_ca.rs`, `src-tauri/src/controller/parity.rs`, `src-tauri/src/commands.rs`, `src-tauri/src/window.rs`, `src-tauri/src/lib.rs`
- Out: `crates/conduit-core/`, `crates/conduit-vault/`, `crates/conduit-runtime/`, `crates/conduit-tray/`, `src-tauri/src/tray_bridge.rs`, `src-tauri/src/tray_tauri.rs`, `src-tauri/ui/`, `src-tauri/tests/secret_leak_scan.rs`

## Sub-tasks
1. [done] Wire `AppController` in `src-tauri/src/controller.rs` to hold `Arc<TunnelManager>` and `Arc<ProxyManager>`, run `load_or_migrate_app_config` on startup, populate both managers from `config.tunnels` / `config.proxies`, and update `delete_secret` / `delete_mitm_ca` in `keys.rs` / `mitm_ca.rs` to include Proxy upstream passwords and Proxy MITM CA references — done when: `AppController` compiles with both managers active.
2. [done] Create `src-tauri/src/controller/proxies.rs` and `src-tauri/src/controller/tunnels.rs` implementing Proxy CRUD + lifecycle + hot-reload + override + Route Tester + Test Upstream + Profile Library CRUD + `set_upstream_password`, and Tunnel CRUD + lifecycle + safe-delete `used_by` + host-key approval + `test_tunnel_chain`, plus `check_proxy_port_conflicts` in `parity.rs` — done when: both modules compile cleanly and have unit tests.
3. [done] Expose all new v2 commands in `src-tauri/src/commands.rs`, register them in `src-tauri/src/lib.rs`, and forward `ProxyEvent` / `TunnelEvent` in `src-tauri/src/window.rs` — done when: `cargo test -p rusty-conduit-gui --lib` passes all existing and new tests.
4. [done] Run `## Verify` and record observed results in `## Evidence` — done when: `## Verify` exits 0.

## Verify
```sh
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p rusty-conduit-gui --lib && CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo clippy -p rusty-conduit-gui --all-targets -- -D warnings
```

## Escalate when
- `load_or_migrate_app_config` breaks existing `src-tauri` v1 controller unit tests that expect `config.sessions` to remain populated → stop, set Status: needs-human — reason: report which existing v1 tests fail so planner can decide whether to gate migration or update those tests

## Log
- (append-only, one line per event)
- began phase (commit 179eb49); read controller/runtime/core APIs
- sub-task 1: replaced load_app_config with conduit_core::load_or_migrate_app_config in AppController::open (src-tauri/src/controller.rs:267); escalation trigger hit, stopped
- planner answered escalation: set `const SCHEMA_VERSION: u32 = conduit_core::CURRENT_SCHEMA_VERSION;` (2) in `src-tauri/src/controller.rs` and add a schema-1 migration test; reopened phase-0001 sub-task 1 to `[todo]` and re-delegated to `sub-u3-p1`
- re-began phase after planner unblock (commit db83d37)
- sub-task 1: controller.rs — SCHEMA_VERSION = conduit_core::CURRENT_SCHEMA_VERSION, load_or_migrate_app_config on open, Arc<TunnelManager> + Arc<ProxyManager> on Inner populated from config.tunnels/config.proxies (stopped Proxies registered via a no-await poll), wake/unlock hooks cover v2 (resume Locked Tunnels/Proxies), known_hosts autosave also listens to TunnelEvent, new AppError variants ProxyValidate/Proxy/Tunnel (codes validation/proxy|vault_locked/tunnel); keys.rs Usage gains tunnels/proxies/library_profiles + count(), key/secret usage and edits cover Tunnel hops, Proxy + library upstream passwords; delete_secret is now async and stops/re-syncs affected Proxies; mitm_ca.rs usage/force-delete cover Proxy mitm.ca
- sub-task 2: created controller/proxies.rs (Proxy CRUD/lifecycle/hot-reload result/override/logs/access records/Route Tester/Test Upstream/Profile Library CRUD/start_all_v2/stop_all_v2/start_autostart_v2/resume_locked_v2) with 10 tests, controller/tunnels.rs (CRUD, lifecycle, safe delete with used_by, pin cleanup, duplicate with pin copy, host-key approve/reject, test_tunnel_chain storing unknown keys for trust_tested_host_key) with 8 tests; set_upstream_password in keys.rs; check_proxy_port_conflicts in parity.rs with 1 test; schema-1 migration + fresh-schema tests in controller.rs
- sub-task 3: commands.rs — 32 new v2 commands registered in ipc_handler! (used by lib.rs invoke_handler), start_all/stop_all commands also run v2, delete_secret command awaits async controller; new IPC test exercising every V2_COMMANDS entry with secret-leak scan; window.rs forward_proxy_events/forward_tunnel_events (proxy-state-changed, proxy-reloaded, proxy-override-changed, tunnel-state-changed; lag → runtime-lagged) + test; lib.rs spawns both forwarders and start_autostart_v2
- sub-task 4: ran ## Verify, exit 0

## Evidence
- (append-only: command → observed result)
- `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo check -p rusty-conduit-gui --tests` (after sub-tasks 1–3) → `Finished dev profile`, no warnings
- `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p rusty-conduit-gui --lib` → `test result: ok. 155 passed; 0 failed` (was 130+2 failing); includes controller::tests::a_schema_1_config_migrates_into_tunnels_and_proxies_on_open, a_fresh_config_is_written_at_the_current_schema, 10 controller::proxies::tests::*, 8 controller::tunnels::tests::*, controller::parity::tests::parity_proxy_port_check_sees_proxies_tunnel_forwards_and_os_sockets, commands::tests::every_v2_ipc_command_works_and_no_response_leaks_a_secret, window::tests::window_v2_event_names_match_the_wire_format; existing config_mutations_persist_across_reopen and sessions_upsert_assigns_ids_and_persists pass
- ## Verify (`cargo test -p rusty-conduit-gui --lib && cargo clippy -p rusty-conduit-gui --all-targets -- -D warnings`, with the three env vars) → EXIT=0; tests `155 passed; 0 failed`; clippy `Finished dev profile` with no warnings
- `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p rusty-conduit-gui --lib` (with load_or_migrate only) → `test result: FAILED. 130 passed; 2 failed`; failing: controller::tests::config_mutations_persist_across_reopen (panicked controller.rs:882:48), controller::sessions::tests::sessions_upsert_assigns_ids_and_persists (panicked sessions.rs:755:46); also `warning: unused import: load_app_config`
