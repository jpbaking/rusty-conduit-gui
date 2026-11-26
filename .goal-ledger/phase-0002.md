# phase-0002 — Add External TOML link watcher in conduit-runtime and wire import/export/link IPC commands in src-tauri

- Status: done
- Owner: executor
- Depends on: phase-0001
- Goal: Implement External TOML link mode live file watching and hot-reload in `conduit-runtime` (`toml_watcher.rs` + `ProxyManager`) and expose AirSwitch `.bak` import, 3-CLI `config.toml` import/export, and External TOML link/unlink/reload operations in `src-tauri` (`controller/import_export.rs`, `commands.rs`, `lib.rs`).
- Done when: `cargo test -p conduit-runtime -p rusty-conduit-gui --lib` and `cargo clippy -p conduit-runtime -p rusty-conduit-gui --all-targets -- -D warnings` pass with unit tests covering External TOML live hot-reload + invalid-TOML resilience, AirSwitch import into Vault, and all 3 CLI TOML imports/exports.
- Pattern to follow: `crates/conduit-runtime/src/proxy_manager.rs`, `src-tauri/src/controller/proxies.rs`, `src-tauri/src/commands.rs:365-650`

## Context
- Disk constraint: ALWAYS pass `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true` on every `cargo` command.
- **External TOML watcher (`crates/conduit-runtime/src/toml_watcher.rs`)**:
  - Pure-Rust async watcher (no new OS/C crates): polls the linked file on `debounce_ms` (clamped to `250..=10_000` ms), checking `(mtime, len)` and content bytes; when bytes change, waits one debounce window to coalesce rapid saves, then calls `conduit_core::import_rusty_conduit_switch_toml`.
  - Integrate into `ProxyManager`: when a running Proxy has `SourceMode::ExternalToml { path, debounce_ms }`, spawn the watcher task alongside the proxy task (cancelled when the proxy stops or switches back to `Managed`).
  - On valid TOML change: merge the parsed profiles/routing/filter/network/logging into the running Proxy (preserving its `id`, `name`, `source`, `autostart`, `enabled`, and existing vaulted `password` refs if profile names match, never storing inline passwords in memory longer than needed) and hot-reload via `ProxyManager::upsert_proxy` (bumping `config_generation` and emitting `ProxyEvent::Reloaded`, or flagging `restart_required` if listeners changed).
  - On invalid TOML or unreadable file: log a clear warning to the Proxy's log buffer and keep the last-good compiled `RoutingState` running untouched!
- **`src-tauri/src/controller/import_export.rs`** (and IPC in `commands.rs` + `lib.rs`):
  - `preview_airswitch_import(path: PathBuf) -> AirSwitchPreview` (returns suggested proxy name, profile count, rule count, extracted password count, warnings, and summary of profiles — NEVER returns plaintext passwords).
  - `commit_airswitch_import(path: PathBuf, proxy_name: Option<String>, target_proxy_id: Option<ProxyId>) -> AirSwitchCommitResult`:
    - If extracted passwords exist and the Vault is locked, return `AppError::VaultLocked` (or `Vault(VaultError::Locked)`) so the UI prompts to unlock Vault first!
    - Store each extracted password via `vault.put_upstream_password` and attach `UpstreamPasswordSource::Vault(secret_ref)` to the corresponding profile.
    - Create a new `Proxy` (or update `target_proxy_id` if provided), save config, sync `ProxyManager`, and return `{ proxy, warnings, stored_passwords }`.
  - `preview_toml_import(path: PathBuf, format: Option<CliTomlFormat>) -> TomlImportPreview` (auto-detects format if `None`; returns detected format, proxy name, tunnel name if SSH, profile count, rule count, extracted password count, warnings/notes — NEVER returns plaintext passwords).
  - `commit_toml_import(path: PathBuf, format: Option<CliTomlFormat>, name: Option<String>) -> TomlImportCommitResult` (stores any extracted switch passwords into Vault, saves imported `Proxy` and optional `Tunnel`, re-pointing the Proxy's `UpstreamKind::Tunnel { tunnel_id }` to the saved Tunnel's ID if `upsert_tunnel` assigns a new UUID, and syncs managers).
  - `export_proxy_toml(proxy_id: ProxyId, format: CliTomlFormat, path: Option<PathBuf>) -> TomlExportResult`:
    - Calls `conduit_core`'s exporter for the chosen format (passing the referenced `Tunnel` when `format == RustyConduitSsh`).
    - If `path` is `Some`, writes with `write_private_file` (`0600`). Always returns `{ format, toml, notes, path }` (guaranteed free of plaintext secrets).
  - `link_proxy_external_toml(proxy_id: ProxyId, path: PathBuf, debounce_ms: u64) -> ProxySaveResult`: validates the TOML file can be parsed right now, updates `proxy.source = SourceMode::ExternalToml { path, debounce_ms }`, saves config, and updates/reloads `ProxyManager`.
  - `unlink_proxy_external_toml(proxy_id: ProxyId) -> ProxySaveResult`: sets `proxy.source = SourceMode::Managed`, saves config, and updates `ProxyManager` (stopping the file watcher).
  - `reload_proxy_external_toml(proxy_id: ProxyId) -> ProxySaveResult`: reads the linked TOML immediately, updates config + hot-reloads `ProxyManager`.
- Register all new commands in `src-tauri/src/commands.rs` and `ipc_handler!` in `src-tauri/src/lib.rs` (check `commands.rs` `V2_COMMANDS` test too).

## Scope
- In: `crates/conduit-runtime/src/lib.rs`, `crates/conduit-runtime/src/toml_watcher.rs` (create), `crates/conduit-runtime/src/proxy_manager.rs`, `src-tauri/src/controller.rs`, `src-tauri/src/controller/import_export.rs` (create), `src-tauri/src/commands.rs`, `src-tauri/src/lib.rs`
- Out: `crates/conduit-core/`, `crates/conduit-vault/`, `crates/conduit-tray/`, `src-tauri/src/controller/export.rs`, `src-tauri/ui/`, `src-tauri/tests/secret_leak_scan.rs`

## Sub-tasks
1. [done] Create `crates/conduit-runtime/src/toml_watcher.rs` and wire it into `crates/conduit-runtime/src/proxy_manager.rs` (plus `lib.rs` export), with runtime tests verifying live hot-reload on TOML edit and last-good preservation on invalid TOML — done when: `cargo test -p conduit-runtime` passes.
2. [done] Create `src-tauri/src/controller/import_export.rs` (wired in `controller.rs`) implementing AirSwitch preview/commit (storing passwords in Vault), 3-CLI TOML preview/commit/export, and External TOML link/unlink/reload, with controller unit tests — done when: `cargo test -p rusty-conduit-gui --lib import_export` passes.
3. [done] Expose and register all new U4 IPC commands in `src-tauri/src/commands.rs` and `src-tauri/src/lib.rs` — done when: `cargo test -p rusty-conduit-gui --lib` passes.
4. [done] Run `## Verify` and record observed results in `## Evidence` — done when: `## Verify` exits 0.

## Verify
```sh
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p conduit-runtime -p rusty-conduit-gui --lib && CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo clippy -p conduit-runtime -p rusty-conduit-gui --all-targets -- -D warnings
```

## Escalate when
- `conduit-core`'s `import_switch_toml` / `import_airswitch_bak` API from phase-0001 is missing a field or helper needed by `toml_watcher.rs` or `import_export.rs` → stop, set Status: needs-human — reason: name the exact missing type or function in `conduit-core`

## Log
- (append-only, one line per event)
- sub-task 1: added `toml_watcher.rs` (polling watcher with (mtime,len)+bytes check, debounce clamp 250..=10000 ms, coalescing; `merge_external_toml*`, `read_external_toml`) and wired a per-slot watcher into `ProxyManager` (spawned on start / upsert when `SourceMode::ExternalToml`, dropped on stop / unlink; invalid or rejected files log a warning and keep last-good; rejected merge restores the saved Proxy). Watcher holds a `Weak<Inner>` (no Arc cycle). The first settled read is treated as a change, so edits made while stopped apply after start (no-op when identical).
- sub-task 2: added `src-tauri/src/controller/import_export.rs` (wired in `controller.rs`): AirSwitch preview/commit (passwords vaulted via `put_upstream_password`, `VaultError::Locked` refused before any save, vault records rolled back if the save fails; `target_proxy_id` replaces only profiles+routing), 3-CLI TOML preview/commit (SSH Tunnel saved first, Proxy re-pointed to the saved Tunnel id) and export (`write_private_file`, 0600), External TOML link/unlink/reload (debounce stored clamped to 250..=10000). 7 controller tests.
- sub-task 3: added 8 `#[tauri::command]`s in `commands.rs`, registered in `ipc_handler!` (the macro lives in `commands.rs`; `src-tauri/src/lib.rs` needed no change), plus `U4_COMMANDS` and an IPC test asserting no response, `config.json`, or exported TOML contains the inline-password canaries.
- sub-task 4: `## Verify` passed first time (no fix-ups).

## Evidence
- (append-only: command → observed result)
- `cargo test -p conduit-runtime` (with low-disk env) → lib 91 passed; e2e_runtime 9; openssh_e2e 9; u2_tunnels_proxies 7; 0 failed (new: `toml_watcher::tests::*` 4, `proxy_manager::tests::external_toml_hot_reloads_and_keeps_last_good_on_invalid_files`)
- `cargo test -p rusty-conduit-gui --lib import_export` → 7 passed; 0 failed
- `cargo test -p rusty-conduit-gui --lib` → 168 passed; 0 failed (incl. `commands::tests::every_u4_ipc_command_works_and_no_response_leaks_an_imported_password`)
- `## Verify` (cargo test -p conduit-runtime -p rusty-conduit-gui --lib && cargo clippy -p conduit-runtime -p rusty-conduit-gui --all-targets -- -D warnings, low-disk env) → conduit-runtime lib 91 passed, rusty-conduit-gui lib 168 passed, clippy `Finished` with no warnings; exit 0
