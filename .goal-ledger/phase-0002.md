# phase-0002 — src-tauri v2 scaffold, AppState & write-only secret IPC commands

- Status: done
- Owner: executor
- Depends on: phase-0001
- Goal: Scaffold the Tauri v2 crate (`src-tauri/`) as a workspace member, implement `AppState` orchestrating `AppConfig`, `KnownHostsStore`, `Vault`, and `SessionManager`, and expose all write-only secret IPC commands with thorough Rust unit tests.
- Done when: `cargo test -p rusty-conduit-ssh-gui && cargo clippy --workspace --all-targets -- -D warnings` exits 0 with unit tests verifying every IPC command handler and confirming raw passwords/private keys/passphrases never appear in any serialized IPC response.
- Pattern to follow: `docs/MASTER-PLAN.md` Sections 4.1, 5.2, 5.3, and 7.2

## Context
`src-tauri/` is a thin adapter over `conduit-core`, `conduit-vault`, `conduit-ssh`, `conduit-runtime`, and `conduit-tray`.
Key decisions already made:
- Use **Tauri v2 stable** (`tauri = "2"`, `tauri-build = "2"`), NOT Tauri 3 alpha.
- **Write-Only WebView Secret Fields:** Rust IPC commands accept raw secrets (`password`, `private_key_pem`, `passphrase`) on write, encrypt them into `vault.bin`, and return ONLY opaque metadata (`SecretRef`, `KeyId`, `VaultKeyMeta`, `has_secret: true`). Raw secrets are NEVER returned to the WebView.
- Keep business logic inside pure testable Rust service methods (`AppController` in `src-tauri/src/controller.rs`) so `cargo test -p rusty-conduit-ssh-gui` tests every command cleanly without needing a live display/WebKit window!
- Persist `config.json` and `known_hosts.json` atomically via `conduit-core::storage` whenever profiles, hosts, keys, or host-key approvals change.
- Include `test_chain` IPC command calling `conduit_ssh::test_chain` prefix-by-prefix and returning structured per-hop diagnostics (`hop_index`, `hop_id`, `host`, `port`, `status`, `error`, `elapsed_ms`).
- Include a minimal placeholder `src-tauri/ui/dist/index.html` (and minimal `src-tauri/icons/icon.png`) so `tauri::generate_context!()` compiles cleanly before `phase-0004` builds the full Svelte 5 frontend.

## Scope
- In: `Cargo.toml`, `Cargo.lock`, `src-tauri/**` (excluding `src-tauri/ui/src/**`, only minimal `src-tauri/ui/dist/index.html` placeholder if needed for `tauri.conf.json`)
- Out: `crates/conduit-core/**`, `crates/conduit-vault/**`, `crates/conduit-ssh/**`, `crates/conduit-runtime/**`, `crates/conduit-tray/**`, `docs/MASTER-PLAN.md`

## Sub-tasks
1. [done] Add `src-tauri` to root `Cargo.toml` workspace members; create `src-tauri/Cargo.toml` (`name = "rusty-conduit-ssh-gui"`, `tauri = "2"`, `tauri-build = "2"`, `tauri-plugin-single-instance = "2"`, `tauri-plugin-autostart = "2"`, workspace crates), `src-tauri/build.rs`, `src-tauri/tauri.conf.json`, `src-tauri/capabilities/default.json`, a valid generated PNG icon in `src-tauri/icons/icon.png`, and a minimal `src-tauri/ui/dist/index.html` placeholder — done when: `cargo check -p rusty-conduit-ssh-gui` exits 0
2. [done] Implement `src-tauri/src/controller.rs` (`AppController`) managing `app_data_dir`, `AppConfig`, `KnownHostsStore`, `Vault` (open/create/unlock with password or keyring/lock/status), and `SessionManager`, with atomic persistence on mutations and `KnownHostsChanged` auto-save — done when: `cargo test -p rusty-conduit-ssh-gui controller` exits 0
3. [done] Implement key-vault and write-only secret methods on `AppController`: `import_key_pem`, `generate_key`, `rename_key`, `delete_key` (returning referencing host/session count & names, requiring `force: true` if referenced), `list_keys` (with `used_by` counts), `set_password_secret`, `set_mitm_passphrase`, `delete_secret`, and `export_backup` / `import_backup` — done when: `cargo test -p rusty-conduit-ssh-gui keys` exits 0
4. [done] Implement session, host-profile, and runtime methods on `AppController`: `get_state_summary`, `list_sessions`, `upsert_session` (validating via `conduit_core::validate`), `delete_session`, `list_hosts`, `upsert_host`, `delete_host`, `promote_hop_to_host`, `start_session`, `stop_session`, `restart_session`, `start_all`, `stop_all`, `get_session_logs`, `clear_session_logs`, `approve_host_key`, `reject_host_key`, `reset_host_key`, and `test_session_chain` (prefix-by-prefix `conduit_ssh::test_chain`) — done when: `cargo test -p rusty-conduit-ssh-gui sessions` exits 0
5. [done] Wire thin `#[tauri::command]` wrappers in `src-tauri/src/commands.rs` and add a security test verifying no serialized response struct or JSON output from `AppController` ever contains raw password/private-key/passphrase strings — done when: `cargo test -p rusty-conduit-ssh-gui && cargo clippy --workspace --all-targets -- -D warnings` exits 0

## Verify
```sh
cargo test -p rusty-conduit-ssh-gui && cargo clippy --workspace --all-targets -- -D warnings
```

## Escalate when
- `tauri = "2"` fails to compile due to a missing system library or header on this Linux host → stop, set Status: needs-human — reason: exact missing library/header from `pkg-config` or linker

## Log
- (append-only, one line per event)
- sub-task 1: added src-tauri to the workspace with Cargo.toml, build.rs, tauri.conf.json, capabilities/default.json, generated 256x256 RGBA icon, and placeholder ui/dist/index.html
- sub-task 2: implemented AppController (open, vault create/unlock/lock, atomic config and known_hosts saves, KnownHostsChanged autosave)
- sub-task 3: implemented key-vault and write-only secret methods, including forced delete, password rotation, and encrypted backup export/import
- sub-task 4: implemented session, host, runtime, host-key, and prefix-by-prefix chain-test methods
- sub-task 5: wired 34 thin Tauri commands and added an IPC dispatch test covering all of them with secret-leak assertions
- note: tauri.conf.json identifier io.github.rusty-conduit-ssh-gui was not specified by the plan and needs planner confirmation because it sets the app data directory
- note: no code registers a keyring-core default store, so OS keyring create/unlock is expected to return KeyringUnavailable in the real app; keyring paths were tested with MemoryKeyringBackend only
- note: real window launch not run because this host session has no DISPLAY, WAYLAND_DISPLAY, or xvfb-run

## Evidence
- (append-only: command → observed result)
- pkg-config --modversion webkit2gtk-4.1 gtk+-3.0 libsoup-3.0 → 2.52.6, 3.24.52, 3.6.6 (no missing Tauri system library)
- cargo check -p rusty-conduit-ssh-gui → exit 0 (tauri 2.12.7); 3 unused-dependency manifest warnings for conduit-tray and the two plugins, which later phases wire
- cargo test -p rusty-conduit-ssh-gui --lib controller → 40 passed, 0 failed
- cargo test -p rusty-conduit-ssh-gui --lib keys → 14 passed, 0 failed
- cargo test -p rusty-conduit-ssh-gui --lib sessions → 14 passed, 0 failed
- cargo test -p rusty-conduit-ssh-gui && cargo clippy --workspace --all-targets -- -D warnings → exit 0, 43 passed, 0 failed
- cargo test -p rusty-conduit-ssh-gui --lib (5 repeats) → 43 passed each run
- cargo test --workspace → 257 passed, 0 failed
- git diff --stat -- crates docs → empty (Scope: Out untouched)
