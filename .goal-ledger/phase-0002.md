# phase-0002 — Update conduit-tray and src-tauri tray bridge for PROXIES (Mode submenu) and TUNNELS sections

- Status: done
- Owner: executor
- Depends on: phase-0001
- Goal: Upgrade `conduit-tray` (`model.rs`, `linux_ksni.rs`) and `src-tauri` (`tray_bridge.rs`, `tray_tauri.rs`) to render the §9.1 tray menu with **PROXIES** (Mode override submenu, Stop/Restart, Copy HTTP Proxy URL, Copy SOCKS Proxy URL `socks5h://`, View Logs) and **TUNNELS** (status, linked indicator, Start/Stop, Open Manage Window on attention).
- Done when: `conduit-tray` and `src-tauri` tray tests plus Linux `conduit_check_tauri_tray` compile check pass with zero warnings.
- Pattern to follow: `crates/conduit-tray/src/model.rs:1-220`, `crates/conduit-tray/src/linux_ksni.rs:1-160`, `src-tauri/src/tray_bridge.rs:1-200`, `src-tauri/src/tray_tauri.rs:1-149`, `docs/MASTER-PLAN.md:270-294`

## Context
- Disk constraint: ALWAYS pass `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true` on every `cargo` command.
- Follow `docs/MASTER-PLAN.md` §9.1 tray layout:
  - Header summary: `Rusty Conduit GUI` + live counts (e.g. `2 proxies running · 1 tunnel needs attention`).
  - **PROXIES** section: each Proxy shows status indicator, name, active mode (`Auto Switch` or `Override: <profile>`), and bound ports; submenu includes:
    - `Mode ▸` submenu with `✓ Auto Switch (N rules)`, `Force Direct`, and `Force <profile>` for each non-builtin profile (selecting emits `TrayAction::SetProxyOverride { id, profile: Option<String> }`).
    - `Start` / `Stop` / `Restart` (`TrayAction::StartProxy`, `StopProxy`, `RestartProxy`).
    - `Copy HTTP Proxy URL` (`http://<addr>`) and `Copy SOCKS Proxy URL` (`socks5h://<addr>` — ALWAYS `socks5h://`, NEVER `socks5://`).
    - `View Logs` (`TrayAction::ViewProxyLogs(id)`).
  - **TUNNELS** section: each Tunnel shows status indicator, name, state (including `(linked to <proxy>)` when Linked and referenced, or `Needs attention → Open Manage Window`), and Start/Stop/Restart/View Logs actions (`TrayAction::StartTunnel`, `StopTunnel`, `RestartTunnel`, `ViewTunnelLogs`).
  - Bottom global actions: `Start All`, `Stop All`, `Unlock Vault…` (only when locked), `Open Manage Window…`, `Quit`.
- Keep `linux_ksni.rs` (ksni on Linux) and `tray_tauri.rs` (Tauri tray on Windows/macOS, compiled on Linux via `--cfg conduit_check_tauri_tray`) both supporting the nested `Mode ▸` submenu cleanly.
- Wire `src-tauri/src/tray_bridge.rs` to subscribe to `ProxyEvent` and `TunnelEvent` from `AppController` and route every `TrayAction` to `AppController`. Ensure tray `StartAll`, `StopAll`, and `Quit` invoke `start_all_v2()` / `stop_all_v2()` (in addition to legacy `start_all()` / `stop_all()` if still present) so running Proxies and Tunnels are properly stopped on Quit.

## Scope
- In: `crates/conduit-tray/src/model.rs`, `crates/conduit-tray/src/linux_ksni.rs`, `crates/conduit-tray/src/lib.rs`, `crates/conduit-tray/src/backend.rs`, `src-tauri/src/tray_bridge.rs`, `src-tauri/src/tray_tauri.rs`
- Out: `crates/conduit-core/`, `crates/conduit-runtime/`, `crates/conduit-vault/`, `src-tauri/src/controller*`, `src-tauri/src/commands.rs`, `src-tauri/ui/`

## Sub-tasks
1. [done] Update `crates/conduit-tray/src/model.rs` (and `lib.rs` / `backend.rs`) with `ProxyTrayItem`, `TunnelTrayItem`, `TrayState` containing `proxies` + `tunnels`, nested `Mode ▸` submenu support in `MenuItem`, `TrayAction` variants for Proxies/Tunnels/Mode overrides, and unit tests verifying `socks5h://` URLs, Mode checkmarks, and linked/attention labels — done when: `cargo test -p conduit-tray` passes.
2. [done] Update `crates/conduit-tray/src/linux_ksni.rs` and `src-tauri/src/tray_tauri.rs` to render nested submenus (`Mode ▸` inside a Proxy submenu) cleanly — done when: both `conduit-tray` and `RUSTFLAGS="--cfg conduit_check_tauri_tray" cargo check -p rusty-conduit-gui --tests --features tauri/tray-icon` compile with zero warnings.
3. [done] Update `src-tauri/src/tray_bridge.rs` to build `TrayState` from `AppController`'s Proxies & Tunnels, subscribe to `ProxyEvent`/`TunnelEvent`, and route all `TrayAction`s, updating its unit tests — done when: `cargo test -p rusty-conduit-gui --lib tray_bridge` passes.
4. [done] Run `## Verify` and record observed results in `## Evidence` — done when: `## Verify` exits 0.

## Verify
```sh
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p conduit-tray -p rusty-conduit-gui --lib && CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true RUSTFLAGS="--cfg conduit_check_tauri_tray" cargo check -p rusty-conduit-gui --tests --features tauri/tray-icon && CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo clippy -p conduit-tray -p rusty-conduit-gui --all-targets -- -D warnings
```

## Escalate when
- `ksni` or `tauri::menu::Submenu` has a platform constraint preventing two-level nested submenus → stop, set Status: needs-human — reason: describe the exact menu API constraint

## Log
- (append-only, one line per event)
- sub-task 1: added ProxyTrayItem/TunnelTrayItem/TrayState, TrayMenuEntry/TraySubmenu (nested Mode submenu), Proxy/Tunnel/override TrayActions, TrayMenuModel::from_state with PROXIES/TUNNELS entries; kept from_snapshots for legacy v1 sessions; 6 new model tests
- sub-task 2: ksni `build_menu` and Tauri `MenuBuild` render PROXIES/TUNNELS section labels and recurse into `TrayMenuEntry::Submenu` so `Mode` nests inside each Proxy submenu; added `ksni_menu_nests_mode_submenu_inside_proxy`; first Tauri-cfg check failed only on the non-exhaustive `TrayAction` match in tray_bridge.rs (sub-task 3's file), rechecked after sub-task 3
- sub-task 3: tray_bridge builds `TrayState` from `list_proxies`/`list_tunnels` (sorted, linked_to = running referencing Proxies), selects on `subscribe_proxy_events`/`subscribe_tunnel_events`, routes all new TrayActions; StartAll runs `start_all` + `start_all_v2`, StopAll and `quit_app` run `stop_all_v2` + `stop_all`; Proxy/Tunnel View Logs reuse `UiEvent::ViewLogs { session_id: <uuid> }` (window.rs is outside Scope: In); 5 new bridge tests
- sub-task 4: ran `## Verify`; passed first try, no fix-ups

## Evidence
- (append-only: command → observed result)
- `cargo test -p conduit-tray` (low-disk env) → `test result: ok. 29 passed; 0 failed` (lib) + `1 passed` (integration), no warnings
- `RUSTFLAGS="--cfg conduit_check_tauri_tray" cargo check -p rusty-conduit-gui --tests --features tauri/tray-icon` (before sub-task 3) → `error[E0004]: non-exhaustive patterns: TrayAction::StartProxy(_)… --> src-tauri/src/tray_bridge.rs:103:11` only
- `cargo test -p conduit-tray` (after sub-task 2) → `test result: ok. 30 passed; 0 failed` + `1 passed`
- `cargo test -p rusty-conduit-gui --lib tray_bridge` → `test result: ok. 15 passed; 0 failed; 145 filtered out`
- `RUSTFLAGS="--cfg conduit_check_tauri_tray" cargo check -p rusty-conduit-gui --tests --features tauri/tray-icon` (after sub-task 3) → `Finished`, exit 0, no warnings
- `## Verify` block (full, from project root) → exit 0: conduit-tray `30 passed; 0 failed`, rusty-conduit-gui lib `160 passed; 0 failed`, Tauri-cfg check `Finished`, `cargo clippy -p conduit-tray -p rusty-conduit-gui --all-targets -- -D warnings` `Finished` with no warnings
