# phase-0001 — conduit-tray trait, menu model & pure-Rust Linux ksni backend

- Status: done
- Owner: executor
- Depends on: none
- Goal: Implement `crates/conduit-tray` with the UI-agnostic `TrayBackend` trait, menu state model (`TrayMenuModel` built from `SessionSnapshot` + vault lock status), pure-Rust Linux `ksni` D-Bus SNI backend with watcher online/offline status, and unit tests.
- Done when: `cargo test -p conduit-tray && cargo clippy --workspace --all-targets -- -D warnings` exits 0 with unit tests verifying menu construction, `socks5h://` URL formatting, vault-locked state, tray action dispatch, and no-tray-host fallback state.
- Pattern to follow: `docs/MASTER-PLAN.md` Sections 4.2 and 8.1

## Context
`conduit-tray` abstracts system tray operations across platforms so Linux uses pure-Rust D-Bus `StatusNotifierItem` (`ksni` — zero GTK3 / `libappindicator` dependency) while Windows/macOS will plug in Tauri v2's `tray-icon` adapter in `src-tauri/`.
Key decisions already made:
- Menu-first tray: never hide a required action behind left-click; every action lives in the tray menu.
- Always format SOCKS proxy URLs as `socks5h://` (never `socks5://`) so DNS resolution stays remote.
- Menu layout follows `docs/MASTER-PLAN.md` Section 8.1: summary header (`N connected · M needs attention`), per-session entries (`●`/`◐`/`!`/`○`) with Stop/Restart/Start, Copy HTTP Proxy URL, Copy SOCKS Proxy URL (`socks5h://`), View Logs; then `Start All`, `Stop All`, conditional `Unlock Vault…` (only when locked), `Open Manage Window…`, and `Quit`.
- Expose `TrayHostStatus` (`Online`, `Offline`, `Waiting`) so `src-tauri/` can implement the 10-second login wait + no-tray-host fallback banner cleanly.

## Scope
- In: `Cargo.toml`, `Cargo.lock`, `crates/conduit-tray/**`
- Out: `crates/conduit-core/**`, `crates/conduit-vault/**`, `crates/conduit-ssh/**`, `crates/conduit-runtime/**`, `docs/MASTER-PLAN.md`

## Sub-tasks
1. [done] Add `crates/conduit-tray` to root `Cargo.toml` workspace members and create `crates/conduit-tray/Cargo.toml` (depending on `conduit-core`, `conduit-runtime`, `tokio`, `thiserror`, `uuid`, and on `#[cfg(target_os = "linux")]` `ksni = "0.3"`) — done when: `cargo check -p conduit-tray` exits 0
2. [done] Implement `crates/conduit-tray/src/model.rs` defining `TrayAction` (Start/Stop/Restart session, CopyHttpUrl, CopySocksUrl, ViewLogs, StartAll, StopAll, UnlockVault, OpenManageWindow, Quit), `TrayIconState` (Idle, Connected, Reconnecting, Attention, Locked), `TrayHostStatus`, and `TrayMenuModel::from_snapshots(snapshots, vault_locked)` formatting `http://...` and `socks5h://...` URLs accurately — done when: `cargo test -p conduit-tray model` exits 0
3. [done] Implement `crates/conduit-tray/src/backend.rs` defining the `TrayBackend` trait (`update(&self, model: TrayMenuModel)`, `host_status(&self) -> TrayHostStatus`, `subscribe_actions(&self)`, `shutdown(self)`) plus a `MockTrayBackend` for deterministic tests — done when: `cargo test -p conduit-tray backend` exits 0
4. [done] Implement `crates/conduit-tray/src/linux_ksni.rs` (`#[cfg(target_os = "linux")]`) implementing `ksni::Tray` and `KsniTrayBackend` wrapping `ksni::TrayService` / `ksni::blocking::TrayMethods` (or async handle), translating `TrayMenuModel` into `ksni::MenuItem` trees, dispatching `TrayAction`s over an `mpsc` channel, and tracking `TrayHostStatus` gracefully when D-Bus or `StatusNotifierWatcher` is absent (never panicking in headless/no-DBus environments) — done when: `cargo test -p conduit-tray` exits 0
5. [done] Fix-up: replace the `&[s.clone()]` test argument in `crates/conduit-tray/src/model.rs` that fails `clippy::cloned_ref_to_slice_refs` — done when: the `## Verify` command exits 0

## Verify
```sh
cargo test -p conduit-tray && cargo clippy --workspace --all-targets -- -D warnings
```

## Escalate when
- `ksni = "0.3"` pulls GTK or C system libraries (`libappindicator`) or fails to compile on this Linux host → stop, set Status: needs-human — reason: exact `ksni` feature/dependency issue

## Log
- (append-only, one line per event)
- sub-task 1: added crates/conduit-tray to the workspace with its manifest and ksni 0.3 on Linux
- sub-task 2: implemented TrayAction, TrayIconState, TrayHostStatus, and TrayMenuModel::from_snapshots, including multiplexed listeners and wildcard-to-loopback URLs
- sub-task 3: implemented TrayBackend, TrayError, and MockTrayBackend
- sub-task 4: implemented KsniTrayBackend on a dedicated worker thread with retry, watcher tracking, and a no-D-Bus integration test
- sub-task 5 (fix-up): first Verify failed on one clippy error in a test; replaced the clone with std::slice::from_ref

## Evidence
- (append-only: command → observed result)
- `cargo check -p conduit-tray` → exit 0; ksni 0.3.7 resolved
- `cargo tree -p ksni -e normal` filtered for -sys/gtk/gdk/glib/appindicator/dbus/cairo/pango → only linux-raw-sys (pure-Rust bindings), so the GTK escalation condition did not occur
- `cargo test -p conduit-tray model` → 10 passed, 0 failed
- `cargo test -p conduit-tray backend` → 5 passed, 0 failed
- `cargo test -p conduit-tray` → 20 unit + 1 integration passed, 0 failed
- first Verify → exit 101: clippy `unnecessary use of clone to create a slice from a reference` at crates/conduit-tray/src/model.rs:464
- `cargo test -p conduit-tray && cargo clippy --workspace --all-targets -- -D warnings` → exit 0 (20 unit + 1 integration passed, clippy clean)
- `dbus-run-session` with throwaway probe and fake StatusNotifierWatcher (not committed) → Offline, then Online when watcher appeared, full menu read via dbusmenu GetLayout including socks5h:// URL, Offline when watcher left, clean shutdown (exit 0)
- not tested: a real desktop panel (XFCE, KDE, Waybar) rendering the icon
