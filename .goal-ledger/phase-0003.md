# phase-0003 — src-tauri desktop lifecycle, tray wiring, autostart & platform rules

- Status: done
- Owner: executor
- Depends on: phase-0001, phase-0002
- Goal: Complete `src-tauri/` desktop application wiring: destroy-webview-on-close & recreate-on-demand, `conduit-tray` integration (Linux `ksni` + Windows/macOS Tauri tray), `tauri-plugin-single-instance`, `tauri-plugin-autostart` (`--tray` + `$APPIMAGE`), macOS `Accessory`/`Regular` Dock policy, NVIDIA WebKitGTK env mitigation, no-tray-host fallback, and Wayland clipboard fallback.
- Done when: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings` exits 0 with unit tests covering CLI flag parsing (`--tray`, `--show`, `--safe-rendering`), NVIDIA/WebKitGTK env mitigation & child-env stripping, autostart command resolution (including `$APPIMAGE`), tray action dispatch, and no-tray-host fallback state.
- Pattern to follow: `docs/MASTER-PLAN.md` Sections 4.1, 4.2, and 6.1

## Context
The Manage Window must never keep WebKitGTK / WebView2 / WKWebView helper processes alive in the background when closed: closing the Manage Window destroys the webview completely, while tunnels and tray stay running in Rust. Re-opening from the tray or launching a second instance (`--show`) recreates the window on demand.
Key decisions already made:
- CLI flags: `--tray` (start minimized to tray), `--show` (open/focus Manage Window), `--safe-rendering` (sets `WEBKIT_DISABLE_COMPOSITING_MODE=1` before GTK init).
- NVIDIA + WebKitGTK mitigation (Linux only): detect NVIDIA (e.g., `/proc/driver/nvidia/version` or `/sys/module/nvidia`), apply `WEBKIT_DISABLE_DMABUF_RENDERER=1` before GTK init if not already set, and strip those WebKit env vars from any child/worker processes.
- Linux no-tray-host fallback: wait up to 10s for `StatusNotifierWatcher`; if `TrayHostStatus::Offline`, open the Manage Window with `tray_available: false` so the UI shows the dismissible info banner and asks Keep running in background vs. Quit on close.
- Wayland clipboard fallback: if copying a proxy URL from a windowless tray menu fails on Linux/Wayland, open the Manage Window with a `clipboard-fallback` event carrying the URL pre-selected.
- macOS: `ActivationPolicy::Accessory` when no window is open, `ActivationPolicy::Regular` while the Manage Window is open.
- Call `conduit_runtime::disable_core_dumps()` at startup.

## Scope
- In: `src-tauri/src/**`, `src-tauri/Cargo.toml`, `Cargo.lock`
- Out: `crates/conduit-core/**`, `crates/conduit-vault/**`, `crates/conduit-ssh/**`, `crates/conduit-runtime/**`, `src-tauri/ui/**`, `docs/MASTER-PLAN.md`

## Sub-tasks
1. [done] Implement `src-tauri/src/platform.rs` covering: CLI flag parsing (`--tray`, `--show`, `--safe-rendering`), Linux NVIDIA detection & pre-GTK WebKitGTK env mitigation + child-env sanitization helper, AppImage `$APPIMAGE` autostart executable path resolution, and process hardening (`disable_core_dumps`) — done when: `cargo test -p rusty-conduit-ssh-gui platform` exits 0
2. [done] Implement `src-tauri/src/window.rs` managing on-demand Manage Window creation (`open_or_focus_manage_window`), destroy-webview-on-close (`on_window_event(CloseRequested)`), macOS `ActivationPolicy::Accessory`/`Regular` switching (`#[cfg(target_os = "macos")]`), and `tray_available` / `clipboard-fallback` event payloads — done when: `cargo check -p rusty-conduit-ssh-gui` exits 0
3. [done] Implement `src-tauri/src/tray_bridge.rs` bridging `AppController` + `RuntimeEvent`s to `conduit_tray::TrayBackend` (`KsniTrayBackend` on Linux; Tauri `tray-icon` adapter on Windows/macOS), handling all `TrayAction`s (start/stop/restart, copy HTTP/`socks5h://` URL with Wayland fallback, view logs, start/stop all, unlock vault, open Manage Window, quit), and implementing the 10-second watcher-online wait + automatic late-panel registration — done when: `cargo test -p rusty-conduit-ssh-gui tray_bridge` exits 0
4. [done] Wire `src-tauri/src/lib.rs` and `src-tauri/src/main.rs` integrating `tauri-plugin-single-instance` (second launch / `--show` opens Manage Window), `tauri-plugin-autostart` (`--tray` + autostart get/set IPC commands), `RuntimeEvent` forwarding to open webviews, and staggered autostart on startup — done when: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings` exits 0

## Verify
```sh
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings
```

## Escalate when
- `tauri-plugin-single-instance` or `tauri-plugin-autostart` v2 API conflicts with Tauri v2 features or requires an unsupported capability → stop, set Status: needs-human — reason: exact plugin version and API conflict

## Log
- (append-only, one line per event)
- sub-task 1: added platform.rs (CLI flags, NVIDIA/WebKitGTK env, child-env sanitizer, $APPIMAGE resolution, hardening)
- sub-task 2: added window.rs (on-demand window, destroy on close, macOS policy, queued UI events, close decision)
- sub-task 3: added tray_bridge.rs (all TrayActions, 10s host wait, late registration, clipboard fallback) and tray_tauri.rs (Windows/macOS adapter); added arboard for clipboard access
- sub-task 4: wired lib.rs with single-instance, autostart, runtime event forwarding, staggered autostart; added get_autostart, set_autostart, shell_ready, resolve_close IPC commands
- not run: real window launch (no headless display available) and Windows/macOS target builds (targets not installed)

## Evidence
- (append-only: command → observed result)
- `cargo test -p rusty-conduit-ssh-gui platform` → 12 passed, 0 failed
- `cargo check -p rusty-conduit-ssh-gui` → Finished dev profile, exit 0 (window tests: 8 passed)
- `cargo test -p rusty-conduit-ssh-gui tray_bridge` → 10 passed, 0 failed
- `cargo test --workspace` → exit 0, 286 passed, 0 failed (72 in the src-tauri lib)
- `cargo clippy --workspace --all-targets -- -D warnings` → exit 0
- scratch copy with tauri `tray-icon` and `--cfg conduit_check_tauri_tray`: `cargo clippy -p rusty-conduit-ssh-gui --lib -- -D warnings` → exit 0 (adapter compiled against Linux types only)
