# crates/conduit-tray

Sub-root: Cargo workspace member crate `conduit-tray`.

## Purpose
UI-agnostic system tray: the platform-neutral menu model (PROXIES and TUNNELS sections, vault lock state) and tray backends.

## Ownership
Owns everything under `crates/conduit-tray/`. Inherits all root DOX rules and adds the local rules below. The Windows/macOS Tauri backend and the bridge to the app live in `../../src-tauri` (`src/tray_tauri.rs`, `src/tray_bridge.rs`).

## Local Contracts
- Backends implement the `TrayBackend` trait; Linux uses the pure-Rust `ksni` backend (no GTK tray libraries). Windows and macOS plug in the Tauri adapter from `src-tauri`.
- A missing D-Bus bus or watcher is reported as offline and retried — never a panic.
- The menu model is built from runtime state only; it holds no secrets.

## Verification
- `cargo test -p conduit-tray` — `tests/ksni_headless.rs` must stay alone in its test binary because it changes a process-wide environment variable.

## Feature Map
- **Tray menu model** — builds the menu from Proxy, Tunnel, legacy session, and vault state. Start: `src/model.rs`.
- **Backend interface** — platform-neutral `TrayBackend` trait, mock backend, and tray image. Start: `src/backend.rs`. Files: `src/image.rs`, `src/lib.rs`.
- **Linux `ksni` tray** — D-Bus StatusNotifierItem backend on its own thread. Start: `src/linux_ksni.rs`. Files: `tests/ksni_headless.rs`.

## Child DOX Index
- (none)
