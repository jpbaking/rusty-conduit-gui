# phase-0001 — OS sleep/wake hooks & runtime wake wiring

- Status: done
- Owner: executor
- Depends on: none
- Goal: Implement cross-platform OS sleep/wake listeners in `conduit-runtime` and wire them to `SessionManager::notify_system_wake` from `src-tauri`.
- Done when: `cargo test -p conduit-runtime -p rusty-conduit-ssh-gui && cargo clippy -p conduit-runtime -p rusty-conduit-ssh-gui --all-targets -- -D warnings && python3 scripts/check-pure-rust-crypto.py` exits 0 with unit tests verifying wake event handling and graceful fallback.
- Pattern to follow: `crates/conduit-runtime/src/hardening.rs:1` (platform-gated OS hooks with clean fallback) and `crates/conduit-runtime/src/manager.rs:362-380` (`SessionManager::notify_system_wake`).

## Context
`docs/MASTER-PLAN.md` §6.2 specifies subscribing to OS wake events (`logind` `PrepareForSleep(false)` on Linux, `PBT_APMRESUMEAUTOMATIC` on Windows, `NSWorkspace.didWakeNotification` on macOS) and triggering debounced session recycling via `SessionManager::notify_system_wake()`. `notify_system_wake()` is already implemented and tested in `crates/conduit-runtime/src/manager.rs`, but nothing currently listens for OS wake events or calls it.
`zbus = "5"` is already in `Cargo.lock` (pure Rust D-Bus, no OpenSSL/aws-lc). `windows-sys` and `objc2`/`block2` are also already in `Cargo.lock`. Make sure `scripts/check-pure-rust-crypto.py` still passes (no `openssl-sys`, `native-tls`, or `aws-lc-sys`).
The wake listener must be best-effort and non-fatal: if D-Bus/logind or the OS API is unavailable (e.g. containers, headless CI), log once or return cleanly without panicking or failing app startup.

## Scope
- In: `crates/conduit-runtime/Cargo.toml`, `crates/conduit-runtime/src/lib.rs`, `crates/conduit-runtime/src/wake.rs`, `src-tauri/src/controller.rs`, `src-tauri/src/lib.rs`, `Cargo.lock`
- Out: `docs/MASTER-PLAN.md`, `../rusty-conduit-ssh`, `src-tauri/ui/**`, `crates/conduit-core/**`, `crates/conduit-ssh/**`, `crates/conduit-openssh/**`

## Sub-tasks
1. [done] Add `crates/conduit-runtime/src/wake.rs` and export `spawn_wake_listener` (or `WakeGuard` / `spawn_wake_listener(on_wake: Arc<dyn Fn() + Send + Sync>) -> WakeHandle`) from `crates/conduit-runtime/src/lib.rs`. On Linux (`#[cfg(target_os = "linux")]`), subscribe via `zbus` (system bus, `org.freedesktop.login1`, `/org/freedesktop/login1`, `org.freedesktop.login1.Manager`, `PrepareForSleep(bool)`) and invoke `on_wake()` only when `going_to_sleep == false`, with a clean helper `is_wake_signal(going_to_sleep: bool) -> bool` and graceful shutdown/no-op if the system bus or `login1` is unreachable. On Windows (`#[cfg(target_os = "windows")]`), implement a hidden message-only window (`HWND_MESSAGE`) thread handling `WM_POWERBROADCAST` when `wParam == PBT_APMRESUMEAUTOMATIC` (0x0012). On macOS (`#[cfg(target_os = "macos")]`), register for `NSWorkspaceDidWakeNotification` via `objc2` / `block2` (or `objc2-app-kit` only if already in `Cargo.lock`; if macOS AppKit bindings are not in `Cargo.lock`, check `Cargo.lock` and use `objc2` raw message send so no heavy/non-pure-Rust crates are pulled in). On other targets, provide a no-op stub. Add unit tests in `wake.rs` covering `is_wake_signal`, handle drop/cancellation, and graceful behavior when no D-Bus system bus is present. — done when: `cargo test -p conduit-runtime wake` passes and `python3 scripts/check-pure-rust-crypto.py` exits 0.
2. [done] Expose `pub fn notify_system_wake(&self)` on `AppController` in `src-tauri/src/controller.rs` delegating to `self.manager.notify_system_wake()`, and spawn the wake listener during Tauri setup in `src-tauri/src/lib.rs` (keeping its handle alive for the lifetime of the app via `app.manage(...)` or a spawned task). Add a unit test in `src-tauri/src/controller.rs` verifying `controller.notify_system_wake()` is callable without error. — done when: `cargo test -p rusty-conduit-ssh-gui` passes.
3. [done] Run full phase verification (`cargo test`, `cargo clippy`, `check-pure-rust-crypto.py`). — done when: all commands in `## Verify` exit 0.

## Verify
```sh
cargo test -p conduit-runtime -p rusty-conduit-ssh-gui && cargo clippy -p conduit-runtime -p rusty-conduit-ssh-gui --all-targets -- -D warnings && python3 scripts/check-pure-rust-crypto.py
```

## Escalate when
- Adding a platform crate (`zbus`, `windows-sys`, `objc2`) breaks `scripts/check-pure-rust-crypto.py` or requires network access that is unavailable → stop, set Status: needs-human — reason: <exact cargo/crypto error>
- Existing runtime or controller tests fail for reasons outside this phase's scope → stop, set Status: needs-human — reason: <failing test and output>

## Log
- (append-only, one line per event)
- sub-task 1: added crates/conduit-runtime/src/wake.rs (spawn_wake_listener/WakeHandle/WakeCallback, is_wake_signal, is_windows_resume; Linux zbus logind PrepareForSleep on own thread+current-thread runtime; Windows HWND_MESSAGE window + RegisterSuspendResumeNotification handling WM_POWERBROADCAST/PBT_APMRESUMEAUTOMATIC; macOS NSWorkspaceDidWakeNotification via objc2-app-kit (already in Cargo.lock); no-op elsewhere), exported from lib.rs, target-gated deps in Cargo.toml; Cargo.lock gained only dependency edges, no new packages
- sub-task 2: added AppController::notify_system_wake delegating to the manager plus unit test; src-tauri/src/lib.rs setup spawns the wake listener and app.manage()s the WakeHandle; callback spawns onto tauri::async_runtime before calling notify_system_wake
- sub-task 3: ran full ## Verify, all exit 0

## Evidence
- (append-only: command → observed result)
- `cargo test -p conduit-runtime wake` → 9 passed (5 new wake::tests incl. missing_system_bus_stops_quietly, real_listener_starts_and_stops_without_panicking, plus 3 manager wake tests); exit 0
- `python3 scripts/check-pure-rust-crypto.py` → PURE_RUST_CRYPTO_OK; exit 0
- `cargo test -p rusty-conduit-ssh-gui` → 104 passed + 5 passed, incl. controller::tests::notify_system_wake_is_callable_without_sessions; exit 0
- `cargo test -p conduit-runtime -p rusty-conduit-ssh-gui && cargo clippy -p conduit-runtime -p rusty-conduit-ssh-gui --all-targets -- -D warnings && python3 scripts/check-pure-rust-crypto.py` → all test results ok (56, 8, 8, 104, 5 passed), clippy no warnings, PURE_RUST_CRYPTO_OK; exit 0
- note: Windows and macOS code paths were not compiled (only x86_64-unknown-linux-gnu target installed); API signatures checked against cached windows-sys 0.61.2 / objc2-foundation 0.3.2 / objc2-app-kit 0.3.2 sources
