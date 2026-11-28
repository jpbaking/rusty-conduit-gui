# phase-0005 — conduit-openssh: Linux-only parent thread and stale runtime directory sweep

- Status: done
- Owner: planner
- Depends on: phase-0004
- Goal: Spawn `ssh` from a dedicated `conduit-ssh-parent` thread only on Linux, where `PR_SET_PDEATHSIG` needs it, and remove the `rc-*` runtime directories a crashed app left behind, once at app startup.
- Done when: every command in `## Verify` exits 0, including a sweep test that removes a stale `rc-<8 hex>` directory and keeps a non-matching one.
- Pattern to follow: `crates/conduit-openssh/src/supervisor.rs:234-258` (`spawn_guarded`), `crates/conduit-openssh/src/runtime_dir.rs:28-52` (`RuntimeDir::create_in`, the `rc-<hex>` naming)

## Context
B-03 (GUI part): `spawn_guarded` creates an idle OS thread per session on every platform, but only Linux needs it (the parent-death signal fires when the spawning thread exits). macOS uses the `conduit-worker` parent watcher and Windows a Job Object, both already in `crates/conduit-openssh/src/orphan.rs`. On non-Linux targets, spawn directly inside the runtime and return a keep-alive sender whose receiver is already dropped, so callers stay unchanged.
A crash (`SIGKILL`, power loss) skips `RuntimeDir`'s `Drop`, leaving `rc-<hex>` directories (askpass sockets, agent sockets, known_hosts) under the runtime base. Decision: add `pub fn sweep_stale_runtime_dirs() -> io::Result<usize>` (with a testable `sweep_in(base)`) that removes entries named exactly `rc-` + 8 lowercase hex characters that are directories owned by the current user (Unix: `metadata.uid() == getuid()`); call it once from app startup after the single-instance guard and before any Tunnel starts, logging the count at debug level. The single-instance plugin guarantees no other app instance owns those directories.
Amendment (planner, 2026-11-28, before starting): on macOS the base is the shared `/tmp`, where another program could own a same-named `rc-<hex>` directory. `RuntimeDir::create_in` therefore writes an empty marker file `.rusty-conduit-runtime` (owner-only) inside each new directory, and the sweep removes only matching directories that contain that marker. Directories left by a crash before this change lack the marker and are kept (safe failure).
Deferred by plan: owner-only DACLs on the Windows agent pipes (`agent_server.rs:149-153`); the `socks_port == 0` path (unreachable).

## Scope
- In: `crates/conduit-openssh/src/supervisor.rs` (`spawn_guarded` only), `crates/conduit-openssh/src/runtime_dir.rs`, `crates/conduit-openssh/src/lib.rs` (re-export only), the one `src-tauri/src/` startup site that calls the sweep, `crates/conduit-openssh/DOX.md`
- Out: `crates/conduit-openssh/src/orphan.rs`, `agent_server.rs`, `askpass.rs`, `crates/conduit-runtime/`, `src-tauri/ui/`

## Sub-tasks
1. [done] `#[cfg(target_os = "linux")]` on the thread-based `spawn_guarded`; a `#[cfg(not(target_os = "linux"))]` variant that spawns directly and returns `(child, keep_tx)` with the receiver dropped; doc comments explain why — done when: `cargo clippy -p conduit-openssh --all-targets --locked -- -D warnings` passes and `grep -n 'conduit-ssh-parent' crates/conduit-openssh/src/supervisor.rs` sits inside the Linux-only function.
2. [done] Marker file in `RuntimeDir::create_in`, and `sweep_in(base)` / `sweep_stale_runtime_dirs()` in `runtime_dir.rs` as decided, with tests on a temp base: a stale `rc-0a1b2c3d` directory with the marker is removed; `rc-0a1b2c3e` without the marker, `rc-xyz`, `rc-0a1b2c3d0`, a plain file named `rc-01234567`, and `other` are kept; a `RuntimeDir` created in the base contains the marker — done when: `cargo test -p conduit-openssh --locked runtime_dir` passes.
3. [done] Call the sweep once at startup in `src-tauri/src/` (find the site with `grep -n 'single_instance\|fn run' src-tauri/src/lib.rs`) and log the count at debug level; a failure is logged and ignored — done when: `cargo test -p rusty-conduit-gui --locked` passes.
4. [done] DOX pass: `crates/conduit-openssh/DOX.md` notes the Linux-only parent thread and the startup sweep — done when: `grep -c 'sweep' crates/conduit-openssh/DOX.md` prints at least `1`.

## Verify
```sh
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
git diff --exit-code -- crates/conduit-openssh/src/orphan.rs crates/conduit-openssh/src/agent_server.rs crates/conduit-runtime src-tauri/ui
```
- manual (planner): the Linux build compiles the thread path — CI after push, or a Linux container if Docker is running.

## Escalate when
- The app has no single-instance guard on some platform → stop, set Status: needs-human — reason: the sweep could delete a live instance's directory.
- A Tunnel test fails on macOS after the direct-spawn change → stop, set Status: needs-human — reason: paste the failure.

## Log
- (append-only, one line per event)
- planner amended Context and sub-task 2 before starting: marker-file guard so the sweep cannot delete a same-named directory another program owns in the shared macOS `/tmp`
- planner begins phase-0005 (planner-owned)
- sub-task 1: thread-based `spawn_guarded` is `#[cfg(target_os = "linux")]`; non-Linux variant spawns directly and returns a sender whose receiver is dropped
- sub-task 2: `RUNTIME_MARKER` written by `create_in` (Drop removes the dir if that fails); `sweep_in` / `sweep_stale_runtime_dirs` match `rc-<8 lowercase hex>`, real dir (symlink_metadata), owner uid, marker file; tests `runtime_dir_sweep_removes_only_marked_stale_dirs`, `runtime_dir_holds_the_sweep_marker` (an uppercase-name case was dropped: macOS filesystems are case-insensitive)
- sub-task 3: sweep called in `src-tauri/src/lib.rs` setup just before `AppController::open`; the app has no log levels (eprintln only), so it prints only when something was removed or the sweep failed
- sub-task 4: conduit-openssh DOX Local Contracts describe the Linux-only parent thread and the marker-guarded startup sweep
- rustfmt: the crate had 4 pre-existing rustfmt diffs (lib.rs, supervisor.rs imports); the new code adds none
- phase-0005 verified and closed

## Evidence
- (append-only: command → observed result)
- `cargo test -p conduit-openssh --locked runtime_dir` → 7 passed + `runtime_dir_is_removed_and_ssh_stops_on_drop` passed
- `grep -n 'conduit-ssh-parent' crates/conduit-openssh/src/supervisor.rs` → line 244, inside the `#[cfg(target_os = "linux")]` fn at 238
- `grep -c 'sweep' crates/conduit-openssh/DOX.md` → 1
- `cargo clippy --workspace --all-targets --locked -- -D warnings` → exit 0; `cargo test --workspace --locked` → 680 passed, 0 failed; `git diff --exit-code -- crates/conduit-openssh/src/orphan.rs crates/conduit-openssh/src/agent_server.rs crates/conduit-runtime src-tauri/ui` → exit 0
- manual Linux: rust:1-bookworm `cargo clippy -p conduit-openssh --all-targets --locked -- -D warnings && cargo test -p conduit-openssh --locked` → exit 0 (59 unit + 6 integration passed)
