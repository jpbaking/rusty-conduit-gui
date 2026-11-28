# phase-0001 — Release and dev build profiles, Linux malloc arena cap

- Status: done
- Owner: executor
- Depends on: none
- Goal: Add an optimized `[profile.release]`, optimize dependencies in debug builds, and cap glibc malloc arenas at 2 at app start on Linux when `MALLOC_ARENA_MAX` is unset.
- Done when: every command in `## Verify` exits 0.
- Pattern to follow: `../rusty-conduit/src/main.rs` after that repo's phase-0001 of this goal (same `cap_malloc_arenas` function; copy it, changing only the call that follows it)

## Context
The workspace `Cargo.toml` has no `[profile.release]`, and `[profile.dev] opt-level = 0` also compiles the crypto crates unoptimized, so a 128 MiB Argon2id unlock is slow in debug builds. The planner chose the values below; do not pick others. `[profile.dev.package."*"]` applies only to dependencies, so workspace crates still compile fast.
glibc reads an explicit `MALLOC_ARENA_MAX` itself; only call `mallopt` when it is unset. `src-tauri` has no `libc` dependency yet; the workspace already declares `libc = "0.2"` (`Cargo.toml:47`), and `Cargo.lock` already contains `libc 0.2.191`, so adding the edge changes only the `rusty-conduit-gui` package's dependency list in `Cargo.lock`. The Linux branch is not compiled on macOS; the planner checks it in CI or a Linux container.
Escalation answered (planner, 2026-11-28): this Mac's Python has no PyYAML and nothing may be installed globally; run the release validator as `uv run -q --no-project --with pyyaml python3 scripts/validate-release-config.py` (ephemeral environment; CI installs PyYAML itself). The phase work was complete, so the planner re-ran ## Verify and closed the phase.

## Scope
- In: `Cargo.toml`, `src-tauri/Cargo.toml`, `src-tauri/src/main.rs`, `Cargo.lock` (only the added `"libc"` line under `name = "rusty-conduit-gui"`)
- Out: `crates/`, `src-tauri/src/lib.rs`, `src-tauri/ui/`, `.github/`, `docs/`

## Sub-tasks
1. [done] In `Cargo.toml`, replace the last three lines (`# Keep debug builds small and fast to compile.`, `[profile.dev]`, `opt-level = 0`) with exactly: (block 1 below) — done when: `grep -c '^\[profile' Cargo.toml` prints `3` and `cargo metadata --format-version 1 --no-deps >/dev/null` exits 0.
   Block 1:
   ```toml
   # Keep debug builds of the workspace crates fast to compile.
   [profile.dev]
   opt-level = 0

   # Optimize dependencies (argon2, chacha20poly1305, ring) in debug builds too, so a 128 MiB
   # Argon2id vault unlock takes about as long as in a release build.
   [profile.dev.package."*"]
   opt-level = 2

   # Thin LTO with one codegen unit inlines across the rusty-conduit-engine crate boundary;
   # stripped symbols keep the installers small.
   [profile.release]
   lto = "thin"
   codegen-units = 1
   strip = "symbols"
   ```
2. [done] In `src-tauri/Cargo.toml`, directly after the `[target.'cfg(not(target_os = "linux"))'.dependencies]` block (after its `tauri = ...` line and a blank line), add exactly: (block 1 below) then run `cargo build -p rusty-conduit-gui` once (without `--locked`) to record the edge — done when: `git diff --stat -- Cargo.lock` shows 1 insertion and 0 deletions, and that inserted line is `"libc",`.
   Block 1:
   ```toml
   # `mallopt` caps glibc malloc arenas at startup (see `src/main.rs`).
   [target.'cfg(all(target_os = "linux", target_env = "gnu"))'.dependencies]
   libc = { workspace = true }
   ```
3. [done] Replace `src-tauri/src/main.rs` with exactly: (block 1 below) — done when: `cargo build -p rusty-conduit-gui --locked` succeeds.
   Block 1:
   ```rust
   // Hide the console window on Windows release builds.
   #![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

   fn main() {
       cap_malloc_arenas();
       rusty_conduit_gui_lib::run();
   }

   /// glibc gives every worker thread its own malloc arena, which multiplies memory on hosts with
   /// many CPUs (about 8x per open connection); two arenas keep it low with no measurable
   /// throughput cost. glibc applies an explicit `MALLOC_ARENA_MAX` itself, so that one wins.
   #[cfg(all(target_os = "linux", target_env = "gnu"))]
   fn cap_malloc_arenas() {
       if std::env::var_os("MALLOC_ARENA_MAX").is_none() {
           // SAFETY: runs first in `main`, before any other thread exists; `mallopt` takes
           // integer arguments and touches no Rust-managed memory.
           unsafe {
               libc::mallopt(libc::M_ARENA_MAX, 2);
           }
       }
   }

   #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
   fn cap_malloc_arenas() {}
   ```

## Verify
```sh
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
python3 scripts/check-pure-rust-crypto.py
uv run -q --no-project --with pyyaml python3 scripts/validate-release-config.py
test "$(git diff --numstat bfcae88ea5e88f46691d34233e4eef963475e9b4 -- Cargo.lock | cut -f1-2)" = "$(printf '1\t0')"
git diff --exit-code -- crates src-tauri/src/lib.rs src-tauri/ui .github docs
```
- manual (planner): the Linux-only branch compiles — CI `Linux` jobs after the user pushes, or a Linux container if Docker is running.

## Escalate when
- `Cargo.lock` gains anything besides the one `"libc",` line → stop, set Status: needs-human — reason: paste `git diff -- Cargo.lock`.
- `validate-release-config.py` fails → stop, set Status: needs-human — reason: paste its output (it may check `Cargo.toml` shape).
- clippy reports a lint on the new code → stop, set Status: needs-human — reason: paste the lint; do not add `#[allow]`.

## Log
- (append-only, one line per event)
- sub-task 1: updated `Cargo.toml` with `[profile.dev]`, `[profile.dev.package."*"]`, and `[profile.release]`
- sub-task 2: added Linux/glibc `libc` dependency to `src-tauri/Cargo.toml` and updated `Cargo.lock`
- sub-task 3: replaced `src-tauri/src/main.rs` with `cap_malloc_arenas()` implementation
- verify: clippy, workspace tests, `check-pure-rust-crypto.py`, `Cargo.lock` numstat, and out-of-scope diff all passed, but `python3 scripts/validate-release-config.py` failed due to missing PyYAML; escalated per `## Escalate when`

- planner answered the PyYAML escalation (uv ephemeral env), re-ran ## Verify, closed phase-0001
- planner: Linux compile of the glibc branch deferred to the CI `Linux` job (needs WebKitGTK toolchain); the function is byte-identical to rusty-conduit's Linux-verified copy

## Evidence
- (append-only: command → observed result)
- `grep -c '^\[profile' Cargo.toml && cargo metadata --format-version 1 --no-deps >/dev/null` → `3`, exit 0
- `cargo build -p rusty-conduit-gui && git diff --stat -- Cargo.lock` → build finished in 50.78s; `Cargo.lock | 1 +` (1 insertion, 0 deletions; inserted line is `"libc",`)
- `cargo build -p rusty-conduit-gui --locked` → finished in 0.71s, exit 0
- `cargo clippy --workspace --all-targets --locked -- -D warnings` → exit 0
- `cargo test --workspace --locked` → all tests passed (including 176 gui unit tests + 6 secret_leak_scan tests), exit 0
- `python3 scripts/check-pure-rust-crypto.py` → `PURE_RUST_CRYPTO_OK`, exit 0
- `python3 scripts/validate-release-config.py` → exit 1: `release config error: PyYAML is required to validate workflows: pip install pyyaml` (also checked `/opt/homebrew/bin/python3`, same error)
- `test "$(git diff --numstat bfcae88ea5e88f46691d34233e4eef963475e9b4 -- Cargo.lock | cut -f1-2)" = "$(printf '1\t0')"` → exit 0
- `git diff --exit-code -- crates src-tauri/src/lib.rs src-tauri/ui .github docs` → exit 0
- planner: `uv run -q --no-project --with pyyaml python3 scripts/validate-release-config.py` → RELEASE_CONFIG_OK
- planner: clippy --workspace --all-targets → exit 0; `cargo test --workspace --locked` → 669 passed, 0 failed; PURE_RUST_CRYPTO_OK; `git diff --numstat bfcae88 -- Cargo.lock` → `1 0`; `git diff --exit-code bfcae88 -- crates src-tauri/src/lib.rs src-tauri/ui .github docs` → exit 0; `cap_malloc_arenas` identical to ../rusty-conduit/src/main.rs
