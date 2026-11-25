# phase-0002 — Implement §3.3 one-time upgrade migration (data-dir, autostart, single-instance, banner)

- Status: done
- Owner: planner
- Depends on: phase-0001
- Goal: Implement `src-tauri/src/migration.rs` and wire it into startup and the Manage Window UI to migrate v0.1.0 `io.github.rusty-conduit-ssh-gui` data directories and login autostart entries, refuse startup if the old `Rusty Conduit (SSH)` is still running, log the migration, and display a one-time notice banner.
- Done when: Unit tests for fresh install, same-volume upgrade, cross-volume copy-verify-remove, non-empty new dir (no merge + notice), autostart migration, and old-app-running guard all pass, and frontend checks/tests/build pass.
- Pattern to follow: `src-tauri/src/window.rs:20-62` and `src-tauri/ui/src/lib/components/App.svelte:47-58`

## Context
Changing the bundle identifier from `io.github.rusty-conduit-ssh-gui` to `io.github.rusty-conduit-gui` moves Tauri's `app_data_dir()`. Per MASTER-PLAN §3.3, before `AppController::open` opens any store: (1) refuse to start with a clear error if the old `rusty-conduit-ssh-gui` process is still running, (2) move the old data dir to the new path if new does not exist (atomic rename, with copy-verify-remove fallback across volumes, preserving owner-only `0o700`/`0o600` permissions on Unix; never merge into a non-empty new dir — surface a notice instead), (3) migrate enabled login autostart from `rusty-conduit-ssh-gui` to `rusty-conduit-gui` and remove the old entry, (4) leave `conduit-vault` keyring entries untouched, and (5) log and show a one-time `"Rusty Conduit (SSH) is now Rusty Conduit GUI"` banner in the Manage Window.

## Scope
- In: `src-tauri/src/migration.rs`, `src-tauri/src/lib.rs`, `src-tauri/src/window.rs`, `src-tauri/src/commands.rs`, `src-tauri/ui/src/lib/types.ts`, `src-tauri/ui/src/lib/stores.svelte.ts`, `src-tauri/ui/src/lib/components/App.svelte`, `src-tauri/ui/src/lib/mock.ts`
- Out: `crates/conduit-vault/**`, `scripts/**`, `.github/**`, `docs/**`

## Sub-tasks
1. [done] Create `src-tauri/src/migration.rs` with testable data-dir migration (atomic rename + cross-volume copy-verify-remove fallback + Unix owner-only permissions + non-empty new dir conflict notice), autostart migration helper, and cross-name old-instance running check — done when: `CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p rusty-conduit-gui migration::` passes with tests for all 6 scenarios (fresh install, same-volume upgrade, cross-volume fallback, non-empty new dir, autostart migration, old app running)
2. [done] Wire migration startup hook in `src-tauri/src/lib.rs` (before `AppController::open`), record migration outcome in diagnostic log, and pass one-time banner notice through `ShellState` / `ShellSnapshot` (`src-tauri/src/window.rs`) — done when: `CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p rusty-conduit-gui` passes
3. [done] Render dismissible migration info/warning banner in `src-tauri/ui/src/lib/components/App.svelte` wired via `types.ts`, `stores.svelte.ts`, and `mock.ts` — done when: `(cd src-tauri/ui && npm run check && npm test && npm run build)` passes

## Verify
```sh
CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p rusty-conduit-gui && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo clippy -p rusty-conduit-gui --all-targets -- -D warnings && (cd src-tauri/ui && npm run check && npm test && npm run build)
```

## Escalate when
- Cross-platform single-instance detection requires a new non-pure-Rust or platform-breaking crate → stop, set `Status: needs-human — reason: <constraint>`

## Log
- (append-only, one line per event)
- began phase-0002
- sub-tasks 1–3 done & verified: implemented `src-tauri/src/migration.rs` (6 unit tests), wired startup hook & `UiEvent::MigrationNotice` banner in `lib.rs`, `window.rs`, and Svelte UI; tests, clippy `-D warnings`, and frontend build all passed

## Evidence
- (append-only: command → observed result)
- `CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p rusty-conduit-gui` → 132 passed, 0 failed (including 6/6 `migration::tests::*`)
- `CARGO_NET_GIT_FETCH_WITH_CLI=true cargo clippy -p rusty-conduit-gui --all-targets -- -D warnings` → exit 0
- `cd src-tauri/ui && npm run check && npm test && npm run build` → `svelte-check` 0 errors/0 warnings, 78/78 tests passed, `vite build` succeeded
