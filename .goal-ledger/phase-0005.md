# phase-0005 — src-tauri + ui: check_openssh_binary IPC, secret-leak test & LoggingAdvancedTab

- Status: done
- Owner: executor
- Depends on: phase-0004
- Goal: Expose `check_openssh_binary` in `src-tauri` (extending `ALL_COMMANDS` and the secret-leak IPC test) and surface detected `ssh` version, resolved path, and compatibility status in `LoggingAdvancedTab.svelte`.
- Done when: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && (cd src-tauri/ui && npm run check && npm run build)` exits 0 with all 45 IPC commands exercised in the secret-leak test and clean Svelte 5 build.
- Pattern to follow: `src-tauri/src/controller/parity.rs` (editor helper methods), `src-tauri/src/commands.rs:750-824` (IPC test & `ALL_COMMANDS`), `src-tauri/ui/src/lib/components/MitmTab.svelte` (async backend check button & status badge), `src-tauri/ui/src/lib/components/LoggingAdvancedTab.svelte`.

## Context
Users selecting `SshEngine::OpenSsh` need immediate feedback in the Session Editor's Logging & Advanced tab on whether their configured `ssh_bin` is found, what OpenSSH version it reports, and whether it meets platform requirements (e.g. OpenSSH >= 8.4 on Windows).
This phase adds the thin `check_openssh_binary` IPC command wrapping `conduit_openssh::check_openssh_binary`, registers it in `src-tauri`, extends the secret-leak IPC test to cover all 45 commands, and wires it into `api.ts`, `mock.ts`, `types.ts`, and `LoggingAdvancedTab.svelte`.

## Scope
- In: `src-tauri/Cargo.toml`, `Cargo.lock`, `src-tauri/src/controller/parity.rs`, `src-tauri/src/commands.rs`, `src-tauri/src/lib.rs`, `src-tauri/ui/src/lib/types.ts`, `src-tauri/ui/src/lib/api.ts`, `src-tauri/ui/src/lib/mock.ts`, `src-tauri/ui/src/lib/components/LoggingAdvancedTab.svelte`, `src-tauri/ui/dist/**`
- Out: `docs/MASTER-PLAN.md`, `../rusty-conduit-ssh/**`, `crates/**`

## Sub-tasks
1. [done] Add `conduit-openssh = { path = "../crates/conduit-openssh" }` to `src-tauri/Cargo.toml`, add `check_openssh_binary(ssh_bin: Option<String>) -> OpenSshBinaryInfo` in `src-tauri/src/controller/parity.rs`, expose `#[tauri::command] pub async fn check_openssh_binary(...)` in `src-tauri/src/commands.rs` (running on the blocking pool), register it in `src-tauri/src/lib.rs` `invoke_handler`, and add `"check_openssh_binary"` to `ALL_COMMANDS` and exercise it in the secret-leak IPC test in `src-tauri/src/commands.rs` (verifying both default `"ssh"` and a nonexistent binary path) — done when: `cargo test -p rusty-conduit-ssh-gui` passes.
2. [done] Add `OpenSshBinaryInfo` to `src-tauri/ui/src/lib/types.ts`, `checkOpensshBinary(sshBin?: string)` to `src-tauri/ui/src/lib/api.ts`, and a realistic mock handler in `src-tauri/ui/src/lib/mock.ts` — done when: `(cd src-tauri/ui && npm run check)` passes.
3. [done] Wire `checkOpensshBinary` into `src-tauri/ui/src/lib/components/LoggingAdvancedTab.svelte`: add a "Check binary" button next to the `ssh program` input (and auto-check when `draft.engine === "OpenSsh"`), showing the detected version string, resolved path, and a clear supported/warning/error status badge — done when: `(cd src-tauri/ui && npm run check && npm run build)` passes with 0 errors and 0 warnings.

## Verify
```sh
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && (cd src-tauri/ui && npm run check && npm run build)
```

## Escalate when
- `src-tauri` build or IPC test fails due to a signature mismatch in `conduit-openssh` → stop, set `Status: needs-human — reason: <exact compiler error>`
- `svelte-check` or `vite build` reports a type or bundle warning that requires touching files outside `Scope: In` → stop, set `Status: needs-human — reason: <exact warning/error>`

## Log
- (append-only, one line per event)
- sub-task 1: added conduit-openssh dep, parity::check_openssh_binary, the IPC command, ipc_handler! entry (lib.rs uses that macro, so it needed no edit), ALL_COMMANDS entry and secret-leak test calls
- sub-task 2: added OpenSshBinaryInfo type, api.checkOpensshBinary and a mock handler
- sub-task 3: added Check binary button, 500 ms debounced auto-check for the OpenSsh engine, version/path facts and supported/warning/error badge
- Verify passed; stopped before close because the build changed tracked src-tauri/ui/dist, outside Scope: In; dist left uncommitted in the working tree
- planner resolved: added `src-tauri/ui/dist/**` to `Scope: In` (tracked for `tauri::generate_context!()`), confirmed debounced auto-check is safe because plain imports neutralize `ssh_bin` to `"ssh"` (phase-0001), staged rebuilt `dist` and closed phase-0005.

## Evidence
- (append-only: command → observed result)
- `cargo test -p rusty-conduit-ssh-gui` → exit 0, 103 passed, 0 failed
- `(cd src-tauri/ui && npm run check)` → exit 0, 158 files, 0 errors, 0 warnings
- `(cd src-tauri/ui && npm run check && npm run build)` → check exit 0 with 0 errors and 0 warnings; build exit 0, 154 modules, no warnings
- `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && (cd src-tauri/ui && npm run check && npm run build)` → exit 0, 413 tests passed, 0 failed, clippy clean, svelte-check 0 errors and 0 warnings, build OK
- `git status --short` after Verify → ` D src-tauri/ui/dist/assets/index-D2N8AH_b.js`, ` M src-tauri/ui/dist/index.html`, `?? src-tauri/ui/dist/assets/index-6bIeZ1Rb.js` (outside Scope: In, not committed)
