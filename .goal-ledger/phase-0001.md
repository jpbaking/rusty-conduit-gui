# phase-0001 — Pin rusty-conduit-ssh v1.3.0 and rebrand Rust crates, Tauri shell, and UI

- Status: done
- Owner: planner
- Depends on: none
- Goal: Pin `rusty-conduit-ssh` to git tag `v1.3.0` so U0 stays strictly rebrand-only, and rename all package, binary, bundle, tray, CLI, and UI identifiers from `rusty-conduit-ssh-gui` / `Rusty Conduit (SSH)` to `rusty-conduit-gui` / `Rusty Conduit GUI` (`io.github.rusty-conduit-gui`).
- Done when: `CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test --workspace` and `(cd src-tauri/ui && npm run check && npm test && npm run build)` pass with the new names.
- Pattern to follow: `docs/MASTER-PLAN.md:63-76`

## Context
`../rusty-conduit-ssh` is now at v1.4.0 (engine-based), which changed `UpstreamDialer::dial` from `TcpStream` to `UpstreamStream`. Per user decision, U0 pins `rusty-conduit-ssh` to tag `v1.3.0` in `Cargo.toml` so U0 remains a pure rebrand before U1 migrates to `rusty-conduit-engine`. Keep `conduit-vault` keyring service and `conduit-*` crate names unchanged.

## Scope
- In: `Cargo.toml`, `Cargo.lock`, `crates/*/Cargo.toml`, `crates/conduit-tray/src/lib.rs`, `crates/conduit-tray/src/model.rs`, `crates/conduit-tray/src/linux_ksni.rs`, `src-tauri/Cargo.toml`, `src-tauri/tauri.conf.json`, `src-tauri/src/lib.rs`, `src-tauri/src/main.rs`, `src-tauri/src/platform.rs`, `src-tauri/tests/secret_leak_scan.rs`, `src-tauri/ui/package.json`, `src-tauri/ui/package-lock.json`, `src-tauri/ui/index.html`, `src-tauri/ui/src/lib/components/Sidebar.svelte`
- Out: `src-tauri/src/migration.rs` (phase-0002), `scripts/**`, `.github/**`, `src-tauri/windows/nsis-hooks.nsh`, `README.md`, `docs/RELEASING.md` (phase-0003)

## Sub-tasks
1. [done] Pin `rusty-conduit-ssh = { git = "https://github.com/jpbaking/rusty-conduit-ssh", tag = "v1.3.0" }` in `Cargo.toml` and update workspace/crate descriptions across `Cargo.toml` and `crates/*/Cargo.toml` — done when: `grep -q 'tag = "v1.3.0"' Cargo.toml`
2. [done] Rename Tauri package/lib/bin/config/tray/CLI strings (`rusty-conduit-gui`, `rusty_conduit_gui_lib`, `Rusty Conduit GUI`, `io.github.rusty-conduit-gui`, `AUTOSTART_NAME`) in `src-tauri/Cargo.toml`, `src-tauri/tauri.conf.json`, `src-tauri/src/lib.rs`, `src-tauri/src/main.rs`, `src-tauri/src/platform.rs`, `src-tauri/tests/secret_leak_scan.rs`, `crates/conduit-tray/src/{lib,model,linux_ksni}.rs` — done when: `CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test --workspace` passes
3. [done] Update UI brand/title/package name in `src-tauri/ui/package.json`, `src-tauri/ui/index.html`, and `src-tauri/ui/src/lib/components/Sidebar.svelte` — done when: `(cd src-tauri/ui && npm run check && npm test && npm run build)` passes

## Verify
```sh
CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test --workspace && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p rusty-conduit-gui --test secret_leak_scan && (cd src-tauri/ui && npm run check && npm test && npm run build)
```

## Escalate when
- `rusty-conduit-ssh` tag `v1.3.0` fails to resolve or compile → stop, set `Status: needs-human — reason: <exact cargo error>`

## Log
- (append-only, one line per event)
- began phase-0001
- sub-tasks 1–3 done & verified: pinned `rusty-conduit-ssh` tag `v1.3.0`, rebranded Rust crates/Tauri/UI (plus synced `package-lock.json` package name), ran `npm ci` for UI dependencies, all workspace tests + `secret_leak_scan` + frontend check/test/build passed

## Evidence
- (append-only: command → observed result)
- `CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test --workspace` → all workspace tests passed (including `rusty-conduit-gui` unit tests & `secret_leak_scan` 5/5)
- `CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p rusty-conduit-gui --test secret_leak_scan` → 5 passed, 0 failed
- `cd src-tauri/ui && npm ci && npm run check && npm test && npm run build` → `svelte-check` 0 errors/0 warnings, 78/78 tests passed, `vite build` succeeded
