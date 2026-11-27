# GOAL — AirSwitch-style Routing UX & Tunnel Proxy Revamp

## Goal
- Goal ID: 20261127-airswitch-routing-ux
- Outcome: Revamp `rusty-conduit-gui` so Proxy routing uses an AirSwitch-style drag-ordered table with inline condition types, grouped profile pickers (DIRECT, BLOCK, Tunnels, tagged `-L` proxy forwards, and custom upstream servers), and a pinned Default row, while Tunnels support optional Forward listeners + conditional MITM, tunnel-level filters enforced on Proxy traffic, `-L` proxy protocol tags, and plain 3-option start modes.
- Done when: All 6 phases are complete, `src-tauri/ui/dist/` is rebuilt, `docs/TODO.md` and affected `DOX.md` files are updated, and the full verification suite (`cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo test -p rusty-conduit-gui --test secret_leak_scan`, `python3 scripts/check-pure-rust-crypto.py`, `python3 scripts/validate-release-config.py`, and `npm run check && npm test && npm run build` in `src-tauri/ui`) exits 0.
- Goal status: completed
- Goal status meaning: drafting | approved | executing | blocked-on-human | in-review | awaiting-acceptance | completed | abandoned
- Last completed phase: phase-0006

## Execution
- Execution mode: delegated
- Planner tier: Gemini 4 Neon (Medium)
- Executor tier: herdr-subagent (primary: claude opus 5.5 medium; fallback 1: agy opus 5.5 medium; fallback 2: agy neon medium)
- Full verification: cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && cargo test -p rusty-conduit-gui --test secret_leak_scan && python3 scripts/check-pure-rust-crypto.py && python3 scripts/validate-release-config.py && (cd src-tauri/ui && npm run check && npm test && npm run build)

## Git
- Repository: yes
- Strategy: isolated-branch
- Starting branch: main
- Work branch: goal/20261127-airswitch-routing-ux
- Baseline commit: 2e9dc3ed428cf6a37f0da27070527ad13f3e8f60
- Starting upstream at start: origin/main@2e9dc3ed428cf6a37f0da27070527ad13f3e8f60
- Work upstream at start: none

## Phases
- [done] phase-0001 — Core data model, validation, mapping, and migration (conduit-core)
- [done] phase-0002 — Runtime tunnel forward listener, filtered dialer, and in-process -L proxy dialer (conduit-runtime)
- [done] phase-0003 — Tauri controller, IPC, tray bridge, and frontend types/validation sync
- [done] phase-0004 — UI: AirSwitch-style Proxy Routing tab and simplified Upstream servers tab
- [done] phase-0005 — UI: Tunnel editor Proxy/Filters/MITM tabs, -L proxy protocol, and plain Start mode
- [done] phase-0006 — Docs, TODO entry, dist/ rebuild, and full verification

## Handoff
- Current position: completed
- Next role: planner
- Next action: none
- Last verified evidence: Gate D full CI suite passed (clippy 0 warnings, all Rust workspace tests + secret_leak_scan, PURE_RUST_CRYPTO_OK, RELEASE_CONFIG_OK via uv, svelte-check 0 warnings, 105/105 UI tests, dist/ clean)
- Blockers: none

## Review
- Reviewed by: Gemini 4 Neon (Medium) (planner)
- Verification result: pass (cargo clippy -D warnings, cargo test --workspace, secret_leak_scan, check-pure-rust-crypto.py, uv run --with pyyaml validate-release-config.py, npm run check/test/build)
- Diff reviewed: 2e9dc3ed428cf6a37f0da27070527ad13f3e8f60..687f7af (all changed paths audited against Scope: In; key core/runtime/UI diffs reviewed)
- Findings: none (phase-0005 ReverseProxyTab/PortForwardsTab tunnel-toggle edge case was caught and fixed in sub-task 5)

## Log
- created ledger with 6 phases
- user approved Gates A–C; created isolated branch goal/20261127-airswitch-routing-ux from main
- delegated phase-0001 to executor (herdr-subagent: claude opus 5.5 medium)
- phase-0001 blocked on sub-task 2: `crates/conduit-core/src/migrate_v2.rs` constructs `Tunnel` without `..Tunnel::default()` and is outside `Scope: In`
- planner resolved phase-0001 blocker: added `migrate_v2.rs` and `toml_io.rs` to `phase-0001` `Scope: In` and re-delegated to `sub-phase-0001-neon`
- completed phase-0001 (`cargo clippy -p conduit-core --all-targets -- -D warnings` and `cargo test -p conduit-core` passed: 146 passed, 0 warnings)
- planner verified phase-0001 (146 conduit-core tests + clippy) and delegated phase-0002 to executor (agy Gemini 4 Neon Medium)
- completed phase-0002 (`cargo clippy -p conduit-runtime --all-targets -- -D warnings && cargo test -p conduit-runtime` passed: 123 passed, 0 warnings)
- planner verified phase-0002 (123 conduit-runtime tests + clippy), tightened phase-0003 scope, and delegated phase-0003 to executor (agy Gemini 4 Neon Medium)
- phase-0003 blocked on sub-task 1: `src-tauri/src/controller/parity.rs` (`check_port_conflicts`/`check_proxy_port_conflicts`) and `src-tauri/tests/secret_leak_scan.rs` (`AppController::test_route` call sites) are outside `Scope: In`
- planner resolved phase-0003 blocker: added parity.rs to Scope: In and specified AppController::test_route_live(&self) for commands.rs; steered sub-phase-0003-neon
- completed phase-0003 (`cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && (cd src-tauri/ui && npm run check && npm test)` passed: 0 warnings, all Rust workspace tests and 95 UI tests passed)
- planner verified phase-0003 (workspace clippy + tests + svelte-check + 95 UI tests) and delegated phase-0004 to executor (agy Gemini 4 Neon Medium)
- completed phase-0004 (`cd src-tauri/ui && npm run check && npm test` passed: 0 errors, 0 warnings, 104 UI tests passed)
- planner verified phase-0004 (svelte-check 0 warnings + 104 UI tests) and delegated phase-0005 to executor (agy Gemini 4 Neon Medium)
- completed phase-0005 (`cd src-tauri/ui && npm run check && npm test` passed: 0 errors, 0 warnings, 105 UI tests passed)
- planner reopened phase-0005 with sub-task 5 (unlock ReverseProxyTab/PortForwardsTab toggles on Tunnels) and steered sub-phase-0005-neon
- completed phase-0005 sub-task 5 (`cd src-tauri/ui && npm run check && npm test` passed: 0 errors, 0 warnings, 105 UI tests passed)
- planner verified phase-0005 (including sub-task 5; svelte-check 0 warnings + 105 UI tests) and delegated phase-0006 to executor (agy Gemini 4 Neon Medium)
- completed phase-0006 (updated `docs/TODO.md` and 5 `DOX.md` Feature Maps, rebuilt `src-tauri/ui/dist/`, and verified all CI gates pass; `validate-release-config.py` run via `uv run --with pyyaml`)
- Gate D planner review passed clean; moved Goal status to awaiting-acceptance
- user review tweak: switched Tunnel Start mode in KeepaliveTab.svelte from radio buttons to a dropdown (<select>), rebuilt dist/, and re-verified npm check/test/build
- user review tweak: moved Test Upstream dials (host/port) inside each upstream server card with per-upstream state in ProxyProfilesTab.svelte, rebuilt dist/, and re-verified npm check/test/build
- user review tweak: right-aligned .header-actions (margin-left: auto; justify-content: flex-end; flex-wrap: wrap) and tightened .title-input basis in app.css so header buttons stay right-aligned on both Tunnels and Proxies
- user review fix: added Vault::unlock_with_keyring_fallback and wired AppController::unlock_vault_with_keyring to fall back to the pre-migration io.github.rusty-conduit-ssh-gui vault.bin keyring entry and copy it forward
- user accepted finished result and chose squash; soft-reset to baseline and committed final squashed snapshot
