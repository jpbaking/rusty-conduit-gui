# GOAL — Phase 6: Master Plan Audit & Polish

## Goal
- Goal ID: 20261124-phase6-audit-polish
- Outcome: Close the remaining gaps against `docs/MASTER-PLAN.md` and polish the repository for users and contributors: wire OS sleep/wake listeners to `SessionManager::notify_system_wake`, add manual one-time OpenSSH `known_hosts` file import, add automated frontend unit tests to `npm test` and CI, add `--help`/`--version` CLI flags, and add `LICENSE` + `README.md`.
- Done when: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && (cd src-tauri/ui && npm run check && npm test && npm run build) && python3 scripts/check-pure-rust-crypto.py && python3 scripts/validate-release-config.py` exits 0 with all 4 phases verified.
- Goal status: completed
- Goal status meaning: drafting | approved | executing | blocked-on-human | in-review | awaiting-acceptance | completed | abandoned
- Last completed phase: phase-0004

## Execution
- Execution mode: delegated
- Planner tier: Gemini 4 Neon (Medium)
- Executor tier: claude --model opus --effort medium via herdr-subagent
- Full verification: cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && (cd src-tauri/ui && npm run check && npm test && npm run build) && python3 scripts/check-pure-rust-crypto.py && python3 scripts/validate-release-config.py

## Git
- Repository: yes
- Strategy: isolated-branch
- Starting branch: main
- Work branch: goal/20261124-phase6-audit-polish
- Baseline commit: 7497edd5b71668a4ab6af6bd0f685547ada1320f
- Starting upstream at start: none
- Work upstream at start: none

## Phases
- [done] phase-0001 — OS sleep/wake hooks & runtime wake wiring
- [done] phase-0002 — Manual OpenSSH known_hosts file import
- [done] phase-0003 — Frontend unit tests & CI integration
- [done] phase-0004 — CLI --help/--version, README.md, LICENSE & workspace polish

## Handoff
- Current position: completed
- Next role: planner
- Next action: none
- Last verified evidence: Gate D full verification exited 0 (444 Rust tests passed, clippy clean, svelte-check 0/0, 55/55 frontend node:test passed, vite build clean, PURE_RUST_CRYPTO_OK, RELEASE_CONFIG_OK)
- Blockers: none

## Review
- Reviewed by: Gemini 4 Neon (Medium) — planner Gate D review
- Verification result: PASS — `cargo test --workspace` (444 passed, 0 failed, 0 ignored), `cargo clippy --workspace --all-targets -- -D warnings` (0 warnings), `(cd src-tauri/ui && npm run check && npm test && npm run build)` (0 errors, 0 warnings; 55/55 tests in 20 suites; 180.65 kB JS / 12.43 kB CSS), `check-pure-rust-crypto.py` (`PURE_RUST_CRYPTO_OK`), `validate-release-config.py` (`RELEASE_CONFIG_OK`)
- Diff reviewed: `7497edd5b71668a4ab6af6bd0f685547ada1320f..c76d5a7` read in full (35 files changed: 30 non-ledger + 5 ledger; zero scope drift, zero edits to `docs/MASTER-PLAN.md` or `../rusty-conduit-ssh`)
- Findings: No blocking defects. Environment limits noted: (1) Windows (`windows-sys`) and macOS (`objc2-app-kit`) wake listener code paths in `crates/conduit-runtime/src/wake.rs` were checked against cached crate signatures but not compiled on this Linux-only host (CI matrix builds both); (2) frontend unit tests were run on Node v26.13.0 locally (CI runs Node 22).

## Log
- created Phase 6 ledger with 4 phases on branch goal/20261124-phase6-audit-polish from baseline 7497edd5b71668a4ab6af6bd0f685547ada1320f; user approved Gates A-C
- delegated phase-0001 to sub-m6-phase-0001 (claude --model opus --effort medium)
- phase-0001 done: wake listener (conduit-runtime/src/wake.rs) wired to AppController::notify_system_wake in Tauri setup; Verify exit 0; Windows/macOS paths not compiled locally
- planner verified phase-0001 (cargo test, clippy clean, PURE_RUST_CRYPTO_OK, closed sub-m6-phase-0001) and delegated phase-0002 to sub-m6-phase-0002 (claude --model opus --effort medium)
- phase-0002 blocked at sub-task 2 (sub-task 1 done: known_hosts_import parser, 11 tests pass): sub-task 2 return type HostKeyPin with approved_at/public_key does not exist; KnownHostsStore stores HostKeyRecord — approve returning HostKeyEntry? (details in phase-0002.md Status)
- planner unblocked phase-0002 (approved HostKeyRecord + returning HostKeyEntry with no schema change) and resumed sub-m6-phase-0002
- phase-0002 done: known_hosts_import parser (11 tests), AppController::import_known_host_from_file + IPC import_known_host returning HostKeyEntry (4 controller tests + IPC coverage), HopEditor "Import from file…" UI; Verify exit 0
- planner verified phase-0002 (52+108+5 tests, clippy clean, svelte-check 0/0, vite build clean, closed sub-m6-phase-0002), added src-tauri/ui/dist/** to phase-0003 scope to commit rebuilt bundle, and delegated phase-0003 to sub-m6-phase-0003 (claude --model opus --effort medium)
- phase-0003 blocked before sub-task 1 output: svelte-check rejects node:test/.ts-extension imports in src/lib test files; options (a) tsconfig exclude, (b) tsconfig+ambient d.ts, (c) // @ts-nocheck (verified clean) — awaiting planner
- planner unblocked phase-0003 (approved option (b): allowImportingTsExtensions in tsconfig.json + ambient src/lib/node-test.d.ts) and resumed sub-m6-phase-0003
- phase-0003 done: validate/chain/format .test.ts (55 node:test tests), allowImportingTsExtensions + src/lib/node-test.d.ts, npm test script, npm test in ci.yml frontend job + validate-release-config.py, rebuilt dist/; Verify exit 0; Node 22 run not tested locally (Node 26 only)
- planner verified phase-0003 (svelte-check 0/0, 55/55 tests, vite build clean, RELEASE_CONFIG_OK, closed sub-m6-phase-0003) and delegated phase-0004 to sub-m6-phase-0004 (claude --model opus --effort medium)
- phase-0004 done: --help/-h and --version/-V in CliFlags with help_text()/version_text() handled before GTK init (4 new tests), duplicate Cargo.toml comment removed, BSD-3-Clause LICENSE copied from ../rusty-conduit-ssh, README.md added; Verify exit 0
- planner Gate D review passed (444 Rust tests, clippy clean, svelte-check 0/0, 55/55 frontend tests, vite build clean, PURE_RUST_CRYPTO_OK, RELEASE_CONFIG_OK, closed sub-m6-phase-0004); set status to awaiting-acceptance
- user accepted Phase 6 with squash; marked completed, squashed onto goal/20261124-phase6-audit-polish, and fast-forwarded main
