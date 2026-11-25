# GOAL — U0 Rebrand to Rusty Conduit GUI

## Goal
- Goal ID: 20261126-u0-rebrand
- Outcome: Complete Milestone U0 (§3.2 step 1) by rebranding `rusty-conduit-ssh-gui` to `rusty-conduit-gui` (`Rusty Conduit GUI`, bundle ID `io.github.rusty-conduit-gui`), pinning `rusty-conduit-ssh` to `v1.3.0` for U0, implementing §3.3 one-time data-dir/autostart/cross-name single-instance migration and banner, updating packaging/CI/docs, and passing all local CI checks before the manual GitHub/folder rename.
- Done when: All Rust workspace tests, clippy (`-D warnings`), `secret_leak_scan`, Tauri tray compile check, `check-pure-rust-crypto.py`, `validate-release-config.py`, `smoke-test-bundle.py --self-test`, and frontend (`npm run check`, `npm test`, `npm run build`) pass with zero errors, and §3.3 migration tests cover fresh install, upgrade, cross-volume copy-verify-remove, non-empty new dir, autostart migration, and old-app-running guard.
- Goal status: completed
- Goal status meaning: drafting | approved | executing | blocked-on-human | in-review | awaiting-acceptance | completed | abandoned
- Last completed phase: phase-0004

## Execution
- Execution mode: solo
- Planner tier: primary session
- Executor tier: same
- Full verification: CARGO_NET_GIT_FETCH_WITH_CLI=true cargo clippy --workspace --all-targets -- -D warnings && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test --workspace && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p rusty-conduit-gui --test secret_leak_scan && CARGO_NET_GIT_FETCH_WITH_CLI=true RUSTFLAGS="--cfg conduit_check_tauri_tray" cargo check -p rusty-conduit-gui --tests --features tauri/tray-icon && python3 scripts/check-pure-rust-crypto.py && python3 scripts/validate-release-config.py && python3 scripts/smoke-test-bundle.py --self-test && (cd src-tauri/ui && npm run check && npm test && npm run build)

## Git
- Repository: yes
- Strategy: isolated-branch
- Starting branch: feat/one-gui
- Work branch: goal/20261126-u0-rebrand
- Baseline commit: 42026aab3d7270d7795511afde7a875bebfe1204
- Starting upstream at start: origin/feat/one-gui@42026aab3d7270d7795511afde7a875bebfe1204
- Work upstream at start: none

## Phases
- [done] phase-0001 — Pin rusty-conduit-ssh v1.3.0 and rebrand Rust crates, Tauri shell, and UI
- [done] phase-0002 — Implement §3.3 one-time upgrade migration (data-dir, autostart, single-instance, banner)
- [done] phase-0003 — Update NSIS hooks, packaging scripts, CI/Release workflows, and docs
- [done] phase-0004 — Run full local CI verification suite and stale-name audit

## Handoff
- Current position: completed
- Next role: planner
- Next action: none
- Last verified evidence: user accepted and squashed U0 into one clean commit on `goal/20261126-u0-rebrand`, merged into `feat/one-gui`, ready for manual GitHub repo rename and local folder rename (§3.2 steps 2–3)
- Blockers: none

## Review
- Reviewed by: planner (primary session)
- Verification result: pass — Full verification command exited 0 across all Rust, Python, and Svelte/Node CI gates; 6/6 §3.3 migration unit tests passed; stale-name audit clean
- Diff reviewed: `42026aa..f5d8b37` (read in full; 9 matching Goal-ID commits, 42 files changed strictly within planned phase scopes)
- Findings: none

## Log
- created ledger with 4 phases for Milestone U0 rebrand in `rusty-conduit-ssh-gui`
- approved Gates A–C; created isolated branch `goal/20261126-u0-rebrand` off `feat/one-gui` (`42026aab3d72`)
- began phase-0001
- closed phase-0001: pinned `rusty-conduit-ssh` v1.3.0 and rebranded crates, Tauri shell, and UI; all Rust & UI tests green
- began phase-0002
- closed phase-0002: implemented §3.3 migration (`src-tauri/src/migration.rs`) and UI banner; 132 Rust tests, clippy `-D warnings`, and 78 UI tests green
- began phase-0003
- closed phase-0003: updated NSIS hooks, packaging scripts, CI/Release workflows, and docs (`RELEASE_CONFIG_OK`, `SMOKE_TEST_SELF_TEST_OK`, `PURE_RUST_CRYPTO_OK`)
- began phase-0004
- closed phase-0004: full local CI suite and stale-name audit clean; entering Gate D (`in-review`)
- Gate D review passed (0 findings, validator 0 warnings); transitioned to `awaiting-acceptance`
- accepted by user; squashed 10 goal commits into one commit retaining `.goal-ledger/`, marked `completed`, and merged into `feat/one-gui`
