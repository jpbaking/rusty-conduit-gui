# GOAL — Phase 5: Packaging, Signing & Release Automation

## Goal
- Goal ID: 20261124-phase5-packaging-release
- Outcome: Implement Master Plan Phase 5 (Packaging, Signing & Release Automation): cross-platform Tauri v2 bundle config (icons, `conduit-worker` sidecar overlay, Windows NSIS per-user worker-stop hooks, Linux `.deb`/`.rpm`/`.AppImage`, macOS Universal `lipo`), automated secret-leak scan tests and bundle/crypto/config verification scripts, cross-platform CI and release GitHub Actions workflows with conditional signing/notarization, and `docs/RELEASING.md`.
- Done when: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && (cd src-tauri/ui && npm run check && npm run build) && python3 scripts/check-pure-rust-crypto.py && python3 scripts/validate-release-config.py` exits 0 with passing secret-leak scan tests, staged `conduit-worker` verification, and validated CI/release workflows.
- Goal status: completed
- Goal status meaning: drafting | approved | executing | blocked-on-human | in-review | awaiting-acceptance | completed | abandoned
- Last completed phase: phase-0004

## Execution
- Execution mode: delegated
- Planner tier: Gemini 4 Neon (Medium)
- Executor tier: claude --model opus --effort medium via herdr-subagent
- Full verification: cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && (cd src-tauri/ui && npm run check && npm run build) && python3 scripts/check-pure-rust-crypto.py && python3 scripts/validate-release-config.py

## Git
- Repository: yes
- Strategy: isolated-branch
- Starting branch: main
- Work branch: goal/20261124-phase5-packaging-release
- Baseline commit: 169ebb1aed72610017b466ee34c5f396752e0faa
- Starting upstream at start: none
- Work upstream at start: none

## Phases
- [done] phase-0001 — Cross-platform icons, Tauri v2 bundle config & NSIS worker-stop hooks
- [done] phase-0002 — Automated secret-leak scan tests & packaging/smoke-test scripts
- [done] phase-0003 — Cross-platform CI & Release automation workflows
- [done] phase-0004 — Release runbook & end-to-end local staging validation

## Handoff
- Current position: completed
- Next role: planner
- Next action: none
- Last verified evidence: Gate D full verification exited 0 (418 Rust tests passed incl. 5 secret_leak_scan, clippy clean, svelte-check 0/0, vite build clean, PURE_RUST_CRYPTO_OK, SMOKE_TEST_SELF_TEST_OK, RELEASE_CONFIG_OK)
- Blockers: none

## Review
- Reviewed by: Gemini 4 Neon (Medium) — planner Gate D review
- Verification result: PASS — `cargo test --workspace` (418 passed, 0 failed, 0 ignored; incl. 5 `secret_leak_scan`), `cargo clippy --workspace --all-targets -- -D warnings` (0 warnings), `(cd src-tauri/ui && npm run check && npm run build)` (0 errors, 0 warnings, 179.16 kB JS / 12.43 kB CSS), `check-pure-rust-crypto.py` (`PURE_RUST_CRYPTO_OK`), `smoke-test-bundle.py --self-test` (`SMOKE_TEST_SELF_TEST_OK`), `validate-release-config.py` (`RELEASE_CONFIG_OK`)
- Diff reviewed: `169ebb1aed72610017b466ee34c5f396752e0faa..1ffbe52` read in full (23 files changed: 18 non-ledger files + 5 ledger files; zero scope drift, zero edits to `docs/MASTER-PLAN.md` or `../rusty-conduit-ssh`)
- Findings: No blocking defects. Environment limits noted in `docs/RELEASING.md`: (1) `.github/workflows/ci.yml` and `release.yml` have not run on GitHub runners yet (no git remote configured; dry-run recommended on first push); (2) real `cargo tauri build`, `makensis`, `lipo`, and Authenticode/Apple Developer ID signing were not executed on this Linux-only host.

## Log
- created Phase 5 ledger with 4 phases on branch goal/20261124-phase5-packaging-release from baseline 169ebb1aed72610017b466ee34c5f396752e0faa; user approved Gates A-C
- delegated phase-0001 to sub-m5-phase-0001 (claude --model opus --effort medium)
- phase-0001 blocked at sub-task 3: invalid category "Network" and no recorded copyright holder; sub-tasks 1-2 done, partial config kept
- corrected phase-0001 mirror line to the validator's bracketed needs-human format
- planner unblocked phase-0001 (category "Utility", copyright "Copyright (c) 2026, Joseph Baking") and resumed sub-m5-phase-0001
- phase-0001 done: sub-tasks 3-4 finished and ## Verify passed
- planner verified phase-0001 (PHASE1_ASSETS_OK, cargo check clean, closed sub-m5-phase-0001) and delegated phase-0002 to sub-m5-phase-0002 (claude --model opus --effort medium)
- phase-0002 done: secret-leak scan test and four packaging scripts added, ## Verify passed
- planner verified phase-0002 (5 secret_leak_scan tests, clippy clean, 4 scripts verified, closed sub-m5-phase-0002), added rpm runner note to phase-0003, and delegated phase-0003 to sub-m5-phase-0003 (claude --model opus --effort medium)
- phase-0003 done: ci.yml and release.yml added, validator tightened, ## Verify passed; workflows not yet run on GitHub runners
- planner verified phase-0003 (YAML_OK, RELEASE_CONFIG_OK, closed sub-m5-phase-0003) and delegated phase-0004 to sub-m5-phase-0004 (claude --model opus --effort medium)
- phase-0004 blocked at sub-task 2: disk full during worker staging; docs/RELEASING.md written, full verification not run
- planner unblocked phase-0004 (ran cargo clean freeing 26.1 GiB; added windows-arm64 signing parity sub-task) and resumed sub-m5-phase-0004
- phase-0004 done: docs/RELEASING.md written, windows-arm64 signing enabled, worker staging and ## Verify passed; installers and workflows not run
- planner Gate D review passed (418 tests, clippy clean, svelte-check 0/0, vite build clean, PURE_RUST_CRYPTO_OK, SMOKE_TEST_SELF_TEST_OK, RELEASE_CONFIG_OK, closed sub-m5-phase-0004); set status to awaiting-acceptance
- user accepted Phase 5 with squash; marked completed, squashed onto goal/20261124-phase5-packaging-release, and fast-forwarded main
