# GOAL — U5 Packaging & Release

## Goal
- Goal ID: 20261126-u5-packaging-release
- Outcome: Complete Milestone U5 (`docs/MASTER-PLAN.md` §3.3 & §10 U5): add Linux `.deb`/`.rpm` package replacement metadata (`Replaces`/`Conflicts` and `Obsoletes`/`Conflicts` for `rusty-conduit-ssh-gui`) and Windows NSIS legacy `Rusty Conduit (SSH)` uninstall detection/prompt, bump release version to `0.2.0` across all manifests and lockfiles, update release validation/smoke-test scripts, CI/release workflows, `docs/RELEASING.md`, and `README.md`, and run the full low-disk verification suite.
- Done when: All manifests/lockfiles report `0.2.0`, `.deb`/`.rpm` and NSIS §3.3 upgrade-path rules are configured and covered by `validate-release-config.py` and `smoke-test-bundle.py --self-test`, docs/workflows reflect `rusty-conduit-engine` `v0.2.0` and the unified GUI, and the full verification suite (`clippy -D warnings`, `cargo test --workspace`, `secret_leak_scan`, `conduit_check_tauri_tray`, `check-pure-rust-crypto.py`, `validate-release-config.py`, `smoke-test-bundle.py --self-test`, `npm run check && npm test && npm run build`) exits 0 with `rusty-conduit-gui --version` reporting `0.2.0`.
- Goal status: completed
- Goal status meaning: drafting | approved | executing | blocked-on-human | in-review | awaiting-acceptance | completed | abandoned
- Last completed phase: phase-0003

## Execution
- Execution mode: delegated
- Planner tier: primary session
- Executor tier: herdr-subagent (primary: claude opus 5.5 medium; backup: agy claude opus 5.5 medium)
- Full verification: CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo clippy --workspace --all-targets -- -D warnings && CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test --workspace && CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p rusty-conduit-gui --test secret_leak_scan && CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true RUSTFLAGS="--cfg conduit_check_tauri_tray" cargo check -p rusty-conduit-gui --tests --features tauri/tray-icon && python3 scripts/check-pure-rust-crypto.py && python3 scripts/validate-release-config.py && python3 scripts/smoke-test-bundle.py --self-test && (cd src-tauri/ui && npm run check && npm test && npm run build)

## Git
- Repository: yes
- Strategy: isolated-branch
- Starting branch: feat/one-gui
- Work branch: goal/20261126-u5-packaging-release
- Baseline commit: ccd7f76763d120da69bc799a4880f27147219e0b
- Starting upstream at start: origin/feat/one-gui@5ad227c55f4815e91c3354f7736b6c105917bf28
- Work upstream at start: none

## Phases
- [done] phase-0001 — Add §3.3 deb/rpm/NSIS upgrade-path packaging metadata and bump release version to 0.2.0
- [done] phase-0002 — Update release validation/smoke scripts, CI/release workflows, RELEASING.md, and README.md for v0.2.0
- [done] phase-0003 — Rebuild src-tauri/ui/dist/ if needed and run full low-disk verification suite plus version check

## Handoff
- Current position: completed
- Next role: planner
- Next action: none
- Last verified evidence: User accepted U5 (#1); squashed into 1 commit on `goal/20261126-u5-packaging-release` and fast-forward merged into `feat/one-gui`. Gate D full verification exit 0 (clippy -D warnings clean, workspace tests + secret_leak_scan passed, conduit_check_tauri_tray clean, `rusty-conduit-gui --version` → `0.2.0`, 3 Python checks OK, svelte-check 0/0, npm test 93/93, vite build ok).
- Blockers: none

## Review
- Reviewed by: planner (primary session)
- Verification result: Full verification exit 0 (clippy -D warnings clean, workspace Rust tests + secret_leak_scan passed, conduit_check_tauri_tray clean, `rusty-conduit-gui 0.2.0`, check-pure-rust-crypto/validate-release-config/smoke-test-bundle OK, svelte-check 0/0, npm test 93/93, vite build ok; 139G free, target 6.8G)
- Diff reviewed: ccd7f76763d1..bff2d49 (18 changed files across phases 1–3 + .goal-ledger/; 0 scope drift; 7 commits on goal branch, 0 foreign/merge commits)
- Findings: none

## Log
- created ledger with 3 phases for Milestone U5 (replacing completed U4 ledger `20261126-u4-import-export`, preserved in git history)
- user approved Gates A–C; created isolated branch `goal/20261126-u5-packaging-release` off `feat/one-gui` (`ccd7f76763d120`)
- started Gate C and delegated `phase-0001` to `sub-u5-p1` (`claude --model opus --effort medium`)
- phase-0001 done: deb/rpm replacement metadata, NSIS legacy `Rusty Conduit (SSH)` uninstall prompt, version 0.2.0 in manifests/lockfiles; Verify exit 0 (NSIS not compiled locally: no `makensis`).
- planner verified phase-0001 independently (`5073a41`, scope clean, checks exit 0), closed `sub-u5-p1`, and delegated `phase-0002` to `sub-u5-p2` (`claude --model opus --effort medium`)
- phase-0002 done: validator enforces deb/rpm/NSIS §3.3 rules, smoke test checks .deb/.rpm replacement metadata, workflows drop sibling engine checkout, RELEASING.md/README updated for v0.2.0; Verify exit 0 (no real .rpm built locally: no rpm/rpmbuild).
- planner verified phase-0002 independently (`aee4f33`, scope clean, checks exit 0), closed `sub-u5-p2`, and delegated `phase-0003` to `sub-u5-p3` (`claude --model opus --effort medium`)
- phase-0003 done: full low-disk verification suite exit 0, `--version` reports 0.2.0, `src-tauri/ui/dist/` unchanged by build (no dist commit), 139G free / target 6.8G.
- planner completed Gate D review: independent full verification exit 0, 0 scope drift across all 18 changed files, closed `sub-u5-p3`, set Goal status `awaiting-acceptance`
- user accepted U5 (#1); squashed 8 commits into 1 commit on `goal/20261126-u5-packaging-release` and fast-forward merged into `feat/one-gui`
