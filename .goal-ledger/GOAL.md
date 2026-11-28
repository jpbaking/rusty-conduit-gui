# GOAL — Optimization roadmap Phase 1 for rusty-conduit-gui

## Goal
- Goal ID: 20261128-optimization-phase1
- Outcome: The GUI ships optimized release builds and fast-unlocking debug builds, caps glibc malloc arenas on Linux, bounds Argon2 costs read from disk and zeroizes raw key copies, imports and exports CLI `config.toml` without the `error_page` / `@tunnel:` / `@forward:` / `socks_block_web` drift, fixes the v2 UI usage, host-key, preset, and IPC-type gaps, gates the `ssh` parent thread to Linux and sweeps stale runtime directories, and caches Rust builds in the release workflow.
- Done when: the Full verification command exits 0, every phase `## Verify` passes, and `git diff <baseline>..HEAD` touches only paths named under some phase's `Scope: In`.
- Goal status: completed
- Goal status meaning: drafting | approved | executing | blocked-on-human | in-review | awaiting-acceptance | completed | abandoned
- Last completed phase: phase-0006

## Execution
- Execution mode: delegated
- Planner tier: Claude Code (claude-opus-5-5)
- Executor tier: agy --model gemini-4-neon-medium via the herdr-subagent skill (fallback: claude --model opus --effort medium via herdr-subagent while agy is rate-limited)
- Full verification: cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && cargo test -p rusty-conduit-gui --test secret_leak_scan && python3 scripts/check-pure-rust-crypto.py && uv run -q --no-project --with pyyaml python3 scripts/validate-release-config.py && (cd src-tauri/ui && npm ci && npm run check && npm test && npm run build)

## Git
- Repository: yes
- Strategy: isolated-branch
- Starting branch: main
- Work branch: goal/20261128-optimization-phase1
- Baseline commit: bfcae88ea5e88f46691d34233e4eef963475e9b4
- Starting upstream at start: origin/main@bfcae88ea5e88f46691d34233e4eef963475e9b4
- Work upstream at start: none

## Phases
- [done] phase-0001 — Release and dev build profiles, Linux malloc arena cap
- [done] phase-0002 — Vault hardening: bounded Argon2 costs, zeroized key copies, owner-only temp files
- [done] phase-0003 — CLI config.toml drift: error_page, @tunnel/@forward export, socks_block_web merge
- [done] phase-0004 — v2 UI fixes: CA/key usage, tunnel host-key prompt, preset targets, IPC types
- [done] phase-0005 — conduit-openssh: Linux-only parent thread and stale runtime directory sweep
- [done] phase-0006 — Release workflow Rust cache

## Handoff
- Current position: completed; accepted by the user 2026-11-28
- Next role: planner
- Next action: none
- Last verified evidence: Gate D → full verification pass (680 Rust, 119 UI, secret_leak_scan, crypto, release config, build)
- Blockers: none

## Review
- Reviewed by: planner, Claude Code (claude-opus-5-5); re-run from the top after the pause
- Verification result: pass — full verification command exit 0 (uv form of the release validator); Linux: conduit-openssh clippy + tests in rust:1-bookworm exit 0; the src-tauri glibc malloc branch is byte-identical to rusty-conduit's Linux-verified copy and is left to the CI Linux job (needs WebKitGTK)
- Diff reviewed: bfcae88..HEAD, read in full (Rust, UI sources, workflow, docs; dist/ checked as reproducible from `npm run build`); 30 non-ledger paths, all within phase Scope: In (dist/ added to phase-0004 after escalation); Goal-ID on every commit, no merges
- Findings: 3 fixed at Gate D — misplaced doc comment in storage.rs and mid-file `use` in export.rs (phase-0002 fix-up), over-long lines in toml_watcher.rs (phase-0003 fix-up). Open for the user: phase-0004 manual dev-server check (CA delete dialog lists the demo Proxy). Deferred by plan: Windows agent-pipe DACLs; macOS/Windows paths of B-03 beyond the Linux thread gate

## Log
- created ledger with 6 phases; replaces the completed ledger 20261127-airswitch-routing-ux (kept in Git history)
- source plan: rusty-conduit-series/docs/OPTIMIZATION.md, roadmap Phase 1 (items P-01, P-02, B-02, B-03, B-04, B-05, M-05)
- sibling ledgers with the same Goal ID: rusty-conduit, rusty-conduit-switch, rusty-conduit-ssh, and the rusty-conduit-series workspace
- user decisions: roadmap Phase 1 only; delegated to agy neon medium via herdr
- planner decisions: phases 0002, 0003, and 0005 stay with the planner (security, persisted-data migration, process lifecycle); B-03 Windows agent-pipe DACLs are deferred (cannot compile Windows code on this Mac); B-03 `socks_port == 0` is skipped as unreachable (`conduit-runtime/src/tunnel_manager.rs:900-915` always resolves a real port before `OpenSshSupervisor::start`); M-05 `beforeDevCommand`/`beforeBuildCommand` are skipped (`release.yml` builds the frontend in its own step, and `npm run dev` is the browser demo mode); `tauri-cli` stays a pinned `cargo install`, made cheap by `Swatinem/rust-cache` caching `~/.cargo/bin`
- user approved the goal (Gate A) on 2026-11-28
- Gate B: isolated branch goal/20261128-optimization-phase1 created from main at baseline bfcae88ea5e88f46691d34233e4eef963475e9b4; user asked to commit only and not start execution yet
- resumed 2026-11-28 by planner (claude-opus-5-5); evidence: branch and baseline consistent, HEAD = approve commit 0642629, clean tree, validator OK; origin/goal/20261128-optimization-phase1 holds the approve commit, so automated squash is prohibited
- Gate C: user started execution; executor agy neon medium, fallback claude opus medium while agy is rate-limited
- delegated phase-0001 to agy (herdr-subagent)
- phase-0001 escalated (needs-human): all 3 sub-tasks completed and clippy/tests/crypto/diff checks passed, but `python3 scripts/validate-release-config.py` failed with missing PyYAML
- planner answered phase-0001 escalation: no PyYAML locally → run the validator as `uv run -q --no-project --with pyyaml python3 scripts/validate-release-config.py`; Full verification and phase-0006 Verify updated; planner re-ran phase-0001 Verify and closed it; Linux compile deferred to CI
- phase-0002 done (planner): Argon2 caps enforced in conduit-vault, raw key copies zeroized, temp files 0600 from creation
- phase-0003 done (planner): error_page accepted, @tunnel/@forward export, migrate at import, socks_block_web merge
- delegated phase-0004 to agy (herdr-subagent)
- phase-0004 escalated (needs-human): all 6 sub-tasks and npm ci/check/test/build passed, but npm run build regenerated tracked src-tauri/ui/dist/ which is outside Scope: In and fails the Verify scope check
- planner answered phase-0004 escalation: src-tauri/ui/dist/ is a tracked build output (DOX) and joins the phase scope; phase-0004 closed with rebuilt dist/
- planner amended phase-0005 (marker-file guard for the runtime-dir sweep) and began it
- phase-0005 done (planner): Linux-only ssh parent thread, marker-guarded startup sweep
- delegated phase-0006 to agy (herdr-subagent)
- phase-0006 done (executor): added Swatinem/rust-cache@v2 step to .github/workflows/release.yml
- planner accepted phase-0006 (Verify re-run, diff in scope); Gate D started: full verification passed, scope check clean; paused at the user's request before the full diff read and ## Review
- resumed after the pause; Gate D re-run from the top; 3 findings fixed as fix-up sub-tasks; Gate D passed; status awaiting-acceptance
- user accepted 2026-11-28; branch kept unsquashed (published on origin); user asked to squash-merge into main, delete the goal branch, and push
