# GOAL — Phase 4: Opt-In OpenSSH Compatibility Engine & Hardening

## Goal
- Goal ID: 20261124-phase4-openssh-engine
- Outcome: Implement Master Plan Phase 4 (Opt-In OpenSSH Compatibility Engine & Hardening): close Phase 3 Gate D hardening items, add `crates/conduit-openssh` + `conduit-worker` (binary discovery, hardened `-F` config, app-owned `known_hosts`, isolated agent socket/named-pipe, authenticated IPC askpass, `hop-proxy` multi-hop wrapper, orphan-guarded supervision), wire `SshEngine::OpenSsh` into `conduit-runtime` with real `/usr/bin/ssh` E2E tests, and expose `check_openssh_binary` in `src-tauri` + `LoggingAdvancedTab.svelte`.
- Done when: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && (cd src-tauri/ui && npm run check && npm run build)` exits 0 with passing real `/usr/bin/ssh` loopback E2E tests, hardened denylist & plain-import sanitization tests, zero secret leaks across all 45 IPC commands, and clean Svelte 5 typecheck and production bundle.
- Goal status: completed
- Goal status meaning: drafting | approved | executing | blocked-on-human | in-review | awaiting-acceptance | completed | abandoned
- Last completed phase: phase-0005

## Execution
- Execution mode: delegated
- Planner tier: Gemini 4 Neon (Medium)
- Executor tier: claude --model opus --effort medium via herdr-subagent
- Full verification: cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && (cd src-tauri/ui && npm run check && npm run build)

## Git
- Repository: yes
- Strategy: isolated-branch
- Starting branch: main
- Work branch: goal/20261124-phase4-openssh-engine
- Baseline commit: a1b1b83666e904ce64a5b38e38886732452324aa
- Starting upstream at start: none
- Work upstream at start: none

## Phases
- [done] phase-0001 — Hardening follow-ups & host-key public-key storage
- [done] phase-0002 — conduit-openssh core: binary check, hardened -F config, known_hosts & isolated agent socket
- [done] phase-0003 — conduit-openssh: IPC askpass, conduit-worker, orphan guard & supervisor
- [done] phase-0004 — conduit-runtime: wire SshEngine::OpenSsh into runner.rs & real /usr/bin/ssh E2E tests
- [done] phase-0005 — src-tauri + ui: check_openssh_binary IPC, secret-leak test & LoggingAdvancedTab

## Handoff
- Current position: completed
- Next role: planner
- Next action: none
- Last verified evidence: Gate D full verification exited 0 (413 Rust tests passed, clippy clean, svelte-check 0/0, vite build 179.16 kB JS / 12.43 kB CSS, PURE_RUST_CRYPTO_OK, 0 warnings)
- Blockers: none

## Review
- Reviewed by: Gemini 4 Neon (Medium) — planner Gate D review
- Verification result: PASS — `cargo test --workspace` (413 passed, 0 failed; includes 52+6 `conduit-openssh` and 50+8+8 `conduit-runtime` real `/usr/bin/ssh` tests + 45-command `src-tauri` secret-leak IPC test), `cargo clippy --workspace --all-targets -- -D warnings` (0 warnings), `(cd src-tauri/ui && npm run check && npm run build)` (0 errors, 0 warnings, 179.16 kB JS / 12.43 kB CSS), `PURE_RUST_CRYPTO_OK`, `validate_goal_ledger.py --root .` (valid, 5 phases, 0 warnings)
- Diff reviewed: `a1b1b83666e904ce64a5b38e38886732452324aa..6e19d45` (51 files, +5464/-372 across all 5 phases); zero scope drift, zero edits to `docs/MASTER-PLAN.md` or `../rusty-conduit-ssh`
- Findings: No blocking defects. Platform notes for Phase 5 CI: (1) `cfg(windows)` named-pipe/Job-Object/runtime-dir paths and `cfg(target_os = "macos")` parent-PID watcher were not compiled or executed on this Linux-only host (Phase 5 cross-OS CI will verify them); (2) `-E` remains allowed in `extra_args` (optional follow-up if log-file flag should be restricted); (3) OpenSSH engine logs a notice when `agent_forward` is enabled because `ssh -N` opens no session channel (per Master Plan Section 3.1).

## Log
- created Milestone 4 ledger with 5 phases for Master Plan Phase 4 (opt-in OpenSSH engine & hardening) on branch goal/20261124-phase4-openssh-engine from baseline a1b1b83666e904ce64a5b38e38886732452324aa
- delegated phase-0001 to sub-m4-phase-0001 (claude --model opus --effort medium)
- phase-0001 blocked: sub-tasks 1-3 done, sub-task 4 stopped on out-of-scope compile failures in conduit-tray/src/model.rs:509 and src-tauri/src/controller.rs:640
- planner unblocked phase-0001: added crates/conduit-tray/src/model.rs and src-tauri/src/controller.rs to Scope: In and resumed sub-m4-phase-0001 from sub-task 4
- phase-0001 done: Verify exit 0 with 345 tests passed, clippy clean, svelte-check 0 errors
- planner verified phase-0001 (345 tests, clippy clean, svelte-check 0/0) and delegated phase-0002 to sub-m4-phase-0002 (claude --model opus --effort medium)
- phase-0002 done: Verify exit 0 with 33 conduit-openssh tests, clippy clean; cfg(windows) code not compiled on this host
- planner verified phase-0002 (33 tests, PURE_RUST_CRYPTO_OK, clippy clean), updated phase-0003 context with IdentitiesOnly .pub file requirement, and delegated phase-0003 to sub-m4-phase-0003 (claude --model opus --effort medium)
- phase-0003 done: Verify exit 0 with 52 unit + 6 real /usr/bin/ssh loopback tests, clippy clean; cfg(windows) and macOS code not compiled on this host
- planner verified phase-0003 (52 unit + 6 loopback tests, clippy clean), updated phase-0004 context & Verify for conduit-worker build and shutdown().await, and delegated phase-0004 to sub-m4-phase-0004 (claude --model opus --effort medium)
- phase-0004 blocked: sub-task 1 done (50 unit tests, clippy clean); sub-task 2 at 7/8 E2E tests after two failed runs, last failure a SOCKS port collision
- planner unblocked phase-0004: approved port-collision fix (non-ephemeral test ports + socks_port skipping profile forward ports) and confirmed agent_forward notice behavior; resumed sub-m4-phase-0004 from sub-task 2
- phase-0004 done: Verify exit 0 with 50 unit + 8 e2e_runtime + 8 real /usr/bin/ssh tests, clippy clean; cfg(windows) and macOS paths not run on this host
- planner verified phase-0004 (50 unit + 8 e2e_runtime + 8 openssh_e2e, clippy clean) and delegated phase-0005 to sub-m4-phase-0005 (claude --model opus --effort medium)
- phase-0005 blocked: sub-tasks 1-3 done and Verify exit 0 (413 tests), but the rebuilt tracked src-tauri/ui/dist is outside Scope: In and is left uncommitted
- planner added src-tauri/ui/dist/** to phase-0005 Scope: In, committed rebuilt dist, closed phase-0005, and entered Gate D review
- planner Gate D review passed (413 tests, clippy clean, svelte-check 0/0, vite build clean, PURE_RUST_CRYPTO_OK); set status to awaiting-acceptance
- user accepted Milestone 4 with squash; marked completed, squashed onto goal/20261124-phase4-openssh-engine, and fast-forwarded main
