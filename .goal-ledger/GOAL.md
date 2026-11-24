# GOAL — Phase 3: Full Option Parity, Scoped Agent Forwarding & Config Export/Import

## Goal
- Goal ID: 20261124-phase3-parity-scoped-agent
- Outcome: Implement Master Plan Phase 3: live per-hop Scoped Agent Forwarding (RFC/OpenSSH `ssh-agent` wire protocol over `ScopedAgent` with signature audit logging), full 7-Tab Session Editor (`rusty-conduit-ssh` 100% option parity with port-conflict detection, interactive filter tester, and MITM CA inspection), and Config Export/Import (secrets stripped by default; optional passphrase-encrypted full backup).
- Done when: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && (cd src-tauri/ui && npm run check && npm run build)` exits 0 with passing loopback scoped-agent tests, parity IPC tests, zero secret leaks, and clean Svelte 5 typecheck and production bundle.
- Goal status: completed
- Goal status meaning: drafting | approved | executing | blocked-on-human | in-review | awaiting-acceptance | completed | abandoned
- Last completed phase: phase-0006

## Execution
- Execution mode: delegated
- Planner tier: Gemini 4 Neon (Medium)
- Executor tier: claude --model opus --effort medium via herdr-subagent
- Full verification: cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && (cd src-tauri/ui && npm run check && npm run build)

## Git
- Repository: yes
- Strategy: isolated-branch
- Starting branch: main
- Work branch: goal/20261124-phase3-parity-scoped-agent
- Baseline commit: c95efbf86784c4b8c6473129e076232e76091a44
- Starting upstream at start: none
- Work upstream at start: none

## Phases
- [done] phase-0001 — conduit-core + conduit-ssh: scoped agent forwarding wire protocol & loopback tests
- [done] phase-0002 — conduit-runtime: wire AgentForwardRelay, audit logs & E2E flake hardening
- [done] phase-0003 — src-tauri: port conflicts, filter tester, MITM CA inspector & config export/import IPC
- [done] phase-0004 — src-tauri/ui: 7-tab SessionEditor shell & Tabs 1-3 (Chain+Agent, Forward, Reverse)
- [done] phase-0005 — src-tauri/ui: Tabs 4-7 (Filters, HTTPS MITM, Keepalive, Logging & Advanced)
- [done] phase-0006 — src-tauri/ui: Config Export/Import UI in Settings & full cross-stack verification

## Handoff
- Current position: completed
- Next role: planner
- Next action: none
- Last verified evidence: Gate D full verification exited 0 (333 Rust tests passed, clippy clean, svelte-check 0/0, vite build 176.85 kB JS / 12.43 kB CSS, PURE_RUST_CRYPTO_OK)
- Blockers: none

## Review
- Reviewed by: Gemini 4 Neon (Medium) — planner Gate D review
- Verification result: PASS — `cargo test --workspace` (333 passed, 0 failed), `cargo clippy --workspace --all-targets -- -D warnings` (0 warnings), `(cd src-tauri/ui && npm run check && npm run build)` (0 errors, 0 warnings), `PURE_RUST_CRYPTO_OK` (no aws-lc-sys/openssl-sys), headless Chromium mock-IPC smoke journey 69/69 passed
- Diff reviewed: `c95efbf86784c4b8c6473129e076232e76091a44..75b3074` across all 6 phases; zero scope drift, zero edits to `docs/MASTER-PLAN.md` or `../rusty-conduit-ssh`
- Findings: No blocking defects. Four non-blocking follow-up items tracked for Phase 4 (OpenSSH engine & hardening): (1) `conduit-core` `extra_args` denylist matches whole case-sensitive flags only (misses attached/case-variant options like `-oProxyCommand=x`); (2) plain config import preserves `logging.http_access_log`/`socks_log`/`openssh.ssh_bin` paths (inert until OpenSSH engine ships); (3) `ScopedAgent` RSA signing currently supports SHA-512 only (Ed25519/ECDSA unaffected); (4) `lock_vault` leaves already-connected sessions up so active agent relays keep signing until disconnect.

## Log
- created Milestone 3 ledger with 6 phases for Master Plan Phase 3 (scoped agent forwarding, 7-tab option parity, config export/import) on branch goal/20261124-phase3-parity-scoped-agent from baseline c95efbf86784c4b8c6473129e076232e76091a44
- delegated phase-0001 to sub-m3-phase-0001 (claude --model opus --effort medium)
- phase-0001 blocked after sub-task 1: workspace clippy needs a one-line fix in out-of-scope src-tauri/src/controller/test_support.rs:90
- planner unblocked phase-0001: added src-tauri/src/controller/test_support.rs to Scope: In and resumed sub-m3-phase-0001 from sub-task 2
- phase-0001 done: scoped agent wire protocol, relay, and loopback tests verified
- planner verified phase-0001 (34 core + 63 ssh + 5 agent loopback + 12 multihop tests, clippy clean) and delegated phase-0002 to sub-m3-phase-0002 (claude --model opus --effort medium)
- phase-0002 blocked at sub-task 1 before any code change: SignAudit has no algorithm field and crates/conduit-ssh/** is Scope: Out
- planner unblocked phase-0002 (Option A): added crates/conduit-ssh/src/agent.rs to Scope: In for SignAudit.algorithm and resumed sub-m3-phase-0002 from sub-task 1
- phase-0002 done: per-hop scoped agent relays, agent-audit logs, E2E coverage, and port hardening verified
- planner verified phase-0002 (48 runtime + 8 E2E + 63 ssh + 5 agent + 12 multihop tests, clippy clean) and delegated phase-0003 to sub-m3-phase-0003 (claude --model opus --effort medium)
- phase-0003 done: port conflicts, filter tester, MITM CA inspector, config export/import, and agent-forward key tracking verified across 44 IPC commands
- planner verified phase-0003 (99 src-tauri tests, 44 IPC commands + secret-leak test, clippy clean) and delegated phase-0004 to sub-m3-phase-0004 (claude --model opus --effort medium)
- phase-0004 done: 7-tab SessionEditor, per-hop Forwarded Keys picker, Forward and Reverse Proxy tabs, and typed clients for the 5 Phase 3 commands verified
- planner verified phase-0004 (svelte-check 0/0, vite build clean, ledger valid) and delegated phase-0005 to sub-m3-phase-0005 (claude --model opus --effort medium)
- phase-0005 done: Tabs 4-7 wired with full validation; open finding: conduit-core extra_args denylist misses attached and case-variant ssh options
- planner verified phase-0005 (svelte-check 0/0, vite build clean, ledger valid) and delegated phase-0006 to sub-m3-phase-0006 (claude --model opus --effort medium)
- phase-0006 done: Settings config export/import wired; full cross-stack verification and mock-IPC smoke journey passed
- planner Gate D review passed (333 tests, clippy clean, svelte-check 0/0, vite build clean, PURE_RUST_CRYPTO_OK); set status to awaiting-acceptance
- user accepted Milestone 3 with squash; marked completed and squashed onto goal/20261124-phase3-parity-scoped-agent
