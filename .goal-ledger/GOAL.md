# GOAL — Core Engine, Secret Vault, Multi-Hop SSH & Session Runtime

## Goal
- Goal ID: 20261123-core-engine-vault-runtime
- Outcome: Implement Phase 1 (plus Spike 0.1 loopback validation) of Rusty Conduit SSH GUI: the UI-agnostic Rust workspace (`conduit-core`, `conduit-vault`, `conduit-ssh`, `conduit-runtime`) integrating `../rusty-conduit-ssh` over a pure-Rust `russh` multi-hop engine with envelope-encrypted secret storage and full loopback E2E verification.
- Done when: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings` exits 0 with passing unit and multi-hop loopback integration tests covering forward HTTP/SOCKS5h, reverse proxy, filters, MITM, vault encryption, host-key pinning, reconnect, and lockout protection with zero `~/.ssh` access.
- Goal status: completed
- Goal status meaning: drafting | approved | executing | blocked-on-human | in-review | awaiting-acceptance | completed | abandoned
- Last completed phase: phase-0006

## Execution
- Execution mode: delegated
- Planner tier: Gemini 4 Neon (Medium)
- Executor tier: claude --model opus --effort medium via herdr-subagent (upgraded from opencode after phase-0002)
- Full verification: cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings

## Git
- Repository: yes
- Strategy: isolated-branch
- Starting branch: main
- Work branch: goal/20261123-core-engine-vault-runtime
- Baseline commit: df6fea97155a069ef2cc4887f61232e3e3c37c34
- Starting upstream at start: none
- Work upstream at start: none

## Phases
- [done] phase-0001 — Cargo workspace scaffold & conduit-core data model
- [done] phase-0002 — conduit-vault envelope encryption, key management & keyring
- [done] phase-0003 — conduit-ssh multi-hop russh chain, host-key pinning & scoped agent
- [done] phase-0004 — conduit-ssh RusshDialer bridge, reverse forwarding & loopback SSH tests
- [done] phase-0005 — conduit-runtime SessionManager, state machine, backoff, logs & events
- [done] phase-0006 — End-to-end runtime integration tests & hardening verification

## Handoff
- Current position: completed
- Next role: planner
- Next action: none
- Last verified evidence: cargo test --workspace (193 passed, 0 failed) && cargo clippy --workspace --all-targets -- -D warnings (exit 0); zero aws-lc-sys/openssl-sys; zero scope drift; accepted and squashed
- Blockers: none

## Review
- Reviewed by: Gemini 4 Neon (Medium) (planner)
- Verification result: pass — cargo test --workspace (193 passed, 0 failed: 33 conduit-core, 43 conduit-vault, 64 conduit-ssh, 53 conduit-runtime) && cargo clippy --workspace --all-targets -- -D warnings (exit 0); cargo tree --workspace free of aws-lc-sys and openssl-sys
- Diff reviewed: df6fea97155a069ef2cc4887f61232e3e3c37c34..HEAD (read in full across all 6 phase reviews; 44 changed files, all within declared Scope: In)
- Findings: none remaining (4 phase-0002 review findings fixed in 9c69ac1 before phase-0003)

## Log
- created ledger with 6 phases for Master Plan Phase 1 (core workspace, vault, russh multi-hop engine, runtime, and Spike 0.1 loopback validation)
- user approved Gates A-C; initialized git with docs/MASTER-PLAN.md baseline df6fea97155a069ef2cc4887f61232e3e3c37c34 and created branch goal/20261123-core-engine-vault-runtime
- delegated phase-0001 to opencode (sub-phase-0001)
- phase-0001 done: 4-crate workspace + conduit-core (model, validate, mapping, storage) implemented; 33 tests pass, clippy clean; committed on goal/20261123-core-engine-vault-runtime
- planner reviewed and accepted phase-0001; closed sub-phase-0001; sharpened phase-0002 crate versions and delegated phase-0002 to opencode (sub-phase-0002)
- phase-0002 done: conduit-vault (crypto envelope, keyring hybrid, store lifecycle, key import/generation/backup, tests/vault_security.rs) implemented; 43 tests pass (37 unit + 6 integration); clippy clean; committed on goal/20261123-core-engine-vault-runtime
- planner reviewed phase-0002: fixed hardcoded /tmp/test_* paths in keys.rs tests, guarded Unix PermissionsExt import in store.rs, redacted BackupKey Debug, added OsKeyringBackend mutex, and fixed hybrid password-unlock test; closed sub-phase-0002; switched executor to claude (--model opus --effort medium) for complex async russh/runtime phases and delegated phase-0003 (sub-phase-0003)
- phase-0003 done: conduit-ssh (error, host_key, agent, handler, chain) implemented; 42 tests pass including in-process multi-hop loopback; workspace 118 pass; clippy clean
- planner reviewed and accepted phase-0003; closed sub-phase-0003; delegated phase-0004 to claude (--model opus --effort medium) (sub-phase-0004)
- phase-0004 done: RusshDialer, StatsDialer, ReverseRelay, in-process SSH harness and 12 loopback tests; conduit-ssh 64 tests pass, workspace 140 pass, clippy clean; Cargo.lock gained one line for the new dependency
- planner reviewed and accepted phase-0004; closed sub-phase-0004; updated phase-0005 context/scope and delegated phase-0005 to claude (--model opus --effort medium) (sub-phase-0005)
- phase-0005 done: conduit-runtime (state, events, logs, backoff, hardening, runner, manager) implemented; 46 runtime tests pass, workspace 186 pass, clippy clean; RusshLink success path is left for phase-0006 loopback E2E
- planner reviewed and accepted phase-0005; closed sub-phase-0005; clarified phase-0006 MITM E2E context/scope and delegated phase-0006 to claude (--model opus --effort medium) (sub-phase-0006)
- phase-0006 done: 7 E2E runtime tests in crates/conduit-runtime/tests/e2e_runtime.rs (concurrent sessions, reconnect, 4 security gates, MITM); workspace 193 pass, clippy clean; no src changes
- planner reviewed and accepted phase-0006; closed sub-phase-0006; Gate D passed clean (193 tests, clippy clean, zero scope drift, zero forbidden crypto); status set to awaiting-acceptance
- user accepted goal and chose squash; soft-reset to baseline df6fea97155a069ef2cc4887f61232e3e3c37c34 and squashed into a single commit retaining .goal-ledger/
