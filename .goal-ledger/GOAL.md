# GOAL — U1 Move to rusty-conduit-engine

## Goal
- Goal ID: 20261126-u1-engine
- Outcome: Complete Milestone U1 (`docs/MASTER-PLAN.md` §4.2 & §10 U1) by replacing `rusty-conduit-ssh` (`v1.3.0`) with `rusty-conduit-engine` (`v0.2.0`, pinned via git tag), moving `RusshDialer` and `StatsDialer` to `UpstreamStream::Boxed` (dropping the loopback TCP bridge), rebuilding `ReverseProxy` on an engine `Server` with direct egress, loading MITM CAs from memory via `MitmState::from_pem_bytes` (dropping temp-file staging), wiring the OpenSSH dialer through the engine's `Socks5Dialer`, updating CI/release workflows and `docs/TODO.md`, and keeping the v1 session data model intact.
- Done when: All Rust workspace tests, `clippy -D warnings`, `secret_leak_scan`, Linux `conduit_check_tauri_tray` check, `check-pure-rust-crypto.py`, `validate-release-config.py`, `smoke-test-bundle.py --self-test`, and frontend (`npm run check`, `npm test`, `npm run build`) pass with zero errors, and `rusty-conduit-ssh` is completely removed from Cargo dependencies.
- Goal status: completed
- Goal status meaning: drafting | approved | executing | blocked-on-human | in-review | awaiting-acceptance | completed | abandoned
- Last completed phase: phase-0004

## Execution
- Execution mode: delegated
- Planner tier: primary session
- Executor tier: herdr-subagent (primary: claude opus 5.5 medium; backup: agy claude opus 5.5 medium)
- Full verification: CARGO_NET_GIT_FETCH_WITH_CLI=true cargo clippy --workspace --all-targets -- -D warnings && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test --workspace && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p rusty-conduit-gui --test secret_leak_scan && CARGO_NET_GIT_FETCH_WITH_CLI=true RUSTFLAGS="--cfg conduit_check_tauri_tray" cargo check -p rusty-conduit-gui --tests --features tauri/tray-icon && python3 scripts/check-pure-rust-crypto.py && python3 scripts/validate-release-config.py && python3 scripts/smoke-test-bundle.py --self-test && (cd src-tauri/ui && npm run check && npm test && npm run build)

## Git
- Repository: yes
- Strategy: isolated-branch
- Starting branch: feat/one-gui
- Work branch: goal/20261126-u1-engine
- Baseline commit: 5ad227c55f4815e91c3354f7736b6c105917bf28
- Starting upstream at start: origin/feat/one-gui@5ad227c55f4815e91c3354f7736b6c105917bf28
- Work upstream at start: none

## Phases
- [done] phase-0001 — Add rusty-conduit-engine v0.2.0 and port conduit-core
- [done] phase-0002 — Port conduit-ssh and conduit-openssh to rusty-conduit-engine
- [done] phase-0003 — Port conduit-runtime and src-tauri, remove rusty-conduit-ssh
- [done] phase-0004 — Update CI/release workflows, validate-release-config.py, docs/TODO.md, and run full verification

## Handoff
- Current position: completed
- Next role: planner
- Next action: none
- Last verified evidence: user accepted and squashed U1 into one clean commit on `goal/20261126-u1-engine`; full Gate D verification passed
- Blockers: none

## Review
- Reviewed by: planner (primary session)
- Verification result: pass — Full verification exited 0 across all Rust, Python, and Svelte/Node CI gates; `rusty-conduit-ssh` completely removed from Cargo dependencies
- Diff reviewed: `5ad227c..c8e4466` (read in full; 13 matching Goal-ID commits, 37 files changed strictly within planned phase scopes)
- Findings: none

## Log
- created ledger with 4 phases for Milestone U1 (replacing completed U0 ledger `20261126-u0-rebrand`, preserved in git history)
- approved Gates A–C; created isolated branch `goal/20261126-u1-engine` off `feat/one-gui` (`5ad227c55f48`)
- delegated phase-0001 to herdr-subagent executor (`claude` opus 5.5 medium)
- phase-0001 done: conduit-core ported to rusty-conduit-engine v0.2.0 (`to_engine_config`/`EngineConfig`, local `SshIpVersion`); verify passed
- planner accepted phase-0001 and delegated phase-0002 to herdr-subagent executor (`claude` opus 5.5 medium)
- phase-0002 done: conduit-ssh (`RusshDialer`/`StatsDialer` return `UpstreamStream::boxed`, no loopback bridge) and conduit-openssh (`TunnelState`, `OpenSshDialer` over engine `Socks5Dialer`) ported; verify passed; conduit-runtime still fails to build (phase-0003)
- planner accepted phase-0002 and delegated phase-0003 to herdr-subagent executor (`claude` opus 5.5 medium)
- phase-0003 done: conduit-runtime ported (`reverse.rs` engine `Server` reverse proxy with direct egress, in-memory `MitmState::from_pem_bytes`, `mitm_ca_file.rs` deleted, `ssh-tunnel` external routing, `OpenSshDialer`), src-tauri imports switched, `rusty-conduit-ssh` removed from workspace; verify passed after one clippy fix-up
- planner accepted phase-0003 and delegated phase-0004 to herdr-subagent executor (`claude` opus 5.5 medium)
- phase-0004 done: CI/release workflows and validate-release-config.py point at rusty-conduit-engine v0.2.0; docs/TODO.md cleared; full verification passed
- planner accepted phase-0004; Gate D review passed (0 findings); transitioned to `awaiting-acceptance`
- accepted by user; squashed 14 goal commits into one commit retaining `.goal-ledger/` and marked `completed`
