# GOAL — U2 Tunnels + Proxies Model

## Goal
- Goal ID: 20261126-u2-tunnels-proxies
- Outcome: Implement Milestone U2 (`docs/MASTER-PLAN.md` §5, §6.4, §8.2, §10 U2): split `conduit-core` into `Tunnel`, `Proxy`, `UpstreamProfile` (including `tunnel`), routing rules, validation, engine mapping, and §6.4 `v0.1.0` migration; add upstream-password record support in `conduit-vault`; build `TunnelManager` and `ProxyManager` in `conduit-runtime` (Linked/Manual start modes, zero-downtime `ArcSwap` hot-reload, tray overrides, Route Tester, Test Upstream probe, per-rule/profile counters); and verify with headless integration tests while keeping legacy `SessionProfile`/`SessionManager` intact until U3.
- Done when: All headless U2 integration tests (multi-Proxy routing, Tunnel failover, hot-reload under active `CONNECT` and SOCKS5 tunnels, override swap/restore, cross-Proxy and reverse-listener self-loop detection, §6.4 migration round-trip) and the full local CI suite (`clippy -D warnings`, `cargo test --workspace`, `secret_leak_scan`, Linux tray check, `check-pure-rust-crypto.py`, `validate-release-config.py`, `smoke-test-bundle.py --self-test`, and frontend `npm run check && npm test && npm run build`) pass with zero errors.
- Goal status: completed
- Goal status meaning: drafting | approved | executing | blocked-on-human | in-review | awaiting-acceptance | completed | abandoned
- Last completed phase: phase-0005

## Execution
- Execution mode: delegated
- Planner tier: primary session
- Executor tier: herdr-subagent (primary: claude opus 5.5 medium; backup: agy claude opus 5.5 medium)
- Full verification: CARGO_NET_GIT_FETCH_WITH_CLI=true cargo clippy --workspace --all-targets -- -D warnings && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test --workspace && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p rusty-conduit-gui --test secret_leak_scan && CARGO_NET_GIT_FETCH_WITH_CLI=true RUSTFLAGS="--cfg conduit_check_tauri_tray" cargo check -p rusty-conduit-gui --tests --features tauri/tray-icon && python3 scripts/check-pure-rust-crypto.py && python3 scripts/validate-release-config.py && python3 scripts/smoke-test-bundle.py --self-test && (cd src-tauri/ui && npm run check && npm test && npm run build)

## Git
- Repository: yes
- Strategy: isolated-branch
- Starting branch: feat/one-gui
- Work branch: goal/20261126-u2-tunnels-proxies
- Baseline commit: 874ec3f1897f21ca23915ded883d18eb3ad8fbb1
- Starting upstream at start: origin/feat/one-gui@5ad227c55f4815e91c3354f7736b6c105917bf28
- Work upstream at start: none

## Phases
- [done] phase-0001 — Add Tunnel, Proxy, UpstreamProfile, and routing models to conduit-core and upstream-password record to conduit-vault
- [done] phase-0002 — Add Tunnel/Proxy validation, engine mapping, and §6.4 v0.1.0 migration in conduit-core
- [done] phase-0003 — Build TunnelManager in conduit-runtime
- [done] phase-0004 — Build ProxyManager in conduit-runtime (hot-reload, overrides, Route Tester, Test Upstream, counters)
- [done] phase-0005 — Add headless U2 integration tests and run full verification suite

## Handoff
- Current position: completed
- Next role: planner
- Next action: none
- Last verified evidence: user accepted and squashed U2 into one clean commit on `goal/20261126-u2-tunnels-proxies` and merged into `feat/one-gui`; full Gate D verification passed
- Blockers: none

## Review
- Reviewed by: planner (primary session)
- Verification result: pass — Full verification exited 0 across all Rust (`clippy -D warnings`, workspace tests incl. 7 headless U2 integration tests, `secret_leak_scan`, Linux tray check), Python (`PURE_RUST_CRYPTO_OK`, `RELEASE_CONFIG_OK`, `SMOKE_TEST_SELF_TEST_OK`), and Svelte/Node (`npm run check`, 78 tests, `npm run build`) gates
- Diff reviewed: `874ec3f..HEAD` (read across all 5 phases; all files strictly within planned phase scopes)
- Findings: none

## Log
- created ledger with 5 phases for Milestone U2 (replacing completed U1 ledger `20261126-u1-engine`, preserved in git history)
- approved Gates A–C; created isolated branch `goal/20261126-u2-tunnels-proxies` off `feat/one-gui` (`874ec3f1897f`)
- tightened phase-0003 sub-task 1 wording and delegated phase-0001 to herdr-subagent executor (`claude` opus 5.5 medium)
- executor completed phase-0001: v2_model.rs, AppConfig v2 fields, vault upstream-password helpers; Verify exit 0
- planner accepted phase-0001 and delegated phase-0002 to herdr-subagent executor (`claude` opus 5.5 medium)
- executor completed phase-0002: v2_mapping.rs, v2_validate.rs, migrate_v2.rs (+ pub(crate) helper refactors in validate.rs/mapping.rs, zeroize dep); Verify exit 0
- planner accepted phase-0002 and delegated phase-0003 to herdr-subagent executor (`claude` opus 5.5 medium)
- executor completed phase-0003: tunnel_manager.rs (TunnelManager, TunnelSnapshot, TunnelEvent, gated persistent dialer, Linked refcount, reverse/forwards, host keys, wake), pub(crate) runner helpers, ReverseProxy::local_listeners; 1 fix-up (clippy); Verify exit 0
- planner accepted phase-0003 and delegated phase-0004 to herdr-subagent executor (`claude` opus 5.5 medium)
- executor completed phase-0004: proxy_manager.rs (ProxyManager lifecycle, ArcSwap hot-reload with restart_required + counter preservation, tray overrides, Linked tunnel reconcile, Route Tester, Test Upstream, AccessRecordBuffer sink) exported from lib.rs; no Cargo.toml change; Verify exit 0
- planner accepted phase-0004 and delegated phase-0005 to herdr-subagent executor (`claude` opus 5.5 medium)
- executor wrote u2_tunnels_proxies.rs (7 tests, 8/8 green runs); full Verify blocked by disk full (ENOSPC, 0 bytes free, target/ 25G); escalated
- planner recovered after `target/` cleanup, ran full Verify with `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0` (exit 0, `target/` 4.1G), closed phase-0005, and passed Gate D review → `awaiting-acceptance`
- accepted by user; squashed 16 goal commits into one commit retaining `.goal-ledger/`, marked `completed`, and fast-forward merged into `feat/one-gui`
