# phase-0005 — Add headless U2 integration tests and run full verification suite

- Status: done
- Owner: executor
- Depends on: phase-0004
- Goal: Add a comprehensive headless U2 integration test suite (`crates/conduit-runtime/tests/u2_tunnels_proxies.rs`) covering all §10 U2 scenarios and verify the entire workspace CI suite passes.
- Done when: All 6+ headless U2 integration tests pass reliably and the complete `Full verification` command (Rust, Python, Frontend) exits 0.
- Pattern to follow: `crates/conduit-runtime/tests/e2e_runtime.rs:1-120`, `docs/MASTER-PLAN.md:328-331`

## Context
- `docs/MASTER-PLAN.md` §10 U2 requires headless tests covering:
  1. **Multi-Proxy routing:** two Proxies running concurrently (e.g., one plain `direct` Proxy and one Auto Switch Proxy with rules routing one host to an upstream HTTP/SOCKS5 proxy, another host to an SSH Tunnel, and default to `direct`), verifying per-profile and per-rule traffic counters accumulate accurately.
  2. **Tunnel failover:** a Proxy with failover chain `["bastion", "direct"]` falls through to `direct` while the `bastion` Tunnel is stopped/down, and routes through `bastion` once the Tunnel is connected (also verifying `Linked` tunnel auto-start/stop).
  3. **Zero-downtime hot-reload under active `CONNECT` and SOCKS5 tunnels:** open a live HTTP `CONNECT` tunnel and a live SOCKS5 tunnel through a running Proxy, hot-reload the Proxy's routing rules (bumping `config_generation` from 0 to 1), verify both in-flight tunnels continue exchanging data without dropping, and verify new connections follow the new rule while counters keep accumulating.
  4. **Tray override swap & restore:** switch a running Auto Switch Proxy to `Force Direct`, verify traffic bypasses rules and goes direct; switch to `Force <profile>`, verify traffic goes to that profile; restore to `Auto Switch` (`None`), verify rules take effect again.
  5. **Cross-Proxy and reverse-listener self-loop detection:** verify a Proxy whose upstream profile points to another running Proxy's listener OR a running Tunnel's reverse-proxy local listener is rejected at start and on hot-reload (leaving the running Proxy's previous routing intact on failed reload).
  6. **§6.4 `v0.1.0` migration round-trip:** write a v1 `AppConfig` JSON with a `SessionProfile` to disk, run `load_or_migrate_app_config`, verify `config.v1.bak.json` is created, `schema_version == 2`, `tunnels` + `proxies` are populated, and start the migrated Proxy + Linked Tunnel to serve real proxied traffic end-to-end.
- Also include a test for `test_route` and `test_upstream` against live local listeners.
- Always use `CARGO_NET_GIT_FETCH_WITH_CLI=true` when running cargo commands.

## Scope
- In: `crates/conduit-runtime/tests/u2_tunnels_proxies.rs` (create)
- Out: `Cargo.toml`, `crates/conduit-core/`, `crates/conduit-vault/`, `crates/conduit-ssh/`, `crates/conduit-openssh/`, `crates/conduit-tray/`, `src-tauri/`, `.github/`, `scripts/`, `docs/`

## Sub-tasks
1. [done] Create `crates/conduit-runtime/tests/u2_tunnels_proxies.rs` with reusable in-process echo/HTTP origin and in-process `russh` server helpers, and implement tests for (1) multi-Proxy routing + counters and (2) Tunnel failover (`["bastion", "direct"]`) + `Linked` lifecycle — done when: both tests pass under `cargo test -p conduit-runtime --test u2_tunnels_proxies`.
2. [done] Add tests to `crates/conduit-runtime/tests/u2_tunnels_proxies.rs` for (3) zero-downtime hot-reload under active HTTP `CONNECT` and SOCKS5 tunnels and (4) tray override swap/restore — done when: both tests pass reliably.
3. [done] Add tests to `crates/conduit-runtime/tests/u2_tunnels_proxies.rs` for (5) cross-Proxy & reverse-listener self-loop detection (at start and on hot-reload), (6) §6.4 `v0.1.0` migration round-trip serving real traffic, and (7) `test_route` + `test_upstream` — done when: all tests in `u2_tunnels_proxies` pass.
4. [done] Run the complete `## Verify` command (Rust clippy + workspace tests + `secret_leak_scan` + Linux tray check + Python checks + frontend check/test/build) and record observed results in `## Evidence` — done when: every check exits 0.

## Verify
```sh
CARGO_NET_GIT_FETCH_WITH_CLI=true cargo clippy --workspace --all-targets -- -D warnings && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test --workspace && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p rusty-conduit-gui --test secret_leak_scan && CARGO_NET_GIT_FETCH_WITH_CLI=true RUSTFLAGS="--cfg conduit_check_tauri_tray" cargo check -p rusty-conduit-gui --tests --features tauri/tray-icon && python3 scripts/check-pure-rust-crypto.py && python3 scripts/validate-release-config.py && python3 scripts/smoke-test-bundle.py --self-test && (cd src-tauri/ui && npm run check && npm test && npm run build)
```

## Escalate when
- An integration test reveals a bug in `conduit-core` or `conduit-runtime` source files (which are Out of scope for this phase) → stop, set Status: needs-human — reason: describe the exact bug and failing test so the planner can open a fix-up

## Log
- (append-only, one line per event)
- sub-task 1: created `crates/conduit-runtime/tests/u2_tunnels_proxies.rs` with hermetic HOME, range-based free_port, in-process russh node (shared `conduit-ssh/tests/common`), echo/HTTP origins, a minimal upstream HTTP CONNECT proxy, and tests (1) `two_proxies_route_concurrently_and_count_per_profile_and_rule` and (2) `failover_chain_falls_through_to_direct_while_the_tunnel_is_down`
- sub-task 2: added (3) `hot_reload_keeps_live_connect_and_socks_tunnels_and_counters` and (4) `tray_override_swaps_and_auto_switch_restores_rules`
- sub-task 3: added (5) `self_loops_to_other_proxies_and_reverse_listeners_are_rejected`, (6) `v1_config_migrates_and_the_migrated_proxy_serves_traffic`, (7) `route_tester_and_test_upstream_against_live_listeners` (sub-tasks 1-3 were written in one file pass and checked together)
- sub-task 4: full `## Verify` failed with ENOSPC (disk full) during clippy, before any check of the new file ran; escalated
- planner recovery: after `target/` was cleared (25G free), planner took over sub-task 4 with `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0`; full `## Verify` exited 0 (`target/` kept at 4.1G)

## Evidence
- (append-only: command → observed result)
- `CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p conduit-runtime --test u2_tunnels_proxies` → `test result: ok. 7 passed; 0 failed` (0.75s)
- same command repeated 8 times in a loop → 8/8 `test result: ok. 7 passed; 0 failed`
- full `## Verify` command → EXIT=101; `error: failed to write query cache to .../target/debug/incremental/conduit_tray-.../query-cache.bin: No space left on device (os error 28)`; `could not compile conduit-tray / conduit-runtime / rusty-conduit-gui`
- `df -h .` → `/dev/sda2 126G 120G 0 100% /`; `du -sh target` → `25G`
- planner `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0` full `## Verify` → EXIT=0: clippy `-D warnings` clean; all workspace tests pass (incl. 7/7 `u2_tunnels_proxies`); `secret_leak_scan` pass; Linux tray check pass; `PURE_RUST_CRYPTO_OK`, `RELEASE_CONFIG_OK`, `SMOKE_TEST_SELF_TEST_OK`; frontend `npm run check` / `npm test` (78/78) / `npm run build` pass; `target/` 4.1G (21G free)
