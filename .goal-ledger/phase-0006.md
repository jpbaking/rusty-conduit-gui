# phase-0006 — End-to-end runtime integration tests & hardening verification

- Status: done
- Owner: executor
- Depends on: phase-0005
- Goal: Verify the complete headless stack (`conduit-core` + `conduit-vault` + `conduit-ssh` + `conduit-runtime` + `rusty_conduit_ssh`) via comprehensive end-to-end integration tests covering concurrent sessions, reconnects, lockout protection, host-key approval, vault locking, filters, MITM, and zero `~/.ssh` access.
- Done when: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings` exits 0 with all E2E tests in `crates/conduit-runtime/tests/e2e_runtime.rs` passing cleanly.
- Pattern to follow: `crates/conduit-ssh/tests/loopback_multihop.rs`

## Context
This phase proves the overall goal's "Done when" criteria across crate boundaries before Gate D planner review. Every test runs hermetically against in-process `russh` test servers on loopback with `HOME` pointing to an isolated temp directory containing no `.ssh` folder.
Note on MITM E2E: `MitmState::from_config` uses `rustls-platform-verifier` for upstream origin TLS verification (it will not trust a self-signed loopback origin certificate without OS root trust). For `mitm_through_runtime`, generate a passphrase-protected CA (PKCS#12 or encrypted PEM) stored in temp files with its passphrase in `Vault`, verify `SessionManager` loads the CA via `Vault`, performs a real `CONNECT` + client TLS handshake through the `russh` tunnel where the proxy presents a dynamically minted leaf cert signed by the test CA, and logs `mitm=true` in the session's `LogRingBuffer` (without needing OS-trusted upstream roots).

## Scope
- In: `Cargo.toml`, `Cargo.lock`, `crates/conduit-runtime/tests/**`, `crates/conduit-runtime/Cargo.toml` (dev-dependencies if needed), plus small bug fixes in `crates/conduit-*/src/**` only if an E2E test uncovers a defect
- Out: `docs/MASTER-PLAN.md`, `../rusty-conduit-ssh/**`

## Sub-tasks
1. [done] Build E2E test fixture in `crates/conduit-runtime/tests/e2e_runtime.rs` setting up isolated temp `app_data` dir, `Vault`, `KnownHostsStore`, `SessionManager`, and in-process `russh` servers — done when: `cargo test -p conduit-runtime --test e2e_runtime -- --list` exits 0
2. [done] Add E2E test for concurrent sessions (two sessions running simultaneously: one 3-hop forward HTTP+SOCKS5h with forward allow/block filter, one with reverse proxy `-R`) verifying traffic isolation, live stats counters, and ring-buffer log capture — done when: `cargo test -p conduit-runtime --test e2e_runtime concurrent_sessions` exits 0
3. [done] Add E2E test for intermediate hop drop → `Reconnecting` → automatic recovery with forward listener staying bound and proxy requests succeeding after reconnect — done when: `cargo test -p conduit-runtime --test e2e_runtime reconnect_after_drop` exits 0
4. [done] Add E2E tests for security gates: (a) bad password halts immediately in `NeedsAttention` with exactly 1 auth attempt (no lockout retry), (b) unknown host key pauses in `AwaitingHostKey` and connects after `approve_host_key`, (c) changed host key halts in `NeedsAttention`, and (d) locked vault puts secret-dependent session in `Locked` until `on_vault_unlocked` — done when: `cargo test -p conduit-runtime --test e2e_runtime security_gates` exits 0
5. [done] Add E2E test for HTTPS MITM through a `SessionManager`-managed `russh` tunnel using a generated test CA stored in temp files + passphrase in `Vault`, verifying intercepted HTTPS response and access log entry — done when: `cargo test -p conduit-runtime --test e2e_runtime mitm_through_runtime` exits 0

## Verify
```sh
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings
```

## Escalate when
- Any E2E test exposes an architectural flaw requiring changes to `../rusty-conduit-ssh` or a phase re-scope → stop, set Status: needs-human — reason: exact failing scenario and root cause

## Log
- (append-only, one line per event)
- sub-task 1: added e2e_runtime.rs fixture (hermetic HOME, temp app_data, Vault, KnownHostsStore, SessionManager, in-process russh nodes) and TLS dev-dependencies
- sub-task 2: added concurrent_sessions_stay_isolated (3-hop forward with allowlist + 1-hop reverse, simultaneous traffic, per-session stats and logs)
- sub-task 3: added reconnect_after_drop_recovers_on_the_same_listeners (hop 1 dropped, Reconnecting observed, same listeners, HTTP and SOCKS work after recovery)
- sub-task 4: added four security_gates tests (bad password, unknown host key, changed host key, locked vault) against real russh servers
- sub-task 5: added mitm_through_runtime_intercepts_https (encrypted PKCS#12 CA, passphrase in Vault, real CONNECT + TLS through russh, minted leaf, mitm=true access record); origin trusted only through a temp SSL_CERT_FILE
- verification passed: 193 workspace tests, clippy clean, E2E suite stable over 10 repeat runs; no src changes were needed

## Evidence
- (append-only: command → observed result)
- cargo test -p conduit-runtime --test e2e_runtime -- --list → exit 0 (0 tests, fixture compiles)
- cargo test -p conduit-runtime --test e2e_runtime concurrent_sessions → 1 passed, exit 0
- cargo test -p conduit-runtime --test e2e_runtime reconnect_after_drop → 1 passed, exit 0
- cargo test -p conduit-runtime --test e2e_runtime security_gates → 4 passed, exit 0
- cargo test -p conduit-runtime --test e2e_runtime mitm_through_runtime → 1 passed, exit 0
- cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings → test exit 0 (193 passed, 0 failed), clippy exit 0
- e2e_runtime binary run 10 times → 0 failures
- strace -f -e trace=%file on e2e_runtime → 7 passed; 7 paths contain .ssh, all ENOENT statx of the temp HOME (the tests' own absence check); 0 outside temp HOME
