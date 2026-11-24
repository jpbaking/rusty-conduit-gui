# phase-0004 — conduit-runtime: wire SshEngine::OpenSsh into runner.rs & real /usr/bin/ssh E2E tests

- Status: done
- Owner: executor
- Depends on: phase-0003
- Goal: Wire `SshEngine::OpenSsh` into `crates/conduit-runtime/src/runner.rs` with full state-machine, lockout protection, host-key TOFU, backoff, `LogRingBuffer`, and `StatsDialer` parity, plus real `/usr/bin/ssh` loopback E2E tests.
- Done when: `cargo test -p conduit-runtime && cargo clippy --workspace --all-targets -- -D warnings` exits 0 with passing real `/usr/bin/ssh` loopback E2E tests in `crates/conduit-runtime/tests/openssh_e2e.rs`.
- Pattern to follow: `crates/conduit-runtime/src/runner.rs:608-920` (`RusshLink` and `impl Link for RusshLink`), `crates/conduit-runtime/tests/e2e_runtime.rs` (runtime E2E test harness), `../rusty-conduit-ssh/src/net.rs:198-235` (`Socks5UpstreamDialer`).

## Context
`crates/conduit-runtime/src/runner.rs` already defines `trait Engine` and `trait Link`, and `RusshLink::prepare` currently returns `LinkError::Fatal("the OpenSSH engine is not available in this build")` at line 639 when `profile.engine == SshEngine::OpenSsh`.
In this phase:
- `RusshEngine::prepare` (or a dispatching `DefaultEngine`) routes `SshEngine::OpenSsh` to `OpenSshLink::prepare`.
- `OpenSshLink` uses `rusty_conduit_ssh::net::Socks5UpstreamDialer` fed by a `watch::Sender<TunnelState>`, wrapped in `StatsDialer` and `FilteredDialer`, driving `build_engines`, `MitmState`, `ReverseProxy`, `Server`, and `AccessLogger`/`LogRingBuffer` identically to `RusshLink`.
- Before launching `OpenSshSupervisor`, `OpenSshLink::connect` checks that every hop has an approved pin with `public_key_openssh` in `known_hosts`; if any hop is unpinned (or missing `public_key_openssh`), it probes the chain's host keys via `conduit_ssh::connect_chain` (or a lightweight host-key probe) to surface `LinkError::HostKey(HostKeyPrompt)` so the exact same `AwaitingHostKey` → `approve_host_key` flow works seamlessly for OpenSSH sessions too!
- Auth failures (`OpenSshError::AuthFailed`) and changed host keys (`OpenSshError::HostKeyChanged`) map to `LinkError::Attention` (zero retries, preventing account lockout). Unsupported binary / invalid config maps to `LinkError::Fatal`. Unexpected `ssh` exit / network drop maps to `LinkError::Transient`.
- `OpenSshLink::disconnect` updates `TunnelState::Disconnected(...)` and stops the supervisor via `supervisor.shutdown().await` (preferring `shutdown().await` over bare drop so `ssh` is terminated and reaped before the runtime dir is removed) while keeping forward listeners bound; `OpenSshLink::shutdown` drains `Server` → stops supervisor → drains `ReverseProxy` → flushes `AccessLogger`.
- Note from phase-0003: `OpenSshSupervisor` expects validated `extra_args` (already enforced by `conduit_core::validate(&profile)` in `prepare`). During `conduit-runtime` integration tests, ensure `conduit-worker` is built (`cargo build -p conduit-openssh --bin conduit-worker`) and located via `target/debug/conduit-worker` (sibling of `current_exe().parent().parent()`).

## Scope
- In: `crates/conduit-runtime/Cargo.toml`, `crates/conduit-runtime/src/runner.rs`, `crates/conduit-runtime/src/manager.rs`, `crates/conduit-runtime/tests/openssh_e2e.rs`, `Cargo.lock`
- Out: `docs/MASTER-PLAN.md`, `../rusty-conduit-ssh/**`, `crates/conduit-core/**`, `crates/conduit-ssh/**`, `crates/conduit-openssh/**`, `src-tauri/**`

## Sub-tasks
1. [done] Add `conduit-openssh = { path = "../conduit-openssh" }` to `crates/conduit-runtime/Cargo.toml` and implement `OpenSshLink` in `crates/conduit-runtime/src/runner.rs` (dispatched when `profile.engine == SshEngine::OpenSsh`), with full parity for `validate`, vault unlock check (`LinkError::Locked`), `check_openssh_binary` validation, `AccessLogger` + `LogRingBuffer`, `ReverseProxy` (`-R` specs), `Socks5UpstreamDialer` wrapped in `StatsDialer` + `FilteredDialer`, `MitmState`, `Server` bound once across reconnects, `AwaitingHostKey` host-key check, lockout-safe error classification (`LinkError::Attention`), and graceful shutdown — done when: `cargo test -p conduit-runtime --lib` passes.
2. [done] Add real `/usr/bin/ssh` loopback E2E tests in `crates/conduit-runtime/tests/openssh_e2e.rs` driving `SessionManager` with `SshEngine::OpenSsh`: (a) single-hop key auth + HTTP/SOCKS proxy roundtrip verifying `StatsSnapshot` counters increment and `LogRingBuffer` captures logs, (b) password auth via `conduit-worker askpass` + HTTP proxy roundtrip, (c) bad password transitions immediately to `SessionState::NeedsAttention` with zero retries, (d) host-key mismatch transitions to `SessionState::NeedsAttention`, and (e) clean `stop()` leaves no lingering `ssh` child process — done when: `cargo test -p conduit-runtime --test openssh_e2e` passes.

## Verify
```sh
cargo build -p conduit-openssh --bin conduit-worker && cargo test -p conduit-runtime && cargo clippy --workspace --all-targets -- -D warnings
```

## Escalate when
- `conduit-openssh` API is missing a required field or method (e.g. `-R` reverse forward specs or stderr log callback) needed by `OpenSshLink` → stop, set `Status: needs-human — reason: <exact API gap in conduit-openssh>`
- `conduit-worker` binary is not automatically built before `cargo test -p conduit-runtime` (note: in Cargo, integration tests in `conduit-runtime` do not automatically build binaries from a dependency crate unless `cargo build -p conduit-openssh --bin conduit-worker` ran or a helper builds/locates it) → stop, set `Status: needs-human — reason: <describe worker binary discovery issue>`

## Log
- (append-only, one line per event)
- sub-task 1: added OpenSshLink and DefaultEngine dispatch in runner.rs, moved shared proxy setup into ProxyStack used by both engines, switched manager.rs to DefaultEngine
- sub-task 2: added crates/conduit-runtime/tests/openssh_e2e.rs with 8 real /usr/bin/ssh tests; test helper builds conduit-worker and passes its path through CARGO_BIN_EXE_conduit-worker
- sub-task 2 stopped after two failed check runs; port-collision fix not attempted
- planner unblocked: approved port-collision fix (allocate test ports below ephemeral range as in `e2e_runtime.rs:297-315` and make `OpenSshLink::socks_port()` skip the profile's `forward.http_port`/`forward.socks_port`). Confirmed `agent_forward` on OpenSSH should log a clear notice and continue (per Master Plan Section 3.1 `ssh -N` limitation). Run full `## Verify` including `e2e_runtime` and `openssh_e2e`.
- sub-task 2: applied the approved fix: test forward ports now come from 30000-31999, below the ephemeral range, and OpenSshLink::socks_port skips the profile forward ports
- phase verified and closed

## Evidence
- (append-only: command → observed result)
- `cargo test -p conduit-runtime --lib` → test result: ok. 50 passed; 0 failed
- `cargo test -p conduit-runtime --test openssh_e2e` (run 1) → FAILED 0 passed, 8 failed: conduit-worker was not found near target/debug/build/conduit-runtime/<hash>/out/openssh_e2e-<hash>
- `cargo test -p conduit-runtime --test openssh_e2e` (run 2) → FAILED 7 passed, 1 failed: key_auth_carries_http_and_socks_with_stats_and_logs, failed to bind SOCKS4/4a/5 listener on 127.0.0.1:41797: Address already in use (os error 98)
- `cargo clippy --workspace --all-targets -- -D warnings` → exit 0
- `cargo test -p conduit-runtime --lib` → test result: ok. 50 passed; 0 failed
- full ## Verify block → not run to completion, because sub-task 2 is blocked
- `cargo test -p conduit-runtime --test openssh_e2e` (run 3, after approved fix) → test result: ok. 8 passed; 0 failed
- `cargo build -p conduit-openssh --bin conduit-worker && cargo test -p conduit-runtime && cargo clippy --workspace --all-targets -- -D warnings` → exit 0; lib 50 passed, e2e_runtime 8 passed, openssh_e2e 8 passed, doc 0
- `cargo test -p conduit-runtime --test openssh_e2e` repeated 5 times → 8 passed, 0 failed each run, no `Address already in use`
- `ps -axww -o command= | grep -cE '^[/]usr/bin/ssh -F'` after all runs → 0 leftover ssh processes
