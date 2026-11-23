# phase-0005 — conduit-runtime SessionManager, state machine, backoff, logs & events

- Status: done
- Owner: executor
- Depends on: phase-0001, phase-0002, phase-0003, phase-0004
- Goal: Implement `conduit-runtime` with `SessionManager`, full session state machine, bounded log ring buffers, live stats, exponential backoff reconnect with account-lockout protection, vault lock/unlock gating, host-key approval flow, and debounced sleep/wake hooks.
- Done when: `cargo test -p conduit-runtime && cargo clippy --workspace --all-targets -- -D warnings` exits 0 with unit tests covering state transitions, backoff reset, lockout halt, log ring buffer bounding/redaction, and debounced wake handling.
- Pattern to follow: `/home/j.baking/Workspace/github/rusty-conduit-ssh/src/lib.rs:106` (`run_until` startup and graceful shutdown order)

## Context
`conduit-runtime` is the UI-agnostic supervisor that Tauri commands and the system tray will drive in Phase 2.
Key decisions already made:
- State machine: `Stopped`, `Starting`, `Connected`, `Reconnecting { attempt, next_retry_secs }`, `WaitingForNetwork`, `Locked`, `AwaitingHostKey(HostKeyPrompt)`, `NeedsAttention { reason }`, `Failed { reason }`.
- Graceful startup/shutdown order mirrors `rusty_conduit_ssh::run_until`: start `AccessLogger` → start `ReverseProxy` (survives reconnects) → connect SSH chain → wire `tcpip-forward` → start forward `Server` (with `MitmState`, `FilteredDialer`, `StatsDialer`). On shutdown: drain forward `Server` → tear down SSH chain → drain `ReverseProxy` → flush `AccessLogger`.
- Keep forward listeners bound while reconnecting (`RusshDialer` returns `NotConnected`). Reset exponential backoff only after 5s of stable uptime.
- **Account Lockout Protection:** on `SshError::AuthFailed` or `SshError::HostKeyChanged`, immediately halt reconnects and transition to `NeedsAttention`. Never auto-retry bad credentials.
- If vault is locked when starting a session that requires secrets, transition to `Locked`; sessions requiring no secrets may still start.
- Wake-from-sleep events debounce 2–5s (configurable for tests) and proactively recycle only `Connected` or `Reconnecting` sessions (never `Stopped` or `NeedsAttention`).
- On each SSH chain connect/reconnect when reverse forwarding is enabled, create a fresh `conduit_ssh::reverse_policy` and `ReverseRelay::start` (the policy receiver is consumed per connection).
- For `AuthMethod::KeyboardInteractive` (whose `conduit-core` variant currently stores only `prompts: Vec<String>` without `SecretRef`), pass an empty answer list or map any configured vault answers if present; do not modify `conduit-core`.

## Scope
- In: `Cargo.toml`, `Cargo.lock`, `crates/conduit-runtime/**`
- Out: `crates/conduit-core/**`, `crates/conduit-vault/**`, `crates/conduit-ssh/**`, `docs/MASTER-PLAN.md`

## Sub-tasks
1. [done] Implement `crates/conduit-runtime/src/state.rs` and `crates/conduit-runtime/src/events.rs` defining `SessionState`, `HostKeyPrompt`, `SessionSnapshot`, `SessionStatsSnapshot`, and `RuntimeEvent` broadcast channel — done when: `cargo test -p conduit-runtime state` exits 0
2. [done] Implement `crates/conduit-runtime/src/logs.rs` providing bounded `LogRingBuffer` (default 2,000 lines, query/clear/subscribe) and `std::io::Write` / `tokio::io::AsyncWrite` adapters for `rusty_conduit_ssh::logging::Logger::with_writer` and `AccessLogger::start_with_stdout` — done when: `cargo test -p conduit-runtime logs` exits 0
3. [done] Implement `crates/conduit-runtime/src/backoff.rs` and `crates/conduit-runtime/src/hardening.rs` (exponential backoff with 5s stable-uptime reset, plus cross-platform `disable_core_dumps()` using `PR_SET_DUMPABLE=0` on Linux and `setrlimit(RLIMIT_CORE, 0)` on Unix) — done when: `cargo test -p conduit-runtime backoff` exits 0
4. [done] Implement `crates/conduit-runtime/src/runner.rs` driving a single session end-to-end: resolving secrets from `Vault`, validating & building `rusty_conduit_ssh::Config`, running `ReverseProxy` + `RusshChain` + `RusshDialer` + `StatsDialer` + `FilteredDialer` + `MitmState` + `Server`, handling reconnects, host-key approval oneshot/re-start, and lockout-safe error halts — done when: `cargo check -p conduit-runtime` exits 0
5. [done] Implement `crates/conduit-runtime/src/manager.rs` (`SessionManager`) managing multiple concurrent sessions (`start`, `stop`, `restart`, `start_all`, `stop_all`, `start_autostart_staggered`, `on_vault_unlocked`, `approve_host_key`, `reject_host_key`, `notify_system_wake` with configurable debounce, `snapshots`, `logs`, `subscribe_events`) — done when: `cargo test -p conduit-runtime` exits 0
6. [done] Fix-up: release the known-hosts read guard before the await in the `approve_never_overwrites_a_different_pin` test (clippy::await_holding_lock) — done when: the phase Verify block exits 0

## Verify
```sh
cargo test -p conduit-runtime && cargo clippy --workspace --all-targets -- -D warnings
```

## Escalate when
- `rusty_conduit_ssh::logging::Logger::with_writer` or `AccessLogger::start_with_stdout` has a different signature or visibility than expected → stop, set Status: needs-human — reason: exact signature/visibility in `../rusty-conduit-ssh/src/logging.rs`

## Log
- (append-only, one line per event)
- sub-task 1: added state.rs (SessionState, transitions, StateCell, snapshots) and events.rs (RuntimeEvent, EventBus); added tokio-util workspace dep
- sub-task 2: added logs.rs (LogRingBuffer, redact, LogWriter sync+async adapters); signatures of Logger::with_writer and AccessLogger::start_with_stdout matched the phase
- sub-task 3: added backoff.rs (doubling, cap, 5s stable reset, 100ms floor) and hardening.rs (PR_SET_DUMPABLE=0, RLIMIT_CORE=0)
- sub-task 4: added runner.rs (Link/Engine seams, supervise loop, SshError classification, vault-per-attempt hop resolution, RusshLink startup/shutdown order, passphrase scrubbing)
- sub-task 5: added manager.rs (SessionManager lifecycle, autostart stagger, vault resume, host-key approve/reject, debounced wake, snapshots, logs, events)
- fix-up 6: first Verify failed on clippy::await_holding_lock in one manager test; released the guard before the await

## Evidence
- (append-only: command → observed result)
- cargo test -p conduit-runtime state → 6 passed, 0 failed
- cargo test -p conduit-runtime logs → 10 passed, 0 failed
- cargo test -p conduit-runtime backoff → 5 passed, 0 failed; cargo test -p conduit-runtime hardening → 1 passed
- cargo check -p conduit-runtime → exit 0
- cargo test -p conduit-runtime → 46 passed, 0 failed
- cargo test -p conduit-runtime && cargo clippy --workspace --all-targets -- -D warnings → exit 0 (46 passed, clippy clean); cargo test --workspace → 186 passed, 0 failed; 10 repeat runs of the runtime lib tests before the fix-up → 0 failures
