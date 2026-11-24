# phase-0002 — conduit-runtime: wire AgentForwardRelay, audit logs & E2E flake hardening

- Status: done
- Owner: executor
- Depends on: phase-0001
- Goal: Wire per-hop `AgentForwardRelay` into `conduit-runtime`'s `RusshLink` (loading only `hop.agent_forward_keys` from `Vault`, logging every agent signature audit event into `LogRingBuffer`, tearing down cleanly on disconnect/reconnect), add a runtime E2E test for scoped agent forwarding, and harden `e2e_runtime.rs` against transient ephemeral port collisions.
- Done when: `cargo test -p conduit-runtime && cargo clippy --workspace --all-targets -- -D warnings` exits 0 with passing E2E tests for scoped agent forwarding (including audit log capture) and 10 consecutive flake-free runs of `e2e_runtime`.
- Pattern to follow: `crates/conduit-runtime/src/runner.rs:726` (`RusshLink::connect` reverse relay wiring)

## Context
In Milestone 2 `phase-0006`, `concurrent_sessions_stay_isolated` hit a rare `Address already in use` flake because `free_port()` binds and drops a TCP socket before `SessionManager` later binds it. Also `runner.rs` currently leaves `hop.agent_forward` unwired.
Key decisions already made:
- Only start `AgentForwardRelay` on hops where `hop.agent_forward == true` AND `!hop.agent_forward_keys.is_empty()`. (If `agent_forward == true` with empty keys, log a clear notice and do not open an agent channel.)
- `needs_secrets(profile)` in `runner.rs` must also return `true` if any hop has `agent_forward && !agent_forward_keys.is_empty()` so a locked vault parks the session in `Locked`.
- Every signature audit event from `ScopedAgent` (allowed or refused, including hop_id, key fingerprint, and algorithm — NEVER private key material) is pushed to the session's `LogRingBuffer` with prefix `[agent-audit]`.
- On reconnect, build a fresh `agent_policy` and `AgentForwardRelay` per opted-in hop (just like `reverse_policy`), and stop/drop previous relays in `drop_connection()` / `shutdown()`.

## Scope
- In: `crates/conduit-runtime/src/**`, `crates/conduit-runtime/tests/**`, `crates/conduit-ssh/src/agent.rs` (only to add `pub algorithm: String` to `SignAudit` and populate it in `ScopedAgent`)
- Out: `crates/conduit-core/**`, `crates/conduit-vault/**`, `crates/conduit-ssh/**` (except `crates/conduit-ssh/src/agent.rs`), `crates/conduit-tray/**`, `src-tauri/**`, `docs/MASTER-PLAN.md`

## Sub-tasks
1. [done] Update `crates/conduit-runtime/src/runner.rs`: include `agent_forward_keys` in `needs_secrets`, resolve vaulted keys for opted-in hops into `ScopedAgent` with a `LogRingBuffer` audit callback (`[agent-audit]`), attach `agent_policy` to each opted-in hop's `ChannelPolicy`, start `AgentForwardRelay`s after `connect_chain`, and cleanly stop/drop them on `drop_connection` and `shutdown` — done when: `cargo test -p conduit-runtime --lib` exits 0
2. [done] Add E2E test `scoped_agent_forwarding_exposes_only_assigned_keys_and_audits_logs` in `crates/conduit-runtime/tests/e2e_runtime.rs` verifying: locked vault parks an agent-forwarding session, after unlock the remote server sees only the assigned key, signs cleanly, and `[agent-audit]` appears in `manager.logs(id)` without leaking private key material — done when: `cargo test -p conduit-runtime --test e2e_runtime scoped_agent_forwarding` exits 0
3. [done] Harden `crates/conduit-runtime/tests/e2e_runtime.rs` against transient `free_port()` port collisions (e.g., use OS-assigned distinct loopback ports or retry-safe port allocation so parallel tests never collide on the same ephemeral port) and verify 10 consecutive runs pass with 0 failures — done when: `cargo test -p conduit-runtime && cargo clippy --workspace --all-targets -- -D warnings` exits 0

## Verify
```sh
cargo test -p conduit-ssh -p conduit-runtime && cargo clippy --workspace --all-targets -- -D warnings
```

## Escalate when
- `SshChain` in `conduit-ssh` is missing a needed accessor for per-hop `Handle<HopHandler>` → stop, set Status: needs-human — reason: exact missing accessor in `conduit-ssh`

## Log
- (append-only, one line per event)
- sub-task 1: read the phase-0001 agent API before editing and found SignAudit has no algorithm field; stopped with no code changes and escalated
- planner approved Option A: added crates/conduit-ssh/src/agent.rs to Scope: In for SignAudit.algorithm and expanded Verify to include conduit-ssh; resumed sub-m3-phase-0002 from sub-task 1
- sub-task 1: added SignAudit.algorithm; wired per-hop agents into RusshLink with [agent-audit] logging, fresh relays per connect, and teardown in drop_connection
- sub-task 2: added scoped_agent_forwarding_exposes_only_assigned_keys_and_audits_logs covering locked vault, key scoping, signing, refusal audit, reconnect, and no key leakage
- sub-task 3: replaced free_port in e2e_runtime.rs with a per-process counter in 20000-29999, below the OS ephemeral range, plus a bind probe
- note for planner: a connected session keeps signing after the vault locks, because lock_vault leaves connected sessions up (src-tauri/src/controller.rs:463)

## Evidence
- (append-only: command → observed result)
- `grep -rn -i "algorithm\|algo" crates/conduit-ssh/src/agent.rs crates/conduit-ssh/src/agent_relay.rs crates/conduit-ssh/src/agent_wire.rs` → no algorithm in SignAudit (agent.rs:59-64); only RSA flag handling in agent_wire.rs and test key generation in agent.rs
- `grep -rn "SignAudit {" crates src-tauri --include=*.rs` (non-test paths) → the struct is built only at agent.rs:134 and agent.rs:153, so option A stays within agent.rs
- `cargo test -p conduit-runtime --lib` → 48 passed, 0 failed
- `cargo test -p conduit-runtime --test e2e_runtime scoped_agent_forwarding` → 1 passed, 0 failed
- `cargo test -p conduit-runtime --test e2e_runtime` x10 consecutive → 10 of 10 runs passed, 8 passed and 0 failed each, no `Address already in use`
- `cargo test -p conduit-ssh -p conduit-runtime` → exit 0 (runtime 48 + 8 E2E; ssh 63 + 5 agent loopback + 12 multihop)
- `cargo clippy --workspace --all-targets -- -D warnings` → exit 0
