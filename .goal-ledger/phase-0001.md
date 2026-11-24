# phase-0001 — conduit-core + conduit-ssh: scoped agent forwarding wire protocol & loopback tests

- Status: done
- Owner: executor
- Depends on: none
- Goal: Extend `HopEntry` with per-hop `agent_forward_keys` / `agent_forward_command` (`#[serde(default)]`) and implement `AgentForwardRelay` in `conduit-ssh` serving the read-only OpenSSH `ssh-agent` wire protocol over `ScopedAgent` with signature audit callbacks and loopback tests.
- Done when: `cargo test -p conduit-core -p conduit-ssh && cargo clippy --workspace --all-targets -- -D warnings` exits 0 with a loopback test proving an opted-in hop exposes ONLY its explicitly assigned key(s) over `auth-agent@openssh.com`, refuses mutating agent requests, and invokes the audit callback on every sign request.
- Pattern to follow: `crates/conduit-ssh/src/agent.rs` and `crates/conduit-ssh/src/reverse.rs`

## Context
`conduit-ssh` already has `ScopedAgent` (sealed read-only key set with `list_identities`, `sign`, and audit callback) and `HopHandler` (which accepts `server_channel_open_agent_forward` only when `ChannelPolicy::agent_channels` is `Some`).
Key decisions already made:
- Backwards-compatible `conduit-core` schema: add `#[serde(default)] pub agent_forward_keys: Vec<KeyId>` and `#[serde(default)] pub agent_forward_command: Option<String>` to `HopEntry` so existing `config.json` files deserialize cleanly.
- OpenSSH `ssh-agent` wire protocol (`draft-miller-ssh-agent`): 4-byte big-endian length prefix + 1-byte message type + payload:
  - `SSH_AGENTC_REQUEST_IDENTITIES` (11) → `SSH_AGENT_IDENTITIES_ANSWER` (12) containing ONLY the keys assigned to that hop's `ScopedAgent`.
  - `SSH_AGENTC_SIGN_REQUEST` (13) → `SSH_AGENT_SIGN_RESPONSE` (14) on valid signature, or `SSH_AGENT_FAILURE` (5) if key is not in `ScopedAgent` or signing fails; ALWAYS invokes `ScopedAgent`'s audit callback.
  - Every other message type (including `ADD_IDENTITY` 17, `REMOVE_IDENTITY` 18, `REMOVE_ALL` 19, `LOCK` 22, `UNLOCK` 23, `ADD_ID_CONSTRAINED` 25) → `SSH_AGENT_FAILURE` (5), never mutating state.
  - Enforce a sane max packet length (e.g., 256 KiB) to prevent memory exhaustion from a hostile remote host.
- Tunnel-only SSH (`ssh -N`) does not open a session channel, so `AgentForwardRelay::start(handle, hop_index, agent, agent_channels, remote_command)` opens a session channel on that hop's `Handle<HopHandler>`, calls `request_agent_forwarding(true)` (and runs `remote_command` if provided, or keeps the session channel alive cleanly), and spawns a relay task serving every accepted `Channel<Msg>` from `agent_channels` over `ScopedAgent`.

## Scope
- In: `crates/conduit-core/src/model.rs`, `crates/conduit-ssh/src/**`, `crates/conduit-ssh/tests/**`, `crates/conduit-ssh/Cargo.toml`, `Cargo.lock`, `src-tauri/src/controller/test_support.rs` (only to add `..Default::default()` to the `HopEntry` test helper literal)
- Out: `crates/conduit-vault/**`, `crates/conduit-runtime/**`, `crates/conduit-tray/**`, `src-tauri/**` (except `src-tauri/src/controller/test_support.rs`), `docs/MASTER-PLAN.md`

## Sub-tasks
1. [done] Add `#[serde(default)] pub agent_forward_keys: Vec<KeyId>` and `#[serde(default)] pub agent_forward_command: Option<String>` to `HopEntry` in `crates/conduit-core/src/model.rs` and add a serde backwards-compatibility unit test confirming old `HopEntry` JSON without those fields deserializes cleanly — done when: `cargo test -p conduit-core` exits 0
2. [done] Implement `crates/conduit-ssh/src/agent_wire.rs` encoding/decoding `ssh-agent` wire messages (`REQUEST_IDENTITIES`, `SIGN_REQUEST`, `IDENTITIES_ANSWER`, `SIGN_RESPONSE`, `FAILURE`), enforcing max packet size, delegating exclusively to `ScopedAgent`, and refusing all mutating/unknown opcodes — done when: `cargo test -p conduit-ssh agent_wire` exits 0
3. [done] Implement `AgentForwardRelay` and `agent_policy(capacity)` in `crates/conduit-ssh/src/agent_relay.rs` (wired into `lib.rs` and `SshChain::hop(index)` accessor) opening the session channel + `agent_forward_request` (+ optional `exec` remote command) on an opted-in hop and serving accepted agent channels via `agent_wire` — done when: `cargo test -p conduit-ssh agent_relay` exits 0
4. [done] Extend `crates/conduit-ssh/tests/common/mod.rs` and add loopback integration tests in `crates/conduit-ssh/tests/loopback_agent_forward.rs` proving: (a) opted-in hop exposes ONLY its assigned key(s) (1 of 2 keys) and completes a real signature roundtrip verified against the public key, (b) mutating agent opcodes return `SSH_AGENT_FAILURE`, (c) audit callback records the signature event, and (d) non-opted-in hops reject `server_channel_open_agent_forward` — done when: `cargo test -p conduit-core -p conduit-ssh && cargo clippy --workspace --all-targets -- -D warnings` exits 0

## Verify
```sh
cargo test -p conduit-core -p conduit-ssh && cargo clippy --workspace --all-targets -- -D warnings
```

## Escalate when
- `russh` 0.65.4 `Channel` lacks `agent_forward_request` or server-side `channel_open_agent_forward` cannot be triggered in the test harness → stop, set Status: needs-human — reason: exact `russh` 0.65.4 API gap

## Log
- (append-only, one line per event)
- sub-task 1: added agent_forward_keys and agent_forward_command to HopEntry plus a serde backwards-compatibility test in crates/conduit-core/src/model.rs
- escalated before sub-task 2: required workspace clippy cannot pass without editing src-tauri, which is Scope: Out; sub-tasks 2-4 not started
- planner approved adding src-tauri/src/controller/test_support.rs to Scope: In (for ..Default::default() on HopEntry literal) and confirmed russh 0.65.4 uses Channel::agent_forward(want_reply) and server channel_open_agent; resumed phase-0001 from sub-task 2
- sub-task 2: added agent_wire.rs with framing, a 256 KiB limit, read-only dispatch to ScopedAgent, and audit of unparseable sign requests
- sub-task 3: added agent_relay.rs (AgentForwardRelay, agent_policy) and SshChain::hop(index), using russh Channel::agent_forward as approved
- sub-task 4: extended the test harness and added 5 loopback tests; added the approved `..Default::default()` to test_support.rs; moved the dead_code allowance onto `mod common` in both conduit-ssh test binaries

## Evidence
- (append-only: command → observed result)
- cargo test -p conduit-core → exit 0, 34 passed, 0 failed, including model::tests::hop_entry_without_agent_forward_fields_deserializes
- cargo clippy --workspace --all-targets --keep-going -- -D warnings → exit 101, only error: E0063 missing fields agent_forward_command and agent_forward_keys at src-tauri/src/controller/test_support.rs:90:5
- cargo test -p conduit-ssh agent_wire → exit 0, 8 passed
- cargo test -p conduit-ssh agent_relay → exit 0, 3 passed
- cargo test -p conduit-ssh --test loopback_agent_forward (10 repeats) → 0 failures, 5 tests each
- cargo test -p conduit-core -p conduit-ssh && cargo clippy --workspace --all-targets -- -D warnings → exit 0; 34 core, 63 ssh unit, 5 agent loopback, 12 multihop loopback passed
