# phase-0003 — conduit-ssh multi-hop russh chain, host-key pinning & scoped agent

- Status: done
- Owner: executor
- Depends on: phase-0001, phase-0002
- Goal: Implement the pure-Rust `russh` (using `ring` only) multi-hop SSH chain builder, strict app-owned host-key pinning, auth failure classification, prefix-by-prefix chain tester, and read-only scoped in-process agent signer.
- Done when: `cargo test -p conduit-ssh && cargo clippy --workspace --all-targets -- -D warnings` exits 0 with unit tests verifying host-key policy decisions, auth error classification, scoped agent read-only enforcement, and multi-hop chain compilation.
- Pattern to follow: `docs/MASTER-PLAN.md` Sections 3.3, 3.4, 3.5, and 5.4

## Context
`conduit-ssh` owns all pure-Rust SSH connectivity via `russh` (`ring` crypto backend only — no `aws-lc` and no OpenSSL).
Key decisions already made:
- Never read `~/.ssh/config`, `~/.ssh/id_*`, `~/.ssh/known_hosts`, or ambient `SSH_AUTH_SOCK` by default.
- Host-key pinning uses `conduit-core`'s `KnownHostsStore` keyed by `(hop_id, host, port)`. Unknown keys pause/return `SshError::HostKeyUnknown { hop_index, hop_id, host, port, algorithm, sha256 }` (never auto-trusted unattended); changed keys return `SshError::HostKeyChanged { .. }` (hard stop).
- Override permissive `russh` client handler defaults: reject `server_channel_open_agent_forward` unless explicitly enabled on that hop; reject `server_channel_open_forwarded_tcpip` unless matching an explicitly requested `(remote_addr, remote_port)` forward.
- Authentication failures (`Permission denied`, rejected password/key/keyboard-interactive) must map cleanly to `SshError::AuthFailed { hop_index, hop_id, detail }` so `conduit-runtime` halts reconnects to prevent server account lockouts.

## Scope
- In: `Cargo.toml`, `crates/conduit-ssh/**`
- Out: `crates/conduit-runtime/**`, `crates/conduit-vault/**`, `docs/MASTER-PLAN.md`

## Sub-tasks
1. [done] Add `russh` (with `ring` feature, `default-features = false` so neither `aws-lc-rs` nor OpenSSL is pulled in) and required async dependencies to `Cargo.toml` and `crates/conduit-ssh/Cargo.toml` — done when: `cargo check -p conduit-ssh` exits 0 and `cargo tree -p conduit-ssh` does not contain `aws-lc-sys` or `openssl-sys`
2. [done] Implement `crates/conduit-ssh/src/error.rs` and `crates/conduit-ssh/src/host_key.rs` defining `SshError` (with `is_lockout_sensitive()` classifying `AuthFailed`, `HostKeyUnknown`, `HostKeyChanged`) and `HostKeyVerifier` backed by `KnownHostsStore` (`Trusted`, `Unknown`, `Changed`) — done when: `cargo test -p conduit-ssh host_key` exits 0
3. [done] Implement `crates/conduit-ssh/src/agent.rs` providing `ScopedAgent` (sealed read-only key set holding only explicitly assigned keys for one hop, supporting `list_identities` and `sign` with signature audit callback, rejecting any mutation operations) — done when: `cargo test -p conduit-ssh agent` exits 0
4. [done] Implement `crates/conduit-ssh/src/handler.rs` implementing `russh::client::Handler` with strict `check_server_key`, default-deny `server_channel_open_agent_forward` (per-hop opt-in only), default-deny `server_channel_open_forwarded_tcpip` (allowlisted reverse forwards only), and disconnect notification channel — done when: `cargo test -p conduit-ssh handler` exits 0
5. [done] Implement `crates/conduit-ssh/src/chain.rs` connecting `Hop 0 → Hop 1 → … → Target` sequentially over nested `direct-tcpip` (`russh::client::connect_stream`), authenticating each hop with ordered methods (in-memory vaulted key, password, keyboard-interactive), applying keepalive (`ServerAliveInterval`/`ServerAliveCountMax`), and implementing `test_chain` returning per-hop diagnostics — done when: `cargo test -p conduit-ssh chain` exits 0
6. [done] Fix-up: resolve `clippy::result_large_err` from `## Verify` without changing the `SshError` field shape required by `## Context` — done when: `cargo clippy --workspace --all-targets -- -D warnings` exits 0

## Verify
```sh
cargo test -p conduit-ssh && cargo clippy --workspace --all-targets -- -D warnings
```

## Escalate when
- `russh` version API differs significantly for `connect_stream`, `keyboard_interactive`, or `server_channel_open_agent_forward` → stop, set Status: needs-human — reason: exact `russh` version and method signature mismatch
- `cargo tree -p conduit-ssh` unavoidably pulls `aws-lc-sys` or `openssl-sys` → stop, set Status: needs-human — reason: dependency path pulling non-ring crypto

## Log
- (append-only, one line per event)
- sub-task 1: added tokio workspace dependency and conduit-ssh dependencies (russh via ring-only workspace entry)
- sub-task 2: added SshError with is_lockout_sensitive and HostKeyVerifier (Trusted/Unknown/Changed)
- sub-task 3: added sealed read-only ScopedAgent with sign audit callback
- sub-task 4: added HopHandler; denies all server-initiated channels except opted-in agent and allowlisted forwarded-tcpip
- sub-task 5: added connect_chain and test_chain with ordered single-attempt auth, keepalive, and in-process loopback russh tests
- fix-up 6: crate-level allow for clippy::result_large_err, keeping the flat SshError fields the phase specifies

## Evidence
- (append-only: command → observed result)
- `cargo check -p conduit-ssh` → exit 0; `cargo tree -p conduit-ssh -e all | grep -cE 'aws-lc-sys|openssl-sys'` → 0
- `cargo test -p conduit-ssh --lib host_key` → 9 passed, 0 failed
- `cargo test -p conduit-ssh --lib agent` → 10 passed, 0 failed
- `cargo test -p conduit-ssh --lib handler` → 6 passed, 0 failed
- `cargo test -p conduit-ssh --lib chain` → 21 passed, 0 failed
- `cargo test -p conduit-ssh --lib` repeated 10 times → 42 passed, 0 failed every run
- first `cargo clippy --workspace --all-targets -- -D warnings` → failed with 6 clippy::result_large_err; after fix-up 6 → exit 0
- `cargo test -p conduit-ssh && cargo clippy --workspace --all-targets -- -D warnings` → 42 passed, clippy exit 0
- `cargo test --workspace` → 118 passed, 0 failed
