# crates/conduit-ssh

Sub-root: Cargo workspace member crate `conduit-ssh`.

## Purpose
Default pure-Rust SSH engine (`russh` + `ring`): multi-hop jump chains, strict host-key pinning, a scoped in-process agent, reverse forwarding, and the engine-facing dialer.

## Ownership
Owns everything under `crates/conduit-ssh/`. Inherits all root DOX rules and adds the local rules below. The opt-in OpenSSH engine is owned by `../conduit-openssh`; session supervision by `../conduit-runtime`.

## Local Contracts
- Never read `~/.ssh/config`, `~/.ssh/id_*`, `~/.ssh/known_hosts`, or `SSH_AUTH_SOCK`.
- Each hop authenticates end to end; private keys never reach a jump host. Each credential is tried at most once per attempt (lockout protection).
- Host keys are checked only against the app-owned `KnownHostsStore`; nothing here writes a pin — trust comes only from a recorded user approval.
- The client handler denies all server-initiated channels except allowlisted `forwarded-tcpip`; agent forwarding is always refused.
- The scoped agent is read-only (list and sign only); no code path adds, removes, or exports keys.
- A hop carried inside another hop's channel must run over `src/nested.rs`'s `NestedTransport`, never the raw `ChannelStream`: a `russh` session loop that waits on the outer channel's window deadlocks the chain under sustained upload (`tests/upload_burst.rs`).
- Errors are classified in `src/error.rs` so the runtime can tell retry from stop; keep that classification when adding failures.
- Tests use in-process `russh` servers only: no network, `sshd`, or `~/.ssh`.

## Verification
- `cargo test -p conduit-ssh`

## Feature Map
- **Multi-hop chain** — sequential `Hop 0 → … → Target` connect over nested `direct-tcpip`, with time-bounded teardown. Start: `src/chain.rs`. Files: `src/nested.rs`, `src/handler.rs`, `src/error.rs`, `src/chain/tests.rs`.
- **Host-key pinning** — strict verification against the app-owned store. Start: `src/host_key.rs`.
- **Scoped agent** — sealed per-hop key set and the read-only `ssh-agent` wire subset. Start: `src/agent.rs`. Files: `src/agent_wire.rs`.
- **Engine dialer and stats** — `russh` channels as the engine's `UpstreamDialer`, with live counters. Start: `src/dialer.rs`. Files: `src/stats.rs`.
- **Reverse forwarding** — publishes local reverse-proxy listeners on the final hop (`ssh -R`). Start: `src/reverse.rs`.
- **Loopback E2E tests** — real engines over in-process SSH servers, plus bursty-upload stall regressions over a rate-limited link. Start: `tests/loopback_multihop.rs`. Files: `tests/upload_burst.rs`, `tests/common/mod.rs`.

## Child DOX Index
- (none)
