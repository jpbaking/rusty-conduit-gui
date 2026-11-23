# phase-0004 — conduit-ssh RusshDialer bridge, reverse forwarding & loopback SSH tests

- Status: done
- Owner: executor
- Depends on: phase-0003
- Goal: Implement `RusshDialer` (bridging `russh` `direct-tcpip` into `rusty_conduit_ssh::net::UpstreamDialer`), `StatsDialer`, `tcpip-forward` reverse proxy wiring, and comprehensive loopback multi-hop integration tests.
- Done when: `cargo test -p conduit-ssh && cargo clippy --workspace --all-targets -- -D warnings` exits 0 including 1-hop and 3-hop loopback tests driving real `rusty_conduit_ssh` HTTP, SOCKS5h, and ReverseProxy engines.
- Pattern to follow: `/home/j.baking/Workspace/github/rusty-conduit-ssh/src/lib.rs:411` (`check_plan` / `check_socks_plan`) and `/home/j.baking/Workspace/github/rusty-conduit-ssh/src/net.rs:48` (`UpstreamDialer`)

## Context
`rusty_conduit_ssh::net::UpstreamDialer::connect` returns `Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send + 'a>>`.
Key decisions already made:
- `RusshDialer` bridges `russh` `ChannelStream` into a `TcpStream` via a verified per-dial loopback TCP pair (`127.0.0.1:0` bind → connect → accept → verify accepted peer addr == client local addr → drop listener → `tokio::io::copy_bidirectional`).
- Map `russh::ChannelOpenFailure` to exact `io::ErrorKind` (`ConnectFailed` → `ConnectionRefused`, `AdministrativelyProhibited` → `PermissionDenied`, timeout → `TimedOut`, disconnected chain → `NotConnected`) so `rusty_conduit_ssh` returns accurate HTTP 502/504 and SOCKS5 reply codes.
- `RusshDialer` supports swapping its active SSH chain handle atomically so forward listeners stay bound across reconnects.
- Loopback integration tests use an in-process `russh::server` test harness (no external `sshd` dependency, deterministic across Linux/macOS/Windows).

## Scope
- In: `crates/conduit-ssh/src/dialer.rs`, `crates/conduit-ssh/src/stats.rs`, `crates/conduit-ssh/src/reverse.rs`, `crates/conduit-ssh/src/lib.rs`, `crates/conduit-ssh/tests/**`, `crates/conduit-ssh/Cargo.toml`
- Out: `crates/conduit-core/**`, `crates/conduit-vault/**`, `crates/conduit-runtime/**`

## Sub-tasks
1. [done] Implement `crates/conduit-ssh/src/dialer.rs` (`RusshDialer` implementing `rusty_conduit_ssh::net::UpstreamDialer`) with verified loopback TCP pair bridging, remote-only DNS (passing hostnames unresolved to `channel_open_direct_tcpip`), exact `io::ErrorKind` mapping, and swappable/disconnectable handle state — done when: `cargo test -p conduit-ssh dialer` exits 0
2. [done] Implement `crates/conduit-ssh/src/stats.rs` (`StatsDialer` wrapping any `Arc<dyn UpstreamDialer>` and updating `Arc<AtomicStats>` for active connections, total connections, bytes sent, and bytes received via a counting loopback or stream wrapper) — done when: `cargo test -p conduit-ssh stats` exits 0
3. [done] Implement `crates/conduit-ssh/src/reverse.rs` requesting `tcpip_forward` on the final hop for each `rusty_conduit_ssh::ssh::ReverseForward` entry, registering allowed `(remote_addr, remote_port) -> local_addr` mappings in the handler, and relaying accepted `forwarded-tcpip` channels to the local `ReverseProxy` listener — done when: `cargo test -p conduit-ssh reverse` exits 0
4. [done] Create an in-process `russh::server` test harness in `crates/conduit-ssh/tests/common/mod.rs` supporting password auth, keyboard-interactive auth, Ed25519 key auth, `direct-tcpip` forwarding (including recording requested hostnames to prove remote-only DNS), and `tcpip-forward` reverse connections — done when: `cargo test -p conduit-ssh --test loopback_multihop -- --list` exits 0
5. [done] Write `crates/conduit-ssh/tests/loopback_multihop.rs` testing: (a) 3-hop chain (`key → password → key`) driving real `rusty_conduit_ssh` HTTP + SOCKS5h proxies with payload integrity check, (b) remote-only DNS hostname preservation, (c) reverse proxy (`-R`) roundtrip, (d) keyboard-interactive auth, (e) unknown & changed host-key rejection, (f) bad password classified as `SshError::AuthFailed`, and (g) intermediate hop-1 drop detection — done when: `cargo test -p conduit-ssh --test loopback_multihop` exits 0

## Verify
```sh
cargo test -p conduit-ssh && cargo clippy --workspace --all-targets -- -D warnings
```

## Escalate when
- `russh::server` in the installed `russh` version lacks a required server callback for `tcpip-forward` or `direct-tcpip` → stop, set Status: needs-human — reason: exact missing server trait method

## Log
- (append-only, one line per event)
- sub-task 1: added RusshDialer (verified loopback bridge, remote DNS, error mapping, swap/detach/shutdown); added rusty-conduit-ssh dep (Cargo.lock +1 line in conduit-ssh entry)
- sub-task 2: added AtomicStats/StatsSnapshot/StatsDialer with a counting loopback relay (AtomicStats did not exist, so it is defined in stats.rs)
- sub-task 3: added reverse_policy, ReverseInbound, ReverseRelay (all-or-nothing tcpip_forward on final hop, allowlist registration, relay to local listener)
- sub-task 4: added in-process russh::server harness (password, keyboard-interactive, Ed25519, direct-tcpip with host recording, tcpip-forward)
- sub-task 5: added loopback tests (a)-(g) plus 1-hop engines, 1-hop and 3-hop reverse, chain swap, and error-kind mapping

## Evidence
- (append-only: command → observed result)
- cargo test -p conduit-ssh dialer → exit 0, 5 passed
- cargo test -p conduit-ssh stats → exit 0, 2 passed
- cargo test -p conduit-ssh reverse → exit 0, 4 passed
- cargo test -p conduit-ssh --test loopback_multihop -- --list → exit 0, 12 tests
- cargo test -p conduit-ssh --test loopback_multihop → exit 0, 12 passed
- cargo test -p conduit-ssh && cargo clippy --workspace --all-targets -- -D warnings → exit 0 (52 unit + 12 loopback passed, clippy clean)
- 15 repeated runs of cargo test -p conduit-ssh --test loopback_multihop → 0 failures
- cargo test --workspace → 140 passed, 0 failed
- cargo tree -p conduit-ssh -i aws-lc-sys / openssl-sys → neither package is in the dependency graph
- git diff --stat -- Cargo.lock → 1 insertion (rusty-conduit-ssh in the conduit-ssh entry)
