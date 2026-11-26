# phase-0002 — Port conduit-ssh and conduit-openssh to rusty-conduit-engine

- Status: done
- Owner: executor
- Depends on: phase-0001
- Goal: Port `conduit-ssh` (`RusshDialer` & `StatsDialer` returning `UpstreamStream::Boxed` without loopback bridges) and `conduit-openssh` (`TunnelState` + `OpenSshDialer` delegating to `rusty_conduit_engine::upstream::Socks5Dialer`) onto `rusty-conduit-engine`.
- Done when: `conduit-ssh` and `conduit-openssh` have zero `rusty_conduit_ssh` references, no loopback bridge in `dialer.rs` or `stats.rs`, and pass `cargo test` and `cargo clippy -D warnings`.
- Pattern to follow: `../rusty-conduit-engine/src/upstream/mod.rs:53-164` (`UpstreamStream::boxed`, `UpstreamDialer`, `DialError`), `../rusty-conduit-engine/src/upstream/socks5.rs:28-97` (`Socks5Dialer`)

## Context
- `rusty_conduit_engine::upstream::UpstreamDialer` returns `DialFuture<'_>` (`Pin<Box<dyn Future<Output = io::Result<UpstreamStream>> + Send + 'a>>`) and also requires `fn redacted_upstream(&self) -> String`.
- `RusshDialer` (`crates/conduit-ssh/src/dialer.rs`) no longer needs `loopback_pair()`, `accept_verified()`, or a per-dial `tokio::spawn(copy_bidirectional(...))` relay: `channel.into_stream()` implements `AsyncRead + AsyncWrite + Send + Unpin + 'static`, so return `Ok(UpstreamStream::boxed(channel.into_stream()))` directly. Keep `map_open_error` producing the exact `io::ErrorKind`s (`ConnectionRefused`, `PermissionDenied`, `Other`, `NotConnected`) and `TimedOut` for dial timeouts. Return `"ssh-tunnel".to_string()` from `redacted_upstream()`.
- `StatsDialer` (`crates/conduit-ssh/src/stats.rs`) also drops `loopback_pair()` and the relay task: change `CountingStream` to hold `inner: UpstreamStream`, `stats: Arc<AtomicStats>`, and `_guard: ActiveGuard`, and return `Ok(UpstreamStream::boxed(CountingStream { inner: upstream, stats, _guard: guard }))`. Delegate `redacted_upstream()` to `self.inner.redacted_upstream()`.
- `crates/conduit-ssh/src/reverse.rs` drops `use rusty_conduit_ssh::ssh::ReverseForward;` and `impl From<&ReverseForward> for RemoteForward`.
- `crates/conduit-openssh`: define and export `pub enum TunnelState { Connecting, Ready(SocketAddr), Disconnected(String) }` and `pub struct OpenSshDialer` (holding `watch::Receiver<TunnelState>`). When `TunnelState::Ready(addr)`, delegate to `rusty_conduit_engine::upstream::Socks5Dialer::new(addr.ip().to_string(), addr.port()).connect(host, port, timeout)`; when `Connecting` or `Disconnected(reason)`, return `DialError::NotConnected { kind: io::ErrorKind::NotConnected, message }.into_io()`. Implement `redacted_upstream()` returning `format!("socks5://{addr}")` when `Ready(addr)` else `"ssh-tunnel".to_string()`.
- Always use `CARGO_NET_GIT_FETCH_WITH_CLI=true` when running cargo commands.

## Scope
- In: `crates/conduit-ssh/Cargo.toml`, `crates/conduit-ssh/src/dialer.rs`, `crates/conduit-ssh/src/stats.rs`, `crates/conduit-ssh/src/reverse.rs`, `crates/conduit-ssh/tests/loopback_multihop.rs`, `crates/conduit-openssh/Cargo.toml`, `crates/conduit-openssh/src/lib.rs`, `crates/conduit-openssh/src/supervisor.rs`, `crates/conduit-openssh/src/dialer.rs` (new, or in `supervisor.rs`), `crates/conduit-openssh/tests/openssh_loopback.rs`, `Cargo.lock`
- Out: `Cargo.toml`, `crates/conduit-core/`, `crates/conduit-runtime/`, `crates/conduit-tray/`, `crates/conduit-vault/`, `src-tauri/`, `.github/`, `scripts/`, `docs/`

## Sub-tasks
1. [done] Switch `crates/conduit-ssh/Cargo.toml` to `rusty-conduit-engine = { workspace = true }`, refactor `crates/conduit-ssh/src/dialer.rs` to implement `rusty_conduit_engine::upstream::UpstreamDialer` returning `UpstreamStream::boxed(channel.into_stream())` (removing `loopback_pair`, `accept_verified`, and the bridge task), and update its unit tests — done when: `dialer.rs` has no `loopback_pair` or `TcpListener` bridge and compiles cleanly.
2. [done] Refactor `crates/conduit-ssh/src/stats.rs` to wrap `UpstreamStream` + `ActiveGuard` directly in `CountingStream` returning `UpstreamStream::boxed(...)` (dropping `loopback_pair` and the spawned bridge task), and remove `rusty_conduit_ssh::ssh::ReverseForward` from `crates/conduit-ssh/src/reverse.rs` — done when: `stats.rs` and `reverse.rs` have zero `rusty_conduit_ssh` references and no loopback bridge.
3. [done] Port `crates/conduit-ssh/tests/loopback_multihop.rs` to `rusty_conduit_engine` (`RoutingState::from_input` + `DialerOptions::default().with_external("ssh-tunnel", dialer)` + `EngineHandlers::from_routing` for forward proxy; direct-egress engine `Server` on ephemeral loopback ports for the reverse proxy test) — done when: `CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p conduit-ssh` passes all unit and E2E tests.
4. [done] Switch `crates/conduit-openssh/Cargo.toml` to `rusty-conduit-engine = { workspace = true }`, define and export `TunnelState` and `OpenSshDialer` (backed by `rusty_conduit_engine::upstream::Socks5Dialer`), update `supervisor.rs` and `tests/openssh_loopback.rs`, and add unit tests for `OpenSshDialer` (`Connecting`, `Disconnected`, `Ready`) — done when: `CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p conduit-openssh` passes all tests.
5. [done] Run `## Verify` and record observed results in `## Evidence` — done when: all tests, clippy `-D warnings`, and grep check exit 0.

## Verify
```sh
CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p conduit-ssh -p conduit-openssh && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo clippy -p conduit-ssh -p conduit-openssh --all-targets -- -D warnings && ! git grep -n "rusty.conduit.ssh" -- crates/conduit-ssh/ crates/conduit-openssh/
```

## Escalate when
- `russh::ChannelStream` fails `AsyncRead + AsyncWrite + Send + Unpin + 'static` bounds for `UpstreamStream::boxed` → stop, set Status: needs-human — reason: ChannelStream trait bound mismatch
- Any `loopback_multihop` or `openssh_loopback` test fails for a reason outside the engine API migration → stop, set Status: needs-human — reason: describe the failing test and error

## Log
- (append-only, one line per event)
- sub-task 1: switched both Cargo.toml deps to `rusty-conduit-engine`; `RusshDialer` now returns `UpstreamStream::boxed(channel.into_stream())`, removed `loopback_pair`/`accept_verified`/relay and their 2 tests, added `redacted_upstream()` = "ssh-tunnel" + test
- sub-task 2: `StatsDialer` wraps `UpstreamStream` + `ActiveGuard` in `CountingStream` returned boxed (no relay), delegates `redacted_upstream()`; removed `ReverseForward` import and `From` impl from reverse.rs

## Evidence
- (append-only: command → observed result)
- `grep -n "loopback_pair\|TcpListener\|copy_bidirectional" crates/conduit-ssh/src/dialer.rs` → no output; `cargo check -p conduit-ssh --lib --tests` → lib compiles (only errors in tests/loopback_multihop.rs, sub-task 3); ChannelStream satisfied `UpstreamStream::boxed` bounds
- `grep -n "rusty_conduit_ssh\|loopback_pair" crates/conduit-ssh/src/{stats,reverse}.rs` → no output; `cargo test -p conduit-ssh --lib` → ok. 58 passed; 0 failed
- `CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p conduit-ssh` → lib ok. 58 passed; loopback_multihop ok. 12 passed; doc ok. 0 passed
- `CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p conduit-openssh` → lib ok. 57 passed; openssh_loopback ok. 6 passed (real /usr/bin/ssh); bin/doc 0
- `## Verify` block → tests: 57+6+58+12 passed, 0 failed; clippy `-D warnings` → Finished, no warnings; `! git grep -n "rusty.conduit.ssh" -- crates/conduit-ssh/ crates/conduit-openssh/` → no matches; overall exit 0
- `cargo check -p conduit-runtime` → 7 errors (expected; phase-0003)
