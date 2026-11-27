# phase-0002 — Runtime tunnel forward listener, filtered dialer, and in-process -L proxy dialer (conduit-runtime)

- Status: done
- Owner: executor
- Depends on: phase-0001
- Goal: Implement tunnel-level filter enforcement on Proxy traffic, in-process HTTP/SOCKS5 handshakes for `@forward:<tid>:<fid>` targets, optional tunnel forward listener + MITM in `TunnelManager`, and automatic external dialer registration in `ProxyManager`.
- Done when: `cargo clippy -p conduit-runtime --all-targets -- -D warnings` and `cargo test -p conduit-runtime` pass, including tests for filtered tunnel dialing, in-process `-L` HTTP and SOCKS5 handshake dialing, optional tunnel forward listener, and `ProxyManager::test_route` with `@tunnel:` / `@forward:` targets.
- Pattern to follow: `crates/conduit-runtime/src/tunnel_manager.rs:160-217` (`SwitchableDialer`), `crates/conduit-runtime/src/runner.rs:750-770` and `923-945` (forward `Server::from_options` and `MitmState` setup), `crates/conduit-runtime/src/proxy_manager.rs:565-610` (`compile_routing`).

## Context
`rusty-conduit-engine` already exposes `rusty_conduit_engine::upstream::http::connect_tunnel` and `rusty_conduit_engine::upstream::socks5::{handshake, encode_connect_request}` over any `AsyncRead + AsyncWrite + Unpin` stream. When a Proxy routes through `@tunnel:<tid>`, it must dial the tunnel's in-process SSH dialer (bypassing any customized tunnel forward `ip:port` and bypassing tunnel MITM), while STILL enforcing the tunnel's configured `forward.allow` / `forward.block` `HostFilter`. When a Proxy routes through `@forward:<tid>:<fid>`, it checks the tunnel's filter on the requested destination host, dials `(forward.dest_host, forward.dest_port)` through the tunnel's raw SSH dialer (skipping the local `-L` port), and runs the HTTP CONNECT or SOCKS5 handshake on that stream. Meanwhile, if `tunnel.forward.enabled` is true, `TunnelStack` runs a local `Server::from_options` with the tunnel's `forward_filter` and optional `MitmState` (loaded from the vault if `tunnel.mitm` is set).

## Scope
- In: `crates/conduit-runtime/src/tunnel_manager.rs`, `crates/conduit-runtime/src/proxy_manager.rs`, `crates/conduit-runtime/src/lib.rs`, `crates/conduit-runtime/tests/u2_tunnels_proxies.rs` (plus an optional new helper module `crates/conduit-runtime/src/forward_dialer.rs` if cleaner)
- Out: `crates/conduit-core/`, `crates/conduit-tray/`, `src-tauri/`

## Sub-tasks
1. [done] In `crates/conduit-runtime/src/tunnel_manager.rs`, add `FilteredTunnelDialer` wrapping `SwitchableDialer` with a live `Arc<RwLock<Option<HostFilter>>>` (refreshed on `upsert_tunnel` and tunnel start). On `connect(host, port, timeout)`, check the filter first; if denied, return `RouteBlocked::new(...).into_io()` (using `rusty_conduit_engine::upstream::RouteBlocked`), otherwise delegate to the inner dialer. Expose `TunnelManager::dialer(&self, id: TunnelId)` returning the filtered dialer and `TunnelManager::forward_dialer(&self, tid: TunnelId, fid: Uuid) -> Option<Arc<dyn UpstreamDialer>>` returning a `TunnelForwardDialer` that: (a) checks the tunnel filter on `host`, (b) looks up the current `PortForward` by `fid` (verifying `direction == Local` and `proxy_protocol != None`), (c) dials `(dest_host, dest_port)` via the raw `SwitchableDialer`, (d) performs `http::connect_tunnel` (attaching any trailing bytes via `UpstreamStream::with_prefix`) or `socks5::handshake` with `encode_connect_request(host, port)`. — done when: unit tests verify filter denial and both HTTP CONNECT and SOCKS5 in-process handshakes against local mock servers.
2. [done] In `crates/conduit-runtime/src/tunnel_manager.rs`, extend `TunnelSnapshot` with `pub listeners: Vec<ListenerInfo>` (the tunnel's bound forward listeners when `tunnel.forward.enabled`, empty otherwise) and update `TunnelStack` to start/stop an optional forward `Server::from_options(&cfg.forward_server, ...)` backed by the tunnel's raw dialer + `cfg.forward_filter` + optional `MitmState` (reading CA PEM from `ctx.vault` when `cfg.mitm_enabled`, returning `LinkError::Locked` if vault is locked and MITM CA is needed). Update `needs_secrets` check in `TunnelStack::start` to also account for `tunnel.forward.enabled && tunnel.mitm.is_some()`. Also expose `TunnelManager::tunnels(&self) -> Vec<Tunnel>` (or `known_tunnels_full`) for `ProxyManager`. — done when: unit/integration test starts a Tunnel with `forward.enabled = true` and confirms `snapshot.listeners` is populated and traffic flows through it; and starts a Tunnel with `forward.enabled = false` and confirms `snapshot.listeners` is empty.
3. [done] In `crates/conduit-runtime/src/proxy_manager.rs`, update `compile_routing`, `launch`, `reload`, `test_route`, `test_upstream`, `set_override`, and `profile_exists` to: (a) validate using `validate_proxy_with_tunnels` with live tunnels from `TunnelManager`, (b) register external dialers for all `@tunnel:<tid>` (via `tunnels.dialer(tid)`) and `@forward:<tid>:<fid>` (via `tunnels.forward_dialer(tid, fid)`) targets referenced in `proxy.routing`, (c) include Tunnel forward listeners in `other_listeners` for self-loop / port-conflict checks, (d) format friendly `redacted_upstream` in `test_route` (e.g. `tunnel:<name>` and `tunnel:<name> › <fwd_name> (http|socks5)`), and (e) allow `set_override` to accept `@tunnel:<tid>` and `@forward:<tid>:<fid>` targets by registering that target's external dialer in the override `RoutingState` whenever it is not already in `saved.registry`. — done when: `ProxyManager` tests pass for routing through `@tunnel:<id>`, `@forward:<tid>:<fid>`, tunnel filter enforcement on Proxy traffic, and `test_route` / `set_override`.
4. [done] Run `cargo clippy -p conduit-runtime --all-targets -- -D warnings` and `cargo test -p conduit-runtime`. — done when: both commands exit 0 with zero warnings.

## Verify
```sh
cargo clippy -p conduit-runtime --all-targets -- -D warnings && cargo test -p conduit-runtime
```

## Escalate when
- `rusty_conduit_engine::upstream::http::connect_tunnel` or `socks5::handshake` is private or lacks a needed method/type export in the pinned `v0.4.1` engine crate → stop, set Status: needs-human — reason: name the exact missing engine symbol.
- `TunnelStack` forward server setup conflicts with `OpenSshTunnelLink` or `RusshTunnelLink` lifecycle ordering → stop, set Status: needs-human — reason: describe the lifecycle conflict.

## Log
- (append-only, one line per event)
- sub-task 1: added `FilteredTunnelDialer` in `tunnel_manager.rs`, `TunnelForwardDialer` in `forward_dialer.rs`, exposed `TunnelManager::dialer` (filtered) and `TunnelManager::forward_dialer`, and added unit tests for filter denial and HTTP CONNECT / SOCKS5 in-process handshakes
- sub-task 2: extended `TunnelSnapshot` with `listeners`, added optional forward `Server` + `MitmState` + vault-lock check to `TunnelStack`, exposed `TunnelManager::tunnels` and `TunnelManager::forward_listeners`, and added unit tests
- sub-task 3: updated `ProxyManager` (`compile_routing`, `launch`, `reload`, `test_route`/`test_route_with_tunnels`/`test_route_live`, `test_upstream`, `set_override`, `profile_exists`, `other_listeners`, `port_conflict`) for `validate_proxy_with_tunnels`, `@tunnel:`/`@forward:` external dialers, tunnel forward listener conflict/self-loop checks, friendly upstream labels, and added unit + E2E tests
- sub-task 4: ran full `conduit-runtime` clippy and test verification suite

## Evidence
- (append-only: command → observed result)
- `cargo test -p conduit-runtime --lib tunnel_manager::tests` → exit 0 (14 passed; 0 failed)
- `cargo test -p conduit-runtime --lib tunnel_manager::tests::loopback_tunnel_forward` → exit 0 (2 passed; 0 failed)
- `cargo test -p conduit-runtime --lib proxy_manager::tests && cargo test -p conduit-runtime --test u2_tunnels_proxies proxy_routes_through_synthetic_tunnel_and_forward_targets_with_filter` → exit 0 (15 unit + 1 E2E passed; 0 failed)
- `cargo clippy -p conduit-runtime --all-targets -- -D warnings && cargo test -p conduit-runtime` → exit 0 (0 warnings; 97 unit + 9 e2e_runtime + 9 openssh_e2e + 8 u2_tunnels_proxies = 123 passed, 0 failed)
