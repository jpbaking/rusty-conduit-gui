# crates/conduit-runtime

Sub-root: Cargo workspace member crate `conduit-runtime`.

## Purpose
UI-agnostic supervisor over `rusty-conduit-engine`: runs Proxies, Tunnels, and legacy v1 sessions with a state machine, hot reload, reconnect backoff, redacted logs, events, External TOML watching, and OS wake handling.

## Ownership
Owns everything under `crates/conduit-runtime/`. Inherits all root DOX rules and adds the local rules below. Data models come from `../conduit-core`, secrets from `../conduit-vault`, SSH from `../conduit-ssh` and `../conduit-openssh`. The Tauri shell (`../../src-tauri`) and tray drive this crate; it must not depend on them.

## Local Contracts
- Hot reload swaps a Proxy's `ArcSwap<RoutingState>` without dropping connections; non-reloadable changes (bind, ports, `max_connections`, MITM CA, log sinks) require a restart.
- Running Tunnels register an external dialer that Proxies reference as a `tunnel` upstream; a down Tunnel returns `NotConnected` so failover chains fall through.
- Secrets are resolved in memory only and redacted (`src/logs.rs`) before anything is stored or emitted.
- No HTTP response or DNS caching; hostnames routed to a Tunnel or upstream proxy stay unresolved.
- Reconnect backoff resets only after a stable connection (`STABLE_UPTIME`).
- Wake listeners are best-effort, pure Rust or thin OS bindings, per platform in `Cargo.toml`.

## Verification
- `cargo test -p conduit-runtime` — includes loopback E2E suites; `tests/openssh_e2e.rs` needs a real `ssh` client.

## Feature Map
- **Session manager (v1 sessions)** — runs many legacy sessions; drives one session end to end. Start: `src/manager.rs`. Files: `src/runner.rs`, `src/state.rs`, `src/backoff.rs`, `src/port_forward.rs`, `src/reverse.rs`.
- **Tunnel manager** — supervises v2 Tunnels (hops, optional forward proxy/MITM, tunnel-level filtered dialers, reverse proxy, port forwards, and in-process `-L` proxy forward dialers) and exposes them as dialers. Start: `src/tunnel_manager.rs`. Files: `src/forward_dialer.rs`, `src/port_forward.rs`, `src/reverse.rs`, `src/backoff.rs`.
- **Proxy manager and hot reload** — runs every saved Proxy, compiles hot-swappable routing (including tunnel and `-L` proxy-forward upstreams), resolves vaulted upstream passwords and MITM CA. Start: `src/proxy_manager.rs`. Files: `src/forward_dialer.rs`.
- **External TOML link mode** — polls a linked `rusty-conduit-switch` `config.toml` and reloads on change. Start: `src/toml_watcher.rs`.
- **Logs and events** — bounded, redacted per-session logs and the UI event bus. Start: `src/logs.rs`. Files: `src/events.rs`.
- **Wake reconnect** — OS resume-from-sleep listener. Start: `src/wake.rs`.
- **Process hardening** — keeps decrypted secrets out of core dumps. Start: `src/hardening.rs`.
- **Integration tests** — headless E2E of sessions, OpenSSH, and Tunnels + Proxies on loopback. Start: `tests/u2_tunnels_proxies.rs`. Files: `tests/e2e_runtime.rs`, `tests/openssh_e2e.rs`.

## Child DOX Index
- (none)
