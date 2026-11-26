# phase-0003 — Build TunnelManager in conduit-runtime

- Status: done
- Owner: executor
- Depends on: phase-0002
- Goal: Implement `TunnelManager` in `conduit-runtime` to supervise `conduit_core::Tunnel` lifecycles, expose live `Arc<dyn UpstreamDialer>` handles for Proxies, run `-R` reverse proxies and `-L`/`-R` port forwards, and report bound reverse listeners.
- Done when: `TunnelManager` is exported from `conduit-runtime`, passes unit and loopback SSH tests (including `NotConnected` dial errors while stopped/reconnecting, reverse proxy, port forwards, host-key approval, and wake recycle), and existing `SessionManager` tests remain green.
- Pattern to follow: `crates/conduit-runtime/src/manager.rs:120-250`, `crates/conduit-runtime/src/runner.rs:553-1010` (`RusshLink`, `OpenSshLink`), `crates/conduit-runtime/src/state.rs:28-191`

## Context
- Keep existing `SessionManager` and `runner.rs` completely intact and working so `src-tauri` stays green until U3.
- Create `crates/conduit-runtime/src/tunnel_manager.rs` (and export `TunnelManager`, `TunnelSnapshot`, `TunnelRuntimeEvent` or extend `RuntimeEvent` carefully without breaking existing `src-tauri` matches — prefer a dedicated `TunnelEvent` / `TunnelManager` API or additive methods so `src-tauri` needs zero changes in U2!).
- Key design of `TunnelManager`:
  - Owns `HashMap<TunnelId, Arc<TunnelSlot>>`, `SharedVault`, `Arc<RwLock<KnownHostsStore>>`, `ManagerConfig`, and a broadcast `TunnelEvent` bus (`StateChanged { tunnel_id, state }`, `KnownHostsChanged { tunnel_id, hop_id, host, port }`).
  - Each `TunnelSlot` owns a persistent `Arc<dyn UpstreamDialer>` created at registration time (a `StatsDialer` wrapping a `SwitchableDialer` that holds either a `RusshDialer` or an `OpenSshDialer` depending on `tunnel.engine`, swapped when `tunnel.engine` changes or on connect/disconnect).
  - **Critical for failover:** `TunnelManager::dialer(&self, id: TunnelId) -> Option<Arc<dyn UpstreamDialer>>` returns that persistent dialer handle. While the tunnel is `Stopped`, `Starting`, `Reconnecting`, `Locked`, `NeedsAttention`, or `Failed`, calling `connect()` on the dialer returns `DialError::NotConnected { kind: io::ErrorKind::NotConnected, .. }.into_io()` immediately, so an engine `FailoverDialer` (`["bastion", "direct"]`) falls through cleanly!
  - Reuses existing `conduit-ssh` (`connect_chain`, `RusshDialer`, `ReverseRelay`, `StatsDialer`, `HostKeyVerifier`), `conduit-openssh` (`OpenSshSupervisor`, `OpenSshDialer`, `TunnelState`), `crate::reverse::ReverseProxy`, `crate::port_forward::LocalForwards`, `crate::backoff::Backoff`, and `crate::logs::LogRingBuffer`.
  - Runs the same lockout-safe supervisor loop as `runner.rs`: never auto-retries `AuthFailed`, `HostKeyChanged`, `Locked`, or `InvalidProfile`; supports `approve_host_key`, `reject_host_key`, `on_system_wake`, `start`, `stop`, `restart`, `stop_all`, `snapshot`, `snapshots`, `logs`, `upsert_tunnel`, `remove_tunnel`.
  - Tracks bound local reverse-proxy listeners (`reverse_listeners(&self) -> Vec<SocketAddr>`) so `ProxyManager` can include them in cross-Proxy self-loop checks.
  - Supports Linked reference counting: `acquire_linked(&self, id: TunnelId, holder: ProxyId)` (increments linked holders; starts the tunnel if `start_mode == TunnelStartMode::Linked`) and `release_linked(&self, id: TunnelId, holder: ProxyId)` (removes holder; stops the tunnel if `start_mode == TunnelStartMode::Linked` and no holders remain).
- Always use `CARGO_NET_GIT_FETCH_WITH_CLI=true` when running cargo commands.

## Scope
- In: `crates/conduit-runtime/src/lib.rs`, `crates/conduit-runtime/src/tunnel_manager.rs` (create), `crates/conduit-runtime/src/runner.rs` (only if making shared helper functions `pub(crate)`), `crates/conduit-runtime/src/reverse.rs` (only if adding a `local_listeners(&self) -> Vec<SocketAddr>` getter)
- Out: `crates/conduit-core/`, `crates/conduit-ssh/`, `crates/conduit-openssh/`, `crates/conduit-vault/`, `crates/conduit-tray/`, `src-tauri/`

## Sub-tasks
1. [done] Add `pub(crate) fn local_listeners(&self) -> Vec<SocketAddr>` to `ReverseProxy` in `crates/conduit-runtime/src/reverse.rs` and expose shared classify/resolve helpers in `runner.rs` as `pub(crate)` without altering `SessionManager` behavior — done when: existing `conduit-runtime` tests compile and pass unchanged.
2. [done] Create `crates/conduit-runtime/src/tunnel_manager.rs` implementing `TunnelManager`, `TunnelSnapshot`, `TunnelEvent`, `SwitchableDialer` (always returning `DialError::NotConnected` when down/reconnecting), full `russh` + `OpenSSH` supervision, `-R` reverse proxy + `-L`/`-R` port forwards, `approve_host_key`/`reject_host_key`, `on_system_wake`, `reverse_listeners()`, and `acquire_linked`/`release_linked` — done when: `tunnel_manager.rs` compiles with zero warnings.
3. [done] Export `TunnelManager`, `TunnelSnapshot`, and `TunnelEvent` from `crates/conduit-runtime/src/lib.rs` and add unit & loopback SSH tests in `tunnel_manager.rs` verifying: (a) dialer returns `NotConnected` while stopped and succeeds once connected, (b) `Linked` acquire/release starts and stops the tunnel cleanly, (c) `Manual` tunnel is not stopped on `release_linked`, (d) host-key approval flow, (e) auth failure halts without retry — done when: `cargo test -p conduit-runtime` passes all existing and new tests.
4. [done] Run `## Verify` and record observed results in `## Evidence` — done when: `## Verify` exits 0.
5. [done] Fix-up: replace `result.err().expect(..)` in the `assert_not_connected` test helper with a `let Err(..) else panic!` (clippy `err_expect` under `-D warnings`; `UpstreamStream` has no `Debug`, so `expect_err` is not usable) — done when: `## Verify` exits 0.

## Verify
```sh
CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p conduit-runtime && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo clippy -p conduit-runtime --all-targets -- -D warnings
```

## Escalate when
- `runner.rs` helpers cannot be reused cleanly without changing `SessionManager` public API → stop, set Status: needs-human — reason: describe the conflict

## Log
- (append-only, one line per event)
- began phase (commit 9672ca7)
- sub-task 1: added `ReverseProxy::local_listeners()` (reverse.rs); made runner.rs helpers `pub(crate)` (supervise, halt_state, describe, classify_reverse, vault_error, access_log_config, remote_listener_info, classify_openssh, probe_store, supervisor_hops, REVERSE_CHANNEL_CAPACITY, LIVENESS_POLL, SOCKS_PORT_ATTEMPTS); no signature or behavior change
- sub-task 2: created tunnel_manager.rs: TunnelManager, TunnelSnapshot, TunnelEvent (+TunnelEventReceiver, TunnelError), SwitchableDialer gated on `Connected` behind a persistent StatsDialer, RusshTunnelLink/OpenSshTunnelLink reusing runner `supervise`, reverse proxy + -L/-R forwards, host-key approve/reject, on_system_wake, reverse_listeners, acquire_linked/release_linked; shared runner helpers take a hop-only `SessionProfile` shim so their signatures stay unchanged
- sub-task 3: exported TunnelManager/TunnelSnapshot/TunnelEvent/TunnelEventReceiver/TunnelError from lib.rs; added 7 scripted + 4 loopback russh tests (loopback server included via `#[path]` from conduit-ssh/tests/common)
- sub-task 4: first Verify run failed on clippy `err_expect` in a test helper; appended fix-up sub-task 5, fixed, Verify exit 0
- extra check: `cargo check -p rusty-conduit-gui` clean with zero src-tauri changes

## Evidence
- (append-only: command → observed result)
- sub-task 1: `CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p conduit-runtime` → lib 63 passed, e2e_runtime 9 passed, openssh_e2e 9 passed, 0 failed (only warning: `local_listeners` unused, consumed in sub-task 2); `crates/conduit-runtime/src/reverse.rs:171`
- sub-task 2: `CARGO_NET_GIT_FETCH_WITH_CLI=true cargo clippy -p conduit-runtime` → no warnings, no errors; `crates/conduit-runtime/src/tunnel_manager.rs:202` (SwitchableDialer), `:915` (TunnelManager), `:1002` (dialer), `:1102`/`:1117` (acquire/release_linked), `:1195` (on_system_wake), `:1216` (reverse_listeners)
- sub-task 3: `CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p conduit-runtime --lib tunnel_manager` → 11 passed, 0 failed (dialer_is_persistent_and_refuses_while_not_connected, linked_acquire_and_release_start_and_stop_the_tunnel, disabled_linked_tunnel_is_not_started_by_a_holder, manual_tunnel_is_not_started_or_stopped_by_holders, system_wake_recycles_connected_tunnels_once, invalid_tunnel_is_refused_before_start, tunnel_event_serializes_with_tunnel_id, loopback_dialer_refuses_while_stopped_and_carries_traffic_when_connected, loopback_host_key_approval_pins_and_connects, loopback_auth_failure_halts_without_retry, loopback_reverse_proxy_and_port_forwards_run_and_report_listeners); `crates/conduit-runtime/src/lib.rs:25`
- sub-task 4 (first run): `## Verify` → tests all pass; clippy error `called .err().expect() on a Result value` at tunnel_manager.rs test helper → exit 101
- sub-task 5 / Verify: `CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p conduit-runtime && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo clippy -p conduit-runtime --all-targets -- -D warnings` → EXIT=0; lib 74 passed, e2e_runtime 9 passed, openssh_e2e 9 passed, doc 0; clippy clean
- extra: `CARGO_NET_GIT_FETCH_WITH_CLI=true cargo check -p rusty-conduit-gui` → Finished, no warnings/errors
