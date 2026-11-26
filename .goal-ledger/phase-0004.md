# phase-0004 — Build ProxyManager in conduit-runtime (hot-reload, overrides, Route Tester, Test Upstream, counters)

- Status: done
- Owner: executor
- Depends on: phase-0003
- Goal: Implement `ProxyManager` in `conduit-runtime` wired to `TunnelManager`, supporting zero-downtime `ArcSwap` hot-reload, tray overrides, Linked tunnel lifecycle, Route Tester, Test Upstream probe, per-rule/profile counters, and structured `AccessRecord` log sink.
- Done when: `ProxyManager` and its types are exported from `conduit-runtime`, pass unit tests and `clippy -D warnings`, and existing `SessionManager` tests remain green.
- Pattern to follow: `docs/MASTER-PLAN.md:134-164`, `../rusty-conduit-engine/src/routing.rs:687-1080` (`RoutingState`, `SharedRouting`, `RoutingCounters`), `../rusty-conduit-engine/src/router/mod.rs:40-460` (`ParsedTarget`, `RouteRequest`, `Router`)

## Context
- Create `crates/conduit-runtime/src/proxy_manager.rs` (exported from `crates/conduit-runtime/src/lib.rs`).
- `ProxyState` enum (`#[serde(tag = "state", rename_all = "snake_case")]`): `Stopped`, `Starting`, `Running { override_profile: Option<String>, config_generation: u64, restart_required: bool }`, `Reloading`, `Locked`, `NeedsAttention { reason: String }`, `Stopping`.
- `ProxySnapshot`: `id: ProxyId`, `name: String`, `enabled: bool`, `state: ProxyState`, `listeners: Vec<ListenerInfo>`, `config_generation: u64`, `override_profile: Option<String>`, `restart_required: bool`, `profile_counters: BTreeMap<String, TrafficSnapshot>`, `rule_counters: BTreeMap<String, TrafficSnapshot>` (using a serde-serializable mirror `ProxyTrafficSnapshot { active, bytes_in, bytes_out, hits }` since engine's `TrafficSnapshot` may not derive `Serialize`), `referenced_tunnels: Vec<TunnelId>`.
- `ProxyManager` holds `Arc<TunnelManager>`, `SharedVault`, `ManagerConfig`, `HashMap<ProxyId, Arc<ProxySlot>>`, and a `ProxyEvent` broadcast bus (`StateChanged { proxy_id, state }`, `Reloaded { proxy_id, config_generation }`, `OverrideChanged { proxy_id, override_profile }`).
- **Start flow (`start(id)`):**
  1. Validate `proxy` via `validate_proxy(&proxy, &known_tunnels, &other_listeners)` where `other_listeners` collects all bound listeners of other running Proxies plus `tunnels.reverse_listeners()` (and also check listener port conflicts against other running Proxies).
  2. Check vault: if any profile has `UpstreamPasswordSource::Vault(_)` or `proxy.mitm` has a CA and vault is locked → transition to `ProxyState::Locked` and return `Err(ProxyError::VaultLocked)`.
  3. Resolve vaulted upstream passwords into `BTreeMap<String, Zeroizing<String>>` and optional MITM CA PEM bytes into `Option<Zeroizing<Vec<u8>>>`.
  4. Build `RoutingInput` via `proxy_to_routing_input(&proxy, &passwords, &other_listeners)`, attach every referenced Tunnel's dialer (`tunnels.dialer(tid)`) via `DialerOptions::with_external(profile.name, dialer)`, compile `RoutingState::from_input` → `SharedRouting` (`Arc<ArcSwap<RoutingState>>`).
  5. Build `MitmState::from_pem_bytes` if MITM enabled.
  6. Acquire Linked Tunnels (`tunnels.acquire_linked(tid, proxy.id)`) staggered if multiple, then bind `Server::from_options(&proxy_server_options(&proxy), handlers, logger)` with `.with_runtime(Arc::clone(&shared_routing))` so client TCP keepalive also hot-reloads! Spawn `server.run()` and optional MITM cert reaper.
  7. Support an optional `AccessRecordSink` (or bounded ring buffer of structured `AccessRecord` entries per Proxy) alongside `LogRingBuffer`.
- **Zero-downtime hot-reload (`upsert_proxy(proxy)` / `reload(id)`):**
  - Compare running baseline config vs updated `Proxy`: changes to `listeners` (`bind`, `http_port`, `socks_port`, `max_connections`), `mitm` (on/off, CA, TTL, cache max, `socks_block_web`), or `logging` sinks set `restart_required = true` (do not rebind listeners).
  - Compile the next `RoutingState` (re-resolving vaulted passwords, attaching referenced tunnel dialers, checking cross-Proxy + reverse-listener self-loops), preserving existing `RoutingCounters` via `.with_counters(prev.counters().clone())` and setting `.with_generation(next_gen)`.
  - On success: update saved `compiled_routing`, atomically `shared_routing.store(Arc::new(next_state))` (unless a tray override is currently active, in which case keep the saved state updated and re-apply override if profile still exists or clear override), reconcile `acquire_linked` / `release_linked` for added/removed tunnel refs, and emit `Reloaded`.
  - On failure: keep current `RoutingState` untouched and return `Err(ProxyError::...)`.
- **Tray overrides (`set_override(id, override_profile: Option<String>)`):**
  - `Some(profile_name)` (e.g. `"direct"` or any configured profile name): build a temporary rule-less `RoutingState` whose default target is `OneOrMany::One(profile_name)` using the current proxy's profiles/external dialers/keepalive/timeout/filter and preserving `RoutingCounters`, then `shared_routing.store(...)`.
  - `None` (*Auto Switch*): restore the saved compiled `RoutingState` via `shared_routing.store(...)`.
- **Route Tester (`test_route(proxy: &Proxy, raw_target: &str, inbound: RouteInbound) -> Result<RouteTestResult, ProxyError>`):**
  - Parses `raw_target` with `rusty_conduit_engine::router::ParsedTarget::parse(raw_target)`, builds `RoutingInput` (using dummy placeholder passwords so vault isn't needed for route testing) + `Router::from_input`, evaluates `RouteRequest`, and returns `RouteTestResult { table, matched_rule, blocked_by_filter, filter_reason, targets: Vec<RouteTestTarget { profile, redacted_upstream, bypassed }> }`.
- **Test Upstream (`test_upstream(&self, proxy: &Proxy, profile_name: &str, host: &str, port: u16, timeout: Duration) -> Result<UpstreamProbeResult, ProxyError>`):**
  - Resolves vaulted password (if needed) or Tunnel dialer from `TunnelManager`, dials `host:port` through that profile's `UpstreamDialer`, and returns `UpstreamProbeResult { ok: bool, elapsed_ms: u64, redacted_upstream: String, error: Option<String> }` (never leaking passwords).
- Always use `CARGO_NET_GIT_FETCH_WITH_CLI=true` when running cargo commands.

## Scope
- In: `crates/conduit-runtime/Cargo.toml` (only if `arc-swap` is needed directly), `crates/conduit-runtime/src/lib.rs`, `crates/conduit-runtime/src/proxy_manager.rs` (create), `Cargo.lock`
- Out: `Cargo.toml`, `crates/conduit-core/`, `crates/conduit-ssh/`, `crates/conduit-openssh/`, `crates/conduit-vault/`, `crates/conduit-tray/`, `src-tauri/`

## Sub-tasks
1. [done] Create `crates/conduit-runtime/src/proxy_manager.rs` with `ProxyState`, `ProxySnapshot`, `ProxyTrafficSnapshot`, `ProxyEvent`, `ProxyError`, `RouteTestResult`, `UpstreamProbeResult`, and `ProxyManager` lifecycle (`upsert_proxy`, `remove_proxy`, `start`, `stop`, `restart`, `stop_all`, `snapshot`, `snapshots`, `logs`, Linked tunnel acquire/release) — done when: `proxy_manager.rs` compiles cleanly.
2. [done] Implement `reload` (with `restart_required` classification and `RoutingCounters` preservation), `set_override` (swap temporary rule-less `RoutingState` and restore saved state), `test_route` (`ParsedTarget` + `Router`), and `test_upstream` (dial probe with timing and redacted errors) in `proxy_manager.rs` — done when: all methods compile with zero warnings.
3. [done] Export `ProxyManager` and its public types from `crates/conduit-runtime/src/lib.rs` and add unit tests in `proxy_manager.rs` covering `test_route`, `test_upstream`, `restart_required` detection, and `ProxyState` serialization — done when: `cargo test -p conduit-runtime` passes.
4. [done] Run `## Verify` and record observed results in `## Evidence` — done when: `## Verify` exits 0.

## Verify
```sh
CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p conduit-runtime && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo clippy -p conduit-runtime --all-targets -- -D warnings
```

## Escalate when
- `arc-swap` is not re-exported by `rusty-conduit-engine` and needs to be added to root `Cargo.toml` → stop, set Status: needs-human — reason: confirm adding `arc-swap = "1"` to `[workspace.dependencies]`
- Any `rusty_conduit_engine::router::ParsedTarget` or `RouteDecision` field differs from expected → stop, set Status: needs-human — reason: document the exact field mismatch

## Log
- (append-only, one line per event)
- sub-task 1: created `crates/conduit-runtime/src/proxy_manager.rs` (ProxyState, ProxySnapshot, ProxyTrafficSnapshot, ProxyEvent, ProxyError, RouteTestResult/RouteTestTarget, UpstreamProbeResult, AccessRecordBuffer, ProxyManager upsert/remove/start/stop/restart/stop_all/snapshot(s)/logs, staggered Linked acquire + release) and declared `pub mod proxy_manager` in lib.rs; no Cargo.toml change needed (`SharedRouting` methods `store`/`load_full` are inherent, `RoutingState::shared()` builds it)
- sub-task 2: implemented in the same file `reload` (restart_required via `requires_restart`, counters via `with_counters`, `with_generation`, tunnel acquire/release reconcile, override re-apply/clear), `set_override` (rule-less state sharing saved dialers/counters), `test_route` (ParsedTarget + Router + RouteRequest, placeholder passwords), `test_upstream` (dialer_for_profile, timing, redacted errors)

- sub-task 3: exported `ProxyManager`, `ProxyError`, `ProxyEvent`, `ProxySnapshot`, `ProxyState`, `ProxyTrafficSnapshot`, `RouteTestResult`, `RouteTestTarget`, `UpstreamProbeResult`, `AccessRecordBuffer`, `requires_restart` from lib.rs; added 12 unit tests (state serialization, restart_required, test_route rule/bypass/filter/vault/tunnel/bad targets, test_upstream direct/refused/unknown/tunnel-down/vault-locked, Locked and NeedsAttention starts, port conflict, CONNECT counters, hot reload + rejected reload, override swap/keep/clear/restore, Linked acquire/release)

- sub-task 4: ran `## Verify`; both commands passed with no fix-ups needed

## Evidence
- (append-only: command → observed result)
- sub-task 1: `CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build -p conduit-runtime` → `Finished dev profile`, exit 0
- sub-task 2: `touch proxy_manager.rs && cargo build -p conduit-runtime 2>&1 | grep -c '^warning'` → `0`; build `Finished`
- sub-task 3: `cargo test -p conduit-runtime --lib proxy_manager` → 12 passed; `cargo test -p conduit-runtime` → lib 86 passed, e2e_runtime 9 passed, openssh_e2e 9 passed, doctests 0; exit 0
- sub-task 4 / Verify: `CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p conduit-runtime && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo clippy -p conduit-runtime --all-targets -- -D warnings` → tests 86+9+9 passed; clippy `Finished dev profile` with no warnings; exit 0
