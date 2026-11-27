# phase-0001 — Core data model, validation, mapping, and migration (conduit-core)

- Status: done
- Owner: executor
- Depends on: none
- Goal: Extend `conduit-core` v2 models, validation, engine mapping, and migration for `@tunnel:<id>` / `@forward:<tid>:<fid>` targets, `PortForward.proxy_protocol`, and optional `Tunnel.forward` / `Tunnel.mitm` / `Tunnel.socks_block_web`.
- Done when: `cargo test -p conduit-core` and `cargo clippy -p conduit-core --all-targets -- -D warnings` pass with unit tests covering all new types, validation rules, synthetic external profiles, and tunnel-profile migration.
- Pattern to follow: `crates/conduit-core/src/v2_model.rs:130-187` (serde defaults on `Tunnel`), `crates/conduit-core/src/v2_mapping.rs:248-329` (`build_routing_input`), `crates/conduit-core/src/v2_validate.rs:88-216` (`validate_tunnel` and `validate_proxy`).

## Context
Previously, routing rules could only target built-ins (`direct`, `block`) or manually created `UpstreamProfile` entries, and Tunnels had no forward proxy, forward filter, or MITM. To power the AirSwitch-style routing UX without breaking the engine's string-based `RouteTarget`, we reserve `@tunnel:<uuid>` and `@forward:<tunnel_uuid>:<forward_uuid>` target strings that `build_routing_input` automatically turns into `ProfileType::External` profiles. Tunnels gain `forward: ForwardConfig` (default `enabled: false`, keeping `allow`/`block` filters always active for Proxy traffic), `mitm: Option<MitmConfig>`, and `socks_block_web: bool`. Note: `conduit-core` must stay pure data/logic with no network or UI code. Downstream crates (`conduit-runtime`, `src-tauri`) may need signature updates in phases 2–3, so keep `validate_proxy` ergonomic or update its callers only if strictly needed for `conduit-core` to compile — do NOT edit files outside `crates/conduit-core/`.

## Scope
- In: `crates/conduit-core/src/model.rs`, `crates/conduit-core/src/v2_model.rs`, `crates/conduit-core/src/v2_validate.rs`, `crates/conduit-core/src/v2_mapping.rs`, `crates/conduit-core/src/lib.rs`, `crates/conduit-core/src/migrate_v2.rs`, `crates/conduit-core/src/toml_io.rs`
- Out: `crates/conduit-runtime/`, `crates/conduit-tray/`, `src-tauri/`

## Sub-tasks
1. [done] In `crates/conduit-core/src/model.rs`, add `#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)] #[serde(rename_all = "snake_case")] pub enum ForwardProxyProtocol { #[default] None, Http, Socks5 }` and add `#[serde(default)] pub proxy_protocol: ForwardProxyProtocol` to `PortForward` (default `None`). Export `ForwardProxyProtocol` from `crates/conduit-core/src/lib.rs`. — done when: `PortForward` round-trips with and without `proxy_protocol` in JSON.
2. [done] In `crates/conduit-core/src/v2_model.rs`, add `forward: ForwardConfig` (with `#[serde(default = "default_tunnel_forward")]` where `enabled: false`), `#[serde(default)] pub mitm: Option<MitmConfig>`, and `#[serde(default)] pub socks_block_web: bool` to `Tunnel` and its `Default` impl. Update `Tunnel` struct literals in `crates/conduit-core/src/migrate_v2.rs` and `crates/conduit-core/src/toml_io.rs` to include `..Tunnel::default()`. Add `TUNNEL_TARGET_PREFIX = "@tunnel:"`, `FORWARD_TARGET_PREFIX = "@forward:"`, `TargetRef` enum (`Direct`, `Block`, `Tunnel(TunnelId)`, `TunnelForward { tunnel_id: TunnelId, forward_id: Uuid }`, `Profile(String)`), `TargetRef::parse(&str)`, `TargetRef::to_wire(&self)`, `tunnel_target_name(TunnelId)`, `forward_target_name(TunnelId, Uuid)`, and `migrate_tunnel_profiles(proxy: &mut Proxy) -> bool` (rewrites references to any `UpstreamKind::Tunnel { tunnel_id }` profile name in `proxy.routing` and composite profiles to `@tunnel:<id>` and removes the redundant `UpstreamKind::Tunnel` entry from `proxy.profiles`). Export new public items from `lib.rs`. — done when: existing `Tunnel` JSON without `forward`/`mitm` deserializes with `forward.enabled == false`, `mitm == None`, and `migrate_tunnel_profiles` tests pass.
3. [done] In `crates/conduit-core/src/v2_mapping.rs`, update `tunnel_to_engine_config` to map `tunnel.forward` (when `forward.enabled`, bind/ports/max_connections; `forward_filter` ALWAYS compiled from `forward.allow` and `forward.block` even when `forward.enabled == false`), `tunnel.mitm` (active only when `forward.enabled && tunnel.mitm.is_some()`), and `tunnel.socks_block_web`. Add `tunnel_forward_filter(tunnel: &Tunnel) -> Result<Option<HostFilter>, MappingError>`. Update `proxy_referenced_tunnels(proxy: &Proxy) -> Vec<TunnelId>` to also collect tunnels referenced via `@tunnel:<id>` and `@forward:<tid>:<fid>` in `proxy.routing` (unified + http + socks rules and defaults). Add `proxy_referenced_forwards(proxy: &Proxy) -> Vec<(TunnelId, Uuid)>` and `proxy_referenced_targets(proxy: &Proxy) -> Vec<TargetRef>`. Update `build_routing_input` to auto-insert `ProfileConfig::of_kind(ProfileType::External)` for every `@tunnel:` and `@forward:` target referenced in `proxy.routing`. — done when: unit tests verify `tunnel_to_engine_config` with forward off/on + filters + MITM, and `proxy_to_routing_input` compiles a Proxy with zero manual `UpstreamProfile`s targeting `@tunnel:<id>` and `@forward:<tid>:<fid>`.
4. [done] In `crates/conduit-core/src/v2_validate.rs`, update `validate_tunnel` to: (a) always validate `tunnel.forward.allow` and `tunnel.forward.block` filter rules, (b) when `tunnel.forward.enabled`, validate bind/ports/max_connections (same rules as v1 `validate.rs`) and pass `Some((forward.bind, forward.effective_ports()))` to `port_forward_problem_in`, (c) when `tunnel.forward.enabled`, validate `tunnel.mitm` (CA required, `cert_ttl >= MIN_MITM_CERT_TTL`), (d) reject `PortForward` with `direction == Remote && proxy_protocol != ForwardProxyProtocol::None`. Update `validate_proxy`: keep existing `validate_proxy(proxy, known_tunnels: &[TunnelId], extra_listeners)` working AND add `validate_proxy_with_tunnels(proxy: &Proxy, known_tunnels: &[Tunnel], extra_listeners: &[SocketAddr]) -> Result<(), ProxyValidateError>` (or check `@tunnel:` against `known_tunnels` and `@forward:` against `known_tunnels`'s local forwards with `proxy_protocol != None`, and reject user profile names starting with `@` with a new `ReservedProfileName` error). — done when: unit tests cover all new `validate_tunnel` and `validate_proxy_with_tunnels` error and success cases.
5. [done] Run `cargo clippy -p conduit-core --all-targets -- -D warnings` and `cargo test -p conduit-core`. — done when: both commands exit 0 with zero warnings.

## Verify
```sh
cargo clippy -p conduit-core --all-targets -- -D warnings && cargo test -p conduit-core
```

## Escalate when
- `rusty_conduit_engine::routing::RoutingInput::validate()` rejects profile keys starting with `@` → stop, set Status: needs-human — reason: engine rejects `@` in profile names, need alternate prefix (e.g. `__tunnel_` / `__forward_`).
- Updating `validate_tunnel` or `v2_mapping` requires changing a v1 `SessionProfile` contract in `model.rs` or `validate.rs` → stop, set Status: needs-human — reason: describe the conflict.

## Log
- (append-only, one line per event)
- sub-task 1: added `ForwardProxyProtocol` and `PortForward.proxy_protocol` in `model.rs` (re-exported via `lib.rs`) with JSON round-trip test.
- sub-task 2: blocked — `crates/conduit-core/src/migrate_v2.rs:47-63` constructs `Tunnel` without `..Tunnel::default()` and is outside `Scope: In`; escalating to planner.
- planner resolved escalation: added `crates/conduit-core/src/migrate_v2.rs` and `crates/conduit-core/src/toml_io.rs` to `Scope: In`; confirmed `..Tunnel::default()` should be used on both `Tunnel` initializers so migrated/imported tunnels keep `forward.enabled = false`, `mitm = None`, `socks_block_web = false`. Returned sub-task 2 and phase-0001 to `todo` for executor continuation.
- sub-task 2: added `Tunnel.{forward, mitm, socks_block_web}`, `TargetRef`, prefix helpers, and `migrate_tunnel_profiles` in `v2_model.rs`, updated `migrate_v2.rs` with `..Tunnel::default()`, and added unit tests.
- sub-task 3: updated `tunnel_to_engine_config`, added `tunnel_forward_filter`, `proxy_referenced_forwards`, `proxy_referenced_targets`, updated `proxy_referenced_tunnels` and `build_routing_input` for synthetic `@tunnel:`/`@forward:` `External` profiles in `v2_mapping.rs`, exported from `lib.rs`, and added unit tests.
- sub-task 4: updated `validate_tunnel`, `validate_proxy`, and added `validate_proxy_with_tunnels` + `ProxyValidateError::UnknownTunnelForward` in `v2_validate.rs`, exported from `lib.rs`, and added unit tests.
- sub-task 5: ran full `conduit-core` clippy and test verification; both exited 0 with zero warnings and 146 tests passing.

## Evidence
- (append-only: command → observed result)
- `cargo test -p conduit-core port_forward_round_trips_with_and_without_proxy_protocol` → ok (1 passed)
- `cargo test -p conduit-core v2_model` → ok (12 passed)
- `cargo test -p conduit-core v2_mapping` → ok (12 passed)
- `cargo test -p conduit-core v2_validate` → ok (21 passed)
- `cargo clippy -p conduit-core --all-targets -- -D warnings && cargo test -p conduit-core` → exit 0 (0 warnings, 146 passed, 0 failed)
