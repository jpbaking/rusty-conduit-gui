# phase-0003 — Tauri controller, IPC, tray bridge, and frontend types/validation sync

- Status: done
- Owner: executor
- Depends on: phase-0002
- Goal: Wire the new core/runtime tunnel and routing capabilities through `src-tauri` controllers, tray bridge, and `src-tauri/ui` TypeScript wire types, client validation, and mock data.
- Done when: `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, and `(cd src-tauri/ui && npm run check && npm test)` all exit 0.
- Pattern to follow: `src-tauri/src/controller/proxies.rs:176-210` (`upsert_proxy`), `src-tauri/src/tray_bridge.rs:85-115` (proxy tray item building), `src-tauri/ui/src/lib/types.ts` and `src-tauri/ui/src/lib/validate.ts`.

## Context
`src-tauri` adapts `conduit-core` and `conduit-runtime` over Tauri IPC, and `src-tauri/ui/src/lib/types.ts` + `validate.ts` must exactly mirror the serialized Rust structs and validation rules. Existing saved configs may contain legacy `UpstreamKind::Tunnel` profiles in `proxy.profiles`, so `AppController` should run `migrate_tunnel_profiles` on load (and keep config valid). Also `src-tauri/ui/src/lib/mock.ts` must compile against updated `types.ts` so `npm run check` stays green.

## Scope
- In: `src-tauri/src/controller/proxies.rs`, `src-tauri/src/controller/tunnels.rs`, `src-tauri/src/controller/parity.rs`, `src-tauri/src/controller.rs`, `src-tauri/src/controller/import_export.rs`, `src-tauri/src/tray_bridge.rs`, `src-tauri/src/commands.rs`, `src-tauri/ui/src/lib/types.ts`, `src-tauri/ui/src/lib/validate.ts`, `src-tauri/ui/src/lib/validate.test.ts` (if present), `src-tauri/ui/src/lib/mock.ts`, `src-tauri/ui/src/lib/stores.svelte.ts`, `src-tauri/ui/src/lib/portForwards.ts`, `src-tauri/ui/src/lib/components/TunnelEditor.svelte` (only minimal compile-fix if `TunnelSnapshot.listeners` or `Tunnel.forward` breaks `npm run check`)
- Out: `crates/conduit-core/`, `crates/conduit-runtime/`, `src-tauri/ui/src/lib/components/ProxyRoutingTab.svelte`, `src-tauri/ui/src/lib/components/ProxyProfilesTab.svelte`, `src-tauri/ui/dist/`

## Sub-tasks
1. [done] In `src-tauri/src/controller/proxies.rs`, `src-tauri/src/controller/tunnels.rs`, `src-tauri/src/controller/parity.rs`, and `src-tauri/src/controller.rs`: (a) switch proxy validation to `validate_proxy_with_tunnels` passing the saved `&[Tunnel]` slice, (b) run `migrate_tunnel_profiles` on loaded proxies in `AppController` startup (persisting if any proxy was migrated), (c) in `parity.rs`, include tunnel forward listeners (`tunnels.forward_listeners()` / saved tunnel `forward` ports) in `check_port_conflicts` and `check_proxy_port_conflicts`, (d) keep `AppController::test_route` static and add `AppController::test_route_live(&self, ...)` calling `self.proxies.test_route_live(...)`, and call `controller.test_route_live(...)` from `src-tauri/src/commands.rs:442` so `@tunnel:` and `@forward:` targets show friendly upstream names without modifying `secret_leak_scan.rs`. — done when: `cargo test -p rusty-conduit-gui` passes.
2. [done] In `src-tauri/src/tray_bridge.rs`, keep `profiles` passing custom `proxy.profiles` names (do NOT expose raw `@tunnel:<uuid>` UUIDs in tray menu labels, since `conduit-tray` displays the override string verbatim). Verify `cargo test -p rusty-conduit-gui` and `cargo test -p conduit-tray` pass. — done when: `cargo test -p rusty-conduit-gui` and `cargo test -p conduit-tray` pass.
3. [done] In `src-tauri/ui/src/lib/types.ts`, add `ForwardProxyProtocol = "none" | "http" | "socks5"`, add `proxy_protocol: ForwardProxyProtocol` to `PortForward`, add `forward: ForwardConfig`, `mitm: MitmConfig | null`, `socks_block_web: boolean` to `Tunnel`, and add `listeners: ListenerInfo[]` to `TunnelSnapshot`. Update `src-tauri/ui/src/lib/mock.ts` and any minimal compile references (e.g. `TunnelEditor.svelte`, `portForwards.ts`) so `npm run check` passes. — done when: `(cd src-tauri/ui && npm run check)` exits 0.
4. [done] In `src-tauri/ui/src/lib/validate.ts`, add target helper constants/functions (`TUNNEL_TARGET_PREFIX = "@tunnel:"`, `FORWARD_TARGET_PREFIX = "@forward:"`, `tunnelTarget(id)`, `forwardTarget(tid, fid)`, `isSyntheticTarget(name)`), mirror `validate_tunnel` (always validate `forward.allow`/`block`, validate `forward` ports & `mitm` when `forward.enabled`, reject remote forward with `proxy_protocol !== "none"`), and mirror `validate_proxy_with_tunnels` (reject profile names starting with `@`, validate `@tunnel:` and `@forward:` targets against known tunnels/forwards). Update or add unit tests in `src-tauri/ui/src/lib/`. — done when: `(cd src-tauri/ui && npm run check && npm test)` exits 0.
5. [done] Run workspace Rust checks and UI checks: `cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && (cd src-tauri/ui && npm run check && npm test)`. — done when: command exits 0.

## Verify
```sh
cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && (cd src-tauri/ui && npm run check && npm test)
```

## Escalate when
- `crates/conduit-tray` cannot display a friendly label separate from the override target string `@tunnel:<uuid>` without changing `conduit-tray`'s public API → stop, set Status: needs-human — reason: ask whether to widen scope to `crates/conduit-tray/` or keep tray override limited to named profiles for now.
- Any existing Rust integration test in `src-tauri/tests/` fails due to the `migrate_tunnel_profiles` behavior on load → stop, set Status: needs-human — reason: describe the failing test.

## Log
- (append-only, one line per event)
- blocked on sub-task 1: `check_port_conflicts` / `check_proxy_port_conflicts` live in `src-tauri/src/controller/parity.rs` (outside `Scope: In`), and changing `AppController::test_route` to `&self` affects `src-tauri/tests/secret_leak_scan.rs:679,682` (outside `Scope: In`)
- planner resolved escalation: added `src-tauri/src/controller/parity.rs` to `Scope: In`, and specified keeping `AppController::test_route` static while adding `AppController::test_route_live(&self, ...)` called from `src-tauri/src/commands.rs:442`. Returned sub-task 1 and phase-0003 to `todo` for executor continuation.
- completed sub-task 1: wired `validate_proxy_with_tunnels`, startup `migrate_tunnel_profiles`, tunnel forward port conflict checks in `parity.rs`, and `AppController::test_route_live` in `commands.rs`
- completed sub-task 2: verified `tray_bridge.rs` keeps custom `proxy.profiles` names only and passes `rusty-conduit-gui` and `conduit-tray` tests
- completed sub-task 3: synced `types.ts`, `mock.ts`, `portForwards.ts`, `stores.svelte.ts`, `TunnelEditor.svelte`, and `validate.test.ts` with new `ForwardProxyProtocol`, `Tunnel`, and `TunnelSnapshot` fields
- completed sub-task 4: added target helpers and synced `tunnelErrors`/`proxyErrors` in `validate.ts`, updated `stores.svelte.ts` to pass full `Tunnel` objects, and added unit tests in `validate.test.ts`
- completed sub-task 5 and phase verification: full workspace clippy, Rust tests, svelte-check, and UI unit tests all passed

## Evidence
- (append-only: command → observed result)
- `rg -n "check_port_conflicts|validate_proxy|test_route|migrate_tunnel_profiles|forward_listeners" src-tauri/src` → `check_port_conflicts` at `src-tauri/src/controller/parity.rs:166`, `check_proxy_port_conflicts` at `src-tauri/src/controller/parity.rs:248`
- `rg -n "test_route|check_port_conflicts|UpstreamKind::Tunnel" src-tauri/tests/` → `AppController::test_route` called statically at `src-tauri/tests/secret_leak_scan.rs:679` and `682`
- `cargo test -p rusty-conduit-gui && cargo test -p conduit-tray` → exit 0 (`rusty-conduit-gui`: 176 unit + 6 secret_leak_scan passed; `conduit-tray`: 23 passed)
- `cd src-tauri/ui && npm run check` → exit 0 (`svelte-check found 0 errors and 0 warnings`)
- `cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && (cd src-tauri/ui && npm run check && npm test)` → exit 0 (0 clippy warnings; all workspace Rust tests passed; svelte-check 0 errors/warnings; 95/95 UI tests passed)
