# phase-0003 — Update Svelte UI core layer (types, api, mock, stores, validation, and tests) for v2 Proxies and Tunnels

- Status: done
- Owner: executor
- Depends on: phase-0002
- Goal: Update `src-tauri/ui/src/lib/` (`types.ts`, `api.ts`, `mock.ts`, `stores.svelte.ts`, `validate.ts`, and unit tests) to model and manage v2 `Proxy`, `Tunnel`, `UpstreamProfile`, routing rules, Profile Library, Route Tester, Test Upstream, and tray overrides.
- Done when: `cd src-tauri/ui && npm run check && npm test && npm run build` exits 0 with new frontend unit tests covering Proxy/Tunnel/rule validation.
- Pattern to follow: `src-tauri/ui/src/lib/types.ts`, `src-tauri/ui/src/lib/api.ts`, `src-tauri/ui/src/lib/stores.svelte.ts`, `src-tauri/ui/src/lib/validate.ts`

## Context
- Keep existing Svelte components compiling during this phase (phases 4 & 5 replace/re-home the UI components). Do not break `npm run check` or `npm run build`.
- `types.ts`: add TypeScript interfaces matching the Rust serde wire shapes from `conduit-core/src/v2_model.rs`, `conduit-runtime/src/proxy_manager.rs`, `conduit-runtime/src/tunnel_manager.rs`, and `src-tauri/src/controller/{proxies,tunnels}.rs`:
  - `Proxy`, `ProxyId`, `SourceMode`, `ListenerConfig`, `NetworkConfig`, `GlobalFilterConfig`, `UpstreamProfile`, `UpstreamKind`, `UpstreamPasswordSource`, `RouteInbound`, `RouteTarget`, `RoutePortSpec`, `RouteHostLevels`, `RoutingRule`, `RoutingTable`, `RoutingTablesConfig`, `ProxyState`, `ProxySnapshot`, `ProxyTrafficSnapshot`, `ProxyView`, `RouteTestResult`, `RouteTestTarget`, `UpstreamProbeResult`.
  - `Tunnel`, `TunnelId`, `TunnelStartMode`, `TunnelSnapshot`, `TunnelView`.
- `api.ts` & `mock.ts`: add typed invoke wrappers and browser-preview mock implementations for all new v2 commands (`list_proxies`, `upsert_proxy`, `delete_proxy`, `duplicate_proxy`, `start_proxy`, `stop_proxy`, `restart_proxy`, `set_proxy_override`, `get_proxy_logs`, `clear_proxy_logs`, `get_proxy_access_records`, `test_route`, `test_upstream`, `list_tunnels`, `upsert_tunnel`, `delete_tunnel`, `duplicate_tunnel`, `start_tunnel`, `stop_tunnel`, `restart_tunnel`, `get_tunnel_logs`, `clear_tunnel_logs`, `approve_tunnel_host_key`, `reject_tunnel_host_key`, `test_tunnel_chain`, `list_profile_library`, `upsert_library_profile`, `delete_library_profile`, `set_upstream_password`, `check_proxy_port_conflicts`).
- `stores.svelte.ts`: add reactive state & actions for `proxies`, `tunnels`, `profileLibrary`, active selection (`proxy` | `tunnel` | `hosts` | `profileLibrary` | `vault` | `settings`), draft editing for both Proxy and Tunnel, `proxy-state-changed` / `proxy-reloaded` / `proxy-override-changed` / `tunnel-state-changed` event subscriptions, and `newProxyFromPreset("direct" | "tunnel" | "switch")` + `newTunnel()` factories. Note: tray "View Logs" emits `UiEvent::ViewLogs { session_id: <uuid> }` for Proxies, Tunnels, and legacy sessions (UUIDs never collide), so handle `view_logs` by checking `proxies`, `tunnels`, and `sessions` to open the log drawer for the matching item.
- `validate.ts` & `validate.test.ts`: add `proxyErrors(proxy, knownTunnels)` and `tunnelErrors(tunnel)` matching `conduit-core`'s `validate_proxy` and `validate_tunnel` rules, plus unit tests.

## Scope
- In: `src-tauri/ui/src/lib/types.ts`, `src-tauri/ui/src/lib/api.ts`, `src-tauri/ui/src/lib/mock.ts`, `src-tauri/ui/src/lib/stores.svelte.ts`, `src-tauri/ui/src/lib/validate.ts`, `src-tauri/ui/src/lib/validate.test.ts`
- Out: `crates/`, `src-tauri/src/`, `src-tauri/ui/src/lib/components/`

## Sub-tasks
1. [done] Add all v2 TypeScript wire types (`Proxy`, `Tunnel`, `UpstreamProfile`, `RoutingRule`, snapshots, Route Tester, Test Upstream) to `src-tauri/ui/src/lib/types.ts` — done when: `npm run check` passes.
2. [done] Add v2 command wrappers in `src-tauri/ui/src/lib/api.ts` and browser-preview mock handlers in `src-tauri/ui/src/lib/mock.ts` — done when: `npm run check` passes.
3. [done] Extend `src-tauri/ui/src/lib/stores.svelte.ts` with reactive `proxies`, `tunnels`, `profileLibrary`, v2 draft/save/hot-reload/override/start/stop actions, and v2 event listeners — done when: `npm run check` passes.
4. [done] Add `proxyErrors` and `tunnelErrors` to `src-tauri/ui/src/lib/validate.ts` and unit tests to `src-tauri/ui/src/lib/validate.test.ts`, then run `## Verify` — done when: `## Verify` exits 0.

## Verify
```sh
cd src-tauri/ui && npm run check && npm test && npm run build
```

## Escalate when
- A Rust serde tag or field name in `commands.rs` / `v2_model.rs` is ambiguous → stop, set Status: needs-human — reason: document the exact field name mismatch

## Log
- (append-only, one line per event)
- sub-task 1: added v2 wire types (Tunnel, Proxy, UpstreamProfile, UpstreamKind, routing, ProxyState/Snapshot/View/SaveResult, AccessRecordView, RouteTest*, UpstreamProbeResult, TunnelSnapshot/View/ChainTestResult, ProxyEvent/TunnelEvent) to types.ts; added Usage.tunnels/proxies/library_profiles as optional (components outside scope build Usage literals); updated mock Usage literals
- sub-task 2: added typed wrappers for all 30 listed v2 commands (+ start_all_v2/stop_all_v2) and subscribeV2Events (proxy-state-changed, proxy-reloaded, proxy-override-changed, tunnel-state-changed) to api.ts; added in-memory browser-preview handlers for every v2 command to mock.ts via dispatchV2
- sub-task 3: extended stores.svelte.ts with proxies/tunnels/profileLibrary state, NavView v2 members (proxy/tunnel/hosts/profileLibrary/vault/settings, legacy sessions/keys kept), Proxy+Tunnel drafts with save (ProxySaveNote for gen #N/hot-reload/reload_error)/discard/duplicate/delete/enable, start/stop/restart/override/Route Tester/Test Upstream/Test Chain/library actions, newProxyFromPreset(direct|tunnel|switch) + newTunnel, v2 event subscription (proxy-state-changed/proxy-reloaded/proxy-override-changed/tunnel-state-changed) with snapshot replay, v2 snapshot polling, and view-logs resolving proxies → tunnels → sessions via openLogsFor/logTarget
- sub-task 4: added tunnelErrors(tunnel) and proxyErrors(proxy, knownTunnels) (+ portSpecError, BUILTIN_PROFILES) to validate.ts mirroring validate_tunnel / validate_proxy and the engine's profile, target, composite, self-loop, port-spec, cidr/ip, and host_levels checks; renamed the private v1 keepalive helper to keepaliveErrors(prefix) and generalized portForwardErrors/opensshErrors (v1 keys unchanged); wired proxyDraftErrors/tunnelDraftErrors into the store; added 16 v2 tests to validate.test.ts
- note: `npm run build` rewrites the tracked `src-tauri/ui/dist/` (outside Scope: In); restored it to HEAD with `git checkout -- src-tauri/ui/dist` and removed the 2 new hashed assets instead of committing it
- phase-0003 done: Verify exit 0

## Evidence
- (append-only: command → observed result)
- sub-task 1: `cd src-tauri/ui && npm run check` → COMPLETED 188 FILES 0 ERRORS 0 WARNINGS
- sub-task 2: `cd src-tauri/ui && npm run check` → COMPLETED 188 FILES 0 ERRORS 0 WARNINGS
- sub-task 3: `cd src-tauri/ui && npm run check` → COMPLETED 188 FILES 0 ERRORS 0 WARNINGS
- sub-task 4 / ## Verify: `cd src-tauri/ui && npm run check && npm test && npm run build` → exit 0; svelte-check COMPLETED 188 FILES 0 ERRORS 0 WARNINGS; node --test tests 93 pass 93 fail 0; vite ✓ built in 2.14s
- scope: `git status --short` after restoring dist → only the 6 Scope-In files + .goal-ledger modified
