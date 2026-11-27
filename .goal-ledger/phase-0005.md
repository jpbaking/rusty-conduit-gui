# phase-0005 — UI: Tunnel editor Proxy/Filters/MITM tabs, -L proxy protocol, and plain Start mode

- Status: done
- Owner: executor
- Depends on: phase-0003
- Goal: Update the Tunnel editor to show Proxy (Forward + Reverse cards with clear guidance), Filters, and conditional MITM tabs, add the Proxy protocol selector to Local `-L` port forwards, and reword Tunnel Start mode into 3 plain radio choices.
- Done when: `(cd src-tauri/ui && npm run check && npm test)` exits 0 with zero warnings.
- Pattern to follow: `src-tauri/ui/src/lib/components/TunnelEditor.svelte`, `src-tauri/ui/src/lib/components/SessionEditor.svelte` (how `ProxyTab`, `FiltersTab`, and `MitmTab` are wired), `src-tauri/ui/src/lib/components/ForwardProxyTab.svelte`, `src-tauri/ui/src/lib/components/KeepaliveTab.svelte:133-169`, `src-tauri/ui/src/lib/components/PortForwardRow.svelte`.

## Context
Decisions already made by the user:
1. Tunnels must still have both **Forward** and **Reverse** cards in a **"Proxy"** tab (replacing today's "Reverse" tab). On a Tunnel, Forward is **off by default**, and can be toggled off even if Reverse and port forwards are also off (unlike legacy v1 sessions). Show a clear guidance note in the Forward card: Proxies that route through this tunnel dial it directly without needing a local forward listener; only enable Forward if you need a dedicated local bind address and port (`ssh -D` style). If Forward is enabled and a Proxy also uses this tunnel, the Proxy bypasses the tunnel's forward ip:port and tunnel MITM, while still enforcing the tunnel's configured filters.
2. Add a **"Filters"** tab to `TunnelEditor.svelte` editing `tunnel.forward.allow` / `tunnel.forward.block` (with a note that these filters apply both to the optional Forward listener and to all Proxy traffic routed through this tunnel) and `tunnel.reverse.reverse_allow` / `tunnel.reverse.reverse_block`.
3. Show a **"MITM"** tab in `TunnelEditor.svelte` **only when `tunnel.forward.enabled` is true** (reset `activeTab` to Proxy/Connection if Forward is toggled off while on MITM). Include a note that MITM applies only to this tunnel's own Forward listener, not to Proxies routing through the tunnel.
4. In `PortForwardRow.svelte`, for `Local -L` forwards only, add a **Proxy protocol** `<select>` (`None (raw TCP)` = `"none"`, `HTTP proxy` = `"http"`, `SOCKS5 proxy` = `"socks5"`) with a short hint that HTTP/SOCKS5 forwards appear as selectable profiles in Proxy Routing. When switching direction to `Remote -R`, reset `proxy_protocol` to `"none"`.
5. In `KeepaliveTab.svelte`, reword the Tunnel Start mode fieldset into 3 clear top-level radio options (no nested checkbox):
   - *Run only while a Proxy uses it* (`"linked"`)
   - *Start manually* (`{ manual: { autostart: false } }`)
   - *Start with the app* (`{ manual: { autostart: true } }`)
   Also update the header pill in `TunnelEditor.svelte` to reflect `"Auto-start"` when `manual.autostart` is true, `"Manual"` when `manual.autostart` is false, and `"Linked"` when `"linked"`.

## Scope
- In: `src-tauri/ui/src/lib/components/TunnelEditor.svelte`, `src-tauri/ui/src/lib/components/ForwardProxyTab.svelte`, `src-tauri/ui/src/lib/components/ReverseProxyTab.svelte`, `src-tauri/ui/src/lib/components/PortForwardsTab.svelte`, `src-tauri/ui/src/lib/components/FiltersTab.svelte`, `src-tauri/ui/src/lib/components/PortForwardRow.svelte`, `src-tauri/ui/src/lib/components/KeepaliveTab.svelte`, `src-tauri/ui/src/lib/portForwards.ts`, `src-tauri/ui/src/lib/portForwards.test.ts`
- Out: `crates/`, `src-tauri/src/`, `src-tauri/ui/src/lib/components/ProxyRoutingTab.svelte`, `src-tauri/ui/dist/`

## Sub-tasks
1. [done] In `src-tauri/ui/src/lib/components/TunnelEditor.svelte`: (a) wire `tunnel.forward`, `tunnel.mitm`, `tunnel.socks_block_web`, and `snapshot.listeners` through `tunnelAsSession`, `sessionIntoTunnel`, and `tunnelAsSessionView` (removing `NO_FORWARD`), (b) replace the `"Reverse"` tab with `"Proxy"` (rendering `ForwardProxyTab` with tunnel guidance + `ReverseProxyTab`), add `"Filters"` tab (rendering `FiltersTab` with tunnel filter note), and conditionally include the `"MITM"` tab (rendering `MitmTab`) only when `tunnel.forward.enabled` is true, (c) update `tabForField` and `activeTab` clamping when MITM tab disappears, (d) update the start-mode header pill (`Linked` / `Manual` / `Auto-start`). — done when: `TunnelEditor.svelte` compiles cleanly under `npm run check`.
2. [done] In `src-tauri/ui/src/lib/components/ForwardProxyTab.svelte`, detect tunnel mode (or accept an optional `isTunnel` prop) so that on a Tunnel: (a) `lockedReason` is always `undefined` (Forward can always be turned off), (b) the guidance note about Proxies dialing the tunnel directly (bypassing ip:port and tunnel MITM, while still enforcing tunnel filters) is shown, and (c) `ForwardProxyTab` reads/writes `editor.draft.forward` via `useChainEditor()` or props so it works identically for both `SessionEditor` and `TunnelEditor`. Check `FiltersTab.svelte` similarly so it works cleanly in `TunnelEditor` via the editor context or props. — done when: `(cd src-tauri/ui && npm run check)` exits 0.
3. [done] In `src-tauri/ui/src/lib/components/PortForwardRow.svelte` and `src-tauri/ui/src/lib/portForwards.ts`, add the **Proxy protocol** `<select>` (`none` / `http` / `socks5`) for `Local -L` forwards, reset `proxy_protocol` to `"none"` in `setDirection("remote")`, and ensure newly created `PortForward` objects include `proxy_protocol: "none"`. Update `portForwards.test.ts` to cover `proxy_protocol` defaults and round-trips. — done when: `(cd src-tauri/ui && npm run check && npm test)` exits 0.
4. [done] In `src-tauri/ui/src/lib/components/KeepaliveTab.svelte`, replace the 2-radio + nested-checkbox Start mode UI with the 3 plain radio choices (*Run only while a Proxy uses it*, *Start manually*, *Start with the app*) mapping directly to `"linked"`, `{ manual: { autostart: false } }`, and `{ manual: { autostart: true } }`. — done when: `(cd src-tauri/ui && npm run check && npm test)` exits 0.
5. [done] In `src-tauri/ui/src/lib/components/ReverseProxyTab.svelte` and `src-tauri/ui/src/lib/components/PortForwardsTab.svelte`, allow turning off Reverse proxy and Port Forwards freely when `ed.isTunnel` is true (`lockedReason` = `undefined` on Tunnels, since Tunnels need no local listener), while preserving the existing lock for legacy v1 `SessionEditor`. — done when: `(cd src-tauri/ui && npm run check && npm test)` exits 0.

## Verify
```sh
cd src-tauri/ui && npm run check && npm test
```

## Escalate when
- `ForwardProxyTab.svelte` or `FiltersTab.svelte` relies on `store.draft` in a way that breaks legacy `SessionEditor.svelte` when adapted for `TunnelEditor.svelte` → stop, set Status: needs-human — reason: describe the coupling.

## Log
- (append-only, one line per event)
- sub-task 1: wired `tunnel.forward`, `tunnel.mitm`, `tunnel.socks_block_web` in `TunnelEditor.svelte`, replaced Reverse with Proxy, added Filters and conditional MITM tabs, clamped `activeTab` when Forward is disabled, and updated start-mode header pill (`Linked` / `Manual` / `Auto-start`).
- sub-task 2: adapted `ForwardProxyTab.svelte` and `FiltersTab.svelte` to use `chainEditor()` with tunnel mode detection, unlocked Forward toggle on Tunnels, and added tunnel guidance/filter notes.
- sub-task 3: added Proxy protocol selector (`none` / `http` / `socks5`) for Local `-L` forwards in `PortForwardRow.svelte`, reset `proxy_protocol` to `"none"` on switch to Remote `-R`, verified `newForward` defaults in `portForwards.ts`, and added `proxy_protocol` tests in `portForwards.test.ts`.
- sub-task 4: replaced 2-radio + nested-checkbox Start mode in `KeepaliveTab.svelte` with 3 plain top-level radio choices (`Run only while a Proxy uses it`, `Start manually`, `Start with the app`) and removed unused `.nested` style.
- planner reopened phase-0005 with sub-task 5 to unlock `lockedReason` in `ReverseProxyTab.svelte` and `PortForwardsTab.svelte` when `ed.isTunnel` is true.
- sub-task 5: unlocked `lockedReason` when `ed.isTunnel` is true in `ReverseProxyTab.svelte` and `PortForwardsTab.svelte`, preserving the legacy v1 `SessionEditor` lock.

## Evidence
- (append-only: command → observed result)
- `cd src-tauri/ui && npm run check` → exit 0 (`svelte-check found 0 errors and 0 warnings`)
- `cd src-tauri/ui && npm run check` (after sub-task 2) → exit 0 (`svelte-check found 0 errors and 0 warnings`)
- `cd src-tauri/ui && npm run check && npm test` (after sub-task 3) → exit 0 (`svelte-check found 0 errors and 0 warnings`; 105/105 UI tests passed)
- `cd src-tauri/ui && npm run check && npm test` (after sub-task 4 / phase verify) → exit 0 (`svelte-check found 0 errors and 0 warnings`; 105/105 UI tests passed)
- `cd src-tauri/ui && npm run check && npm test` (after sub-task 5 / phase verify) → exit 0 (`svelte-check found 0 errors and 0 warnings`; 105/105 UI tests passed)
