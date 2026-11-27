# phase-0004 — UI: AirSwitch-style Proxy Routing tab and simplified Upstream servers tab

- Status: done
- Owner: executor
- Depends on: phase-0003
- Goal: Rebuild `ProxyRoutingTab.svelte` into an AirSwitch-style drag-ordered routing table with grouped condition types, inline details editors, grouped profile pickers, and a pinned Default row, and simplify `ProxyProfilesTab.svelte` / `ProxyEditor.svelte` to "Upstream servers".
- Done when: `(cd src-tauri/ui && npm run check && npm test)` exits 0 with unit tests covering rule-to-row classification, inline condition editing, AirSwitch IP/CIDR handling, drag reorder logic, and target resolution.
- Pattern to follow: `src-tauri/ui/src/lib/components/ProxyRoutingTab.svelte` (existing store wiring, Route Tester, quick actions, and Advanced drawer), `src-tauri/ui/src/lib/components/ProxyEditor.svelte:30-47` (`proxyMode`).

## Context
Users found the previous Routing tab (drawer with 14 matcher textareas + manual Tunnel upstream profiles + 3 table tabs) far too complex compared to AirSwitch. Decisions already made by the user:
1. Each row has: (a) a drag handle column (`⋮⋮`) where left-click-and-hold drags the row up/down to reorder priority (plus `Alt+↑/↓` keyboard fallback on the handle for accessibility), (b) an enabled toggle (replacing AirSwitch's FalseCondition), (c) a grouped Condition type `<select>`, (d) an inline Condition details editor with AirSwitch placeholder examples, (e) a grouped Profile `<select>`, and (f) a Delete (`✕`) button.
2. Grouped Condition types (full AirSwitch parity + our extras):
   - **Host**: `Host wildcard` (`e.g. *.example.com`, `|` separates alternatives), `Host (exact)` (`e.g. example.com`), `Host regex` (`e.g. (^|\.)example\.com$`), `Host levels` (two compact number inputs `min` `~` `max`), `IP / CIDR` (`e.g. 10.0.0.0/8` or `192.168.1.1`; stored in `rule.cidr`)
   - **URL**: `URL wildcard` (`e.g. http://*.example.com/api/*`), `URL regex` (`e.g. ^http://example\.com/api/`), `Keyword` (`e.g. example`) — all three show a compact warning badge when `!proxy.mitm`
   - **Special**: `Weekday` (7 compact day checkboxes Mon–Sun), `Time` (compact start–end range inputs, e.g. `09:00`–`17:30`), `Port` (`e.g. 443` or `8000-8999`), `Always (match all)`
   - **Advanced…**: opens the existing full rule drawer (multi-condition rules, bypass, inbound, per-rule DNS, failover chains). Any rule with multiple matchers, `bypass`, `inbound`, `resolve_dns`, or a failover chain automatically renders in Advanced summary mode with an `Edit…` button.
3. Fix the existing bug in the Advanced drawer: the `match_all` checkbox label must accurately state `"Match all (matches every request unconditionally; multiple conditions on one rule are always ANDed)"`.
4. Grouped Profile `<select>` options:
   - **Built-in**: `DIRECT` (`"direct"`), `BLOCK` (`"block"`)
   - **Tunnels**: each tunnel in `store.tunnels` (`@tunnel:<id>`)
   - **Tunnel forwards**: each `Local` `PortForward` across `store.tunnels` with `proxy_protocol !== "none"` (`@forward:<tid>:<fid>`, labeled `<tunnel name> › <forward name or port> (HTTP|SOCKS5)`)
   - **Upstream servers**: each profile in `proxy.profiles`
   - If a saved target is missing/unknown, show it as a disabled/bad option so the user sees the validation error clearly.
5. The LAST row is ALWAYS pinned (not draggable) as **Default (everything else)** using the same grouped Profile `<select>`. A Proxy with 0 rules shows just this Default row (enabling DIRECT + optional MITM/filter, or single-tunnel routing, with zero rules).
6. HTTP/SOCKS split override tables move behind a collapsed **"Advanced: HTTP / SOCKS split tables"** toggle (auto-expanded only if `routing.http` or `routing.socks` is already set).
7. Rename the "Profiles" tab in `ProxyEditor.svelte` to **"Upstream servers"** and remove `"tunnel"` from the `KINDS` dropdown in `ProxyProfilesTab.svelte` (keep rendering any legacy `tunnel` profile gracefully if present, with a note that tunnels are now picked directly in Routing).

## Scope
- In: `src-tauri/ui/src/lib/components/ProxyRoutingTab.svelte`, `src-tauri/ui/src/lib/components/ProxyEditor.svelte`, `src-tauri/ui/src/lib/components/ProxyProfilesTab.svelte`, `src-tauri/ui/src/lib/routingRows.ts` (new pure helper module for row/condition mapping & unit tests), `src-tauri/ui/src/lib/routingRows.test.ts` (new unit tests), `src-tauri/ui/src/app.css` (only if small shared table/drag styles are needed)
- Out: `crates/`, `src-tauri/src/`, `src-tauri/ui/src/lib/components/TunnelEditor.svelte`, `src-tauri/ui/dist/`

## Sub-tasks
1. [done] Create `src-tauri/ui/src/lib/routingRows.ts` with pure, testable helpers: `ConditionKind` union, `CONDITION_GROUPS` (with labels and AirSwitch placeholder examples), `classifyRule(rule: RoutingRule)` (detects single simple condition vs `"advanced"`), `ruleDetailText(rule, kind)` / `applySimpleCondition(rule, kind, value)` (handling pipe-separated wildcards, IP/CIDR stored in `cidr`, `host_levels` min/max, `weekday` 7-day booleans, `time` start/end, `port`, `match_all`), `reorderList<T>(items, fromIndex, toIndex)`, and `buildProfileOptionGroups(tunnels, proxyProfiles)` + `formatTargetLabel(target, tunnels, proxyProfiles)`. — done when: unit tests in `src-tauri/ui/src/lib/routingRows.test.ts` pass for every condition type, round-trip, reorder, and profile group.
2. [done] Rebuild `src-tauri/ui/src/lib/components/ProxyRoutingTab.svelte` around the AirSwitch-style table using `routingRows.ts`: drag handle column (`draggable` / pointer drag with clear insertion border + `Alt+↑/↓` keyboard fallback), enabled toggle, grouped Condition type `<select>`, inline details editor per type (including inline validation errors and URL-without-MITM badge), grouped Profile `<select>`, Delete button, and pinned non-draggable **Default (everything else)** last row. Add `+ Add condition` button, `Resolve DNS locally` checkbox, collapsed `Advanced: HTTP / SOCKS split tables` disclosure (auto-open if an override exists), and keep the Advanced rule drawer (with the fixed `match_all` label) + Route Tester (highlighting the matched rule row or the Default row, and displaying friendly target names). — done when: `(cd src-tauri/ui && npm run check)` passes with zero warnings.
3. [done] Update `src-tauri/ui/src/lib/components/ProxyEditor.svelte` (rename "Profiles" tab to "Upstream servers", update `proxyMode` to recognize `@tunnel:<id>` as `"Tunnel"` and `@forward:<tid>:<fid>` as `"Tunnel"` or `"Upstream"`, format friendly override pill label if overriding to `@tunnel:`/`@forward:`) and `src-tauri/ui/src/lib/components/ProxyProfilesTab.svelte` (remove `"tunnel"` from `KINDS` for new profiles, keep legacy tunnel profiles readable with a migration note, update copy to "Upstream servers"). — done when: `(cd src-tauri/ui && npm run check && npm test)` passes with zero warnings.

## Verify
```sh
cd src-tauri/ui && npm run check && npm test
```

## Escalate when
- Any `svelte-check` accessibility warning on the drag handle cannot be resolved cleanly with standard ARIA/button semantics → stop, set Status: needs-human — reason: paste the exact svelte-check warning.
- `ProxyEditor.svelte` or `NewProxyWizardModal.svelte` creates `UpstreamKind::Tunnel` profiles in a way that conflicts with removing `"tunnel"` from `ProxyProfilesTab` → stop, set Status: needs-human — reason: name the file and line.

## Log
- (append-only, one line per event)
- sub-task 1: created `src-tauri/ui/src/lib/routingRows.ts` and `src-tauri/ui/src/lib/routingRows.test.ts` with condition classification, round-trip editing, IP/CIDR normalization, list reordering, and grouped profile options/labels
- sub-task 2: rebuilt `src-tauri/ui/src/lib/components/ProxyRoutingTab.svelte` as an AirSwitch-style drag-ordered routing table with grouped conditions, inline editors, grouped profile pickers, pinned Default row, collapsed HTTP/SOCKS split tables disclosure, fixed `match_all` label in Advanced drawer, and Route Tester highlighting/labels
- sub-task 3: updated `src-tauri/ui/src/lib/components/ProxyEditor.svelte` (renamed tab to "Upstream servers", recognized `@tunnel:`/`@forward:` in `proxyMode`, formatted override pill and traffic counter labels) and `src-tauri/ui/src/lib/components/ProxyProfilesTab.svelte` (removed `"tunnel"` from `KINDS`, kept legacy tunnel profiles readable with migration note, updated copy to "Upstream servers")

## Evidence
- (append-only: command → observed result)
- `cd src-tauri/ui && node --experimental-strip-types --test src/lib/routingRows.test.ts` → 9 passed, 0 failed
- `cd src-tauri/ui && npm run check` → exit 0 (0 errors, 0 warnings)
- `cd src-tauri/ui && npm run check && npm test` → exit 0 (svelte-check: 0 errors, 0 warnings; node test: 104 passed, 0 failed)
