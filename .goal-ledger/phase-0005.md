# phase-0005 — Build 7-tab Proxy editor, Proxy header (hot-reload/counters), and Log drawer quick actions

- Status: done
- Owner: executor
- Depends on: phase-0004
- Goal: Implement the full 7-tab Proxy editor (`ProxyEditor.svelte` + tab subcomponents), Proxy header (`gen #N · hot-reloaded`, `Save (Hot-Reload)` vs `Restart to Apply` banner, live counters, override indicator), and Log drawer (`LogDrawer.svelte`) filtering and quick actions (*Test route*, *Create rule for this host…*).
- Done when: `cd src-tauri/ui && npm run check && npm test && npm run build` passes with zero errors and zero warnings.
- Pattern to follow: `src-tauri/ui/src/lib/components/TunnelEditor.svelte`, `src-tauri/ui/src/lib/components/FilterEditor.svelte`, `src-tauri/ui/src/lib/components/MitmTab.svelte`, `src-tauri/ui/src/lib/components/LogDrawer.svelte`, `docs/MASTER-PLAN.md:295-302`

## Context
- Follow `docs/MASTER-PLAN.md` §9.2 for the 7 Proxy editor tabs:
  1. **Routing Rules (`ProxyRoutingTab.svelte`)**: table selector (`Unified` / `HTTP override` / `SOCKS override`), default target or failover chain, `resolve_dns` toggle with DNS-leak notice, reorderable rules list (up/down buttons + keyboard reorder + enable/disable toggle), condition chips, failover badges, URL-rule-without-MITM warning badge, rule editor drawer supporting every engine matcher (`inbound`, `host`, `host_wildcard`, `host_regex`, `cidr`, `ip`, `port`, `host_levels`, `bypass`, `weekday`, `time`, `url_wildcard`, `url_regex`, `keyword`, `match_all`, `resolve_dns`, `target`), and inline **Route Tester** (calls `api.testRoute`, shows table, matched rule, bypass, failover chain, redacted upstreams, highlights matched rule).
  2. **Upstream Profiles (`ProxyProfilesTab.svelte`)**: shows built-ins (`direct`, `block`) + all configured profiles (`http`, `https` with `tls_insecure_skip_verify`, `socks5`, `socks4a`, `composite`, `tunnel` referencing a Tunnel), color badge, write-only vaulted password (`api.setUpstreamPassword`) or `password_env` / `password_file`, import-from-Profile-Library picker, bypass lists, self-loop warning, and **Test Upstream** button (calls `api.testUpstream`, shows timing and redacted error).
  3. **Listeners & Network (`ProxyListenersTab.svelte`)**: bind address (with non-loopback warning), HTTP/SOCKS ports, mux checkbox, `max_connections`, live port-conflict check (`api.checkProxyPortConflicts`), `connect_timeout`, and TCP keepalive settings.
  4. **Global Filter**: mode (`Off` / `Allow` / `Block`), rule editor, bulk paste, host checker (reusing `FilterEditor.svelte`).
  5. **HTTPS MITM**: CA selector from Vault, `cert_ttl`, `cert_cache_max_entries`, `socks_block_web` (reusing `MitmTab.svelte` adapted for `Proxy`).
  6. **Import / Export & TOML (`ProxyImportExportTab.svelte`)**: clean placeholder panel explaining AirSwitch `.bak` / CLI `config.toml` / External TOML link mode coming in Milestone U4 (displays current `source` mode).
  7. **Logging & General (`ProxyLoggingTab.svelte`)**: name, `enabled`, `autostart`, log level/format, optional HTTP/SOCKS log file paths.
- **Proxy Header**: title, state pill, `gen #N · hot-reloaded` badge when running, `Restart to Apply` banner with Restart button when `restart_required` is true, live per-profile/total counters, Test Route shortcut, Save (Hot-Reload vs Save), Start/Stop/Restart, and tray override pill.
- **Log drawer (`LogDrawer.svelte`)**: support both Proxy and Tunnel logs, filter by kind/level/profile/rule/text, pause/copy/clear; on Proxy access log rows, add **Test route** (opens Route Tester pre-filled with that host) and **Create rule for this host…** (opens Routing Rules tab with a new draft rule for that host).
- Note: `npm run build` rewrites the tracked `src-tauri/ui/dist/` directory (which will be rebuilt and committed in phase-0006). After `npm run build` passes, restore `src-tauri/ui/dist/` (`git checkout -- src-tauri/ui/dist && git clean -fd src-tauri/ui/dist`) before committing so only `Scope: In` files are staged.

## Scope
- In: `src-tauri/ui/src/lib/components/ProxyEditor.svelte`, `src-tauri/ui/src/lib/components/ProxyRoutingTab.svelte` (create), `src-tauri/ui/src/lib/components/ProxyProfilesTab.svelte` (create), `src-tauri/ui/src/lib/components/ProxyListenersTab.svelte` (create), `src-tauri/ui/src/lib/components/ProxyImportExportTab.svelte` (create), `src-tauri/ui/src/lib/components/ProxyLoggingTab.svelte` (create), `src-tauri/ui/src/lib/components/LogDrawer.svelte`, `src-tauri/ui/src/lib/components/MitmTab.svelte`, `src-tauri/ui/src/lib/components/FilterEditor.svelte`, `src-tauri/ui/src/lib/components/SessionEditor.svelte` (remove if unused), `src-tauri/ui/src/lib/stores.svelte.ts` (only if needed for LogDrawer → ProxyEditor quick-action handoff)
- Out: `crates/`, `src-tauri/src/`

## Sub-tasks
1. [done] Create `ProxyRoutingTab.svelte` (table selector, default target/chain, `resolve_dns` notice, reorderable rules, condition/failover/URL-without-MITM badges, rule editor drawer, inline Route Tester with matched-rule highlight) — done when: `npm run check` passes.
2. [done] Create `ProxyProfilesTab.svelte` (built-ins + all `UpstreamKind` variants incl. `tunnel`, write-only vaulted password / `password_env`, Profile Library import, bypass, Test Upstream probe) and `ProxyListenersTab.svelte` (bind warning, ports, mux, `max_connections`, port-conflict check, `connect_timeout`, keepalive) — done when: `npm run check` passes.
3. [done] Create `ProxyImportExportTab.svelte` and `ProxyLoggingTab.svelte`, wire all 7 tabs + Proxy header (`gen #N · hot-reloaded`, `Restart to Apply` banner, counters, Save/Start/Stop) in `ProxyEditor.svelte` — done when: `npm run check` passes.
4. [done] Upgrade `LogDrawer.svelte` for Proxy & Tunnel logs with kind/level/profile/rule/text filters and *Test route* / *Create rule for this host…* quick actions, remove any unused legacy `SessionEditor.svelte`, and run `## Verify` — done when: `## Verify` exits 0.

## Verify
```sh
cd src-tauri/ui && npm run check && npm test && npm run build
```

## Escalate when
- `npm run check` reports a Svelte 5 reactivity or type error that requires changing `types.ts` / `stores.svelte.ts` (outside Scope) → stop, set Status: needs-human — reason: list the exact type or store change needed

## Log
- (append-only, one line per event)
- sub-task 4: rewrote LogDrawer.svelte for Proxy (app log + HTTP/SOCKS access records), Tunnel, and session logs with kind/level/profile/rule/text filters, pause/copy/clear per target, and per-access-row Test route / Create rule for this host… quick actions via store.requestProxyQuickAction; SessionEditor.svelte kept because App.svelte (out of scope) still imports it; restored src-tauri/ui/dist after build
- sub-task 3: created ProxyImportExportTab.svelte (U4 placeholder showing source mode) and ProxyLoggingTab.svelte (name/enabled/autostart, level/format, log file paths); rewrote ProxyEditor.svelte body with 7 keyboard-navigable tabs + error badges and header (state pill, gen #N · hot-reloaded, override pill with clear, live counters, Test Route shortcut, Save (Hot-Reload)/Save, Start/Stop/Restart, Restart to Apply banner, reload-error notice); MitmTab gained an optional target prop for Proxy, FilterEditor an optional errorPrefix and global scope
- sub-task 2: created ProxyProfilesTab.svelte (built-ins, all UpstreamKind variants incl. tunnel, color badge, write-only vault password via api.setUpstreamPassword or env/file source, Profile Library import, bypass, composite self-loop warning, Test Upstream probe) and ProxyListenersTab.svelte (bind non-loopback warning, ports + mux, max_connections, debounced api.checkProxyPortConflicts, connect_timeout, TCP keepalive)
- sub-task 1: created ProxyRoutingTab.svelte (table selector, default/failover target picker, resolve_dns notice, up/down + Alt+Arrow reorder, enable toggle, condition/failover/URL-without-MITM badges, rule editor drawer for every matcher, inline Route Tester with matched-rule highlight); added ProxyQuickAction handoff (proxyQuickAction, requestProxyQuickAction, takeProxyQuickAction) to stores.svelte.ts

## Evidence
- (append-only: command → observed result)
- `cd src-tauri/ui && npm run check` → 193 FILES 0 ERRORS 0 WARNINGS
- `cd src-tauri/ui && npm run check` → 195 FILES 0 ERRORS 0 WARNINGS
- `cd src-tauri/ui && npm run check` → 197 FILES 0 ERRORS 0 WARNINGS
- `cd src-tauri/ui && npm run check && npm test && npm run build` → exit 0 (svelte-check 197 files 0 errors 0 warnings; tests 93 pass 0 fail; vite ✓ built in 3.02s); `git checkout -- src-tauri/ui/dist && git clean -fdq src-tauri/ui/dist` → git status shows only Scope: In files + ledger
