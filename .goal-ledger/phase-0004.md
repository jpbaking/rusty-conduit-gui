# phase-0004 — src-tauri/ui: 7-tab SessionEditor shell & Tabs 1-3 (Chain+Agent, Forward, Reverse)

- Status: done
- Owner: executor
- Depends on: phase-0003
- Goal: Refactor `SessionEditor.svelte` into the Master Plan Section 8.2 7-Tab Session Editor, update `types.ts` / `api.ts` / `mock.ts` for all 44 backend commands and new `HopEntry` fields, and implement Tabs 1–3 (**Connection & Jump Chain** with per-hop Forwarded Keys picker, **Forward Proxy** with single-port mux & live port-conflict detection, and **Reverse Proxy (`-R`)** with exposure warning & mux indicator).
- Done when: `(cd src-tauri/ui && npm run check && npm run build)` exits 0 with Tabs 1–3 fully functional and clean placeholder panels for Tabs 4–7 (completed in `phase-0005`).
- Pattern to follow: `docs/MASTER-PLAN.md` Section 8.2 and `src-tauri/ui/src/lib/components/SessionEditor.svelte`

## Context
Master Plan Section 8.2 defines a 7-tab Session Editor:
1. Connection & Jump Chain
2. Forward Proxy
3. Reverse Proxy (`-R`)
4. Destination Filters
5. HTTPS MITM
6. Keepalive & Reconnect
7. Logging & Advanced

Key decisions already made:
- Tab 1 (`JumpChainBuilder` + `HopEditor`): when `hop.agent_forward` is enabled, show a **Forwarded Keys** multi-select checklist of vaulted keys (`hop.agent_forward_keys`) and an optional **Remote Command** input (`hop.agent_forward_command`), while keeping the clear security warning that root on that remote host can use forwarded keys while connected. (Remove the old "does not forward yet" caveat now that Phase 3 wired it!)
- Tab 2 (`ForwardProxyTab.svelte`): bind IP (with non-loopback warning when bind is not `127.0.0.1` / `::1`), HTTP port, SOCKS port, **Single-port multiplex** toggle (syncs HTTP & SOCKS to one shared port), `max_connections` (`0` = unlimited), and debounced live port-conflict check via `api.checkPortConflicts(...)`.
- Tab 3 (`ReverseProxyTab.svelte`): remote bind IP (with non-loopback / `GatewayPorts` exposure warning), remote HTTP port, remote SOCKS port, single-port mux indicator when both ports are equal and non-zero.
- Show per-tab validation error badges so the user can see immediately if another tab has an invalid field blocking Save.

## Scope
- In: `src-tauri/ui/src/**`, `src-tauri/ui/dist/**`
- Out: `crates/**`, `src-tauri/src/**`, `docs/MASTER-PLAN.md`

## Sub-tasks
1. [done] Update `src-tauri/ui/src/lib/types.ts`, `api.ts`, and `mock.ts` to add `agent_forward_keys` / `agent_forward_command` on `HopEntry` and typed clients + preview mocks for `check_port_conflicts`, `test_filter_rules`, `inspect_mitm_ca`, `export_config`, and `import_config` — done when: `cd src-tauri/ui && npm run check` exits 0
2. [done] Upgrade `src-tauri/ui/src/lib/components/HopEditor.svelte` with the per-hop **Forwarded Keys** multi-select picker (`agent_forward_keys`) and optional **Remote Command** (`agent_forward_command`) when `agent_forward` is checked, updating the security warning text — done when: `cd src-tauri/ui && npm run check` exits 0
3. [done] Implement `src-tauri/ui/src/lib/components/ForwardProxyTab.svelte` (bind IP + non-loopback warning, HTTP/SOCKS ports, single-port mux toggle, `max_connections`, live `checkPortConflicts` warnings) and `ReverseProxyTab.svelte` (remote bind IP + `GatewayPorts` warning, remote HTTP/SOCKS ports, mux indicator) — done when: `cd src-tauri/ui && npm run check` exits 0
4. [done] Refactor `src-tauri/ui/src/lib/components/SessionEditor.svelte` into the accessible 7-tab editor (`role="tablist"` / `role="tab"` / `role="tabpanel"` with error badges per tab) wiring Tabs 1–3 and clean placeholders for Tabs 4–7, and rebuild `src-tauri/ui/dist/` — done when: `(cd src-tauri/ui && npm run check && npm run build)` exits 0

## Verify
```sh
(cd src-tauri/ui && npm run check && npm run build)
```

## Escalate when
- Any Phase 3 IPC command signature in `src-tauri/src/commands.rs` mismatches the expected TypeScript contract → stop, set Status: needs-human — reason: exact signature mismatch

## Log
- (append-only, one line per event)
- sub-task 1: added hop agent fields, typed clients and preview mocks for the 5 Phase 3 commands; new hops and key deletion now handle agent_forward_keys
- sub-task 2: HopEditor gained the Forwarded Keys checklist and optional Remote Command, and the old not-forwarded caveat is gone
- sub-task 3: added ForwardProxyTab (bind warning, ports, mux toggle, max_connections, debounced conflict check), ReverseProxyTab (GatewayPorts warning, mux indicator), and a shared PortField
- sub-task 4: SessionEditor is now the accessible 7-tab editor with per-tab error badges, Tabs 1-3 wired, placeholders for Tabs 4-7, and dist rebuilt

## Evidence
- (append-only: command → observed result)
- cd src-tauri/ui && npm run check → 149 FILES 0 ERRORS 0 WARNINGS
- cd src-tauri/ui && npm run check → 149 FILES 0 ERRORS 0 WARNINGS; grep 'does not forward' src-tauri/ui/src → 0 matches
- cd src-tauri/ui && npm run check → 152 FILES 0 ERRORS 0 WARNINGS
- (cd src-tauri/ui && npm run check && npm run build) → exit 0; 152 FILES 0 ERRORS 0 WARNINGS; 148 modules, built in 3.58s
- ## Verify: (cd src-tauri/ui && npm run check && npm run build) → exit 0; 0 errors, 0 warnings; production bundle built
- headless Chromium against the Vite preview with mock IPC → 23 PASS, 0 FAIL, 0 console errors (tabs, keyboard nav, port conflicts, mux, badges, warnings, key picker, save round trip); not run against the real Tauri backend
