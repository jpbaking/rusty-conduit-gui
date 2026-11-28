# phase-0004 — v2 UI fixes: CA/key usage, tunnel host-key prompt, preset targets, IPC types

- Status: done
- Owner: executor
- Depends on: phase-0003
- Goal: Make the CA and key delete flows warn about and confirm Proxies and Tunnels, open the host-key prompt after a Tunnel chain test, create tunnel presets with `@tunnel:<id>` targets, and add the missing `"proxy"` / `"tunnel"` IPC type variants.
- Done when: every command in `## Verify` exits 0.
- Pattern to follow: `src-tauri/ui/src/lib/stores.svelte.ts:946-966` (`testSelected` sets `testHostKey` from the first hop with `host_key`), `src-tauri/ui/src/lib/components/KeyVaultView.svelte:33-41` (`usageRefs` lists hosts, sessions, tunnels, proxies, and library profiles with a kind label), `src-tauri/ui/src/lib/validate.ts:510` (`tunnelTarget`)

## Context
The backend already returns `usage.proxies` and `usage.tunnels` for CAs and keys, and force-delete removes the CA or key from them. The UI looks only at `usage.sessions` (and `hosts`), so it force-stops running Proxies without listing them, and its "changed since you looked" check ignores new Proxy/Tunnel users.
`testTunnelChain` never sets `store.testHostKey`, so an unknown host key found by a Tunnel test never opens `HostKeyModal`. The backend's `trust_tested_host_key(id, sha256)` works for a Tunnel id (it is keyed by the id `test_tunnel_chain` used), so the existing `trustTestedHostKey` store method can be reused; after trusting, re-run the Tunnel test rather than the session test.
`newProxyFromPreset` still builds a legacy `{ type: "tunnel" }` profile. v2 routes straight to `@tunnel:<id>`: the "tunnel" preset sets `routing.default` to `tunnelTarget(id)` and adds no profile; the "switch" preset adds nothing (rules can pick the Tunnel from the target picker). The Rust side emits `"proxy"` and `"tunnel"` error codes (`src-tauri/src/controller.rs:144-145`) and port-conflict kinds (`src-tauri/src/controller/parity.rs:31`).
Escalation answered (planner, 2026-11-28): `src-tauri/DOX.md:15` and `src-tauri/ui/DOX.md:13` make `src-tauri/ui/dist/` a tracked build output that must be rebuilt and committed after source changes; the plan missed it. `dist/` is in scope and is committed with the phase.
`mock.ts` is the demo data behind `npm run dev` and the website screenshots: change it only as sub-task 6 says.
`src-tauri/ui/src/lib/validate.test.ts:568` builds a legacy `{ type: "tunnel" }` profile to test the validator; it does not assert the preset or `tunnelProfileName`, so it is not an escalation trigger — leave it unchanged.

## Scope
- In: `src-tauri/ui/src/lib/types.ts`, `src-tauri/ui/src/lib/stores.svelte.ts`, `src-tauri/ui/src/lib/components/CaVaultSection.svelte`, `src-tauri/ui/src/lib/mock.ts`, `src-tauri/ui/dist/` (rebuilt by `npm run build`; added by the planner after escalation)
- Out: all Rust code, every other component, `src-tauri/ui/package.json`, `package-lock.json`

## Sub-tasks
1. [done] `types.ts`: add `| "proxy"` and `| "tunnel"` to `AppErrorCode` directly after `| "runtime"`; change `PortConflictKind` to `"session" | "proxy" | "tunnel" | "os_socket"` — done when: `grep -c '| "proxy"' src-tauri/ui/src/lib/types.ts` prints `1` and `(cd src-tauri/ui && npm run check)` passes.
2. [done] `stores.svelte.ts`: in `deleteKey`, build `seen` and `current` from `hosts`, `sessions`, `tunnels ?? []`, and `proxies ?? []`; in `deleteMitmCa`, build them from `sessions` and `proxies ?? []`; `draftsUsingCa` also returns the names of `this.proxyDrafts` entries whose `mitm?.ca === id`; after a successful CA delete, also clear `mitm.ca` to `null` in matching `this.proxyDrafts` (same shape as the existing `this.drafts` loop) — done when: `(cd src-tauri/ui && npm run check)` passes.
3. [done] `CaVaultSection.svelte`: initialize `deleteUsage` with `proxies: []`; `runningIds` also includes `store.proxies` whose `snapshot.state.state` is `"starting"`, `"running"`, or `"reloading"` (by `profile.id`); `affected` = `deleteUsage.sessions.length + (deleteUsage.proxies ?? []).length`; the delete dialog lists sessions then proxies, each proxy line as `{ref.name} (Proxy)` with the same running pill; `usageNames` joins sessions and proxies; `usageLabel` says `item`/`items` instead of `session`/`sessions`; the dialog text says "These sessions and Proxies will have no CA" — done when: `(cd src-tauri/ui && npm run check)` passes and `grep -c 'deleteUsage.proxies' src-tauri/ui/src/lib/components/CaVaultSection.svelte` prints at least `2`.
4. [done] `stores.svelte.ts` `testTunnelChain`: set `this.testHostKey = null` at the start; after a result for the still-selected Tunnel, take the first `result.hops` entry with `host_key` and set `this.testHostKey = { sessionId: id, sessionName: <that Tunnel's profile.name>, prompt, source: "test" }`. In `trustTestedHostKey`, after `this.refresh()`, call `await this.testTunnelChain(pending.sessionId)` when `this.selectedTunnelId === pending.sessionId`, otherwise keep the existing `testSelected()` branch — done when: `(cd src-tauri/ui && npm run check)` passes.
5. [done] `stores.svelte.ts` `newProxyFromPreset`: delete the whole `if (preset !== "direct" && ...) { ... }` block and, in its place, write `if (preset === "tunnel") proxy.routing = { ...proxy.routing, default: tunnelTarget(tunnel?.id ?? tunnelId ?? NEW_SESSION_ID) };` (import `tunnelTarget` from `./validate`). Then delete `export function tunnelProfileName` (lines 149-152); the planner checked it has no other caller — done when: `grep -rn 'tunnelProfileName\|type: "tunnel", tunnel_id' src-tauri/ui/src/lib/stores.svelte.ts` prints nothing and `(cd src-tauri/ui && npm run check && npm test)` passes.
6. [done] `mock.ts`: in `check_proxy_port_conflicts` (line ~754) use `kind: "proxy"`; in `proxyA` (line ~411) remove the `upstream("staging", { type: "tunnel", ... })` profile and change the `staging` rule's `target` to `` `@tunnel:${TUNNEL_A}` `` — done when: `grep -c 'type: "tunnel"' src-tauri/ui/src/lib/mock.ts` prints `0` and `(cd src-tauri/ui && npm run build)` passes.

## Verify
```sh
(cd src-tauri/ui && npm ci && npm run check && npm test && npm run build)
git diff --exit-code -- crates src-tauri/src src-tauri/ui/package.json src-tauri/ui/package-lock.json
git diff --name-only -- src-tauri/ui | sort
```
- The last command must list only the four source files under `Scope: In` plus `src-tauri/ui/dist/` build output.
- manual (planner): `npm run dev`, open the Vault page and delete a CA used by the demo "Work" Proxy; the dialog lists it as a Proxy.

## Escalate when
- `npm run check` reports a type error outside the four files → stop, set Status: needs-human — reason: paste the error.
- The Tunnel's name cannot be found for `sessionName` (no `this.tunnels` entry for `id`) → use `"Tunnel"` and note it in the Log; any other missing data → stop, set Status: needs-human — reason: describe it.
- A `*.test.ts` file asserts the old preset profile or `tunnelProfileName` → stop, set Status: needs-human — reason: name the test.

## Log
- (append-only, one line per event)
- planner: before delegation, noted in Context that validate.test.ts:568 (legacy tunnel profile in a validator test) is not an escalation trigger
- sub-task 1: added `"proxy"` and `"tunnel"` to `AppErrorCode` and `PortConflictKind` in `src-tauri/ui/src/lib/types.ts`
- sub-task 2: included `tunnels`/`proxies` in `deleteKey`, `proxies` in `deleteMitmCa`, and `proxyDrafts` in `draftsUsingCa`/CA-delete cleanup in `src-tauri/ui/src/lib/stores.svelte.ts`
- sub-task 3: updated `src-tauri/ui/src/lib/components/CaVaultSection.svelte` to track, list, and label affected Proxies alongside sessions
- sub-task 4: wired `testHostKey` in `testTunnelChain` and tunnel re-test branch in `trustTestedHostKey` in `src-tauri/ui/src/lib/stores.svelte.ts` (falling back to `"Tunnel"` if `this.tunnels` has no entry for `id`)
- sub-task 5: updated `newProxyFromPreset` to use `tunnelTarget(...)` and removed `tunnelProfileName` in `src-tauri/ui/src/lib/stores.svelte.ts`
- sub-task 6: updated `check_proxy_port_conflicts` (`kind: "proxy"`) and `proxyA` (`@tunnel:${TUNNEL_A}` target, removed legacy tunnel profile) in `src-tauri/ui/src/lib/mock.ts`
- verify: all 6 sub-tasks and npm ci/check/test/build passed, but `git diff --name-only -- src-tauri/ui | sort` included tracked `src-tauri/ui/dist/` files regenerated by `npm run build`; escalating rather than modifying or committing outside `Scope: In`

- planner answered the dist/ escalation, reviewed the source diff (matches sub-tasks 1-6, four files only), re-ran ## Verify, and closed the phase with the rebuilt dist/
- manual dev-server check (CA delete dialog lists the demo Proxy) not performed by the planner; left for the user's review

## Evidence
- (append-only: command → observed result)
- `grep -c '| "proxy"' src-tauri/ui/src/lib/types.ts && (cd src-tauri/ui && npm run check)` → `2` (both `AppErrorCode` and `PortConflictKind` contain `| "proxy"`), svelte-check found 0 errors and 0 warnings
- `(cd src-tauri/ui && npm run check)` → svelte-check found 0 errors and 0 warnings
- `(cd src-tauri/ui && npm run check) && grep -c 'deleteUsage.proxies' src-tauri/ui/src/lib/components/CaVaultSection.svelte` → svelte-check found 0 errors and 0 warnings, `2`
- `(cd src-tauri/ui && npm run check)` → svelte-check found 0 errors and 0 warnings
- `! grep -rn 'tunnelProfileName\|type: "tunnel", tunnel_id' src-tauri/ui/src/lib/stores.svelte.ts && (cd src-tauri/ui && npm run check && npm test)` → 0 matches, svelte-check 0 errors/0 warnings, 119/119 tests pass
- `(grep -c 'type: "tunnel"' src-tauri/ui/src/lib/mock.ts || true) && (cd src-tauri/ui && npm run build)` → `0`, vite build succeeded in 405ms
- `Verify`: `(cd src-tauri/ui && npm ci && npm run check && npm test && npm run build)` → exit 0 (0 check errors/warnings, 119/119 tests pass, built in 522ms); `git diff --exit-code -- crates src-tauri/src src-tauri/ui/package.json src-tauri/ui/package-lock.json` → exit 0; `git diff --name-only -- src-tauri/ui | sort` → listed the 4 `Scope: In` files plus `src-tauri/ui/dist/assets/dist-js-D_VMHjsH.js`, `src-tauri/ui/dist/assets/index-Cb0qFUBZ.js`, `src-tauri/ui/dist/index.html` (plus untracked `dist/assets/dist-js-Dayu6qH8.js`, `dist/assets/index-B03qwwP_.js`)
- planner: `(cd src-tauri/ui && npm ci && npm run check && npm test && npm run build)` → svelte-check 0 errors / 0 warnings; tests 119 pass, 0 fail; vite build ok
- planner: `git diff --exit-code -- crates src-tauri/src src-tauri/ui/package.json src-tauri/ui/package-lock.json` → exit 0; `grep -c 'type: "tunnel"' mock.ts` → 0; no `tunnelProfileName` in stores.svelte.ts; `grep -c 'deleteUsage.proxies' CaVaultSection.svelte` → 2
