# phase-0004 — src-tauri/ui Svelte 5 scaffold, typed IPC client, shell & live log drawer

- Status: done
- Owner: executor
- Depends on: phase-0002, phase-0003
- Goal: Scaffold the Svelte 5 + TypeScript + Vite frontend in `src-tauri/ui/`, build the typed Tauri IPC client and reactive state stores, and implement the core Manage Window shell (searchable Session Sidebar, Header Bar with live stats/actions, and collapsible Live Log Drawer).
- Done when: `(cd src-tauri/ui && npm run check && npm run build) && cargo check -p rusty-conduit-ssh-gui` exits 0 with zero TypeScript/Svelte errors and a clean production bundle in `src-tauri/ui/dist/`.
- Pattern to follow: `docs/MASTER-PLAN.md` Section 8.2

## Context
`src-tauri/ui/` is a clean, lightweight Svelte 5 (runes: `$state`, `$derived`, `$effect`) + TypeScript + Vite application that talks exclusively to `src-tauri`'s typed IPC commands and events (`@tauri-apps/api`).
Key decisions already made:
- Use `npm` (Node 26 / npm 11 installed on this host; `pnpm` is not installed).
- Add `src-tauri/ui/node_modules/` and `src-tauri/ui/dist/` to `.gitignore` — wait: `tauri::generate_context!()` expects `frontendDist` (`ui/dist`) to exist at Rust build time, so keep `src-tauri/ui/node_modules` in `.gitignore` and configure `tauri.conf.json` `frontendDist` to `ui/dist` (built by `npm run build`).
- Never store or request plaintext secrets from the backend; secret inputs are write-only and cleared immediately on submit.
- Follow Section 8.2 layout:
  - Left Sidebar: searchable session list with live status indicators (`●` Connected, `◐` Starting/Reconnecting, `!` NeedsAttention/AwaitingHostKey/Locked/Failed, `○` Stopped), `+ New Session`, and nav items for **Sessions**, **Host Profiles**, **Key Vault**, and **Settings**.
  - Dismissible no-tray-host info banner when `tray_available === false`, plus a focusable clipboard-fallback dialog when `clipboard-fallback` fires.
  - Header Bar: session title, live state pill, active connections + bytes in/out counters, `[Test Chain]`, `[Save]`, `[Start / Stop]`.
  - Bottom Collapsible Log Drawer: virtualized/windowed live diagnostic + access log viewer per session with level filter, text search, pause/autoscroll, copy, and clear.
- **Exact `src-tauri` shell event contract (from `src-tauri/src/window.rs` & `commands.rs`):** After attaching Tauri event listeners, call `invoke("shell_ready")` to flush queued startup events, and handle `tray-status`, `runtime-event`, `runtime-lagged`, `clipboard-fallback`, `view-logs`, `unlock-vault`, `close-confirm` (calling `resolve_close`), and `quit-confirm` (calling `resolve_close`).
- **Planner answers to escalation:**
  1. `.svelte` module typing: a `.svelte` file without `<script lang="ts">` is treated by `svelte-check` as JS and triggers `noImplicitAny` unless `allowJs` is enabled. Add `"allowJs": true` and `"checkJs": true` to `src-tauri/ui/tsconfig.json` (standard Vite `svelte-ts` config), and include `<script lang="ts">` in `.svelte` components.
  2. `src-tauri/ui/dist/`: commit the `npm run build` output in `src-tauri/ui/dist/` (do not gitignore `dist`) so `cargo test --workspace` and `tauri::generate_context!()` always work on a clean checkout.
  3. TypeScript `~5.9.3` pin: confirmed, keep `~5.9.3`.

## Scope
- In: `.gitignore`, `src-tauri/tauri.conf.json` (if `frontendDist`/`build` config needs alignment), `src-tauri/ui/**`
- Out: `crates/**`, `src-tauri/src/**`, `docs/MASTER-PLAN.md`

## Sub-tasks
1. [done] Initialize `src-tauri/ui/` (`package.json`, `vite.config.ts`, `tsconfig.json`, `svelte.config.js`, `index.html`, `src/main.ts`, `src/app.css`) with Svelte 5, TypeScript, `@tauri-apps/api`, `svelte-check`, and Vite; add `src-tauri/ui/node_modules` to `.gitignore` and run `npm install` — done when: `cd src-tauri/ui && npm run check` exits 0
2. [done] Implement `src-tauri/ui/src/lib/types.ts` and `src-tauri/ui/src/lib/api.ts` mirroring every `src-tauri/src/commands.rs` command & event payload with strict TypeScript types (plus a clean browser-preview fallback or mock guard when `window.__TAURI_INTERNALS__` is absent) — done when: `cd src-tauri/ui && npm run check` exits 0
3. [done] Implement `src-tauri/ui/src/lib/stores.svelte.ts` using Svelte 5 runes managing live sessions, host profiles, key vault metadata, vault lock state, active navigation view, selected session, pending host-key prompt, clipboard fallback URL, tray availability, and Tauri event subscriptions — done when: `cd src-tauri/ui && npm run check` exits 0
4. [done] Implement `src-tauri/ui/src/lib/components/Sidebar.svelte`, `HeaderBar.svelte`, `LogDrawer.svelte`, and `App.svelte` assembling the complete Manage Window shell (with clean dark/system CSS styling, no heavy CSS framework bloat) — done when: `(cd src-tauri/ui && npm run check && npm run build) && cargo check -p rusty-conduit-ssh-gui` exits 0

## Verify
```sh
(cd src-tauri/ui && npm run check && npm run build) && cargo check -p rusty-conduit-ssh-gui
```

## Escalate when
- `npm install` fails due to network/registry restrictions → stop, set Status: needs-human — reason: exact npm error

## Log
- (append-only, one line per event)
- sub-task 1: scaffolded src-tauri/ui, added node_modules to .gitignore, npm install succeeded (47 packages); typecheck failed twice, escalated
- sub-task 1: applied planner answer (allowJs + checkJs, lang=ts App.svelte)
- sub-task 2: added types.ts, api.ts (38 commands, 8 events) and a dev-only browser preview mock.ts
- sub-task 3: added stores.svelte.ts and format.ts; listeners attach before shell_ready, and live state events are replayed over in-flight snapshots
- sub-task 4: added Sidebar, HeaderBar, LogDrawer, ModalDialog and App shell with dark/light CSS; committed the production bundle in ui/dist per planner answer

## Evidence
- (append-only: command → observed result)
- `npm install --no-fund --no-audit` → added 47 packages
- `npm run check` (attempt 1) → exit 1: src/main.ts 3:17 cannot find declaration file for './lib/components/App.svelte'; 1 error, 0 warnings
- `npm run check` (attempt 2, after adding src/vite-env.d.ts) → exit 1: same error; 1 error, 0 warnings
- `cd src-tauri/ui && npm run check` → exit 0, 0 errors, 0 warnings
- `npm run check` → exit 0, 0 errors, 0 warnings; comparison of commands.rs ALL_COMMANDS with api.ts → no differences, 38 commands
- `npm run check` → exit 0, 0 errors, 0 warnings
- `(cd src-tauri/ui && npm run check && npm run build) && cargo check -p rusty-conduit-ssh-gui` → exit 0; svelte-check 0 errors, 0 warnings; bundle JS 89.11 kB, CSS 5.71 kB
- headless Chromium against the production bundle with a stubbed Tauri IPC → 21/21 checks passed (listener order, queued events, close/quit answers, live state, search, windowed logs 22 of 2000 rows, filter, autoscroll, draft state, no console errors); the real Tauri window was not launched
- `cargo test -p rusty-conduit-ssh-gui` → 72 passed, 0 failed
