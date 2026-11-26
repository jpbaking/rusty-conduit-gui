# phase-0004 — Build Sidebar, New Proxy wizard, 5-tab Tunnel editor, Profile Library view, and Vault upstream-password UI

- Status: done
- Owner: executor
- Depends on: phase-0003
- Goal: Upgrade the Manage Window navigation (`Sidebar.svelte`, `App.svelte`), add the New Proxy wizard (*Direct* / *Through a tunnel* / *Auto Switch*), re-home the 5-tab Tunnel editor (with Linked/Manual start mode and "Used by" Proxies list), add the Profile Library view, and add upstream-password visibility/safe-delete support in `KeyVaultView.svelte`.
- Done when: `cd src-tauri/ui && npm run check && npm test && npm run build` passes with zero errors and zero warnings.
- Pattern to follow: `src-tauri/ui/src/lib/components/Sidebar.svelte`, `src-tauri/ui/src/lib/components/SessionEditor.svelte`, `src-tauri/ui/src/lib/components/KeyVaultView.svelte`, `docs/MASTER-PLAN.md:295-302`

## Context
- Follow `docs/MASTER-PLAN.md` §9.2:
  - **Sidebar (`Sidebar.svelte`)**: **Proxies** and **Tunnels** lists (with search input, live status dots, mode pill e.g. `Direct` / `Tunnel` / `Auto Switch` / `Override`), `+ New Proxy` button (opens `NewProxyWizardModal.svelte`), `+ New Tunnel` button, then bottom nav for **Host Profiles**, **Profile Library**, **Vault**, **Settings**.
  - **New Proxy wizard (`NewProxyWizardModal.svelte`)**: three clear starting presets — *Direct* (plain `rusty-conduit`, default `direct`, no rules), *Through a tunnel* (`rusty-conduit-ssh`, choose an existing Tunnel or create one, default `tunnel`), *Auto Switch* (`rusty-conduit-switch`, starter rules view). Creates the draft Proxy and opens it in the Proxy editor.
  - **Tunnel editor (`TunnelEditor.svelte`)**: re-homed from `SessionEditor.svelte` with 5 tabs:
    1. Connection & Jump Chain (`JumpChainBuilder`, `HopProfileBar`, per-hop auth, host-key status, IP version, engine)
    2. Reverse Proxy (`-R`)
    3. Port Forwards (+ presets)
    4. Keepalive & Reconnect + `Linked` / `Manual` (+ autostart) start mode selector
    5. Logging & Advanced (OpenSSH options with isolation validation)
    Plus a **"Used by"** list of Proxies referencing this Tunnel, and header with Test Chain, Start/Stop/Restart, Save, Logs.
  - **Profile Library view (`ProfileLibraryView.svelte`)**: list, add, edit, and delete shared `UpstreamProfile` entries (reusable across Proxies).
  - **Vault (`KeyVaultView.svelte`)**: show upstream-password usage across Proxies and ensure safe-delete confirmation lists affected Proxies and Tunnels.
  - Wire `App.svelte` to render `ProxyEditor` (stub/shell ready for phase-0005 if needed, or basic placeholder if phase-0005 replaces it), `TunnelEditor`, `ProfileLibraryView`, `HostProfilesView`, `KeyVaultView`, `SettingsView`, `NewProxyWizardModal`, and `HostKeyModal` (wired to Tunnel host-key approval).
- Note: `npm run build` rewrites the tracked `src-tauri/ui/dist/` directory (which will be rebuilt and committed in phase-0006). After `npm run build` passes, restore `src-tauri/ui/dist/` (`git checkout -- src-tauri/ui/dist && git clean -fd src-tauri/ui/dist`) before committing so only `Scope: In` files are staged.

## Scope
- In: `src-tauri/ui/src/lib/components/App.svelte`, `src-tauri/ui/src/lib/components/Sidebar.svelte`, `src-tauri/ui/src/lib/components/NewProxyWizardModal.svelte` (create), `src-tauri/ui/src/lib/components/TunnelEditor.svelte` (create), `src-tauri/ui/src/lib/components/ProfileLibraryView.svelte` (create), `src-tauri/ui/src/lib/components/ProxyEditor.svelte` (create minimal shell for phase-0005), `src-tauri/ui/src/lib/components/KeyVaultView.svelte`, `src-tauri/ui/src/lib/components/HostKeyModal.svelte`, `src-tauri/ui/src/lib/components/HeaderBar.svelte`, `src-tauri/ui/src/lib/components/JumpChainBuilder.svelte`, `src-tauri/ui/src/lib/components/HopEditor.svelte`, `src-tauri/ui/src/lib/components/ReverseProxyTab.svelte`, `src-tauri/ui/src/lib/components/PortForwardsTab.svelte`, `src-tauri/ui/src/lib/components/KeepaliveTab.svelte`, `src-tauri/ui/src/lib/components/LoggingAdvancedTab.svelte`, `src-tauri/ui/src/lib/components/EngineCheck.svelte`
- Out: `crates/`, `src-tauri/src/`, `src-tauri/ui/src/lib/components/LogDrawer.svelte`

## Sub-tasks
1. [done] Update `Sidebar.svelte` (Proxies + Tunnels lists with search, live status, mode pills, `+ New Proxy`, `+ New Tunnel`, Profile Library nav) and create `NewProxyWizardModal.svelte` (*Direct* / *Through a tunnel* / *Auto Switch*) — done when: `npm run check` passes.
2. [done] Create `TunnelEditor.svelte` (5 tabs: Connection & Jump Chain, Reverse Proxy, Port Forwards, Keepalive & Start Mode, Logging & Advanced, plus "Used by" Proxies list) and adapt the shared Tunnel tab components (`JumpChainBuilder`, `ReverseProxyTab`, `PortForwardsTab`, `KeepaliveTab`, `LoggingAdvancedTab`, `EngineCheck`, `HostKeyModal`) — done when: `npm run check` passes.
3. [done] Create `ProfileLibraryView.svelte`, update `KeyVaultView.svelte` for Proxy/Tunnel usage and upstream passwords, create the `ProxyEditor.svelte` shell, and wire `App.svelte` — done when: `npm run check` passes.
4. [done] Run `## Verify` and record observed results in `## Evidence` — done when: `## Verify` exits 0.

## Verify
```sh
cd src-tauri/ui && npm run check && npm test && npm run build
```

## Escalate when
- A shared tab component needs a new backend command not exposed in phase-0001 → stop, set Status: needs-human — reason: name the missing command and signature

## Log
- (append-only, one line per event)
- started phase-0004 (begin commit 00b91dd)
- sub-task 2 (done first, as the Sidebar/App wiring depends on the shared editor): added a `ChainEditor` context (`provideChainEditor`/`chainEditor`, module script of `JumpChainBuilder.svelte`) that the store satisfies structurally; `JumpChainBuilder`, `ReverseProxyTab`, `PortForwardsTab`, `KeepaliveTab` (Linked/Manual + autostart selector for Tunnels), `LoggingAdvancedTab`, `EngineCheck` now read it; `HostKeyModal` gains `kind="tunnel"` (approve/reject_tunnel_host_key); created `TunnelEditor.svelte` (5 tabs, Used by list, header with Test Chain/Start/Stop/Restart/Save/Discard/Logs) adapting a Tunnel to the session shape
- sub-task 1: rewrote `Sidebar.svelte` (search, Proxies + Tunnels lists with status glyphs and mode pills, `+ New Proxy`/`+ New Tunnel`, context menus with Tunnel delete listing affected Proxies, bottom nav Host Profiles / Profile Library / Vault / Settings); created `NewProxyWizardModal.svelte` (Direct / Through a tunnel / Auto Switch → `store.newProxyFromPreset`)
- sub-task 3: created `ProfileLibraryView.svelte` (list/add/edit/delete, vault/env/file password source), `ProxyEditor.svelte` shell (header + summary; exports `proxyStatusOf`/`proxyActive`/`proxyMode`), updated `KeyVaultView.svelte` (key delete lists Hosts/Sessions/Tunnels/Proxies/Profile Library; new Upstream passwords section with safe delete), wired `App.svelte` (proxy/tunnel/profileLibrary/vault views, wizard, Tunnel host-key modal, opens on Proxies)
- sub-task 4: ran ## Verify → exit 0; restored `src-tauri/ui/dist/`

## Evidence
- (append-only: command → observed result)
- after sub-task 2: `cd src-tauri/ui && npm run check` → `COMPLETED 190 FILES 0 ERRORS 0 WARNINGS 0 FILES_WITH_PROBLEMS`
- after sub-tasks 1 and 3: `cd src-tauri/ui && npm run check` → `COMPLETED 192 FILES 0 ERRORS 0 WARNINGS 0 FILES_WITH_PROBLEMS`
- ## Verify: `cd src-tauri/ui && npm run check && npm test && npm run build` → exit 0; svelte-check 0 errors / 0 warnings; node tests 93 pass / 0 fail; vite `✓ 186 modules transformed … ✓ built in 2.55s`
- `git checkout -- src-tauri/ui/dist && git clean -fdq src-tauri/ui/dist; git status --short` → only the 10 modified + 4 new files under `src-tauri/ui/src/lib/components/` listed in Scope: In
