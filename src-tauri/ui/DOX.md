# src-tauri/ui

Sub-root: npm package `rusty-conduit-gui-ui` — the Svelte 5 + TypeScript frontend of the Manage Window.

## Purpose
The Manage Window UI: Proxy and Tunnel editors, legacy session editor, key vault, host profiles, settings, and dialogs, talking to the Rust backend over Tauri IPC.

## Ownership
Owns everything under `src-tauri/ui/`. Inherits all root and `../DOX.md` rules and adds the local rules below. The IPC commands it calls are owned by `../src/commands.rs` and `../src/controller/`.

## Local Contracts
- Build, check, and test from this folder: `npm ci`, `npm run check`, `npm test`, `npm run build`. `npm run dev` serves sample data from `src/lib/mock.ts` in a plain browser (dev builds only).
- `dist/` is a tracked build output read by `tauri::generate_context!()`; regenerate it with `npm run build` after source changes and never hand-edit it. `node_modules/` is ignored.
- `src/lib/types.ts` field names match the serialized Rust structs; change both sides together.
- `src/lib/api.ts` is the only IPC client. Secret arguments are write-only; no secret ever enters `src/lib/stores.svelte.ts` or other UI state, and secret inputs are cleared before any request is awaited.
- Client-side rules (`src/lib/validate.ts`, `src/lib/password.ts`) mirror backend rules (`../src/controller/password.rs`, `../../crates/conduit-core`); keep them in sync.
- Tests run with Node's built-in runner (`node --experimental-strip-types --test`); there is no `@types/node` (see `src/lib/node-test.d.ts`).

## Verification
- `npm run check` (svelte-check, fails on warnings), `npm test`, and `npm run build` must pass — CI runs all three on Node 22.

## Feature Map
- **App shell** — mount point, top-level layout, sidebar, header, log drawer, context menu, and tooltips. Start: `src/main.ts`. Files: `src/lib/components/App.svelte`, `src/lib/components/Sidebar.svelte`, `src/lib/components/HeaderBar.svelte`, `src/lib/components/LogDrawer.svelte`, `src/lib/components/ContextMenu.svelte`, `src/lib/tooltip.ts`, `src/app.css`.
- **IPC client and state** — typed command/event client, wire types, reactive metadata store, dev mock data. Start: `src/lib/api.ts`. Files: `src/lib/types.ts`, `src/lib/stores.svelte.ts`, `src/lib/mock.ts`.
- **Proxy editor** — listeners, custom upstream servers, AirSwitch-style drag-ordered Auto Switch routing table with grouped profile pickers and Route Tester, filters, MITM, logging, import/export, and the New Proxy wizard. Start: `src/lib/components/ProxyEditor.svelte`. Files: `src/lib/components/ProxyListenersTab.svelte`, `src/lib/components/ProxyProfilesTab.svelte`, `src/lib/components/ProxyRoutingTab.svelte`, `src/lib/routingRows.ts`, `src/lib/components/ProxyLoggingTab.svelte`, `src/lib/components/ProxyImportExportTab.svelte`, `src/lib/components/FilterEditor.svelte`, `src/lib/components/MitmTab.svelte`, `src/lib/components/NewProxyWizardModal.svelte`, `src/lib/components/ProfileLibraryView.svelte`.
- **Tunnel editor** — hops, optional forward proxy, tunnel-level filters, conditional MITM, keepalive & plain Start mode, reverse proxy, port forwards (with `-L` proxy protocol tags), logging, engine check, OpenSSH fallback. Start: `src/lib/components/TunnelEditor.svelte`. Files: `src/lib/components/HopEditor.svelte`, `src/lib/components/ForwardProxyTab.svelte`, `src/lib/components/FiltersTab.svelte`, `src/lib/components/MitmTab.svelte`, `src/lib/components/KeepaliveTab.svelte`, `src/lib/components/ReverseProxyTab.svelte`, `src/lib/components/PortForwardsTab.svelte`, `src/lib/components/PortForwardRow.svelte`, `src/lib/components/LoggingAdvancedTab.svelte`, `src/lib/components/EngineCheck.svelte`, `src/lib/components/OpensshFallbackDialog.svelte`, `src/lib/portForwards.ts`, `src/lib/opensshCheck.svelte.ts`.
- **Legacy session editor** — v1 session with jump chain builder, hop profiles, forward/reverse proxy, filters, and listener strip. Start: `src/lib/components/SessionEditor.svelte`. Files: `src/lib/components/JumpChainBuilder.svelte`, `src/lib/components/HopProfileBar.svelte`, `src/lib/components/ProxyTab.svelte`, `src/lib/components/ForwardProxyTab.svelte`, `src/lib/components/FiltersTab.svelte`, `src/lib/components/ListenerStrip.svelte`, `src/lib/chain.ts`.
- **Host profiles and host keys** — saved hop profiles and host-key approval dialog. Start: `src/lib/components/HostProfilesView.svelte`. Files: `src/lib/components/HostKeyModal.svelte`.
- **Key vault and MITM CAs** — SSH keys, CA vault, and vault unlock. Start: `src/lib/components/KeyVaultView.svelte`. Files: `src/lib/components/AddKeyModal.svelte`, `src/lib/components/CaVaultSection.svelte`, `src/lib/components/AddCaModal.svelte`, `src/lib/components/VaultUnlockModal.svelte`.
- **Settings and backups** — vault settings, master password rules, backups and import, port-forward presets. Start: `src/lib/components/SettingsView.svelte`. Files: `src/lib/components/VaultSettingsSection.svelte`, `src/lib/components/PasswordRules.svelte`, `src/lib/components/BackupSection.svelte`, `src/lib/components/ImportModal.svelte`, `src/lib/components/ForwardPresetsSection.svelte`, `src/lib/password.ts`.
- **Shared form controls and helpers** — fields, switches, modal, file dialogs, port mux, validation, and formatting. Start: `src/lib/validate.ts`. Files: `src/lib/components/PortField.svelte`, `src/lib/components/NumberField.svelte`, `src/lib/components/ProxySwitch.svelte`, `src/lib/components/MuxCheckbox.svelte`, `src/lib/components/ModalDialog.svelte`, `src/lib/components/BrowseButton.svelte`, `src/lib/fileDialog.ts`, `src/lib/portMux.svelte.ts`, `src/lib/format.ts`.
- **Unit tests** — pure-helper tests. Start: `src/lib/validate.test.ts`. Files: `src/lib/chain.test.ts`, `src/lib/format.test.ts`, `src/lib/password.test.ts`, `src/lib/portForwards.test.ts`, `src/lib/routingRows.test.ts`.

## Child DOX Index
- (none)
