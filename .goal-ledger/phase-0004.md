# phase-0004 — Build Svelte UI for Sidebar Import modal, full ProxyImportExportTab (incl. External TOML link), and v2 BackupSection

- Status: done
- Owner: executor
- Depends on: phase-0003
- Goal: Wire the Svelte 5 Manage Window (`src-tauri/ui/src/lib/`) to all U4 import/export/link commands: add Sidebar `Import…` button + `ImportModal.svelte` (AirSwitch `.bak` wizard + 3-CLI `config.toml` import), replace the placeholder in `ProxyImportExportTab.svelte` with full AirSwitch import, CLI TOML import/export, and External TOML link/unlink/reload controls, and update `BackupSection.svelte` to display v2 Proxy/Tunnel/Profile Library counts.
- Done when: `cd src-tauri/ui && npm run check && npm test && npm run build` passes with zero errors and zero warnings.
- Pattern to follow: `src-tauri/ui/src/lib/components/NewProxyWizardModal.svelte`, `src-tauri/ui/src/lib/components/ProxyImportExportTab.svelte`, `src-tauri/ui/src/lib/components/BackupSection.svelte`, `docs/MASTER-PLAN.md:295-311`

## Context
- **Core UI layer (`types.ts`, `api.ts`, `mock.ts`, `stores.svelte.ts`)**:
  - Add TypeScript types matching `src-tauri/src/controller/import_export.rs` (`CliTomlFormat`, `AirSwitchPreview`, `AirSwitchCommitResult`, `TomlImportPreview`, `TomlImportCommitResult`, `TomlExportResult`) and add optional/new v2 fields on `ExportSummary` & `ImportSummary`.
  - Add typed invoke wrappers in `api.ts` and browser-preview mock handlers in `mock.ts` for `preview_airswitch_import`, `commit_airswitch_import`, `preview_toml_import`, `commit_toml_import`, `export_proxy_toml`, `link_proxy_external_toml`, `unlink_proxy_external_toml`, `reload_proxy_external_toml`.
  - Add store helper(s) in `stores.svelte.ts` to reload proxies/tunnels after import/link and open the newly imported Proxy/Tunnel in the editor.
- **Sidebar & `ImportModal.svelte`** (per §9.2):
  - Add an `Import…` button in `Sidebar.svelte` next to `+ New Proxy` / `+ New Tunnel` that opens `ImportModal.svelte` (wired in `App.svelte`).
  - `ImportModal.svelte` has two modes/tabs:
    1. **AirSwitch / ZeroOmega / SwitchyOmega `.bak`**: pick `.bak`/`.json` file → preview (profile count, rule count, extracted passwords count with Vault unlock prompt if needed, browser-only warnings list) → choose name & import into new Proxy.
    2. **CLI `config.toml`**: pick `.toml` file + format selector (`Auto-detect` / `rusty-conduit` / `rusty-conduit-ssh` / `rusty-conduit-switch`) → preview (detected format, profiles/rules/passwords/notes) → import into Proxy (and Tunnel for `rusty-conduit-ssh`).
- **Full `ProxyImportExportTab.svelte`**:
  - **Config Source & External TOML link mode**:
    - When `Managed`: file picker + debounce ms input + **Link to External TOML** button (calls `api.linkProxyExternalToml`).
    - When `ExternalToml`: shows linked file path, debounce ms, banner noting external edits hot-reload live, **Reload Now** button (`api.reloadProxyExternalToml`), and **Unlink (Switch to Managed)** button (`api.unlinkProxyExternalToml`).
  - **Export CLI `config.toml`**: format selector (`rusty-conduit`, `rusty-conduit-ssh`, `rusty-conduit-switch`), **Preview TOML** / **Copy TOML** / **Save to File…** buttons (`api.exportProxyToml`), showing any setup notes (`~/.ssh/config` notes, `password_env` placeholders, commented `tunnel` placeholders) or eligibility error clearly.
  - **Import into this Proxy**: AirSwitch `.bak` import targeting the current Proxy (`target_proxy_id`), with preview + warnings.
- **`BackupSection.svelte`**:
  - Display v2 counts (`proxies`, `tunnels`, `library profiles`) alongside `sessions` (if any), `hosts`, `keys`, `CAs`, and `secrets` in both export and import result summaries.
- Note: `npm run build` rewrites the tracked `src-tauri/ui/dist/` directory (rebuilt and committed in phase-0005). After `npm run build` passes, restore `src-tauri/ui/dist/` (`git checkout -- src-tauri/ui/dist && git clean -fd src-tauri/ui/dist`) before committing so only `Scope: In` files are staged.

## Scope
- In: `src-tauri/ui/src/lib/types.ts`, `src-tauri/ui/src/lib/api.ts`, `src-tauri/ui/src/lib/mock.ts`, `src-tauri/ui/src/lib/stores.svelte.ts`, `src-tauri/ui/src/lib/components/App.svelte`, `src-tauri/ui/src/lib/components/Sidebar.svelte`, `src-tauri/ui/src/lib/components/ImportModal.svelte` (create), `src-tauri/ui/src/lib/components/ProxyImportExportTab.svelte`, `src-tauri/ui/src/lib/components/BackupSection.svelte`
- Out: `crates/`, `src-tauri/src/`, `src-tauri/ui/dist/`

## Sub-tasks
1. [done] Add U4 wire types, IPC wrappers, browser mocks, and store helpers in `types.ts`, `api.ts`, `mock.ts`, `stores.svelte.ts` — done when: `npm run check` passes.
2. [done] Create `ImportModal.svelte` (AirSwitch `.bak` wizard + 3-CLI `config.toml` import) and wire Sidebar `Import…` button in `Sidebar.svelte` and `App.svelte` — done when: `npm run check` passes.
3. [done] Replace `ProxyImportExportTab.svelte` placeholder with External TOML link/unlink/reload, 3-CLI TOML export preview/save, and AirSwitch import-into-proxy, and update `BackupSection.svelte` for v2 counts — done when: `npm run check` passes.
4. [done] Run `## Verify`, restore `src-tauri/ui/dist/`, and record observed results in `## Evidence` — done when: `## Verify` exits 0.

## Verify
```sh
cd src-tauri/ui && npm run check && npm test && npm run build
```

## Escalate when
- A U4 Rust IPC command signature or field name in `commands.rs` / `import_export.rs` does not match what the UI needs → stop, set Status: needs-human — reason: name the exact command and mismatch

## Log
- (append-only, one line per event)
- sub-task 1: added U4 wire types (CliTomlFormat, ImportedProfileSummary, AirSwitch*/TomlImport*/TomlExportResult, v2 Export/ImportSummary counts), 8 api wrappers, browser mocks (dispatchU4), store helpers openImported/applyProxySourceChange
- sub-task 2: created ImportModal.svelte (mode picker: extension .bak / CLI config.toml with Auto-detect + 3 formats; Preview → counts, profiles, warnings, notes, vault-locked prompt; name; Import → store.openImported, vault_locked → runUnlocked retry); Sidebar `Import…` button (onImport prop) wired in App.svelte
- sub-task 3: rewrote ProxyImportExportTab.svelte (Managed: link file + debounce 250–10000 ms + Link button; ExternalToml: path/debounce, hot-reload banner, Reload Now, Unlink; Export: 3-format selector, Preview/Copy/Save to File…, notes + errors; AirSwitch import-into-proxy with preview/warnings and vault unlock); BackupSection shows v2 proxy/tunnel/library counts in export and import summaries (sessions only when present)
- sub-task 4: ran ## Verify (exit 0), restored src-tauri/ui/dist with `git checkout -- src-tauri/ui/dist && git clean -fdq src-tauri/ui/dist`; git status shows only Scope: In files + ledger

## Evidence
- (append-only: command → observed result)
- sub-task 1: `npm run check` → `COMPLETED 197 FILES 0 ERRORS 0 WARNINGS 0 FILES_WITH_PROBLEMS`
- sub-task 2: `npm run check` → `COMPLETED 198 FILES 0 ERRORS 0 WARNINGS 0 FILES_WITH_PROBLEMS`
- sub-task 3: `npm run check` → `COMPLETED 198 FILES 0 ERRORS 0 WARNINGS 0 FILES_WITH_PROBLEMS`
- Verify: `cd src-tauri/ui && npm run check && npm test && npm run build` → exit 0; svelte-check `198 FILES 0 ERRORS 0 WARNINGS`; node test `tests 93, pass 93, fail 0`; vite `✓ built in 3.04s` with no build warnings
- `git status --short` after dist restore → only types.ts, api.ts, mock.ts, stores.svelte.ts, App.svelte, Sidebar.svelte, ProxyImportExportTab.svelte, BackupSection.svelte, ImportModal.svelte (new), .goal-ledger/phase-0004.md
