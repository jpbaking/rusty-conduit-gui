# phase-0006 — src-tauri/ui: Config Export/Import UI in Settings & full cross-stack verification

- Status: done
- Owner: executor
- Depends on: phase-0005
- Goal: Wire Config Export/Import (redacted JSON by default; optional passphrase-encrypted full backup) into `SettingsView.svelte` and run full cross-stack Rust + frontend + headless browser verification for Milestone 3.
- Done when: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && (cd src-tauri/ui && npm run check && npm run build)` exits 0 with all Phase 3 features verified end-to-end and zero secret leaks.
- Pattern to follow: `src-tauri/ui/src/lib/components/SettingsView.svelte`

## Context
Settings currently has Key-only backup export/import. Phase 3 adds full **Config Export / Import** with secrets omitted by default and an explicit opt-in passphrase-encrypted full backup (config + known hosts + vault secrets).
Key decisions already made:
- Default export mode is **Config only (secrets omitted)**; enabling **Include secrets (encrypted full backup)** reveals a required write-only passphrase input + confirmation (cleared immediately on submit, never stored in component state).
- Import UI auto-detects or allows optional passphrase for encrypted bundles, with a **Replace existing** checkbox (default false = merge/skip duplicates), and refreshes `store` on success.

## Scope
- In: `src-tauri/ui/src/**`, `src-tauri/ui/dist/**`, plus small bug fixes in `src-tauri/src/**` only if cross-stack verification uncovers a mismatch
- Out: `crates/conduit-core/**`, `crates/conduit-vault/**`, `crates/conduit-ssh/**`, `crates/conduit-runtime/**`, `docs/MASTER-PLAN.md`

## Sub-tasks
1. [done] Update `src-tauri/ui/src/lib/components/SettingsView.svelte` with Config Export (redacted JSON default vs. passphrase-encrypted full backup with write-only passphrase + confirm) and Config Import (path, optional write-only passphrase, replace-existing toggle, result summary) wired to `api.exportConfig` and `api.importConfig` — done when: `cd src-tauri/ui && npm run check && npm run build` exits 0
2. [done] Run full cross-stack verification (`cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && (cd src-tauri/ui && npm run check && npm run build)`), verify zero raw secret fields in frontend types/bundle, and run a headless Chromium smoke check of the 7-tab editor + Settings config export/import against a stubbed IPC — done when: full verification command exits 0

## Verify
```sh
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && (cd src-tauri/ui && npm run check && npm run build)
```

## Escalate when
- Full verification uncovers a regression in `crates/**` outside this phase's scope → stop, set Status: needs-human — reason: exact failing test and crate

## Log
- (append-only, one line per event)
- sub-task 1: added Config export and import section to SettingsView.svelte; passphrases stay in DOM inputs, are emptied on submit, and never enter component state; rebuilt dist
- sub-task 2: ran full verification, secret scan, and headless smoke journey; no regressions and no src-tauri/src or crates changes needed

## Evidence
- (append-only: command → observed result)
- `cd src-tauri/ui && npm run check && npm run build` → exit 0; svelte-check 158 files, 0 errors, 0 warnings; vite built 154 modules (index-D2N8AH_b.js)
- `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && (cd src-tauri/ui && npm run check && npm run build)` → exit 0; 18 test suites, 333 passed, 0 failed, 0 ignored; clippy clean; svelte-check 0 errors, 0 warnings; vite build clean
- secret scan of src/lib/types.ts for private_key, privateKey, secret_value, password_value, plaintext, key_material, pem fields → 0 hits; same scan of dist JS → 1 hit, the AddKeyModal textarea placeholder "-----BEGIN OPENSSH PRIVATE KEY-----" (not data); mock data not in production bundle
- headless Chromium flow.mjs against Vite dev server with mock IPC (7 editor tabs; Settings config export/import, passphrase mismatch, inputs emptied on submit, replace toggle, locked vault) → 69/69 steps passed
- inspect.mjs on initial load → 0 JS errors, 0 failed requests; console was not monitored during the 69-step journey; real Tauri backend not exercised through the UI (covered by cargo IPC tests)
