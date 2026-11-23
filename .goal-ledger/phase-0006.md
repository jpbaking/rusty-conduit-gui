# phase-0006 — src-tauri/ui Key Vault, Host-Key & Vault Unlock modals, Settings & E2E verify

- Status: done
- Owner: executor
- Depends on: phase-0005
- Goal: Complete the remaining Phase 2 Manage Window views and modals (Key Vault with upload/paste/generate/copy-pubkey/delete-impact warning, Host-Key Approval modal, Vault Unlock modal, Settings view) and run full Rust + frontend verification.
- Done when: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && (cd src-tauri/ui && npm run check && npm run build)` exits 0 with all Phase 2 views wired cleanly.
- Pattern to follow: `docs/MASTER-PLAN.md` Sections 5.3, 5.4, and 8.2

## Context
Every secret-ingestion surface in the UI must be strictly write-only: pasted keys, uploaded key passphrases, and master passwords are cleared from Svelte component state immediately upon submit, and the backend never returns private key material back to JS.
Key decisions already made:
- Key Vault view: lists saved keys with friendly name, algorithm, SHA-256 fingerprint, created date, and `"Used by N hosts/sessions"` badge; supports **Upload File**, **Paste Private Key** (with optional passphrase for encrypted keys), **Generate New Key** (`Ed25519` default / `ECDSA-P256`), **Copy Public Key**, **Rename**, and **Delete** (warns and lists affected hosts/sessions before deleting a referenced key).
- Host-Key Approval modal: opens automatically when any session enters `AwaitingHostKey`, showing hop name, `host:port`, algorithm, and SHA-256 fingerprint, with **Trust & Pin** (`approve_host_key`) and **Reject** (`reject_host_key`).
- Vault Unlock modal: opens on startup/tray action when vault is locked (or first-time setup to initialize vault with Master Password / OS Keyring), never offering plaintext fallback.
- Settings view: app autostart toggle (`--tray`), vault lock/unlock controls, and encrypted backup export/import trigger.

## Scope
- In: `src-tauri/ui/src/**`, `src-tauri/ui/dist/**`, plus small bug fixes in `src-tauri/src/**` only if full integration verification uncovers a mismatch
- Out: `crates/conduit-core/**`, `crates/conduit-vault/**`, `crates/conduit-ssh/**`, `crates/conduit-runtime/**`, `docs/MASTER-PLAN.md`

## Sub-tasks
1. [done] Implement `src-tauri/ui/src/lib/components/KeyVaultView.svelte` with key table (name, algorithm, SHA-256 fingerprint, created date, `Used by N hosts/sessions`), Copy Public Key, Rename, Delete confirmation listing affected hosts/sessions, and write-only modals for Upload File, Paste Private Key (with optional passphrase), and Generate New Key (`Ed25519`/`ECDSA-P256`) — done when: `cd src-tauri/ui && npm run check` exits 0
2. [done] Implement `src-tauri/ui/src/lib/components/HostKeyModal.svelte` and `VaultUnlockModal.svelte` (covering first-time vault creation, Master Password unlock, OS keyring unlock, and strict TOFU fingerprint approval/rejection) — done when: `cd src-tauri/ui && npm run check` exits 0
3. [done] Implement `src-tauri/ui/src/lib/components/SettingsView.svelte` (OS login autostart toggle, vault status/lock button, encrypted backup export/import) and wire `KeyVaultView`, `HostKeyModal`, `VaultUnlockModal`, and `SettingsView` into `App.svelte` — done when: `cd src-tauri/ui && npm run check && npm run build` exits 0
4. [done] Run full cross-stack verification (`cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && (cd src-tauri/ui && npm run check && npm run build)`) and verify zero raw secret fields exist in frontend TypeScript types or IPC responses — done when: full verification command exits 0

## Verify
```sh
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && (cd src-tauri/ui && npm run check && npm run build)
```

## Escalate when
- A Rust/TypeScript IPC contract mismatch requires changing `crates/conduit-core` or `crates/conduit-runtime` → stop, set Status: needs-human — reason: exact contract mismatch

## Log
- (append-only, one line per event)
- sub-task 1: added KeyVaultView, write-only AddKeyModal, store key-delete and vault helpers, unique modal title ids, and preview mock commands
- sub-task 2: added HostKeyModal (explicit Trust & Pin or Reject) and VaultUnlockModal (create, password, OS keyring)
- sub-task 3: added SettingsView and wired Key Vault, Settings, host-key and unlock modals into App
- sub-task 4: full verification passed on rerun; first run hit a port-collision flake in conduit-runtime concurrent_sessions_stay_isolated (out of scope, not changed); secret audit and browser run with a fake backend passed

## Evidence
- (append-only: command → observed result)
- cd src-tauri/ui && npm run check → 146 files, 0 errors, 0 warnings
- cd src-tauri/ui && npm run check → 148 files, 0 errors, 0 warnings
- cd src-tauri/ui && npm run check && npm run build → 149 files, 0 errors, 0 warnings; bundle 136.69 kB JS + 10.38 kB CSS
- full Verify command → exit 0; 17 test suites, 286 passed, 0 failed; clippy clean; svelte-check 149 files 0 errors 0 warnings; bundle 136.69 kB JS + 10.38 kB CSS
- first full Verify run → exit 101: concurrent_sessions_stay_isolated failed at crates/conduit-runtime/tests/e2e_runtime.rs:212 with "failed to bind HTTP/HTTPS listener on 127.0.0.1:45015: Address already in use"; test alone 5/5 passed, full rerun passed
- grep of src-tauri/ui/src/lib/types.ts → secret-named fields are only SecretRef ids, has_secret, and a passphrase file path; grep of UI source → no web storage or console logging; production bundle → no mock data
- headless Chromium on production bundle with fake IPC → 29/29 checks passed, 0 page exceptions (vault create/unlock/lock, key import/delete reconfirm, host-key approve, autostart, backup, secrets cleared)
