# phase-0005 — src-tauri/ui: Tabs 4-7 (Filters, HTTPS MITM, Keepalive, Logging & Advanced)

- Status: done
- Owner: executor
- Depends on: phase-0004
- Goal: Implement Tabs 4–7 of the 7-Tab Session Editor (**Destination Filters**, **HTTPS MITM**, **Keepalive & Reconnect**, and **Logging & Advanced**) giving 100% `rusty-conduit-ssh` option parity from the Manage Window.
- Done when: `(cd src-tauri/ui && npm run check && npm run build)` exits 0 with all 7 Session Editor tabs wired to live backend validation and IPC commands.
- Pattern to follow: `docs/MASTER-PLAN.md` Section 8.2 and `src-tauri/ui/src/lib/components/ForwardProxyTab.svelte`

## Context
Every `rusty-conduit-ssh` option must be configurable from the Manage Window with clear inline validation and zero raw secret exposure.
Key decisions already made:
- **Tab 4 (`FiltersTab.svelte`):** Separate sections for Forward and Reverse filters. Each has a mode toggle (**Disabled** / **Allowlist** / **Blocklist**, enforcing mutual exclusivity by clearing the opposite list when switching), add/remove rule list (IP, CIDR, FQDN, `*.domain`), **Bulk Paste Import** textarea (splits on newlines/commas, deduplicates), and interactive **"Test host against rules"** input calling `api.testFilterRules(...)` showing allowed/blocked + rule errors.
- **Tab 5 (`MitmTab.svelte`):** Mode selector (**Off** / **PEM (cert + key)** / **PKCS#12**), path inputs, write-only CA passphrase input calling `api.setMitmPassphrase(sessionId, passphrase)` (cleared immediately on submit, displays `Saved passphrase` badge) or optional passphrase file path (mutually exclusive), `cert_ttl` (seconds, validated `>= 10`), `cert_cache_max_entries`, `socks_block_web` toggle, and a **Inspect CA** button calling `api.inspectMitmCa(...)` showing parsed CA subject, expiry date, and expired/expiring-soon warning.
- **Tab 6 (`KeepaliveTab.svelte`):** `server_alive_interval` (seconds), `server_alive_count_max`, auto-reconnect toggle (`!no_reconnect`), `reconnect_initial_delay` / `reconnect_max_delay` (validated `initial <= max`), `startup_timeout`, and session `autostart` toggle.
- **Tab 7 (`LoggingAdvancedTab.svelte`):** `level` (`QUIET`, `FATAL`, `ERROR`, `INFO`, `DEBUG`, `VERBOSE`), `format` (`text` / `json`), `http_access_log` & `socks_log` optional file paths, and OpenSSH-only section (`ssh_bin`, `ssh_socks_bind`, `ssh_socks_port`, `extra_args` editor with live isolation-denylist highlighting matching `conduit-core`'s denylist and a redacted command-args preview).

## Scope
- In: `src-tauri/ui/src/**`, `src-tauri/ui/dist/**`
- Out: `crates/**`, `src-tauri/src/**`, `docs/MASTER-PLAN.md`

## Sub-tasks
1. [done] Implement `src-tauri/ui/src/lib/components/FiltersTab.svelte` (Forward & Reverse Disabled/Allowlist/Blocklist toggle, rule list editor, bulk paste import, and interactive `testFilterRules` host tester) — done when: `cd src-tauri/ui && npm run check` exits 0
2. [done] Implement `src-tauri/ui/src/lib/components/MitmTab.svelte` (Off/PEM/PKCS#12 selector, file paths, write-only vault passphrase setter, `cert_ttl >= 10s`, `cert_cache_max_entries`, `socks_block_web`, and live `inspectMitmCa` CA subject/expiry display) — done when: `cd src-tauri/ui && npm run check` exits 0
3. [done] Implement `src-tauri/ui/src/lib/components/KeepaliveTab.svelte` (`server_alive_interval`, `server_alive_count_max`, auto-reconnect, initial/max backoff delays, `startup_timeout`, `autostart`) and `LoggingAdvancedTab.svelte` (log level/format/files + OpenSSH-only `ssh_bin`/`ssh_socks_bind`/`ssh_socks_port`/`extra_args` with live isolation-denylist validation and redacted preview) — done when: `cd src-tauri/ui && npm run check` exits 0
4. [done] Wire Tabs 4–7 into `SessionEditor.svelte`, extend `src-tauri/ui/src/lib/validate.ts` with full validation across all 7 tabs (per-tab error indicators), and rebuild `src-tauri/ui/dist/` — done when: `(cd src-tauri/ui && npm run check && npm run build)` exits 0

## Verify
```sh
(cd src-tauri/ui && npm run check && npm run build)
```

## Escalate when
- Any `SessionProfile` field required by Tabs 4–7 is missing from `src-tauri/ui/src/lib/types.ts` or `conduit-core` → stop, set Status: needs-human — reason: exact missing field

## Log
- (append-only, one line per event)
- sub-task 1: added FiltersTab and FilterEditor with mode toggle, rule editor, bulk import, and testFilterRules host tester
- sub-task 2: added MitmTab with Off/PEM/PKCS#12, write-only vault passphrase, passphrase file exclusivity, TTL/cache/SOCKS options, and Inspect CA; MITM passphrase refs now join orphaned-secret cleanup
- sub-task 3: added KeepaliveTab (autostart moved from Tab 1) and LoggingAdvancedTab with denylist highlighting and redacted args preview
- sub-task 4: wired Tabs 4-7, extended validate.ts across all tabs with per-tab error counts, and rebuilt dist
- open finding for planner: conduit-core denylist misses attached and case-variant ssh options such as -oProxyCommand=x; UI mirrors it exactly because crates/** is Scope: Out

## Evidence
- (append-only: command → observed result)
- sub-tasks 1-3: cd src-tauri/ui && npm run check → 158 files, 0 errors, 0 warnings
- sub-task 4 and Verify: (cd src-tauri/ui && npm run check && npm run build) → exit 0; 0 errors, 0 warnings; 154 modules built
- node parity script for validate.ts (filter rules, denylist, redaction, per-field errors) → all checks passed
- headless Chromium against Vite dev server with mock IPC, Tabs 4-7 → 27 passed, 0 failed, no console errors; real Tauri backend not exercised
