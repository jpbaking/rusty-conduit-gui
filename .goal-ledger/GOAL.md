# GOAL — U4 Import / Export

## Goal
- Goal ID: 20261126-u4-import-export
- Outcome: Complete Milestone U4 (`docs/MASTER-PLAN.md` §6.3, §9.2, §9.3 & §10 U4): AirSwitch / ZeroOmega / SwitchyOmega `.bak` import wizard (extracting inline passwords into Vault), CLI `config.toml` import & export for all 3 CLIs (`rusty-conduit`, `rusty-conduit-ssh`, `rusty-conduit-switch`, using `password_env` placeholders and never plaintext secrets), External TOML link mode with live debounced hot-reload, and backup format v2 (sealing Tunnels, Proxies, Profile Library, and vaulted upstream passwords, while importing v1 backups through §6.4 migration).
- Done when: All Rust workspace tests (including new `conduit-core` AirSwitch/TOML tests, `conduit-runtime` External TOML watcher tests, `src-tauri` v2 backup & import/export tests, and updated `secret_leak_scan`), `clippy -D warnings`, Linux `conduit_check_tauri_tray` check, `check-pure-rust-crypto.py`, `validate-release-config.py`, `smoke-test-bundle.py --self-test`, and frontend (`npm run check && npm test && npm run build`) pass with zero errors.
- Goal status: completed
- Goal status meaning: drafting | approved | executing | blocked-on-human | in-review | awaiting-acceptance | completed | abandoned
- Last completed phase: phase-0005

## Execution
- Execution mode: delegated
- Planner tier: primary session
- Executor tier: herdr-subagent (primary: claude opus 5.5 medium; backup: agy claude opus 5.5 medium)
- Full verification: CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo clippy --workspace --all-targets -- -D warnings && CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test --workspace && CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p rusty-conduit-gui --test secret_leak_scan && CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true RUSTFLAGS="--cfg conduit_check_tauri_tray" cargo check -p rusty-conduit-gui --tests --features tauri/tray-icon && python3 scripts/check-pure-rust-crypto.py && python3 scripts/validate-release-config.py && python3 scripts/smoke-test-bundle.py --self-test && (cd src-tauri/ui && npm run check && npm test && npm run build)

## Git
- Repository: yes
- Strategy: isolated-branch
- Starting branch: feat/one-gui
- Work branch: goal/20261126-u4-import-export
- Baseline commit: 566f3bd42110e23bbedefb6167a53e5db8a3bf3a
- Starting upstream at start: origin/feat/one-gui@5ad227c55f4815e91c3354f7736b6c105917bf28
- Work upstream at start: none

## Phases
- [done] phase-0001 — Add AirSwitch/ZeroOmega/SwitchyOmega .bak importer and 3-CLI config.toml import/export in conduit-core
- [done] phase-0002 — Add External TOML link watcher in conduit-runtime and wire import/export/link IPC commands in src-tauri
- [done] phase-0003 — Bump app backup format to v2 (Tunnels, Proxies, Profile Library, upstream passwords, v1 migration) and update secret_leak_scan
- [done] phase-0004 — Build Svelte UI for Sidebar Import modal, full ProxyImportExportTab (incl. External TOML link), and v2 BackupSection
- [done] phase-0005 — Rebuild src-tauri/ui/dist/ and run full low-disk verification suite

## Handoff
- Current position: completed
- Next role: planner
- Next action: none
- Last verified evidence: User accepted U4 (#1); squashed into 1 commit on `goal/20261126-u4-import-export` and merged into `feat/one-gui`. Full verification exit 0 (clippy -D warnings clean, workspace Rust tests + secret_leak_scan 6/6 passed, conduit_check_tauri_tray clean, 3 Python checks OK, svelte-check 0/0, npm test 93/93, vite build ok).
- Blockers: none

## Review
- Reviewed by: planner (primary session)
- Verification result: Full verification exit 0 (clippy -D warnings clean, workspace Rust tests incl. conduit-core 133, conduit-runtime 91, gui lib 174, secret_leak_scan 6/6 passed, conduit_check_tauri_tray clean, check-pure-rust-crypto/validate-release-config/smoke-test-bundle OK, svelte-check 0/0, npm test 93/93, vite build ok; target 6.1G, 19G free)
- Diff reviewed: 566f3bd42110..c95258b (34 changed files verified against phases 1–5 Scope: In; 0 scope drift; 16 matching Goal-ID commits, 0 foreign/merge commits)
- Findings: none

## Log
- created ledger with 5 phases for Milestone U4 (replacing completed U3 ledger `20261126-u3-manage-window-tray`, preserved in git history)
- approved Gates A–C; created isolated branch `goal/20261126-u4-import-export` off `feat/one-gui` (`566f3bd42110`)
- started Gate C and delegated `phase-0001` to `sub-u4-p1` (`claude --model opus --effort medium`)
- phase-0001 done: added `airswitch_import.rs` + `toml_io.rs` to conduit-core (21 new tests); Verify passed after one clippy fix-up
- planner verified phase-0001 independently (133/133 tests, clippy clean, PURE_RUST_CRYPTO_OK, scope clean), closed `sub-u4-p1`, and delegated `phase-0002` to `sub-u4-p2` (`claude --model opus --effort medium`)
- phase-0002 done: added `toml_watcher.rs` + ProxyManager watcher wiring, `controller/import_export.rs`, and 8 U4 IPC commands (tests: runtime 91, gui lib 168); Verify passed with no fix-ups
- planner verified phase-0002 independently (91+168 tests, clippy clean, scope clean), closed `sub-u4-p2`, and delegated `phase-0003` to `sub-u4-p3` (`claude --model opus --effort medium`)
- phase-0003 done: backup format v2 in `export.rs` (v2 AADs, v1 import via §6.4 migration, Tunnels/Proxies/Profile Library + upstream password sealing/restoring, plain-import stripping/neutralizing, v2 counts, 6 new tests); `secret_leak_scan` checks `secret_count >= 4` and CLI TOML exports; Verify passed with no fix-ups
- planner verified phase-0003 independently (174 lib + 6 leak-scan tests, clippy clean, scope clean), closed `sub-u4-p3`, and delegated `phase-0004` to `sub-u4-p4` (`claude --model opus --effort medium`)
- phase-0004 done: U4 UI — wire types/api/mocks/store helpers, Sidebar `Import…` + ImportModal (.bak + 3-CLI config.toml), full ProxyImportExportTab (External TOML link/unlink/reload, TOML export preview/copy/save, .bak import into Proxy), v2 BackupSection counts; Verify passed with no fix-ups
- planner verified phase-0004 independently (svelte-check 0/0, 93/93 tests, vite build ok, scope clean), closed `sub-u4-p4`, and delegated `phase-0005` to `sub-u4-p5` (`claude --model opus --effort medium`)
- phase-0005 done: rebuilt `src-tauri/ui/dist/` (stale hashed assets removed) and full Verify passed with no fix-ups (target 6.1G, 19G free)
- planner completed Gate D review: independent full verification exit 0, 0 scope drift across all 34 changed files, closed `sub-u4-p5`, set Goal status `awaiting-acceptance`
- user accepted U4 (#1); squashed 17 commits into 1 commit on `goal/20261126-u4-import-export` and merged into `feat/one-gui`
