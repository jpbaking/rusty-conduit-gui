# GOAL — U3 Manage Window & Tray

## Goal
- Goal ID: 20261126-u3-manage-window-tray
- Outcome: Complete Milestone U3 (`docs/MASTER-PLAN.md` §9 & §10 U3) by wiring `src-tauri` (`AppController`, IPC `commands.rs`, `tray_bridge.rs`, `tray_tauri.rs`) and `conduit-tray` (`model.rs`, `linux_ksni.rs`) to `TunnelManager` + `ProxyManager` (with §9.1 PROXIES/TUNNELS tray sections and Mode override submenu), and upgrading the Svelte 5 Manage Window (`src-tauri/ui`) with the Proxies + Tunnels sidebar, New Proxy wizard, 7-tab Proxy editor (inline Route Tester, Test Upstream, `gen #N · hot-reloaded`, `Restart to Apply` banner), re-homed 5-tab Tunnel editor, Profile Library, Vault upstream-password support, and Log drawer quick actions.
- Done when: All Rust workspace tests (including updated `src-tauri`, `conduit-tray`, and `secret_leak_scan`), `clippy -D warnings`, Linux `conduit_check_tauri_tray` check, `check-pure-rust-crypto.py`, `validate-release-config.py`, `smoke-test-bundle.py --self-test`, and frontend (`npm run check && npm test && npm run build`) pass with zero errors.
- Goal status: completed
- Goal status meaning: drafting | approved | executing | blocked-on-human | in-review | awaiting-acceptance | completed | abandoned
- Last completed phase: phase-0006

## Execution
- Execution mode: delegated
- Planner tier: primary session
- Executor tier: herdr-subagent (primary: claude opus 5.5 medium; backup: agy claude opus 5.5 medium)
- Full verification: CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo clippy --workspace --all-targets -- -D warnings && CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test --workspace && CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p rusty-conduit-gui --test secret_leak_scan && CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true RUSTFLAGS="--cfg conduit_check_tauri_tray" cargo check -p rusty-conduit-gui --tests --features tauri/tray-icon && python3 scripts/check-pure-rust-crypto.py && python3 scripts/validate-release-config.py && python3 scripts/smoke-test-bundle.py --self-test && (cd src-tauri/ui && npm run check && npm test && npm run build)

## Git
- Repository: yes
- Strategy: isolated-branch
- Starting branch: feat/one-gui
- Work branch: goal/20261126-u3-manage-window-tray
- Baseline commit: ca16a92be966d2aaf67e3fb47cbe8ff418ce5352
- Starting upstream at start: origin/feat/one-gui@5ad227c55f4815e91c3354f7736b6c105917bf28
- Work upstream at start: none

## Phases
- [done] phase-0001 — Wire AppController and Tauri commands to TunnelManager and ProxyManager
- [done] phase-0002 — Update conduit-tray and src-tauri tray bridge for PROXIES (Mode submenu) and TUNNELS sections
- [done] phase-0003 — Update Svelte UI core layer (types, api, mock, stores, validation, and tests) for v2 Proxies and Tunnels
- [done] phase-0004 — Build Sidebar, New Proxy wizard, 5-tab Tunnel editor, Profile Library view, and Vault upstream-password UI
- [done] phase-0005 — Build 7-tab Proxy editor, Proxy header (hot-reload/counters), and Log drawer quick actions
- [done] phase-0006 — Update secret_leak_scan for v2 and run full low-disk verification suite

## Handoff
- Current position: completed
- Next role: planner
- Next action: none
- Last verified evidence: User accepted U3 (#1); squashed into 1 commit on `goal/20261126-u3-manage-window-tray` and merged into `feat/one-gui`. Full verification exit 0 (clippy -D warnings clean, workspace Rust tests + secret_leak_scan 6/6 passed, conduit_check_tauri_tray clean, 3 Python checks OK, svelte-check 0/0, npm test 93/93, vite build ok).
- Blockers: none

## Review
- Reviewed by: planner (primary session)
- Verification result: Full verification exit 0 (clippy -D warnings clean, workspace Rust tests + secret_leak_scan 6/6 passed, conduit_check_tauri_tray clean, check-pure-rust-crypto/validate-release-config/smoke-test-bundle OK, svelte-check 0/0, npm test 93/93, vite build ok; target 4.5G, 20G free)
- Diff reviewed: ca16a92be966..0d2858f (55 changed files verified against phases 1–6 Scope: In; 0 scope drift; 22 matching Goal-ID commits, 0 foreign/merge commits)
- Findings: none (encrypted backup export sealing of v2 Proxies/Tunnels/upstream passwords belongs to Milestone U4 as planned)

## Log
- created ledger with 6 phases for Milestone U3 (replacing completed U2 ledger `20261126-u2-tunnels-proxies`, preserved in git history)
- approved Gates A–B; created isolated branch `goal/20261126-u3-manage-window-tray` off `feat/one-gui` (`ca16a92be966`); paused before Gate C for fresh session handoff
- resumed in fresh planner session (verified clean tree, branch `goal/20261126-u3-manage-window-tray` at `c620b44`, validator 0 warnings); started Gate C and delegated `phase-0001` to executor (`claude --model opus --effort medium`)
- executor stopped phase-0001 on its Escalate-when trigger: load_or_migrate_app_config breaks 2 v1 reopen tests (see phase-0001 Evidence)
- planner answered phase-0001 escalation (`SCHEMA_VERSION = conduit_core::CURRENT_SCHEMA_VERSION` = 2) and steered `sub-u3-p1` to continue phase-0001
- executor completed phase-0001: AppController wired to TunnelManager + ProxyManager with schema-2 stamping and v1 migration on open, 32 v2 IPC commands, v2 event forwarding; Verify exit 0 (155 lib tests, clippy clean)
- planner verified phase-0001 independently (155/155 tests, clippy clean, scope clean), closed `sub-u3-p1`, and delegated `phase-0002` to `sub-u3-p2` (`claude --model opus --effort medium`)
- executor completed phase-0002: tray model gains PROXIES (nested Mode submenu, Start/Stop/Restart, socks5h:// copy, View Logs) and TUNNELS (linked/attention labels) sections; ksni + Tauri render nested submenus; tray_bridge builds TrayState from Proxies/Tunnels, listens to Proxy/Tunnel events, StartAll/StopAll/Quit use the v2 calls; Verify exit 0
- planner verified phase-0002 independently (30+160 tests, tauri-tray check, clippy clean, scope clean), closed `sub-u3-p2`, and delegated `phase-0003` to `sub-u3-p3` (`claude --model opus --effort medium`)
- executor completed phase-0003: v2 wire types, 30+2 v2 api wrappers + subscribeV2Events, browser-preview mocks for every v2 command, store state/actions/events for Proxies/Tunnels/Profile Library (presets, drafts, hot-reload note, override, Route Tester, Test Upstream, view-logs resolution), proxyErrors/tunnelErrors + 16 tests; Verify exit 0
- planner verified phase-0003 independently (svelte-check 0/0, 93/93 tests, vite build ok, scope clean), closed `sub-u3-p3`, updated phase-0004/0005/0006 for `src-tauri/ui/dist/`, and delegated `phase-0004` to `sub-u3-p4` (`claude --model opus --effort medium`)
- executor completed phase-0004: Proxies/Tunnels sidebar with mode pills, New Proxy wizard, 5-tab TunnelEditor via a shared ChainEditor context, Profile Library view, ProxyEditor shell, Vault upstream-password usage + safe delete, App wiring incl. Tunnel host-key modal; Verify exit 0
- planner verified phase-0004 independently (svelte-check 0/0, 93/93 tests, vite build ok, scope clean), closed `sub-u3-p4`, and delegated `phase-0005` to `sub-u3-p5` (`claude --model opus --effort medium`)
- executor completed phase-0005: 7-tab ProxyEditor (Routing w/ rule drawer + Route Tester, Profiles w/ vault password + Test Upstream, Listeners & Network, Global Filter, MITM, Import/Export placeholder, Logging & General), Proxy header (gen #N · hot-reloaded, Restart to Apply, counters, override pill, Save (Hot-Reload)), LogDrawer for Proxy/Tunnel/session with filters + quick actions; SessionEditor kept (App.svelte still imports it); Verify exit 0
- planner verified phase-0005 independently (svelte-check 0/0, 93/93 tests, vite build ok, scope clean), closed `sub-u3-p5`, and delegated `phase-0006` to `sub-u3-p6` (`claude --model opus --effort medium`)
- executor completed phase-0006: added v2 Proxy/Tunnel/vaulted upstream-password secret-leak scan; full Verify exit 0; rebuilt `src-tauri/ui/dist/`; open question: encrypted export does not seal upstream passwords (secret_count 3)
- planner completed Gate D review: independent full verification exit 0, 0 scope drift across all 55 changed files, closed `sub-u3-p6`, set Goal status `awaiting-acceptance`
- user accepted U3 (#1); squashed 23 commits into 1 commit on `goal/20261126-u3-manage-window-tray` and merged into `feat/one-gui`
