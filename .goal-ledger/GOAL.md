# GOAL — Tauri v2 Shell, System Tray & Svelte 5 Manage Window

## Goal
- Goal ID: 20261124-tauri-tray-svelte-ui
- Outcome: Implement Master Plan Phase 2: `conduit-tray` (`ksni` pure-Rust D-Bus SNI on Linux + Tauri tray adapter on Windows/macOS + no-tray fallback), the Tauri v2 desktop shell (`src-tauri/` with write-only secret IPC, destroy-webview-on-close, single-instance, autostart `--tray`, and NVIDIA WebKitGTK mitigation), and the Svelte 5 + TypeScript core Manage Window (`src-tauri/ui/`).
- Done when: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && (cd src-tauri/ui && npm run check && npm run build)` exits 0 with passing `conduit-tray` and `src-tauri` tests, clean Svelte 5 typecheck and production bundle, and zero raw secrets exposed to the WebView.
- Goal status: completed
- Goal status meaning: drafting | approved | executing | blocked-on-human | in-review | awaiting-acceptance | completed | abandoned
- Last completed phase: phase-0006

## Execution
- Execution mode: delegated
- Planner tier: Gemini 4 Neon (Medium)
- Executor tier: claude --model opus --effort medium via herdr-subagent
- Full verification: cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && (cd src-tauri/ui && npm run check && npm run build)

## Git
- Repository: yes
- Strategy: isolated-branch
- Starting branch: main
- Work branch: goal/20261124-tauri-tray-svelte-ui
- Baseline commit: 552b6fb5f129b7def92dd879bb1c4a780227c3da
- Starting upstream at start: none
- Work upstream at start: none

## Phases
- [done] phase-0001 — conduit-tray trait, menu model & pure-Rust Linux ksni backend
- [done] phase-0002 — src-tauri v2 scaffold, AppState & write-only secret IPC commands
- [done] phase-0003 — src-tauri desktop lifecycle, tray wiring, autostart & platform rules
- [done] phase-0004 — src-tauri/ui Svelte 5 scaffold, typed IPC client, shell & live log drawer
- [done] phase-0005 — src-tauri/ui Multi-Hop Jump Chain Builder & Host Profiles
- [done] phase-0006 — src-tauri/ui Key Vault, Host-Key & Vault Unlock modals, Settings & E2E verify

## Handoff
- Current position: completed
- Next role: planner
- Next action: none
- Last verified evidence: cargo test --workspace (286 passed, 0 failed) && cargo clippy --workspace --all-targets -- -D warnings (exit 0) && (cd src-tauri/ui && npm run check && npm run build) (0 errors/0 warnings, 136.69 kB JS + 10.38 kB CSS); accepted and squashed
- Blockers: none

## Review
- Reviewed by: Gemini 4 Neon (Medium) (planner)
- Verification result: pass — cargo test --workspace (286 passed, 0 failed: 33 conduit-core, 43 conduit-vault, 64 conduit-ssh, 53 conduit-runtime, 21 conduit-tray, 72 rusty-conduit-ssh-gui) && cargo clippy --workspace --all-targets -- -D warnings (exit 0) && (cd src-tauri/ui && npm run check && npm run build) (0 errors, 0 warnings, 136.69 kB JS + 10.38 kB CSS)
- Diff reviewed: 552b6fb5f129b7def92dd879bb1c4a780227c3da..HEAD (reviewed across all 6 phase reviews; all changed paths within declared Scope: In)
- Findings: none blocking (note: real Tauri window launch, OS keyring default-store registration, and Windows/macOS cross-builds were not run on this headless Linux host)

## Log
- created Milestone 2 ledger with 6 phases for Master Plan Phase 2 (conduit-tray, Tauri v2 shell, Svelte 5 Manage Window) on branch goal/20261124-tauri-tray-svelte-ui from baseline 552b6fb5f129b7def92dd879bb1c4a780227c3da
- delegated phase-0001 to claude (--model opus --effort medium) (sub-m2-phase-0001)
- phase-0001 done: conduit-tray model, backend trait, mock, and ksni Linux backend verified
- planner reviewed and accepted phase-0001; closed sub-m2-phase-0001; delegated phase-0002 to claude (--model opus --effort medium) (sub-m2-phase-0002)
- phase-0002 done: src-tauri scaffold, AppController, and 34 write-only IPC commands verified; open items for planner are the app identifier, OS keyring store registration, and an unrun real-window launch
- planner reviewed and accepted phase-0002; closed sub-m2-phase-0002; delegated phase-0003 to claude (--model opus --effort medium) (sub-m2-phase-0003)
- phase-0003 done: desktop lifecycle, tray bridge, autostart and platform rules verified; real window launch and Windows/macOS target builds not run
- planner reviewed and accepted phase-0003; closed sub-m2-phase-0003; added shell_ready/event contract to phase-0004 and delegated phase-0004 to claude (--model opus --effort medium) (sub-m2-phase-0004)
- phase-0004 blocked at sub-task 1: svelte-check cannot type .svelte imports after two attempts; partial scaffold committed
- planner answered phase-0004 escalation (allowJs+checkJs + <script lang="ts"> for svelte-check, commit ui/dist build output, keep TS ~5.9.3), returned phase-0004 to todo, and steered sub-m2-phase-0004
- phase-0004 done: Svelte 5 shell, typed 38-command IPC client, stores and windowed log drawer verified; real Tauri window launch not run
- planner reviewed and accepted phase-0004; closed sub-m2-phase-0004; added src-tauri/ui/dist/** to phase-0005/0006 scope and delegated phase-0005 to claude (--model opus --effort medium) (sub-m2-phase-0005)
- phase-0005 blocked before sub-task 1: no IPC read path for pinned host-key fingerprints; no UI files changed
- planner added read-only list_host_key_pins IPC command in src-tauri/src/commands.rs, answered phase-0005 escalation (pins apply to session hops), returned phase-0005 to todo, and steered sub-m2-phase-0005
- phase-0005 done: jump chain builder, hop editor, session editor and host profiles wired to IPC; verified by check, build and mock-IPC browser run; real Tauri window and live SSH not run
- planner reviewed and accepted phase-0005; closed sub-m2-phase-0005; delegated phase-0006 to claude (--model opus --effort medium) (sub-m2-phase-0006)
- phase-0006 done: Key Vault, host-key and vault unlock modals, and Settings wired; full verification passed on rerun after one port-collision flake in conduit-runtime e2e; real Tauri window and live SSH not run
- planner reviewed and accepted phase-0006; closed sub-m2-phase-0006; Gate D passed clean (286 Rust tests, clippy clean, svelte-check 0 errors/0 warnings, production bundle built); status set to awaiting-acceptance
- user accepted goal and chose squash; soft-reset to baseline 552b6fb5f129b7def92dd879bb1c4a780227c3da and squashed into a single commit retaining .goal-ledger/
