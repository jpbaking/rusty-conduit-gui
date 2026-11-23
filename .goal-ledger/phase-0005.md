# phase-0005 — src-tauri/ui Multi-Hop Jump Chain Builder & Host Profiles

- Status: done
- Owner: executor
- Depends on: phase-0004
- Goal: Implement the Connection & Multi-Hop Jump Chain Builder UI (with drag-and-drop + keyboard reorder, reusable Host Profile picker, per-hop auth/vaulted key picker, agent-forwarding warning, host-key status/reset, and prefix-by-prefix `Test Chain` diagnostics) plus the Host Profiles management view.
- Done when: `(cd src-tauri/ui && npm run check && npm run build)` exits 0 with all chain-builder and host-profile components wired to live `src-tauri` IPC commands.
- Pattern to follow: `docs/MASTER-PLAN.md` Sections 5.3 and 8.2

## Context
Multi-hop jump chains (`Local → Jump 1 → Jump 2 → … → Target`) are the signature UX feature of Rusty Conduit SSH GUI.
Key decisions already made:
- Every hop in a session's chain can either be picked from a reusable `HostProfile` (or promoted via *Save as Profile*) or configured inline.
- Support both drag-and-drop AND keyboard-accessible Move Up / Move Down reordering of hops, plus Add Jump / Remove Hop.
- Per-hop Auth editor: ordered list of vaulted Key picker (`KeyId` from Key Vault metadata) and write-only Password input (sends password to backend, receives `SecretRef`, clears input immediately, displays `Saved password` badge + Replace/Clear).
- Per-hop opt-in Agent Forwarding toggle displays a clear warning that root on that remote host can use forwarded keys while connected.
- Prefix-by-prefix **Test Chain** displays live per-hop badges (`✓` connected + ms, `!` exact failing hop + error reason, `–` not attempted).
- Include basic Forward/Reverse port fields in the session editor so users can create, save, test, and start a real session immediately (full 7-tab parity for Filters/MITM/Logging/Advanced comes in Master Plan Phase 3).
- **Planner answers to escalation:**
  1. Added read-only IPC command `list_host_key_pins` in `src-tauri/src/commands.rs` returning `Vec<HostKeyEntry>` (`{ key: { hop_id, host, port }, record: { algorithm, fingerprint_sha256, first_seen, approved } }`). Wire `listHostKeyPins()` in `src-tauri/ui/src/lib/api.ts` and store `pins` in `stores.svelte.ts` (reloaded on `refresh()` and `KnownHostsChanged`).
  2. Pinned host-key fingerprint display and Reset Pin apply to **session hops** (keyed by `(hop_id, host, port)`), not standalone `HostProfile`s.

## Scope
- In: `src-tauri/ui/src/**`, `src-tauri/ui/dist/**`
- Out: `crates/**`, `src-tauri/src/**`, `docs/MASTER-PLAN.md`

## Sub-tasks
1. [done] Implement `src-tauri/ui/src/lib/components/JumpChainBuilder.svelte` rendering the visual `[Local] → [Jump 1] → … → [Target]` chain with drag-and-drop + keyboard reorder (Move Left/Right or Up/Down), Add/Remove hop, Host Profile picker, *Save as Profile* action, and per-hop `Test Chain` diagnostic badges — done when: `cd src-tauri/ui && npm run check` exits 0
2. [done] Implement `src-tauri/ui/src/lib/components/HopEditor.svelte` for editing a selected hop's host/port/user, ordered auth methods (vaulted Key picker + write-only Password setter with immediate input clearing), per-hop Agent Forwarding opt-in with security warning, and pinned host-key fingerprint display + Reset Pin action — done when: `cd src-tauri/ui && npm run check` exits 0
3. [done] Implement `src-tauri/ui/src/lib/components/SessionEditor.svelte` combining `JumpChainBuilder`, `HopEditor`, IP version (`4`/`6`/`auto`), engine selector (`Built-in Rust SSH` vs `OpenSSH (Phase 4)`), autostart toggle, and core Forward/Reverse proxy bind & port fields with validation feedback — done when: `cd src-tauri/ui && npm run check` exits 0
4. [done] Implement `src-tauri/ui/src/lib/components/HostProfilesView.svelte` for listing, creating, editing, and deleting reusable `HostProfile`s (reusing `HopEditor` auth/key picker) and wire both `SessionEditor` and `HostProfilesView` into `App.svelte` — done when: `cd src-tauri/ui && npm run check && npm run build` exits 0

## Verify
```sh
(cd src-tauri/ui && npm run check && npm run build)
```

## Escalate when
- Any required IPC command or response field is missing from `src-tauri/src/commands.rs` → stop, set Status: needs-human — reason: exact missing IPC command or field

## Log
- (append-only, one line per event)
- read phase, UI sources, IPC commands, controller, and core model before editing; found no IPC read path for pinned host keys; escalated per ## Escalate when; no sub-task started and no UI file changed
- sub-task 1: added list_host_key_pins client, pins store, validation and chain helpers, and JumpChainBuilder.svelte with pointer drag, keyboard move, add/remove, profile picker, Save as Profile, and test badges
- sub-task 2: added HopEditor.svelte with host/port/user, ordered key and write-only password methods, agent-forwarding warning, and pinned fingerprint with confirmed Reset Pin
- sub-task 3: added SessionEditor.svelte combining chain and hop editors with IP version, engine, autostart, forward and reverse fields, and inline validation
- sub-task 4: added HostProfilesView.svelte, wired SessionEditor and HostProfilesView into App.svelte, blocked Save on invalid fields, and rebuilt dist

## Evidence
- (append-only: command → observed result)
- `grep -rnE 'host_key_pin\s*(=|:)\s*Some|\.host_key_pin\s*=' crates src-tauri/src` → no matches, exit 1
- `grep -cE 'pub async fn (list|get)_(known_hosts?|host_keys?|host_key_pins?|pins?)' src-tauri/src/commands.rs` → 0
- `grep -c 'known_hosts' src-tauri/src/commands.rs` → 0
- `grep -rn 'KnownHostsChanged {' -A6 crates/conduit-runtime/src` → fields are session_id, hop_id, host, port (no fingerprint), events.rs:22
- `cd src-tauri/ui && npm run check` → 0 errors, 0 warnings (141 files)
- `cd src-tauri/ui && npm run check` → 0 errors, 0 warnings (142 files)
- `cd src-tauri/ui && npm run check` → 0 errors, 0 warnings (143 files)
- `cd src-tauri/ui && npm run check && npm run build` → 0 errors, 0 warnings (144 files), built index-BNaa-GU4.js and index-C3o6H_5g.css
- `(cd src-tauri/ui && npm run check && npm run build)` (## Verify) → exit 0, svelte-check 0 errors and 0 warnings across 144 files, production bundle index-BNaa-GU4.js
- headless Chromium against the Vite dev server with mock IPC → 29/29 checks passed (add, keyboard and pointer reorder, password clearing, key order, validation, test badges, pin display and reset, promote, profile create/edit/delete, no console errors); real Tauri window and live SSH were not run
