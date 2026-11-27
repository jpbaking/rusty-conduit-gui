# phase-0006 — Docs, TODO entry, dist/ rebuild, and full verification

- Status: done
- Owner: executor
- Depends on: phase-0004, phase-0005
- Goal: Add the `docs/TODO.md` entry for future Advanced routing UX rework/removal, update affected `DOX.md` Feature Maps, rebuild `src-tauri/ui/dist/`, and verify every CI gate passes.
- Done when: `docs/TODO.md` and `DOX.md` files are updated, `src-tauri/ui/dist/` is freshly built, and the full CI verification command exits 0.
- Pattern to follow: `docs/TODO.md` (existing item style), `DOX.md` Feature Map format (`- **Name** — one line. Start: ... Files: ...`).

## Context
`src-tauri/ui/dist/` is a tracked build artifact read by `tauri::generate_context!()`; it must be regenerated via `npm run build` after frontend edits. The user also asked to record a `docs/TODO.md` entry noting that the Advanced routing drawer and HTTP/SOCKS split tables are kept for now and should be reworked or removed in the future.

## Scope
- In: `docs/TODO.md`, `DOX.md`, `crates/conduit-core/DOX.md`, `crates/conduit-runtime/DOX.md`, `src-tauri/DOX.md`, `src-tauri/ui/DOX.md`, `src-tauri/ui/dist/`
- Out: `crates/*/src/`, `src-tauri/src/`, `src-tauri/ui/src/`

## Sub-tasks
1. [done] Add a concise item to `docs/TODO.md` about reworking (or removing) the Advanced routing drawer (multi-condition rules, failover chains, bypass/inbound) and HTTP/SOCKS split override tables UX in the future. — done when: `docs/TODO.md` contains the new entry.
2. [done] Update the Feature Maps in `DOX.md`, `crates/conduit-core/DOX.md`, `crates/conduit-runtime/DOX.md`, `src-tauri/DOX.md`, and `src-tauri/ui/DOX.md` for any added files (e.g. `routingRows.ts`, `forward_dialer.rs` if created) or changed feature descriptions (AirSwitch-style routing table, tunnel optional forward/MITM/filters, `-L` proxy protocol targets). — done when: every new file and changed feature is accurately reflected in its nearest `DOX.md`.
3. [done] Rebuild `src-tauri/ui/dist/` and run the full CI verification suite from the `rusty-conduit-gui` root. — done when: all commands in `## Verify` exit 0.

## Verify
```sh
cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && cargo test -p rusty-conduit-gui --test secret_leak_scan && python3 scripts/check-pure-rust-crypto.py && python3 scripts/validate-release-config.py && (cd src-tauri/ui && npm run check && npm test && npm run build)
```

## Escalate when
- Any CI gate fails due to a bug in phases 1–5 (outside this phase's Scope: In) → stop, set Status: needs-human — reason: paste the exact failing command and error output.

## Log
- (append-only, one line per event)
- added Advanced routing & HTTP/SOCKS split UX TODO item to `docs/TODO.md`
- updated Feature Maps in `DOX.md`, `crates/conduit-core/DOX.md`, `crates/conduit-runtime/DOX.md`, `src-tauri/DOX.md`, and `src-tauri/ui/DOX.md`
- rebuilt `src-tauri/ui/dist/` and ran the full CI verification suite (used `uv run --with pyyaml python3 scripts/validate-release-config.py` because system `python3` lacks PyYAML locally)

## Evidence
- (append-only: command → observed result)
- `docs/TODO.md` edit → added `Advanced routing & HTTP/SOCKS split UX` entry matching existing bullet style
- `DOX.md`, `crates/conduit-core/DOX.md`, `crates/conduit-runtime/DOX.md`, `src-tauri/DOX.md`, `src-tauri/ui/DOX.md` edits → added `forward_dialer.rs`, `routingRows.ts`, `routingRows.test.ts` and updated Proxy/Tunnel Feature Map entries
- `cargo clippy --workspace --all-targets -- -D warnings` → exit 0 (0 warnings)
- `cargo test --workspace` → exit 0 (all workspace tests passed, including 146 conduit-core, 176 rusty-conduit-gui unit, 6 secret_leak_scan)
- `cargo test -p rusty-conduit-gui --test secret_leak_scan` → exit 0 (6 passed, 0 failed)
- `python3 scripts/check-pure-rust-crypto.py` → exit 0 (`PURE_RUST_CRYPTO_OK`)
- `python3 scripts/validate-release-config.py` → exit 1 (`PyYAML is required to validate workflows: pip install pyyaml` — local system `python3` lacks PyYAML); verified via `uv run --with pyyaml python3 scripts/validate-release-config.py` → exit 0 (`RELEASE_CONFIG_OK`)
- `cd src-tauri/ui && npm run check && npm test && npm run build` → exit 0 (svelte-check: 0 errors, 0 warnings; 105 UI tests passed; `dist/` built cleanly)
