# phase-0004 — Run full local CI verification suite and stale-name audit

- Status: done
- Owner: planner
- Depends on: phase-0002, phase-0003
- Goal: Verify the entire workspace passes every CI gate (Rust, frontend, Python checks) and audit the repository to confirm no unintended `rusty-conduit-ssh-gui` or `Rusty Conduit (SSH)` strings remain.
- Done when: Every command in `## Verify` exits 0 and all remaining occurrences of the old names are strictly intentional migration/compatibility/plan references.
- Pattern to follow: `.github/workflows/ci.yml:40-118`

## Context
Before Gate D review and pausing for the manual GitHub repository rename and local folder rename (§3.2 steps 2–3), run the exact CI command set locally and verify clean grep audit.

## Scope
- In: `.goal-ledger/**` (plus any small fix-ups needed if a CI gate fails)
- Out: GitHub repository rename, local folder rename, `git push`, `git tag`

## Sub-tasks
1. [done] Run full Rust CI gates (`cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `secret_leak_scan`, Linux `conduit_check_tauri_tray` check) — done when: all 4 cargo commands exit 0
2. [done] Run Python and frontend CI gates (`check-pure-rust-crypto.py`, `validate-release-config.py`, `smoke-test-bundle.py --self-test`, `npm run check && npm test && npm run build`) — done when: all commands exit 0
3. [done] Audit remaining occurrences of `rusty-conduit-ssh-gui`, `rusty_conduit_ssh_gui`, and `Rusty Conduit (SSH)` across the repo — done when: every match is verified to belong only to `src-tauri/src/migration.rs`, `nsis-hooks.nsh`, `docs/MASTER-PLAN.md`, `docs/TODO.md`, or `.goal-ledger/`

## Verify
```sh
CARGO_NET_GIT_FETCH_WITH_CLI=true cargo clippy --workspace --all-targets -- -D warnings && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test --workspace && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p rusty-conduit-gui --test secret_leak_scan && CARGO_NET_GIT_FETCH_WITH_CLI=true RUSTFLAGS="--cfg conduit_check_tauri_tray" cargo check -p rusty-conduit-gui --tests --features tauri/tray-icon && python3 scripts/check-pure-rust-crypto.py && python3 scripts/validate-release-config.py && python3 scripts/smoke-test-bundle.py --self-test && (cd src-tauri/ui && npm run check && npm test && npm run build)
```

## Escalate when
- Any CI check fails and cannot be fixed within two fix-up sub-tasks → stop, set `Status: needs-human — reason: <exact failure>`

## Log
- (append-only, one line per event)
- began phase-0004
- sub-tasks 1–3 done & verified: full local CI suite (Rust clippy/tests/secret_leak_scan/tauri_tray, 3 Python scripts, frontend check/test/build) exited 0; stale-name audit confirmed all remaining matches are strictly in `src-tauri/src/migration.rs`, `src-tauri/windows/nsis-hooks.nsh`, and `docs/MASTER-PLAN.md`

## Evidence
- (append-only: command → observed result)
- `## Verify` (all 4 cargo gates + 3 Python checks + frontend `npm run check && npm test && npm run build`) → exit 0
- `grep -rn ... 'rusty-conduit-ssh-gui|rusty_conduit_ssh_gui|Rusty Conduit \(SSH\)' .` → matches only in `src-tauri/src/migration.rs`, `src-tauri/windows/nsis-hooks.nsh`, and `docs/MASTER-PLAN.md`
