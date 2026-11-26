# phase-0005 — Rebuild src-tauri/ui/dist/ and run full low-disk verification suite

- Status: done
- Owner: executor
- Depends on: phase-0004
- Goal: Rebuild and commit the production Svelte UI bundle (`src-tauri/ui/dist/`) and run the complete low-disk local CI verification suite across Rust, Python, and Frontend.
- Done when: `src-tauri/ui/dist/` matches the current UI source and the complete `## Verify` command exits 0 with zero errors or warnings.
- Pattern to follow: `src-tauri/ui/package.json`

## Context
- Disk constraint: ALWAYS pass `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true` on every `cargo` command so `target/` stays under ~5 GB.
- Run the complete `## Verify` command (matching `GOAL.md` `Full verification`), and include the rebuilt `src-tauri/ui/dist/` bundle in the phase close commit (removing any stale old hashed assets in `src-tauri/ui/dist/assets/`).

## Scope
- In: `src-tauri/ui/dist/`
- Out: `Cargo.toml`, `crates/`, `src-tauri/src/`, `src-tauri/tests/`, `src-tauri/ui/src/`, `.github/`, `scripts/`, `docs/`

## Sub-tasks
1. [done] Rebuild `src-tauri/ui/dist/` via `cd src-tauri/ui && npm run check && npm test && npm run build` and verify no stale old hashed assets remain in `src-tauri/ui/dist/assets/` — done when: frontend check, tests, and build exit 0 and `git status` shows clean `dist/` output.
2. [done] Run the complete `## Verify` command and record observed results (including `du -sh target` and `df -h .`) in `## Evidence` — done when: every check exits 0.

## Verify
```sh
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo clippy --workspace --all-targets -- -D warnings && CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test --workspace && CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p rusty-conduit-gui --test secret_leak_scan && CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true RUSTFLAGS="--cfg conduit_check_tauri_tray" cargo check -p rusty-conduit-gui --tests --features tauri/tray-icon && python3 scripts/check-pure-rust-crypto.py && python3 scripts/validate-release-config.py && python3 scripts/smoke-test-bundle.py --self-test && (cd src-tauri/ui && npm run check && npm test && npm run build)
```

## Escalate when
- Any workspace test, clippy lint, Python script, or frontend check fails → stop, set Status: needs-human — reason: report the exact failing test, lint, or script

## Log
- (append-only, one line per event)
- sub-task 1: rebuilt src-tauri/ui/dist/ (vite emptied outDir; old hashed assets dist-js-BB8KCS9e.js, index-CcgPsR_a.css, index-DJgfnu72.js replaced by dist-js-BKqw0l0e.js, index-CmjdL6Z5.css, index-DHmNQCi3.js)
- sub-task 2: ran full ## Verify in one chain → VERIFY_EXIT=0; recorded target/disk usage
- Verify passed with no fix-ups; phase closed

## Evidence
- (append-only: command → observed result)
- `cd src-tauri/ui && npm run check && npm test && npm run build` → svelte-check 198 files 0 errors 0 warnings; node test pass 93 fail 0; vite build ok (index-DHmNQCi3.js 382.34 kB); `ls dist/assets` → only 3 new hashed files; `git status` → only dist/ changes (3 D old assets, 3 ?? new, M index.html)
- full `## Verify` command (clippy -D warnings → workspace tests → secret_leak_scan → tray cfg check → 3 python scripts → npm check/test/build) → VERIFY_EXIT=0; 25 `test result: ok` lines, 0 failed (incl. conduit-core 133, conduit-runtime 91, gui lib 174, secret_leak_scan 6); no compiler/clippy `warning:` lines; PURE_RUST_CRYPTO_OK, RELEASE_CONFIG_OK, SMOKE_TEST_SELF_TEST_OK; svelte-check 198 files 0 errors 0 warnings; node tests pass 93 fail 0; vite build ok with identical hashes (dist-js-BKqw0l0e.js, index-CmjdL6Z5.css, index-DHmNQCi3.js)
- `du -sh target` → 6.1G; `df -h .` → /dev/sda2 126G size, 101G used, 19G avail (85%)
