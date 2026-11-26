# phase-0003 — Rebuild src-tauri/ui/dist/ if needed and run full low-disk verification suite plus version check

- Status: done
- Owner: executor
- Depends on: phase-0002
- Goal: Run the complete low-disk U5 verification suite across Rust, Python scripts, and Svelte UI, rebuild `src-tauri/ui/dist/` if the frontend build produces any changes, verify `rusty-conduit-gui --version` reports `0.2.0`, and confirm disk usage remains healthy.
- Done when: All `## Verify` commands exit 0, `rusty-conduit-gui --version` prints `0.2.0`, any `src-tauri/ui/dist/` updates are committed cleanly, and root `/` has >= 10 GB free.
- Pattern to follow: `.goal-ledger/GOAL.md` Full verification command

## Context
- Disk constraint: ALWAYS pass `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true` on every `cargo` command. Check `df -h /` and `du -sh target` at the end.
- `src-tauri/ui/dist/` is tracked in Git (required by `tauri::generate_context!()`). After `npm run build`, if `git status --short src-tauri/ui/dist` shows changes, stage and commit them cleanly (removing any stale hashed assets); if unchanged, commit only the ledger update.
- Verify `cargo run -p rusty-conduit-gui -- --version` prints `0.2.0`.

## Scope
- In: `src-tauri/ui/dist/` (only if `npm run build` changes it)
- Out: `crates/`, `src-tauri/src/`, `src-tauri/ui/src/`, `scripts/`, `.github/`, `docs/`, `README.md`

## Sub-tasks
1. [done] Run the frontend checks and production build (`cd src-tauri/ui && npm run check && npm test && npm run build`) and inspect `git status --short src-tauri/ui/dist` — done when: `svelte-check` reports 0 errors/warnings, all frontend tests pass, and `vite build` succeeds.
2. [done] Run the full Rust and Python verification suite, check `rusty-conduit-gui --version` prints `0.2.0`, verify disk usage (`df -h / && du -sh target`), and record observed results in `## Evidence` — done when: all `## Verify` commands exit 0 and `target/` + disk space are healthy.

## Verify
```sh
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo clippy --workspace --all-targets -- -D warnings && CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test --workspace && CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p rusty-conduit-gui --test secret_leak_scan && CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true RUSTFLAGS="--cfg conduit_check_tauri_tray" cargo check -p rusty-conduit-gui --tests --features tauri/tray-icon && CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo run -p rusty-conduit-gui -- --version && python3 scripts/check-pure-rust-crypto.py && python3 scripts/validate-release-config.py && python3 scripts/smoke-test-bundle.py --self-test && (cd src-tauri/ui && npm run check && npm test && npm run build) && df -h / && du -sh target
```

## Escalate when
- Any test, clippy check, Python script, frontend check, or `--version` check fails and requires editing files outside `src-tauri/ui/dist/` → stop, set Status: needs-human — reason: paste the failing command and output.
- Free space on `/` drops below 10 GB → stop, set Status: needs-human — reason: report `df -h /` and `du -sh target`.

## Log
- (append-only, one line per event)
- sub-task 1: ran `npm run check && npm test && npm run build` in src-tauri/ui; all passed; `src-tauri/ui/dist/` unchanged (no dist commit needed)
- sub-task 2: ran the `## Verify` block verbatim (output to scratchpad verify.log); every command exited 0; `--version` prints `rusty-conduit-gui 0.2.0`; dist still unchanged after second build
- phase verify: `## Verify` chain → VERIFY_EXIT=0; phase done

## Evidence
- (append-only: command → observed result)
- `df -h /` (start) → 140G avail (43% used)
- `npm run check` → svelte-check 198 files, 0 errors, 0 warnings, exit 0
- `npm test` → tests 93, pass 93, fail 0, exit 0
- `npm run build` → vite built in 3.54s (index-DHmNQCi3.js, index-CmjdL6Z5.css), exit 0
- `git status --short src-tauri/ui/dist` → empty (no changes)
- `## Verify` full chain (verbatim) → VERIFY_EXIT=0
- `cargo clippy --workspace --all-targets -- -D warnings` → Finished, no warnings/errors
- `cargo test --workspace` → all `test result: ok`, 0 failed (largest suites 174, 133, 91 passed; 1 ignored in a 44-test suite)
- `cargo test -p rusty-conduit-gui --test secret_leak_scan` → ok, 0 failed
- `RUSTFLAGS="--cfg conduit_check_tauri_tray" cargo check -p rusty-conduit-gui --tests --features tauri/tray-icon` → Finished, exit 0
- `cargo run -p rusty-conduit-gui -- --version` → `rusty-conduit-gui 0.2.0`
- `python3 scripts/check-pure-rust-crypto.py` → PURE_RUST_CRYPTO_OK
- `python3 scripts/validate-release-config.py` → RELEASE_CONFIG_OK
- `python3 scripts/smoke-test-bundle.py --self-test` → SMOKE_TEST_SELF_TEST_OK
- `(cd src-tauri/ui && npm run check && npm test && npm run build)` → 0 errors/0 warnings; 93/93 pass; built in 3.73s
- `df -h /` → 139G avail (43% used), >= 10 GB OK
- `du -sh target` → 6.8G
- `git status --short` after Verify → only `.goal-ledger/phase-0003.md` modified; dist unchanged
