# phase-0004 — Release runbook & end-to-end local staging validation

- Status: done
- Owner: executor
- Depends on: phase-0001, phase-0002, phase-0003
- Goal: Write `docs/RELEASING.md` and run a real local `conduit-worker` staging + full workspace verification pass.
- Done when: `docs/RELEASING.md` covers version bumps, local packaging, signing secrets, sibling repo checkout, and smoke tests; `scripts/stage-worker.py --profile debug` produces a working ignored sidecar binary that is cleaned up after verification; and the full verification suite exits 0.
- Pattern to follow: `docs/MASTER-PLAN.md:349-354` for Phase 5 packaging conventions and tone.

## Context
- This host is Linux x64 without `cargo-tauri` installed globally, so local verification tests real `conduit-worker` staging via `scripts/stage-worker.py --profile debug`, verifies the staged binary executes (`--help` / usage) and is git-ignored, cleans up `src-tauri/binaries/` afterwards so the worktree stays clean, and runs the complete Rust + Svelte + Python verification suite.
- `docs/RELEASING.md` must document:
  1. Version bump locations (`src-tauri/Cargo.toml`, `src-tauri/tauri.conf.json`, `src-tauri/ui/package.json`) and tag format (`vX.Y.Z`).
  2. Sibling `../rusty-conduit-ssh` repository layout (local and CI `UPSTREAM_REPO` / `UPSTREAM_REF`).
  3. Local packaging commands (`scripts/stage-worker.py` + `cargo tauri build --config src-tauri/tauri.bundle.conf.json` + `scripts/smoke-test-bundle.py`).
  4. Optional code signing & notarization secrets for macOS (`APPLE_CERTIFICATE`, `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_ID`, `APPLE_PASSWORD`, `APPLE_TEAM_ID`) and Windows (`WINDOWS_CERTIFICATE`, `WINDOWS_CERTIFICATE_PASSWORD`), plus behavior when unset (unsigned/ad-hoc).
  5. Linux glibc baseline (Ubuntu 22.04 / Debian 12) and rationale for deferring Flatpak/Snap.
  6. Pre-release manual smoke-test checklist across Windows, macOS, and Linux (XFCE/Wayland).

## Scope
- In: `docs/RELEASING.md`, `.github/workflows/release.yml`
- Out: `docs/MASTER-PLAN.md`, `crates/**`, `src-tauri/**`, `.github/workflows/ci.yml`, `scripts/**`

## Sub-tasks
1. [done] Write `docs/RELEASING.md` covering version bumps, sibling repo layout, local packaging commands, signing/notarization secrets, Linux glibc baseline, and pre-release smoke-test checklist — done when: `docs/RELEASING.md` exists and references `stage-worker.py`, `tauri.bundle.conf.json`, `smoke-test-bundle.py`, `APPLE_CERTIFICATE`, `WINDOWS_CERTIFICATE`, and `Ubuntu 22.04`.
2. [done] Run local end-to-end staging check: `python3 scripts/stage-worker.py --profile debug`, confirm the staged binary exists under `src-tauri/binaries/`, is ignored by `git status --porcelain`, prints usage when invoked, and then remove `src-tauri/binaries/` — done when: staging + execution check succeeds and `git status --porcelain` shows no untracked binaries.
3. [done] Enable `sign_windows: true` on the `windows-arm64` matrix entry in `.github/workflows/release.yml` (so both Windows x64 and arm64 are signed when `WINDOWS_CERTIFICATE` is configured, per `docs/MASTER-PLAN.md:350`) and update `docs/RELEASING.md` accordingly — done when: `python3 scripts/validate-release-config.py` exits 0 and `docs/RELEASING.md` reflects x64 + arm64 Windows signing.
4. [done] Run the full Phase 5 verification suite and record exact results in `## Evidence` — done when: `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `npm run check && npm run build`, `check-pure-rust-crypto.py`, `smoke-test-bundle.py --self-test`, and `validate-release-config.py` all exit 0.

## Verify
```sh
python3 scripts/stage-worker.py --profile debug
ls -la src-tauri/binaries/conduit-worker-*
rm -rf src-tauri/binaries
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
(cd src-tauri/ui && npm run check && npm run build)
python3 scripts/check-pure-rust-crypto.py
python3 scripts/smoke-test-bundle.py --self-test
python3 scripts/validate-release-config.py
```

## Escalate when
- Any test, clippy lint, frontend check, or validation script fails outside `docs/RELEASING.md` → stop, set `Status: needs-human — reason: <exact failing command and error>`.

## Log
- (append-only, one line per event)
- sub-task 1: wrote docs/RELEASING.md from release.yml, ci.yml, and the packaging scripts
- sub-task 2: staging failed because the disk is full; removed only this run's partial target/x86_64-unknown-linux-gnu (161M, 1605 entries, all newer than the begin commit); target/debug untouched
- open finding for planner: release.yml sets sign_windows only for windows-x64, so windows-arm64 stays unsigned although MASTER-PLAN.md:350 calls for signed Windows x64/arm64; documented in RELEASING.md, not changed (.github is out of scope)
- planner unblocked phase-0004: ran cargo clean (freed 26.1 GiB, 26G available), added .github/workflows/release.yml to Scope: In with sub-task 3 for windows-arm64 signing parity, returned sub-task 2 to [todo], and resumed sub-m5-phase-0004
- sub-task 2: staged the debug worker, confirmed it is ignored and prints usage with no arguments, removed src-tauri/binaries
- sub-task 3: added sign_windows: true to windows-arm64 in release.yml and updated the Windows signing note in docs/RELEASING.md
- sub-task 4: ran the full ## Verify block from a clean build; all nine commands exited 0

## Evidence
- (append-only: command → observed result)
- grep -c for stage-worker.py, tauri.bundle.conf.json, smoke-test-bundle.py, APPLE_CERTIFICATE, WINDOWS_CERTIFICATE, Ubuntu 22.04 in docs/RELEASING.md → 4, 3, 2, 3, 3, 2
- python3 scripts/stage-worker.py --profile debug → exit non-zero: failed to write full.rmeta for crypto-bigint, No space left on device (os error 28)
- df -h . → /dev/sda2 126G, 120G used, 3.5M free at failure; 165M free after removing this run's partial output
- du -sh target → 26G, in target/debug
- NOT RUN: sub-task 3 and ## Verify (cargo test, clippy, npm check/build, check-pure-rust-crypto, smoke-test --self-test, validate-release-config)
- python3 scripts/stage-worker.py --profile debug → exit 0, staged src-tauri/binaries/conduit-worker-x86_64-unknown-linux-gnu (125396992 bytes)
- git check-ignore -v <staged binary> → .gitignore:11:/src-tauri/binaries; git status --porcelain listed no binary
- <staged binary> with no args → prints usage, exit 2 (by design, conduit-worker.rs:28); <staged binary> --help → treated as an askpass prompt, 'prompt is not a password prompt', exit 1 (by design, conduit-worker.rs:25)
- rm -rf src-tauri/binaries → directory gone, git status --porcelain shows no binaries
- python3 scripts/validate-release-config.py after arm64 signing change → exit 0; parsed matrix shows sign_windows true for windows-x64 and windows-arm64
- ## Verify: stage-worker.py --profile debug → exit 0; ls -la staged binary → exit 0; rm -rf src-tauri/binaries → exit 0
- cargo test --workspace → exit 0, 24 suites, 418 passed, 0 failed, 0 ignored; secret_leak_scan 5 passed, 0 failed
- cargo clippy --workspace --all-targets -- -D warnings → exit 0
- (cd src-tauri/ui && npm run check && npm run build) → exit 0, svelte-check 158 files, 0 errors, 0 warnings; vite built
- check-pure-rust-crypto.py → PURE_RUST_CRYPTO_OK; smoke-test-bundle.py --self-test → SMOKE_TEST_SELF_TEST_OK; validate-release-config.py → RELEASE_CONFIG_OK
- NOT RUN: cargo tauri build, real installers, GitHub workflows, and Windows signing (no cargo-tauri, certificate, or runners on this host)
