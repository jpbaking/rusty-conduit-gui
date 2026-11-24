# phase-0003 — Cross-platform CI & Release automation workflows

- Status: done
- Owner: executor
- Depends on: phase-0001, phase-0002
- Goal: Add `.github/workflows/ci.yml` and `.github/workflows/release.yml` covering all Phase 5 CI gates and cross-platform packaging/signing targets.
- Done when: Both workflow YAML files parse cleanly, cover Linux/macOS/Windows CI gates and Windows x64/arm64 + macOS Universal + Linux x64/arm64 (Ubuntu 22.04) release builds with conditional signing and smoke tests, and `python3 scripts/validate-release-config.py` exits 0.
- Pattern to follow: `Cargo.toml:18-20` for sibling `../rusty-conduit-ssh` path dependency layout and `scripts/stage-worker.py` + `scripts/smoke-test-bundle.py` for build/smoke steps.

## Context
- `Cargo.toml` depends on `rusty-conduit-ssh = { path = "../rusty-conduit-ssh" }`. In GitHub Actions, check out this repo into `rusty-conduit-ssh-gui/` and check out `jpbaking/rusty-conduit-ssh` (configurable via env `UPSTREAM_REPO` / `UPSTREAM_REF`, defaulting to `jpbaking/rusty-conduit-ssh` at `main`) into `rusty-conduit-ssh/` so `../rusty-conduit-ssh` resolves identically on Linux, macOS, and Windows runners.
- `.github/workflows/ci.yml` must run on `push` (to `main`) and `pull_request`:
  - `frontend` job (Ubuntu 22.04, Node 22): `npm ci`, `npm run check`, `npm run build` in `src-tauri/ui`.
  - `rust-and-e2e` matrix on `ubuntu-22.04`, `macos-latest`, and `windows-latest`:
    - Linux installs `libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf libdbus-1-dev libgtk-3-dev openssh-client`.
    - Runs `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` (which runs unit tests, multi-hop loopback E2E, `conduit-openssh` Windows named-pipe/askpass or Unix tests, and `secret_leak_scan`), `python3 scripts/check-pure-rust-crypto.py`, `python3 scripts/validate-release-config.py`, and on Linux also `RUSTFLAGS="--cfg conduit_check_tauri_tray" cargo check -p rusty-conduit-ssh-gui --tests`.
- `.github/workflows/release.yml` must run on tag push `v*` and `workflow_dispatch` (with `dry_run` boolean input, default `true`):
  - `verify` job running the CI/validation gates before packaging.
  - `package` matrix:
    - `linux-x64` (`ubuntu-22.04`, `x86_64-unknown-linux-gnu`) → `.deb`, `.rpm`, `.AppImage` (install `rpm` alongside WebKitGTK/Tauri Linux build deps so `.rpm` bundling and `smoke-test-bundle.py`'s `rpm -qlp` check succeed)
    - `linux-arm64` (`ubuntu-22.04-arm`, `aarch64-unknown-linux-gnu`) → `.deb`, `.rpm`, `.AppImage` (also install `rpm`)
    - `macos-universal` (`macos-latest`, `universal-apple-darwin`) → `.app` + `.dmg` using `scripts/stage-worker.py --universal-macos` and conditional Apple Developer ID signing/notarization when `APPLE_CERTIFICATE` secret is non-empty (falling back to unsigned/ad-hoc when unset)
    - `windows-x64` (`windows-latest`, `x86_64-pc-windows-msvc`) → NSIS `.exe` + `.msi` with conditional Authenticode signing when `WINDOWS_CERTIFICATE` secret is non-empty
    - `windows-arm64` (`windows-latest`, `aarch64-pc-windows-msvc` cross-target) → NSIS `.exe` + `.msi`
  - Every package job stages `conduit-worker` via `scripts/stage-worker.py`, builds with `tauri build --config src-tauri/tauri.bundle.conf.json`, runs `scripts/smoke-test-bundle.py`, and uploads artifacts.
  - `release` job downloads all artifacts, generates `SHA256SUMS.txt`, and creates a draft GitHub Release on `startsWith(github.ref, 'refs/tags/v')` (skipped on `workflow_dispatch` with `dry_run: true`).
- Update `scripts/validate-release-config.py` if needed so it strictly asserts both `.github/workflows/ci.yml` and `.github/workflows/release.yml` exist and contain the expected matrix targets, secret-leak test invocation, pure-Rust crypto check, and smoke-test step.

## Scope
- In: `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `scripts/validate-release-config.py`
- Out: `crates/**`, `src-tauri/**`, `docs/**`, `.gitignore`

## Sub-tasks
1. [done] Create `.github/workflows/ci.yml` with sibling `rusty-conduit-ssh` checkout, frontend check/build job, 3-OS (`ubuntu-22.04`, `macos-latest`, `windows-latest`) Rust clippy + `cargo test --workspace` + `secret_leak_scan` + `check-pure-rust-crypto.py` + `validate-release-config.py` + Linux `conduit_check_tauri_tray` check — done when: YAML parses cleanly with `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"`.
2. [done] Create `.github/workflows/release.yml` with tag `v*` + `workflow_dispatch` trigger, `verify` gate, 5-target packaging matrix (`linux-x64`, `linux-arm64`, `macos-universal`, `windows-x64`, `windows-arm64`), `stage-worker.py`, `tauri build --config src-tauri/tauri.bundle.conf.json`, conditional Apple/Windows signing env wiring, `smoke-test-bundle.py`, `SHA256SUMS.txt`, and draft GitHub Release publishing — done when: YAML parses cleanly with `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"`.
3. [done] Tighten `scripts/validate-release-config.py` to require `.github/workflows/ci.yml` and `.github/workflows/release.yml` and assert all required OS/arch targets, secret-leak scan, pure-Rust crypto check, and smoke-test invocations are present — done when: `python3 scripts/validate-release-config.py` exits 0.

## Verify
```sh
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); yaml.safe_load(open('.github/workflows/release.yml')); print('YAML_OK')"
python3 scripts/validate-release-config.py
```

## Escalate when
- A required workflow target or Tauri v2 action convention conflicts with `src-tauri/tauri.bundle.conf.json` → stop, set `Status: needs-human — reason: <exact conflict>`.

## Log
- (append-only, one line per event)
- sub-task 1: added .github/workflows/ci.yml with sibling upstream checkout, frontend job, 3-OS rust-and-e2e matrix, and a workflow_call trigger so release.yml reuses the same gates
- sub-task 2: added .github/workflows/release.yml with verify, 5-target package matrix, conditional Apple/Windows signing, smoke tests, SHA256SUMS.txt, and draft release; Tauri CLI pinned to 2.12.6 because the repo has no @tauri-apps/cli dependency
- sub-task 3: tightened scripts/validate-release-config.py to require both workflows and assert triggers, matrix targets, gates, smoke test, signing, and draft-release condition
- phase verify passed; workflows were not executed on GitHub runners (this repository has no git remote)

## Evidence
- (append-only: command → observed result)
- python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))" → exit 0
- python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))" → exit 0
- python3 scripts/validate-release-config.py → RELEASE_CONFIG_OK, exit 0
- ## Verify block → YAML_OK, RELEASE_CONFIG_OK, exit 0
- bash -n on every non-pwsh run block → ci 13 and release 12 checked, no syntax errors
- validator mutation test on a scratch copy (removed secret-leak step, crypto check, windows-latest, smoke test, arm runner, dry_run guard, release.yml) → all 7 rejected, exit 1 for the 6 measured mutations and a missing-file error for release.yml
- tauri-cli 2.12.6 / tauri-bundler 2.10.6 source → --config is repeatable, Apple variables are checked with var_os (empty counts as set), identity "-" is handled as ad-hoc, MSI and NSIS support arm64
