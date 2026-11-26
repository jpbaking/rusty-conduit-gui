# phase-0001 — Add §3.3 deb/rpm/NSIS upgrade-path packaging metadata and bump release version to 0.2.0

- Status: done
- Owner: executor
- Depends on: none
- Goal: Implement the remaining `docs/MASTER-PLAN.md` §3.3 upgrade-path packaging metadata for Linux (`.deb` / `.rpm`) and Windows (NSIS legacy uninstall prompt), and bump the release version consistently from `0.1.0` to `0.2.0` across all release manifests and lockfiles.
- Done when: `src-tauri/tauri.conf.json`, `src-tauri/Cargo.toml`, `src-tauri/ui/package.json`, `Cargo.lock`, and `src-tauri/ui/package-lock.json` all report `0.2.0` with no unrelated dependency bumps, `.deb`/`.rpm` replacement metadata and NSIS legacy uninstall detection are in place, and `## Verify` exits 0.
- Pattern to follow: `docs/MASTER-PLAN.md:72-97`, `src-tauri/tauri.conf.json`, `src-tauri/windows/nsis-hooks.nsh`

## Context
- Disk constraint: ALWAYS pass `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true` on every `cargo` command (`rusty-conduit-engine` is fetched via git tag `v0.2.0`, root `/` has ~19 GB free).
- **`src-tauri/tauri.conf.json`**:
  - Bump `"version"` from `"0.1.0"` to `"0.2.0"`.
  - Under `bundle.linux.deb`, add `"replaces": ["rusty-conduit-ssh-gui"]` and `"conflicts": ["rusty-conduit-ssh-gui"]` (verify Tauri v2 config schema accepts these exact keys via `cargo check -p rusty-conduit-gui`).
  - Under `bundle.linux.rpm`, add `"obsoletes": ["rusty-conduit-ssh-gui"]` and `"conflicts": ["rusty-conduit-ssh-gui"]` (verify Tauri v2 config schema accepts these exact keys; check `tauri-utils` schema in Cargo registry if `tauri-build` rejects any field name).
- **`src-tauri/windows/nsis-hooks.nsh`**:
  - Preserve existing `NSIS_HOOK_PREINSTALL` and `NSIS_HOOK_PREUNINSTALL` process-stop hooks (`rusty-conduit-gui.exe`, `rusty-conduit-ssh-gui.exe`, `conduit-worker.exe`).
  - In `NSIS_HOOK_PREINSTALL`, detect a legacy `Rusty Conduit (SSH)` installation by reading `HKCU` `"Software\Microsoft\Windows\CurrentVersion\Uninstall\Rusty Conduit (SSH)"` `"UninstallString"` (with `HKLM` fallback if empty).
  - When a legacy `UninstallString` is found and the installer is NOT running silently (`IfSilent`), prompt with `MessageBox MB_YESNO|MB_ICONQUESTION` offering to uninstall the legacy `Rusty Conduit (SSH)` app (mentioning that settings and vault are migrated automatically on first launch) and, if Yes, run `ExecWait` on the uninstall string.
- **Version bump to `0.2.0`**:
  - `src-tauri/Cargo.toml`: `[package] version = "0.2.0"`.
  - `Cargo.lock`: refresh cleanly for `rusty-conduit-gui` `0.2.0` (do NOT bump third-party dependency versions).
  - `src-tauri/ui/package.json` and `src-tauri/ui/package-lock.json`: `"version": "0.2.0"` (`npm install --package-lock-only` in `src-tauri/ui`, keeping dependencies untouched).

## Scope
- In: `src-tauri/tauri.conf.json`, `src-tauri/windows/nsis-hooks.nsh`, `src-tauri/Cargo.toml`, `Cargo.lock`, `src-tauri/ui/package.json`, `src-tauri/ui/package-lock.json`
- Out: `scripts/`, `.github/`, `docs/`, `README.md`, `src-tauri/ui/dist/`, `src-tauri/src/`, `crates/`

## Sub-tasks
1. [done] Add `.deb` (`replaces`/`conflicts`) and `.rpm` (`obsoletes`/`conflicts`) upgrade-path metadata to `src-tauri/tauri.conf.json` and verify Tauri v2 accepts the schema — done when: `cargo check -p rusty-conduit-gui` passes with the new keys.
2. [done] Update `src-tauri/windows/nsis-hooks.nsh` `NSIS_HOOK_PREINSTALL` to detect legacy `Rusty Conduit (SSH)` (`UninstallString`) and offer to uninstall it when non-silent — done when: hook handles HKCU/HKLM lookup, `IfSilent` guard, `MessageBox MB_YESNO`, and `ExecWait`.
3. [done] Bump version from `0.1.0` to `0.2.0` in `src-tauri/Cargo.toml`, `src-tauri/tauri.conf.json`, `src-tauri/ui/package.json`, and refresh `Cargo.lock` and `src-tauri/ui/package-lock.json` without upgrading third-party dependencies — done when: `git diff` shows only the `0.1.0 -> 0.2.0` package version bump in manifests and lockfiles.
4. [done] Run `## Verify` and record observed results in `## Evidence` — done when: `## Verify` exits 0.

## Verify
```sh
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo check -p rusty-conduit-gui && python3 scripts/validate-release-config.py && python3 scripts/check-pure-rust-crypto.py
```

## Escalate when
- Tauri v2 (`tauri-build` / `tauri-utils`) does not support any of `deb.replaces`, `deb.conflicts`, `rpm.obsoletes`, or `rpm.conflicts` in `tauri.conf.json` → stop, set Status: needs-human — reason: report the exact `tauri-utils` schema fields available.

## Log
- (append-only, one line per event)
- sub-task 1: confirmed `tauri-utils` 2.10.4 `DebConfig.replaces`/`conflicts` and `RpmConfig.obsoletes`/`conflicts`; added them for `rusty-conduit-ssh-gui` in `src-tauri/tauri.conf.json`.
- sub-task 2: added `CONDUIT_OFFER_LEGACY_UNINSTALL` macro (HKCU then HKLM `UninstallString`, `IfSilent` skip, `MessageBox MB_YESNO|MB_ICONQUESTION`, `ExecWait`) and inserted it in `NSIS_HOOK_PREINSTALL` after `CONDUIT_STOP_ALL`; existing stop hooks kept. Not compiled: `makensis` is not installed here.
- sub-task 3: bumped `0.1.0 -> 0.2.0` in `src-tauri/Cargo.toml`, `src-tauri/tauri.conf.json`, `src-tauri/ui/package.json`; refreshed `Cargo.lock` (via `cargo check`) and `package-lock.json` (`npm install --package-lock-only --ignore-scripts`).
- sub-task 4: ran `## Verify` verbatim; exit 0.

## Evidence
- (append-only: command → observed result)
- `grep -n 'pub replaces\|pub conflicts\|pub obsoletes' ~/.cargo/registry/src/*/tauri-utils-2.10.4/src/config.rs` → deb `conflicts` (349), `replaces` (351); rpm `conflicts` (449), `obsoletes` (452). `Cargo.lock` pins `tauri-utils` 2.10.4.
- `cargo check -p rusty-conduit-gui` (low-disk env) with new keys → `Finished dev profile`; `-v` shows `Fresh rusty-conduit-gui v0.2.0`.
- `grep -n conduit_legacy_done src-tauri/windows/nsis-hooks.nsh` → lines 27 (StrCmp), 28 (IfSilent), 29 (MessageBox IDNO), 31 (label); HKCU/HKLM `ReadRegStr` at 24/26; `ExecWait $0` at 30. `which makensis` → not found (not compiled).
- `git diff Cargo.lock src-tauri/ui/package-lock.json` → only `rusty-conduit-gui` / `rusty-conduit-gui-ui` `0.1.0 -> 0.2.0` (1 line Cargo.lock, 2 lines package-lock); no dependency changes.
- `## Verify` → `Finished dev profile`, `RELEASE_CONFIG_OK`, `PURE_RUST_CRYPTO_OK`, EXIT=0.
