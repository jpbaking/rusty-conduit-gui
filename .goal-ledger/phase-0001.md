# phase-0001 — Cross-platform icons, Tauri v2 bundle config & NSIS worker-stop hooks

- Status: done
- Owner: executor
- Depends on: none
- Goal: Add full Tauri v2 icon assets, bundle metadata, `tauri.bundle.conf.json` sidecar overlay, Windows NSIS worker-stop hooks, and `.gitignore` entry for staged sidecar binaries.
- Done when: All 6 icon files exist and are valid, `src-tauri/tauri.conf.json` and `src-tauri/tauri.bundle.conf.json` are valid JSON with complete bundle settings, `src-tauri/windows/nsis-hooks.nsh` stops `rusty-conduit-ssh-gui.exe` and `conduit-worker.exe`, and `cargo check --workspace` passes cleanly without pre-staged binaries.
- Pattern to follow: `src-tauri/tauri.conf.json:1-19` for Tauri v2 schema and `.gitignore:1-8` for ignore comments.

## Context
- `src-tauri/build.rs` calls `tauri_build::build()`. If `bundle.externalBin` is placed directly in `src-tauri/tauri.conf.json`, `cargo check`/`cargo test` on a clean checkout fails unless `src-tauri/binaries/conduit-worker-<triple>` already exists.
- Therefore, keep `bundle.active: false` (and no `externalBin`) in `src-tauri/tauri.conf.json` alongside all shared bundle metadata (icons, category, descriptions, license, Linux deb/rpm/AppImage settings, macOS minimumSystemVersion, Windows NSIS/WiX settings), and put `"bundle": { "active": true, "targets": "all", "externalBin": ["binaries/conduit-worker"] }` in `src-tauri/tauri.bundle.conf.json` (passed via `tauri build --config src-tauri/tauri.bundle.conf.json` after staging the worker).
- `src-tauri/icons/icon.png` is currently a valid 256x256 RGBA PNG; Python 3 with Pillow (`PIL`) is installed on this host. Generate `32x32.png`, `128x128.png`, `128x128@2x.png` (256x256), `icon.ico` (multi-size 16/32/48/64/128/256), and a valid Apple ICNS `icon.icns` (containing `ic07` 128x128 PNG and `ic08` 256x256 PNG chunks with valid `icns` 8-byte header + chunk headers) from `src-tauri/icons/icon.png`.
- Per Master Plan Section 9 Phase 5, Windows NSIS must be per-user (`"installMode": "currentUser"`) and stop `rusty-conduit-ssh-gui.exe` and `conduit-worker.exe` cleanly before install/upgrade and uninstall via `installerHooks: "windows/nsis-hooks.nsh"`.
- Planner decisions (unblocking sub-task 3): (1) use `"category": "Utility"` (valid in `tauri-bundler` 2.10.6); (2) use `"copyright": "Copyright (c) 2026, Joseph Baking"` (matching sibling `../rusty-conduit-ssh/LICENSE`).

## Scope
- In: `src-tauri/icons/32x32.png`, `src-tauri/icons/128x128.png`, `src-tauri/icons/128x128@2x.png`, `src-tauri/icons/icon.ico`, `src-tauri/icons/icon.icns`, `src-tauri/tauri.conf.json`, `src-tauri/tauri.bundle.conf.json`, `src-tauri/windows/nsis-hooks.nsh`, `.gitignore`
- Out: `src-tauri/src/**`, `src-tauri/ui/**`, `crates/**`, `docs/**`, `.github/**`, `scripts/**`

## Sub-tasks
1. [done] Generate `src-tauri/icons/32x32.png`, `src-tauri/icons/128x128.png`, `src-tauri/icons/128x128@2x.png`, `src-tauri/icons/icon.ico`, and `src-tauri/icons/icon.icns` from `src-tauri/icons/icon.png` (leaving `icon.png` intact) — done when: a Python check verifies all 5 generated files exist, have expected PNG dimensions / ICO format / `icns` magic header with valid total length matching file size.
2. [done] Create `src-tauri/windows/nsis-hooks.nsh` defining `NSIS_HOOK_PREINSTALL` and `NSIS_HOOK_PREUNINSTALL` macros that terminate `rusty-conduit-ssh-gui.exe` and `conduit-worker.exe` using `nsExec::ExecToLog 'taskkill /F /IM ...'` (ignoring exit code when not running) — done when: file exists and contains both hook macros and both process names.
3. [done] Update `src-tauri/tauri.conf.json` with full bundle metadata (`category: "Utility"`, `shortDescription`, `longDescription`, `copyright: "Copyright (c) 2026, Joseph Baking"`, `license: "BSD-3-Clause"`, `icon` array listing `32x32.png`, `128x128.png`, `128x128@2x.png`, `icon.icns`, `icon.ico`, `linux.deb` with `section: "net"` and `desktopTemplate` omitted/default, `linux.rpm`, `linux.appimage`, `macOS.minimumSystemVersion: "11.0"`, `windows.nsis` with `installMode: "currentUser"` and `installerHooks: "windows/nsis-hooks.nsh"`, `windows.wix`) while keeping `bundle.active: false` — done when: `python3 -c "import json; json.load(open('src-tauri/tauri.conf.json'))"` exits 0.
4. [done] Create `src-tauri/tauri.bundle.conf.json` enabling `"bundle": { "active": true, "targets": "all", "externalBin": ["binaries/conduit-worker"] }` and add `/src-tauri/binaries` to `.gitignore` — done when: `tauri.bundle.conf.json` parses as JSON and `git check-ignore -q src-tauri/binaries/conduit-worker-x86_64-unknown-linux-gnu` exits 0.

## Verify
```sh
python3 - <<'PY'
import json, struct
from pathlib import Path
from PIL import Image

icons = Path("src-tauri/icons")
for name, size in [("32x32.png", (32, 32)), ("128x128.png", (128, 128)), ("128x128@2x.png", (256, 256))]:
    with Image.open(icons / name) as img:
        assert img.size == size, f"{name}: {img.size} != {size}"
with Image.open(icons / "icon.ico") as ico:
    assert ico.format == "ICO"
icns = (icons / "icon.icns").read_bytes()
assert icns[:4] == b"icns"
assert struct.unpack(">I", icns[4:8])[0] == len(icns)

conf = json.loads(Path("src-tauri/tauri.conf.json").read_text())
assert conf["bundle"]["active"] is False
assert conf["bundle"]["windows"]["nsis"]["installMode"] == "currentUser"
assert conf["bundle"]["windows"]["nsis"]["installerHooks"] == "windows/nsis-hooks.nsh"

overlay = json.loads(Path("src-tauri/tauri.bundle.conf.json").read_text())
assert overlay["bundle"]["active"] is True
assert overlay["bundle"]["externalBin"] == ["binaries/conduit-worker"]

nsh = Path("src-tauri/windows/nsis-hooks.nsh").read_text()
assert "NSIS_HOOK_PREINSTALL" in nsh and "NSIS_HOOK_PREUNINSTALL" in nsh
assert "conduit-worker.exe" in nsh and "rusty-conduit-ssh-gui.exe" in nsh
print("PHASE1_ASSETS_OK")
PY
git check-ignore -q src-tauri/binaries/conduit-worker-x86_64-unknown-linux-gnu
cargo check --workspace --all-targets
```

## Escalate when
- `tauri_build::build()` rejects any bundle field in `src-tauri/tauri.conf.json` for Tauri v2 schema → stop, set `Status: needs-human — reason: <exact tauri-build schema error>`.
- `cargo check --workspace --all-targets` fails due to a change outside `Scope: In` → stop, set `Status: needs-human — reason: <exact compiler error>`.

## Log
- (append-only, one line per event)
- sub-task 1: generated 32x32.png, 128x128.png, 128x128@2x.png, icon.ico (16/32/48/64/128/256), icon.icns (ic07+ic08 PNG chunks) from icon.png; icon.png unchanged
- sub-task 2: wrote src-tauri/windows/nsis-hooks.nsh with PREINSTALL and PREUNINSTALL hooks stopping both processes, exit codes ignored
- sub-task 3 (partial): applied all bundle fields except category and copyright, which need a planner decision
- escalated at sub-task 3; sub-task 4 and ## Verify not run as a phase gate
- planner unblocked sub-task 3: use category "Utility" and copyright "Copyright (c) 2026, Joseph Baking"; returned sub-task 3 to [todo] and resumed sub-m5-phase-0001
- sub-task 3: added category Utility and the planner's copyright string to bundle metadata; bundle.active stays false
- sub-task 4: created src-tauri/tauri.bundle.conf.json and added /src-tauri/binaries to .gitignore
- ran ## Verify: all checks passed

## Evidence
- (append-only: command → observed result)
- sub-task 1 Python icon check → 32x32/128x128/256x256 RGBA PNGs; ICO sizes 16,32,48,64,128,256; icns header length 8927 == file size, chunks ic07 (7188) + ic08 (1731); icon.png sha256 074053900a70… unchanged
- sub-task 2 grep → both hook macros and both process names present; makensis not installed, so the script was not compiled
- tauri-bundler 2.10.6 src/bundle/category.rs:68-94 → from_str returns Err unless the input exactly matches a known category; `network` is not in CATEGORY_STRINGS. tauri-cli 2.12.6 src/interface/rust.rs:1541-1545 turns that Err into `invalid category`
- git grep for copyright/authors and git ls-files for LICENSE/NOTICE → no copyright holder recorded in the repo
- python3 -c json.load(tauri.conf.json) → exit 0 (partial config, without category and copyright)
- cargo check --workspace --all-targets → exit 0 with the partial config
- sub-task 3: python3 -c json.load(tauri.conf.json) → exit 0; tauri-bundler 2.10.6 category.rs:346 lists `utility`
- sub-task 4: python3 -c json.load(tauri.bundle.conf.json) → exit 0; git check-ignore -q src-tauri/binaries/conduit-worker-x86_64-unknown-linux-gnu → exit 0
- ## Verify: Python block → PHASE1_ASSETS_OK; git check-ignore → exit 0; cargo check --workspace --all-targets → exit 0 with no src-tauri/binaries directory
