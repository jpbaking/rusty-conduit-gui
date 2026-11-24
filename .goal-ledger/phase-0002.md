# phase-0002 — Automated secret-leak scan tests & packaging/smoke-test scripts

- Status: done
- Owner: executor
- Depends on: phase-0001
- Goal: Add an automated secret-leak scan integration test suite covering logs, exports, and OpenSSH files, plus cross-platform Python scripts for sidecar staging, bundle smoke testing, pure-Rust crypto checking, and release config validation.
- Done when: `cargo test -p rusty-conduit-ssh-gui --test secret_leak_scan`, `cargo clippy --workspace --all-targets -- -D warnings`, `python3 scripts/check-pure-rust-crypto.py`, and `python3 scripts/smoke-test-bundle.py --self-test` all exit 0.
- Pattern to follow: `src-tauri/src/commands.rs:567-616` for sentinel secret fragment scanning, and `crates/conduit-openssh/tests/openssh_loopback.rs:1-80` for temp dirs and SSH config helpers.

## Context
- Master Plan Section 9 Phase 5 requires automated secret-leak scanning of logs and exports, plus installer smoke tests and pure-Rust crypto enforcement.
- `src-tauri/src/commands.rs` already tests IPC responses; `src-tauri/tests/secret_leak_scan.rs` must complement it by scanning: (1) runtime diagnostic/access log lines (`conduit_runtime::SessionManager` / `AppController` log ring buffers and auth/host-key error states), (2) plain config exports (zero sentinel secrets) and encrypted config exports (zero plaintext sentinel secrets in the file bytes), and (3) `conduit_openssh::write_config` / `write_known_hosts` output files (zero passwords or private key material).
- All scripts in `scripts/` must use Python 3 standard library only (except `validate-release-config.py` may use `yaml` if installed and fall back or require `PyYAML` cleanly — `PyYAML` is installed on this host and standard in GitHub Actions) so they run identically on Linux, macOS, and Windows without Bash or PowerShell divergence. In `validate-release-config.py`, validate PNG dimensions (IHDR bytes 16..24), ICO header (`\x00\x00\x01\x00`), and ICNS magic/length using stdlib `struct` so Pillow (`PIL`) is not required on CI runners.
- `scripts/stage-worker.py` must support `--target <triple>` (single target) and `--universal-macos` (builds `aarch64-apple-darwin` + `x86_64-apple-darwin` and runs `lipo -create` into `src-tauri/binaries/conduit-worker-universal-apple-darwin`), plus `--profile <debug|release>` (default `release`).
- `scripts/smoke-test-bundle.py` must support `--self-test` (creates synthetic test fixtures in a temp dir to unit-test its own `.deb`/directory/checksum checks) and `--bundle-dir <path> --platform <linux|macos|windows>` to verify real artifacts in CI (checking main binary + `conduit-worker` presence in `.deb` via `dpkg-deb -c`, `.rpm` via `rpm -qlp`, `.AppImage` non-empty executable, macOS `.app` Mach-O slices via `lipo -info` + `.dmg` non-empty, Windows NSIS `.exe` / `.msi` non-empty).

## Scope
- In: `src-tauri/tests/secret_leak_scan.rs`, `scripts/stage-worker.py`, `scripts/smoke-test-bundle.py`, `scripts/check-pure-rust-crypto.py`, `scripts/validate-release-config.py`
- Out: `src-tauri/src/**`, `src-tauri/ui/**`, `crates/**`, `.github/**`, `docs/**`

## Sub-tasks
1. [done] Create `src-tauri/tests/secret_leak_scan.rs` testing sentinel passwords, private keys (PEM/OpenSSH body lines), key passphrases, and MITM CA passphrases across `AppController` plain exports, encrypted exports, session diagnostic logs / error messages, and `conduit_openssh` generated `-F` config + `known_hosts` files — done when: `cargo test -p rusty-conduit-ssh-gui --test secret_leak_scan` exits 0 with at least 4 passing tests.
2. [done] Create `scripts/check-pure-rust-crypto.py` running `cargo tree --workspace --edges normal` and failing non-zero if `openssl-sys` or `aws-lc-sys` appears anywhere in the dependency graph (printing `PURE_RUST_CRYPTO_OK` on pass) — done when: `python3 scripts/check-pure-rust-crypto.py` exits 0.
3. [done] Create `scripts/stage-worker.py` supporting `--target <triple>`, `--universal-macos`, `--profile <debug|release>`, and `--dry-run`, copying the built `conduit-worker[.exe]` into `src-tauri/binaries/conduit-worker-<triple>[.exe]` — done when: `python3 scripts/stage-worker.py --dry-run` exits 0 and prints the resolved target triple and destination path.
4. [done] Create `scripts/smoke-test-bundle.py` supporting `--bundle-dir <path> --platform <linux|macos|windows>` and `--self-test`, verifying packaged artifacts contain both `rusty-conduit-ssh-gui` and `conduit-worker` (and macOS universal slices / non-empty installers) — done when: `python3 scripts/smoke-test-bundle.py --self-test` exits 0.
5. [done] Create `scripts/validate-release-config.py` validating `src-tauri/tauri.conf.json`, `src-tauri/tauri.bundle.conf.json`, `src-tauri/windows/nsis-hooks.nsh`, all icon files in `src-tauri/icons/`, version parity across `src-tauri/Cargo.toml`, `src-tauri/tauri.conf.json`, and `src-tauri/ui/package.json`, and (when `.github/workflows/*.yml` exist) YAML syntax + required CI/release jobs — done when: `python3 scripts/validate-release-config.py` exits 0.

## Verify
```sh
cargo test -p rusty-conduit-ssh-gui --test secret_leak_scan
cargo clippy --workspace --all-targets -- -D warnings
python3 scripts/check-pure-rust-crypto.py
python3 scripts/stage-worker.py --dry-run
python3 scripts/smoke-test-bundle.py --self-test
python3 scripts/validate-release-config.py
```

## Escalate when
- `AppController` or `conduit_openssh` lacks a public API needed by `src-tauri/tests/secret_leak_scan.rs` → stop, set `Status: needs-human — reason: <missing public symbol and crate>`.
- `cargo tree` reports `openssl-sys` or `aws-lc-sys` → stop, set `Status: needs-human — reason: <offending crate chain>`.

## Log
- (append-only, one line per event)
- sub-task 1: added src-tauri/tests/secret_leak_scan.rs with 5 tests (plain export, encrypted export including decoded payload bytes, session logs and auth/host-key/MITM failure states, rejected-input errors, generated OpenSSH files)
- sub-task 2: added scripts/check-pure-rust-crypto.py; uses --target all so Windows and macOS dependencies are also checked from Linux
- sub-task 3: added scripts/stage-worker.py; --universal-macos also stages the two thin sidecars beside the universal binary
- sub-task 4: added scripts/smoke-test-bundle.py with fixture self-test, including a real .deb built by dpkg-deb
- sub-task 5: added scripts/validate-release-config.py; workflow job check requires only the job names phase-0003 already fixes (ci: frontend; release: verify, release)

## Evidence
- (append-only: command → observed result)
- cargo test -p rusty-conduit-ssh-gui --test secret_leak_scan → exit 0, 5 passed, 0 failed
- cargo clippy --workspace --all-targets -- -D warnings → exit 0
- python3 scripts/check-pure-rust-crypto.py → exit 0, PURE_RUST_CRYPTO_OK; with a fake cargo reporting openssl-sys → exit 1
- python3 scripts/stage-worker.py --dry-run → exit 0, target x86_64-unknown-linux-gnu, destination src-tauri/binaries/conduit-worker-x86_64-unknown-linux-gnu
- python3 scripts/smoke-test-bundle.py --self-test → exit 0, SMOKE_TEST_SELF_TEST_OK
- python3 scripts/validate-release-config.py → exit 0, RELEASE_CONFIG_OK; on a scratch copy with bad version, truncated icns and ci.yml lacking frontend → exit 1 with all 3 errors
- not run: real stage-worker builds, lipo, rpm, and real bundle checks (no lipo or rpm on this Linux host, no bundles built in this phase)
