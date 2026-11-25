# phase-0003 — Update NSIS hooks, packaging scripts, CI/Release workflows, and docs

- Status: done
- Owner: planner
- Depends on: phase-0001
- Goal: Update installer hooks, bundle validation/smoke-test scripts, GitHub Actions CI & Release workflows, and user/release documentation to `rusty-conduit-gui` / `Rusty Conduit GUI` (keeping `UPSTREAM_REF: v1.3.0` for U0).
- Done when: `python3 scripts/validate-release-config.py`, `python3 scripts/smoke-test-bundle.py --self-test`, and `python3 scripts/check-pure-rust-crypto.py` all exit 0.
- Pattern to follow: `scripts/validate-release-config.py:15-42` and `.github/workflows/ci.yml:13-118`

## Context
In U0, `ci.yml` and `release.yml` checkout this repository under `rusty-conduit-gui` and keep `UPSTREAM_REPO` = `jpbaking/rusty-conduit-ssh` with `UPSTREAM_REF` = `v1.3.0` (U1 switches to `rusty-conduit-engine`). `nsis-hooks.nsh` should stop both `rusty-conduit-gui.exe` and the legacy `rusty-conduit-ssh-gui.exe` (plus `conduit-worker.exe`) so upgrades cleanly stop an older running instance.

## Scope
- In: `src-tauri/windows/nsis-hooks.nsh`, `scripts/smoke-test-bundle.py`, `scripts/validate-release-config.py`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `README.md`, `docs/RELEASING.md`
- Out: `docs/MASTER-PLAN.md`, `docs/TODO.md`, Rust source code, UI source code

## Sub-tasks
1. [done] Update `src-tauri/windows/nsis-hooks.nsh` (stop `rusty-conduit-gui.exe`, `rusty-conduit-ssh-gui.exe`, `conduit-worker.exe`) and `scripts/smoke-test-bundle.py` (`MAIN = "rusty-conduit-gui"`) — done when: `python3 scripts/smoke-test-bundle.py --self-test` prints `SMOKE_TEST_SELF_TEST_OK`
2. [done] Update `.github/workflows/ci.yml`, `.github/workflows/release.yml`, and `scripts/validate-release-config.py` for `rusty-conduit-gui` and `UPSTREAM_REF` `v1.3.0` — done when: `python3 scripts/validate-release-config.py` prints `RELEASE_CONFIG_OK`
3. [done] Update `README.md` and `docs/RELEASING.md` to `Rusty Conduit GUI` / `rusty-conduit-gui` — done when: `grep -nE 'rusty-conduit-ssh-gui|Rusty Conduit \(SSH\)' README.md docs/RELEASING.md` returns only intentional upgrade/migration notes (or nothing)

## Verify
```sh
python3 scripts/validate-release-config.py && python3 scripts/smoke-test-bundle.py --self-test && python3 scripts/check-pure-rust-crypto.py
```

## Escalate when
- `PyYAML` is unavailable in the local Python environment and blocks `validate-release-config.py` → stop, set `Status: needs-human — reason: missing PyYAML`

## Log
- (append-only, one line per event)
- began phase-0003
- sub-tasks 1–3 done & verified: updated `nsis-hooks.nsh`, `smoke-test-bundle.py`, `validate-release-config.py`, `ci.yml`, `release.yml`, `README.md`, and `docs/RELEASING.md`; all 3 Python verification scripts passed

## Evidence
- (append-only: command → observed result)
- `python3 scripts/validate-release-config.py` → `RELEASE_CONFIG_OK`
- `python3 scripts/smoke-test-bundle.py --self-test` → `SMOKE_TEST_SELF_TEST_OK`
- `python3 scripts/check-pure-rust-crypto.py` → `PURE_RUST_CRYPTO_OK`
