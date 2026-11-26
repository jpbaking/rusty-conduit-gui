# phase-0004 — Update CI/release workflows, validate-release-config.py, docs/TODO.md, and run full verification

- Status: done
- Owner: executor
- Depends on: phase-0003
- Goal: Update CI/release workflows and `scripts/validate-release-config.py` to check out `rusty-conduit-engine` (`v0.2.0`), clear the resolved MITM CA loader items in `docs/TODO.md`, and verify the entire local CI suite passes cleanly.
- Done when: CI/release workflows and `validate-release-config.py` reference `rusty-conduit-engine` (`v0.2.0`), `docs/TODO.md` has the two resolved CA items cleared, and the full verification suite (Rust, Python, Frontend) exits 0.
- Pattern to follow: `.github/workflows/ci.yml:13-17`, `.github/workflows/ci.yml:68-75`, `.github/workflows/release.yml:16-20`, `.github/workflows/release.yml:94-101`, `scripts/validate-release-config.py:221-225`

## Context
- `.github/workflows/ci.yml` and `.github/workflows/release.yml` currently set `UPSTREAM_REPO` to `jpbaking/rusty-conduit-ssh`, `UPSTREAM_REF` to `v1.3.0`, and check out to `path: rusty-conduit-ssh`. Update both to `jpbaking/rusty-conduit-engine`, `v0.2.0`, and `path: rusty-conduit-engine` (including the step name and comment).
- `scripts/validate-release-config.py:223` checks `if not {"rusty-conduit-gui", "rusty-conduit-ssh"} <= paths:` — update `"rusty-conduit-ssh"` to `"rusty-conduit-engine"`.
- Both MITM CA loader items in `docs/TODO.md` (explicit EC curve parameters for P-256/P-384 and clear error/hint for PBES2 HMAC-SHA1 PRF `1.2.840.113549.2.7`) are resolved in `rusty-conduit-engine` `v0.2.0` (`src/mitm/ca.rs`). Clear those resolved items from `docs/TODO.md` (keep `docs/TODO.md` clean with a brief note or empty TODO list).
- Do NOT touch intentional U0 migration/legacy constants (`src-tauri/src/migration.rs`, `src-tauri/windows/nsis-hooks.nsh`, `TRAY_ID` in `linux_ksni.rs` / `tray_tauri.rs`).
- Always use `CARGO_NET_GIT_FETCH_WITH_CLI=true` when running cargo commands.

## Scope
- In: `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `scripts/validate-release-config.py`, `docs/TODO.md`
- Out: `Cargo.toml`, `crates/`, `src-tauri/`, `docs/MASTER-PLAN.md`, `docs/RELEASING.md`

## Sub-tasks
1. [done] Update `.github/workflows/ci.yml` and `.github/workflows/release.yml` (`UPSTREAM_REPO` → `jpbaking/rusty-conduit-engine`, `UPSTREAM_REF` → `v0.2.0`, checkout step name/comment/path → `rusty-conduit-engine`) and update `scripts/validate-release-config.py` line 223 to check `rusty-conduit-engine` — done when: `python3 scripts/validate-release-config.py` prints `RELEASE_CONFIG_OK`.
2. [done] Clear the two resolved MITM CA loader items in `docs/TODO.md` — done when: `docs/TODO.md` no longer lists the two resolved `rusty-conduit-ssh` CA loader TODO checkboxes.
3. [done] Run the complete `## Verify` command (Rust clippy + tests + `secret_leak_scan` + Linux tray check + `check-pure-rust-crypto.py` + `validate-release-config.py` + `smoke-test-bundle.py --self-test` + frontend `npm run check && npm test && npm run build`) and record observed results in `## Evidence` — done when: every check exits 0.

## Verify
```sh
CARGO_NET_GIT_FETCH_WITH_CLI=true cargo clippy --workspace --all-targets -- -D warnings && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test --workspace && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p rusty-conduit-gui --test secret_leak_scan && CARGO_NET_GIT_FETCH_WITH_CLI=true RUSTFLAGS="--cfg conduit_check_tauri_tray" cargo check -p rusty-conduit-gui --tests --features tauri/tray-icon && python3 scripts/check-pure-rust-crypto.py && python3 scripts/validate-release-config.py && python3 scripts/smoke-test-bundle.py --self-test && (cd src-tauri/ui && npm run check && npm test && npm run build)
```

## Escalate when
- `check-pure-rust-crypto.py` or `smoke-test-bundle.py --self-test` or any frontend check fails → stop, set Status: needs-human — reason: report the exact failing check and output

## Log
- (append-only, one line per event)
- sub-task 1: ci.yml/release.yml UPSTREAM_REPO → jpbaking/rusty-conduit-engine, UPSTREAM_REF → v0.2.0, checkout comment/name/path → rusty-conduit-engine; validate-release-config.py:223 → "rusty-conduit-engine"
- sub-task 2: replaced docs/TODO.md with "No open items" plus a note that both MITM CA loader issues are resolved in rusty-conduit-engine v0.2.0
- sub-task 3: ran full ## Verify; every check exited 0

## Evidence
- (append-only: command → observed result)
- `python3 scripts/validate-release-config.py` → RELEASE_CONFIG_OK
- `grep -rn "rusty-conduit-ssh\|v1.3.0" .github scripts/validate-release-config.py docs/TODO.md` → no matches
- `cargo clippy --workspace --all-targets -- -D warnings` → Finished, rc=0
- `cargo test --workspace` → 23 test-result lines, 491 passed, 0 failed, rc=0
- `cargo test -p rusty-conduit-gui --test secret_leak_scan` → 5 passed; 0 failed, rc=0
- `RUSTFLAGS="--cfg conduit_check_tauri_tray" cargo check -p rusty-conduit-gui --tests --features tauri/tray-icon` → Finished, rc=0
- `python3 scripts/check-pure-rust-crypto.py` → PURE_RUST_CRYPTO_OK
- `python3 scripts/smoke-test-bundle.py --self-test` → SMOKE_TEST_SELF_TEST_OK
- `npm run check` → 188 FILES 0 ERRORS 0 WARNINGS; `npm test` → rc=0, 0 cancelled; `npm run build` → built in 2.42s, rc=0
