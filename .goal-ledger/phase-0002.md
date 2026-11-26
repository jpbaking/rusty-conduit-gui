# phase-0002 — Update release validation/smoke scripts, CI/release workflows, RELEASING.md, and README.md for v0.2.0

- Status: done
- Owner: executor
- Depends on: phase-0001
- Goal: Enforce the new §3.3 `.deb`/`.rpm`/NSIS upgrade-path rules in `scripts/validate-release-config.py` and `scripts/smoke-test-bundle.py`, align `.github/workflows/{ci,release}.yml` with the current git-tag `rusty-conduit-engine` `v0.2.0` dependency, and update `docs/RELEASING.md` and `README.md` for `v0.2.0` and the unified Rusty Conduit GUI.
- Done when: `validate-release-config.py` enforces `.deb`/`.rpm` and NSIS upgrade-path rules, `smoke-test-bundle.py --self-test` verifies `.deb` `Replaces`/`Conflicts` and `.rpm` `Obsoletes`/`Conflicts`, workflows/docs/README are accurate for `v0.2.0`, and `## Verify` exits 0.
- Pattern to follow: `scripts/validate-release-config.py`, `scripts/smoke-test-bundle.py`, `docs/RELEASING.md`, `README.md`

## Context
- **`scripts/validate-release-config.py`**:
  - Enforce that `src-tauri/tauri.conf.json` configures `bundle.linux.deb.replaces` and `bundle.linux.deb.conflicts` containing `rusty-conduit-ssh-gui`, and `bundle.linux.rpm.obsoletes` and `bundle.linux.rpm.conflicts` containing `rusty-conduit-ssh-gui` (matching whatever exact keys were landed in `phase-0001`).
  - Enforce that `src-tauri/windows/nsis-hooks.nsh` checks for legacy `Rusty Conduit (SSH)` uninstall entry in `NSIS_HOOK_PREINSTALL` (in addition to stopping `rusty-conduit-gui.exe`, `rusty-conduit-ssh-gui.exe`, `conduit-worker.exe`).
- **`scripts/smoke-test-bundle.py`**:
  - Extend `.deb` inspection (`dpkg-deb -f` / control metadata) to assert `Replaces` and `Conflicts` include `rusty-conduit-ssh-gui`.
  - Extend `.rpm` inspection (`rpm -qp` / header check) to assert `Obsoletes` and `Conflicts` include `rusty-conduit-ssh-gui`.
  - Update `--self-test` to cover both passing and failing cases for the new `.deb` and `.rpm` upgrade-path checks.
- **`.github/workflows/ci.yml` & `.github/workflows/release.yml`**:
  - Audit and clean up stale comments/steps referencing `../rusty-conduit-engine` relative path now that `Cargo.toml` uses git tag `v0.2.0` (keep runner matrices, caching, artifact names, and signing logic intact; ensure git-tag fetching works cleanly in CI).
- **`docs/RELEASING.md`**:
  - Replace stale `rusty-conduit-ssh` / `v1.3.0` / sibling-directory instructions with the current `rusty-conduit-engine` `v0.2.0` git-tag setup.
  - Document the `v0.1.0` (`rusty-conduit-ssh-gui`) → `v0.2.0` (`rusty-conduit-gui`) upgrade path (Linux `.deb` Replaces/Conflicts, `.rpm` Obsoletes/Conflicts, Windows NSIS legacy uninstall offer, macOS drop-in replacement, automatic first-launch config/vault migration).
  - Update the §7 smoke-test / release checklist for unified GUI features (Proxies + Tunnels, Direct / Forward / Auto Switch / PAC / External TOML, AirSwitch/ZeroOmega `.bak` & 3-CLI `config.toml` import/export, backup format v2 & v1 import migration, tray PROXIES + TUNNELS sections).
- **`README.md`**:
  - Update description, Features, Workspace layout, and Prerequisites to reflect the unified Rusty Conduit GUI and `rusty-conduit-engine` `v0.2.0` git dependency (remove the stale `../rusty-conduit-ssh` sibling-repo note).

## Scope
- In: `scripts/validate-release-config.py`, `scripts/smoke-test-bundle.py`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `docs/RELEASING.md`, `README.md`
- Out: `src-tauri/`, `crates/`, `Cargo.toml`, `Cargo.lock`

## Sub-tasks
1. [done] Update `scripts/validate-release-config.py` to enforce the `.deb`/`.rpm` replacement metadata and NSIS legacy uninstall check — done when: `python3 scripts/validate-release-config.py` passes and would fail if those entries were removed.
2. [done] Update `scripts/smoke-test-bundle.py` (including `--self-test`) to verify `.deb` `Replaces`/`Conflicts` and `.rpm` `Obsoletes`/`Conflicts` for `rusty-conduit-ssh-gui` — done when: `python3 scripts/smoke-test-bundle.py --self-test` passes with passing and failing assertions for both.
3. [done] Audit and update `.github/workflows/ci.yml` and `.github/workflows/release.yml` to remove stale sibling-path assumptions while keeping CI/release jobs intact — done when: workflows are valid YAML with no stale `../rusty-conduit-engine` or `rusty-conduit-ssh` sibling-checkout assumptions.
4. [done] Update `docs/RELEASING.md` and `README.md` for `v0.2.0`, `rusty-conduit-engine` `v0.2.0`, the §3.3 upgrade path, and the unified GUI feature set — done when: no stale `v1.3.0` / sibling-path notes remain and §7 checklist covers unified GUI features.
5. [done] Run `## Verify` and record observed results in `## Evidence` — done when: `## Verify` exits 0.

## Verify
```sh
python3 scripts/validate-release-config.py && python3 scripts/smoke-test-bundle.py --self-test && python3 scripts/check-pure-rust-crypto.py
```

## Escalate when
- `scripts/validate-release-config.py` or `scripts/smoke-test-bundle.py` reveals a packaging mismatch in `src-tauri/tauri.conf.json` or `src-tauri/windows/nsis-hooks.nsh` that requires editing `phase-0001` files → stop, set Status: needs-human — reason: describe the mismatch.

## Log
- (append-only, one line per event)
- sub-task 1: validate-release-config.py now requires `rusty-conduit-ssh-gui` in deb replaces/conflicts and rpm obsoletes/conflicts, and checks the expanded NSIS_HOOK_PREINSTALL (macros, arguments, !defines inlined) for taskkill of all three exes plus the legacy `Rusty Conduit (SSH)` UninstallString/MessageBox/ExecWait offer.
- sub-task 2: smoke-test-bundle.py checks `.deb` Replaces/Conflicts via `dpkg-deb -f` and `.rpm` Obsoletes/Conflicts via `rpm -qp --obsoletes/--conflicts`; --self-test covers parser pass/fail and lookalike cases plus real .deb fixtures missing each field. No real .rpm built (no rpm/rpmbuild locally).
- sub-task 3: removed the sibling `rusty-conduit-engine` checkout step and unused UPSTREAM_REPO/UPSTREAM_REF env from ci.yml and release.yml; added `CARGO_NET_GIT_FETCH_WITH_CLI: "true"`; matrices, caching, artifact names, signing unchanged. validate-release-config.py's old "must check out both sibling repositories" rule (which would now fail) replaced by a "must not check out a sibling repository" rule for ci rust-and-e2e and release package.
- sub-task 4: RELEASING.md §2 rewritten for the engine git tag v0.2.0; new §8 documents the v0.1.0 → v0.2.0 upgrade path (§1–§7 numbering kept so the checklist stays §7); §7 checklist extended for unified GUI features and upgrade checks. README description/Features/Workspace layout/Prerequisites updated; sibling-repo note removed.
- sub-task 5: ran ## Verify → exit 0.

## Evidence
- (append-only: command → observed result)
- `python3 scripts/validate-release-config.py` → `RELEASE_CONFIG_OK` (rules at scripts/validate-release-config.py:43, :90, :130, :147, :286)
- in-memory negative test (import module, delete each of deb.replaces/deb.conflicts/rpm.obsoletes/rpm.conflicts; drop `!insertmacro CONDUIT_OFFER_LEGACY_UNINSTALL`; rename `rusty-conduit-ssh-gui.exe`) → each produced the matching error (e.g. `bundle.linux.rpm.obsoletes must include rusty-conduit-ssh-gui`, `NSIS_HOOK_PREINSTALL must use ...Uninstall\Rusty Conduit (SSH)`); unmodified files → no errors
- in-memory negative test (insert a `repository: x/rusty-conduit-engine` checkout into ci rust-and-e2e) → `ci.yml: job rust-and-e2e must not check out a sibling repository`
- `python3 scripts/smoke-test-bundle.py --self-test` → `SMOKE_TEST_SELF_TEST_OK` (scripts/smoke-test-bundle.py:98, :110, :255, :293)
- real .deb fixture built without Conflicts / without Replaces / with neither → `xConflicts.deb Replaces does not include rusty-conduit-ssh-gui`, `xReplaces.deb Conflicts does not include rusty-conduit-ssh-gui`, `x.deb Replaces does not include rusty-conduit-ssh-gui`
- `python3 -c "import yaml; ..."` on ci.yml and release.yml → `YAML_OK`; `grep -rn "UPSTREAM\|rusty-conduit-ssh\|\.\./" .github/workflows/` → only the new comment line naming rusty-conduit-engine's git tag
- `grep -n "v1.3.0\|parent/\|\.\./rusty\|relative path" README.md docs/RELEASING.md` → no matches
- ## Verify `python3 scripts/validate-release-config.py && python3 scripts/smoke-test-bundle.py --self-test && python3 scripts/check-pure-rust-crypto.py` → `RELEASE_CONFIG_OK`, `SMOKE_TEST_SELF_TEST_OK`, `PURE_RUST_CRYPTO_OK`, exit 0
