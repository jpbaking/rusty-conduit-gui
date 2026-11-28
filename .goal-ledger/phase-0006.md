# phase-0006 — Release workflow Rust cache

- Status: done
- Owner: executor
- Depends on: phase-0005
- Goal: Cache the Rust target directory and `~/.cargo/bin` (which holds the pinned `tauri-cli`) in each release `package` matrix job, so `cargo install tauri-cli` and dependency builds stop running cold on all five runners.
- Done when: every command in `## Verify` exits 0.
- Pattern to follow: `.github/workflows/ci.yml:88` (the existing `Swatinem/rust-cache@v2` step in CI; read its `with:` block and copy its style)

## Context
`release.yml` `package` checks the repo out into the `rusty-conduit-gui/` subfolder (`path: rusty-conduit-gui`) and compiles `tauri-cli` from source (`cargo install tauri-cli --version "$TAURI_CLI_VERSION" --locked`) on every matrix runner. `Swatinem/rust-cache@v2` caches `~/.cargo/bin` by default, and `cargo install` of an already-installed version is a fast no-op, so the cache alone removes the rebuild. The planner decided to keep the pinned `cargo install` (no new third-party action). Because the checkout is in a subfolder, the cache step must name it: `workspaces: rusty-conduit-gui -> target`.

## Scope
- In: `.github/workflows/release.yml`
- Out: `.github/workflows/ci.yml`, `src-tauri/tauri.conf.json`, every other file

## Sub-tasks
1. [done] In `.github/workflows/release.yml`, insert this step between the `Install Rust` step (ends with `rustup target add $RUST_TARGETS`) and the `Install Tauri CLI` step, with the same indentation as its neighbours: (block 1 below) — done when: `grep -c 'Swatinem/rust-cache@v2' .github/workflows/release.yml` prints `1` and the step appears after `rustup target add` and before `cargo install tauri-cli` (`grep -n 'rustup target add\|rust-cache\|cargo install tauri-cli' .github/workflows/release.yml` shows them in that order).
   Block 1:
   ```yaml
         - name: Cache Rust builds and the Tauri CLI
           uses: Swatinem/rust-cache@v2
           with:
             workspaces: rusty-conduit-gui -> target
             key: release-${{ matrix.name }}
   ```
2. [done] Validate the YAML: `ruby -ryaml -e 'YAML.load_file(".github/workflows/release.yml")'` — done when: the command exits 0.

## Verify
```sh
test "$(grep -c 'Swatinem/rust-cache@v2' .github/workflows/release.yml)" = 1
grep -n 'rustup target add\|rust-cache\|cargo install tauri-cli' .github/workflows/release.yml
ruby -ryaml -e 'YAML.load_file(".github/workflows/release.yml")'
uv run -q --no-project --with pyyaml python3 scripts/validate-release-config.py
test -z "$(git diff --name-only | grep -vx '.github/workflows/release.yml' | grep -v '^.goal-ledger/')"
```

## Escalate when
- `validate-release-config.py` fails after the edit → stop, set Status: needs-human — reason: paste its output.
- The YAML parse fails → stop, set Status: needs-human — reason: paste the parser error.

## Log
- (append-only, one line per event)
- planner: validator command switched to `uv run -q --no-project --with pyyaml python3 scripts/validate-release-config.py` (no PyYAML on this Mac; see phase-0001 Context)
- executor: sub-task 1 — inserted `Swatinem/rust-cache@v2` step between `Install Rust` and `Install Tauri CLI` in `.github/workflows/release.yml`
- executor: sub-task 2 — validated `.github/workflows/release.yml` with Ruby YAML parser
- executor: phase-0006 Verify passed; closing phase

## Evidence
- (append-only: command → observed result)
- `grep -c 'Swatinem/rust-cache@v2' .github/workflows/release.yml` && `grep -n 'rustup target add\|rust-cache\|cargo install tauri-cli' .github/workflows/release.yml` → exit 0; count `1`; lines 140 (`rustup target add`), 143 (`Swatinem/rust-cache@v2`), 149 (`cargo install tauri-cli`)
- `ruby -ryaml -e 'YAML.load_file(".github/workflows/release.yml")'` → exit 0 (valid YAML)
- `## Verify` (all 5 checks: grep count = 1, grep order 140/143/149, ruby YAML load, `uv run -q --no-project --with pyyaml python3 scripts/validate-release-config.py`, git diff scope check) → exit 0; `RELEASE_CONFIG_OK`
