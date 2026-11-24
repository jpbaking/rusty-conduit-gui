# phase-0004 — CLI --help/--version, README.md, LICENSE & workspace polish

- Status: done
- Owner: executor
- Depends on: phase-0003
- Goal: Add `--help`/`--version` CLI flags before GTK init, remove the duplicate comment in `Cargo.toml`, add BSD-3-Clause `LICENSE`, and write `README.md`.
- Done when: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && (cd src-tauri/ui && npm run check && npm test && npm run build) && python3 scripts/check-pure-rust-crypto.py && python3 scripts/validate-release-config.py` exits 0 with `LICENSE`, `README.md`, and `--help`/`--version` tests passing.
- Pattern to follow: `src-tauri/src/platform.rs:8-63` (`CliFlags`), `../rusty-conduit-ssh/LICENSE` (BSD-3-Clause text), and `docs/RELEASING.md` (concise, accurate documentation style).

## Context
Every crate in the workspace declares `license = "BSD-3-Clause"` and `src-tauri/tauri.conf.json` has `copyright: "Copyright (c) 2026, Joseph Baking"`, matching `../rusty-conduit-ssh/LICENSE`, but the repository root currently has no `LICENSE` or `README.md`.
Also `src-tauri/src/platform.rs` handles `--tray`, `--show`, and `--safe-rendering`, but running `rusty-conduit-ssh-gui --help` or `--version` currently launches the GUI instead of printing usage/version and exiting 0.
Finally, root `Cargo.toml` has a duplicate comment line on lines 29–30 (`# conduit-vault: envelope encryption, key management, and keyring.`).

## Scope
- In: `src-tauri/src/platform.rs`, `src-tauri/src/lib.rs`, `Cargo.toml`, `LICENSE`, `README.md`
- Out: `docs/MASTER-PLAN.md`, `../rusty-conduit-ssh`, `crates/**`, `src-tauri/ui/**`, `.github/**`

## Sub-tasks
1. [done] Extend `CliFlags` in `src-tauri/src/platform.rs` with `help: bool` (`--help` / `-h`) and `version: bool` (`--version` / `-V`), plus pure formatting helpers `help_text() -> String` and `version_text() -> String` (using `env!("CARGO_PKG_NAME")` and `env!("CARGO_PKG_VERSION")`). In `src-tauri/src/lib.rs::run()`, check `flags.help` and `flags.version` immediately after `CliFlags::from_env()` (before `apply_rendering_env` and before Tauri/GTK init): print the text to stdout and return cleanly. Add unit tests in `src-tauri/src/platform.rs` for `-h`, `--help`, `-V`, `--version`, `help_text()`, and `version_text()`. — done when: `cargo test -p rusty-conduit-ssh-gui platform` passes.
2. [done] Remove the duplicate `# conduit-vault: ...` comment line in `Cargo.toml` (lines 29–30) and add `LICENSE` at the repository root with the exact BSD-3-Clause license text (`Copyright (c) 2026, Joseph Baking`, matching `../rusty-conduit-ssh/LICENSE`). — done when: `LICENSE` exists and `cargo metadata --no-deps >/dev/null` exits 0.
3. [done] Write `README.md` at the repository root covering: what Rusty Conduit SSH GUI is (desktop tray + Manage Window for `rusty-conduit-ssh`), key features (pure-Rust `russh` default engine + opt-in isolated OpenSSH engine, visual multi-hop jump chain, hybrid envelope-encrypted vault, embedded scoped agent, zero `~/.ssh` dependence, cross-platform tray including `ksni` on Linux/XFCE/Wayland), workspace crate layout, prerequisites & sibling-repo layout (`../rusty-conduit-ssh`), development & verification commands (`cargo test`, `clippy`, `npm run check`, `npm test`, `npm run build`), CLI flags (`--tray`, `--show`, `--safe-rendering`, `--help`, `--version`), and links to `docs/MASTER-PLAN.md` and `docs/RELEASING.md`. — done when: `README.md` exists and accurately matches the current repo structure and commands.
4. [done] Run the full workspace verification command from `## Verify`. — done when: all commands in `## Verify` exit 0.

## Verify
```sh
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && (cd src-tauri/ui && npm run check && npm test && npm run build) && python3 scripts/check-pure-rust-crypto.py && python3 scripts/validate-release-config.py
```

## Escalate when
- Any pre-existing test or verification script fails for reasons unrelated to this phase → stop, set Status: needs-human — reason: <exact failure>

## Log
- (append-only, one line per event)
- sub-task 1: added help/version to CliFlags (-h/--help, -V/--version), help_text()/version_text(), early print-and-return in lib.rs::run() before apply_rendering_env; 4 new tests; existing struct-literal test given ..CliFlags::default()
- sub-task 2: removed duplicate conduit-vault comment (Cargo.toml line 30); copied LICENSE byte-for-byte from ../rusty-conduit-ssh/LICENSE
- sub-task 3: wrote README.md (features, crate layout, prerequisites, sibling layout, dev/verify commands, CLI flags, doc links, license)
- sub-task 4: ran full ## Verify command; exit 0

## Evidence
- (append-only: command → observed result)
- `cargo test -p rusty-conduit-ssh-gui platform` → 16 passed; 0 failed (incl. platform_parses_help_flags, platform_parses_version_flags, platform_help_text_lists_every_flag, platform_version_text_names_package_and_version)
- `cargo run -q -p rusty-conduit-ssh-gui -- --version` → "rusty-conduit-ssh-gui 0.1.0", exit 0; `-- -h` → usage text listing all 5 flags, exit 0, no window
- `cmp LICENSE ../rusty-conduit-ssh/LICENSE` → identical; `cargo metadata --no-deps >/dev/null` → exit 0
- README.md checked against repo: crates/* dirs, conduit-worker bin in crates/conduit-openssh/Cargo.toml:9, wake.rs in conduit-runtime, linux_ksni.rs in conduit-tray, package.json scripts check/test/build, Node 22 in .github/workflows/ci.yml:36
- `## Verify` full command → exit 0: cargo test --workspace all ok (gui lib 112 passed), clippy -D warnings clean, npm run check ok, npm test 55/55 pass, vite build ok (dist unchanged), PURE_RUST_CRYPTO_OK, RELEASE_CONFIG_OK
