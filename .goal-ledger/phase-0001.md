# phase-0001 — Add AirSwitch/ZeroOmega/SwitchyOmega .bak importer and 3-CLI config.toml import/export in conduit-core

- Status: done
- Owner: executor
- Depends on: none
- Goal: Implement AirSwitch / ZeroOmega / SwitchyOmega `.bak` import (`crates/conduit-core/src/airswitch_import.rs`) and 3-CLI `config.toml` import & export (`crates/conduit-core/src/toml_io.rs`) in `conduit-core`, extracting inline passwords into zeroized `ExtractedSecret` items (never stored plaintext in `Proxy`) and emitting `password_env` placeholders on export.
- Done when: `cargo test -p conduit-core` and `cargo clippy -p conduit-core --all-targets -- -D warnings` pass with unit tests covering AirSwitch `.bak` import, all 3 CLI TOML formats (import + export + round-trip), warning collection, and secret extraction/redaction.
- Pattern to follow: `crates/conduit-core/src/v2_model.rs`, `crates/conduit-core/src/v2_mapping.rs`, `crates/conduit-core/src/v2_validate.rs`, `docs/MASTER-PLAN.md:303-311`

## Context
- Disk constraint: ALWAYS pass `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true` on every `cargo` command.
- `toml` is already in `Cargo.lock` (check version in `Cargo.lock` and pin a compatible `toml` entry in `[workspace.dependencies]` in `Cargo.toml` and `crates/conduit-core/Cargo.toml` so no network fetch is needed).
- **`airswitch_import.rs`** (AirSwitch / ZeroOmega / SwitchyOmega `.bak` JSON):
  - `.bak` files are JSON objects where profile entries are keyed by `+<ProfileName>` with `profileType` (`FixedProfile`, `SwitchProfile`, `PacProfile`, `RuleListProfile`, `VirtualProfile`, etc.), `fallbackProxy` (`scheme`, `host`, `port`, optional `auth: { username, password }`), `bypassList` (`[{ conditionType, pattern }]`), `color`, `defaultProfileName`, and `rules` (`[{ condition: { conditionType, pattern, ... }, profileName }]`).
  - Map `FixedProfile` → `UpstreamProfile` (`http`, `https`, `socks5`, `socks4`/`socks4a`), preserving color, username, bypass patterns (`BypassCondition` / `BypassList`), and extracting any non-empty `password` into `ExtractedSecret { profile_name, password: Zeroizing<String> }` while leaving `profile.password = None` (the controller in phase-0002 will store extracted passwords in the Vault and attach `UpstreamPasswordSource::Vault(ref)`).
  - Map `SwitchProfile` → `RoutingTablesConfig` (`default` from `defaultProfileName`, `rules` mapped from `HostWildcardCondition`, `HostRegexCondition`, `UrlWildcardCondition`, `UrlRegexCondition`, `KeywordCondition`, `IpCondition`, `HostLevelsCondition`, `BypassCondition`, `TimeCondition`, `WeekdayCondition`; built-ins `direct` / `system` → `"direct"` with warning for `system`).
  - Browser-only / unsupported items (`PacProfile`, `RuleListProfile`, `VirtualProfile`, unsupported condition types, `system` profile) are skipped and listed in `warnings: Vec<String>` — never silently dropped.
  - Export `import_airswitch_bak(json: &str, name: Option<&str>) -> Result<AirSwitchImport, ImportError>` where `AirSwitchImport` holds `proxy: Proxy`, `extracted_secrets: Vec<ExtractedSecret>`, `warnings: Vec<String>`, `profile_count: usize`, `rule_count: usize`.
- **`toml_io.rs`** (3-CLI `config.toml` per `docs/MASTER-PLAN.md` §9.3):
  - Define `CliTomlFormat { RustyConduit, RustyConduitSsh, RustyConduitSwitch }` (plus `detect_cli_toml_format(toml_str: &str) -> CliTomlFormat`).
  - **`rusty-conduit` `config.toml`**:
    - Import → `Proxy` (direct, no rules; listeners, network, filter, mitm, logging mapped).
    - Export → allowed only for Proxies with no rules and default routing only to `"direct"` (otherwise return a clear `TomlExportError` explaining why and suggesting `rusty-conduit-switch`).
  - **`rusty-conduit-ssh` `config.toml`**:
    - Import → `Tunnel` (with placeholder hop from `destination` / `ssh` target + reverse/port_forwards/keepalive/logging, plus a `notes: Vec<String>` warning that `~/.ssh/config` aliases and auth must be completed by hand) + `Option<Proxy>` (when forward listeners are enabled, routing default to a `tunnel` profile referencing that `Tunnel`).
    - Export → allowed for Proxies routing only to a single `tunnel` profile (no rules); writes the target hop's `user@host:port` as destination + listeners/filter/mitm/reverse/port_forwards/keepalive/logging, and returns `notes: Vec<String>` listing vault keys, passwords, and jump hosts as `~/.ssh/config` setup notes (NEVER writes secrets).
  - **`rusty-conduit-switch` `config.toml`**:
    - Import → `Proxy` + `extracted_secrets: Vec<ExtractedSecret>` (any inline `password` in `[profiles.<name>]` is extracted into `ExtractedSecret`, NEVER left plaintext in `Proxy`, while `password_env` / `password_file` are preserved as `UpstreamPasswordSource::Env` / `File`) + `warnings: Vec<String>`.
    - Export → any `Proxy`; `UpstreamKind::Tunnel` profiles are exported as commented `# socks5` placeholder blocks with explanatory notes, and `UpstreamPasswordSource::Vault(_)` is exported as `password_env = "CONDUIT_UPSTREAM_<PROFILE_UPPER>_PASSWORD"` (NEVER plaintext secrets).
  - Re-export all public types & functions from `crates/conduit-core/src/lib.rs`.

## Scope
- In: `Cargo.toml`, `Cargo.lock`, `crates/conduit-core/Cargo.toml`, `crates/conduit-core/src/lib.rs`, `crates/conduit-core/src/airswitch_import.rs` (create), `crates/conduit-core/src/toml_io.rs` (create)
- Out: `crates/conduit-vault/`, `crates/conduit-runtime/`, `crates/conduit-tray/`, `src-tauri/`

## Sub-tasks
1. [done] Add `toml` workspace dependency (matching existing `Cargo.lock` version) to `Cargo.toml` and `crates/conduit-core/Cargo.toml` — done when: `cargo check -p conduit-core` passes offline/without breaking `check-pure-rust-crypto.py`.
2. [done] Implement `crates/conduit-core/src/airswitch_import.rs` with full `.bak` parsing, profile/rule mapping, zeroized `ExtractedSecret` extraction, browser-only warning collection, and unit tests — done when: `cargo test -p conduit-core airswitch` passes.
3. [done] Implement `crates/conduit-core/src/toml_io.rs` for `rusty-conduit`, `rusty-conduit-ssh`, and `rusty-conduit-switch` import/export (including format detection, `password_env` placeholders, commented `tunnel` placeholders, setup notes, and unit tests), and re-export from `crates/conduit-core/src/lib.rs` — done when: `cargo test -p conduit-core toml_io` passes.
4. [done] Run `## Verify` and record observed results in `## Evidence` — done when: `## Verify` exits 0.
5. [done] Fix-up: box the `CliTomlImport` variants to clear clippy `large_enum_variant` (`-D warnings`) reported by the first `## Verify` run — done when: `## Verify` exits 0.

## Verify
```sh
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p conduit-core && CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo clippy -p conduit-core --all-targets -- -D warnings && python3 scripts/check-pure-rust-crypto.py
```

## Escalate when
- `Cargo.lock` does not contain a `toml` crate version usable with `serde` or adding `toml` trips `scripts/check-pure-rust-crypto.py` → stop, set Status: needs-human — reason: report the exact Cargo/crypto-check output

## Log
- (append-only, one line per event)
- sub-task 1: added `toml = "1.2"` to `[workspace.dependencies]` (matches locked `toml 1.2.2+spec-1.1.0`, already in the registry cache) and `toml = { workspace = true }` to conduit-core; Cargo.lock gained only the conduit-core → toml 1.2.2 edge
- sub-task 2: created `crates/conduit-core/src/airswitch_import.rs` (`import_airswitch_bak`, `AirSwitchImport`, `ExtractedSecret` with redacted Debug + `Zeroizing<String>`, `ImportError`), modelled on `rusty-conduit-switch/src/import/airswitch.rs`; `name` selects the SwitchProfile to import (like the switch CLI `--profile`); re-exported from lib.rs
- sub-task 3: created `crates/conduit-core/src/toml_io.rs` (file shapes mirror each CLI's `FileConfig` with `deny_unknown_fields`, read from the sibling CLI repos); `CliTomlFormat` + `detect_cli_toml_format`, per-CLI import/export fns, `import_cli_toml` / `export_cli_toml` dispatch, `upstream_password_env_var`, `TomlExport { toml, notes }`; re-exported from lib.rs
- sub-task 3 note: the real `rusty-conduit-ssh` config.toml has `[ssh] target` (no `destination` key) and no port-forward keys, so export writes `target = "user@host"` + `port = N` and lists port forwards as `LocalForward`/`RemoteForward` `~/.ssh/config` notes; import has no forwards to read
- sub-task 4: first `## Verify` run failed on clippy `large_enum_variant` (toml_io.rs:137 `CliTomlImport`); appended fix-up sub-task 5 (boxed the variants); second run exit 0

## Evidence
- (append-only: command → observed result)
- `cargo check -p conduit-core --offline` (disk-safe env) → `Finished dev profile` (only an expected unused-dependency warning before the modules existed); `python3 scripts/check-pure-rust-crypto.py` → `PURE_RUST_CRYPTO_OK`
- `cargo test -p conduit-core --offline airswitch` → `test result: ok. 7 passed; 0 failed` (covers profiles/rules/all listed condition types, composite, base64, SwitchProfile selection errors, warnings, password extraction + no plaintext in JSON/Debug, imported Proxy passes `validate_proxy`)
- `cargo test -p conduit-core --offline toml_io` → `test result: ok. 14 passed; 0 failed` (format detection; import of all 3 CLIs; export + round-trip of all 3; export refusals; MITM/vault/jump/auth/port-forward setup notes; `password_env = "CONDUIT_UPSTREAM_CORP_PASSWORD"`; commented `# type = "socks5"` tunnel placeholder; inline switch password extracted, absent from Proxy JSON/Debug and from exported TOML)
- `## Verify` run 1 → clippy `error: large size difference between variants --> crates/conduit-core/src/toml_io.rs:137:1`, EXIT=101
- `## Verify` run 2 (after fix-up 5) → `cargo test -p conduit-core`: `test result: ok. 133 passed; 0 failed`; `cargo clippy -p conduit-core --all-targets -- -D warnings`: `Finished`, no warnings; `check-pure-rust-crypto.py`: `PURE_RUST_CRYPTO_OK`; EXIT=0
