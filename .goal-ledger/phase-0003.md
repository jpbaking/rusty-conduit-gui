# phase-0003 — Bump app backup format to v2 (Tunnels, Proxies, Profile Library, upstream passwords, v1 migration) and update secret_leak_scan

- Status: done
- Owner: executor
- Depends on: phase-0002
- Goal: Bump `src-tauri/src/controller/export.rs` backup format to `VERSION = 2` so plain and encrypted app backups include v2 `tunnels`, `proxies`, `profile_library`, and vaulted `UPSTREAM_PASSWORD_RECORD` secrets (while still importing v1 backups through §6.4 `migrate_v1_sessions`), and extend `src-tauri/tests/secret_leak_scan.rs` to verify v2 backups and CLI TOML exports never leak secrets.
- Done when: `cargo test -p rusty-conduit-gui --lib export` and `cargo test -p rusty-conduit-gui --test secret_leak_scan` and `cargo clippy -p rusty-conduit-gui --all-targets -- -D warnings` pass with zero warnings.
- Pattern to follow: `src-tauri/src/controller/export.rs:1-350`, `src-tauri/tests/secret_leak_scan.rs:576-820`, `docs/MASTER-PLAN.md:185-195`

## Context
- Disk constraint: ALWAYS pass `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true` on every `cargo` command.
- **`src-tauri/src/controller/export.rs`**:
  - Bump `const VERSION: u32 = 2;` (keep accepting `version == 1` on import for backwards compatibility!).
  - Use versioned AADs: `config-bundle-v2` / `config-only-v2` when writing v2, while still accepting `config-bundle-v1` / `config-only-v1` when decrypting v1 encrypted backups.
  - On **export**:
    - Collect referenced secret IDs across `sessions`, `hosts`, **`tunnels`**, **`proxies`** (`UpstreamPasswordSource::Vault(ref)` and `mitm.ca`), and **`profile_library`** (`UpstreamPasswordSource::Vault(ref)`).
    - Seal `UPSTREAM_PASSWORD_RECORD` records alongside `KEY_RECORD`, `PASSWORD_RECORD`, and `MITM_CA_RECORD` in encrypted-with-secrets bundles.
    - Add v2 counts to `ExportSummary`: `proxy_count`, `tunnel_count`, `library_profile_count` (keep existing `session_count`, `host_count`, `key_count`, `ca_count`, `secret_count`, `missing_secrets`).
  - On **import**:
    - If an imported backup has `version == 1` (or `config.schema_version < 2` with non-empty `sessions` and empty `tunnels`/`proxies`), run `conduit_core::migrate_v1_sessions(&mut config)` so older v1 backups import cleanly into v2 `tunnels` + `proxies`! (Check existing v1 export tests in `export.rs` — keep all existing security/tampering/plain-credential-stripping guarantees intact; update v1 round-trip assertions only where v1 sessions now migrate or if a v2 backup is tested.)
    - Validate imported `tunnels` (`validate_tunnel`) and `proxies` (`validate_proxy`), assign missing UUIDs, neutralize untrusted `openssh.ssh_bin` / log file paths on unauthenticated plain imports, and strip unverified `KeyId` / `SecretRef` / `MitmCaId` references on unauthenticated plain imports (same security contract as v1 sessions!).
    - For encrypted-with-secrets imports, restore `UPSTREAM_PASSWORD_RECORD` records under fresh `SecretRef` IDs and remap all Proxy & Profile Library references; restore `tunnels`, `proxies`, and `profile_library` into `AppConfig` and sync `TunnelManager` + `ProxyManager`.
    - Add v2 counts to `ImportSummary`: `proxies_added`, `proxies_updated`, `proxies_skipped`, `tunnels_added`, `tunnels_updated`, `tunnels_skipped`, `library_profiles_added`, `library_profiles_updated`, `library_profiles_skipped`.
- **`src-tauri/tests/secret_leak_scan.rs`**:
  - Update `v2_proxies_tunnels_and_upstream_passwords_hold_no_secrets` to assert `summary.secret_count >= 4` (now that the vaulted upstream password IS sealed in encrypted v2 backups!) AND also run `export_proxy_toml` for `RustyConduitSwitch` (and `RustyConduitSsh` if applicable) and scan the resulting TOML bytes for zero plaintext secret leaks!

## Scope
- In: `src-tauri/src/controller/export.rs`, `src-tauri/tests/secret_leak_scan.rs`
- Out: `crates/`, `src-tauri/src/controller/{proxies,tunnels,import_export,keys,mitm_ca,sessions}.rs`, `src-tauri/ui/`

## Sub-tasks
1. [done] Upgrade `src-tauri/src/controller/export.rs` to backup format `VERSION = 2` (v2 AADs, v1 backwards-compat + §6.4 migration on v1 import, Tunnels/Proxies/Profile Library + `UPSTREAM_PASSWORD_RECORD` sealing/restoring, plain-import credential/path neutralization, v2 summary counts, and unit tests) — done when: `cargo test -p rusty-conduit-gui --lib export` passes.
2. [done] Update `src-tauri/tests/secret_leak_scan.rs` to assert `secret_count >= 4` on v2 encrypted backup and scan `export_proxy_toml` output for zero plaintext leaks — done when: `cargo test -p rusty-conduit-gui --test secret_leak_scan` passes.
3. [done] Run `## Verify` and record observed results in `## Evidence` — done when: `## Verify` exits 0.

## Verify
```sh
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p rusty-conduit-gui --lib && CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test -p rusty-conduit-gui --test secret_leak_scan && CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo clippy -p rusty-conduit-gui --all-targets -- -D warnings
```

## Escalate when
- An existing `export.rs` security test conflicts with running `migrate_v1_sessions` on v1 imports and needs a planner decision on v1 vs v2 test semantics → stop, set Status: needs-human — reason: list the exact conflicting test(s) and why

## Log
- (append-only, one line per event)
- sub-task 1: bumped `export.rs` to `VERSION = 2` with `config-bundle-v2`/`config-only-v2` AADs (v1 AADs still accepted, picked by header version); export collects Tunnel hop, Proxy MITM CA, and Proxy/Profile Library vaulted upstream refs (sealing `UPSTREAM_PASSWORD_RECORD`) and reports `proxy_count`/`tunnel_count`/`library_profile_count`; import runs `migrate_v1_sessions` for v1 files (or schema < 2), validates Tunnels (`validate_tunnel`), Proxies (`validate_proxy`), and library names, assigns ids, strips untrusted hop creds / Proxy MITM CA (MITM switched off) / upstream passwords (vault, env, file) on unauthenticated imports, neutralizes Tunnel `ssh_bin`, Tunnel/Proxy log paths, and Proxy External TOML source, restores and remaps upstream passwords in bundles, merges Tunnels/Proxies/library with new `ImportSummary` counts, and syncs TunnelManager + ProxyManager; added 6 unit tests
- sub-task 1: one test assertion was wrong (a replace re-import on a *different* install makes new password records, as v1 always did); moved the no-new-records check to the source install, matching the existing v1 test
- sub-task 2: `secret_leak_scan` v2 test now asserts `secret_count >= 4` and proxy/tunnel counts, and scans `export_proxy_toml` output, notes, and written file for RustyConduitSwitch (must succeed, uses `password_env`) and RustyConduitSsh (refused for this routed Proxy: the error text is scanned and no file is written)
- sub-task 3: `## Verify` exit 0

## Evidence
- (append-only: command → observed result)
- `cargo test -p rusty-conduit-gui --lib export` (with low-disk env) → `test result: ok. 32 passed; 0 failed` (26 existing + 6 new v2/v1 tests)
- `cargo test -p rusty-conduit-gui --test secret_leak_scan` → `test result: ok. 6 passed; 0 failed`
- `## Verify` block → EXIT=0: `--lib` `174 passed; 0 failed`; `secret_leak_scan` `6 passed; 0 failed`; `clippy -p rusty-conduit-gui --all-targets -- -D warnings` `Finished` with no warnings
