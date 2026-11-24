# phase-0003 — src-tauri: port conflicts, filter tester, MITM CA inspector & config export/import IPC

- Status: done
- Owner: executor
- Depends on: phase-0001, phase-0002
- Goal: Implement the Phase 3 backend IPC commands in `src-tauri`: live port-conflict detection (`check_port_conflicts`), interactive filter rule tester (`test_filter_rules`), MITM CA certificate inspection (`inspect_mitm_ca`), and config export/import (`export_config` stripped-by-default or passphrase-encrypted full bundle, `import_config`) with full unit and secret-leak tests.
- Done when: `cargo test -p rusty-conduit-ssh-gui && cargo clippy --workspace --all-targets -- -D warnings` exits 0 with all new commands covered by `every_ipc_command_works_and_no_response_or_file_leaks_a_secret`.
- Pattern to follow: `src-tauri/src/commands.rs` and `src-tauri/src/controller/keys.rs`

## Context
Master Plan Phase 3 requires 100% `rusty-conduit-ssh` option parity in the Manage Window plus safe config export/import.
Key decisions already made:
- **`check_port_conflicts(session_id: Option<Uuid>, bind: IpAddr, http_port: u16, socks_port: u16)`:**
  - Checks each non-zero port against all *other* saved sessions' forward ports (same bind IP or either side is unspecified `0.0.0.0`/`::`) AND checks whether a live OS `TcpListener::bind((bind, port))` fails with `AddrInUse` (skipping the OS bind check if `session_id` is currently running and owns that listener!). Returns `PortConflictReport { conflicts: Vec<PortConflict> }` with `port`, `kind` (`"session"` | `"os_socket"`), and `detail`.
- **`test_filter_rules(mode: "allow" | "block", rules: Vec<String>, target: String)`:**
  - Parses each rule with `rusty_conduit_ssh::filter::FilterRule::from_str`, builds `HostFilter`, tests `target` (IP or domain), and returns `FilterTestResult { valid: bool, allowed: Option<bool>, reason: String, rule_errors: Vec<RuleError> }`.
- **`inspect_mitm_ca(ca_mode: MitmCaMode, passphrase: Option<SecretInput>, passphrase_ref: Option<SecretRef>, passphrase_file: Option<PathBuf>)`:**
  - Resolves passphrase (from inline `SecretInput`, or from unlocked `Vault` via `passphrase_ref`, or `passphrase_file`), validates & parses the CA via `rusty_conduit_ssh::mitm` / `x509-parser` (matching the engine's exact CA loader!), and returns `MitmCaInfo { subject: String, not_after: String, expired: bool, days_remaining: i64 }`. Never returns private key material or passphrase!
- **`export_config(path: PathBuf, include_secrets: bool, passphrase: Option<SecretInput>)` & `import_config(path: PathBuf, passphrase: Option<SecretInput>, replace_existing: bool)`:**
  - When `include_secrets == false` (default): writes a redacted JSON config export (`AppConfig` with `keys` metadata preserved or stripped as safe metadata, NO secret values, NO `vault.bin` bytes).
  - When `include_secrets == true`: requires a non-empty `passphrase` and unlocked `Vault`; writes an `XChaCha20-Poly1305` + `Argon2id` encrypted full bundle containing `AppConfig` + `KnownHostsStore` + all referenced vault secrets (reusing `conduit_vault::crypto` primitives, zero plaintext secrets on disk!).
  - `import_config` detects plain JSON vs. encrypted bundle, validates every imported session/host, skips or updates duplicates cleanly, and requires unlocked vault + passphrase when importing an encrypted bundle.
- Update `keys.rs` usage tracking to also count `hop.agent_forward_keys` so deleting a key warns when it is assigned for agent forwarding!

## Scope
- In: `src-tauri/src/**`, `src-tauri/Cargo.toml`, `Cargo.lock`
- Out: `crates/**`, `src-tauri/ui/**`, `docs/MASTER-PLAN.md`

## Sub-tasks
1. [done] Update `src-tauri/src/controller/keys.rs` so key usage counting and forced deletion also track and strip `hop.agent_forward_keys` references — done when: `cargo test -p rusty-conduit-ssh-gui keys` exits 0
2. [done] Implement `src-tauri/src/controller/parity.rs` with `check_port_conflicts`, `test_filter_rules`, and `inspect_mitm_ca` (reusing `rusty_conduit_ssh::filter` and `rusty_conduit_ssh::mitm` CA parsing) plus unit tests — done when: `cargo test -p rusty-conduit-ssh-gui parity` exits 0
3. [done] Implement `src-tauri/src/controller/export.rs` with `export_config` (redacted JSON default + passphrase-encrypted full bundle using `conduit_vault::crypto`) and `import_config` (plain + encrypted auto-detect, validation, zero plaintext secret leakage) plus unit tests — done when: `cargo test -p rusty-conduit-ssh-gui export` exits 0
4. [done] Expose `check_port_conflicts`, `test_filter_rules`, `inspect_mitm_ca`, `export_config`, and `import_config` in `src-tauri/src/commands.rs`, register them in `ipc_handler!` and `ALL_COMMANDS`, and extend `every_ipc_command_works_and_no_response_or_file_leaks_a_secret` to exercise all 44 commands and verify exported files contain zero plaintext secrets — done when: `cargo test -p rusty-conduit-ssh-gui && cargo clippy --workspace --all-targets -- -D warnings` exits 0

## Verify
```sh
cargo test -p rusty-conduit-ssh-gui && cargo clippy --workspace --all-targets -- -D warnings
```

## Escalate when
- `rusty_conduit_ssh::mitm` does not expose a public helper to load/inspect a CA without building a full `MitmState` → stop, set Status: needs-human — reason: exact visibility in `../rusty-conduit-ssh/src/mitm/`

## Log
- (append-only, one line per event)
- sub-task 1: key usage now counts hop.agent_forward_keys (once per session) and forced delete strips them and re-syncs the session
- sub-task 2: added parity.rs (port conflicts, filter tester using engine FilterRule/HostFilter, CA inspector using engine CaMaterial parsers so expired CAs are reported)
- sub-task 3: added export.rs (redacted JSON, Argon2id + XChaCha20-Poly1305 bundle, auto-detecting atomic import; plain imports keep a credential ref only for the same host/port/user)
- sub-task 4: exposed 5 commands, registered them in ipc_handler! and ALL_COMMANDS (44 total), extended the IPC leak test to both export files
- phase verified and closed

## Evidence
- (append-only: command → observed result)
- `cargo test -p rusty-conduit-ssh-gui keys` → 16 passed; 0 failed
- `cargo test -p rusty-conduit-ssh-gui parity` → 12 passed; 0 failed
- `cargo test -p rusty-conduit-ssh-gui export` → 13 passed; 0 failed
- `grep -c '$crate::commands::' src-tauri/src/commands.rs` → 44
- `cargo test -p rusty-conduit-ssh-gui && cargo clippy --workspace --all-targets -- -D warnings` → exit 0; 99 passed, 0 failed, including every_ipc_command_works_and_no_response_or_file_leaks_a_secret; clippy clean
