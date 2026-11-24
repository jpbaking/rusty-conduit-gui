# phase-0002 — Manual OpenSSH known_hosts file import

- Status: done
- Owner: executor
- Depends on: phase-0001
- Goal: Implement strictly manual, user-initiated OpenSSH `known_hosts` file import for a hop (core parser, controller/IPC command, and `HopEditor.svelte` UI action).
- Done when: `cargo test -p conduit-core -p rusty-conduit-ssh-gui && cargo clippy -p conduit-core -p rusty-conduit-ssh-gui --all-targets -- -D warnings && (cd src-tauri/ui && npm run check && npm run build)` exits 0 with unit tests for plain, `[host]:port`, hashed `|1|` entries, and controller import round-trip.
- Pattern to follow: `crates/conduit-core/src/model.rs:548-600` (`KnownHostsStore`, `HostKeyPin`), `src-tauri/src/controller/sessions.rs` (host-key pin methods), `src-tauri/src/commands.rs` (IPC command registration), and `src-tauri/ui/src/lib/components/HopEditor.svelte` (host-key pin UI).

## Context
`docs/MASTER-PLAN.md` §5.4 specifies: "Optional one-time manual import from a user-selected `known_hosts` file (never automatic)."
Non-negotiable rule (§1.4): NEVER automatically read or default to `~/.ssh/known_hosts`. The user must explicitly provide a file path, and the importer reads only that path and imports the matching key for the requested `(hop_id, host, port)` into the app-owned `KnownHostsStore` (`known_hosts.json`), computing its `SHA256:<base64-no-pad>` fingerprint and preserving `public_key_openssh` (`<algorithm> <base64>`) so both `russh` and OpenSSH engines can use it immediately.
`ring` and `base64` are already workspace dependencies in `Cargo.toml` (`ring = "0.17"`, `base64 = "0.22"`). Use `ring::digest::SHA256` for fingerprint calculation and `ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY` for matching OpenSSH `|1|<salt>|<hash>` hashed hostnames.
Planner decision (resolving sub-task 2 escalation): Yes — do NOT change the `KnownHostsStore` schema. Insert `HostKeyRecord { algorithm, fingerprint_sha256, first_seen: Timestamp::now(), approved: true, public_key_openssh: Some(public_key) }` under `HostKeyLookup { hop_id, host, port }`, return `Result<conduit_core::HostKeyEntry, AppError>` from `AppController::import_known_host_from_file` and the `import_known_host` IPC command, and return `HostKeyEntry` from the TS `importKnownHost` API.

## Scope
- In: `crates/conduit-core/Cargo.toml`, `crates/conduit-core/src/lib.rs`, `crates/conduit-core/src/known_hosts_import.rs`, `src-tauri/src/controller/sessions.rs`, `src-tauri/src/commands.rs`, `src-tauri/ui/src/lib/types.ts`, `src-tauri/ui/src/lib/api.ts`, `src-tauri/ui/src/lib/mock.ts`, `src-tauri/ui/src/lib/stores.svelte.ts`, `src-tauri/ui/src/lib/components/HopEditor.svelte`, `Cargo.lock`
- Out: `docs/MASTER-PLAN.md`, `../rusty-conduit-ssh`, `crates/conduit-vault/**`, `crates/conduit-ssh/**`, `crates/conduit-openssh/**`

## Sub-tasks
1. [done] Add `crates/conduit-core/src/known_hosts_import.rs` (exported from `crates/conduit-core/src/lib.rs`, adding `base64 = { workspace = true }` and `ring = { workspace = true }` to `crates/conduit-core/Cargo.toml`) implementing `parse_openssh_known_hosts_for_host(content: &str, host: &str, port: u16) -> Vec<ImportedHostKey>` (with fields `algorithm: String`, `fingerprint_sha256: String`, `public_key: String`). Support: blank lines & `#` comments skipped; `@revoked` and `@cert-authority` lines skipped; comma-separated host patterns with plain `host` (matches port 22), `[host]:port` (matches exact port), negation `!pattern` (excludes the line if matched), and hashed `|1|<base64-salt>|<base64-hmac-sha1>` entries (matching `host` for port 22 or `[host]:port` for non-22). Validate the base64 key blob and compute `SHA256:<standard-base64-no-pad>`. Add comprehensive unit tests covering plain, `[host]:port`, comma lists, negation, hashed `|1|`, `@revoked`/`@cert-authority`, malformed lines, and SHA-256 fingerprint calculation. — done when: `cargo test -p conduit-core known_hosts_import` passes.
2. [done] Add `AppController::import_known_host_from_file(&self, hop_id: &str, host: &str, port: u16, path: &Path) -> Result<HostKeyEntry, AppError>` in `src-tauri/src/controller/sessions.rs` (reads the explicit `path` only, finds matching keys via `parse_openssh_known_hosts_for_host`, returns `AppError::NotFound` if none match, inserts the first matching key as a `HostKeyRecord { algorithm, fingerprint_sha256, first_seen: Timestamp::now(), approved: true, public_key_openssh: Some(public_key) }` under `HostKeyLookup { hop_id, host, port }`, saves `known_hosts.json`, and returns the saved `HostKeyEntry`). Expose it as Tauri IPC command `import_known_host` in `src-tauri/src/commands.rs` and register it in `ipc_handler!`. Add unit tests in `src-tauri/src/controller/sessions.rs` covering successful import (plain & hashed), missing host match, and missing file error. — done when: `cargo test -p rusty-conduit-ssh-gui import_known_host` passes.
3. [done] Wire `importKnownHost(hopId, host, port, path)` into `src-tauri/ui/src/lib/api.ts`, `mock.ts`, and `stores.svelte.ts`, and add an **Import from file…** toggle/input in the Host Key Pin section of `src-tauri/ui/src/lib/components/HopEditor.svelte` where the user can enter an explicit file path (with helper text noting `~/.ssh/known_hosts` is never read automatically) and import the pin for that hop. — done when: `(cd src-tauri/ui && npm run check && npm run build)` exits 0.
4. [done] Run full phase verification. — done when: all commands in `## Verify` exit 0.

## Verify
```sh
cargo test -p conduit-core -p rusty-conduit-ssh-gui && cargo clippy -p conduit-core -p rusty-conduit-ssh-gui --all-targets -- -D warnings && (cd src-tauri/ui && npm run check && npm run build)
```

## Escalate when
- `HopEditor.svelte` or `commands.rs` has an incompatible pin model that would require changing `KnownHostsStore` schema → stop, set Status: needs-human — reason: <exact mismatch>
- Existing tests fail unexpectedly → stop, set Status: needs-human — reason: <failing test>

## Log
- (append-only, one line per event)
- sub-task 1: added crates/conduit-core/src/known_hosts_import.rs (parser + 11 unit tests, fixtures from ssh-keygen -t ed25519/ecdsa, ssh-keygen -l, ssh-keygen -H), exported from lib.rs, added base64/ring deps to conduit-core Cargo.toml (Cargo.lock updated)
- sub-task 2: blocked before any code — specified return type/fields do not exist in the pin model; escalated
- planner unblocked sub-task 2: approved inserting HostKeyRecord (approved: true, first_seen: Timestamp::now(), public_key_openssh: Some) and returning HostKeyEntry (no schema change); returned sub-task 2 to [todo]
- sub-task 2: added AppController::import_known_host_from_file (sessions.rs) returning HostKeyEntry, IPC command import_known_host (commands.rs, registered in ipc_handler! and ALL_COMMANDS, exercised in every_ipc_command test), 4 controller unit tests (plain [host]:port, hashed |1| replacing existing pin, no match → NotFound, missing file → Io)
- sub-task 3: added api.importKnownHost (api.ts), mock import_known_host (mock.ts), store.importKnownHost (stores.svelte.ts), and an "Import from file…" path form in the HopEditor Host key section with helper text that ~/.ssh/known_hosts is never read automatically; types.ts unchanged (HostKeyEntry already exists)
- sub-task 4: ran full ## Verify block → exit 0

## Evidence
- (append-only: command → observed result)
- `cargo test -p conduit-core known_hosts_import` → test result: ok. 11 passed; 0 failed
- `cargo clippy -p conduit-core --all-targets -- -D warnings` → Finished, no warnings
- `grep -n "pub struct HostKeyPin" -A9 crates/conduit-core/src/model.rs` → fields algorithm, fingerprint_sha256, first_seen, approved only (no approved_at, no public_key); KnownHostsStore holds HostKeyRecord (public_key_openssh: Option<String>)
- `cargo test -p rusty-conduit-ssh-gui import_known_host` → test result: ok. 4 passed; 0 failed
- `cargo test -p rusty-conduit-ssh-gui every_ipc_command` → test result: ok. 1 passed; 0 failed
- `(cd src-tauri/ui && npm run check && npm run build)` → svelte-check 0 ERRORS 0 WARNINGS; vite ✓ built
- `cargo test -p conduit-core -p rusty-conduit-ssh-gui && cargo clippy -p conduit-core -p rusty-conduit-ssh-gui --all-targets -- -D warnings && (cd src-tauri/ui && npm run check && npm run build)` → EXIT=0 (conduit-core 52 passed; rusty-conduit-ssh-gui 108 + 5 passed; clippy clean; svelte-check 0 errors 0 warnings; vite built)
