# phase-0001 — Hardening follow-ups & host-key public-key storage

- Status: done
- Owner: executor
- Depends on: none
- Goal: Close Phase 3 Gate D hardening items (attached/case-insensitive `extra_args` denylist in Rust+TS, plain-import path neutralization) and add backwards-compatible `public_key_openssh` to `HostKeyRecord` for Phase 4 `known_hosts` rendering.
- Done when: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && (cd src-tauri/ui && npm run check)` exits 0 with new unit tests covering attached/case-variant `extra_args`, plain-import sanitization, and `HostKeyRecord.public_key_openssh` roundtrips.
- Pattern to follow: `crates/conduit-core/src/validate.rs:86-100` (denylist), `src-tauri/ui/src/lib/validate.ts:98-121` (TS mirror), `src-tauri/src/controller/export.rs:234-257` (untrusted plain-import stripping), `crates/conduit-ssh/src/host_key.rs:14-35` (`ObservedHostKey`).

## Context
Phase 3 Gate D identified two security hardening follow-ups that must land before OpenSSH execution goes live:
1. `conduit-core`'s `extra_args` denylist only matched whole case-sensitive tokens (missing `-oProxyCommand=x`, `-Fconfig`, `-i/path`, `-O`, `-S`, `-A`, `-a`, case-insensitive option names, and `-o` followed by a forbidden option in the next token). Both Rust and TS must enforce the hardened denylist identically.
2. Unauthenticated plain config imports currently preserve `openssh.ssh_bin` and `logging.http_access_log`/`socks_log` paths, which would let a tampered plain export point `ssh_bin` at an arbitrary binary or overwrite arbitrary files via log paths. Neutralize them on plain imports unless unchanged from an existing trusted session with the same ID.
3. OpenSSH `UserKnownHostsFile` requires `<alias> <algorithm> <base64_key>` (not just `SHA256:` fingerprint). Adding `#[serde(default)] pub public_key_openssh: Option<String>` to `HostKeyRecord` (and threading it through `ObservedHostKey`, `SshError::HostKeyUnknown`, `HostKeyPrompt`, and `approve_host_key`) keeps existing `known_hosts.json` files compatible while giving Phase 4 the exact public key blob.

## Scope
- In: `crates/conduit-core/src/validate.rs`, `crates/conduit-core/src/model.rs`, `crates/conduit-core/src/storage.rs`, `crates/conduit-ssh/src/host_key.rs`, `crates/conduit-ssh/src/error.rs`, `crates/conduit-ssh/src/handler.rs`, `crates/conduit-ssh/src/chain/tests.rs`, `crates/conduit-ssh/tests/common/mod.rs`, `crates/conduit-ssh/tests/loopback_multihop.rs`, `crates/conduit-runtime/src/state.rs`, `crates/conduit-runtime/src/runner.rs`, `crates/conduit-runtime/src/manager.rs`, `crates/conduit-runtime/tests/e2e_runtime.rs`, `crates/conduit-tray/src/model.rs`, `src-tauri/src/controller.rs`, `src-tauri/src/controller/export.rs`, `src-tauri/src/controller/sessions.rs`, `src-tauri/src/controller/test_support.rs`, `src-tauri/ui/src/lib/validate.ts`, `src-tauri/ui/src/lib/types.ts`, `src-tauri/ui/src/lib/components/LoggingAdvancedTab.svelte`
- Out: `docs/MASTER-PLAN.md`, `../rusty-conduit-ssh/**`, `crates/conduit-openssh/**`, `crates/conduit-vault/**`

## Sub-tasks
1. [done] Harden `crates/conduit-core/src/validate.rs` `extra_args` denylist: reject forbidden short flags both standalone and with attached values (`-F`, `-Fconfig`, `-J`, `-Jjump`, `-i`, `-i/path`, `-O`, `-Ocheck`, `-S`, `-S/tmp/ctl`, `-A`, `-a`, `-W`), reject `-o<Option>=...` / `-o<Option> ...` and `-o` followed by `<Option>=...` or `<Option> ...` as well as bare/dashed `<Option>` forms case-insensitively for `ProxyCommand`, `ProxyJump`, `IdentityAgent`, `IdentityFile`, `UserKnownHostsFile`, `GlobalKnownHostsFile`, `StrictHostKeyChecking`, `ControlPath`, `ControlMaster`, `ControlPersist`, `ForwardAgent`, `Include`, `LocalCommand`, `PermitLocalCommand`, `RemoteCommand`, `KnownHostsCommand`, `UpdateHostKeys`, `Host`, `Match`, while still allowing safe options like `["-o", "Compression=yes"]` or `["-oCompression=yes"]` or `["-v"]`; add thorough unit tests — done when: `cargo test -p conduit-core` passes with tests for all attached, case-variant, `-o` pair, and safe-arg cases.
2. [done] Mirror the exact hardened `extra_args` denylist in `src-tauri/ui/src/lib/validate.ts` (updating `denylistedFlag` / adding a sequence-aware check for `-o` followed by a forbidden option, and updating `opensshErrors` + `LoggingAdvancedTab.svelte` chip highlighting) — done when: `(cd src-tauri/ui && npm run check)` passes with 0 errors.
3. [done] Neutralize untrusted paths on plain config import in `src-tauri/src/controller/export.rs`: in `strip_untrusted_credentials` (or a sibling helper called from `import_plain`), for each incoming session reset `openssh.ssh_bin` to `"ssh"` unless an existing session with the same `id` already has the exact same `openssh.ssh_bin`, and reset `logging.http_access_log` and `logging.socks_log` to `None` unless the existing session with the same `id` already has the exact same path; keep encrypted bundle imports preserving these fields; add unit tests in `export.rs` verifying both plain-import neutralization and encrypted-import preservation — done when: `cargo test -p rusty-conduit-ssh-gui export` passes.
4. [done] Add `#[serde(default)] pub public_key_openssh: Option<String>` to `HostKeyRecord` in `crates/conduit-core/src/model.rs`, populate `public_key_openssh: Option<String>` on `ObservedHostKey` (`crates/conduit-ssh/src/host_key.rs`, formatted via `key.to_openssh()` so it holds `<alg> <base64>`), carry it through `SshError::HostKeyUnknown`, `HostKeyPrompt` (`crates/conduit-runtime/src/state.rs`), `runner.rs`, and `SessionManager::approve_host_key` (`crates/conduit-runtime/src/manager.rs`), and update all struct literal sites in tests and `src-tauri/ui/src/lib/types.ts` — done when: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && (cd src-tauri/ui && npm run check)` passes with a deserialization backwards-compat test for `HostKeyRecord` without `public_key_openssh` and a test verifying `approve_host_key` stores `public_key_openssh`.

## Verify
```sh
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && (cd src-tauri/ui && npm run check)
```

## Escalate when
- `russh::keys::PublicKey` does not expose `.to_openssh()` or equivalent OpenSSH public-key formatting method in `russh` 0.65 → stop, set `Status: needs-human — reason: <exact method signature gap>`
- Any file outside `Scope: In` fails to compile due to the `HostKeyRecord` or `HostKeyPrompt` field addition → stop, set `Status: needs-human — reason: <list exact file paths>`

## Log
- (append-only, one line per event)
- sub-task 1: hardened the Rust denylist (short flags, getopt clusters, case-insensitive options, quoted and spaced keywords) and added tests. Every token is checked as a possible option, so the value after a separate `-o` is caught without position tracking.
- sub-task 2: mirrored the denylist in validate.ts with ASCII-only case folding. LoggingAdvancedTab.svelte needed no edit because its chips and opensshErrors already call denylistedFlag per token.
- sub-task 3: added neutralize_untrusted_paths to plain import only, with plain and encrypted tests.
- sub-task 4: applied the field to all Scope: In files, then stopped on the phase's escalation rule because two files outside Scope: In no longer compile.
- planner unblocked: added `crates/conduit-tray/src/model.rs` and `src-tauri/src/controller.rs` to `Scope: In` so the two test literals can be updated with `public_key_openssh: None,`. Leaving `-I`/`PKCS11Provider`/`SecurityKeyProvider` allowed to preserve FIDO2/hardware-key use case per Master Plan Section 3.1.
- sub-task 4: added `public_key_openssh: None,` to the two test literals the planner brought into scope (conduit-tray model.rs, src-tauri controller.rs).
- phase verified and closed.

## Evidence
- (append-only: command → observed result)
- `cargo test -p conduit-core --lib` (after sub-task 1) → 39 passed, 0 failed
- `(cd src-tauri/ui && npm run check)` → 158 files, 0 errors, 0 warnings
- `node --experimental-strip-types parity.mts` (scratch script, TS denylist) → 28 denied, 15 allowed, no mismatches
- `cargo test -p rusty-conduit-ssh-gui export` (after sub-task 3, before sub-task 4) → 17 passed, 0 failed
- `cargo test -p conduit-core -p conduit-ssh -p conduit-runtime` (after sub-task 4) → all passed (41, 48, 8, 64, 5, 12)
- `cargo clippy -p conduit-core -p conduit-ssh -p conduit-runtime --all-targets -- -D warnings` → clean
- `cargo check --workspace --all-targets --keep-going` → E0063 missing `public_key_openssh` at crates/conduit-tray/src/model.rs:509 and src-tauri/src/controller.rs:640
- Phase `## Verify` → not run to completion: the workspace tests do not compile until the blocker is resolved
- `cargo check` blocker resolved: both literals updated at crates/conduit-tray/src/model.rs:515 and src-tauri/src/controller.rs:644
- `cargo test -p rusty-conduit-ssh-gui export` (after sub-task 4) → 17 passed, 0 failed
- Phase `## Verify`: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && (cd src-tauri/ui && npm run check)` → exit 0; 345 tests passed, 0 failed; clippy clean; 158 files, 0 errors, 0 warnings
- Correction to the line numbers above: `grep -n "public_key_openssh: None"` → crates/conduit-tray/src/model.rs:516 and src-tauri/src/controller.rs:645
