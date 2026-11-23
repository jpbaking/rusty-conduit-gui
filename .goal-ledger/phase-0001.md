# phase-0001 — Cargo workspace scaffold & conduit-core data model

- Status: done
- Owner: executor
- Depends on: none
- Goal: Create the 4-crate Cargo workspace and implement the complete `conduit-core` data model, validation, `rusty_conduit_ssh::Config` mapping, and atomic config/known-hosts persistence.
- Done when: `cargo test -p conduit-core && cargo clippy --workspace --all-targets -- -D warnings` exits 0 with unit tests verifying serde roundtrips, all validation rules, mapping to `rusty_conduit_ssh::Config`, and atomic file persistence.
- Pattern to follow: `/home/j.baking/Workspace/github/rusty-conduit-ssh/src/config.rs:768` (`Config::default` and validation rules)

## Context
This project embeds `../rusty-conduit-ssh` (`rusty_conduit_ssh` v1.1.0) as a library crate with zero upstream changes. All data models live in `conduit-core` so future UI shells (Tauri v2 + Svelte 5) remain thin adapters.
Key decisions already made:
- Default SSH engine is `SshEngine::Russh`; `SshEngine::OpenSsh` is represented in the schema for Phase 4.
- Zero `~/.ssh/config`, `~/.ssh/id_*`, or `~/.ssh/known_hosts` access anywhere.
- Host-key pins are keyed by `(hop_id, host, port)` in app-owned `known_hosts.json`.
- Workspace edition is 2021 to match `../rusty-conduit-ssh`.

## Scope
- In: `Cargo.toml`, `.gitignore`, `crates/conduit-core/**`, stub `Cargo.toml` + `src/lib.rs` for `crates/conduit-vault`, `crates/conduit-ssh`, `crates/conduit-runtime`
- Out: `docs/MASTER-PLAN.md`, `../rusty-conduit-ssh/**`, any UI or Tauri files

## Sub-tasks
1. [done] Create root `Cargo.toml` (workspace with `crates/conduit-core`, `crates/conduit-vault`, `crates/conduit-ssh`, `crates/conduit-runtime`, shared workspace dependencies including `rusty-conduit-ssh = { path = "../rusty-conduit-ssh" }`), `.gitignore` (ignoring `/target` and NOT ignoring `.goal-ledger/`), and minimal stub `Cargo.toml` + `src/lib.rs` for the four crates — done when: `cargo check --workspace` exits 0
2. [done] Implement `crates/conduit-core/src/model.rs` with `VaultKeyMeta`, `KeyId`, `SecretRef`, `KeySource`, `HostProfile`, `AuthMethod`, `HostKeyPin`, `SessionProfile`, `SshEngine`, `HopEntry`, `ForwardConfig`, `ReverseConfig`, `MitmConfig`, `MitmCaMode`, `TunnelConfig`, `LoggingConfig`, `OpenSshOptions`, `AppConfig`, and `KnownHostsStore` (keyed by `HostKeyLookup { hop_id, host, port }`) with full `serde` Serialize/Deserialize and sensible defaults — done when: `cargo test -p conduit-core model` exits 0
3. [done] Implement `crates/conduit-core/src/validate.rs` enforcing all `rusty-conduit-ssh` and GUI invariants: non-empty hop chain, at least one forward or reverse listener port enabled, mutual exclusion of forward allow/block and reverse allow/block filters, valid `FilterRule` syntax, MITM PEM completeness / PKCS#12 mutual exclusion / `cert_ttl >= 10s`, `reconnect_initial_delay <= reconnect_max_delay`, and `OpenSshOptions::extra_args` isolation denylist (`-F`, `-J`, `-i`, `ProxyCommand`, `ProxyJump`, `IdentityAgent`, `IdentityFile`, `UserKnownHostsFile`, `GlobalKnownHostsFile`, `StrictHostKeyChecking`, `ControlPath`, `ControlMaster`, `ForwardAgent`, `Include`) — done when: `cargo test -p conduit-core validate` exits 0
4. [done] Implement `crates/conduit-core/src/mapping.rs` converting a validated `SessionProfile` (plus optional unlocked MITM passphrase) into `rusty_conduit_ssh::config::Config` and verifying `Config::validate()` succeeds — done when: `cargo test -p conduit-core mapping` exits 0
5. [done] Implement `crates/conduit-core/src/storage.rs` for atomic JSON load/save of `AppConfig` (`config.json`) and `KnownHostsStore` (`known_hosts.json`) using temp-file + `sync_all` + atomic rename and `0600` Unix permissions — done when: `cargo test -p conduit-core storage` exits 0

## Verify
```sh
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && ! git check-ignore -v .goal-ledger/GOAL.md
```

## Escalate when
- `../rusty-conduit-ssh` lacks a public type or field needed to construct `rusty_conduit_ssh::config::Config` → stop, set Status: needs-human — reason: exact missing public API in `rusty-conduit-ssh`
- Cargo dependency resolution fails offline or due to version conflict with `../rusty-conduit-ssh` → stop, set Status: needs-human — reason: exact cargo resolution error

## Log
- sub-task 1: root Cargo.toml (4-crate workspace + shared deps incl. rusty-conduit-ssh), .gitignore (keeps .goal-ledger/), stub crates → cargo check --workspace exit 0
- sub-task 2: model.rs with all 16 types, serde + defaults → cargo test -p conduit-core model exit 0
- sub-task 3: validate.rs (all invariants + isolation denylist for extra_args) → cargo test -p conduit-core validate exit 0
- sub-task 4: mapping.rs to_config() + MappingError; maps MITM CA source, resolved passphrase, upstream cert-ttl/cache defaults → cargo test -p conduit-core mapping exit 0
- sub-task 5: storage.rs atomic JSON load/save (temp-file + sync_all + rename, 0600) → cargo test -p conduit-core storage exit 0
- phase verify: cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && ! git check-ignore -v .goal-ledger/GOAL.md → all pass
- phase done

## Evidence
- cargo check --workspace → exit 0
- cargo test -p conduit-core model → ok
- cargo test -p conduit-core validate → ok (16 tests)
- cargo test -p conduit-core mapping → ok (includes mapped_config_passes_engine_validation)
- cargo test -p conduit-core storage → ok
- cargo test --workspace → test result: ok. 33 passed; 0 failed
- cargo clippy --workspace --all-targets -- -D warnings → Finished dev profile, no warnings
- git check-ignore -v .goal-ledger/GOAL.md → exit 1 (not ignored)
