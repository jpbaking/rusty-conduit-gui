# crates/conduit-core

Sub-root: Cargo workspace member crate `conduit-core`.

## Purpose
UI-agnostic data model for Proxies, Tunnels, and legacy v1 sessions: validation, mapping into `rusty-conduit-engine` option types, import/export of external formats, and atomic JSON persistence.

## Ownership
Owns everything under `crates/conduit-core/`. Inherits all root DOX rules and adds the local rules below. Secrets storage is owned by `../conduit-vault`; running sessions is owned by `../conduit-runtime`.

## Local Contracts
- Pure data and logic: no network, no process spawning, no UI code. Other crates and `src-tauri` depend on this one, so it must not depend on them.
- Profiles reference secrets only by opaque vault UUIDs; never store secret values in models.
- Validation mirrors the `rusty-conduit` CLI family's `FATAL` config rules; keep it aligned with the engine version pinned in the workspace `Cargo.toml`.
- `known_hosts_import.rs` only parses text it is handed; it never opens `~/.ssh/known_hosts`.
- `toml_io.rs` mirrors each CLI's `FileConfig` shape and rejects unknown keys, as the CLIs do.
- Every write in `storage.rs` is atomic (temp file, `sync_all`, rename).

## Verification
- `cargo test -p conduit-core`
- `cargo clippy -p conduit-core --all-targets -- -D warnings`

## Feature Map
- **v1 session model** — legacy `SessionProfile`, host, filter, and log models; validation; mapping into `EngineConfig`. Start: `src/model.rs`. Files: `src/validate.rs`, `src/mapping.rs`, `src/lib.rs`.
- **v2 Tunnel / Proxy model** — `Tunnel` (with optional forward proxy, filters, MITM, and `-L` proxy-tagged forwards), `Proxy`, `UpstreamProfile` (including `tunnel-forward` targets), and routing; validation; mapping into engine `RoutingInput` / `EngineConfig`. Start: `src/v2_model.rs`. Files: `src/v2_validate.rs`, `src/v2_mapping.rs`, `src/model.rs`.
- **v1 → v2 data migration** — one-way split of each v0.1.0 session into a Tunnel and a Proxy. Start: `src/migrate_v2.rs`.
- **Atomic persistence** — `config.json` and app-owned `known_hosts.json`. Start: `src/storage.rs`.
- **CLI `config.toml` import/export** — for `rusty-conduit`, `rusty-conduit-ssh`, and `rusty-conduit-switch`. Start: `src/toml_io.rs`.
- **AirSwitch / ZeroOmega / SwitchyOmega `.bak` import** — browser-extension backups into a v2 Proxy, extracting inline secrets. Start: `src/airswitch_import.rs`.
- **Manual known_hosts import** — parse an OpenSSH `known_hosts` file the user picked. Start: `src/known_hosts_import.rs`.

## Child DOX Index
- (none)
