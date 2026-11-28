# crates/conduit-vault

Sub-root: Cargo workspace member crate `conduit-vault`.

## Purpose
Envelope-encrypted secret vault (`vault.bin`): hop passwords, key passphrases, SSH private keys, upstream proxy passwords, and MITM CAs.

## Ownership
Owns everything under `crates/conduit-vault/`. Inherits all root DOX rules and adds the local rules below. Profiles that reference vault records live in `../conduit-core`.

## Local Contracts
- Every record is encrypted with XChaCha20-Poly1305 under a random 256-bit DEK; the DEK is wrapped by the OS keyring and/or an Argon2id master key. Never add a plaintext fallback.
- Secret material is zeroized after use (`zeroize` / `secrecy`); never log, `Debug`-print, or serialize it in clear.
- Raw key bytes (DEK copies, keyring reads, unwrapped plaintext, generated seeds, backup keys) never leave `Zeroizing` / `SecretBox`.
- Argon2 parameters from any file are untrusted: `Argon2Params::to_argon2` rejects anything above `MAX_ARGON_MEMORY_KIB` (1 GiB), `MAX_ARGON_TIME_COST` (64), or `MAX_ARGON_PARALLELISM` (16), or a key length other than 32, before memory is reserved.
- Every `vault.bin` write is atomic, through a temp file created `0600` (`create_new`) before any byte is written.
- Crypto stays pure Rust: no C crypto library may enter the dependency graph (checked by `../../scripts/check-pure-rust-crypto.py`).
- Platform keyring stores are chosen per target in `Cargo.toml` (macOS login Keychain, Windows native store, Linux Secret Service over `zbus`).

## Verification
- `cargo test -p conduit-vault` (includes `tests/vault_security.rs`)
- From the repo root: `python3 scripts/check-pure-rust-crypto.py`

## Feature Map
- **Vault lifecycle and record store** — create, unlock, lock, rekey, and CRUD over encrypted records in `vault.bin`. Start: `src/store.rs`. Files: `src/lib.rs`.
- **Envelope crypto** — DEK generation, record encryption, Argon2id master-key wrapping. Start: `src/crypto.rs`.
- **DEK keyring backends** — OS secure store and in-memory test backend. Start: `src/keyring.rs`.
- **SSH key management** — import, generation, metadata extraction, and encrypted key backup. Start: `src/keys.rs`.
- **Security guarantees tests** — end-to-end checks through `vault.bin` on disk. Start: `tests/vault_security.rs`.

## Child DOX Index
- (none)
