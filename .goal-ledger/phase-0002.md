# phase-0002 — conduit-vault envelope encryption, key management & keyring

- Status: done
- Owner: executor
- Depends on: phase-0001
- Goal: Implement `conduit-vault` with `vault.bin` envelope encryption (`XChaCha20-Poly1305` + `Argon2id` + `KeyringBackend`), zeroized in-memory secret handling, SSH key import/generation/metadata extraction, and encrypted backup export/import.
- Done when: `cargo test -p conduit-vault && cargo clippy --workspace --all-targets -- -D warnings` exits 0 with tests verifying encryption, tamper/AAD rejection, wrong-password rejection, keyring + master-password hybrid unlock, key import/generation, and zero plaintext leakage in `vault.bin`.
- Pattern to follow: `crates/conduit-core/src/storage.rs` (atomic temp-file + `sync_all` + rename + `0600` permissions)

## Context
All passwords, private keys, key passphrases, and MITM CA passphrases live exclusively in `vault.bin` and are referenced from `conduit-core` profiles by opaque UUIDs (`SecretRef`, `KeyId`).
Key decisions already made:
- Random 256-bit DEK; per-record `XChaCha20-Poly1305` with fresh random 24-byte nonce and AAD binding `(record_id, record_type, vault_version)`.
- Hybrid DEK wrapping: OS keyring (`KeyringBackend` trait with `OsKeyringBackend` via `keyring-core` / platform store, plus `MemoryKeyringBackend` for tests) and/or Master Password (`Argon2id` with calibrated baseline 128 MiB, `t=3`, `p=1` stored in vault header; provide a fast-param constructor only for `#[cfg(test)]`).
- Never fall back to plaintext; if `vault.bin` already exists and unlock fails or keyring entry is missing, return a typed `VaultError::UnlockFailed` / `VaultError::KeyringEntryMissing` and NEVER overwrite `vault.bin`.
- Decrypted secrets use `secrecy::SecretBox` / `zeroize::Zeroizing`; `Debug` impls must never print secret bytes.

## Scope
- In: `Cargo.toml`, `crates/conduit-vault/**`
- Out: `crates/conduit-ssh/**`, `crates/conduit-runtime/**`, `docs/MASTER-PLAN.md`

## Sub-tasks
1. [done] Add dependencies (`chacha20poly1305 = "0.10"`, `argon2 = "0.5"`, `rand = "0.8"`, `zeroize = { version = "1", features = ["derive"] }`, `secrecy = "0.10"`, `russh = { version = "0.65", default-features = false, features = ["ring"] }` for SSH key parsing/generation via `russh::keys`, `keyring-core = "1.1"`, `thiserror`, `uuid`, `serde`, `serde_json`, `base64`) to workspace/crate `Cargo.toml` — done when: `cargo check -p conduit-vault` exits 0
2. [done] Implement `crates/conduit-vault/src/crypto.rs` with `VaultHeader`, `Argon2Params`, DEK generation, Argon2id key derivation, DEK wrapping/unwrapping, and per-record `XChaCha20-Poly1305` encrypt/decrypt binding `(record_id, record_type, vault_version)` as AAD — done when: `cargo test -p conduit-vault crypto` exits 0
3. [done] Implement `crates/conduit-vault/src/keyring.rs` defining the `KeyringBackend` trait (`get_dek`, `set_dek`, `delete_dek`), `MemoryKeyringBackend`, and `OsKeyringBackend` backed by `keyring_core::Entry` (serialized access via a mutex, mapping missing/unconfigured store cleanly to `VaultError::KeyringUnavailable` and missing entry to `VaultError::KeyringEntryMissing`) — done when: `cargo test -p conduit-vault keyring` exits 0
4. [done] Implement `crates/conduit-vault/src/store.rs` implementing `Vault` lifecycle (`create_with_password`, `create_with_keyring`, `open_locked`, `unlock_with_password`, `unlock_with_keyring`, `lock`, `is_unlocked`, `put_secret`, `get_secret`, `delete_secret`, `list_keys`, `save` atomically with `0600` permissions) — done when: `cargo test -p conduit-vault store` exits 0
5. [done] Implement `crates/conduit-vault/src/keys.rs` supporting private key import (OpenSSH / PEM / PKCS#8, encrypted or unencrypted, verifying passphrase on import), in-app keypair generation (`Ed25519` default and `ECDSA-P256`), `VaultKeyMeta` extraction (algorithm, SHA-256 fingerprint, OpenSSH public key), and passphrase-encrypted full backup export/import — done when: `cargo test -p conduit-vault keys` exits 0
6. [done] Add integration tests in `crates/conduit-vault/tests/vault_security.rs` verifying: `vault.bin` bytes contain no plaintext secret strings, tampered ciphertext or swapped record AAD fails decryption, wrong master password fails without modifying `vault.bin`, and `Debug` formatting redacts secrets — done when: `cargo test -p conduit-vault` exits 0

## Verify
```sh
cargo test -p conduit-vault && cargo clippy --workspace --all-targets -- -D warnings
```

## Escalate when
- `keyring-core` 1.1.0 API or feature flags fail to compile on Linux without system libsecret headers → stop, set Status: needs-human — reason: exact crate/feature compilation error and proposed pure-Rust `zbus`/crate alternative
- PuTTY `.ppk` parsing requires an unmaintained or incompatible crate → stop, set Status: needs-human — reason: confirm whether to defer `.ppk` import or which parser crate to use

## Log
- sub-task 1 done: added chacha20poly1305, argon2, rand, zeroize, secrecy, russh(ring), keyring-core, base64, serde, serde_json, thiserror, uuid to workspace + crate Cargo.toml; cargo check -p conduit-vault exits 0
- sub-task 2 done: crypto.rs (VaultHeader, Argon2Params, DEK, wrap/unwrap, per-record XChaCha20-Poly1305); `cargo test -p conduit-vault crypto` → 11 passed
- sub-task 3 done: keyring.rs (KeyringBackend trait, Memory/Os backends); `cargo test -p conduit-vault keyring` → 7 passed
- sub-task 4 done: store.rs (Vault lifecycle + atomic 0600 save); `cargo test -p conduit-vault store` → 10 passed
- Full: `cargo test -p conduit-vault` → 26 passed; `cargo clippy --workspace --all-targets -- -D warnings` → EXIT 0 (only expected `russh` unused-dep warning, reserved for keys.rs)
- sub-task 5 done: keys.rs (import OpenSSH/PEM-SEC1/PKCS#8/PKCS#5 with passphrase verify, Ed25519+ECDSA-P256 generation, KeyInfo extraction, passphrase-encrypted backup export/import); `cargo test -p conduit-vault keys` → 12 passed; clippy clean (removed unused sha2 workspace dep)
- sub-task 6 done: tests/vault_security.rs (6 integration tests: no-plaintext-on-disk, tampered-ciphertext, swapped-AAD, wrong-master-password-no-modify, Debug redaction, hybrid unlock); `cargo test -p conduit-vault` → 43 passed; clippy `--workspace --all-targets -- -D warnings` → EXIT 0

## Evidence
- sub-task 1: `cargo check -p conduit-vault` → Finished dev profile, EXIT 0 (deps resolve; russh 0.65 + ring and keyring-core 1.1 compile on this Linux box)
- sub-task 2: `cargo test -p conduit-vault crypto` → 11 passed (header wrap/unwrap, wrong-password, tampered wrapped DEK, derive determinism, DEK redaction, AAD binding, nonce handling)
- sub-task 3: `cargo test -p conduit-vault keyring` → 7 passed (memory backend get/set/delete, missing entry, hybrid fallback)
- sub-task 4: `cargo test -p conduit-vault store` → 10 passed (round trip, locked access error, wrong password no-modify, tampered ciphertext fails, owner-only 0600, hybrid unlock)
- sub-task 5: `cargo test -p conduit-vault keys` → 12 passed (generate ed25519/ecdsa, import openssh/pkcs8-ed25519/sec1-ecdsa/pkcs8-ecdsa, two-generations-differ, wrong-passphrase rejected, encrypted-requires-passphrase, backup round-trip + bad-magic); `cargo clippy --workspace --all-targets -- -D warnings` → EXIT 0
- sub-task 6: `cargo test -p conduit-vault` → 43 passed (37 unit + 6 integration in tests/vault_security.rs); `cargo clippy --workspace --all-targets -- -D warnings` → EXIT 0. Integration tests: vault_bin_has_no_plaintext_secret, tampered_ciphertext_fails_on_get, swapped_record_aad_fails_on_get, wrong_master_password_does_not_modify_vault, debug_formatting_redacts_secrets, keyring_and_password_unlock_both_work
