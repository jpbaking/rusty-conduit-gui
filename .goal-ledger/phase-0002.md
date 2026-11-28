# phase-0002 — Vault hardening: bounded Argon2 costs, zeroized key copies, owner-only temp files

- Status: done
- Owner: planner
- Depends on: phase-0001
- Goal: Reject unauthenticated Argon2 parameters above fixed caps before any memory is allocated, keep every raw DEK and seed copy in `Zeroizing`, and create vault/config temp files `0600` from the first byte.
- Done when: every command in `## Verify` exits 0, including new tests that a `vault.bin` header and a `CVBK` backup with `memory_kib = u32::MAX` fail fast with an error and no allocation.
- Pattern to follow: `src-tauri/src/controller/export.rs:66-68, 621-635` (`MAX_ARGON_MEMORY_KIB` = 1 GiB, `MAX_ARGON_TIME_COST` = 64, `MAX_ARGON_PARALLELISM` = 16 and the `check_bundle_params` range checks)

## Context
B-02: `VaultHeader::unwrap_dek` (`crates/conduit-vault/src/crypto.rs:186-191`) and `import_backup` (`crates/conduit-vault/src/keys.rs`) pass the `Argon2Params` read from disk straight to `derive_master_key`, which maps `memory_kib` KiB (up to 4 TiB) through `WorkMemory::new` before AEAD authentication runs. Only encrypted GUI exports check bounds today.
Design decision: move the three caps into `conduit-vault` as `pub const`s next to `Argon2Params`, enforce them in `Argon2Params::to_argon2()` (which every derivation goes through) as `VaultError::InvalidFormat { reason: "unsupported Argon2 parameters: ..." }`, and make `export.rs` import those constants instead of defining its own. `BASELINE` (128 MiB, t=3, p=1) and the test-only `FAST` stay inside the caps.
Zeroizing: `Dek::to_bytes` returns `Zeroizing<Vec<u8>>`; the keyring backends wrap `expose_secret().clone()` / `get_secret()` copies; `unwrap_dek` wraps its decrypted plaintext; `generate_key`'s Ed25519 seed and `export_backup`'s `backup_key` are `Zeroizing<[u8; 32]>`.
Temp files: both atomic writers create the file with `File::create` and `chmod 0600` only after writing. Create with `OpenOptions` (`write`, `create_new`, and `OpenOptionsExt::mode(0o600)` on Unix) and drop the later `set_permissions`.

## Scope
- In: `crates/conduit-vault/src/crypto.rs`, `crates/conduit-vault/src/keyring.rs`, `crates/conduit-vault/src/keys.rs`, `crates/conduit-vault/src/store.rs`, `crates/conduit-vault/src/lib.rs` (re-exports only), `crates/conduit-core/src/storage.rs`, `src-tauri/src/controller/export.rs` (constants and imports only), `crates/conduit-vault/DOX.md`
- Out: the on-disk formats (`VAULT_VERSION`, field layout, `CVBK` layout), `crates/conduit-openssh/`, `src-tauri/ui/`

## Sub-tasks
1. [done] Add `pub const MAX_ARGON_MEMORY_KIB: u32 = 1024 * 1024`, `MAX_ARGON_TIME_COST: u32 = 64`, `MAX_ARGON_PARALLELISM: u8 = 16` to `crypto.rs`, re-export them from `lib.rs`, and check `memory_kib <= MAX`, `1..=MAX` time cost, `1..=MAX` parallelism, and `derived_key_len == 32` at the top of `to_argon2()`; switch `export.rs` to the re-exported constants — done when: `grep -c 'const MAX_ARGON' src-tauri/src/controller/export.rs` prints `0` and `cargo test -p conduit-vault --locked` passes.
2. [done] Tests: `unwrap_dek` on a header whose `argon2.memory_kib = u32::MAX` returns `InvalidFormat` (and returns quickly); `import_backup` of a `CVBK` bundle edited to `memory_kib = u32::MAX` fails the same way; the existing `export.rs` test at line ~1532 still passes — done when: `cargo test --workspace --locked argon` runs the new tests and passes.
3. [done] Zeroize raw copies as listed in Context; update callers (`keyring.rs:59, 171`, `export.rs:827, 2035`, the `crypto.rs:440` test) — done when: `cargo clippy --workspace --all-targets --locked -- -D warnings` passes and `grep -n 'fn to_bytes' crates/conduit-vault/src/crypto.rs` shows `Zeroizing<Vec<u8>>`.
4. [done] Owner-only temp files in `store.rs` `atomic_write_bytes` and `storage.rs` `atomic_write_json`; extend the existing perms test in `storage.rs` and add one for `store.rs` that checks the temp file mode by creating it through the same helper — done when: `cargo test -p conduit-vault -p conduit-core --locked` passes.
5. [done] DOX pass: `crates/conduit-vault/DOX.md` Local Contracts state the Argon2 caps and that raw key bytes never leave `Zeroizing`/`SecretBox` — done when: `grep -c 'MAX_ARGON_MEMORY_KIB' crates/conduit-vault/DOX.md` prints at least `1`.
6. [done] (planner, Gate D finding) Move `atomic_write_json`'s doc comment back onto it (it had ended up above `create_private` in `storage.rs`), and merge the `MAX_ARGON_*` import in `export.rs` into the existing `use conduit_vault::{...}` block — done when: clippy and `cargo test --workspace --locked` pass.

## Verify
```sh
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo test -p rusty-conduit-gui --test secret_leak_scan --locked
python3 scripts/check-pure-rust-crypto.py
git diff --exit-code -- crates/conduit-openssh src-tauri/ui
```

## Escalate when
- An existing vault, keyring, or backup fixture fails to open with the new caps → stop, set Status: needs-human — reason: name the fixture and its parameters (real user vaults must keep opening).
- Making a temp file `create_new` breaks a retry path that reuses the name → stop, set Status: needs-human — reason: name the caller.

## Log
- (append-only, one line per event)
- planner begins phase-0002 (planner-owned)
- sub-task 1: `MAX_ARGON_*` consts in crypto.rs, re-exported from lib.rs, enforced at the top of `to_argon2()` (InvalidFormat "unsupported Argon2 parameters: ..."); export.rs imports them
- sub-task 2: tests `argon_params_above_caps_are_rejected`, `unwrap_dek_rejects_huge_argon_memory_before_deriving` (crypto.rs), `backup_rejects_huge_argon_memory_before_deriving` (keys.rs); each asserts < 1 s
- sub-task 3: `Dek::to_bytes` → `Zeroizing<Vec<u8>>`; keyring get_dek copies wrapped; MemoryKeyringBackend::set_dek builds its SecretBox via `with_key` (no loose copy); `unwrap_dek` plaintext wrapped; Ed25519 seed and backup key `Zeroizing<[u8; 32]>`; export.rs salt sites take a public `Vec` slice of the generator output
- sub-task 4: `create_private` (OpenOptions write + create_new + mode 0600) in store.rs and storage.rs replaces `File::create` + later chmod; temp names are fresh UUIDs, so no retry reuses a name; tests check the helper's mode and refusal to reuse
- sub-task 5: conduit-vault DOX Local Contracts list the caps, Zeroizing rule, and 0600 create_new temp file
- phase-0002 verified and closed

- Gate D: storage.rs doc comment was attached to the wrong fn; export.rs had a mid-file `use`; both fixed (sub-task 6)

## Evidence
- (append-only: command → observed result)
- `cargo test --workspace --locked argon` → 3 new tests ok (plus existing export argon test in the full run)
- `grep -c 'const MAX_ARGON' src-tauri/src/controller/export.rs` → 0; `grep -n 'fn to_bytes' crates/conduit-vault/src/crypto.rs` → `75: pub fn to_bytes(&self) -> Zeroizing<Vec<u8>>`
- `cargo test -p conduit-vault -p conduit-core --locked` → all ok (156 + 48 + 7)
- `grep -c 'MAX_ARGON_MEMORY_KIB' crates/conduit-vault/DOX.md` → 1
- `cargo clippy --workspace --all-targets --locked -- -D warnings` → exit 0; `cargo test --workspace --locked` → 673 passed, 0 failed; secret_leak_scan → 6 passed; PURE_RUST_CRYPTO_OK; `git diff --exit-code -- crates/conduit-openssh src-tauri/ui` → exit 0
- Gate D fix-up: clippy exit 0; `cargo test --workspace --locked` → 680 passed
