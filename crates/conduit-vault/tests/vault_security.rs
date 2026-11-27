//! Integration tests for `conduit-vault` security guarantees.
//!
//! These exercise the public API end-to-end (through `vault.bin` on disk) to verify the
//! guarantees the phase's `## Context` demands:
//!
//! * No plaintext secret ever lands on disk in `vault.bin`.
//! * The envelope's integrity protection actually protects: a tampered ciphertext, or a record
//!   whose `(id, type)` AAD was swapped on disk, fails to decrypt.
//! * A wrong master password fails and never rewrites `vault.bin`.
//! * `Debug` formatting never leaks secret material.
//!
//! `Argon2Params::FAST` is `#[cfg(test)]` inside the crate, so it is invisible here; the
//! equivalent fast parameters are rebuilt from the public struct fields.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use conduit_vault::{Argon2Params, Dek, MemoryKeyringBackend, Vault, VaultError};
use std::path::PathBuf;
use uuid::Uuid;

/// Fast, low-memory Argon2id parameters equivalent to `crypto::Argon2Params::FAST`, rebuilt from
/// the public fields so the integration test does not pay the 128 MiB production cost.
fn fast_params() -> Argon2Params {
    Argon2Params {
        memory_kib: 16 * 1024,
        time_cost: 1,
        parallelism: 1,
        derived_key_len: 32,
    }
}

/// A fresh, uniquely-named temp path under the system temp dir.
fn tmp_vault(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("conduit-vault-it-{}-{}", Uuid::new_v4(), tag))
}

/// A distinctive marker that must never appear in the on-disk bytes.
const PLAINTEXT_MARKER: &[u8] = b"PLAINTEXT-VAULT-SECRET-MARKER-a1b2c3d4e5f6";

/// The vault.bin bytes must never contain the plaintext secret, in any of its common encodings.
#[test]
fn vault_bin_has_no_plaintext_secret() {
    let path = tmp_vault("plaintext-leak");
    let mut vault = Vault::create_with_password(&path, b"master-pw", fast_params()).unwrap();
    let id = vault.put_secret("password", PLAINTEXT_MARKER).unwrap();
    // Confirm the secret really is retrievable before we lock it away.
    assert_eq!(&vault.get_secret(&id).unwrap()[..], PLAINTEXT_MARKER);
    drop(vault); // persist + release the in-memory DEK

    let raw = std::fs::read(&path).expect("vault.bin exists");

    // The raw plaintext bytes must not appear anywhere in the file.
    assert!(
        !raw.windows(PLAINTEXT_MARKER.len()).any(|w| w == PLAINTEXT_MARKER),
        "plaintext secret leaked into vault.bin"
    );

    // ... nor its hex encoding, nor its base64 encoding.
    let hex: String = PLAINTEXT_MARKER.iter().map(|b| format!("{b:02x}")).collect();
    let b64 = BASE64.encode(PLAINTEXT_MARKER);
    let haystack = String::from_utf8_lossy(&raw).to_lowercase();
    assert!(
        !haystack.contains(&hex.to_lowercase()),
        "hex-encoded secret leaked into vault.bin"
    );
    assert!(
        !haystack.contains(&b64.to_lowercase()),
        "base64-encoded secret leaked into vault.bin"
    );

    let _ = std::fs::remove_file(&path);
}

/// Tampering a record's on-disk ciphertext must fail authentication (not silently corrupt).
#[test]
fn tampered_ciphertext_fails_on_get() {
    let path = tmp_vault("tamper-ct");
    let mut vault = Vault::create_with_password(&path, b"pw", fast_params()).unwrap();
    let id = vault.put_secret("key", b"ssh-private-key-material").unwrap();
    drop(vault);

    // Read the on-disk JSON, flip exactly one byte inside the first record's ciphertext, write back.
    let mut doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).expect("valid vault.json");
    let ct = BASE64
        .decode(doc["records"][0]["ciphertext"].as_str().unwrap())
        .unwrap();
    let mut tampered = ct;
    tampered[0] ^= 0x01;
    doc["records"][0]["ciphertext"] = serde_json::Value::from(BASE64.encode(tampered));
    std::fs::write(&path, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();

    let mut vault = Vault::open_locked(&path).unwrap();
    vault.unlock_with_password(b"pw").unwrap();
    assert!(matches!(
        vault.get_secret(&id),
        Err(VaultError::UnlockFailed)
    ));

    let _ = std::fs::remove_file(&path);
}

/// Swapping a record's stored type on disk changes the AAD bound into its ciphertext, so
/// decryption must fail — the record is bound to its `(id, type)` identity.
#[test]
fn swapped_record_aad_fails_on_get() {
    let path = tmp_vault("tamper-aad");
    let mut vault = Vault::create_with_password(&path, b"pw", fast_params()).unwrap();
    let id = vault.put_secret("key", b"host-key-material").unwrap();
    drop(vault);

    // Rewrite the on-disk record type from "key" to "password". The ciphertext was authenticated
    // against the original type, so decryption must now fail.
    let mut doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).expect("valid vault.json");
    doc["records"][0]["type"] = serde_json::Value::from("password");
    std::fs::write(&path, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();

    let mut vault = Vault::open_locked(&path).unwrap();
    vault.unlock_with_password(b"pw").unwrap();
    assert!(matches!(
        vault.get_secret(&id),
        Err(VaultError::UnlockFailed)
    ));

    let _ = std::fs::remove_file(&path);
}

/// A wrong master password must fail and must never rewrite vault.bin.
#[test]
fn wrong_master_password_does_not_modify_vault() {
    let path = tmp_vault("wrong-master");
    Vault::create_with_password(&path, b"correct-horse", fast_params()).unwrap();
    let before = std::fs::read(&path).expect("vault.bin exists");

    let mut vault = Vault::open_locked(&path).unwrap();
    assert!(!vault.is_unlocked());
    let err = vault.unlock_with_password(b"definitely-wrong").unwrap_err();
    assert!(matches!(err, VaultError::UnlockFailed));
    assert!(!vault.is_unlocked(), "a wrong password must not unlock the vault");

    let after = std::fs::read(&path).expect("vault.bin still exists");
    assert_eq!(before, after, "a wrong master password must not modify vault.bin");

    // The correct password still works afterwards (the file was untouched).
    let mut vault = Vault::open_locked(&path).unwrap();
    vault.unlock_with_password(b"correct-horse").unwrap();
    assert!(vault.is_unlocked());

    let _ = std::fs::remove_file(&path);
}

/// `Debug` formatting must never reveal secret material: the DEK redacts to a fixed marker, and the
/// vault's Debug output must not contain the stored plaintext secret.
#[test]
fn debug_formatting_redacts_secrets() {
    // Dek: Debug is a fixed redaction marker, never the key bytes.
    let dek = Dek::random();
    let rendered = format!("{dek:?}");
    assert_eq!(rendered, "Dek(\"<redacted>\")");
    let hex: String = dek.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
    assert!(!rendered.to_lowercase().contains(&hex.to_lowercase()));

    // Vault: Debug must not leak the plaintext secret it holds.
    let path = tmp_vault("debug-leak");
    let mut vault = Vault::create_with_password(&path, b"pw", fast_params()).unwrap();
    let id = vault.put_secret("password", PLAINTEXT_MARKER).unwrap();
    let rendered_vault = format!("{vault:?}");
    assert!(
        !rendered_vault.contains(str::from_utf8(PLAINTEXT_MARKER).unwrap()),
        "vault Debug leaked the plaintext secret"
    );

    // And once locked, the DEK is gone from memory.
    vault.lock();
    assert!(!vault.is_unlocked());
    let _ = vault.get_secret(&id); // Locked -> error, no panic.
    let _ = std::fs::remove_file(&path);
}

/// The hybrid keyring path unlocks without a password, and the master-password path still works —
/// the two unlock mechanisms must not clobber each other.
#[test]
fn keyring_and_password_unlock_both_work() {
    let path = tmp_vault("hybrid-it");
    let keyring = MemoryKeyringBackend::new();
    Vault::create_with_keyring(&path, &keyring, b"master", fast_params()).unwrap();

    // Unlock via keyring (no password needed).
    let mut via_keyring = Vault::open_locked(&path).unwrap();
    via_keyring.unlock(&keyring, b"ignored").unwrap();
    assert!(via_keyring.is_unlocked());

    // Unlock via master password on a fresh open (keyring entry still present).
    let mut via_password = Vault::open_locked(&path).unwrap();
    via_password.unlock_with_password(b"master").unwrap();
    assert!(via_password.is_unlocked());

    let _ = std::fs::remove_file(&path);
}


/// After a data-dir rename, `unlock_with_keyring_fallback` finds the DEK stored under the legacy
/// vault path and copies it to the new path so future unlocks work directly.
#[test]
fn keyring_fallback_migrates_legacy_path() {
    let old_path = tmp_vault("legacy-old");
    let new_path = tmp_vault("legacy-new");
    let keyring = MemoryKeyringBackend::new();
    let old_vault =
        Vault::create_with_keyring(&old_path, &keyring, b"master", fast_params()).unwrap();
    let old_id = old_vault.id().to_string();
    drop(old_vault);

    std::fs::rename(&old_path, &new_path).unwrap();

    let mut migrated = Vault::open_locked(&new_path).unwrap();
    assert!(matches!(
        migrated.unlock_with_keyring(&keyring),
        Err(VaultError::KeyringEntryMissing { .. })
    ));

    migrated
        .unlock_with_keyring_fallback(&keyring, Some(&old_id))
        .unwrap();
    assert!(migrated.is_unlocked());

    // Subsequent unlock hits the new path directly without needing the fallback.
    let mut direct = Vault::open_locked(&new_path).unwrap();
    direct.unlock_with_keyring(&keyring).unwrap();
    assert!(direct.is_unlocked());

    let _ = std::fs::remove_file(&new_path);
}
