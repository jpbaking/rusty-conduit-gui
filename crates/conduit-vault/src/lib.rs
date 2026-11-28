//! `conduit-vault` — Phase 2: envelope-encrypted secret vault (`vault.bin`).
//!
//! All passwords, private-key passphrases, and MITM CA passphrases live exclusively in
//! `vault.bin` and are referenced from `conduit-core` profiles by opaque UUIDs
//! ([`conduit_core::SecretRef`] / [`conduit_core::KeyId`]). The vault wraps every secret with a
//! random 256-bit DEK, wraps that DEK with either an OS keyring or a master key derived from a
//! password with Argon2id, and encrypts each record with XChaCha20-Poly1305. No plaintext secret
//! ever touches disk, and decrypted material is returned zeroized on drop.

mod crypto;
mod keys;
mod keyring;
mod store;

pub use crypto::{
    decrypt_record, derive_master_key, generate_dek, encrypt_record, Argon2Params, Dek,
    VaultHeader, DEK_BYTES, MAX_ARGON_MEMORY_KIB, MAX_ARGON_PARALLELISM, MAX_ARGON_TIME_COST,
    NONCE_BYTES, VAULT_MAGIC, VAULT_VERSION,
};
pub use keys::{
    algorithm_name, export_backup, generate_key, import_backup, import_key, BackupKey,
    KeyGenAlgorithm, KeyInfo,
};
pub use keyring::{KeyringBackend, MemoryKeyringBackend, OsKeyringBackend};
pub use store::{Record, Vault, UPSTREAM_PASSWORD_RECORD};

use std::path::PathBuf;

use thiserror::Error;

/// Errors raised by the vault. Never leaks secret material in its `Display`/`Debug` output.
#[derive(Debug, Error)]
pub enum VaultError {
    /// Reading the on-disk vault file failed.
    #[error("failed to read {path}: {source}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Writing the on-disk vault file failed.
    #[error("failed to write {path}: {source}")]
    WriteFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Renaming the temp file onto the vault failed.
    #[error("failed to rename {temp} onto {path}: {source}")]
    Rename {
        temp: PathBuf,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The on-disk file is not a valid conduit vault (bad magic/version).
    #[error("invalid vault format: {reason}")]
    InvalidFormat {
        /// Human-readable reason.
        reason: String,
    },
    /// Decryption failed: wrong password, tampered ciphertext, or altered AAD.
    #[error("unlock failed: wrong password or tampered vault")]
    UnlockFailed,
    /// The OS keyring store is unavailable or unconfigured.
    #[error("keyring store unavailable: {reason}")]
    KeyringUnavailable {
        /// Human-readable reason.
        reason: String,
    },
    /// No keyring entry exists for the requested vault.
    #[error("keyring entry missing for vault {vault_id}")]
    KeyringEntryMissing {
        /// The vault id whose entry was missing.
        vault_id: String,
    },
    /// A cryptographic operation failed.
    #[error("cryptographic error: {reason}")]
    Crypto {
        /// Human-readable reason.
        reason: String,
    },
    /// A key import/generation operation failed.
    #[error("key error: {reason}")]
    Key {
        /// Human-readable reason.
        reason: String,
    },
    /// The vault is locked; secrets cannot be accessed until it is unlocked.
    #[error("vault is locked; unlock before accessing secrets")]
    Locked,
    /// No secret record exists for the given reference.
    #[error("secret not found: {ref_id}")]
    SecretNotFound {
        /// The missing secret reference.
        ref_id: String,
    },
}
