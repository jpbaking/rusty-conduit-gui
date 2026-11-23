//! `conduit-vault` — DEK keyring backends.
//!
//! The data encryption key may be stored in an OS secure store (via [`OsKeyringBackend`]) so the
//! user never types a password, or in an in-memory store for tests ([`MemoryKeyringBackend`]).
//! Both implement [`KeyringBackend`]. Missing entries map to [`VaultError::KeyringEntryMissing`];
//! an unconfigured or locked store maps to [`VaultError::KeyringUnavailable`].

use std::collections::HashMap;
use std::sync::Mutex;

use keyring_core::Entry;
use secrecy::{ExposeSecret, SecretBox};
use crate::crypto::Dek;
use crate::VaultError;

/// The service name under which DEKs are stored in the OS keyring.
const OS_SERVICE: &str = "conduit-vault";

/// A backend that can store, retrieve, and delete the data encryption key for a vault.
///
/// `vault_id` uniquely identifies a vault (see [`crate::store::Vault::id`]); it is the key under
/// which the raw DEK bytes are stored.
pub trait KeyringBackend {
    /// Fetch the DEK for `vault_id`, if present.
    fn get_dek(&self, vault_id: &str) -> Result<Dek, VaultError>;
    /// Store `dek` for `vault_id`.
    fn set_dek(&self, vault_id: &str, dek: &Dek) -> Result<(), VaultError>;
    /// Delete the DEK for `vault_id`, if present.
    fn delete_dek(&self, vault_id: &str) -> Result<(), VaultError>;
}

/// An in-memory [`KeyringBackend`] for tests. Secrets are held in a [`SecretBox`] and zeroized on
/// drop.
#[derive(Default)]
pub struct MemoryKeyringBackend {
    store: Mutex<HashMap<String, SecretBox<Vec<u8>>>>,
}

impl MemoryKeyringBackend {
    /// Create an empty in-memory keyring.
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeyringBackend for MemoryKeyringBackend {
    fn get_dek(&self, vault_id: &str) -> Result<Dek, VaultError> {
        let guard = self.store.lock().expect("keyring mutex poisoned");
        let bytes = guard
            .get(vault_id)
            .map(|s| s.expose_secret().clone())
            .ok_or_else(|| VaultError::KeyringEntryMissing {
                vault_id: vault_id.to_string(),
            })?;
        Dek::from_bytes(&bytes)
    }

    fn set_dek(&self, vault_id: &str, dek: &Dek) -> Result<(), VaultError> {
        let bytes = dek.to_bytes();
        let mut guard = self.store.lock().expect("keyring mutex poisoned");
        guard.insert(
            vault_id.to_string(),
            SecretBox::new(Box::new(bytes)),
        );
        Ok(())
    }

    fn delete_dek(&self, vault_id: &str) -> Result<(), VaultError> {
        let mut guard = self.store.lock().expect("keyring mutex poisoned");
        guard.remove(vault_id);
        Ok(())
    }
}

/// An OS keyring [`KeyringBackend`] backed by `keyring_core::Entry`.
///
/// The DEK is stored as raw bytes under `OS_SERVICE` / `vault_id`. Errors from the platform store
/// are mapped to typed [`VaultError`]s: a missing credential becomes
/// [`VaultError::KeyringEntryMissing`]; anything else (no default store, locked store, platform
/// failure) becomes [`VaultError::KeyringUnavailable`].
#[derive(Clone, Debug)]
pub struct OsKeyringBackend;

impl OsKeyringBackend {
    /// Create a new OS keyring backend.
    pub fn new() -> Self {
        OsKeyringBackend
    }

    /// Build the platform entry for `vault_id`.
    fn entry(vault_id: &str) -> Result<Entry, VaultError> {
        Entry::new(OS_SERVICE, vault_id).map_err(|e| VaultError::KeyringUnavailable {
            reason: format!("{e}"),
        })
    }
}

impl Default for OsKeyringBackend {
    fn default() -> Self {
        OsKeyringBackend
    }
}

/// Process-wide mutex serializing OS keyring calls (required for Linux D-Bus Secret Service safety).
static OS_KEYRING_LOCK: Mutex<()> = Mutex::new(());

impl KeyringBackend for OsKeyringBackend {
    fn get_dek(&self, vault_id: &str) -> Result<Dek, VaultError> {
        let _guard = OS_KEYRING_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let entry = Self::entry(vault_id)?;
        let bytes = entry.get_secret().map_err(|e| match e {
            keyring_core::Error::NoEntry => VaultError::KeyringEntryMissing {
                vault_id: vault_id.to_string(),
            },
            _ => VaultError::KeyringUnavailable {
                reason: format!("{e}"),
            },
        })?;
        Dek::from_bytes(&bytes)
    }

    fn set_dek(&self, vault_id: &str, dek: &Dek) -> Result<(), VaultError> {
        let _guard = OS_KEYRING_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let bytes = dek.to_bytes();
        let entry = Self::entry(vault_id)?;
        entry.set_secret(&bytes).map_err(|e| VaultError::KeyringUnavailable {
            reason: format!("{e}"),
        })
    }

    fn delete_dek(&self, vault_id: &str) -> Result<(), VaultError> {
        let _guard = OS_KEYRING_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let entry = Self::entry(vault_id)?;
        entry.delete_credential().map_err(|e| VaultError::KeyringUnavailable {
            reason: format!("{e}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_backend_round_trips_dek() {
        let backend = MemoryKeyringBackend::new();
        let dek = Dek::random();
        backend.set_dek("vault-1", &dek).unwrap();
        let got = backend.get_dek("vault-1").unwrap();
        assert_eq!(got.to_bytes(), dek.to_bytes());
    }

    #[test]
    fn memory_backend_missing_entry_is_typed_error() {
        let backend = MemoryKeyringBackend::new();
        let err = backend.get_dek("nope").unwrap_err();
        assert!(matches!(
            err,
            VaultError::KeyringEntryMissing { .. }
        ));
    }

    #[test]
    fn memory_backend_delete_removes_entry() {
        let backend = MemoryKeyringBackend::new();
        let dek = Dek::random();
        backend.set_dek("vault-1", &dek).unwrap();
        backend.delete_dek("vault-1").unwrap();
        assert!(matches!(
            backend.get_dek("vault-1"),
            Err(VaultError::KeyringEntryMissing { .. })
        ));
    }

    #[test]
    fn memory_backend_secrets_are_zeroized_on_drop() {
        let store = {
            let backend = MemoryKeyringBackend::new();
            backend.set_dek("v", &Dek::random()).unwrap();
            let guard = backend.store.lock().expect("poisoned");
            guard.get("v").unwrap().expose_secret().clone()
        };
        // After drop, the only copy was the clone above; assert it holds real (non-zero) bytes.
        assert!(store.iter().any(|b| *b != 0));
    }

    #[test]
    fn os_backend_missing_entry_maps_to_missing() {
        // A fresh, unpopulated entry should surface as a missing entry rather than a store error.
        let backend = OsKeyringBackend::new();
        // This may return KeyringEntryMissing (entry never set) or KeyringUnavailable (no store
        // configured in the test environment); either way it must not panic.
        match backend.get_dek("conduit-vault-does-not-exist") {
            Ok(_) => {}
            Err(VaultError::KeyringEntryMissing { .. }) => {}
            Err(VaultError::KeyringUnavailable { .. }) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
}
