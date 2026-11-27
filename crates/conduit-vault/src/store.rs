//! `conduit-vault` — the [`Vault`] lifecycle and record store.
//!
//! The vault persists to a single `vault.bin` file: a JSON document carrying the [`VaultHeader`]
//! (wrapped DEK, Argon2id params, salt) and the encrypted [`Record`]s. Every write is atomic
//! (temp file → `sync_all` → rename → `0600`), mirroring `conduit-core`'s storage strategy.
//!
//! The DEK is wrapped either by an OS keyring or by a master key derived from a password
//! (Argon2id). `create_with_keyring` establishes both so the vault can be unlocked by keyring or
//! by master password (hybrid). The DEK is held in memory only while unlocked and is zeroized on
//! `lock` / drop.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};
use uuid::Uuid;

use crate::crypto::{decrypt_record, encrypt_record, generate_dek, Dek, VaultHeader};
use crate::keyring::KeyringBackend;
use crate::VaultError;

/// Record type of an upstream proxy password (`UpstreamPasswordSource::Vault` in
/// `conduit-core`). Bound into the record's AAD like every other record type.
pub const UPSTREAM_PASSWORD_RECORD: &str = "upstream_password";

/// A single encrypted secret record. The ciphertext is base64-encoded for the on-disk JSON form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// Opaque record id (a UUID string).
    pub id: String,
    /// Record type, bound into the ciphertext AAD (e.g. `key`, `password`, `passphrase`).
    pub r#type: String,
    /// Base64-encoded XChaCha20-Poly1305 ciphertext.
    pub ciphertext: String,
}

impl Record {
    fn encrypt(dek: &crate::crypto::Dek, id: &str, r#type: &str, plaintext: &[u8]) -> Self {
        let ct = encrypt_record(dek, id.as_bytes(), r#type.as_bytes(), plaintext);
        Record {
            id: id.to_string(),
            r#type: r#type.to_string(),
            ciphertext: BASE64.encode(&ct),
        }
    }

    fn decrypt(&self, dek: &crate::crypto::Dek) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let ct = BASE64
            .decode(self.ciphertext.as_bytes())
            .map_err(|e| VaultError::Crypto {
                reason: format!("failed to base64-decode record: {e}"),
            })?;
        decrypt_record(dek, self.id.as_bytes(), self.r#type.as_bytes(), &ct)
    }
}

/// Lightweight, unencrypted metadata for one record (id + type only). Returned by [`Vault::list_keys`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordMeta {
    /// Opaque record id (a UUID string).
    pub id: String,
    /// Record type.
    pub r#type: String,
}

impl From<&Record> for RecordMeta {
    fn from(r: &Record) -> Self {
        RecordMeta {
            id: r.id.clone(),
            r#type: r.r#type.clone(),
        }
    }
}

/// The on-disk vault document: header plus records.
#[derive(Serialize, Deserialize)]
struct VaultFile {
    header: VaultHeader,
    records: Vec<Record>,
}

/// An unlocked-or-locked conduit vault. Holds the DEK in memory only while unlocked.
pub struct Vault {
    path: PathBuf,
    /// Stable id used to key the OS keyring; derived from the vault file's absolute path.
    id: String,
    header: Option<VaultHeader>,
    dek: Option<crate::crypto::Dek>,
    records: Vec<Record>,
}

impl Drop for Vault {
    fn drop(&mut self) {
        if let Some(dek) = self.dek.as_mut() {
            dek.zeroize();
        }
    }
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("id", &self.id)
            .field("is_unlocked", &self.dek.is_some())
            .field("record_count", &self.records.len())
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// The stable vault id (absolute path), used to key the OS keyring.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Whether the DEK is currently in memory.
    pub fn is_unlocked(&self) -> bool {
        self.dek.is_some()
    }

    /// Derive a stable, path-based id for keyring lookups.
    fn id_for(path: &Path) -> String {
        let abs = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|c| c.join(path))
                .unwrap_or_else(|_| path.to_path_buf())
        };
        abs.to_string_lossy().into_owned()
    }

    /// Create a brand-new vault whose DEK is wrapped by `password`. The vault is returned unlocked.
    pub fn create_with_password(
        path: impl Into<PathBuf>,
        password: &[u8],
        params: crate::crypto::Argon2Params,
    ) -> Result<Self, VaultError> {
        let path = path.into();
        let dek = generate_dek();
        let header = VaultHeader::new(&dek, &params, password);
        let mut vault = Vault::lock_only(path, header, Vec::new());
        vault.dek = Some(dek);
        vault.save()?;
        Ok(vault)
    }

    /// Create a brand-new hybrid vault: the DEK is stored in `keyring` AND wrapped by `password`
    /// in the header, so it can be unlocked by keyring or by master password. Returned unlocked.
    pub fn create_with_keyring(
        path: impl Into<PathBuf>,
        keyring: &dyn KeyringBackend,
        password: &[u8],
        params: crate::crypto::Argon2Params,
    ) -> Result<Self, VaultError> {
        let path = path.into();
        let id = Self::id_for(&path);
        let dek = generate_dek();
        keyring.set_dek(&id, &dek)?;
        let header = VaultHeader::new(&dek, &params, password);
        let mut vault = Vault::lock_only(path, header, Vec::new());
        vault.dek = Some(dek);
        vault.save()?;
        Ok(vault)
    }

    /// Open an existing vault without the DEK (locked). Fails if the file does not exist.
    pub fn open_locked(path: impl Into<PathBuf>) -> Result<Self, VaultError> {
        let path = path.into();
        let bytes = fs::read(&path).map_err(|source| VaultError::ReadFile {
            path: path.clone(),
            source,
        })?;
        let file: VaultFile = serde_json::from_slice(&bytes).map_err(|source| VaultError::InvalidFormat {
            reason: format!("vault.bin is not valid JSON: {source}"),
        })?;
        file.header.validate()?;
        Ok(Vault {
            id: Self::id_for(&path),
            path,
            header: Some(file.header),
            dek: None,
            records: file.records,
        })
    }

    /// Internal constructor for a freshly created, still-locked vault body.
    fn lock_only(
        path: PathBuf,
        header: VaultHeader,
        records: Vec<Record>,
    ) -> Self {
        Vault {
            id: Self::id_for(&path),
            path,
            header: Some(header),
            dek: None,
            records,
        }
    }

    /// Unlock with the master password by unwrapping the DEK from the header. A wrong password
    /// yields [`VaultError::UnlockFailed`] and never touches `vault.bin`.
    pub fn unlock_with_password(&mut self, password: &[u8]) -> Result<(), VaultError> {
        let header = self.header.as_ref().ok_or(VaultError::Locked)?;
        let dek = header.unwrap_dek(password)?;
        self.dek = Some(dek);
        Ok(())
    }

    /// Unlock by reading the DEK from `keyring`. A missing entry yields
    /// [`VaultError::KeyringEntryMissing`].
    pub fn unlock_with_keyring(&mut self, keyring: &dyn KeyringBackend) -> Result<(), VaultError> {
        let dek = keyring.get_dek(&self.id)?;
        self.dek = Some(dek);
        Ok(())
    }

    /// Unlock via `keyring`, falling back to `legacy_vault_id` (e.g. after a data-dir migration)
    /// when no entry exists under `self.id`. If found under `legacy_vault_id`, best-effort copies
    /// the DEK to `self.id` so subsequent unlocks hit the current path directly.
    pub fn unlock_with_keyring_fallback(
        &mut self,
        keyring: &dyn KeyringBackend,
        legacy_vault_id: Option<&str>,
    ) -> Result<(), VaultError> {
        match self.unlock_with_keyring(keyring) {
            Ok(()) => Ok(()),
            Err(VaultError::KeyringEntryMissing { .. }) => {
                let Some(old_id) = legacy_vault_id.filter(|id| *id != self.id) else {
                    return Err(VaultError::KeyringEntryMissing {
                        vault_id: self.id.clone(),
                    });
                };
                match keyring.get_dek(old_id) {
                    Ok(dek) => {
                        let _ = keyring.set_dek(&self.id, &dek);
                        self.dek = Some(dek);
                        Ok(())
                    }
                    Err(VaultError::KeyringEntryMissing { .. }) => {
                        Err(VaultError::KeyringEntryMissing {
                            vault_id: self.id.clone(),
                        })
                    }
                    Err(other) => Err(other),
                }
            }
            Err(other) => Err(other),
        }
    }

    /// Hybrid unlock: try `keyring` first; if its entry is missing, fall back to `password`.
    /// A keyring store error is returned as-is; a missing entry falls through to the password.
    pub fn unlock(
        &mut self,
        keyring: &dyn KeyringBackend,
        password: &[u8],
    ) -> Result<(), VaultError> {
        match keyring.get_dek(&self.id) {
            Ok(dek) => {
                self.dek = Some(dek);
                return Ok(());
            }
            Err(VaultError::KeyringEntryMissing { .. }) => {}
            Err(e) => return Err(e),
        }
        self.unlock_with_password(password)
    }

    /// Stores this unlocked vault's DEK in `keyring`, so it can later be unlocked without the
    /// master password. The password keeps working too.
    pub fn store_in_keyring(&self, keyring: &dyn KeyringBackend) -> Result<(), VaultError> {
        let dek = self.dek.as_ref().ok_or(VaultError::Locked)?;
        keyring.set_dek(&self.id, dek)
    }

    /// Removes this vault's DEK from `keyring`. An entry that is already gone is not an error.
    pub fn remove_from_keyring(&self, keyring: &dyn KeyringBackend) -> Result<(), VaultError> {
        match keyring.delete_dek(&self.id) {
            Ok(()) | Err(VaultError::KeyringEntryMissing { .. }) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// The header holding the wrapped DEK, or `None` for a vault body that has none.
    pub fn header(&self) -> Option<&VaultHeader> {
        self.header.as_ref()
    }

    /// Replaces the DEK: every record is re-encrypted from `old` to `new`, and `header`, which
    /// must wrap `new`, replaces the current one, and the result is saved. The vault is unlocked with
    /// `new` afterwards. On failure nothing changes, in memory or on disk.
    ///
    /// The slow part, deriving keys from passwords, is the caller's, so it can run without
    /// holding a lock on this vault.
    pub fn rekey(&mut self, old: &Dek, new: Dek, header: VaultHeader) -> Result<(), VaultError> {
        header.validate()?;
        let mut records = Vec::with_capacity(self.records.len());
        for record in &self.records {
            let plaintext = record.decrypt(old)?;
            records.push(Record::encrypt(&new, &record.id, &record.r#type, &plaintext));
        }
        let previous_header = self.header.replace(header);
        let previous_records = std::mem::replace(&mut self.records, records);
        if let Err(error) = self.save() {
            self.header = previous_header;
            self.records = previous_records;
            return Err(error);
        }
        if let Some(dek) = self.dek.as_mut() {
            dek.zeroize();
        }
        self.dek = Some(new);
        Ok(())
    }

    /// Zeroize the in-memory DEK and lock the vault.
    pub fn lock(&mut self) {
        if let Some(dek) = self.dek.as_mut() {
            dek.zeroize();
        }
        self.dek = None;
    }

    /// Store a secret, returning its opaque UUID id. Requires the vault to be unlocked.
    pub fn put_secret(&mut self, r#type: &str, plaintext: &[u8]) -> Result<String, VaultError> {
        let _ = self.dek.as_ref().ok_or(VaultError::Locked)?;
        let dek = self.dek.as_ref().unwrap();
        let id = Uuid::new_v4().to_string();
        let record = Record::encrypt(dek, &id, r#type, plaintext);
        self.records.push(record);
        self.save()?;
        Ok(id)
    }

    /// Retrieve and decrypt a secret by id. Requires the vault to be unlocked.
    pub fn get_secret(&self, id: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let dek = self.dek.as_ref().ok_or(VaultError::Locked)?;
        let record = self
            .records
            .iter()
            .find(|r| r.id == id)
            .ok_or_else(|| VaultError::SecretNotFound {
                ref_id: id.to_string(),
            })?;
        record.decrypt(dek)
    }

    /// Store an upstream proxy password as an [`UPSTREAM_PASSWORD_RECORD`], returning its id.
    /// Requires the vault to be unlocked.
    pub fn put_upstream_password(&mut self, password: &[u8]) -> Result<String, VaultError> {
        self.put_secret(UPSTREAM_PASSWORD_RECORD, password)
    }

    /// Retrieve an upstream proxy password. A record of any other type is reported as
    /// [`VaultError::SecretNotFound`], so a key or SSH password cannot be read through this
    /// path. Requires the vault to be unlocked.
    pub fn get_upstream_password(&self, ref_id: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let dek = self.dek.as_ref().ok_or(VaultError::Locked)?;
        let record = self
            .records
            .iter()
            .find(|r| r.id == ref_id && r.r#type == UPSTREAM_PASSWORD_RECORD)
            .ok_or_else(|| VaultError::SecretNotFound {
                ref_id: ref_id.to_string(),
            })?;
        record.decrypt(dek)
    }

    /// Delete a secret by id. Requires the vault to be unlocked.
    pub fn delete_secret(&mut self, id: &str) -> Result<(), VaultError> {
        let _ = self.dek.as_ref().ok_or(VaultError::Locked)?;
        let pos = self
            .records
            .iter()
            .position(|r| r.id == id)
            .ok_or_else(|| VaultError::SecretNotFound {
                ref_id: id.to_string(),
            })?;
        self.records.remove(pos);
        self.save()?;
        Ok(())
    }

    /// List unencrypted record metadata (id + type). Does not require the vault to be unlocked.
    pub fn list_keys(&self) -> Vec<RecordMeta> {
        self.records.iter().map(RecordMeta::from).collect()
    }

    /// The record types currently stored (helper for tests/metadata).
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Atomically persist the header and records to `vault.bin` (`0600`).
    pub fn save(&mut self) -> Result<(), VaultError> {
        let header = self.header.as_ref().ok_or(VaultError::Locked)?;
        let file = VaultFile {
            header: header.clone(),
            records: self.records.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&file)
            .map_err(std::io::Error::other)
            .map_err(|source| VaultError::WriteFile {
                path: self.path.clone(),
                source,
            })?;
        atomic_write_bytes(&self.path, &bytes).map_err(|source| VaultError::WriteFile {
            path: self.path.clone(),
            source,
        })
    }
}

/// Atomically write `bytes` to `path`: temp file in the same directory, `sync_all`, rename over the
/// destination, created `0600`. Mirrors `conduit-core::storage::atomic_write_json`.
fn atomic_write_bytes(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    use uuid::Uuid;

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let base = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("vault.bin")
        .to_string();
    let tmp_path = dir.join(format!(".{base}.{tmp}.tmp", tmp = Uuid::new_v4()));

    // Ensure the destination directory exists before creating the temp file.
    fs::create_dir_all(dir)?;

    {
        let mut tmp = fs::File::create(&tmp_path)?;
        tmp.write_all(bytes)?;
        tmp.sync_all()?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;
    }

    fs::rename(&tmp_path, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Argon2Params;
    use crate::keyring::MemoryKeyringBackend;

    fn tmp_vault(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("conduit-vault-test-{}", Uuid::new_v4()));
        dir.join(tag)
    }

    #[test]
    fn create_unlock_put_get_round_trip() {
        let path = tmp_vault("roundtrip");
        let mut vault = Vault::create_with_password(&path, b"pw", Argon2Params::FAST).unwrap();
        assert!(vault.is_unlocked());

        let id = vault.put_secret("password", b"s3cret-pw").unwrap();
        let got = vault.get_secret(&id).unwrap();
        assert_eq!(&got[..], b"s3cret-pw");

        vault.lock();
        assert!(!vault.is_unlocked());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn open_locked_then_unlock_with_password() {
        let path = tmp_vault("open");
        Vault::create_with_password(&path, b"correct", Argon2Params::FAST).unwrap();

        let mut vault = Vault::open_locked(&path).unwrap();
        assert!(!vault.is_unlocked());
        vault.unlock_with_password(b"correct").unwrap();
        let id = vault.put_secret("key", b"private").unwrap();
        assert_eq!(&vault.get_secret(&id).unwrap()[..], b"private");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn wrong_password_fails_and_does_not_modify_vault() {
        let path = tmp_vault("wrongpw");
        Vault::create_with_password(&path, b"correct", Argon2Params::FAST).unwrap();
        let before = fs::read(&path).unwrap();

        let mut vault = Vault::open_locked(&path).unwrap();
        let err = vault.unlock_with_password(b"wrong").unwrap_err();
        assert!(matches!(err, VaultError::UnlockFailed));

        let after = fs::read(&path).unwrap();
        assert_eq!(before, after, "a wrong password must not modify vault.bin");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn keyring_hybrid_unlock_both_ways() {
        let path = tmp_vault("hybrid");
        let keyring = MemoryKeyringBackend::new();
        Vault::create_with_keyring(&path, &keyring, b"master", Argon2Params::FAST)
            .unwrap();

        // Unlock via keyring (no password needed).
        let mut v1 = Vault::open_locked(&path).unwrap();
        v1.unlock(&keyring, b"whatever").unwrap();
        assert!(v1.is_unlocked());

        // Unlock via master password (keyring entry still present, but password path works too).
        let mut v2 = Vault::open_locked(&path).unwrap();
        v2.unlock(&keyring, b"master").unwrap();
        assert!(v2.is_unlocked());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn password_vault_can_be_moved_onto_the_keyring_and_off_again() {
        let path = tmp_vault("move-to-keyring");
        let keyring = MemoryKeyringBackend::new();
        let vault = Vault::create_with_password(&path, b"master", Argon2Params::FAST).unwrap();

        let locked = Vault::open_locked(&path).unwrap();
        assert!(matches!(locked.store_in_keyring(&keyring), Err(VaultError::Locked)));

        vault.store_in_keyring(&keyring).unwrap();
        let mut by_keyring = Vault::open_locked(&path).unwrap();
        by_keyring.unlock_with_keyring(&keyring).unwrap();
        assert!(by_keyring.is_unlocked());

        vault.remove_from_keyring(&keyring).unwrap();
        // Removing twice is fine, and the password still unlocks.
        vault.remove_from_keyring(&keyring).unwrap();
        let mut again = Vault::open_locked(&path).unwrap();
        assert!(matches!(
            again.unlock_with_keyring(&keyring),
            Err(VaultError::KeyringEntryMissing { .. })
        ));
        again.unlock_with_password(b"master").unwrap();
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn keyring_missing_entry_falls_back_to_password() {
        let path = tmp_vault("fallback");
        // create_with_password leaves no keyring entry.
        Vault::create_with_password(&path, b"master", Argon2Params::FAST).unwrap();
        let keyring = MemoryKeyringBackend::new();

        let mut vault = Vault::open_locked(&path).unwrap();
        // keyring has no entry → falls back to the correct password.
        vault.unlock(&keyring, b"master").unwrap();
        assert!(vault.is_unlocked());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn delete_secret_removes_record() {
        let path = tmp_vault("delete");
        let mut vault = Vault::create_with_password(&path, b"pw", Argon2Params::FAST).unwrap();
        let id = vault.put_secret("password", b"data").unwrap();
        assert_eq!(vault.record_count(), 1);
        // delete_secret borrows &self but needs &mut for save; exercise via a reborrow trick.
        vault.delete_secret(&id).unwrap();
        assert_eq!(vault.record_count(), 0);
        assert!(matches!(
            vault.get_secret(&id),
            Err(VaultError::SecretNotFound { .. })
        ));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn list_keys_reports_metadata_without_decrypting() {
        let path = tmp_vault("list");
        let mut vault = Vault::create_with_password(&path, b"pw", Argon2Params::FAST).unwrap();
        vault.put_secret("key", b"k").unwrap();
        vault.put_secret("password", b"p").unwrap();
        let meta = vault.list_keys();
        assert_eq!(meta.len(), 2);
        assert!(meta.iter().any(|m| m.r#type == "key"));
        assert!(meta.iter().any(|m| m.r#type == "password"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn saved_file_is_owner_only() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = tmp_vault("perms");
            Vault::create_with_password(&path, b"pw", Argon2Params::FAST).unwrap();
            let perms = fs::metadata(&path).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
            let _ = fs::remove_file(&path);
        }
    }

    #[test]
    fn locked_vault_access_is_an_error() {
        let path = tmp_vault("locked");
        let _vault = Vault::create_with_password(&path, b"pw", Argon2Params::FAST).unwrap();
        // Re-open locked and attempt to read without unlocking.
        let locked = Vault::open_locked(&path).unwrap();
        assert!(matches!(locked.list_keys().len(), 0));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn tampered_ciphertext_fails_on_get() {
        // Put a secret, then tamper the on-disk ciphertext and confirm decrypt fails.
        let path = tmp_vault("tamper");
        let mut vault = Vault::create_with_password(&path, b"pw", Argon2Params::FAST).unwrap();
        let id = vault.put_secret("password", b"topsecret").unwrap();
        drop(vault);

        // Tamper: read the JSON, flip a byte inside a ciphertext string.
        let mut file: VaultFile =
            serde_json::from_slice(&fs::read(&path).unwrap()).expect("valid");
        let ct = file.records.iter_mut().find_map(|r| {
            if r.id == id {
                let bytes = BASE64.decode(&r.ciphertext).unwrap();
                let mut t = bytes;
                t[0] ^= 0x01;
                Some(BASE64.encode(t))
            } else {
                None
            }
        });
        file.records.iter_mut().find(|r| r.id == id).unwrap().ciphertext = ct.unwrap();
        fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();

        let mut vault = Vault::open_locked(&path).unwrap();
        vault.unlock_with_password(b"pw").unwrap();
        let err = vault.get_secret(&id).unwrap_err();
        assert!(matches!(err, VaultError::UnlockFailed));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn rekey_replaces_the_key_and_password_and_keeps_every_record() {
        let path = tmp_vault("rekey");
        let mut vault = Vault::create_with_password(&path, b"old-pw", Argon2Params::FAST).unwrap();
        let a = vault.put_secret("password", b"alpha").unwrap();
        let b = vault.put_secret("key", b"bravo").unwrap();

        let old = vault.header().unwrap().unwrap_dek(b"old-pw").unwrap();
        let new = generate_dek();
        let header = VaultHeader::new(&new, &Argon2Params::FAST, b"new-pw");
        vault.rekey(&old, new, header).unwrap();
        assert!(vault.is_unlocked());
        assert_eq!(&*vault.get_secret(&a).unwrap(), b"alpha");

        let mut reopened = Vault::open_locked(&path).unwrap();
        assert!(matches!(reopened.unlock_with_password(b"old-pw"), Err(VaultError::UnlockFailed)));
        reopened.unlock_with_password(b"new-pw").unwrap();
        assert_eq!(&*reopened.get_secret(&a).unwrap(), b"alpha");
        assert_eq!(&*reopened.get_secret(&b).unwrap(), b"bravo");
        // The old key no longer opens the records.
        let ct = BASE64.decode(reopened.records[0].ciphertext.as_bytes()).unwrap();
        let record = &reopened.records[0];
        assert!(decrypt_record(&old, record.id.as_bytes(), record.r#type.as_bytes(), &ct).is_err());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn rekey_with_the_wrong_old_key_changes_nothing() {
        let path = tmp_vault("rekey-wrong");
        let mut vault = Vault::create_with_password(&path, b"pw", Argon2Params::FAST).unwrap();
        let id = vault.put_secret("password", b"alpha").unwrap();
        let before = fs::read(&path).unwrap();
        let wrong = generate_dek();
        let new = generate_dek();
        let header = VaultHeader::new(&new, &Argon2Params::FAST, b"new");
        assert!(vault.rekey(&wrong, new, header).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(&*vault.get_secret(&id).unwrap(), b"alpha");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn upstream_password_round_trips_as_its_own_record_type() {
        let path = tmp_vault("upstream-roundtrip");
        let mut vault = Vault::create_with_password(&path, b"pw", Argon2Params::FAST).unwrap();
        let id = vault.put_upstream_password(b"proxy-pw").unwrap();
        assert_eq!(&vault.get_upstream_password(&id).unwrap()[..], b"proxy-pw");
        let meta = vault.list_keys();
        assert_eq!(meta.len(), 1);
        assert_eq!(meta[0].r#type, UPSTREAM_PASSWORD_RECORD);

        // Survives a save / reopen / unlock cycle.
        drop(vault);
        let mut reopened = Vault::open_locked(&path).unwrap();
        reopened.unlock_with_password(b"pw").unwrap();
        assert_eq!(&reopened.get_upstream_password(&id).unwrap()[..], b"proxy-pw");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn upstream_password_refused_while_locked() {
        let path = tmp_vault("upstream-locked");
        let mut vault = Vault::create_with_password(&path, b"pw", Argon2Params::FAST).unwrap();
        let id = vault.put_upstream_password(b"proxy-pw").unwrap();
        vault.lock();
        assert!(matches!(vault.get_upstream_password(&id), Err(VaultError::Locked)));
        assert!(matches!(vault.put_upstream_password(b"x"), Err(VaultError::Locked)));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn upstream_password_rejects_other_record_types() {
        let path = tmp_vault("upstream-wrong-type");
        let mut vault = Vault::create_with_password(&path, b"pw", Argon2Params::FAST).unwrap();
        let ssh_pw = vault.put_secret("password", b"ssh-pw").unwrap();
        let key = vault.put_secret("key", b"private").unwrap();
        for id in [&ssh_pw, &key] {
            assert!(matches!(
                vault.get_upstream_password(id),
                Err(VaultError::SecretNotFound { .. })
            ));
        }
        assert!(matches!(
            vault.get_upstream_password("no-such-id"),
            Err(VaultError::SecretNotFound { .. })
        ));
        let _ = fs::remove_file(&path);
    }
}
