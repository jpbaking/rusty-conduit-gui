//! `conduit-core` — atomic JSON persistence for the app document (`config.json`) and the
//! app-owned known_hosts (`known_hosts.json`).
//!
//! Every write goes to a per-directory temp file, is flushed to disk (`sync_all`), and is
//! then renamed over the destination, so a crash mid-write never corrupts the live file.
//! Files are created `0600`; this crate never touches `~/.ssh/known_hosts`.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

use crate::model::{AppConfig, KnownHostsStore};

/// Errors raised while loading or saving app-owned JSON documents.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("failed to read {path}: {source}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse {path}: {source}")]
    ParseFile {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to write {path}: {source}")]
    WriteFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to rename {temp} onto {path}: {source}")]
    Rename {
        temp: PathBuf,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Write `value` to `path` atomically: temp file in the same directory, `sync_all`, then
/// `rename` over the destination. The final file is created `0600`.
fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), StorageError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| StorageError::WriteFile {
            path: path.to_path_buf(),
            source,
        })?;
    }

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let base = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("data.json")
        .to_string();
    let tmp_path = dir.join(format!(".{base}.{tmp}.json", tmp = Uuid::new_v4()));

    {
        let mut tmp = fs::File::create(&tmp_path).map_err(|source| StorageError::WriteFile {
            path: tmp_path.clone(),
            source,
        })?;
        let json = serde_json::to_vec_pretty(value).map_err(|source| StorageError::ParseFile {
            path: path.to_path_buf(),
            source,
        })?;
        tmp.write_all(&json).map_err(|source| StorageError::WriteFile {
            path: tmp_path.clone(),
            source,
        })?;
        tmp.sync_all().map_err(|source| StorageError::WriteFile {
            path: tmp_path.clone(),
            source,
        })?;
    }

    // Restrict the on-disk permissions to owner read/write (0600).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600)).map_err(|source| {
            StorageError::WriteFile {
                path: tmp_path.clone(),
                source,
            }
        })?;
    }

    fs::rename(&tmp_path, path).map_err(|source| StorageError::Rename {
        temp: tmp_path,
        path: path.to_path_buf(),
        source,
    })?;

    Ok(())
}

/// Load the app document (`config.json`) from `path`.
pub fn load_app_config(path: &Path) -> Result<AppConfig, StorageError> {
    let data = fs::read(path).map_err(|source| StorageError::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_slice(&data).map_err(|source| StorageError::ParseFile {
        path: path.to_path_buf(),
        source,
    })
}

/// Atomically save the app document (`config.json`) to `path`.
pub fn save_app_config(path: &Path, config: &AppConfig) -> Result<(), StorageError> {
    atomic_write_json(path, config)
}

/// Load the app-owned known_hosts (`known_hosts.json`) from `path`.
pub fn load_known_hosts(path: &Path) -> Result<KnownHostsStore, StorageError> {
    let data = fs::read(path).map_err(|source| StorageError::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_slice(&data).map_err(|source| StorageError::ParseFile {
        path: path.to_path_buf(),
        source,
    })
}

/// Atomically save the app-owned known_hosts (`known_hosts.json`) to `path`.
pub fn save_known_hosts(path: &Path, store: &KnownHostsStore) -> Result<(), StorageError> {
    atomic_write_json(path, store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HostKeyLookup, HostKeyRecord, SessionProfile, Timestamp};

    fn tmp_path(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("conduit-core-test-{}", Uuid::new_v4()));
        dir.join(tag)
    }

    #[test]
    fn app_config_round_trips() {
        let path = tmp_path("config.json");
        let mut config = AppConfig {
            schema_version: 1,
            ..Default::default()
        };
        config.sessions.push(SessionProfile::default());
        save_app_config(&path, &config).unwrap();

        let loaded = load_app_config(&path).unwrap();
        assert_eq!(loaded, config);
        assert_eq!(loaded.schema_version, 1);
        assert_eq!(loaded.sessions.len(), 1);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn known_hosts_round_trips() {
        let path = tmp_path("known_hosts.json");
        let mut store = KnownHostsStore::default();
        store.insert(
            HostKeyLookup {
                hop_id: "jump1".into(),
                host: "10.0.0.5".into(),
                port: 22,
            },
            HostKeyRecord {
                algorithm: "ssh-ed25519".into(),
                fingerprint_sha256: "SHA256:abc".into(),
                public_key_openssh: None,
                first_seen: Timestamp::now(),
                approved: false,
            },
        );
        save_known_hosts(&path, &store).unwrap();

        let loaded = load_known_hosts(&path).unwrap();
        assert_eq!(loaded, store);
        assert!(loaded.contains_key("jump1", "10.0.0.5", 22));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn missing_file_is_an_error() {
        let path = tmp_path("does-not-exist.json");
        assert!(matches!(
            load_app_config(&path),
            Err(StorageError::ReadFile { .. })
        ));
    }

    #[test]
    fn malformed_json_is_an_error() {
        let path = tmp_path("malformed.json");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, b"{ not json").unwrap();
        assert!(matches!(
            load_app_config(&path),
            Err(StorageError::ParseFile { .. })
        ));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn written_file_is_owner_only() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = tmp_path("perms.json");
            save_app_config(&path, &AppConfig::default()).unwrap();
            let perms = fs::metadata(&path).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
            let _ = fs::remove_file(&path);
        }
    }

    #[test]
    fn writes_create_parent_directories() {
        let path = tmp_path("nested/dir/config.json");
        save_app_config(&path, &AppConfig::default()).unwrap();
        assert!(path.exists());
        let _ = fs::remove_file(&path);
    }
}
