//! Renders the app-owned `known_hosts` file. Never touches `~/.ssh/known_hosts`.

use std::collections::HashSet;
use std::io;
use std::path::{Component, Path};

use conduit_core::KnownHostsStore;
use ring::digest::{digest, SHA256};

use crate::runtime_dir::write_private_file;

/// A hop's identity: `(hop_id, host, port)`.
pub type HopKey<'a> = (&'a str, &'a str, u16);

/// The stable `HostKeyAlias` (`rc-<hex>`) for a hop.
///
/// Fields are length-prefixed so different triples can never hash the same input.
pub fn host_key_alias(hop_id: &str, host: &str, port: u16) -> String {
    let mut input = Vec::with_capacity(hop_id.len() + host.len() + 18);
    for field in [hop_id, host] {
        input.extend_from_slice(&(field.len() as u64).to_be_bytes());
        input.extend_from_slice(field.as_bytes());
    }
    input.extend_from_slice(&port.to_be_bytes());
    let hash = digest(&SHA256, &input);
    format!("rc-{}", crate::hex(&hash.as_ref()[..16]))
}

/// Renders `<alias> <public_key_openssh>` for each listed hop with an approved, well-formed key.
pub fn render_known_hosts(store: &KnownHostsStore, hops: &[HopKey<'_>]) -> String {
    let mut seen = HashSet::new();
    let mut out = String::new();
    for &(hop_id, host, port) in hops {
        if !seen.insert((hop_id, host, port)) {
            continue;
        }
        let Some(record) = store.get(hop_id, host, port) else {
            continue;
        };
        if !record.approved {
            continue;
        }
        let Some(key) = record.public_key_openssh.as_deref() else {
            continue;
        };
        if !is_valid_public_key(key) {
            continue;
        }
        out.push_str(&host_key_alias(hop_id, host, port));
        out.push(' ');
        out.push_str(key);
        out.push('\n');
    }
    out
}

/// Writes the rendered file with mode `0600`. Refuses any path inside a `.ssh` directory.
pub fn write_known_hosts(
    path: &Path,
    store: &KnownHostsStore,
    hops: &[HopKey<'_>],
) -> io::Result<()> {
    let in_ssh_dir = path
        .components()
        .any(|c| matches!(c, Component::Normal(name) if name == ".ssh"));
    if in_ssh_dir {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing to write known_hosts inside a .ssh directory",
        ));
    }
    write_private_file(path, render_known_hosts(store, hops).as_bytes())
}

/// Accepts exactly `<algorithm> <base64>`, so a stored value cannot add a line or a marker.
fn is_valid_public_key(key: &str) -> bool {
    let Some((algorithm, blob)) = key.split_once(' ') else {
        return false;
    };
    let algorithm_ok = !algorithm.is_empty()
        && algorithm.starts_with(|c: char| c.is_ascii_alphabetic())
        && algorithm
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '@'));
    let blob_ok = !blob.is_empty()
        && blob
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='));
    algorithm_ok && blob_ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_dir::RuntimeDir;
    use conduit_core::{HostKeyLookup, HostKeyRecord, Timestamp};

    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA+b/c=";

    fn record(approved: bool, key: Option<&str>) -> HostKeyRecord {
        HostKeyRecord {
            algorithm: "ssh-ed25519".into(),
            fingerprint_sha256: "SHA256:abc".into(),
            first_seen: Timestamp(1),
            approved,
            public_key_openssh: key.map(str::to_string),
        }
    }

    fn store(entries: &[(&str, HostKeyRecord)]) -> KnownHostsStore {
        let mut store = KnownHostsStore::default();
        for (hop_id, record) in entries {
            store.insert(
                HostKeyLookup {
                    hop_id: (*hop_id).into(),
                    host: "h".into(),
                    port: 22,
                },
                record.clone(),
            );
        }
        store
    }

    #[test]
    fn known_hosts_alias_is_deterministic_and_distinct() {
        let alias = host_key_alias("hop", "example.com", 22);
        assert_eq!(alias, host_key_alias("hop", "example.com", 22));
        assert!(alias.starts_with("rc-"));
        assert_eq!(alias.len(), 35);
        assert!(alias[3..].chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(alias, host_key_alias("hop2", "example.com", 22));
        assert_ne!(alias, host_key_alias("hop", "example.org", 22));
        assert_ne!(alias, host_key_alias("hop", "example.com", 2222));
        assert_ne!(host_key_alias("ab", "c", 22), host_key_alias("a", "bc", 22));
    }

    #[test]
    fn known_hosts_renders_only_approved_keys_for_listed_hops() {
        let store = store(&[
            ("good", record(true, Some(KEY))),
            ("unapproved", record(false, Some(KEY))),
            ("legacy", record(true, None)),
            ("unlisted", record(true, Some(KEY))),
        ]);
        let hops = [
            ("good", "h", 22),
            ("good", "h", 22),
            ("unapproved", "h", 22),
            ("legacy", "h", 22),
            ("absent", "h", 22),
        ];
        let expected = format!("{} {KEY}\n", host_key_alias("good", "h", 22));
        assert_eq!(render_known_hosts(&store, &hops), expected);
    }

    #[test]
    fn known_hosts_skips_keys_that_could_inject_lines() {
        for bad in [
            "ssh-ed25519 AAAA\nevil ssh-ed25519 BBBB",
            "ssh-ed25519 AAAA comment",
            "@revoked ssh-ed25519",
            "ssh-ed25519",
            " ssh-ed25519 AAAA",
            "ssh-ed25519 ",
        ] {
            let store = store(&[("hop", record(true, Some(bad)))]);
            assert_eq!(render_known_hosts(&store, &[("hop", "h", 22)]), "", "{bad}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn known_hosts_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = RuntimeDir::create().unwrap();
        let path = dir.path().join("known_hosts");
        let store = store(&[("hop", record(true, Some(KEY)))]);
        write_known_hosts(&path, &store, &[("hop", "h", 22)]).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .ends_with(&format!("{KEY}\n")));
    }

    #[test]
    fn known_hosts_write_refuses_ssh_directories() {
        let dir = RuntimeDir::create().unwrap();
        let path = dir.path().join(".ssh").join("known_hosts");
        let error = write_known_hosts(&path, &KnownHostsStore::default(), &[]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!path.exists());
    }
}
