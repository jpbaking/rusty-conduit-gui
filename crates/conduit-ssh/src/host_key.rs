//! Strict host-key pinning against the app-owned [`KnownHostsStore`].
//!
//! Never reads `~/.ssh/known_hosts`. Nothing here writes a pin: trust is only granted by a
//! user approval recorded in the store.

use std::sync::{Arc, RwLock};

use conduit_core::KnownHostsStore;
use russh::keys::{HashAlg, PublicKeyOrCertificate};

use crate::error::SshError;

/// The key a server presented, reduced to what pinning compares and displays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedHostKey {
    pub algorithm: String,
    /// `SHA256:<base64>`, matching `ssh-keygen -l`.
    pub sha256: String,
}

impl ObservedHostKey {
    /// Reads the key. A certificate is pinned by its subject key; its CA is not trusted.
    pub fn from_server_key(key: &PublicKeyOrCertificate) -> Self {
        match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => Self {
                algorithm: key.algorithm().as_str().to_string(),
                sha256: key.fingerprint(HashAlg::Sha256).to_string(),
            },
            PublicKeyOrCertificate::Certificate(cert) => Self {
                algorithm: cert.algorithm().as_str().to_string(),
                sha256: cert.public_key().fingerprint(HashAlg::Sha256).to_string(),
            },
        }
    }
}

/// The result of comparing an observed key with the pin store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyDecision {
    /// Fingerprint matches an approved pin.
    Trusted,
    /// No pin exists, or the matching pin is not approved yet.
    Unknown,
    /// Fingerprint differs from the recorded pin, approved or not.
    Changed { expected_sha256: String },
}

/// Which hop a host-key check is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HopIdentity {
    pub hop_index: usize,
    pub hop_id: String,
    pub host: String,
    pub port: u16,
}

/// Checks server keys against a shared store, so an approval applies to the next attempt.
#[derive(Debug, Clone, Default)]
pub struct HostKeyVerifier {
    store: Arc<RwLock<KnownHostsStore>>,
}

impl HostKeyVerifier {
    pub fn new(store: KnownHostsStore) -> Self {
        Self::from_shared(Arc::new(RwLock::new(store)))
    }

    pub fn from_shared(store: Arc<RwLock<KnownHostsStore>>) -> Self {
        Self { store }
    }

    /// The shared store, for recording a user approval.
    pub fn store(&self) -> Arc<RwLock<KnownHostsStore>> {
        Arc::clone(&self.store)
    }

    /// Compare `observed` with the pin for `(hop_id, host, port)`.
    ///
    /// A poisoned store lock reads as [`HostKeyDecision::Unknown`], which never grants trust.
    pub fn decide(
        &self,
        hop_id: &str,
        host: &str,
        port: u16,
        observed: &ObservedHostKey,
    ) -> HostKeyDecision {
        let Ok(store) = self.store.read() else {
            return HostKeyDecision::Unknown;
        };
        match store.get(hop_id, host, port) {
            None => HostKeyDecision::Unknown,
            Some(pin) if pin.fingerprint_sha256 != observed.sha256 => HostKeyDecision::Changed {
                expected_sha256: pin.fingerprint_sha256.clone(),
            },
            Some(pin) if pin.approved => HostKeyDecision::Trusted,
            Some(_) => HostKeyDecision::Unknown,
        }
    }

    /// Returns `Ok` only for a trusted key, otherwise the typed host-key error.
    pub fn enforce(&self, hop: &HopIdentity, observed: &ObservedHostKey) -> Result<(), SshError> {
        match self.decide(&hop.hop_id, &hop.host, hop.port, observed) {
            HostKeyDecision::Trusted => Ok(()),
            HostKeyDecision::Unknown => Err(SshError::HostKeyUnknown {
                hop_index: hop.hop_index,
                hop_id: hop.hop_id.clone(),
                host: hop.host.clone(),
                port: hop.port,
                algorithm: observed.algorithm.clone(),
                sha256: observed.sha256.clone(),
            }),
            HostKeyDecision::Changed { expected_sha256 } => Err(SshError::HostKeyChanged {
                hop_index: hop.hop_index,
                hop_id: hop.hop_id.clone(),
                host: hop.host.clone(),
                port: hop.port,
                algorithm: observed.algorithm.clone(),
                expected_sha256,
                sha256: observed.sha256.clone(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use conduit_core::{HostKeyLookup, HostKeyRecord, Timestamp};

    fn observed(fp: &str) -> ObservedHostKey {
        ObservedHostKey {
            algorithm: "ssh-ed25519".into(),
            sha256: fp.into(),
        }
    }

    fn verifier_with(fp: &str, approved: bool) -> HostKeyVerifier {
        let mut store = KnownHostsStore::default();
        store.insert(
            HostKeyLookup {
                hop_id: "hop-a".into(),
                host: "example.test".into(),
                port: 22,
            },
            HostKeyRecord {
                algorithm: "ssh-ed25519".into(),
                fingerprint_sha256: fp.into(),
                first_seen: Timestamp(1),
                approved,
            },
        );
        HostKeyVerifier::new(store)
    }

    fn hop() -> HopIdentity {
        HopIdentity {
            hop_index: 2,
            hop_id: "hop-a".into(),
            host: "example.test".into(),
            port: 22,
        }
    }

    #[test]
    fn approved_matching_pin_is_trusted() {
        let v = verifier_with("SHA256:good", true);
        assert_eq!(
            v.decide("hop-a", "example.test", 22, &observed("SHA256:good")),
            HostKeyDecision::Trusted
        );
        assert!(v.enforce(&hop(), &observed("SHA256:good")).is_ok());
    }

    #[test]
    fn missing_pin_is_unknown_and_reports_details() {
        let v = HostKeyVerifier::default();
        match v.enforce(&hop(), &observed("SHA256:new")) {
            Err(SshError::HostKeyUnknown {
                hop_index,
                hop_id,
                host,
                port,
                algorithm,
                sha256,
            }) => {
                assert_eq!(
                    (hop_index, hop_id.as_str(), host.as_str(), port),
                    (2, "hop-a", "example.test", 22)
                );
                assert_eq!(algorithm, "ssh-ed25519");
                assert_eq!(sha256, "SHA256:new");
            }
            other => panic!("expected HostKeyUnknown, got {other:?}"),
        }
    }

    #[test]
    fn unapproved_pin_is_never_trusted() {
        let v = verifier_with("SHA256:good", false);
        assert_eq!(
            v.decide("hop-a", "example.test", 22, &observed("SHA256:good")),
            HostKeyDecision::Unknown
        );
    }

    #[test]
    fn changed_key_is_a_hard_stop_even_when_pin_is_unapproved() {
        for approved in [true, false] {
            let v = verifier_with("SHA256:good", approved);
            match v.enforce(&hop(), &observed("SHA256:evil")) {
                Err(SshError::HostKeyChanged {
                    expected_sha256,
                    sha256,
                    ..
                }) => {
                    assert_eq!(expected_sha256, "SHA256:good");
                    assert_eq!(sha256, "SHA256:evil");
                }
                other => panic!("expected HostKeyChanged, got {other:?}"),
            }
        }
    }

    #[test]
    fn pins_are_scoped_to_hop_host_and_port() {
        let v = verifier_with("SHA256:good", true);
        let key = observed("SHA256:good");
        for (hop_id, host, port) in [
            ("hop-b", "example.test", 22),
            ("hop-a", "other.test", 22),
            ("hop-a", "example.test", 2222),
        ] {
            assert_eq!(v.decide(hop_id, host, port, &key), HostKeyDecision::Unknown);
        }
    }

    #[test]
    fn approval_through_shared_store_applies_to_next_check() {
        let v = HostKeyVerifier::default();
        let key = observed("SHA256:good");
        assert_eq!(
            v.decide("hop-a", "example.test", 22, &key),
            HostKeyDecision::Unknown
        );
        v.store().write().unwrap().insert(
            HostKeyLookup {
                hop_id: "hop-a".into(),
                host: "example.test".into(),
                port: 22,
            },
            HostKeyRecord {
                algorithm: key.algorithm.clone(),
                fingerprint_sha256: key.sha256.clone(),
                first_seen: Timestamp(1),
                approved: true,
            },
        );
        assert_eq!(
            v.decide("hop-a", "example.test", 22, &key),
            HostKeyDecision::Trusted
        );
    }
}
