//! A sealed, read-only, in-process agent holding only the keys assigned to one hop.
//!
//! The key set is fixed at construction. Only listing and signing are possible; there is no
//! code path that adds, removes, or exports a key, and it never touches `SSH_AUTH_SOCK`.

use std::fmt;
use std::sync::Arc;

use russh::keys::signature::Signer;
use russh::keys::ssh_key::Signature;
use russh::keys::{HashAlg, PrivateKey, PublicKey};
use thiserror::Error;

/// Agent operations that are always refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationOp {
    AddIdentity,
    RemoveIdentity,
    RemoveAll,
    Lock,
    Unlock,
}

/// A request to the agent, mirroring the ssh-agent protocol's operations.
#[derive(Debug, Clone)]
pub enum AgentRequest {
    RequestIdentities,
    Sign { key: PublicKey, data: Vec<u8> },
    Mutate(MutationOp),
}

/// The reply to an [`AgentRequest`].
#[derive(Debug, Clone)]
pub enum AgentResponse {
    Identities(Vec<AgentIdentity>),
    Signature(Signature),
}

/// A public identity the agent can sign with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentIdentity {
    pub public_key: PublicKey,
    pub comment: String,
}

/// Why the agent refused a request.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AgentError {
    #[error("agent is read-only: {0:?} refused")]
    ReadOnly(MutationOp),
    #[error("key {0} is not assigned to this hop")]
    KeyNotAssigned(String),
    #[error("signing failed")]
    SignFailed,
}

/// One signature attempt, passed to the audit callback. Never contains the signed data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignAudit {
    pub hop_id: String,
    pub key_sha256: String,
    pub data_len: usize,
    pub allowed: bool,
}

/// Receives every signature attempt, allowed or refused.
pub type SignAuditFn = Arc<dyn Fn(&SignAudit) + Send + Sync>;

struct AgentKey {
    key: Arc<PrivateKey>,
    comment: String,
}

/// See the [module docs](self). Clones share the same sealed key set.
#[derive(Clone)]
pub struct ScopedAgent {
    hop_id: Arc<str>,
    keys: Arc<[AgentKey]>,
    audit: Option<SignAuditFn>,
}

impl fmt::Debug for ScopedAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopedAgent")
            .field("hop_id", &self.hop_id)
            .field("keys", &self.keys.len())
            .field("audit", &self.audit.is_some())
            .finish()
    }
}

impl ScopedAgent {
    /// Seals `keys` (key, comment) for `hop_id`. The set cannot change afterwards.
    pub fn seal(
        hop_id: impl Into<String>,
        keys: impl IntoIterator<Item = (Arc<PrivateKey>, String)>,
        audit: Option<SignAuditFn>,
    ) -> Self {
        Self {
            hop_id: Arc::from(hop_id.into()),
            keys: keys
                .into_iter()
                .map(|(key, comment)| AgentKey { key, comment })
                .collect(),
            audit,
        }
    }

    /// The hop this agent is scoped to.
    pub fn hop_id(&self) -> &str {
        &self.hop_id
    }

    /// Public identities of the assigned keys.
    pub fn list_identities(&self) -> Vec<AgentIdentity> {
        self.keys
            .iter()
            .map(|k| AgentIdentity {
                public_key: k.key.public_key().clone(),
                comment: k.comment.clone(),
            })
            .collect()
    }

    /// Signs `data` with an assigned key, reporting the attempt to the audit callback.
    pub fn sign(&self, key: &PublicKey, data: &[u8]) -> Result<Signature, AgentError> {
        let key_sha256 = key.fingerprint(HashAlg::Sha256).to_string();
        let assigned = self
            .keys
            .iter()
            .find(|k| k.key.public_key().key_data() == key.key_data());

        if let Some(audit) = &self.audit {
            audit(&SignAudit {
                hop_id: self.hop_id.to_string(),
                key_sha256: key_sha256.clone(),
                data_len: data.len(),
                allowed: assigned.is_some(),
            });
        }

        let assigned = assigned.ok_or(AgentError::KeyNotAssigned(key_sha256))?;
        assigned
            .key
            .as_ref()
            .try_sign(data)
            .map_err(|_| AgentError::SignFailed)
    }

    /// Handles one request. Every mutation is refused.
    pub fn handle(&self, request: AgentRequest) -> Result<AgentResponse, AgentError> {
        match request {
            AgentRequest::RequestIdentities => {
                Ok(AgentResponse::Identities(self.list_identities()))
            }
            AgentRequest::Sign { key, data } => self.sign(&key, &data).map(AgentResponse::Signature),
            AgentRequest::Mutate(op) => Err(AgentError::ReadOnly(op)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use conduit_vault::{generate_key, KeyGenAlgorithm};
    use russh::keys::signature::Verifier;
    use std::sync::Mutex;

    fn key(algo: KeyGenAlgorithm) -> Arc<PrivateKey> {
        Arc::new(generate_key(algo).unwrap().0)
    }

    #[test]
    fn lists_only_assigned_keys() {
        let assigned = key(KeyGenAlgorithm::Ed25519);
        let agent = ScopedAgent::seal("hop", [(assigned.clone(), "work".to_string())], None);
        let ids = agent.list_identities();
        assert_eq!(ids.len(), 1);
        assert_eq!(&ids[0].public_key, assigned.public_key());
        assert_eq!(ids[0].comment, "work");
        assert_eq!(agent.hop_id(), "hop");
    }

    #[test]
    fn signs_with_assigned_keys_of_each_algorithm() {
        for algo in [KeyGenAlgorithm::Ed25519, KeyGenAlgorithm::EcdsaP256] {
            let k = key(algo);
            let agent = ScopedAgent::seal("hop", [(k.clone(), String::new())], None);
            let sig = agent.sign(k.public_key(), b"payload").unwrap();
            k.public_key().key_data().verify(b"payload", &sig).unwrap();
            assert!(k.public_key().key_data().verify(b"tampered", &sig).is_err());
        }
    }

    #[test]
    fn refuses_keys_not_assigned_to_this_hop() {
        let agent = ScopedAgent::seal(
            "hop",
            [(key(KeyGenAlgorithm::Ed25519), String::new())],
            None,
        );
        let other = key(KeyGenAlgorithm::Ed25519);
        assert!(matches!(
            agent.sign(other.public_key(), b"x"),
            Err(AgentError::KeyNotAssigned(_))
        ));
    }

    #[test]
    fn every_mutation_is_refused_and_keys_are_unchanged() {
        let agent = ScopedAgent::seal(
            "hop",
            [(key(KeyGenAlgorithm::Ed25519), String::new())],
            None,
        );
        for op in [
            MutationOp::AddIdentity,
            MutationOp::RemoveIdentity,
            MutationOp::RemoveAll,
            MutationOp::Lock,
            MutationOp::Unlock,
        ] {
            assert_eq!(
                agent.handle(AgentRequest::Mutate(op)).unwrap_err(),
                AgentError::ReadOnly(op)
            );
        }
        assert_eq!(agent.list_identities().len(), 1);
    }

    #[test]
    fn handle_serves_read_only_requests() {
        let k = key(KeyGenAlgorithm::Ed25519);
        let agent = ScopedAgent::seal("hop", [(k.clone(), String::new())], None);
        assert!(matches!(
            agent.handle(AgentRequest::RequestIdentities),
            Ok(AgentResponse::Identities(ids)) if ids.len() == 1
        ));
        let request = AgentRequest::Sign {
            key: k.public_key().clone(),
            data: b"data".to_vec(),
        };
        assert!(matches!(
            agent.handle(request),
            Ok(AgentResponse::Signature(_))
        ));
    }

    #[test]
    fn audit_records_allowed_and_refused_signatures_without_data() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&events);
        let audit: SignAuditFn = Arc::new(move |e: &SignAudit| sink.lock().unwrap().push(e.clone()));
        let k = key(KeyGenAlgorithm::Ed25519);
        let other = key(KeyGenAlgorithm::Ed25519);
        let agent = ScopedAgent::seal("hop", [(k.clone(), String::new())], Some(audit));

        agent.sign(k.public_key(), b"12345").unwrap();
        agent.sign(other.public_key(), b"123").unwrap_err();

        let events = events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert!(events[0].allowed);
        assert_eq!(events[0].data_len, 5);
        assert_eq!(
            events[0].key_sha256,
            k.public_key().fingerprint(HashAlg::Sha256).to_string()
        );
        assert!(!events[1].allowed);
        assert_eq!(events[1].hop_id, "hop");
    }

    #[test]
    fn debug_output_contains_no_key_material() {
        let k = key(KeyGenAlgorithm::Ed25519);
        let agent = ScopedAgent::seal("hop", [(k, "secret-comment".to_string())], None);
        let text = format!("{agent:?}");
        assert!(text.contains("keys: 1"));
        assert!(!text.contains("secret-comment"));
    }
}
