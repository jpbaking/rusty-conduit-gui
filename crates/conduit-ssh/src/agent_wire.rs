//! The read-only subset of the OpenSSH `ssh-agent` wire protocol, served over [`ScopedAgent`].
//!
//! Each message is a 4-byte big-endian length, a 1-byte type, and a payload. Only listing and
//! signing can succeed. Every other message type gets `SSH_AGENT_FAILURE`.

use std::io;

use russh::keys::ssh_key::Algorithm;
use russh::keys::{HashAlg, PublicKey};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::agent::{AgentRequest, AgentResponse, MutationOp, ScopedAgent};

pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
pub const SSH_AGENTC_ADD_IDENTITY: u8 = 17;
pub const SSH_AGENTC_REMOVE_IDENTITY: u8 = 18;
pub const SSH_AGENTC_REMOVE_ALL_IDENTITIES: u8 = 19;
pub const SSH_AGENTC_LOCK: u8 = 22;
pub const SSH_AGENTC_UNLOCK: u8 = 23;
pub const SSH_AGENTC_ADD_ID_CONSTRAINED: u8 = 25;

const SSH_AGENT_RSA_SHA2_256: u32 = 2;
const SSH_AGENT_RSA_SHA2_512: u32 = 4;

/// Largest accepted message, so a hostile host cannot force a large allocation.
pub const MAX_PACKET_LEN: usize = 256 * 1024;

/// A message length the relay refuses to read.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireError {
    #[error("invalid agent message length {0}")]
    InvalidLength(usize),
}

/// Validates a length prefix before any payload is allocated.
pub fn frame_len(header: [u8; 4]) -> Result<usize, WireError> {
    let len = u32::from_be_bytes(header) as usize;
    if len == 0 || len > MAX_PACKET_LEN {
        return Err(WireError::InvalidLength(len));
    }
    Ok(len)
}

/// Answers one unframed message (type byte plus payload) with one framed reply.
pub fn respond(agent: &ScopedAgent, message: &[u8]) -> Vec<u8> {
    let Some((&kind, payload)) = message.split_first() else {
        return failure();
    };
    match kind {
        SSH_AGENTC_REQUEST_IDENTITIES if payload.is_empty() => identities(agent),
        SSH_AGENTC_SIGN_REQUEST => sign(agent, payload),
        _ => {
            if let Some(op) = mutation(kind) {
                // The agent refuses every mutation. The call keeps that rule in one place.
                let _ = agent.handle(AgentRequest::Mutate(op));
            }
            failure()
        }
    }
}

/// Serves requests until the peer closes the stream or sends an invalid length.
pub async fn serve<S>(stream: &mut S, agent: &ScopedAgent) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let mut header = [0u8; 4];
        match stream.read_exact(&mut header).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        }
        let len =
            frame_len(header).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let mut message = vec![0u8; len];
        stream.read_exact(&mut message).await?;
        stream.write_all(&respond(agent, &message)).await?;
        stream.flush().await?;
    }
}

fn mutation(kind: u8) -> Option<MutationOp> {
    match kind {
        SSH_AGENTC_ADD_IDENTITY | SSH_AGENTC_ADD_ID_CONSTRAINED => Some(MutationOp::AddIdentity),
        SSH_AGENTC_REMOVE_IDENTITY => Some(MutationOp::RemoveIdentity),
        SSH_AGENTC_REMOVE_ALL_IDENTITIES => Some(MutationOp::RemoveAll),
        SSH_AGENTC_LOCK => Some(MutationOp::Lock),
        SSH_AGENTC_UNLOCK => Some(MutationOp::Unlock),
        _ => None,
    }
}

fn identities(agent: &ScopedAgent) -> Vec<u8> {
    let Ok(AgentResponse::Identities(ids)) = agent.handle(AgentRequest::RequestIdentities) else {
        return failure();
    };
    let mut body = vec![SSH_AGENT_IDENTITIES_ANSWER];
    body.extend_from_slice(&(ids.len() as u32).to_be_bytes());
    for id in ids {
        let Ok(blob) = id.public_key.to_bytes() else {
            return failure();
        };
        put_string(&mut body, &blob);
        put_string(&mut body, id.comment.as_bytes());
    }
    frame(&body)
}

fn sign(agent: &ScopedAgent, payload: &[u8]) -> Vec<u8> {
    let Some((blob, data, flags)) = parse_sign(payload) else {
        agent.audit_unparseable_sign(payload.len());
        return failure();
    };
    let Ok(key) = PublicKey::from_bytes(blob) else {
        agent.audit_unparseable_sign(data.len());
        return failure();
    };
    let request = AgentRequest::Sign {
        key,
        data: data.to_vec(),
    };
    let Ok(AgentResponse::Signature(signature)) = agent.handle(request) else {
        return failure();
    };
    if !satisfies_rsa_flags(signature.algorithm(), flags) {
        return failure();
    }
    let Ok(encoded) = Vec::<u8>::try_from(signature) else {
        return failure();
    };
    let mut body = vec![SSH_AGENT_SIGN_RESPONSE];
    put_string(&mut body, &encoded);
    frame(&body)
}

/// An RSA signature must use the hash the client asked for, or the server would reject it.
fn satisfies_rsa_flags(algorithm: Algorithm, flags: u32) -> bool {
    let Algorithm::Rsa { hash } = algorithm else {
        return true;
    };
    let wanted = if flags & SSH_AGENT_RSA_SHA2_256 != 0 {
        Some(HashAlg::Sha256)
    } else if flags & SSH_AGENT_RSA_SHA2_512 != 0 {
        Some(HashAlg::Sha512)
    } else {
        None
    };
    hash == wanted
}

fn parse_sign(payload: &[u8]) -> Option<(&[u8], &[u8], u32)> {
    let mut rest = payload;
    let blob = take_string(&mut rest)?;
    let data = take_string(&mut rest)?;
    let flags = take_u32(&mut rest)?;
    rest.is_empty().then_some((blob, data, flags))
}

fn take_u32(input: &mut &[u8]) -> Option<u32> {
    let (head, tail) = input.split_first_chunk::<4>()?;
    *input = tail;
    Some(u32::from_be_bytes(*head))
}

fn take_string<'a>(input: &mut &'a [u8]) -> Option<&'a [u8]> {
    let mut rest = *input;
    let len = take_u32(&mut rest)? as usize;
    let value = rest.get(..len)?;
    *input = &rest[len..];
    Some(value)
}

fn put_string(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn frame(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 4);
    put_string(&mut out, body);
    out
}

fn failure() -> Vec<u8> {
    frame(&[SSH_AGENT_FAILURE])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{SignAudit, SignAuditFn};
    use conduit_vault::{generate_key, KeyGenAlgorithm};
    use russh::keys::signature::Verifier;
    use russh::keys::ssh_key::Signature;
    use russh::keys::PrivateKey;
    use std::sync::{Arc, Mutex};

    fn key() -> Arc<PrivateKey> {
        Arc::new(generate_key(KeyGenAlgorithm::Ed25519).unwrap().0)
    }

    fn sign_request(key: &PublicKey, data: &[u8]) -> Vec<u8> {
        let mut message = vec![SSH_AGENTC_SIGN_REQUEST];
        put_string(&mut message, &key.to_bytes().unwrap());
        put_string(&mut message, data);
        message.extend_from_slice(&0u32.to_be_bytes());
        message
    }

    fn recording_agent(k: &Arc<PrivateKey>) -> (ScopedAgent, Arc<Mutex<Vec<SignAudit>>>) {
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&events);
        let audit: SignAuditFn =
            Arc::new(move |e: &SignAudit| sink.lock().unwrap().push(e.clone()));
        let agent = ScopedAgent::seal("hop", [(k.clone(), "work".to_string())], Some(audit));
        (agent, events)
    }

    #[test]
    fn frame_len_rejects_zero_and_oversized() {
        assert_eq!(frame_len(1u32.to_be_bytes()), Ok(1));
        assert_eq!(
            frame_len((MAX_PACKET_LEN as u32).to_be_bytes()),
            Ok(MAX_PACKET_LEN)
        );
        assert!(frame_len(0u32.to_be_bytes()).is_err());
        assert!(frame_len((MAX_PACKET_LEN as u32 + 1).to_be_bytes()).is_err());
        assert!(frame_len(u32::MAX.to_be_bytes()).is_err());
    }

    #[test]
    fn identities_answer_lists_the_sealed_key() {
        let k = key();
        let (agent, _) = recording_agent(&k);
        let reply = respond(&agent, &[SSH_AGENTC_REQUEST_IDENTITIES]);
        let mut rest = &reply[4..];
        assert_eq!(rest[0], SSH_AGENT_IDENTITIES_ANSWER);
        rest = &rest[1..];
        assert_eq!(take_u32(&mut rest), Some(1));
        let blob = take_string(&mut rest).unwrap();
        assert_eq!(blob, k.public_key().to_bytes().unwrap());
        assert_eq!(take_string(&mut rest).unwrap(), b"work");
        assert!(rest.is_empty());
    }

    #[test]
    fn sign_response_verifies_and_is_audited() {
        let k = key();
        let (agent, events) = recording_agent(&k);
        let reply = respond(&agent, &sign_request(k.public_key(), b"challenge"));
        assert_eq!(reply[4], SSH_AGENT_SIGN_RESPONSE);
        let mut rest = &reply[5..];
        let encoded = take_string(&mut rest).unwrap();
        let signature = Signature::try_from(encoded).unwrap();
        k.public_key()
            .key_data()
            .verify(b"challenge", &signature)
            .unwrap();
        assert!(events.lock().unwrap()[0].allowed);
    }

    #[test]
    fn unassigned_key_fails_and_is_audited() {
        let k = key();
        let other = key();
        let (agent, events) = recording_agent(&k);
        assert_eq!(
            respond(&agent, &sign_request(other.public_key(), b"x")),
            failure()
        );
        assert!(!events.lock().unwrap()[0].allowed);
    }

    #[test]
    fn malformed_sign_requests_fail_and_are_audited() {
        let k = key();
        let (agent, events) = recording_agent(&k);
        let mut bad_blob = vec![SSH_AGENTC_SIGN_REQUEST];
        put_string(&mut bad_blob, b"not a key");
        put_string(&mut bad_blob, b"data");
        bad_blob.extend_from_slice(&0u32.to_be_bytes());
        let mut trailing = sign_request(k.public_key(), b"data");
        trailing.push(0);
        let oversized_string = [SSH_AGENTC_SIGN_REQUEST, 0xff, 0xff, 0xff, 0xff];

        for message in [&bad_blob[..], &trailing[..], &oversized_string[..]] {
            assert_eq!(respond(&agent, message), failure());
        }
        let events = events.lock().unwrap();
        assert_eq!(events.len(), 3);
        assert!(events.iter().all(|e| !e.allowed));
    }

    #[test]
    fn every_other_opcode_fails() {
        let k = key();
        let (agent, events) = recording_agent(&k);
        for kind in (0..=u8::MAX)
            .filter(|&b| b != SSH_AGENTC_REQUEST_IDENTITIES && b != SSH_AGENTC_SIGN_REQUEST)
        {
            assert_eq!(
                respond(&agent, &[kind, 1, 2, 3]),
                failure(),
                "opcode {kind}"
            );
        }
        assert!(events.lock().unwrap().is_empty());
        assert_eq!(agent.list_identities().len(), 1);
    }

    #[test]
    fn rsa_signatures_must_match_the_requested_hash() {
        let rsa = |hash| Algorithm::Rsa { hash };
        assert!(satisfies_rsa_flags(rsa(Some(HashAlg::Sha512)), 4));
        assert!(satisfies_rsa_flags(rsa(Some(HashAlg::Sha256)), 2));
        assert!(!satisfies_rsa_flags(rsa(Some(HashAlg::Sha512)), 2));
        assert!(!satisfies_rsa_flags(rsa(Some(HashAlg::Sha512)), 0));
        assert!(satisfies_rsa_flags(Algorithm::Ed25519, 2));
    }

    #[tokio::test]
    async fn serve_answers_then_stops_at_eof_and_on_oversized_frames() {
        let k = key();
        let (agent, _) = recording_agent(&k);

        let (mut client, mut server) = tokio::io::duplex(4096);
        let task_agent = agent.clone();
        let task = tokio::spawn(async move { serve(&mut server, &task_agent).await });
        client.write_all(&frame(&[SSH_AGENTC_LOCK])).await.unwrap();
        let mut reply = [0u8; 5];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[4], SSH_AGENT_FAILURE);
        drop(client);
        task.await.unwrap().unwrap();

        let (mut client, mut server) = tokio::io::duplex(64);
        let task = tokio::spawn(async move { serve(&mut server, &agent).await });
        client.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        let error = task.await.unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
