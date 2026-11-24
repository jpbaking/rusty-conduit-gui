//! Scoped agent forwarding over real SSH sessions against in-process servers.

// Each test binary uses a different subset of the shared helpers.
#[allow(dead_code)]
mod common;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use common::*;
use conduit_ssh::agent_wire::{
    SSH_AGENTC_REQUEST_IDENTITIES, SSH_AGENTC_SIGN_REQUEST, SSH_AGENT_FAILURE,
    SSH_AGENT_IDENTITIES_ANSWER, SSH_AGENT_SIGN_RESPONSE,
};
use conduit_ssh::{
    agent_policy, connect_chain, AgentForwardRelay, ScopedAgent, SignAudit, SignAuditFn, SshChain,
};
use russh::keys::signature::Verifier;
use russh::keys::ssh_key::Signature;
use russh::keys::{HashAlg, PrivateKey, PublicKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

type AuditLog = Arc<Mutex<Vec<SignAudit>>>;

/// Opcodes that would change a normal agent, plus smartcard, extension, and unknown types.
const REFUSED_OPCODES: [u8; 11] = [17, 18, 19, 20, 21, 22, 23, 25, 26, 27, 200];

fn scoped_agent(hop_id: &str, assigned: &PrivateKey) -> (ScopedAgent, AuditLog) {
    let log: AuditLog = Arc::default();
    let sink = Arc::clone(&log);
    let audit: SignAuditFn = Arc::new(move |e: &SignAudit| sink.lock().unwrap().push(e.clone()));
    let keys = [(Arc::new(assigned.clone()), "assigned".to_string())];
    (ScopedAgent::seal(hop_id, keys, Some(audit)), log)
}

/// Connects one hop with agent forwarding on, exposing only `assigned`.
async fn opted_in(
    node: &Node,
    login: &PrivateKey,
    assigned: &PrivateKey,
    command: Option<&str>,
) -> (SshChain, AgentForwardRelay, AuditLog) {
    let (policy, inbound) = agent_policy(4);
    let mut hop = spec(0, node, vec![key_auth(login)]);
    hop.policy = policy;
    let chain = connect_chain(&[hop], &pin_all(&[node]), &options(), None)
        .await
        .unwrap();
    let (agent, log) = scoped_agent("hop-0", assigned);
    let relay = AgentForwardRelay::start(chain.hop(0).unwrap(), 0, agent, inbound, command)
        .await
        .unwrap();
    (chain, relay, log)
}

async fn ask<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, message: &[u8]) -> Vec<u8> {
    stream
        .write_all(&(message.len() as u32).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(message).await.unwrap();
    stream.flush().await.unwrap();
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.unwrap();
    let mut reply = vec![0u8; u32::from_be_bytes(header) as usize];
    stream.read_exact(&mut reply).await.unwrap();
    reply
}

fn put_string(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn take_string<'a>(input: &mut &'a [u8]) -> &'a [u8] {
    let (len, rest) = input.split_first_chunk::<4>().unwrap();
    let (value, rest) = rest.split_at(u32::from_be_bytes(*len) as usize);
    *input = rest;
    value
}

fn sign_request(key: &PublicKey, data: &[u8]) -> Vec<u8> {
    let mut message = vec![SSH_AGENTC_SIGN_REQUEST];
    put_string(&mut message, &key.to_bytes().unwrap());
    put_string(&mut message, data);
    message.extend_from_slice(&0u32.to_be_bytes());
    message
}

fn identity_blobs(reply: &[u8]) -> Vec<Vec<u8>> {
    assert_eq!(reply[0], SSH_AGENT_IDENTITIES_ANSWER);
    let count = u32::from_be_bytes(reply[1..5].try_into().unwrap());
    let mut rest = &reply[5..];
    let blobs = (0..count)
        .map(|_| {
            let blob = take_string(&mut rest).to_vec();
            take_string(&mut rest);
            blob
        })
        .collect();
    assert!(rest.is_empty());
    blobs
}

#[tokio::test]
async fn opted_in_hop_exposes_only_its_key_and_signs() {
    let login = new_user_key();
    let assigned = new_user_key();
    let unassigned = new_user_key();
    let node = spawn_node(Some(login.public_key().clone())).await;
    let (chain, _relay, _log) = opted_in(&node, &login, &assigned, None).await;
    assert_eq!(node.state.agent_requests.load(Ordering::SeqCst), 1);

    let mut stream = node.open_agent_channel().await.unwrap().into_stream();
    let blobs = identity_blobs(&ask(&mut stream, &[SSH_AGENTC_REQUEST_IDENTITIES]).await);
    assert_eq!(blobs, vec![assigned.public_key().to_bytes().unwrap()]);
    assert!(!blobs.contains(&unassigned.public_key().to_bytes().unwrap()));
    assert!(!blobs.contains(&login.public_key().to_bytes().unwrap()));

    let reply = ask(
        &mut stream,
        &sign_request(assigned.public_key(), b"challenge"),
    )
    .await;
    assert_eq!(reply[0], SSH_AGENT_SIGN_RESPONSE);
    let mut rest = &reply[1..];
    let signature = Signature::try_from(take_string(&mut rest)).unwrap();
    let verifying = assigned.public_key().key_data();
    verifying.verify(b"challenge", &signature).unwrap();
    assert!(verifying.verify(b"tampered", &signature).is_err());

    for key in [unassigned.public_key(), login.public_key()] {
        let reply = ask(&mut stream, &sign_request(key, b"challenge")).await;
        assert_eq!(reply, [SSH_AGENT_FAILURE]);
    }
    chain.disconnect().await;
}

#[tokio::test]
async fn mutating_and_unknown_opcodes_fail_without_changing_keys() {
    let login = new_user_key();
    let assigned = new_user_key();
    let node = spawn_node(Some(login.public_key().clone())).await;
    let (chain, _relay, log) = opted_in(&node, &login, &assigned, None).await;

    let mut stream = node.open_agent_channel().await.unwrap().into_stream();
    for opcode in REFUSED_OPCODES {
        assert_eq!(
            ask(&mut stream, &[opcode]).await,
            [SSH_AGENT_FAILURE],
            "opcode {opcode}"
        );
    }
    let blobs = identity_blobs(&ask(&mut stream, &[SSH_AGENTC_REQUEST_IDENTITIES]).await);
    assert_eq!(blobs, vec![assigned.public_key().to_bytes().unwrap()]);
    let reply = ask(
        &mut stream,
        &sign_request(assigned.public_key(), b"still works"),
    )
    .await;
    assert_eq!(reply[0], SSH_AGENT_SIGN_RESPONSE);
    assert_eq!(log.lock().unwrap().len(), 1);
    chain.disconnect().await;
}

#[tokio::test]
async fn audit_records_every_sign_request() {
    let login = new_user_key();
    let assigned = new_user_key();
    let unassigned = new_user_key();
    let node = spawn_node(Some(login.public_key().clone())).await;
    let (chain, _relay, log) = opted_in(&node, &login, &assigned, None).await;

    let mut stream = node.open_agent_channel().await.unwrap().into_stream();
    ask(&mut stream, &sign_request(assigned.public_key(), b"12345")).await;
    ask(&mut stream, &sign_request(unassigned.public_key(), b"123")).await;
    let mut malformed = vec![SSH_AGENTC_SIGN_REQUEST];
    put_string(&mut malformed, b"not a key");
    put_string(&mut malformed, b"12");
    malformed.extend_from_slice(&0u32.to_be_bytes());
    assert_eq!(ask(&mut stream, &malformed).await, [SSH_AGENT_FAILURE]);

    let events = log.lock().unwrap().clone();
    assert_eq!(events.len(), 3);
    assert!(events.iter().all(|e| e.hop_id == "hop-0"));
    assert!(events[0].allowed);
    assert_eq!(events[0].data_len, 5);
    assert_eq!(
        events[0].key_sha256,
        assigned
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string()
    );
    assert!(!events[1].allowed);
    assert_eq!(
        events[1].key_sha256,
        unassigned
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string()
    );
    assert!(!events[2].allowed);
    assert_eq!(events[2].key_sha256, "unparseable");
    chain.disconnect().await;
}

#[tokio::test]
async fn only_the_opted_in_hop_accepts_agent_channels() {
    let login = new_user_key();
    let assigned = new_user_key();
    let jump = spawn_node(Some(login.public_key().clone())).await;
    let target = spawn_node(Some(login.public_key().clone())).await;

    let (policy, inbound) = agent_policy(4);
    let first = spec(0, &jump, vec![key_auth(&login)]);
    let mut second = spec(1, &target, vec![key_auth(&login)]);
    second.policy = policy;
    let chain = connect_chain(
        &[first, second],
        &pin_all(&[&jump, &target]),
        &options(),
        None,
    )
    .await
    .unwrap();
    let (agent, _log) = scoped_agent("hop-1", &assigned);
    let _relay = AgentForwardRelay::start(chain.hop(1).unwrap(), 1, agent, inbound, None)
        .await
        .unwrap();

    assert!(jump.open_agent_channel().await.is_err());
    assert_eq!(jump.state.agent_requests.load(Ordering::SeqCst), 0);

    let mut stream = target.open_agent_channel().await.unwrap().into_stream();
    let blobs = identity_blobs(&ask(&mut stream, &[SSH_AGENTC_REQUEST_IDENTITIES]).await);
    assert_eq!(blobs.len(), 1);
    chain.disconnect().await;
}

#[tokio::test]
async fn remote_command_runs_on_the_agent_session() {
    let login = new_user_key();
    let assigned = new_user_key();
    let node = spawn_node(Some(login.public_key().clone())).await;
    let (chain, _relay, _log) = opted_in(&node, &login, &assigned, Some("ssh-add -l")).await;

    assert_eq!(
        node.state.exec_commands.lock().unwrap().as_slice(),
        ["ssh-add -l"]
    );
    let mut stream = node.open_agent_channel().await.unwrap().into_stream();
    let blobs = identity_blobs(&ask(&mut stream, &[SSH_AGENTC_REQUEST_IDENTITIES]).await);
    assert_eq!(blobs.len(), 1);
    chain.disconnect().await;
}
