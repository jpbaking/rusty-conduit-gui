//! Bursty parallel uploads through a multi-hop chain must not stall the tunnel.

// Each test binary uses only part of the shared harness.
#[allow(dead_code)]
mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use conduit_ssh::{connect_chain, SshChain};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Reads everything and answers each read with a small ack, like an upload test server.
async fn spawn_ack_sink() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if socket.write_all(format!("{n}\n").as_bytes()).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

/// A TCP relay to `target` that limits each direction to `rate` bytes/s with `latency`,
/// so SSH windows actually run out as they do on a real uplink.
async fn spawn_slow_link(target: u16, rate: f64, latency: Duration) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let upstream = tokio::net::TcpStream::connect(("127.0.0.1", target))
                .await
                .unwrap();
            client.set_nodelay(true).unwrap();
            upstream.set_nodelay(true).unwrap();
            let (cr, cw) = client.into_split();
            let (ur, uw) = upstream.into_split();
            tokio::spawn(pump(cr, uw, rate, latency));
            tokio::spawn(pump(ur, cw, rate, latency));
        }
    });
    port
}

async fn pump(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    rate: f64,
    latency: Duration,
) {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(tokio::time::Instant, Vec<u8>)>(32);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = match from.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            let at = tokio::time::Instant::now() + latency;
            if tx.send((at, buf[..n].to_vec())).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_secs_f64(n as f64 / rate)).await;
        }
    });
    while let Some((at, bytes)) = rx.recv().await {
        tokio::time::sleep_until(at).await;
        if to.write_all(&bytes).await.is_err() {
            return;
        }
    }
    let _ = to.shutdown().await;
}

async fn run_upload(hops: usize, streams: usize, bytes_per_stream: usize) {
    run_upload_over(hops, streams, bytes_per_stream, None).await;
}

async fn run_upload_over(
    hops: usize,
    streams: usize,
    bytes_per_stream: usize,
    slow_first_link: Option<(f64, Duration)>,
) {
    let (chain, _nodes) = connect(hops, slow_first_link).await;
    let sink = spawn_ack_sink().await;
    burst(&chain, sink, streams, bytes_per_stream).await;
}

/// Connects a chain of `hops` in-process servers, optionally behind a slow first link.
async fn connect(
    hops: usize,
    slow_first_link: Option<(f64, Duration)>,
) -> (Arc<SshChain>, Vec<Node>) {
    let key = new_user_key();
    let mut nodes = Vec::new();
    for _ in 0..hops {
        nodes.push(spawn_node(Some(key.public_key().clone())).await);
    }
    let mut specs: Vec<_> = nodes
        .iter()
        .enumerate()
        .map(|(i, n)| spec(i, n, vec![key_auth(&key)]))
        .collect();
    // The verifier pins hop 0 at whatever port the client dials.
    let mut pinned: Vec<Node> = Vec::new();
    if let Some((rate, latency)) = slow_first_link {
        let port = spawn_slow_link(nodes[0].port, rate, latency).await;
        specs[0].port = port;
        pinned.push(Node {
            port,
            host_key: nodes[0].host_key.clone(),
            state: Arc::clone(&nodes[0].state),
        });
    }
    let mut refs: Vec<&Node> = nodes.iter().collect();
    if let Some(first) = pinned.first() {
        refs[0] = first;
    }
    let chain = connect_chain(&specs, &pin_all(&refs), &options(), None)
        .await
        .expect("chain connects");
    nodes.extend(pinned);
    (Arc::new(chain), nodes)
}

/// Uploads `bytes_per_stream` on each of `streams` parallel channels to `sink`.
async fn burst(chain: &Arc<SshChain>, sink: u16, streams: usize, bytes_per_stream: usize) {
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..streams {
        let chain = Arc::clone(chain);
        tasks.spawn(async move {
            let channel = chain.open_direct_tcpip("127.0.0.1", sink).await.unwrap();
            let (mut read, mut write) = tokio::io::split(channel.into_stream());
            // Drain acks concurrently, as a browser does.
            let reader = tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                while let Ok(n) = read.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                }
            });
            let chunk = payload(64 * 1024);
            let mut sent = 0;
            while sent < bytes_per_stream {
                write.write_all(&chunk).await.unwrap();
                sent += chunk.len();
            }
            write.shutdown().await.unwrap();
            drop(write);
            let _ = reader.await;
        });
    }
    let all = async {
        while let Some(done) = tasks.join_next().await {
            done.expect("upload task panicked");
        }
    };
    tokio::time::timeout(Duration::from_secs(60), all)
        .await
        .expect("bursty upload stalled");
}

fn alive_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

/// Waits up to five seconds for the live task count to reach `at_most`, returning the last count.
async fn settle_to(at_most: usize) -> usize {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let now = alive_tasks();
        if now <= at_most || tokio::time::Instant::now() >= deadline {
            return now;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bursty_upload_single_hop() {
    run_upload(1, 8, 16 * 1024 * 1024).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bursty_upload_two_hops() {
    run_upload(2, 8, 16 * 1024 * 1024).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bursty_upload_two_hops_slow_uplink() {
    run_upload_over(
        2,
        8,
        4 * 1024 * 1024,
        Some((8.0 * 1024.0 * 1024.0, Duration::from_millis(10))),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bursty_upload_single_hop_slow_uplink() {
    run_upload_over(
        1,
        8,
        4 * 1024 * 1024,
        Some((8.0 * 1024.0 * 1024.0, Duration::from_millis(10))),
    )
    .await;
}

/// Repeated bursts leave no channel, relay, or nested-writer task behind, and disconnecting
/// ends every task the chain owns.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repeated_bursts_release_every_task() {
    let (chain, _nodes) =
        connect(2, Some((32.0 * 1024.0 * 1024.0, Duration::from_millis(5)))).await;
    let sink = spawn_ack_sink().await;
    let baseline = alive_tasks();
    for round in 0..5 {
        burst(&chain, sink, 8, 2 * 1024 * 1024).await;
        let left = settle_to(baseline).await;
        assert!(
            left <= baseline,
            "round {round}: {left} tasks alive, baseline {baseline}"
        );
    }
    let chain = Arc::try_unwrap(chain).expect("no channel still holds the chain");
    chain.disconnect().await;
    let left = settle_to(baseline - 1).await;
    assert!(
        left < baseline,
        "{left} tasks alive after disconnect, baseline {baseline}"
    );
}
