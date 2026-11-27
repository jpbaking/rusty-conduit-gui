//! In-process proxy dialer for `@forward:<tunnel_id>:<forward_id>` routing targets.
//!
//! When a Proxy routes traffic through a tagged local (`-L`) port forward on a [`Tunnel`],
//! [`TunnelForwardDialer`] checks the tunnel's forward [`HostFilter`] on the requested
//! destination host, dials `(forward.dest_host, forward.dest_port)` through the tunnel's raw
//! SSH dialer (bypassing the local `-L` TCP listener), and runs an in-process HTTP `CONNECT`
//! or SOCKS5 handshake on the resulting stream.

use std::io;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use conduit_core::{ForwardDirection, ForwardProxyProtocol, PortForward, Tunnel};
use rusty_conduit_engine::filter::HostFilter;
use rusty_conduit_engine::upstream::http::connect_tunnel;
use rusty_conduit_engine::upstream::socks5::{encode_connect_request, handshake as socks5_handshake};
use rusty_conduit_engine::upstream::{DialError, DialFuture, RouteBlocked, UpstreamDialer};
use uuid::Uuid;

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Formats `host:port`, bracketing bare IPv6 literals.
fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Formats the friendly redacted upstream label for a tunnel forward:
/// `tunnel:<tunnel_name> › <fwd_name> (http|socks5)`.
pub(crate) fn format_forward_upstream(tunnel_name: &str, forward: &PortForward) -> String {
    let fwd_label = if forward.name.trim().is_empty() {
        format!("{}:{}", forward.dest_host, forward.dest_port)
    } else {
        forward.name.clone()
    };
    let proto = match forward.proxy_protocol {
        ForwardProxyProtocol::Http => "http",
        ForwardProxyProtocol::Socks5 => "socks5",
        ForwardProxyProtocol::None => "tcp",
    };
    format!("tunnel:{tunnel_name} › {fwd_label} ({proto})")
}

/// Dials a destination through a remote HTTP or SOCKS5 proxy reachable via a Tunnel's
/// tagged `-L` [`PortForward`], entirely in-process over the Tunnel's raw SSH dialer.
pub(crate) struct TunnelForwardDialer {
    tunnel: Arc<Mutex<Tunnel>>,
    forward_id: Uuid,
    filter: Arc<RwLock<Option<HostFilter>>>,
    raw_dialer: Arc<dyn UpstreamDialer>,
}

impl TunnelForwardDialer {
    pub(crate) fn new(
        tunnel: Arc<Mutex<Tunnel>>,
        forward_id: Uuid,
        filter: Arc<RwLock<Option<HostFilter>>>,
        raw_dialer: Arc<dyn UpstreamDialer>,
    ) -> Self {
        Self {
            tunnel,
            forward_id,
            filter,
            raw_dialer,
        }
    }

    fn lookup_forward(&self) -> (String, Option<PortForward>) {
        let tunnel = lock(&self.tunnel);
        let fwd = tunnel
            .port_forwards
            .iter()
            .find(|f| {
                f.id == self.forward_id
                    && f.direction == ForwardDirection::Local
                    && f.proxy_protocol != ForwardProxyProtocol::None
            })
            .cloned();
        (tunnel.name.clone(), fwd)
    }
}

impl UpstreamDialer for TunnelForwardDialer {
    fn connect(&self, host: &str, port: u16, timeout: Duration) -> DialFuture<'_> {
        let host = host.to_string();
        Box::pin(async move {
            // (a) Enforce the tunnel's forward HostFilter on the requested destination host.
            let denied = {
                let guard = self.filter.read().unwrap_or_else(PoisonError::into_inner);
                guard.as_ref().and_then(|f| f.check_host(&host).err())
            };
            if let Some(denied) = denied {
                return Err(RouteBlocked {
                    profile: format!("{} ({denied})", self.redacted_upstream()),
                }
                .into_io());
            }

            // (b) Look up the current PortForward by id (must be Local + HTTP/SOCKS5).
            let (tunnel_name, forward) = self.lookup_forward();
            let Some(forward) = forward else {
                return Err(DialError::NotConnected {
                    kind: io::ErrorKind::NotFound,
                    message: format!(
                        "forward {} on tunnel `{tunnel_name}` is not a local proxy forward",
                        self.forward_id
                    ),
                }
                .into_io());
            };
            let upstream = format_forward_upstream(&tunnel_name, &forward);
            let dest_host = forward.dest_host_unbracketed().to_string();
            let dest_port = forward.dest_port;
            let protocol = forward.proxy_protocol;

            // (c) + (d) Dial (dest_host, dest_port) via raw SSH dialer and run the in-process
            // proxy handshake, bounded by `timeout`.
            let dial_and_handshake = async {
                let mut stream = self
                    .raw_dialer
                    .connect(&dest_host, dest_port, timeout)
                    .await?;
                match protocol {
                    ForwardProxyProtocol::Http => {
                        let target = host_port(&host, port);
                        let leftover = connect_tunnel(&mut stream, &target, None, &upstream).await?;
                        Ok(stream.with_prefix(leftover))
                    }
                    ForwardProxyProtocol::Socks5 => {
                        let request = encode_connect_request(&host, port)?;
                        socks5_handshake(&mut stream, None, &request).await?;
                        Ok(stream)
                    }
                    ForwardProxyProtocol::None => Err(DialError::NotConnected {
                        kind: io::ErrorKind::NotFound,
                        message: format!(
                            "forward {} on tunnel `{tunnel_name}` has no proxy protocol",
                            self.forward_id
                        ),
                    }
                    .into_io()),
                }
            };

            tokio::time::timeout(timeout, dial_and_handshake)
                .await
                .map_err(|_| {
                    DialError::Timeout {
                        message: format!(
                            "dial {} via {upstream} timed out after {} ms",
                            host_port(&host, port),
                            timeout.as_millis()
                        ),
                    }
                    .into_io()
                })?
        })
    }

    fn redacted_upstream(&self) -> String {
        let (tunnel_name, forward) = self.lookup_forward();
        match forward {
            Some(fwd) => format_forward_upstream(&tunnel_name, &fwd),
            None => format!("tunnel:{tunnel_name} › {}", self.forward_id),
        }
    }
}
