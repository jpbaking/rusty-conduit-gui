//! Reverse proxy: a local HTTP/HTTPS + SOCKS4/4a/5 server published on the SSH target with
//! `ssh -R` (or `tcpip-forward`), so clients there egress through this machine.
//!
//! It is a second engine [`Server`] whose [`RoutingState`] egresses through the built-in
//! `direct` profile only. The forward path's tunnel profile must never be used here because
//! that would send traffic straight back to the SSH target. MITM therefore gets its own state
//! and certificate cache, loaded in memory from the vault's CA bytes.
//!
//! The reverse allow/block filter is handed to the direct dialer only (through
//! [`DialerOptions`], not [`RoutingInput::filter`]): the dialer checks the requested name and
//! every locally resolved IP, so an IP/CIDR-only allowlist still admits a hostname that
//! resolves into it, and DNS-to-blocked-IP bypasses are refused.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use conduit_core::EngineConfig;
use conduit_ssh::RemoteForward;
use rusty_conduit_engine::logging::{AccessLogger, Logger, ProxyDirection};
use rusty_conduit_engine::mitm::MitmState;
use rusty_conduit_engine::routing::{
    RoutingInput, RoutingSetupError, RoutingState, DEFAULT_CONNECT_TIMEOUT,
};
use rusty_conduit_engine::server::{
    EngineHandlers, ListenPlan, ListenerRole, ProtocolHandlers, Server, ShutdownReport,
};
use rusty_conduit_engine::upstream::DialerOptions;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// One reverse listener: `remote` on the SSH target forwards to `local` on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReverseForward {
    pub remote: SocketAddr,
    pub local: SocketAddr,
}

impl ReverseForward {
    /// The `ssh -R` spec, `remote_ip:remote_port:local_ip:local_port` (IPv6 bracketed).
    pub(crate) fn spec(&self) -> String {
        format!("{}:{}", self.remote, self.local)
    }

    /// The `tcpip-forward` request for the russh engine.
    pub(crate) fn to_remote_forward(&self) -> RemoteForward {
        RemoteForward {
            remote: self.remote,
            host: self.local.ip().to_string(),
            port: self.local.port(),
        }
    }
}

/// Plan for the reverse proxy: ephemeral loopback ports, never reachable directly from the
/// network. They are bound once, so the remote forwards stay stable across reconnects.
pub(crate) fn reverse_listen_plan(cfg: &EngineConfig) -> ListenPlan {
    let ephemeral = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    if cfg.is_reverse_multiplexed() {
        return ListenPlan::Multiplexed(ephemeral);
    }
    ListenPlan::Separate {
        http: (cfg.reverse_http_port > 0).then_some(ephemeral),
        socks: (cfg.reverse_socks_port > 0).then_some(ephemeral),
    }
}

/// Reverse routing: every request egresses through `direct` (local DNS), with the reverse
/// allow/block filter enforced by the direct dialer, the configured keepalive, and the
/// default connect timeout.
pub(crate) fn reverse_routing(cfg: &EngineConfig) -> Result<RoutingState, RoutingSetupError> {
    let input = RoutingInput {
        filter: None,
        mitm_enabled: cfg.mitm_enabled,
        keepalive: cfg.keepalive,
        connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        ..RoutingInput::default()
    };
    let opts = DialerOptions {
        filter: cfg.reverse_filter.clone().map(Arc::new),
        ..DialerOptions::default()
    };
    RoutingState::from_input(&input, opts)
}

/// A running reverse proxy server.
#[derive(Debug)]
pub(crate) struct ReverseProxy {
    forwards: Vec<ReverseForward>,
    token: CancellationToken,
    run: JoinHandle<ShutdownReport>,
    reaper: Option<JoinHandle<()>>,
}

impl ReverseProxy {
    /// Binds and starts serving, or returns `Ok(None)` when no reverse port is configured.
    ///
    /// `mitm_ca_pem` is the vault's CA (certificate chain and key in one PEM), kept in memory
    /// only. Call this before connecting, so [`Self::forwards`] can be requested on the target.
    pub(crate) async fn start(
        cfg: &EngineConfig,
        mitm_ca_pem: Option<&[u8]>,
        access: &AccessLogger,
        logger: &Logger,
    ) -> Result<Option<Self>, String> {
        if !cfg.reverse_enabled {
            return Ok(None);
        }

        let routing = reverse_routing(cfg)
            .map_err(|e| format!("reverse proxy routing setup failed: {e}"))?
            .shared();
        let mitm = match mitm_ca_pem.filter(|_| cfg.mitm_enabled) {
            Some(pem) => Some(
                MitmState::from_pem_bytes(pem, pem, &cfg.mitm_options)
                    .map_err(|e| format!("reverse proxy MITM setup failed: {e}"))?,
            ),
            None => None,
        };
        if let Some(m) = &mitm {
            m.cache.set_logger(logger.clone());
        }

        let access = access
            .clone()
            .with_direction(ProxyDirection::Reverse)
            .with_routing_fields(false);
        let mut handlers = EngineHandlers::from_routing(routing, access, logger.clone());
        if let Some(m) = &mitm {
            handlers = handlers.with_mitm(Arc::new(m.interceptor.clone()), false);
        }
        if cfg.socks_block_web_in_mitm {
            handlers = handlers.with_socks_block_web();
        }
        let handlers: Arc<dyn ProtocolHandlers> = Arc::new(handlers);
        let server = Server::bind(reverse_listen_plan(cfg), handlers, logger.clone())
            .await
            .map_err(|e| format!("reverse proxy: {e}"))?
            .with_max_connections(cfg.reverse_max_connections)
            .with_tcp_keepalive(cfg.keepalive);

        let mut forwards = Vec::new();
        for (role, local) in server.listeners() {
            let port = match role {
                ListenerRole::Http | ListenerRole::Multiplexed => cfg.reverse_http_port,
                ListenerRole::Socks => cfg.reverse_socks_port,
            };
            let remote = SocketAddr::new(cfg.reverse_bind, port);
            let forward = ReverseForward { remote, local };
            logger.info(format!(
                "reverse {role} proxy listening on {local}, exposed on SSH target at {remote} \
                 (ssh -R {})",
                forward.spec()
            ));
            forwards.push(forward);
        }

        let token = server.shutdown_token();
        let reaper = mitm
            .as_ref()
            .map(|m| m.cache.spawn_reaper(token.clone(), logger.clone()));
        let run = tokio::spawn(server.run());
        Ok(Some(Self {
            forwards,
            token,
            run,
            reaper,
        }))
    }

    /// The loopback addresses the reverse proxy listens on, on this machine.
    pub(crate) fn local_listeners(&self) -> Vec<SocketAddr> {
        self.forwards.iter().map(|forward| forward.local).collect()
    }

    /// The remote forwards for the bound listeners.
    pub(crate) fn forwards(&self) -> &[ReverseForward] {
        &self.forwards
    }

    /// Stops accepting, drains in-flight connections, and joins the certificate reaper.
    pub(crate) async fn shutdown(self) -> ShutdownReport {
        self.token.cancel();
        let report = self.run.await.unwrap_or(ShutdownReport { drained: false });
        if let Some(reaper) = self.reaper {
            let _ = reaper.await;
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusty_conduit_engine::filter::{access_denied_error, is_access_denied, HostFilter};
    use rusty_conduit_engine::logging::{AccessLogConfig, LogFormat, LogLevel};
    use rusty_conduit_engine::router::RouteRequest;
    use rusty_conduit_engine::routing::{Inbound, RouteResolver};

    fn config() -> EngineConfig {
        let profile = conduit_core::SessionProfile {
            hops: vec![conduit_core::HopEntry::default()],
            ..Default::default()
        };
        conduit_core::to_engine_config(&profile).unwrap()
    }

    fn rules(r: &[&str]) -> Vec<rusty_conduit_engine::filter::FilterRule> {
        r.iter().map(|r| r.parse().unwrap()).collect()
    }

    #[test]
    fn spec_brackets_ipv6_and_maps_to_remote_forward() {
        let forward = ReverseForward {
            remote: "127.0.0.1:8080".parse().unwrap(),
            local: "127.0.0.1:50000".parse().unwrap(),
        };
        assert_eq!(forward.spec(), "127.0.0.1:8080:127.0.0.1:50000");
        let v6 = ReverseForward {
            remote: "[::1]:8080".parse().unwrap(),
            ..forward
        };
        assert_eq!(v6.spec(), "[::1]:8080:127.0.0.1:50000");
        let remote = forward.to_remote_forward();
        assert_eq!(remote.remote, forward.remote);
        assert_eq!(remote.host, "127.0.0.1");
        assert_eq!(remote.port, 50000);
    }

    #[test]
    fn reverse_plan_uses_ephemeral_loopback() {
        let ephemeral = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let plan = |reverse_http_port, reverse_socks_port| {
            reverse_listen_plan(&EngineConfig {
                // The remote bind must never leak into the local listener address.
                reverse_bind: "0.0.0.0".parse().unwrap(),
                reverse_http_port,
                reverse_socks_port,
                ..config()
            })
        };
        assert_eq!(plan(8888, 8888), ListenPlan::Multiplexed(ephemeral));
        assert_eq!(
            plan(8888, 1081),
            ListenPlan::Separate {
                http: Some(ephemeral),
                socks: Some(ephemeral),
            }
        );
        assert_eq!(
            plan(8888, 0),
            ListenPlan::Separate {
                http: Some(ephemeral),
                socks: None,
            }
        );
        assert_eq!(
            plan(0, 1081),
            ListenPlan::Separate {
                http: None,
                socks: Some(ephemeral),
            }
        );
    }

    /// Routes and dials `host:port` through `state` the way the engines do.
    async fn dial(state: &RoutingState, host: &str, port: u16) -> std::io::Result<()> {
        let decision = state
            .resolve(&RouteRequest {
                inbound: Inbound::Http,
                host,
                port,
                scheme: None,
                url: None,
            })
            .map_err(access_denied_error)?;
        let chain = state.registry.chain_for(&decision.targets).unwrap();
        chain
            .dial(host, port, std::time::Duration::from_secs(5))
            .await
            .map(drop)
    }

    #[tokio::test]
    async fn reverse_filter_checks_resolved_ips_for_hostnames() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { while listener.accept().await.is_ok() {} });

        // An IP/CIDR-only allowlist admits a hostname that resolves into it.
        let allow = reverse_routing(&EngineConfig {
            reverse_filter: Some(HostFilter::Allow(rules(&["127.0.0.0/8"]))),
            ..config()
        })
        .unwrap();
        dial(&allow, "localhost", port).await.unwrap();
        dial(&allow, "127.0.0.1", port).await.unwrap();

        // A blocklist refuses a hostname that resolves to a blocked IP (DNS-to-loopback).
        let block = reverse_routing(&EngineConfig {
            reverse_filter: Some(HostFilter::Block(rules(&["127.0.0.0/8", "::1"]))),
            ..config()
        })
        .unwrap();
        let err = dial(&block, "localhost", port).await.unwrap_err();
        assert!(is_access_denied(&err), "{err}");
    }

    #[tokio::test]
    async fn start_binds_loopback_listeners_and_reports_forwards() {
        let logger = Logger::with_writer(LogLevel::Quiet, Box::new(std::io::sink()));
        let access = AccessLogger::start(
            AccessLogConfig::new(LogLevel::Quiet, LogFormat::Text, None, None),
            logger.clone(),
        )
        .await
        .unwrap();
        let disabled = EngineConfig {
            reverse_enabled: false,
            reverse_http_port: 0,
            reverse_socks_port: 0,
            ..config()
        };
        assert!(ReverseProxy::start(&disabled, None, &access, &logger)
            .await
            .unwrap()
            .is_none());

        let cfg = EngineConfig {
            reverse_enabled: true,
            reverse_bind: "127.0.0.1".parse().unwrap(),
            reverse_http_port: 8888,
            reverse_socks_port: 1081,
            ..config()
        };
        let proxy = ReverseProxy::start(&cfg, None, &access, &logger)
            .await
            .unwrap()
            .unwrap();
        let mut remotes: Vec<u16> = proxy.forwards().iter().map(|f| f.remote.port()).collect();
        remotes.sort_unstable();
        assert_eq!(remotes, [1081, 8888]);
        for forward in proxy.forwards() {
            assert!(forward.local.ip().is_loopback());
            assert_ne!(forward.local.port(), 0);
            tokio::net::TcpStream::connect(forward.local).await.unwrap();
        }
        proxy.shutdown().await;
        access.shutdown().await.unwrap();
    }
}
