//! The platform-neutral tray menu, built from Proxy and Tunnel state (plus any legacy v1
//! sessions) and the vault lock state.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use conduit_core::{ProxyId, TunnelId};
use conduit_runtime::{ListenerInfo, ProxyState, SessionSnapshot, SessionState};
use uuid::Uuid;

/// Name shown at the top of the tray menu.
pub const APP_TITLE: &str = "Rusty Conduit GUI";

/// The routing profile name that sends everything direct.
pub const PROFILE_DIRECT: &str = "direct";

// These match the `Display` output of the engine's `ListenerRole`, which is how
// `ListenerInfo::role` is filled in.
const ROLE_HTTP: &str = "HTTP/HTTPS";
const ROLE_SOCKS: &str = "SOCKS4/4a/5";
const ROLE_MULTIPLEXED: &str = "multiplexed HTTP/HTTPS + SOCKS4/4a/5";


/// Something the user picked from the tray menu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrayAction {
    StartSession(Uuid),
    StopSession(Uuid),
    RestartSession(Uuid),
    /// `session_id` is the session, Proxy, or Tunnel the URL belongs to.
    CopyHttpUrl {
        session_id: Uuid,
        url: String,
    },
    /// `session_id` is the session, Proxy, or Tunnel the URL belongs to.
    CopySocksUrl {
        session_id: Uuid,
        url: String,
    },
    ViewLogs(Uuid),
    StartProxy(ProxyId),
    StopProxy(ProxyId),
    RestartProxy(ProxyId),
    /// `Some(profile)` forces every connection through `profile` (`direct` included); `None`
    /// returns to Auto Switch.
    SetProxyOverride {
        id: ProxyId,
        profile: Option<String>,
    },
    ViewProxyLogs(ProxyId),
    StartTunnel(TunnelId),
    StopTunnel(TunnelId),
    RestartTunnel(TunnelId),
    ViewTunnelLogs(TunnelId),
    StartAll,
    StopAll,
    UnlockVault,
    OpenManageWindow,
    /// The handler must confirm first when `TrayMenuModel::quit_needs_confirmation` is set.
    Quit,
}

/// The overall tray icon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayIconState {
    Idle,
    Connected,
    Reconnecting,
    Attention,
    Locked,
}

/// Whether a desktop tray host can currently show the icon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayHostStatus {
    /// A tray host accepted the icon.
    Online,
    /// No tray host is available. Sessions keep running and the app uses its window fallback.
    Offline,
    /// The first connection attempt has not finished yet.
    Waiting,
}

/// One clickable menu row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayMenuItem {
    pub label: String,
    pub action: TrayAction,
    pub enabled: bool,
}

impl TrayMenuItem {
    fn new(label: impl Into<String>, action: TrayAction) -> Self {
        Self {
            label: label.into(),
            action,
            enabled: true,
        }
    }
}

/// A row inside a submenu: a clickable item or a further (nested) submenu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrayMenuEntry {
    Item(TrayMenuItem),
    Submenu(TraySubmenu),
}

/// A nested submenu, such as a Proxy's `Mode ▸`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraySubmenu {
    pub label: String,
    pub entries: Vec<TrayMenuEntry>,
}

/// One legacy v1 session and its submenu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraySessionEntry {
    pub id: Uuid,
    pub name: String,
    /// `●` connected, `◐` in progress, `!` needs attention, `○` stopped.
    pub marker: char,
    pub status: String,
    pub http_url: Option<String>,
    pub socks_url: Option<String>,
    pub items: Vec<TrayMenuItem>,
}

impl TraySessionEntry {
    /// The session's row in the root menu.
    pub fn label(&self) -> String {
        format!("{} {} — {}", self.marker, self.name, self.status)
    }
}

/// A Proxy as the tray needs to see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyTrayItem {
    pub id: ProxyId,
    pub name: String,
    pub enabled: bool,
    pub state: ProxyState,
    /// Bound listeners, while running.
    pub listeners: Vec<ListenerInfo>,
    /// How many Auto Switch routing rules the Proxy has.
    pub rule_count: usize,
    /// The Proxy's own upstream profile names (never the built-in `direct` / `block`).
    pub profiles: Vec<String>,
}

/// A Tunnel as the tray needs to see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelTrayItem {
    pub id: TunnelId,
    pub name: String,
    pub enabled: bool,
    pub state: SessionState,
    /// The Tunnel runs while a Proxy routes through it (start mode *Linked*).
    pub linked: bool,
    /// Names of the running Proxies that route through this Tunnel.
    pub linked_to: Vec<String>,
}

/// Everything the tray menu is built from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrayState {
    pub proxies: Vec<ProxyTrayItem>,
    pub tunnels: Vec<TunnelTrayItem>,
    /// Legacy v1 sessions, shown in their own section while any exist.
    pub sessions: Vec<SessionSnapshot>,
    pub vault_locked: bool,
}

/// One Proxy row and its submenu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayProxyEntry {
    pub id: ProxyId,
    pub name: String,
    /// `●` running, `◐` in progress, `!` needs attention, `○` stopped.
    pub marker: char,
    pub status: String,
    pub http_url: Option<String>,
    pub socks_url: Option<String>,
    /// `Mode ▸` (while running), lifecycle actions, Copy URLs, and View Logs.
    pub entries: Vec<TrayMenuEntry>,
}

impl TrayProxyEntry {
    /// The Proxy's row in the root menu.
    pub fn label(&self) -> String {
        format!("{} {} — {}", self.marker, self.name, self.status)
    }
}

/// One Tunnel row and its submenu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayTunnelEntry {
    pub id: TunnelId,
    pub name: String,
    /// `●` connected, `◐` in progress, `!` needs attention, `○` stopped.
    pub marker: char,
    pub status: String,
    pub items: Vec<TrayMenuItem>,
}

impl TrayTunnelEntry {
    /// The Tunnel's row in the root menu.
    pub fn label(&self) -> String {
        format!("{} {} — {}", self.marker, self.name, self.status)
    }
}

/// Everything a tray backend needs to draw the menu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayMenuModel {
    /// `N proxies running · M tunnels need attention` (or the v1 session summary).
    pub summary: String,
    /// Running Proxies, connected Tunnels, and connected sessions.
    pub connected: usize,
    pub needs_attention: usize,
    pub icon: TrayIconState,
    /// The PROXIES section.
    pub proxies: Vec<TrayProxyEntry>,
    /// The TUNNELS section.
    pub tunnels: Vec<TrayTunnelEntry>,
    /// Legacy v1 sessions.
    pub sessions: Vec<TraySessionEntry>,
    /// Start All, Stop All, the conditional Unlock Vault, Open Manage Window, and Quit.
    pub global_items: Vec<TrayMenuItem>,
    pub vault_locked: bool,
    pub quit_needs_confirmation: bool,
}

/// How one item counts toward the summary, the icon, and Start All / Stop All.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Health {
    Connected,
    InProgress,
    /// Waiting on the vault.
    Locked,
    Attention,
    Stopped,
}

impl Health {
    fn of_session(state: &SessionState) -> Self {
        match state {
            SessionState::Connected => Self::Connected,
            SessionState::Stopped => Self::Stopped,
            SessionState::Locked => Self::Locked,
            s if needs_attention(s) => Self::Attention,
            _ => Self::InProgress,
        }
    }

    fn of_proxy(state: &ProxyState) -> Self {
        match state {
            ProxyState::Running { .. } => Self::Connected,
            ProxyState::Stopped => Self::Stopped,
            ProxyState::Locked => Self::Locked,
            ProxyState::NeedsAttention { .. } => Self::Attention,
            ProxyState::Starting | ProxyState::Reloading | ProxyState::Stopping => {
                Self::InProgress
            }
        }
    }

    fn needs_attention(self) -> bool {
        matches!(self, Self::Locked | Self::Attention)
    }

    fn marker(self) -> char {
        match self {
            Self::Connected => '●',
            Self::Stopped => '○',
            Self::Locked | Self::Attention => '!',
            Self::InProgress => '◐',
        }
    }
}

/// `1 proxy running`, `2 proxies running`.
fn count_label(n: usize, one: &str, many: &str, verb_one: &str, verb_many: &str) -> String {
    if n == 1 {
        format!("{n} {one} {verb_one}")
    } else {
        format!("{n} {many} {verb_many}")
    }
}

impl TrayMenuModel {
    /// Builds the menu from legacy v1 sessions only. Session order is preserved.
    pub fn from_snapshots(snapshots: &[SessionSnapshot], vault_locked: bool) -> Self {
        Self::from_state(&TrayState {
            sessions: snapshots.to_vec(),
            vault_locked,
            ..TrayState::default()
        })
    }

    /// Builds the menu. Proxy, Tunnel, and session order is preserved.
    pub fn from_state(state: &TrayState) -> Self {
        let vault_locked = state.vault_locked;
        // (health, enabled, terminal) for every item.
        let mut all: Vec<(Health, bool, bool)> = Vec::new();
        all.extend(state.proxies.iter().map(|p| {
            let terminal = matches!(
                p.state,
                ProxyState::Stopped | ProxyState::NeedsAttention { .. }
            );
            (Health::of_proxy(&p.state), p.enabled, terminal)
        }));
        all.extend(state.tunnels.iter().map(|t| {
            (Health::of_session(&t.state), t.enabled, t.state.is_terminal())
        }));
        all.extend(state.sessions.iter().map(|s| {
            (Health::of_session(&s.state), s.enabled, s.state.is_terminal())
        }));

        let connected = all.iter().filter(|(h, ..)| *h == Health::Connected).count();
        let needs_attention = all.iter().filter(|(h, ..)| h.needs_attention()).count();
        // Start All leaves disabled items out, so they do not make it clickable.
        let any_startable = all.iter().any(|(_, enabled, terminal)| *enabled && *terminal);
        let any_active = all.iter().any(|(.., terminal)| !terminal);

        let mut start_all = TrayMenuItem::new("Start All", TrayAction::StartAll);
        start_all.enabled = any_startable;
        let mut stop_all = TrayMenuItem::new("Stop All", TrayAction::StopAll);
        stop_all.enabled = any_active;

        let mut global_items = vec![start_all, stop_all];
        if vault_locked {
            global_items.push(TrayMenuItem::new("Unlock Vault…", TrayAction::UnlockVault));
        }
        global_items.push(TrayMenuItem::new(
            "Open Manage Window…",
            TrayAction::OpenManageWindow,
        ));
        global_items.push(TrayMenuItem::new("Quit", TrayAction::Quit));

        let summary = if state.proxies.is_empty() && state.tunnels.is_empty() && !state.sessions.is_empty() {
            format!("{connected} connected · {needs_attention} needs attention")
        } else {
            let running = state
                .proxies
                .iter()
                .filter(|p| matches!(p.state, ProxyState::Running { .. }))
                .count();
            let tunnel_attention = state
                .tunnels
                .iter()
                .filter(|t| Health::of_session(&t.state).needs_attention())
                .count();
            format!(
                "{} · {}",
                count_label(running, "proxy", "proxies", "running", "running"),
                count_label(tunnel_attention, "tunnel", "tunnels", "needs attention", "need attention"),
            )
        };

        Self {
            summary,
            connected,
            needs_attention,
            icon: icon_for(all.iter().map(|(h, ..)| *h), vault_locked),
            proxies: state
                .proxies
                .iter()
                .map(|p| proxy_entry(p, vault_locked))
                .collect(),
            tunnels: state
                .tunnels
                .iter()
                .map(|t| tunnel_entry(t, vault_locked))
                .collect(),
            sessions: state
                .sessions
                .iter()
                .map(|s| session_entry(s, vault_locked))
                .collect(),
            global_items,
            vault_locked,
            quit_needs_confirmation: any_active,
        }
    }
}

/// Formats a listener as an HTTP proxy URL.
pub fn http_proxy_url(addr: SocketAddr) -> String {
    format!("http://{}", client_addr(addr))
}

/// Formats a listener as a SOCKS proxy URL. Always `socks5h://`, so DNS stays remote.
pub fn socks_proxy_url(addr: SocketAddr) -> String {
    format!("socks5h://{}", client_addr(addr))
}

// A wildcard bind address is not something a client can connect to.
fn client_addr(addr: SocketAddr) -> SocketAddr {
    let ip = match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, addr.port())
}

fn needs_attention(state: &SessionState) -> bool {
    matches!(
        state,
        SessionState::Locked
            | SessionState::AwaitingHostKey(_)
            | SessionState::NeedsAttention { .. }
            | SessionState::Failed { .. }
    )
}

fn icon_for(health: impl Iterator<Item = Health> + Clone, vault_locked: bool) -> TrayIconState {
    let any = |wanted: Health| health.clone().any(|h| h == wanted);
    if any(Health::Attention) {
        TrayIconState::Attention
    } else if vault_locked {
        TrayIconState::Locked
    } else if any(Health::Locked) {
        TrayIconState::Attention
    } else if any(Health::InProgress) {
        TrayIconState::Reconnecting
    } else if any(Health::Connected) {
        TrayIconState::Connected
    } else {
        TrayIconState::Idle
    }
}

fn listener_addr(listeners: &[ListenerInfo], role: &str) -> Option<SocketAddr> {
    let by_role = |wanted: &str| listeners.iter().find(|l| l.role == wanted).map(|l| l.addr);
    by_role(role).or_else(|| by_role(ROLE_MULTIPLEXED))
}

fn status_text(state: &SessionState) -> String {
    match state {
        SessionState::Stopped => "Stopped".into(),
        SessionState::Starting => "Starting…".into(),
        SessionState::Connected => "Connected".into(),
        SessionState::Reconnecting {
            next_retry_secs, ..
        } => format!("Reconnecting ({next_retry_secs}s)…"),
        SessionState::WaitingForNetwork => "Waiting for network…".into(),
        SessionState::Locked => "Vault locked".into(),
        SessionState::AwaitingHostKey(_) => "Host key review".into(),
        SessionState::NeedsAttention { .. } | SessionState::Failed { .. } => {
            "Needs attention".into()
        }
    }
}

fn copy_items(
    source: Uuid,
    http_url: Option<&String>,
    socks_url: Option<&String>,
) -> Vec<TrayMenuItem> {
    let mut items = Vec::new();
    if let Some(url) = http_url {
        items.push(TrayMenuItem::new(
            format!("Copy HTTP Proxy URL ({url})"),
            TrayAction::CopyHttpUrl {
                session_id: source,
                url: url.clone(),
            },
        ));
    }
    if let Some(url) = socks_url {
        items.push(TrayMenuItem::new(
            format!("Copy SOCKS Proxy URL ({url})"),
            TrayAction::CopySocksUrl {
                session_id: source,
                url: url.clone(),
            },
        ));
    }
    items
}

fn session_entry(snapshot: &SessionSnapshot, vault_locked: bool) -> TraySessionEntry {
    let id = snapshot.id;
    let state = &snapshot.state;
    // A stopped session's last listeners are no longer bound, so offer no URLs for it.
    let (http, socks) = if state.is_terminal() {
        (None, None)
    } else {
        (
            listener_addr(&snapshot.listeners, ROLE_HTTP),
            listener_addr(&snapshot.listeners, ROLE_SOCKS),
        )
    };
    let http_url = http.map(http_proxy_url);
    let socks_url = socks.map(socks_proxy_url);

    let mut items = Vec::new();
    if *state == SessionState::Locked && vault_locked {
        items.push(TrayMenuItem::new("Unlock Vault…", TrayAction::UnlockVault));
    } else if state.is_terminal() {
        items.push(TrayMenuItem::new("Start", TrayAction::StartSession(id)));
    } else {
        items.push(TrayMenuItem::new("Stop", TrayAction::StopSession(id)));
        items.push(TrayMenuItem::new("Restart", TrayAction::RestartSession(id)));
    }
    items.extend(copy_items(id, http_url.as_ref(), socks_url.as_ref()));
    items.push(TrayMenuItem::new("View Logs", TrayAction::ViewLogs(id)));
    if needs_attention(state) {
        items.push(TrayMenuItem::new(
            "Open Manage Window…",
            TrayAction::OpenManageWindow,
        ));
    }

    TraySessionEntry {
        id,
        name: snapshot.name.clone(),
        marker: Health::of_session(state).marker(),
        status: status_text(state),
        http_url,
        socks_url,
        items,
    }
}

/// The `Mode ▸` submenu: the current choice carries a `✓`.
fn mode_submenu(proxy: &ProxyTrayItem, current: Option<&str>) -> TraySubmenu {
    let check = |on: bool, label: String| {
        if on {
            format!("✓ {label}")
        } else {
            label
        }
    };
    let set = |profile: Option<&str>| TrayAction::SetProxyOverride {
        id: proxy.id,
        profile: profile.map(str::to_owned),
    };
    let rules = if proxy.rule_count == 1 {
        "1 rule".to_owned()
    } else {
        format!("{} rules", proxy.rule_count)
    };
    let mut entries = vec![
        TrayMenuItem::new(
            check(current.is_none(), format!("Auto Switch ({rules})")),
            set(None),
        ),
        TrayMenuItem::new(
            check(current == Some(PROFILE_DIRECT), "Force Direct".into()),
            set(Some(PROFILE_DIRECT)),
        ),
    ];
    entries.extend(proxy.profiles.iter().map(|name| {
        TrayMenuItem::new(
            check(current == Some(name.as_str()), format!("Force {name}")),
            set(Some(name)),
        )
    }));
    TraySubmenu {
        label: "Mode".into(),
        entries: entries.into_iter().map(TrayMenuEntry::Item).collect(),
    }
}

fn proxy_entry(proxy: &ProxyTrayItem, vault_locked: bool) -> TrayProxyEntry {
    let id = proxy.id;
    let health = Health::of_proxy(&proxy.state);
    let running = match &proxy.state {
        ProxyState::Running {
            override_profile, ..
        } => Some(override_profile.as_deref()),
        _ => None,
    };
    // Only a running Proxy's listeners are bound, so offer no URLs otherwise.
    let (http, socks) = if running.is_some() {
        (
            listener_addr(&proxy.listeners, ROLE_HTTP),
            listener_addr(&proxy.listeners, ROLE_SOCKS),
        )
    } else {
        (None, None)
    };
    let http_url = http.map(http_proxy_url);
    let socks_url = socks.map(socks_proxy_url);

    let status = match &proxy.state {
        ProxyState::Stopped => "Stopped".into(),
        ProxyState::Starting => "Starting…".into(),
        ProxyState::Running { .. } => "Running".into(),
        ProxyState::Reloading => "Reloading…".into(),
        ProxyState::Locked => "Vault locked".into(),
        ProxyState::NeedsAttention { .. } => "Needs attention".into(),
        ProxyState::Stopping => "Stopping…".into(),
    };

    let mut entries = Vec::new();
    if let Some(current) = running {
        entries.push(TrayMenuEntry::Submenu(mode_submenu(proxy, current)));
    }
    let mut items = Vec::new();
    if proxy.state == ProxyState::Locked && vault_locked {
        items.push(TrayMenuItem::new("Unlock Vault…", TrayAction::UnlockVault));
    } else if matches!(
        proxy.state,
        ProxyState::Stopped | ProxyState::NeedsAttention { .. }
    ) {
        items.push(TrayMenuItem::new("Start", TrayAction::StartProxy(id)));
    } else {
        items.push(TrayMenuItem::new("Stop", TrayAction::StopProxy(id)));
        items.push(TrayMenuItem::new("Restart", TrayAction::RestartProxy(id)));
    }
    items.extend(copy_items(id.as_uuid(), http_url.as_ref(), socks_url.as_ref()));
    items.push(TrayMenuItem::new("View Logs", TrayAction::ViewProxyLogs(id)));
    if health.needs_attention() {
        items.push(TrayMenuItem::new(
            "Open Manage Window…",
            TrayAction::OpenManageWindow,
        ));
    }
    entries.extend(items.into_iter().map(TrayMenuEntry::Item));

    TrayProxyEntry {
        id,
        name: proxy.name.clone(),
        marker: health.marker(),
        status,
        http_url,
        socks_url,
        entries,
    }
}

fn tunnel_entry(tunnel: &TunnelTrayItem, vault_locked: bool) -> TrayTunnelEntry {
    let id = tunnel.id;
    let state = &tunnel.state;
    let status = status_text(state);

    let mut items = Vec::new();
    if *state == SessionState::Locked && vault_locked {
        items.push(TrayMenuItem::new("Unlock Vault…", TrayAction::UnlockVault));
    } else if state.is_terminal() {
        items.push(TrayMenuItem::new("Start", TrayAction::StartTunnel(id)));
    } else {
        items.push(TrayMenuItem::new("Stop", TrayAction::StopTunnel(id)));
        items.push(TrayMenuItem::new("Restart", TrayAction::RestartTunnel(id)));
    }
    items.push(TrayMenuItem::new("View Logs", TrayAction::ViewTunnelLogs(id)));
    if needs_attention(state) {
        items.push(TrayMenuItem::new(
            "Open Manage Window…",
            TrayAction::OpenManageWindow,
        ));
    }

    TrayTunnelEntry {
        id,
        name: tunnel.name.clone(),
        marker: Health::of_session(state).marker(),
        status,
        items,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use conduit_runtime::{HostKeyPrompt, SessionStatsSnapshot};

    fn snap(name: &str, state: SessionState, listeners: &[(&str, &str)]) -> SessionSnapshot {
        SessionSnapshot {
            id: Uuid::new_v4(),
            name: name.into(),
            enabled: true,
            state,
            stats: SessionStatsSnapshot::default(),
            listeners: listeners
                .iter()
                .map(|(role, addr)| ListenerInfo {
                    role: (*role).into(),
                    addr: addr.parse().unwrap(),
                })
                .collect(),
            remote_listeners: Vec::new(),
            port_forwards: Vec::new(),
        }
    }

    fn labels(items: &[TrayMenuItem]) -> Vec<&str> {
        items.iter().map(|i| i.label.as_str()).collect()
    }

    fn both() -> [(&'static str, &'static str); 2] {
        [
            (ROLE_HTTP, "127.0.0.1:3128"),
            (ROLE_SOCKS, "127.0.0.1:1080"),
        ]
    }

    #[test]
    fn model_builds_full_connected_session_menu() {
        let s = snap("Prod Bastion", SessionState::Connected, &both());
        let id = s.id;
        let model = TrayMenuModel::from_snapshots(&[s], false);
        let entry = &model.sessions[0];

        assert_eq!(model.summary, "1 connected · 0 needs attention");
        assert_eq!(model.icon, TrayIconState::Connected);
        assert_eq!(entry.label(), "● Prod Bastion — Connected");
        assert_eq!(
            labels(&entry.items),
            [
                "Stop",
                "Restart",
                "Copy HTTP Proxy URL (http://127.0.0.1:3128)",
                "Copy SOCKS Proxy URL (socks5h://127.0.0.1:1080)",
                "View Logs",
            ]
        );
        assert_eq!(entry.items[0].action, TrayAction::StopSession(id));
        assert_eq!(
            entry.items[3].action,
            TrayAction::CopySocksUrl {
                session_id: id,
                url: "socks5h://127.0.0.1:1080".into()
            }
        );
        assert!(model.quit_needs_confirmation);
    }

    #[test]
    fn model_formats_socks5h_and_client_reachable_urls() {
        assert_eq!(
            socks_proxy_url("127.0.0.1:1080".parse().unwrap()),
            "socks5h://127.0.0.1:1080"
        );
        assert_eq!(
            socks_proxy_url("0.0.0.0:1080".parse().unwrap()),
            "socks5h://127.0.0.1:1080"
        );
        assert_eq!(
            http_proxy_url("[::]:3128".parse().unwrap()),
            "http://[::1]:3128"
        );
        assert_eq!(
            http_proxy_url("192.168.1.5:3128".parse().unwrap()),
            "http://192.168.1.5:3128"
        );
    }

    #[test]
    fn model_multiplexed_listener_serves_both_urls() {
        let s = snap(
            "Mux",
            SessionState::Connected,
            &[(ROLE_MULTIPLEXED, "127.0.0.1:8080")],
        );
        let model = TrayMenuModel::from_snapshots(&[s], false);
        let entry = &model.sessions[0];
        assert_eq!(entry.http_url.as_deref(), Some("http://127.0.0.1:8080"));
        assert_eq!(entry.socks_url.as_deref(), Some("socks5h://127.0.0.1:8080"));
    }

    #[test]
    fn model_unlock_vault_only_when_locked() {
        let unlocked = TrayMenuModel::from_snapshots(&[], false);
        assert_eq!(
            labels(&unlocked.global_items),
            ["Start All", "Stop All", "Open Manage Window…", "Quit"]
        );
        assert_eq!(unlocked.icon, TrayIconState::Idle);

        let locked = TrayMenuModel::from_snapshots(&[], true);
        assert_eq!(
            labels(&locked.global_items),
            [
                "Start All",
                "Stop All",
                "Unlock Vault…",
                "Open Manage Window…",
                "Quit"
            ]
        );
        assert_eq!(locked.icon, TrayIconState::Locked);
    }

    #[test]
    fn model_locked_session_offers_unlock_instead_of_start() {
        let s = snap("Vaulted", SessionState::Locked, &[]);
        let model = TrayMenuModel::from_snapshots(std::slice::from_ref(&s), true);
        assert_eq!(model.needs_attention, 1);
        assert_eq!(model.icon, TrayIconState::Locked);
        assert_eq!(model.sessions[0].items[0].action, TrayAction::UnlockVault);

        let after_unlock = TrayMenuModel::from_snapshots(std::slice::from_ref(&s), false);
        assert_eq!(
            after_unlock.sessions[0].items[0].action,
            TrayAction::StartSession(s.id)
        );
    }

    #[test]
    fn model_markers_summary_and_icon_priority() {
        let snapshots = [
            snap("A", SessionState::Connected, &both()),
            snap("B", SessionState::Connected, &both()),
            snap(
                "C",
                SessionState::Reconnecting {
                    attempt: 2,
                    next_retry_secs: 8,
                },
                &[],
            ),
            snap(
                "D",
                SessionState::NeedsAttention {
                    reason: "Auth rejected".into(),
                },
                &[],
            ),
            snap("E", SessionState::Stopped, &[]),
        ];
        let model = TrayMenuModel::from_snapshots(&snapshots, true);
        let markers: Vec<char> = model.sessions.iter().map(|e| e.marker).collect();

        assert_eq!(markers, ['●', '●', '◐', '!', '○']);
        assert_eq!(model.summary, "2 connected · 1 needs attention");
        assert_eq!(model.icon, TrayIconState::Attention);
        assert_eq!(model.sessions[2].status, "Reconnecting (8s)…");
        assert_eq!(model.sessions[3].status, "Needs attention");
        assert_eq!(model.sessions[4].status, "Stopped");
    }

    #[test]
    fn model_host_key_prompt_routes_to_manage_window() {
        let prompt = HostKeyPrompt {
            hop_index: 0,
            hop_id: "hop".into(),
            host: "h".into(),
            port: 22,
            algorithm: "ssh-ed25519".into(),
            sha256: "SHA256:x".into(),
            public_key_openssh: None,
        };
        let model = TrayMenuModel::from_snapshots(
            &[snap("K", SessionState::AwaitingHostKey(prompt), &[])],
            false,
        );
        assert_eq!(model.icon, TrayIconState::Attention);
        assert!(model.sessions[0]
            .items
            .iter()
            .any(|i| i.action == TrayAction::OpenManageWindow));
    }

    #[test]
    fn model_stopped_session_hides_stale_urls() {
        let s = snap("Old", SessionState::Stopped, &both());
        let model = TrayMenuModel::from_snapshots(&[s], false);
        let entry = &model.sessions[0];
        assert_eq!(entry.http_url, None);
        assert_eq!(entry.socks_url, None);
        assert_eq!(labels(&entry.items), ["Start", "View Logs"]);
        assert!(!model.quit_needs_confirmation);
    }

    #[test]
    fn model_start_and_stop_all_track_session_states() {
        let idle = TrayMenuModel::from_snapshots(&[snap("A", SessionState::Stopped, &[])], false);
        assert!(idle.global_items[0].enabled);
        assert!(!idle.global_items[1].enabled);

        let running =
            TrayMenuModel::from_snapshots(&[snap("A", SessionState::Connected, &[])], false);
        assert!(!running.global_items[0].enabled);
        assert!(running.global_items[1].enabled);

        let mut disabled = snap("A", SessionState::Stopped, &[]);
        disabled.enabled = false;
        let only_disabled = TrayMenuModel::from_snapshots(&[disabled], false);
        assert!(!only_disabled.global_items[0].enabled, "Start All would start nothing");
    }

    fn proxy(name: &str, state: ProxyState, listeners: &[(&str, &str)]) -> ProxyTrayItem {
        ProxyTrayItem {
            id: ProxyId::new(),
            name: name.into(),
            enabled: true,
            state,
            listeners: listeners
                .iter()
                .map(|(role, addr)| ListenerInfo {
                    role: (*role).into(),
                    addr: addr.parse().unwrap(),
                })
                .collect(),
            rule_count: 14,
            profiles: vec!["corp".into(), "tunnel Bastion".into()],
        }
    }

    fn running(override_profile: Option<&str>) -> ProxyState {
        ProxyState::Running {
            override_profile: override_profile.map(str::to_owned),
            config_generation: 1,
            restart_required: false,
        }
    }

    fn tunnel(name: &str, state: SessionState, linked_to: &[&str]) -> TunnelTrayItem {
        TunnelTrayItem {
            id: TunnelId::new(),
            name: name.into(),
            enabled: true,
            state,
            linked: true,
            linked_to: linked_to.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn entry_labels(entries: &[TrayMenuEntry]) -> Vec<String> {
        entries
            .iter()
            .map(|e| match e {
                TrayMenuEntry::Item(i) => i.label.clone(),
                TrayMenuEntry::Submenu(s) => format!("{} ▸", s.label),
            })
            .collect()
    }

    fn mode(entry: &TrayProxyEntry) -> &TraySubmenu {
        match &entry.entries[0] {
            TrayMenuEntry::Submenu(s) => s,
            TrayMenuEntry::Item(_) => panic!("expected the Mode submenu first"),
        }
    }

    fn item(entry: &TrayMenuEntry) -> &TrayMenuItem {
        match entry {
            TrayMenuEntry::Item(i) => i,
            TrayMenuEntry::Submenu(_) => panic!("expected an item"),
        }
    }

    #[test]
    fn model_running_proxy_has_mode_submenu_and_socks5h_urls() {
        let p = proxy("Work", running(None), &both());
        let id = p.id;
        let model = TrayMenuModel::from_state(&TrayState {
            proxies: vec![p],
            ..TrayState::default()
        });
        let entry = &model.proxies[0];

        assert_eq!(model.summary, "1 proxy running · 0 tunnels need attention");
        assert_eq!(model.icon, TrayIconState::Connected);
        assert_eq!(entry.label(), "● Work — Running");
        assert_eq!(
            entry_labels(&entry.entries),
            [
                "Mode ▸",
                "Stop",
                "Restart",
                "Copy HTTP Proxy URL (http://127.0.0.1:3128)",
                "Copy SOCKS Proxy URL (socks5h://127.0.0.1:1080)",
                "View Logs",
            ]
        );
        assert_eq!(entry.socks_url.as_deref(), Some("socks5h://127.0.0.1:1080"));
        assert!(!entry_labels(&entry.entries).iter().any(|l| l.contains("socks5://")));
        assert_eq!(item(&entry.entries[1]).action, TrayAction::StopProxy(id));
        assert_eq!(
            item(&entry.entries[4]).action,
            TrayAction::CopySocksUrl {
                session_id: id.as_uuid(),
                url: "socks5h://127.0.0.1:1080".into()
            }
        );
        assert_eq!(item(&entry.entries[5]).action, TrayAction::ViewProxyLogs(id));
        assert!(model.quit_needs_confirmation);
    }

    #[test]
    fn model_mode_submenu_checks_the_active_choice() {
        let auto = proxy("Work", running(None), &both());
        let id = auto.id;
        let model = TrayMenuModel::from_state(&TrayState {
            proxies: vec![auto],
            ..TrayState::default()
        });
        let submenu = mode(&model.proxies[0]);
        assert_eq!(submenu.label, "Mode");
        assert_eq!(
            entry_labels(&submenu.entries),
            [
                "✓ Auto Switch (14 rules)",
                "Force Direct",
                "Force corp",
                "Force tunnel Bastion"
            ]
        );
        assert_eq!(
            item(&submenu.entries[0]).action,
            TrayAction::SetProxyOverride { id, profile: None }
        );
        assert_eq!(
            item(&submenu.entries[1]).action,
            TrayAction::SetProxyOverride { id, profile: Some("direct".into()) }
        );
        assert_eq!(
            item(&submenu.entries[2]).action,
            TrayAction::SetProxyOverride { id, profile: Some("corp".into()) }
        );

        for (forced, checked) in [("direct", 1), ("corp", 2)] {
            let p = proxy("Work", running(Some(forced)), &both());
            let model = TrayMenuModel::from_state(&TrayState {
                proxies: vec![p],
                ..TrayState::default()
            });
            let labels = entry_labels(&mode(&model.proxies[0]).entries);
            let marked: Vec<usize> = labels
                .iter()
                .enumerate()
                .filter(|(_, l)| l.starts_with('✓'))
                .map(|(i, _)| i)
                .collect();
            assert_eq!(marked, [checked], "{labels:?}");
            assert_eq!(model.proxies[0].status, "Running");
        }
    }

    #[test]
    fn model_stopped_proxy_offers_start_without_mode_or_urls() {
        let p = proxy("Lab", ProxyState::Stopped, &both());
        let id = p.id;
        let model = TrayMenuModel::from_state(&TrayState {
            proxies: vec![p],
            ..TrayState::default()
        });
        let entry = &model.proxies[0];
        assert_eq!(entry.label(), "○ Lab — Stopped");
        assert_eq!(entry_labels(&entry.entries), ["Start", "View Logs"]);
        assert_eq!(item(&entry.entries[0]).action, TrayAction::StartProxy(id));
        assert_eq!(entry.http_url, None);
        assert!(model.global_items[0].enabled, "Start All");
        assert!(!model.global_items[1].enabled, "Stop All");
        assert!(!model.quit_needs_confirmation);
    }

    #[test]
    fn model_tunnel_shows_linked_and_attention_labels() {
        let linked = tunnel("Bastion", SessionState::Connected, &["Work"]);
        let broken = tunnel(
            "Client VPN",
            SessionState::NeedsAttention { reason: "Auth rejected".into() },
            &[],
        );
        let broken_id = broken.id;
        let model = TrayMenuModel::from_state(&TrayState {
            proxies: vec![
                proxy("Work", running(None), &both()),
                proxy("Lab", ProxyState::Stopped, &[]),
            ],
            tunnels: vec![linked, broken],
            ..TrayState::default()
        });

        assert_eq!(
            model.summary,
            "1 proxy running · 1 tunnel needs attention"
        );
        assert_eq!(model.icon, TrayIconState::Attention);
        assert_eq!(model.tunnels[0].label(), "● Bastion — Connected");
        assert_eq!(model.tunnels[1].label(), "! Client VPN — Needs attention");
        assert_eq!(
            labels(&model.tunnels[1].items),
            ["Start", "View Logs", "Open Manage Window…"]
        );
        assert_eq!(model.tunnels[1].items[0].action, TrayAction::StartTunnel(broken_id));
        assert_eq!(
            model.tunnels[1].items[1].action,
            TrayAction::ViewTunnelLogs(broken_id)
        );
        assert_eq!(model.proxies[0].status, "Running");
    }

    #[test]
    fn model_tunnel_actions_and_unlinked_label() {
        let mut manual = tunnel("Jump", SessionState::Connected, &["Work"]);
        manual.linked = false;
        let id = manual.id;
        let model = TrayMenuModel::from_state(&TrayState {
            tunnels: vec![manual],
            ..TrayState::default()
        });
        let entry = &model.tunnels[0];
        assert_eq!(entry.label(), "● Jump — Connected");
        assert_eq!(labels(&entry.items), ["Stop", "Restart", "View Logs"]);
        assert_eq!(entry.items[0].action, TrayAction::StopTunnel(id));
        assert_eq!(entry.items[1].action, TrayAction::RestartTunnel(id));
        assert_eq!(model.summary, "0 proxies running · 0 tunnels need attention");
    }

    #[test]
    fn model_locked_proxy_and_tunnel_offer_unlock() {
        let model = TrayMenuModel::from_state(&TrayState {
            proxies: vec![proxy("Work", ProxyState::Locked, &[])],
            tunnels: vec![tunnel("Bastion", SessionState::Locked, &[])],
            vault_locked: true,
            ..TrayState::default()
        });
        assert_eq!(model.icon, TrayIconState::Locked);
        assert_eq!(model.needs_attention, 2);
        assert_eq!(
            item(&model.proxies[0].entries[0]).action,
            TrayAction::UnlockVault
        );
        assert_eq!(model.tunnels[0].items[0].action, TrayAction::UnlockVault);
        assert_eq!(model.proxies[0].status, "Vault locked");
    }
}
