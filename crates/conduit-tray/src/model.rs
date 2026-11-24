//! The platform-neutral tray menu, built from session snapshots and the vault lock state.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use conduit_runtime::{ListenerInfo, SessionSnapshot, SessionState};
use uuid::Uuid;

/// Name shown at the top of the tray menu.
pub const APP_TITLE: &str = "Rusty Conduit (SSH)";

// These match the `Display` output of the engine's `ListenerRole`, which is how
// `ListenerInfo::role` is filled in.
const ROLE_HTTP: &str = "HTTP/HTTPS";
const ROLE_SOCKS: &str = "SOCKS4/4a/5";
const ROLE_MULTIPLEXED: &str = "multiplexed HTTP/HTTPS + SOCKS4/4a/5";

/// Longest failure reason shown in a menu label, in characters.
const MAX_REASON_CHARS: usize = 48;

/// Something the user picked from the tray menu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrayAction {
    StartSession(Uuid),
    StopSession(Uuid),
    RestartSession(Uuid),
    CopyHttpUrl {
        session_id: Uuid,
        url: String,
    },
    CopySocksUrl {
        session_id: Uuid,
        url: String,
    },
    ViewLogs(Uuid),
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

/// One session and its submenu.
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

/// Everything a tray backend needs to draw the menu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayMenuModel {
    /// `N connected · M needs attention`.
    pub summary: String,
    pub connected: usize,
    pub needs_attention: usize,
    pub icon: TrayIconState,
    pub sessions: Vec<TraySessionEntry>,
    /// Start All, Stop All, the conditional Unlock Vault, Open Manage Window, and Quit.
    pub global_items: Vec<TrayMenuItem>,
    pub vault_locked: bool,
    pub quit_needs_confirmation: bool,
}

impl TrayMenuModel {
    /// Builds the menu. Session order is preserved.
    pub fn from_snapshots(snapshots: &[SessionSnapshot], vault_locked: bool) -> Self {
        let connected = snapshots
            .iter()
            .filter(|s| s.state == SessionState::Connected)
            .count();
        let needs_attention = snapshots
            .iter()
            .filter(|s| needs_attention(&s.state))
            .count();
        // Start All leaves disabled sessions out, so they do not make it clickable.
        let any_startable = snapshots.iter().any(|s| s.enabled && s.state.is_terminal());
        let any_active = snapshots.iter().any(|s| !s.state.is_terminal());

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

        Self {
            summary: format!("{connected} connected · {needs_attention} needs attention"),
            connected,
            needs_attention,
            icon: icon_for(snapshots, vault_locked),
            sessions: snapshots
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

fn in_progress(state: &SessionState) -> bool {
    matches!(
        state,
        SessionState::Starting
            | SessionState::Reconnecting { .. }
            | SessionState::WaitingForNetwork
    )
}

fn icon_for(snapshots: &[SessionSnapshot], vault_locked: bool) -> TrayIconState {
    let any = |test: fn(&SessionState) -> bool| snapshots.iter().any(|s| test(&s.state));
    if any(|s| needs_attention(s) && *s != SessionState::Locked) {
        TrayIconState::Attention
    } else if vault_locked {
        TrayIconState::Locked
    } else if any(|s| *s == SessionState::Locked) {
        TrayIconState::Attention
    } else if any(in_progress) {
        TrayIconState::Reconnecting
    } else if any(|s| *s == SessionState::Connected) {
        TrayIconState::Connected
    } else {
        TrayIconState::Idle
    }
}

fn marker_for(state: &SessionState) -> char {
    match state {
        SessionState::Connected => '●',
        SessionState::Stopped => '○',
        s if needs_attention(s) => '!',
        _ => '◐',
    }
}

fn listener_addr(listeners: &[ListenerInfo], role: &str) -> Option<SocketAddr> {
    let by_role = |wanted: &str| listeners.iter().find(|l| l.role == wanted).map(|l| l.addr);
    by_role(role).or_else(|| by_role(ROLE_MULTIPLEXED))
}

// One line, bounded, so a long engine error cannot break the menu layout.
fn short_reason(reason: &str) -> String {
    let flat = reason.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= MAX_REASON_CHARS {
        return flat;
    }
    let kept: String = flat.chars().take(MAX_REASON_CHARS - 1).collect();
    format!("{}…", kept.trim_end())
}

fn status_text(
    state: &SessionState,
    http: Option<SocketAddr>,
    socks: Option<SocketAddr>,
) -> String {
    match state {
        SessionState::Stopped => "Stopped → Start".into(),
        SessionState::Starting => "Starting…".into(),
        SessionState::Connected => {
            let ports: Vec<String> = [("HTTP", http), ("SOCKS", socks)]
                .into_iter()
                .filter_map(|(name, addr)| addr.map(|a| format!("{name} :{}", a.port())))
                .collect();
            if ports.is_empty() {
                "Connected".into()
            } else {
                format!("Connected ({})", ports.join(" · "))
            }
        }
        SessionState::Reconnecting {
            next_retry_secs, ..
        } => format!("Reconnecting ({next_retry_secs}s)…"),
        SessionState::WaitingForNetwork => "Waiting for network…".into(),
        SessionState::Locked => "Vault locked".into(),
        SessionState::AwaitingHostKey(_) => "Host key needs review → Open Manage Window".into(),
        SessionState::NeedsAttention { reason } | SessionState::Failed { reason } => {
            format!("{} → Open Manage Window", short_reason(reason))
        }
    }
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
    if let Some(url) = &http_url {
        items.push(TrayMenuItem::new(
            format!("Copy HTTP Proxy URL ({url})"),
            TrayAction::CopyHttpUrl {
                session_id: id,
                url: url.clone(),
            },
        ));
    }
    if let Some(url) = &socks_url {
        items.push(TrayMenuItem::new(
            format!("Copy SOCKS Proxy URL ({url})"),
            TrayAction::CopySocksUrl {
                session_id: id,
                url: url.clone(),
            },
        ));
    }
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
        marker: marker_for(state),
        status: status_text(state, http, socks),
        http_url,
        socks_url,
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
        assert_eq!(
            entry.label(),
            "● Prod Bastion — Connected (HTTP :3128 · SOCKS :1080)"
        );
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
        assert_eq!(
            model.sessions[3].status,
            "Auth rejected → Open Manage Window"
        );
        assert_eq!(model.sessions[4].status, "Stopped → Start");
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

    #[test]
    fn model_long_reason_is_one_bounded_line() {
        let text = short_reason(&format!("first\nsecond {}", "x".repeat(200)));
        assert!(!text.contains('\n'));
        assert_eq!(text.chars().count(), MAX_REASON_CHARS);
        assert!(text.ends_with('…'));
    }
}
