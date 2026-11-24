//! Linux tray backend using `ksni`, a pure-Rust D-Bus `StatusNotifierItem` client.
//!
//! A dedicated thread owns the D-Bus service, so callers need no async runtime. A missing bus
//! or watcher is reported as [`TrayHostStatus::Offline`] and retried, and never panics.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use ksni::menu::{StandardItem, SubMenu};
use ksni::{Category, Handle, Icon, MenuItem, OfflineReason, Status, Tray, TrayMethods};
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::backend::{ActionDispatcher, SharedHostStatus, TrayBackend, TrayError};
use crate::image::TrayImage;
use crate::model::{
    TrayAction, TrayHostStatus, TrayIconState, TrayMenuItem, TrayMenuModel, APP_TITLE,
};

const TRAY_ID: &str = "rusty-conduit-ssh";
/// How often a lost D-Bus connection is retried.
const RETRY_INTERVAL: Duration = Duration::from_secs(5);
/// Upper limit for one D-Bus operation, so a stuck bus cannot block shutdown forever.
const DBUS_TIMEOUT: Duration = Duration::from_secs(3);

struct ConduitTray {
    model: TrayMenuModel,
    /// The app logo. Without one, the state icons from the desktop's theme are used.
    icon: Option<TrayImage>,
    dispatcher: ActionDispatcher,
    status: SharedHostStatus,
    watcher_missing: Arc<AtomicBool>,
}

// Dbusmenu treats `_` as a keyboard-accelerator marker, and `__` as a literal underscore.
fn escape_label(label: &str) -> String {
    label.replace('_', "__")
}

fn icon_name(icon: TrayIconState) -> &'static str {
    match icon {
        TrayIconState::Idle => "network-offline",
        TrayIconState::Connected => "network-transmit-receive",
        TrayIconState::Reconnecting => "view-refresh",
        TrayIconState::Attention => "dialog-warning",
        TrayIconState::Locked => "changes-prevent",
    }
}

fn sni_icon(image: &TrayImage) -> Icon {
    Icon {
        width: i32::try_from(image.width).unwrap_or(i32::MAX),
        height: i32::try_from(image.height).unwrap_or(i32::MAX),
        data: image.to_argb32(),
    }
}

fn sni_status(icon: TrayIconState) -> Status {
    match icon {
        TrayIconState::Attention | TrayIconState::Locked => Status::NeedsAttention,
        _ => Status::Active,
    }
}

fn standard_item(item: &TrayMenuItem) -> MenuItem<ConduitTray> {
    let action: TrayAction = item.action.clone();
    StandardItem {
        label: escape_label(&item.label),
        enabled: item.enabled,
        activate: Box::new(move |tray: &mut ConduitTray| {
            tray.dispatcher.dispatch(action.clone());
        }),
        ..Default::default()
    }
    .into()
}

fn build_menu(model: &TrayMenuModel) -> Vec<MenuItem<ConduitTray>> {
    let mut menu: Vec<MenuItem<ConduitTray>> = vec![
        StandardItem {
            label: escape_label(&format!("{APP_TITLE} — {}", model.summary)),
            enabled: false,
            ..Default::default()
        }
        .into(),
        MenuItem::Separator,
    ];

    if model.sessions.is_empty() {
        menu.push(
            StandardItem {
                label: "No sessions".into(),
                enabled: false,
                ..Default::default()
            }
            .into(),
        );
    }
    for session in &model.sessions {
        menu.push(
            SubMenu {
                label: escape_label(&session.label()),
                submenu: session.items.iter().map(standard_item).collect(),
                ..Default::default()
            }
            .into(),
        );
    }

    menu.push(MenuItem::Separator);
    menu.extend(model.global_items.iter().map(standard_item));
    menu
}

impl Tray for ConduitTray {
    fn id(&self) -> String {
        TRAY_ID.into()
    }

    fn category(&self) -> Category {
        Category::ApplicationStatus
    }

    fn title(&self) -> String {
        format!("{APP_TITLE} — {}", self.model.summary)
    }

    fn status(&self) -> Status {
        sni_status(self.model.icon)
    }

    fn icon_name(&self) -> String {
        // Hosts prefer a theme name over a pixmap, so leave it empty when there is a logo.
        if self.icon.is_some() {
            String::new()
        } else {
            icon_name(self.model.icon).into()
        }
    }

    fn icon_pixmap(&self) -> Vec<Icon> {
        self.icon.iter().map(sni_icon).collect()
    }

    /// Shown instead of the logo while the status is `NeedsAttention`.
    fn attention_icon_name(&self) -> String {
        if self.icon.is_some() {
            icon_name(TrayIconState::Attention).into()
        } else {
            String::new()
        }
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        build_menu(&self.model)
    }

    fn watcher_online(&self) {
        self.watcher_missing.store(false, Ordering::Release);
        self.status.set(TrayHostStatus::Online);
    }

    // Returning `true` keeps the service alive, so the icon registers when a watcher appears.
    fn watcher_offline(&self, _reason: OfflineReason) -> bool {
        self.watcher_missing.store(true, Ordering::Release);
        self.status.set(TrayHostStatus::Offline);
        true
    }
}

enum Command {
    Update(Box<TrayMenuModel>),
    Shutdown,
}

#[derive(Clone)]
struct Shared {
    status: SharedHostStatus,
    dispatcher: ActionDispatcher,
}

// Runs even if the worker panics, so callers never see a stale status or a hanging stream.
struct WorkerExit(Shared);

impl Drop for WorkerExit {
    fn drop(&mut self) {
        self.0.status.set(TrayHostStatus::Offline);
        self.0.dispatcher.close();
    }
}

async fn connect(
    model: &TrayMenuModel,
    icon: Option<&TrayImage>,
    shared: &Shared,
) -> Option<Handle<ConduitTray>> {
    let watcher_missing = Arc::new(AtomicBool::new(false));
    let tray = ConduitTray {
        model: model.clone(),
        icon: icon.cloned(),
        dispatcher: shared.dispatcher.clone(),
        status: shared.status.clone(),
        watcher_missing: Arc::clone(&watcher_missing),
    };
    match timeout(DBUS_TIMEOUT, tray.assume_sni_available(true).spawn()).await {
        Ok(Ok(handle)) => {
            // The runtime is single-threaded, so no callback can run between load and set.
            if !watcher_missing.load(Ordering::Acquire) {
                shared.status.set(TrayHostStatus::Online);
            }
            Some(handle)
        }
        Ok(Err(_)) | Err(_) => {
            shared.status.set(TrayHostStatus::Offline);
            None
        }
    }
}

async fn run(
    mut model: TrayMenuModel,
    icon: Option<TrayImage>,
    mut commands: mpsc::UnboundedReceiver<Command>,
    shared: Shared,
) {
    let mut handle: Option<Handle<ConduitTray>> = None;
    let mut next_attempt = tokio::time::Instant::now();

    loop {
        if handle.as_ref().is_some_and(Handle::is_closed) {
            handle = None;
            shared.status.set(TrayHostStatus::Offline);
        }
        if handle.is_none() && tokio::time::Instant::now() >= next_attempt {
            handle = connect(&model, icon.as_ref(), &shared).await;
            next_attempt = tokio::time::Instant::now() + RETRY_INTERVAL;
        }

        let command = tokio::select! {
            command = commands.recv() => command,
            () = tokio::time::sleep(RETRY_INTERVAL) => continue,
        };
        match command {
            Some(Command::Update(next)) => {
                model = *next;
                if let Some(active) = &handle {
                    let shown = model.clone();
                    let update = active.update(move |tray| tray.model = shown);
                    if matches!(timeout(DBUS_TIMEOUT, update).await, Ok(None)) {
                        handle = None;
                        shared.status.set(TrayHostStatus::Offline);
                    }
                }
            }
            Some(Command::Shutdown) | None => {
                if let Some(active) = handle {
                    let _ = timeout(DBUS_TIMEOUT, active.shutdown()).await;
                }
                return;
            }
        }
    }
}

/// The Linux tray. Dropping it also removes the icon.
pub struct KsniTrayBackend {
    commands: mpsc::UnboundedSender<Command>,
    shared: Shared,
    worker: Option<JoinHandle<()>>,
}

impl KsniTrayBackend {
    /// Starts the tray worker. This succeeds without D-Bus or a tray host: check
    /// [`TrayBackend::host_status`] for availability.
    ///
    /// `icon` is the app logo. Without it, the desktop theme's state icons are shown instead.
    pub fn spawn(initial: TrayMenuModel, icon: Option<TrayImage>) -> Result<Self, TrayError> {
        let (commands, receiver) = mpsc::unbounded_channel();
        let shared = Shared {
            status: SharedHostStatus::new(TrayHostStatus::Waiting),
            dispatcher: ActionDispatcher::default(),
        };
        let worker_shared = shared.clone();
        let worker = thread::Builder::new()
            .name("conduit-tray".into())
            .spawn(move || {
                let _exit = WorkerExit(worker_shared.clone());
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return;
                };
                runtime.block_on(run(initial, icon, receiver, worker_shared));
            })?;
        Ok(Self {
            commands,
            shared,
            worker: Some(worker),
        })
    }
}

impl TrayBackend for KsniTrayBackend {
    fn update(&self, model: TrayMenuModel) -> Result<(), TrayError> {
        self.commands
            .send(Command::Update(Box::new(model)))
            .map_err(|_| TrayError::Closed)
    }

    fn host_status(&self) -> TrayHostStatus {
        self.shared.status.get()
    }

    fn subscribe_actions(&self) -> mpsc::UnboundedReceiver<TrayAction> {
        self.shared.dispatcher.subscribe()
    }

    fn shutdown(mut self) {
        let _ = self.commands.send(Command::Shutdown);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for KsniTrayBackend {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Shutdown);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use conduit_runtime::{ListenerInfo, SessionSnapshot, SessionState, SessionStatsSnapshot};
    use uuid::Uuid;

    fn session(name: &str) -> SessionSnapshot {
        SessionSnapshot {
            id: Uuid::new_v4(),
            name: name.into(),
            enabled: true,
            state: SessionState::Connected,
            stats: SessionStatsSnapshot::default(),
            listeners: vec![ListenerInfo {
                role: "SOCKS4/4a/5".into(),
                addr: "127.0.0.1:1080".parse().unwrap(),
            }],
            remote_listeners: Vec::new(),
        }
    }

    fn tray(model: TrayMenuModel) -> ConduitTray {
        ConduitTray {
            model,
            icon: None,
            dispatcher: ActionDispatcher::default(),
            status: SharedHostStatus::new(TrayHostStatus::Waiting),
            watcher_missing: Arc::new(AtomicBool::new(false)),
        }
    }

    #[test]
    fn ksni_logo_replaces_theme_icons_and_attention_uses_a_warning() {
        let model = TrayMenuModel::from_snapshots(&[session("a")], false);
        let plain = tray(model.clone());
        assert_eq!(plain.icon_name(), "network-transmit-receive");
        assert!(plain.icon_pixmap().is_empty());
        assert!(plain.attention_icon_name().is_empty());

        let logo = TrayImage::new(1, 1, vec![10, 20, 30, 255]).unwrap();
        let branded = ConduitTray { icon: Some(logo), ..tray(model) };
        assert_eq!(branded.icon_name(), "", "a theme name would win over the logo");
        let pixmap = branded.icon_pixmap();
        assert_eq!((pixmap[0].width, pixmap[0].height), (1, 1));
        assert_eq!(pixmap[0].data, vec![255, 10, 20, 30]);
        assert_eq!(branded.attention_icon_name(), "dialog-warning");
    }

    fn label(item: &MenuItem<ConduitTray>) -> &str {
        match item {
            MenuItem::Standard(i) => &i.label,
            MenuItem::SubMenu(i) => &i.label,
            _ => "",
        }
    }

    #[test]
    fn ksni_menu_matches_model_layout() {
        let model = TrayMenuModel::from_snapshots(&[session("prod_eu")], true);
        let menu = build_menu(&model);
        let labels: Vec<&str> = menu.iter().map(label).collect();

        assert_eq!(
            labels,
            [
                "Rusty Conduit SSH — 1 connected · 0 needs attention",
                "",
                "● prod__eu — Connected (SOCKS :1080)",
                "",
                "Start All",
                "Stop All",
                "Unlock Vault…",
                "Open Manage Window…",
                "Quit",
            ]
        );
        assert!(matches!(&menu[0], MenuItem::Standard(i) if !i.enabled));
    }

    #[test]
    fn ksni_menu_click_dispatches_action() {
        let snapshot = session("prod");
        let id = snapshot.id;
        let model = TrayMenuModel::from_snapshots(&[snapshot], false);
        let menu = build_menu(&model);
        let mut tray = tray(model);
        let mut actions = tray.dispatcher.subscribe();

        let MenuItem::SubMenu(submenu) = &menu[2] else {
            panic!("expected a session submenu");
        };
        let MenuItem::Standard(stop) = &submenu.submenu[0] else {
            panic!("expected a Stop item");
        };
        (stop.activate)(&mut tray);

        assert_eq!(actions.try_recv().unwrap(), TrayAction::StopSession(id));
    }

    #[test]
    fn ksni_empty_menu_shows_placeholder() {
        let menu = build_menu(&TrayMenuModel::from_snapshots(&[], false));
        assert_eq!(label(&menu[2]), "No sessions");
    }

    #[test]
    fn ksni_watcher_callbacks_track_host_status() {
        let tray = tray(TrayMenuModel::from_snapshots(&[], false));

        assert!(tray.watcher_offline(OfflineReason::No));
        assert_eq!(tray.status.get(), TrayHostStatus::Offline);
        assert!(tray.watcher_missing.load(Ordering::Acquire));

        tray.watcher_online();
        assert_eq!(tray.status.get(), TrayHostStatus::Online);
        assert!(!tray.watcher_missing.load(Ordering::Acquire));
    }

    #[test]
    fn ksni_icon_maps_every_state() {
        assert_eq!(icon_name(TrayIconState::Attention), "dialog-warning");
        assert!(matches!(
            sni_status(TrayIconState::Locked),
            Status::NeedsAttention
        ));
        assert!(matches!(sni_status(TrayIconState::Idle), Status::Active));
    }
}
