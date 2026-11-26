//! Windows and macOS tray backend, using Tauri's built-in `tray-icon`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use conduit_tray::{
    TrayAction, TrayBackend, TrayError, TrayHostStatus, TrayMenuEntry, TrayMenuItem, TrayMenuModel,
    APP_TITLE,
};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::{TrayIcon, TrayIconBuilder};
use tauri::{AppHandle, Runtime};
use tokio::sync::mpsc;

const TRAY_ID: &str = "rusty-conduit-ssh";

type Subscribers = Arc<Mutex<Vec<mpsc::UnboundedSender<TrayAction>>>>;
type ActionMap = Arc<Mutex<HashMap<String, TrayAction>>>;

// These lists stay valid if a holder panics, so a poisoned lock is safe to reuse.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

// Menus treat `&` as a keyboard-accelerator marker, and `&&` as a literal ampersand.
fn escape_label(label: &str) -> String {
    label.replace('&', "&&")
}

/// Builds a native menu, and the id-to-action table for it.
struct MenuBuild<'a, R: Runtime> {
    app: &'a AppHandle<R>,
    actions: HashMap<String, TrayAction>,
}

impl<R: Runtime> MenuBuild<'_, R> {
    fn item(&mut self, item: &TrayMenuItem) -> tauri::Result<MenuItem<R>> {
        let id = format!("conduit-{}", self.actions.len());
        self.actions.insert(id.clone(), item.action.clone());
        MenuItem::with_id(self.app, id, escape_label(&item.label), item.enabled, None::<&str>)
    }

    fn label(&self, text: &str) -> tauri::Result<MenuItem<R>> {
        MenuItem::new(self.app, escape_label(text), false, None::<&str>)
    }

    fn submenu(&mut self, label: &str, entries: &[TrayMenuEntry]) -> tauri::Result<Submenu<R>> {
        let submenu = Submenu::new(self.app, escape_label(label), true)?;
        for entry in entries {
            // Recursive, so a Proxy's `Mode ▸` becomes a submenu inside the Proxy's submenu.
            match entry {
                TrayMenuEntry::Item(item) => submenu.append(&self.item(item)?)?,
                TrayMenuEntry::Submenu(nested) => {
                    submenu.append(&self.submenu(&nested.label, &nested.entries)?)?;
                }
            }
        }
        Ok(submenu)
    }

    fn flat_submenu(&mut self, label: &str, items: &[TrayMenuItem]) -> tauri::Result<Submenu<R>> {
        let entries: Vec<TrayMenuEntry> = items.iter().cloned().map(TrayMenuEntry::Item).collect();
        self.submenu(label, &entries)
    }

    fn menu(&mut self, model: &TrayMenuModel) -> tauri::Result<Menu<R>> {
        let menu = Menu::new(self.app)?;
        menu.append(&self.label(&format!("{APP_TITLE} — {}", model.summary))?)?;
        menu.append(&PredefinedMenuItem::separator(self.app)?)?;

        if model.proxies.is_empty() && model.tunnels.is_empty() && model.sessions.is_empty() {
            menu.append(&self.label("No proxies or tunnels")?)?;
        }
        if !model.proxies.is_empty() {
            menu.append(&self.label("PROXIES")?)?;
            for proxy in &model.proxies {
                menu.append(&self.submenu(&proxy.label(), &proxy.entries)?)?;
            }
        }
        if !model.tunnels.is_empty() {
            menu.append(&self.label("TUNNELS")?)?;
            for tunnel in &model.tunnels {
                menu.append(&self.flat_submenu(&tunnel.label(), &tunnel.items)?)?;
            }
        }
        if !model.sessions.is_empty() && !(model.proxies.is_empty() && model.tunnels.is_empty()) {
            menu.append(&self.label("SESSIONS")?)?;
        }
        for session in &model.sessions {
            menu.append(&self.flat_submenu(&session.label(), &session.items)?)?;
        }

        menu.append(&PredefinedMenuItem::separator(self.app)?)?;
        for item in &model.global_items {
            menu.append(&self.item(item)?)?;
        }
        Ok(menu)
    }
}

/// The Windows and macOS tray. These platforms always have a tray host.
pub struct TauriTrayBackend<R: Runtime> {
    app: AppHandle<R>,
    tray: TrayIcon<R>,
    actions: ActionMap,
    subscribers: Subscribers,
}

/// The menu-bar icon. macOS draws a template image from its alpha channel alone, so it gets a
/// version of the logo whose ring and bar are transparent cutouts; the colored app icon would
/// show as a plain disc there. Other platforms show the app icon in color.
fn tray_icon<R: Runtime>(app: &AppHandle<R>) -> Option<tauri::image::Image<'static>> {
    if cfg!(target_os = "macos") {
        Some(tauri::include_image!("icons/tray-template.png"))
    } else {
        app.default_window_icon().map(|icon| icon.clone().to_owned())
    }
}

impl<R: Runtime> TauriTrayBackend<R> {
    pub fn spawn(app: &AppHandle<R>, initial: &TrayMenuModel) -> tauri::Result<Self> {
        let mut build = MenuBuild { app, actions: HashMap::new() };
        let menu = build.menu(initial)?;
        let actions: ActionMap = Arc::new(Mutex::new(build.actions));
        let subscribers: Subscribers = Arc::default();

        let (event_actions, event_subscribers) = (Arc::clone(&actions), Arc::clone(&subscribers));
        let mut builder = TrayIconBuilder::with_id(TRAY_ID)
            .menu(&menu)
            // Menu-first: every action is in the menu on every click.
            .show_menu_on_left_click(true)
            .tooltip(format!("{APP_TITLE} — {}", initial.summary))
            .icon_as_template(cfg!(target_os = "macos"))
            .on_menu_event(move |_app, event| {
                let action = lock(&event_actions).get(event.id().as_ref()).cloned();
                if let Some(action) = action {
                    lock(&event_subscribers).retain(|tx| tx.send(action.clone()).is_ok());
                }
            });
        if let Some(icon) = tray_icon(app) {
            builder = builder.icon(icon);
        }
        let tray = builder.build(app)?;

        Ok(Self { app: app.clone(), tray, actions, subscribers })
    }
}

impl<R: Runtime> TrayBackend for TauriTrayBackend<R> {
    fn update(&self, model: TrayMenuModel) -> Result<(), TrayError> {
        let mut build = MenuBuild { app: &self.app, actions: HashMap::new() };
        let applied = build.menu(&model).and_then(|menu| {
            self.tray.set_menu(Some(menu))?;
            self.tray.set_tooltip(Some(format!("{APP_TITLE} — {}", model.summary)))
        });
        match applied {
            Ok(()) => {
                *lock(&self.actions) = build.actions;
                Ok(())
            }
            Err(error) => Err(TrayError::Spawn(std::io::Error::other(error.to_string()))),
        }
    }

    fn host_status(&self) -> TrayHostStatus {
        TrayHostStatus::Online
    }

    fn subscribe_actions(&self) -> mpsc::UnboundedReceiver<TrayAction> {
        let (tx, rx) = mpsc::unbounded_channel();
        lock(&self.subscribers).push(tx);
        rx
    }

    fn shutdown(self) {
        lock(&self.subscribers).clear();
        let _ = self.tray.set_visible(false);
    }
}
