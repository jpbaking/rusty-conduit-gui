//! The Manage Window lifecycle. Closing it destroys the webview, so no WebKitGTK, WebView2, or
//! WKWebView helper stays alive while tunnels and the tray keep running in Rust.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, Runtime, WebviewUrl, WebviewWindowBuilder, Window, WindowEvent};
use uuid::Uuid;

/// The window label. `capabilities/default.json` grants permissions to this label.
pub const MAIN_WINDOW: &str = "main";
pub const EVENT_RUNTIME: &str = "runtime-event";
pub const EVENT_RUNTIME_LAGGED: &str = "runtime-lagged";
pub const EVENT_TRAY_STATUS: &str = "tray-status";

/// Undelivered UI events kept for the next window. The oldest are dropped past this.
const MAX_PENDING_EVENTS: usize = 16;

/// A request from the backend to the Manage Window. The serialized `event` is also the Tauri
/// event name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "event", content = "payload", rename_all = "kebab-case")]
pub enum UiEvent {
    /// The tray could not write to the clipboard. Show this URL pre-selected.
    ClipboardFallback { url: String },
    ViewLogs { session_id: Uuid },
    UnlockVault,
    /// No tray host: ask Keep running in background vs. Quit.
    CloseConfirm,
    /// Sessions are active: confirm before quitting.
    QuitConfirm,
    /// One-time upgrade banner (e.g. rebrand migration completed or skipped).
    MigrationNotice { message: String, is_warning: bool },
}

impl UiEvent {
    pub fn name(&self) -> &'static str {
        match self {
            Self::ClipboardFallback { .. } => "clipboard-fallback",
            Self::ViewLogs { .. } => "view-logs",
            Self::UnlockVault => "unlock-vault",
            Self::CloseConfirm => "close-confirm",
            Self::QuitConfirm => "quit-confirm",
            Self::MigrationNotice { .. } => "migration-notice",
        }
    }

    fn payload(&self) -> serde_json::Value {
        match serde_json::to_value(self) {
            Ok(serde_json::Value::Object(mut fields)) => {
                fields.remove("payload").unwrap_or(serde_json::Value::Null)
            }
            _ => serde_json::Value::Null,
        }
    }
}

/// What the UI receives when it finishes loading.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ShellSnapshot {
    pub tray_available: bool,
    pub pending: Vec<UiEvent>,
}

/// The user's answer to [`UiEvent::CloseConfirm`] or [`UiEvent::QuitConfirm`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloseChoice {
    KeepRunning,
    Quit,
    Cancel,
}

/// What to do with a window close request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseDecision {
    /// Let the close proceed, which destroys the webview.
    Destroy,
    /// Keep the window and ask the user.
    Ask,
}

#[derive(Default)]
struct UiChannel {
    /// The current webview finished loading and listens for events.
    ready: bool,
    pending: Vec<UiEvent>,
}

/// Window and tray state shared by the shell.
pub struct ShellState {
    tray_available: AtomicBool,
    close_asked: AtomicBool,
    ui: Mutex<UiChannel>,
    /// Stops two concurrent opens from both creating the window.
    open_lock: Mutex<()>,
}

impl Default for ShellState {
    fn default() -> Self {
        Self {
            // Assume a tray until the startup wait says otherwise, so the banner cannot flash.
            tray_available: AtomicBool::new(true),
            close_asked: AtomicBool::new(false),
            ui: Mutex::new(UiChannel::default()),
            open_lock: Mutex::new(()),
        }
    }
}

// Guarded values stay valid if a holder panics, so a poisoned lock is safe to reuse.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl ShellState {
    pub fn tray_available(&self) -> bool {
        self.tray_available.load(Ordering::Acquire)
    }

    pub fn set_tray_available(&self, available: bool) {
        self.tray_available.store(available, Ordering::Release);
    }

    /// Marks the webview as listening and hands it everything queued while it loaded.
    pub fn mark_ui_ready(&self) -> ShellSnapshot {
        let mut ui = lock(&self.ui);
        ui.ready = true;
        ShellSnapshot {
            tray_available: self.tray_available(),
            pending: std::mem::take(&mut ui.pending),
        }
    }

    /// Returns the event if the UI can receive it now. Otherwise queues it, because an event
    /// emitted before the page has its listeners would be lost.
    fn route(&self, event: UiEvent) -> Option<UiEvent> {
        let mut ui = lock(&self.ui);
        if ui.ready {
            return Some(event);
        }
        if !ui.pending.contains(&event) {
            if ui.pending.len() == MAX_PENDING_EVENTS {
                ui.pending.remove(0);
            }
            ui.pending.push(event);
        }
        None
    }

    /// Only a loaded UI can answer, so a blank or broken page can always be closed. A second
    /// close while the question is open also goes through, so the window cannot get stuck.
    pub fn on_close_requested(&self) -> CloseDecision {
        if self.tray_available() || !lock(&self.ui).ready {
            return CloseDecision::Destroy;
        }
        if self.close_asked.swap(true, Ordering::AcqRel) {
            CloseDecision::Destroy
        } else {
            CloseDecision::Ask
        }
    }

    pub fn clear_close_question(&self) {
        self.close_asked.store(false, Ordering::Release);
    }

    pub fn on_window_destroyed(&self) {
        lock(&self.ui).ready = false;
        self.clear_close_question();
    }
}

/// Shows the Dock icon only while the Manage Window exists.
#[cfg(target_os = "macos")]
fn set_dock_visible<R: Runtime>(app: &AppHandle<R>, visible: bool) {
    let policy = if visible {
        tauri::ActivationPolicy::Regular
    } else {
        tauri::ActivationPolicy::Accessory
    };
    if let Err(error) = app.set_activation_policy(policy) {
        eprintln!("could not change the activation policy: {error}");
    }
}

#[cfg(not(target_os = "macos"))]
fn set_dock_visible<R: Runtime>(_app: &AppHandle<R>, _visible: bool) {}

/// Logical width and starting height of the Manage Window. The width is fixed, because the UI
/// is laid out for it; the height can only grow from here, for more log and editor space.
const MANAGE_WINDOW_SIZE: (f64, f64) = (1100.0, 720.0);
/// Height cap for the Manage Window, well above any screen: the OS limits the window to the
/// screen, so maximize or zoom fills the screen's height and keeps the width.
const MANAGE_WINDOW_MAX_HEIGHT: f64 = 16_384.0;

/// Focuses the Manage Window, creating it if needed. Do not call from a synchronous command,
/// where creating a window can deadlock on Windows.
pub fn open_or_focus_manage_window<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    let state = app.state::<ShellState>();
    let _opening = lock(&state.open_lock);

    if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
        window.unminimize()?;
        window.show()?;
        return window.set_focus();
    }

    set_dock_visible(app, true);
    let built = WebviewWindowBuilder::new(app, MAIN_WINDOW, WebviewUrl::App("index.html".into()))
        .title(conduit_tray::APP_TITLE)
        // Fixed width, so the layout stays predictable; the height can grow (drag the top or
        // bottom edge, or maximize/zoom) when the logs need more room.
        .inner_size(MANAGE_WINDOW_SIZE.0, MANAGE_WINDOW_SIZE.1)
        .min_inner_size(MANAGE_WINDOW_SIZE.0, MANAGE_WINDOW_SIZE.1)
        .max_inner_size(MANAGE_WINDOW_SIZE.0, MANAGE_WINDOW_MAX_HEIGHT)
        .resizable(true)
        .maximizable(true)
        .build();
    match built {
        Ok(window) => window.set_focus(),
        Err(error) => {
            set_dock_visible(app, false);
            Err(error)
        }
    }
}

/// Delivers `event` to the Manage Window now, or when it next finishes loading.
pub fn deliver_ui_event<R: Runtime>(app: &AppHandle<R>, event: UiEvent) {
    let state = app.state::<ShellState>();
    if let Some(event) = state.route(event) {
        if let Err(error) = app.emit_to(MAIN_WINDOW, event.name(), event.payload()) {
            eprintln!("could not notify the Manage Window: {error}");
        }
    }
}

/// Handles close and destroy for the Manage Window.
pub fn on_window_event<R: Runtime>(window: &Window<R>, event: &WindowEvent) {
    if window.label() != MAIN_WINDOW {
        return;
    }
    let app = window.app_handle();
    let state = app.state::<ShellState>();
    match event {
        WindowEvent::CloseRequested { api, .. } => {
            if state.on_close_requested() == CloseDecision::Ask {
                api.prevent_close();
                deliver_ui_event(app, UiEvent::CloseConfirm);
            }
        }
        WindowEvent::Destroyed => {
            state.on_window_destroyed();
            set_dock_visible(app, false);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tauri::test::{mock_builder, mock_context, noop_assets, MockRuntime};

    use super::*;

    #[test]
    fn window_close_destroys_the_webview_when_a_tray_exists() {
        let state = ShellState::default();
        state.mark_ui_ready();
        assert_eq!(state.on_close_requested(), CloseDecision::Destroy);
    }

    #[test]
    fn window_close_asks_once_without_a_tray() {
        let state = ShellState::default();
        state.set_tray_available(false);
        state.mark_ui_ready();
        assert_eq!(state.on_close_requested(), CloseDecision::Ask);
        assert_eq!(state.on_close_requested(), CloseDecision::Destroy);

        state.clear_close_question();
        assert_eq!(state.on_close_requested(), CloseDecision::Ask);
    }

    #[test]
    fn window_unloaded_page_can_always_be_closed() {
        let state = ShellState::default();
        state.set_tray_available(false);
        assert_eq!(state.on_close_requested(), CloseDecision::Destroy);
    }

    #[test]
    fn window_events_queue_until_the_ui_is_ready() {
        let state = ShellState::default();
        let event = UiEvent::ClipboardFallback { url: "socks5h://127.0.0.1:1080".into() };
        assert_eq!(state.route(event.clone()), None);
        assert_eq!(state.route(event.clone()), None, "duplicates collapse");

        let snapshot = state.mark_ui_ready();
        assert_eq!(snapshot.pending, vec![event.clone()]);
        assert!(snapshot.tray_available);
        assert_eq!(state.route(event.clone()), Some(event.clone()));

        state.on_window_destroyed();
        assert_eq!(state.route(event), None);
    }

    #[test]
    fn window_pending_queue_is_bounded() {
        let state = ShellState::default();
        for port in 0..(MAX_PENDING_EVENTS + 4) {
            state.route(UiEvent::ClipboardFallback { url: format!("http://127.0.0.1:{port}") });
        }
        let pending = state.mark_ui_ready().pending;
        assert_eq!(pending.len(), MAX_PENDING_EVENTS);
        assert_eq!(pending[0], UiEvent::ClipboardFallback { url: "http://127.0.0.1:4".into() });
    }

    #[test]
    fn window_event_names_and_payloads_match_the_wire_format() {
        let url = "http://127.0.0.1:3128";
        let fallback = UiEvent::ClipboardFallback { url: url.into() };
        assert_eq!(fallback.name(), "clipboard-fallback");
        assert_eq!(fallback.payload(), json!({ "url": url }));
        assert_eq!(
            serde_json::to_value(&fallback).unwrap(),
            json!({ "event": "clipboard-fallback", "payload": { "url": url } })
        );
        for event in [UiEvent::UnlockVault, UiEvent::CloseConfirm, UiEvent::QuitConfirm] {
            assert_eq!(serde_json::to_value(&event).unwrap()["event"], event.name());
            assert_eq!(event.payload(), serde_json::Value::Null);
        }
        let id = Uuid::new_v4();
        let logs = UiEvent::ViewLogs { session_id: id };
        assert_eq!(serde_json::to_value(&logs).unwrap()["event"], logs.name());
        assert_eq!(logs.payload(), json!({ "session_id": id }));
    }

    #[test]
    fn window_open_creates_once_then_reuses() {
        let app = mock_builder()
            .manage(ShellState::default())
            .build(mock_context(noop_assets()))
            .unwrap();
        let handle: &AppHandle<MockRuntime> = app.handle();
        open_or_focus_manage_window(handle).unwrap();
        open_or_focus_manage_window(handle).unwrap();
        assert_eq!(app.webview_windows().len(), 1);
        assert!(app.get_webview_window(MAIN_WINDOW).is_some());
    }
}
