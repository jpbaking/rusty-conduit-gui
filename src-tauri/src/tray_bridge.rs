//! Connects the tray to the app: session state flows to the menu, and menu picks flow to the
//! [`AppController`] and the Manage Window.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use conduit_tray::{TrayAction, TrayBackend, TrayError, TrayHostStatus, TrayMenuModel};
use tauri::{AppHandle, Emitter, Manager, Runtime};
use tokio::sync::broadcast::error::RecvError;
use tokio::time::Instant;

use crate::controller::{AppController, AppError};
use crate::window::{
    deliver_ui_event, open_or_focus_manage_window, ShellState, UiEvent, EVENT_TRAY_STATUS, MAIN_WINDOW,
};

/// How long to wait at login for a panel to register `StatusNotifierWatcher`.
pub const HOST_WAIT: Duration = Duration::from_secs(10);
/// How often the host is checked during that wait.
const HOST_POLL: Duration = Duration::from_millis(250);
/// Catches changes that raise no runtime event: profile edits and vault lock changes.
const REFRESH_INTERVAL: Duration = Duration::from_secs(2);
/// A second Quit within this time confirms the first.
const QUIT_CONFIRM_WINDOW: Duration = Duration::from_secs(10);
/// Longest a quit waits for sessions to stop.
const QUIT_STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// What the bridge needs from the desktop shell. Tests supply a recording fake.
pub trait ShellActions: Send + Sync + 'static {
    fn open_manage_window(&self);
    /// Opens the Manage Window and delivers `event` to it.
    fn show_ui_event(&self, event: UiEvent);
    fn copy_to_clipboard(&self, text: &str) -> Result<(), String>;
    fn tray_availability_changed(&self, available: bool);
    /// Stops sessions and exits the app.
    fn quit(&self);
}

/// Requires a second Quit when sessions are active, so a stray click cannot drop tunnels.
#[derive(Debug, Default)]
pub struct QuitGuard {
    asked_at: Mutex<Option<Instant>>,
}

impl QuitGuard {
    /// Whether to quit now. Otherwise the user must be asked.
    fn should_quit(&self, needs_confirmation: bool, now: Instant) -> bool {
        let mut asked_at = self.asked_at.lock().unwrap_or_else(PoisonError::into_inner);
        if !needs_confirmation {
            *asked_at = None;
            return true;
        }
        match asked_at.take() {
            Some(previous) if now.duration_since(previous) <= QUIT_CONFIRM_WINDOW => true,
            _ => {
                *asked_at = Some(now);
                false
            }
        }
    }
}

/// The menu for the current state. Sessions are sorted so the menu order stays stable.
pub fn current_model(controller: &AppController) -> TrayMenuModel {
    let summary = controller.get_state_summary();
    let mut sessions = summary.sessions;
    sessions.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
    // Before a vault exists there is nothing to unlock.
    let vault_locked = summary.vault.initialized && !summary.vault.unlocked;
    TrayMenuModel::from_snapshots(&sessions, vault_locked)
}

fn report(action: &str, result: Result<(), AppError>) {
    if let Err(error) = result {
        eprintln!("tray {action} failed: {error}");
    }
}

/// Runs a shell call off the async workers, because creating a window can block.
async fn on_shell<S: ShellActions>(shell: &Arc<S>, work: impl FnOnce(&S) + Send + 'static) {
    let shell = Arc::clone(shell);
    if let Err(error) = tokio::task::spawn_blocking(move || work(&shell)).await {
        eprintln!("tray shell task failed: {error}");
    }
}

async fn copy_url<S: ShellActions>(shell: &Arc<S>, url: String) {
    let writer = Arc::clone(shell);
    let text = url.clone();
    let copied = tokio::task::spawn_blocking(move || writer.copy_to_clipboard(&text)).await;
    if !matches!(copied, Ok(Ok(()))) {
        on_shell(shell, move |s| s.show_ui_event(UiEvent::ClipboardFallback { url })).await;
    }
}

/// Carries out one tray menu pick.
pub async fn handle_action<S: ShellActions>(
    controller: &AppController,
    shell: &Arc<S>,
    quit: &QuitGuard,
    action: TrayAction,
) {
    match action {
        TrayAction::StartSession(id) => report("start", controller.start_session(id).await),
        TrayAction::StopSession(id) => report("stop", controller.stop_session(id).await),
        TrayAction::RestartSession(id) => report("restart", controller.restart_session(id).await),
        TrayAction::CopyHttpUrl { url, .. } | TrayAction::CopySocksUrl { url, .. } => {
            copy_url(shell, url).await;
        }
        TrayAction::ViewLogs(session_id) => {
            on_shell(shell, move |s| s.show_ui_event(UiEvent::ViewLogs { session_id })).await;
        }
        TrayAction::StartAll => controller.start_all().await,
        TrayAction::StopAll => controller.stop_all().await,
        TrayAction::UnlockVault => on_shell(shell, |s| s.show_ui_event(UiEvent::UnlockVault)).await,
        TrayAction::OpenManageWindow => on_shell(shell, |s| s.open_manage_window()).await,
        TrayAction::Quit => {
            let needs_confirmation = current_model(controller).quit_needs_confirmation;
            if quit.should_quit(needs_confirmation, Instant::now()) {
                shell.quit();
            } else {
                on_shell(shell, |s| s.show_ui_event(UiEvent::QuitConfirm)).await;
            }
        }
    }
}

/// Keeps the menu and tray availability current and serves menu picks until the runtime ends.
///
/// `open_if_no_host` opens the Manage Window when the wait ends with no tray, for a launch
/// that started hidden. A host appearing later is picked up automatically.
pub async fn run_bridge<B, S>(
    controller: AppController,
    backend: Arc<B>,
    shell: Arc<S>,
    open_if_no_host: bool,
) where
    B: TrayBackend + ?Sized,
    S: ShellActions,
{
    let mut actions = backend.subscribe_actions();
    let mut actions_open = true;
    let mut events = controller.subscribe_events();
    let quit = Arc::new(QuitGuard::default());
    let deadline = Instant::now() + HOST_WAIT;
    let mut waiting = true;
    let mut available = true;
    let mut shown: Option<TrayMenuModel> = None;

    loop {
        let online = backend.host_status() == TrayHostStatus::Online;
        let wait_ended = waiting && (online || Instant::now() >= deadline);
        if wait_ended {
            waiting = false;
        }
        let now_available = online || waiting;
        if now_available != available {
            available = now_available;
            shell.tray_availability_changed(available);
        }
        if wait_ended && !online && open_if_no_host {
            on_shell(&shell, |s| s.open_manage_window()).await;
        }

        let model = current_model(&controller);
        if shown.as_ref() != Some(&model) {
            match backend.update(model.clone()) {
                Ok(()) => shown = Some(model),
                Err(TrayError::Closed) => actions_open = false,
                Err(error) => eprintln!("could not update the tray: {error}"),
            }
        }

        let delay = if waiting { HOST_POLL } else { REFRESH_INTERVAL };
        tokio::select! {
            action = actions.recv(), if actions_open => match action {
                Some(action) => {
                    let (controller, shell, quit) =
                        (controller.clone(), Arc::clone(&shell), Arc::clone(&quit));
                    // A slow start or stop must not freeze the menu.
                    tokio::spawn(async move {
                        handle_action(&controller, &shell, &quit, action).await;
                    });
                }
                None => actions_open = false,
            },
            event = events.recv() => {
                if matches!(event, Err(RecvError::Closed)) {
                    return;
                }
            }
            () = tokio::time::sleep(delay) => {}
        }
    }
}

/// A backend for when no tray can be created. The app then uses its no-tray fallback.
struct NoTrayBackend;

impl TrayBackend for NoTrayBackend {
    fn update(&self, _model: TrayMenuModel) -> Result<(), TrayError> {
        Ok(())
    }

    fn host_status(&self) -> TrayHostStatus {
        TrayHostStatus::Offline
    }

    fn subscribe_actions(&self) -> tokio::sync::mpsc::UnboundedReceiver<TrayAction> {
        // The sender is dropped here, so the stream reports closed at once.
        tokio::sync::mpsc::unbounded_channel().1
    }

    fn shutdown(self) {}
}

#[cfg(target_os = "linux")]
fn platform_backend<R: Runtime>(
    _app: &AppHandle<R>,
    initial: TrayMenuModel,
) -> Result<Arc<dyn TrayBackend>, String> {
    conduit_tray::KsniTrayBackend::spawn(initial)
        .map(|backend| Arc::new(backend) as Arc<dyn TrayBackend>)
        .map_err(|error| error.to_string())
}

#[cfg(not(target_os = "linux"))]
fn platform_backend<R: Runtime>(
    app: &AppHandle<R>,
    initial: TrayMenuModel,
) -> Result<Arc<dyn TrayBackend>, String> {
    crate::tray_tauri::TauriTrayBackend::spawn(app, &initial)
        .map(|backend| Arc::new(backend) as Arc<dyn TrayBackend>)
        .map_err(|error| error.to_string())
}

/// Creates this platform's tray. Failure is not fatal: the app runs with its no-tray fallback.
pub fn create_backend<R: Runtime>(app: &AppHandle<R>, initial: TrayMenuModel) -> Arc<dyn TrayBackend> {
    platform_backend(app, initial).unwrap_or_else(|error| {
        eprintln!("could not create the tray: {error}");
        Arc::new(NoTrayBackend)
    })
}

/// The OS clipboard. On Linux the owner must stay alive to keep serving what it copied.
#[derive(Default)]
pub struct SystemClipboard(Mutex<Option<arboard::Clipboard>>);

impl SystemClipboard {
    pub fn write(&self, text: &str) -> Result<(), String> {
        let mut slot = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(arboard::Clipboard::new().map_err(|e| e.to_string())?);
        }
        let Some(clipboard) = slot.as_mut() else {
            return Err("clipboard unavailable".into());
        };
        clipboard.set_text(text).map_err(|error| {
            // A later attempt reconnects instead of reusing a broken connection.
            *slot = None;
            error.to_string()
        })
    }
}

/// [`ShellActions`] for the real application.
pub struct TauriShell<R: Runtime> {
    app: AppHandle<R>,
    clipboard: SystemClipboard,
}

impl<R: Runtime> TauriShell<R> {
    pub fn new(app: AppHandle<R>) -> Self {
        Self { app, clipboard: SystemClipboard::default() }
    }
}

impl<R: Runtime> ShellActions for TauriShell<R> {
    fn open_manage_window(&self) {
        if let Err(error) = open_or_focus_manage_window(&self.app) {
            eprintln!("could not open the Manage Window: {error}");
        }
    }

    fn show_ui_event(&self, event: UiEvent) {
        self.open_manage_window();
        deliver_ui_event(&self.app, event);
    }

    fn copy_to_clipboard(&self, text: &str) -> Result<(), String> {
        self.clipboard.write(text)
    }

    fn tray_availability_changed(&self, available: bool) {
        self.app.state::<ShellState>().set_tray_available(available);
        let payload = serde_json::json!({ "tray_available": available });
        if let Err(error) = self.app.emit_to(MAIN_WINDOW, EVENT_TRAY_STATUS, payload) {
            eprintln!("could not report tray status: {error}");
        }
    }

    fn quit(&self) {
        quit_app(self.app.clone());
    }
}

/// Stops every session, waiting a bounded time, then exits.
pub fn quit_app<R: Runtime>(app: AppHandle<R>) {
    tauri::async_runtime::spawn(async move {
        if let Some(controller) = app.try_state::<AppController>() {
            let controller = controller.inner().clone();
            if tokio::time::timeout(QUIT_STOP_TIMEOUT, controller.stop_all()).await.is_err() {
                eprintln!("sessions did not stop in time; exiting anyway");
            }
        }
        app.exit(0);
    });
}

#[cfg(test)]
mod tests {
    use conduit_tray::MockTrayBackend;
    use uuid::Uuid;

    use super::*;
    use crate::controller::test_support::{controller, profile, TempDir};

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        Open,
        Ui(UiEvent),
        Copy(String),
        Available(bool),
        Quit,
    }

    #[derive(Default)]
    struct FakeShell {
        calls: Mutex<Vec<Call>>,
        clipboard_fails: bool,
    }

    impl FakeShell {
        fn failing_clipboard() -> Self {
            Self { clipboard_fails: true, ..Self::default() }
        }

        fn record(&self, call: Call) {
            self.calls.lock().unwrap().push(call);
        }

        fn calls(&self) -> Vec<Call> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl ShellActions for FakeShell {
        fn open_manage_window(&self) {
            self.record(Call::Open);
        }

        fn show_ui_event(&self, event: UiEvent) {
            self.record(Call::Ui(event));
        }

        fn copy_to_clipboard(&self, text: &str) -> Result<(), String> {
            self.record(Call::Copy(text.to_owned()));
            if self.clipboard_fails {
                Err("no focus".into())
            } else {
                Ok(())
            }
        }

        fn tray_availability_changed(&self, available: bool) {
            self.record(Call::Available(available));
        }

        fn quit(&self) {
            self.record(Call::Quit);
        }
    }

    async fn dispatch(shell: &Arc<FakeShell>, action: TrayAction) -> Vec<Call> {
        let dir = TempDir::new();
        let controller = controller(&dir);
        handle_action(&controller, shell, &QuitGuard::default(), action).await;
        shell.calls()
    }

    #[tokio::test]
    async fn tray_bridge_copy_success_opens_nothing() {
        let shell = Arc::new(FakeShell::default());
        let url = "socks5h://127.0.0.1:1080".to_owned();
        let action = TrayAction::CopySocksUrl { session_id: Uuid::new_v4(), url: url.clone() };
        assert_eq!(dispatch(&shell, action).await, vec![Call::Copy(url)]);
    }

    #[tokio::test]
    async fn tray_bridge_copy_failure_falls_back_to_the_window() {
        let shell = Arc::new(FakeShell::failing_clipboard());
        let url = "http://127.0.0.1:3128".to_owned();
        let action = TrayAction::CopyHttpUrl { session_id: Uuid::new_v4(), url: url.clone() };
        assert_eq!(
            dispatch(&shell, action).await,
            vec![Call::Copy(url.clone()), Call::Ui(UiEvent::ClipboardFallback { url })]
        );
    }

    #[tokio::test]
    async fn tray_bridge_window_actions_reach_the_shell() {
        let id = Uuid::new_v4();
        for (action, expected) in [
            (TrayAction::ViewLogs(id), Call::Ui(UiEvent::ViewLogs { session_id: id })),
            (TrayAction::UnlockVault, Call::Ui(UiEvent::UnlockVault)),
            (TrayAction::OpenManageWindow, Call::Open),
            (TrayAction::Quit, Call::Quit),
        ] {
            let shell = Arc::new(FakeShell::default());
            assert_eq!(dispatch(&shell, action).await, vec![expected]);
        }
    }

    #[tokio::test]
    async fn tray_bridge_session_actions_reach_the_controller() {
        let dir = TempDir::new();
        let controller = controller(&dir);
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let saved = controller.upsert_session(profile("s", closed)).unwrap();
        let shell = Arc::new(FakeShell::default());
        let quit = QuitGuard::default();

        for action in [
            TrayAction::StartSession(saved.id),
            TrayAction::RestartSession(saved.id),
            TrayAction::StopSession(saved.id),
            TrayAction::StartAll,
            TrayAction::StopAll,
            // An unknown session is reported, and must not panic.
            TrayAction::StopSession(Uuid::new_v4()),
        ] {
            handle_action(&controller, &shell, &quit, action).await;
        }
        assert!(shell.calls().is_empty());
        assert!(current_model(&controller).sessions[0].status.starts_with("Stopped"));
    }

    #[test]
    fn tray_bridge_quit_guard_requires_a_prompt_second_click() {
        let start = Instant::now();
        let guard = QuitGuard::default();
        assert!(guard.should_quit(false, start));

        assert!(!guard.should_quit(true, start));
        assert!(guard.should_quit(true, start + Duration::from_secs(3)));

        assert!(!guard.should_quit(true, start));
        let late = start + QUIT_CONFIRM_WINDOW + Duration::from_secs(1);
        assert!(!guard.should_quit(true, late), "an expired request asks again");
    }

    #[tokio::test]
    async fn tray_bridge_model_hides_unlock_before_a_vault_exists() {
        let dir = TempDir::new();
        let model = current_model(&controller(&dir));
        assert!(!model.vault_locked);
        assert!(!model.global_items.iter().any(|i| i.action == TrayAction::UnlockVault));
    }

    #[tokio::test(start_paused = true)]
    async fn tray_bridge_no_host_falls_back_after_the_wait_and_recovers() {
        let dir = TempDir::new();
        let controller = controller(&dir);
        let backend = Arc::new(MockTrayBackend::new(TrayHostStatus::Offline));
        let shell = Arc::new(FakeShell::default());
        let bridge = tokio::spawn(run_bridge(controller, Arc::clone(&backend), Arc::clone(&shell), true));

        tokio::time::sleep(HOST_WAIT - Duration::from_secs(1)).await;
        assert!(shell.calls().is_empty(), "still inside the wait");
        assert_eq!(backend.update_count(), 1, "the menu is ready for a late host");

        tokio::time::sleep(Duration::from_secs(2)).await;
        for _ in 0..50 {
            if shell.calls().len() >= 2 {
                break;
            }
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(shell.calls(), vec![Call::Available(false), Call::Open]);

        backend.set_host_status(TrayHostStatus::Online);
        tokio::time::sleep(REFRESH_INTERVAL + Duration::from_millis(10)).await;
        assert_eq!(shell.calls().last(), Some(&Call::Available(true)));
        bridge.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn tray_bridge_online_host_never_triggers_the_fallback() {
        let dir = TempDir::new();
        let controller = controller(&dir);
        let backend = Arc::new(MockTrayBackend::new(TrayHostStatus::Online));
        let shell = Arc::new(FakeShell::default());
        let bridge = tokio::spawn(run_bridge(controller, Arc::clone(&backend), Arc::clone(&shell), true));

        tokio::time::sleep(HOST_WAIT * 2).await;
        assert!(shell.calls().is_empty());
        assert_eq!(backend.update_count(), 1, "an unchanged menu is not redrawn");
        bridge.abort();
    }

    #[tokio::test]
    async fn tray_bridge_routes_menu_clicks() {
        let dir = TempDir::new();
        let controller = controller(&dir);
        let backend = Arc::new(MockTrayBackend::default());
        let shell = Arc::new(FakeShell::default());
        let bridge = tokio::spawn(run_bridge(controller, Arc::clone(&backend), Arc::clone(&shell), false));

        while backend.update_count() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        backend.click(TrayAction::OpenManageWindow);
        for _ in 0..200 {
            if !shell.calls().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(shell.calls(), vec![Call::Open]);
        bridge.abort();
    }

    #[test]
    fn tray_bridge_no_tray_backend_reports_offline() {
        let backend = NoTrayBackend;
        assert_eq!(backend.host_status(), TrayHostStatus::Offline);
        let mut actions = backend.subscribe_actions();
        assert!(actions.try_recv().is_err());
    }
}
