//! Tauri v2 shell: a thin adapter over the conduit crates.

pub mod commands;
pub mod controller;
pub mod migration;
pub mod platform;
pub mod tray_bridge;
#[cfg(any(not(target_os = "linux"), conduit_check_tauri_tray))]
pub mod tray_tauri;
pub mod window;

use std::sync::Arc;

use conduit_runtime::RuntimeEvent;
use tauri::{AppHandle, Emitter, Manager, RunEvent, Runtime};
use tauri_plugin_autostart::ManagerExt as _;
use tokio::sync::broadcast::error::RecvError;

use commands::{AutostartControl, AutostartHandle};
use controller::{AppController, ControllerOptions};
use platform::CliFlags;
use tray_bridge::TauriShell;
use window::{ShellState, EVENT_RUNTIME, EVENT_RUNTIME_LAGGED, MAIN_WINDOW};

/// Name of the login autostart entry, such as `rusty-conduit-gui.desktop` on Linux.
const AUTOSTART_NAME: &str = "rusty-conduit-gui";

/// Keeps decrypted secrets out of crash output: panics report only their source location.
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| match info.location() {
        Some(location) => eprintln!("internal error at {}:{}", location.file(), location.line()),
        None => eprintln!("internal error"),
    }));
}

/// Autostart through the plugin's registered login entry.
struct PluginAutostart<R: Runtime>(AppHandle<R>);

impl<R: Runtime> AutostartControl for PluginAutostart<R> {
    fn is_enabled(&self) -> Result<bool, String> {
        self.0.autolaunch().is_enabled().map_err(|e| e.to_string())
    }

    fn set_enabled(&self, enabled: bool) -> Result<(), String> {
        let manager = self.0.autolaunch();
        let result = if enabled { manager.enable() } else { manager.disable() };
        result.map_err(|e| e.to_string())
    }
}

/// Forwards runtime events to the Manage Window. With no window open this does nothing.
async fn forward_runtime_events<R: Runtime>(app: AppHandle<R>, controller: AppController) {
    let mut events = controller.subscribe_events();
    loop {
        let sent = match events.recv().await {
            Ok(event @ RuntimeEvent::StateChanged { .. })
            | Ok(event @ RuntimeEvent::KnownHostsChanged { .. }) => {
                app.emit_to(MAIN_WINDOW, EVENT_RUNTIME, event)
            }
            // Events were lost, so the UI must reload its state.
            Err(RecvError::Lagged(_)) => app.emit_to(MAIN_WINDOW, EVENT_RUNTIME_LAGGED, ()),
            Err(RecvError::Closed) => return,
        };
        if let Err(error) = sent {
            eprintln!("could not forward a runtime event: {error}");
        }
    }
}

/// Opens the Manage Window off the calling thread, where creating it cannot deadlock.
fn open_window_in_background<R: Runtime>(app: &AppHandle<R>) {
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        if let Err(error) = window::open_or_focus_manage_window(&app) {
            eprintln!("could not open the Manage Window: {error}");
        }
    });
}

/// Builds and runs the Tauri application.
pub fn run() {
    install_panic_hook();
    platform::harden_process();
    // Must happen here: before GTK initializes and before any other thread starts.
    let flags = CliFlags::from_env();
    // Informational flags print and exit before any GUI or GTK initialization.
    if flags.help {
        print!("{}", platform::help_text());
        return;
    }
    if flags.version {
        println!("{}", platform::version_text());
        return;
    }
    platform::apply_rendering_env(flags);

    tauri::Builder::default()
        // Registered first, so a second launch exits before anything else initializes.
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            if CliFlags::parse(&args).second_launch_opens_window() {
                open_window_in_background(app);
            }
        }))
        .plugin(
            tauri_plugin_autostart::Builder::new()
                .app_name(AUTOSTART_NAME)
                .arg(platform::FLAG_TRAY)
                .build(),
        )
        // Native open and save dialogs for file paths. Only those two are allowed, in
        // `capabilities/default.json`; the plugin's file-system access is not granted.
        .plugin(tauri_plugin_dialog::init())
        // Opens the About links in the default browser. `capabilities/default.json` scopes it
        // to the project's own web pages.
        .plugin(tauri_plugin_opener::init())
        .manage(ShellState::default())
        .on_window_event(window::on_window_event)
        .invoke_handler(commands::ipc_handler!())
        .setup(move |app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            let dir = app.path().app_data_dir()?;
            migration::ensure_old_instance_not_running().map_err(|error| {
                eprintln!("{error}");
                error
            })?;
            let migration_outcome = migration::migrate_data_dir(&dir).map_err(|error| {
                eprintln!("{error}");
                error
            })?;
            if let Some((message, is_warning)) = migration_outcome.banner() {
                eprintln!("upgrade migration: {message}");
                window::deliver_ui_event(
                    app.handle(),
                    window::UiEvent::MigrationNotice { message, is_warning },
                );
            }
            // After the single-instance guard and before any Tunnel starts: remove the runtime
            // directories (askpass and agent sockets, known_hosts) a crashed run left behind.
            match conduit_openssh::sweep_stale_runtime_dirs() {
                Ok(0) => {}
                Ok(removed) => eprintln!("removed {removed} stale ssh runtime directories"),
                Err(error) => eprintln!("could not sweep stale ssh runtime directories: {error}"),
            }
            let controller = AppController::open(dir, ControllerOptions::default())?;
            tauri::async_runtime::spawn(controller.known_hosts_autosave());
            app.manage(controller.clone());

            // Best-effort: with no OS wake source the handle does nothing. Kept for the app's life.
            let wake_controller = controller.clone();
            app.manage(conduit_runtime::spawn_wake_listener(Arc::new(move || {
                let controller = wake_controller.clone();
                tauri::async_runtime::spawn(async move { controller.notify_system_wake() });
            })));

            let handle = app.handle().clone();
            let autostart = PluginAutostart(handle.clone());
            match migration::migrate_os_autostart(&autostart) {
                Ok(true) => eprintln!("upgrade migration: migrated login autostart to {AUTOSTART_NAME}"),
                Ok(false) => {}
                Err(error) => eprintln!("upgrade migration: could not migrate login autostart: {error}"),
            }
            app.manage(AutostartHandle::new(autostart));
            tauri::async_runtime::spawn(forward_runtime_events(handle.clone(), controller.clone()));
            tauri::async_runtime::spawn(window::forward_proxy_events(
                handle.clone(),
                controller.subscribe_proxy_events(),
            ));
            tauri::async_runtime::spawn(window::forward_tunnel_events(
                handle.clone(),
                controller.subscribe_tunnel_events(),
            ));

            let backend = tray_bridge::create_backend(&handle, tray_bridge::current_model(&controller));
            let shell = Arc::new(TauriShell::new(handle.clone()));
            tauri::async_runtime::spawn(tray_bridge::run_bridge(
                controller.clone(),
                backend,
                shell,
                flags.starts_hidden(),
            ));

            if !flags.starts_hidden() {
                window::open_or_focus_manage_window(&handle)?;
            }

            // Tunnels and Proxies start whether or not a tray or window is available.
            tauri::async_runtime::spawn(async move {
                controller.start_autostart().await;
                controller.start_autostart_v2().await;
            });
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("failed to build the Tauri application")
        .run(|_app, event| {
            // Closing the last window must leave tunnels and the tray running. An explicit
            // exit carries a code and is not blocked.
            if let RunEvent::ExitRequested { code: None, api, .. } = event {
                api.prevent_exit();
            }
        });
}
