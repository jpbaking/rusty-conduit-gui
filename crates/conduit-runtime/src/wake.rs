//! Best-effort OS wake listener.
//!
//! [`spawn_wake_listener`] calls a callback each time the machine resumes from sleep, so the
//! caller can forward it to [`crate::SessionManager::notify_system_wake`]:
//!
//! - Linux: logind `PrepareForSleep(false)` on the system D-Bus.
//! - Windows: `WM_POWERBROADCAST` with `PBT_APMRESUMEAUTOMATIC` on a message-only window.
//! - macOS: `NSWorkspaceDidWakeNotification`.
//! - Other targets: nothing.
//!
//! The listener never fails app startup. When the OS service is missing (a container, headless
//! CI) it logs once and stops; the returned [`WakeHandle`] then does nothing.
//!
//! The callback may run on a thread without a Tokio runtime. Spawn onto a runtime from it
//! before calling `notify_system_wake`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Called once per system wake.
pub type WakeCallback = Arc<dyn Fn() + Send + Sync>;

/// `true` when logind's `PrepareForSleep` argument reports a resume rather than a suspend.
pub fn is_wake_signal(going_to_sleep: bool) -> bool {
    !going_to_sleep
}

/// Windows `PBT_APMRESUMEAUTOMATIC`: the system resumed, with or without a user present.
pub const PBT_APMRESUMEAUTOMATIC: usize = 0x0012;

/// `true` when a `WM_POWERBROADCAST` `wParam` reports a resume.
pub fn is_windows_resume(wparam: usize) -> bool {
    wparam == PBT_APMRESUMEAUTOMATIC
}

/// Keeps the wake listener alive. Dropping it stops the listener.
pub struct WakeHandle {
    active: Arc<AtomicBool>,
    stop: Option<Box<dyn FnOnce() + Send + Sync>>,
}

impl WakeHandle {
    /// A handle with no listener behind it.
    pub fn noop() -> Self {
        Self {
            active: Arc::new(AtomicBool::new(false)),
            stop: None,
        }
    }

    /// `true` while the listener is subscribed to OS wake events.
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }
}

impl Drop for WakeHandle {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            stop();
        }
        self.active.store(false, Ordering::SeqCst);
    }
}

impl std::fmt::Debug for WakeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WakeHandle")
            .field("active", &self.is_active())
            .finish()
    }
}

/// Starts listening for OS wake events. Never fails: an unavailable OS service yields a handle
/// that does nothing.
pub fn spawn_wake_listener(on_wake: WakeCallback) -> WakeHandle {
    #[cfg(target_os = "linux")]
    {
        linux::spawn(None, on_wake)
    }
    #[cfg(target_os = "windows")]
    {
        windows::spawn(on_wake)
    }
    #[cfg(target_os = "macos")]
    {
        macos::spawn(on_wake)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        drop(on_wake);
        WakeHandle::noop()
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use futures_util::StreamExt;
    use tokio_util::sync::CancellationToken;

    const DEST: &str = "org.freedesktop.login1";
    const PATH: &str = "/org/freedesktop/login1";
    const INTERFACE: &str = "org.freedesktop.login1.Manager";

    /// Runs the listener on its own thread and current-thread runtime, so it works whether or
    /// not the caller is inside Tokio. `address` overrides the system bus, for tests.
    pub(super) fn spawn(address: Option<String>, on_wake: WakeCallback) -> WakeHandle {
        let active = Arc::new(AtomicBool::new(true));
        let cancel = CancellationToken::new();
        let thread_active = Arc::clone(&active);
        let thread_cancel = cancel.clone();
        let spawned = std::thread::Builder::new()
            .name("conduit-wake".into())
            .spawn(move || {
                match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                    Ok(runtime) => runtime.block_on(async {
                        tokio::select! {
                            _ = thread_cancel.cancelled() => {}
                            result = listen(address, &thread_active, on_wake) => {
                                if let Err(error) = result {
                                    eprintln!("system wake detection unavailable: {error}");
                                }
                            }
                        }
                    }),
                    Err(error) => eprintln!("system wake detection unavailable: {error}"),
                }
                thread_active.store(false, Ordering::SeqCst);
            });
        let thread = match spawned {
            Ok(thread) => thread,
            Err(error) => {
                eprintln!("system wake detection unavailable: {error}");
                return WakeHandle::noop();
            }
        };
        WakeHandle {
            active,
            stop: Some(Box::new(move || {
                cancel.cancel();
                let _ = thread.join();
            })),
        }
    }

    async fn listen(
        address: Option<String>,
        active: &AtomicBool,
        on_wake: WakeCallback,
    ) -> zbus::Result<()> {
        let connection = match address {
            Some(address) => zbus::connection::Builder::address(address.as_str())?.build().await?,
            None => zbus::Connection::system().await?,
        };
        let proxy = zbus::Proxy::new(&connection, DEST, PATH, INTERFACE).await?;
        let mut signals = proxy.receive_signal("PrepareForSleep").await?;
        while let Some(message) = signals.next().await {
            match message.body().deserialize::<bool>() {
                Ok(going_to_sleep) if is_wake_signal(going_to_sleep) => on_wake(),
                Ok(_) => {}
                Err(error) => eprintln!("ignoring malformed PrepareForSleep signal: {error}"),
            }
        }
        active.store(false, Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use std::cell::RefCell;
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc;

    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::Power::{
        RegisterSuspendResumeNotification, UnregisterSuspendResumeNotification,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
        PostMessageW, PostQuitMessage, RegisterClassW, DEVICE_NOTIFY_WINDOW_HANDLE, HWND_MESSAGE,
        MSG, WM_CLOSE, WM_DESTROY, WM_POWERBROADCAST, WNDCLASSW,
    };

    thread_local! {
        static ON_WAKE: RefCell<Option<WakeCallback>> = const { RefCell::new(None) };
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    unsafe extern "system" fn window_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match msg {
            WM_POWERBROADCAST => {
                if is_windows_resume(wparam) {
                    let callback = ON_WAKE.with(|cell| cell.borrow().clone());
                    if let Some(callback) = callback {
                        callback();
                    }
                }
                1
            }
            WM_CLOSE => {
                // SAFETY: `hwnd` is this thread's own window.
                unsafe { DestroyWindow(hwnd) };
                0
            }
            WM_DESTROY => {
                // SAFETY: takes no pointers.
                unsafe { PostQuitMessage(0) };
                0
            }
            // SAFETY: forwards the arguments Windows passed in.
            _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
        }
    }

    pub(super) fn spawn(on_wake: WakeCallback) -> WakeHandle {
        let active = Arc::new(AtomicBool::new(false));
        let hwnd_slot = Arc::new(AtomicUsize::new(0));
        let (ready_tx, ready_rx) = mpsc::channel::<bool>();
        let thread_active = Arc::clone(&active);
        let thread_hwnd = Arc::clone(&hwnd_slot);
        let spawned = std::thread::Builder::new()
            .name("conduit-wake".into())
            .spawn(move || {
                ON_WAKE.with(|cell| *cell.borrow_mut() = Some(on_wake));
                let class = wide("ConduitWakeListener");
                // SAFETY: every pointer passed below is valid for the duration of its call, and
                // the window and class belong to this thread.
                unsafe {
                    let instance = GetModuleHandleW(std::ptr::null());
                    let mut wc: WNDCLASSW = std::mem::zeroed();
                    wc.lpfnWndProc = Some(window_proc);
                    wc.hInstance = instance;
                    wc.lpszClassName = class.as_ptr();
                    RegisterClassW(&wc);
                    let hwnd = CreateWindowExW(
                        0,
                        class.as_ptr(),
                        class.as_ptr(),
                        0,
                        0,
                        0,
                        0,
                        0,
                        HWND_MESSAGE,
                        std::ptr::null_mut(),
                        instance,
                        std::ptr::null(),
                    );
                    if hwnd.is_null() {
                        eprintln!(
                            "system wake detection unavailable: {}",
                            std::io::Error::last_os_error()
                        );
                        let _ = ready_tx.send(false);
                        return;
                    }
                    // Message-only windows get no broadcasts; this opts in to power events.
                    let notify = RegisterSuspendResumeNotification(hwnd, DEVICE_NOTIFY_WINDOW_HANDLE);
                    thread_hwnd.store(hwnd as usize, Ordering::SeqCst);
                    thread_active.store(true, Ordering::SeqCst);
                    let _ = ready_tx.send(true);

                    let mut msg: MSG = std::mem::zeroed();
                    while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
                        DispatchMessageW(&msg);
                    }
                    if notify != 0 {
                        UnregisterSuspendResumeNotification(notify);
                    }
                }
                thread_active.store(false, Ordering::SeqCst);
            });
        let thread = match spawned {
            Ok(thread) => thread,
            Err(error) => {
                eprintln!("system wake detection unavailable: {error}");
                return WakeHandle::noop();
            }
        };
        if !ready_rx.recv().unwrap_or(false) {
            let _ = thread.join();
            return WakeHandle::noop();
        }
        WakeHandle {
            active,
            stop: Some(Box::new(move || {
                let hwnd = hwnd_slot.load(Ordering::SeqCst) as HWND;
                // SAFETY: posting to a window handle is safe even if it was already destroyed.
                unsafe { PostMessageW(hwnd, WM_CLOSE, 0, 0) };
                let _ = thread.join();
            })),
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::ptr::NonNull;

    use block2::RcBlock;
    use objc2::rc::Retained;
    use objc2::runtime::{NSObjectProtocol, ProtocolObject};
    use objc2_app_kit::{NSWorkspace, NSWorkspaceDidWakeNotification};
    use objc2_foundation::{NSNotification, NSNotificationCenter};

    struct Observer {
        center: Retained<NSNotificationCenter>,
        token: Retained<ProtocolObject<dyn NSObjectProtocol>>,
    }

    // SAFETY: `NSNotificationCenter` is thread-safe, and the observer token is only passed back
    // to it in `removeObserver:`.
    unsafe impl Send for Observer {}
    // SAFETY: as above; `Observer` exposes no shared access to either object.
    unsafe impl Sync for Observer {}

    pub(super) fn spawn(on_wake: WakeCallback) -> WakeHandle {
        let center = NSWorkspace::sharedWorkspace().notificationCenter();
        let block = RcBlock::new(move |_note: NonNull<NSNotification>| on_wake());
        // SAFETY: the name is a valid AppKit constant, no sender filter or queue is given, and
        // the block captures only `Send + Sync` state.
        let token = unsafe {
            center.addObserverForName_object_queue_usingBlock(
                Some(NSWorkspaceDidWakeNotification),
                None,
                None,
                &block,
            )
        };
        let observer = Observer { center, token };
        WakeHandle {
            active: Arc::new(AtomicBool::new(true)),
            stop: Some(Box::new(move || {
                let token: &objc2::runtime::AnyObject = (*observer.token).as_ref();
                // SAFETY: `token` was returned by this center's `addObserverForName:...`.
                unsafe { observer.center.removeObserver(token) };
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::{Duration, Instant};

    fn counter() -> (Arc<AtomicUsize>, WakeCallback) {
        let count = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&count);
        (count, Arc::new(move || {
            seen.fetch_add(1, Ordering::SeqCst);
        }))
    }

    #[test]
    fn wake_signal_is_resume_only() {
        assert!(is_wake_signal(false));
        assert!(!is_wake_signal(true));
    }

    #[test]
    fn windows_resume_matches_pbt_apmresumeautomatic() {
        assert!(is_windows_resume(0x0012));
        assert!(!is_windows_resume(0x0004)); // PBT_APMSUSPEND
        assert!(!is_windows_resume(0x0007)); // PBT_APMRESUMESUSPEND
    }

    #[test]
    fn noop_handle_is_inactive_and_drops_cleanly() {
        let handle = WakeHandle::noop();
        assert!(!handle.is_active());
        drop(handle);
    }

    #[test]
    fn dropping_the_handle_runs_its_stop_once() {
        let (count, callback) = counter();
        let handle = WakeHandle {
            active: Arc::new(AtomicBool::new(true)),
            stop: Some(Box::new(move || callback())),
        };
        assert!(handle.is_active());
        drop(handle);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn real_listener_starts_and_stops_without_panicking() {
        let (count, callback) = counter();
        let handle = spawn_wake_listener(callback);
        let started = Instant::now();
        drop(handle);
        assert!(started.elapsed() < Duration::from_secs(5), "drop must not hang");
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn missing_system_bus_stops_quietly() {
        let (count, callback) = counter();
        let handle = linux::spawn(
            Some("unix:path=/nonexistent/conduit-test-bus".into()),
            callback,
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while handle.is_active() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!handle.is_active(), "an unreachable bus must end the listener");
        drop(handle);
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }
}
