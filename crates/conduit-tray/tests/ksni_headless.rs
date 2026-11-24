//! Proves the Linux tray degrades cleanly with no D-Bus session bus.
//!
//! This is the only test in its binary because it changes a process-wide environment variable.
#![cfg(target_os = "linux")]

use std::time::{Duration, Instant};

use conduit_tray::{KsniTrayBackend, TrayBackend, TrayHostStatus, TrayMenuModel};

#[test]
fn ksni_without_dbus_reports_offline_and_shuts_down() {
    std::env::set_var(
        "DBUS_SESSION_BUS_ADDRESS",
        "unix:path=/nonexistent/conduit-tray-test-bus",
    );

    let backend = KsniTrayBackend::spawn(TrayMenuModel::from_snapshots(&[], false), None).unwrap();
    let mut actions = backend.subscribe_actions();

    let deadline = Instant::now() + Duration::from_secs(5);
    while backend.host_status() != TrayHostStatus::Offline && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(backend.host_status(), TrayHostStatus::Offline);

    backend
        .update(TrayMenuModel::from_snapshots(&[], true))
        .unwrap();
    backend.shutdown();

    assert!(actions.blocking_recv().is_none());
}
