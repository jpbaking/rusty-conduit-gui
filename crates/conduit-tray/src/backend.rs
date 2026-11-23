//! The platform-neutral tray interface and a deterministic test backend.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use thiserror::Error;
use tokio::sync::mpsc;

use crate::model::{TrayAction, TrayHostStatus, TrayMenuModel};

/// A tray backend failure. A missing tray host is not an error: see [`TrayHostStatus`].
#[derive(Debug, Error)]
pub enum TrayError {
    #[error("the tray backend has shut down")]
    Closed,
    #[error("could not start the tray worker: {0}")]
    Spawn(#[from] std::io::Error),
}

/// Shows the tray menu and reports what the user picks.
pub trait TrayBackend: Send + Sync {
    /// Replaces the displayed menu.
    fn update(&self, model: TrayMenuModel) -> Result<(), TrayError>;

    /// Whether a tray host can currently show the icon.
    fn host_status(&self) -> TrayHostStatus;

    /// Returns a new stream of menu actions. It ends when the backend shuts down.
    fn subscribe_actions(&self) -> mpsc::UnboundedReceiver<TrayAction>;

    /// Removes the tray icon and ends every action stream.
    fn shutdown(self)
    where
        Self: Sized;
}

/// Delivers each action to every live subscriber.
#[derive(Debug, Clone, Default)]
pub(crate) struct ActionDispatcher {
    subscribers: Arc<Mutex<Vec<mpsc::UnboundedSender<TrayAction>>>>,
}

impl ActionDispatcher {
    pub(crate) fn subscribe(&self) -> mpsc::UnboundedReceiver<TrayAction> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.lock().push(tx);
        rx
    }

    pub(crate) fn dispatch(&self, action: TrayAction) {
        self.lock().retain(|tx| tx.send(action.clone()).is_ok());
    }

    pub(crate) fn close(&self) {
        self.lock().clear();
    }

    // The list stays valid if a holder panics, so a poisoned lock is safe to reuse.
    fn lock(&self) -> MutexGuard<'_, Vec<mpsc::UnboundedSender<TrayAction>>> {
        self.subscribers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// A [`TrayHostStatus`] shared between threads.
#[derive(Debug, Clone)]
pub(crate) struct SharedHostStatus(Arc<AtomicU8>);

impl SharedHostStatus {
    pub(crate) fn new(status: TrayHostStatus) -> Self {
        Self(Arc::new(AtomicU8::new(status as u8)))
    }

    pub(crate) fn get(&self) -> TrayHostStatus {
        match self.0.load(Ordering::Acquire) {
            s if s == TrayHostStatus::Online as u8 => TrayHostStatus::Online,
            s if s == TrayHostStatus::Offline as u8 => TrayHostStatus::Offline,
            _ => TrayHostStatus::Waiting,
        }
    }

    pub(crate) fn set(&self, status: TrayHostStatus) {
        self.0.store(status as u8, Ordering::Release);
    }
}

/// An in-memory backend for tests.
#[derive(Debug)]
pub struct MockTrayBackend {
    models: Mutex<Vec<TrayMenuModel>>,
    status: SharedHostStatus,
    dispatcher: ActionDispatcher,
}

impl Default for MockTrayBackend {
    fn default() -> Self {
        Self::new(TrayHostStatus::Online)
    }
}

impl MockTrayBackend {
    pub fn new(status: TrayHostStatus) -> Self {
        Self {
            models: Mutex::new(Vec::new()),
            status: SharedHostStatus::new(status),
            dispatcher: ActionDispatcher::default(),
        }
    }

    /// Simulates a tray host appearing or going away.
    pub fn set_host_status(&self, status: TrayHostStatus) {
        self.status.set(status);
    }

    /// Simulates the user clicking a menu item.
    pub fn click(&self, action: TrayAction) {
        self.dispatcher.dispatch(action);
    }

    /// The most recent menu passed to [`TrayBackend::update`].
    pub fn last_model(&self) -> Option<TrayMenuModel> {
        self.lock_models().last().cloned()
    }

    /// How many times the menu was updated.
    pub fn update_count(&self) -> usize {
        self.lock_models().len()
    }

    fn lock_models(&self) -> MutexGuard<'_, Vec<TrayMenuModel>> {
        self.models.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl TrayBackend for MockTrayBackend {
    fn update(&self, model: TrayMenuModel) -> Result<(), TrayError> {
        self.lock_models().push(model);
        Ok(())
    }

    fn host_status(&self) -> TrayHostStatus {
        self.status.get()
    }

    fn subscribe_actions(&self) -> mpsc::UnboundedReceiver<TrayAction> {
        self.dispatcher.subscribe()
    }

    fn shutdown(self) {
        self.dispatcher.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc::error::TryRecvError;

    #[test]
    fn backend_stores_latest_model() {
        let backend = MockTrayBackend::default();
        backend
            .update(TrayMenuModel::from_snapshots(&[], false))
            .unwrap();
        backend
            .update(TrayMenuModel::from_snapshots(&[], true))
            .unwrap();
        assert_eq!(backend.update_count(), 2);
        assert!(backend.last_model().unwrap().vault_locked);
    }

    #[test]
    fn backend_dispatches_actions_to_every_subscriber() {
        let backend = MockTrayBackend::default();
        let mut first = backend.subscribe_actions();
        let mut second = backend.subscribe_actions();

        backend.click(TrayAction::StartAll);
        backend.click(TrayAction::Quit);

        for rx in [&mut first, &mut second] {
            assert_eq!(rx.try_recv().unwrap(), TrayAction::StartAll);
            assert_eq!(rx.try_recv().unwrap(), TrayAction::Quit);
            assert_eq!(rx.try_recv().unwrap_err(), TryRecvError::Empty);
        }
    }

    #[test]
    fn backend_drops_closed_subscribers() {
        let backend = MockTrayBackend::default();
        let closed = backend.subscribe_actions();
        let mut open = backend.subscribe_actions();
        drop(closed);

        backend.click(TrayAction::StopAll);

        assert_eq!(open.try_recv().unwrap(), TrayAction::StopAll);
        assert_eq!(backend.dispatcher.lock().len(), 1);
    }

    #[test]
    fn backend_reports_no_tray_host_fallback_state() {
        let backend = MockTrayBackend::new(TrayHostStatus::Waiting);
        assert_eq!(backend.host_status(), TrayHostStatus::Waiting);

        backend.set_host_status(TrayHostStatus::Offline);
        assert_eq!(backend.host_status(), TrayHostStatus::Offline);
        // The menu keeps tracking state so it is current if a host appears later.
        backend
            .update(TrayMenuModel::from_snapshots(&[], true))
            .unwrap();

        backend.set_host_status(TrayHostStatus::Online);
        assert_eq!(backend.host_status(), TrayHostStatus::Online);
        assert!(backend.last_model().unwrap().vault_locked);
    }

    #[test]
    fn backend_shutdown_ends_action_streams() {
        let backend = MockTrayBackend::default();
        let mut rx = backend.subscribe_actions();
        backend.shutdown();
        assert_eq!(rx.try_recv().unwrap_err(), TryRecvError::Disconnected);
    }
}
