//! Runtime events broadcast to the UI layer.

use serde::Serialize;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::state::SessionState;

/// Default number of events a slow subscriber can fall behind before it sees `Lagged`.
pub const DEFAULT_EVENT_CAPACITY: usize = 256;

/// Something the UI may want to react to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum RuntimeEvent {
    /// A session moved to a new state.
    StateChanged {
        session_id: Uuid,
        state: SessionState,
    },
    /// A host-key pin was approved. The owner of `known_hosts.json` should save it.
    KnownHostsChanged {
        session_id: Uuid,
        hop_id: String,
        host: String,
        port: u16,
    },
}

/// Cloneable sender side of the runtime event channel.
#[derive(Debug, Clone)]
pub struct EventBus {
    sender: broadcast::Sender<RuntimeEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity.max(1));
        Self { sender }
    }

    /// Publishes `event`. Having no subscribers is normal and not an error.
    pub fn emit(&self, event: RuntimeEvent) {
        let _ = self.sender.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<RuntimeEvent> {
        self.sender.subscribe()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(DEFAULT_EVENT_CAPACITY)
    }
}
