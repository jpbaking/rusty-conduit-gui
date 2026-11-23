//! The session state machine and the read-only snapshots given to the UI.

use std::net::SocketAddr;
use std::sync::{Mutex, PoisonError};

use conduit_ssh::StatsSnapshot;
use serde::Serialize;
use tokio::time::Instant;
use uuid::Uuid;

use crate::events::{EventBus, RuntimeEvent};

/// An unknown host key waiting for the user's decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostKeyPrompt {
    pub hop_index: usize,
    pub hop_id: String,
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    /// `SHA256:<base64>`, matching `ssh-keygen -l`.
    pub sha256: String,
}

/// Where a session is in its lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SessionState {
    Stopped,
    Starting,
    Connected,
    Reconnecting { attempt: u32, next_retry_secs: u64 },
    WaitingForNetwork,
    /// The session needs vault secrets and the vault is locked.
    Locked,
    AwaitingHostKey(HostKeyPrompt),
    /// Reconnects are halted until the user acts (bad credentials or a changed host key).
    NeedsAttention { reason: String },
    Failed { reason: String },
}

impl SessionState {
    /// `true` when no supervisor is running for this state.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Stopped | Self::Locked | Self::NeedsAttention { .. } | Self::Failed { .. }
        )
    }

    /// Whether the state machine allows moving from `self` to `next`.
    pub fn can_transition_to(&self, next: &SessionState) -> bool {
        use SessionState::*;
        if matches!(next, Stopped) {
            return true;
        }
        if self.is_terminal() {
            return matches!(next, Starting);
        }
        match next {
            Stopped => true,
            Starting => matches!(self, AwaitingHostKey(_)),
            Connected => !matches!(self, Connected),
            Reconnecting { .. } | WaitingForNetwork => !matches!(self, AwaitingHostKey(_)),
            AwaitingHostKey(_) => !matches!(self, Connected),
            Locked | NeedsAttention { .. } | Failed { .. } => true,
        }
    }
}

/// One bound local proxy listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListenerInfo {
    pub role: String,
    pub addr: SocketAddr,
}

/// Live traffic counters for one session.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct SessionStatsSnapshot {
    pub active_connections: u64,
    pub total_connections: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    /// Seconds in the current `Connected` period, or zero.
    pub uptime_secs: u64,
}

impl SessionStatsSnapshot {
    pub(crate) fn from_stats(stats: StatsSnapshot, uptime_secs: u64) -> Self {
        Self {
            active_connections: stats.active_connections,
            total_connections: stats.total_connections,
            bytes_sent: stats.bytes_sent,
            bytes_received: stats.bytes_received,
            uptime_secs,
        }
    }
}

/// A point-in-time view of one session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionSnapshot {
    pub id: Uuid,
    pub name: String,
    pub state: SessionState,
    pub stats: SessionStatsSnapshot,
    pub listeners: Vec<ListenerInfo>,
}

#[derive(Debug)]
struct CellInner {
    state: SessionState,
    connected_at: Option<Instant>,
}

/// The authoritative state of one session. Every change is validated and broadcast.
#[derive(Debug)]
pub(crate) struct StateCell {
    id: Uuid,
    inner: Mutex<CellInner>,
    events: EventBus,
}

impl StateCell {
    pub(crate) fn new(id: Uuid, events: EventBus) -> Self {
        Self {
            id,
            inner: Mutex::new(CellInner {
                state: SessionState::Stopped,
                connected_at: None,
            }),
            events,
        }
    }

    pub(crate) fn get(&self) -> SessionState {
        self.lock().state.clone()
    }

    pub(crate) fn uptime_secs(&self) -> u64 {
        self.lock()
            .connected_at
            .map_or(0, |since| since.elapsed().as_secs())
    }

    /// Applies a legal transition and returns `true`. Illegal or no-op changes return `false`.
    pub(crate) fn set(&self, next: SessionState) -> bool {
        let mut inner = self.lock();
        if inner.state == next || !inner.state.can_transition_to(&next) {
            return false;
        }
        inner.connected_at = matches!(next, SessionState::Connected).then(Instant::now);
        inner.state = next.clone();
        // Sent under the lock so subscribers see transitions in order.
        self.events.emit(RuntimeEvent::StateChanged {
            session_id: self.id,
            state: next,
        });
        true
    }

    // The cell holds plain values that are replaced whole, so a poisoned lock is still valid.
    fn lock(&self) -> std::sync::MutexGuard<'_, CellInner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use SessionState::*;

    fn prompt() -> HostKeyPrompt {
        HostKeyPrompt {
            hop_index: 0,
            hop_id: "hop".into(),
            host: "h".into(),
            port: 22,
            algorithm: "ssh-ed25519".into(),
            sha256: "SHA256:x".into(),
        }
    }

    fn reconnecting() -> SessionState {
        Reconnecting {
            attempt: 1,
            next_retry_secs: 1,
        }
    }

    fn attention() -> SessionState {
        NeedsAttention { reason: "r".into() }
    }

    fn failed() -> SessionState {
        Failed { reason: "r".into() }
    }

    #[test]
    fn state_terminal_states_only_restart_through_starting() {
        for from in [Stopped, Locked, attention(), failed()] {
            assert!(from.is_terminal());
            assert!(from.can_transition_to(&Starting));
            for next in [Connected, reconnecting(), WaitingForNetwork] {
                assert!(!from.can_transition_to(&next), "{from:?} -> {next:?}");
            }
        }
    }

    #[test]
    fn state_every_state_can_stop() {
        for from in [
            Starting,
            Connected,
            reconnecting(),
            WaitingForNetwork,
            Locked,
            AwaitingHostKey(prompt()),
            attention(),
            failed(),
        ] {
            assert!(from.can_transition_to(&Stopped));
        }
    }

    #[test]
    fn state_normal_connect_and_reconnect_path_is_legal() {
        assert!(Starting.can_transition_to(&Connected));
        assert!(Connected.can_transition_to(&reconnecting()));
        assert!(reconnecting().can_transition_to(&reconnecting()));
        assert!(reconnecting().can_transition_to(&WaitingForNetwork));
        assert!(WaitingForNetwork.can_transition_to(&Connected));
    }

    #[test]
    fn state_host_key_prompt_only_comes_from_a_connect_attempt() {
        assert!(Starting.can_transition_to(&AwaitingHostKey(prompt())));
        assert!(reconnecting().can_transition_to(&AwaitingHostKey(prompt())));
        assert!(!Connected.can_transition_to(&AwaitingHostKey(prompt())));
        assert!(AwaitingHostKey(prompt()).can_transition_to(&Starting));
        assert!(!AwaitingHostKey(prompt()).can_transition_to(&reconnecting()));
    }

    #[tokio::test]
    async fn state_cell_broadcasts_legal_changes_and_rejects_illegal_ones() {
        let bus = EventBus::default();
        let mut events = bus.subscribe();
        let id = Uuid::new_v4();
        let cell = StateCell::new(id, bus);

        assert!(!cell.set(Connected), "Stopped -> Connected is illegal");
        assert!(!cell.set(Stopped), "no-op is not a change");
        assert!(cell.set(Starting));
        assert_eq!(cell.get(), Starting);
        assert_eq!(
            events.recv().await.unwrap(),
            RuntimeEvent::StateChanged {
                session_id: id,
                state: Starting
            }
        );
        assert!(events.try_recv().is_err());
    }

    #[test]
    fn state_serializes_with_a_stable_tag() {
        let json = serde_json::to_value(reconnecting()).unwrap();
        assert_eq!(json["state"], "reconnecting");
        assert_eq!(json["attempt"], 1);
        let json = serde_json::to_value(AwaitingHostKey(prompt())).unwrap();
        assert_eq!(json["state"], "awaiting_host_key");
        assert_eq!(json["sha256"], "SHA256:x");
    }
}
