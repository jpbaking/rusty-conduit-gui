//! [`SessionManager`]: runs many sessions concurrently on behalf of the UI.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use conduit_core::{HostKeyLookup, HostKeyRecord, KnownHostsStore, SessionProfile, Timestamp};
use conduit_ssh::AtomicStats;
use conduit_vault::Vault;
use thiserror::Error;
use tokio::sync::{broadcast, mpsc};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::events::{EventBus, RuntimeEvent, DEFAULT_EVENT_CAPACITY};
use crate::logs::{LogRingBuffer, DEFAULT_LOG_CAPACITY};
use crate::runner::{
    run_session, Control, DefaultEngine, Engine, SessionContext, SharedListeners, SharedVault,
};
use crate::state::{SessionSnapshot, SessionState, SessionStatsSnapshot, StateCell};

/// Tunable manager settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagerConfig {
    /// Quiet period after the last wake notification before sessions are recycled.
    pub wake_debounce: Duration,
    /// Delay between sessions during autostart.
    pub autostart_stagger: Duration,
    pub log_capacity: usize,
    pub event_capacity: usize,
}

impl Default for ManagerConfig {
    fn default() -> Self {
        Self {
            wake_debounce: Duration::from_secs(3),
            autostart_stagger: Duration::from_millis(500),
            log_capacity: DEFAULT_LOG_CAPACITY,
            event_capacity: DEFAULT_EVENT_CAPACITY,
        }
    }
}

/// A request the manager could not carry out.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RuntimeError {
    #[error("unknown session {0}")]
    UnknownSession(Uuid),
    #[error("session {0} is not waiting for a host-key decision")]
    NoPendingHostKey(Uuid),
    #[error("fingerprint does not match the key awaiting approval")]
    FingerprintMismatch,
    #[error("a different host key is already pinned for {hop_id}; it will not be overwritten")]
    PinConflict { hop_id: String },
}

struct Running {
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

struct Slot {
    profile: Mutex<SessionProfile>,
    logs: LogRingBuffer,
    stats: Arc<AtomicStats>,
    listeners: SharedListeners,
    cell: Arc<StateCell>,
    control: Mutex<Option<mpsc::UnboundedSender<Control>>>,
    /// Serializes start and stop, so a session never has two supervisors.
    lifecycle: tokio::sync::Mutex<Option<Running>>,
}

impl Slot {
    fn send(&self, message: Control) {
        if let Some(sender) = lock(&self.control).as_ref() {
            let _ = sender.send(message);
        }
    }

    fn snapshot(&self) -> SessionSnapshot {
        let profile = lock(&self.profile);
        SessionSnapshot {
            id: profile.id,
            name: profile.name.clone(),
            state: self.cell.get(),
            stats: SessionStatsSnapshot::from_stats(self.stats.snapshot(), self.cell.uptime_secs()),
            listeners: lock(&self.listeners).clone(),
        }
    }
}

// Guarded values are replaced whole, so a poisoned lock still holds valid data.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

struct Inner {
    vault: SharedVault,
    known_hosts: Arc<RwLock<KnownHostsStore>>,
    engine: Arc<dyn Engine>,
    config: ManagerConfig,
    events: EventBus,
    sessions: Mutex<HashMap<Uuid, Arc<Slot>>>,
    wake_generation: AtomicU64,
}

/// Supervises every session. Cloning yields another handle to the same manager.
#[derive(Clone)]
pub struct SessionManager {
    inner: Arc<Inner>,
}

impl SessionManager {
    pub fn new(
        vault: Arc<RwLock<Vault>>,
        known_hosts: Arc<RwLock<KnownHostsStore>>,
        config: ManagerConfig,
    ) -> Self {
        Self::with_engine(vault, known_hosts, config, Arc::new(DefaultEngine))
    }

    pub(crate) fn with_engine(
        vault: SharedVault,
        known_hosts: Arc<RwLock<KnownHostsStore>>,
        config: ManagerConfig,
        engine: Arc<dyn Engine>,
    ) -> Self {
        let events = EventBus::new(config.event_capacity);
        Self {
            inner: Arc::new(Inner {
                vault,
                known_hosts,
                engine,
                config,
                events,
                sessions: Mutex::new(HashMap::new()),
                wake_generation: AtomicU64::new(0),
            }),
        }
    }

    /// Adds a session, or updates its profile. A running session uses the update on next start.
    pub fn upsert_profile(&self, profile: SessionProfile) {
        let mut sessions = lock(&self.inner.sessions);
        match sessions.get(&profile.id) {
            Some(slot) => *lock(&slot.profile) = profile,
            None => {
                let id = profile.id;
                let slot = Slot {
                    profile: Mutex::new(profile),
                    logs: LogRingBuffer::new(self.inner.config.log_capacity),
                    stats: Arc::new(AtomicStats::default()),
                    listeners: Arc::default(),
                    cell: Arc::new(StateCell::new(id, self.inner.events.clone())),
                    control: Mutex::new(None),
                    lifecycle: tokio::sync::Mutex::new(None),
                };
                sessions.insert(id, Arc::new(slot));
            }
        }
    }

    /// Stops a session and forgets it.
    pub async fn remove_profile(&self, id: Uuid) -> Result<(), RuntimeError> {
        self.stop(id).await?;
        lock(&self.inner.sessions).remove(&id);
        Ok(())
    }

    fn slot(&self, id: Uuid) -> Result<Arc<Slot>, RuntimeError> {
        lock(&self.inner.sessions)
            .get(&id)
            .cloned()
            .ok_or(RuntimeError::UnknownSession(id))
    }

    fn ids(&self) -> Vec<Uuid> {
        lock(&self.inner.sessions).keys().copied().collect()
    }

    /// Starts a session. Does nothing if it is already running.
    pub async fn start(&self, id: Uuid) -> Result<(), RuntimeError> {
        let slot = self.slot(id)?;
        let mut lifecycle = slot.lifecycle.lock().await;
        if lifecycle.as_ref().is_some_and(|r| !r.task.is_finished()) {
            return Ok(());
        }
        // A finished task has already published its final state.
        if let Some(previous) = lifecycle.take() {
            let _ = previous.task.await;
        }

        let (sender, receiver) = mpsc::unbounded_channel();
        *lock(&slot.control) = Some(sender);
        slot.cell.set(SessionState::Starting);

        let ctx = SessionContext {
            profile: lock(&slot.profile).clone(),
            vault: Arc::clone(&self.inner.vault),
            known_hosts: Arc::clone(&self.inner.known_hosts),
            logs: slot.logs.clone(),
            stats: Arc::clone(&slot.stats),
            listeners: Arc::clone(&slot.listeners),
        };
        let cancel = CancellationToken::new();
        let session = tokio::spawn(run_session(
            Arc::clone(&self.inner.engine),
            ctx,
            Arc::clone(&slot.cell),
            receiver,
            cancel.clone(),
        ));
        // A panic must not leave the UI showing a live session.
        let cell = Arc::clone(&slot.cell);
        let task = tokio::spawn(async move {
            if session.await.is_err() {
                cell.set(SessionState::Failed {
                    reason: "session task panicked".into(),
                });
            }
        });
        *lifecycle = Some(Running { cancel, task });
        Ok(())
    }

    /// Stops a session, waiting for its graceful shutdown.
    pub async fn stop(&self, id: Uuid) -> Result<(), RuntimeError> {
        let slot = self.slot(id)?;
        let mut lifecycle = slot.lifecycle.lock().await;
        if let Some(running) = lifecycle.take() {
            running.cancel.cancel();
            let _ = running.task.await;
        }
        *lock(&slot.control) = None;
        slot.cell.set(SessionState::Stopped);
        Ok(())
    }

    pub async fn restart(&self, id: Uuid) -> Result<(), RuntimeError> {
        self.stop(id).await?;
        self.start(id).await
    }

    pub async fn start_all(&self) {
        for id in self.ids() {
            // An id removed concurrently is simply skipped.
            let _ = self.start(id).await;
        }
    }

    /// Stops every session concurrently, so one slow drain does not delay the rest.
    pub async fn stop_all(&self) {
        let mut stops = JoinSet::new();
        for id in self.ids() {
            let manager = self.clone();
            stops.spawn(async move {
                let _ = manager.stop(id).await;
            });
        }
        while stops.join_next().await.is_some() {}
    }

    /// Starts autostart sessions in name order, pausing between them.
    pub async fn start_autostart_staggered(&self) {
        let mut targets: Vec<(String, Uuid)> = lock(&self.inner.sessions)
            .values()
            .filter_map(|slot| {
                let profile = lock(&slot.profile);
                profile.autostart.then(|| (profile.name.clone(), profile.id))
            })
            .collect();
        targets.sort();
        for (index, (_, id)) in targets.into_iter().enumerate() {
            if index > 0 {
                tokio::time::sleep(self.inner.config.autostart_stagger).await;
            }
            let _ = self.start(id).await;
        }
    }

    /// Restarts sessions that were waiting on the vault.
    pub async fn on_vault_unlocked(&self) {
        let unlocked = self
            .inner
            .vault
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .is_unlocked();
        if !unlocked {
            return;
        }
        for id in self.ids() {
            let Ok(slot) = self.slot(id) else { continue };
            if slot.cell.get() == SessionState::Locked {
                let _ = self.start(id).await;
            }
        }
    }

    /// Pins the key awaiting approval and resumes the session.
    ///
    /// `sha256` must be the fingerprint the user saw, so a prompt that changed in the meantime
    /// cannot be approved by accident.
    pub fn approve_host_key(&self, id: Uuid, sha256: &str) -> Result<(), RuntimeError> {
        let slot = self.slot(id)?;
        let SessionState::AwaitingHostKey(prompt) = slot.cell.get() else {
            return Err(RuntimeError::NoPendingHostKey(id));
        };
        if prompt.sha256 != sha256 {
            return Err(RuntimeError::FingerprintMismatch);
        }
        {
            let mut store = self
                .inner
                .known_hosts
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            let existing = store.get(&prompt.hop_id, &prompt.host, prompt.port);
            if existing.is_some_and(|pin| pin.fingerprint_sha256 != prompt.sha256) {
                return Err(RuntimeError::PinConflict {
                    hop_id: prompt.hop_id,
                });
            }
            let first_seen = existing.map_or_else(Timestamp::now, |pin| pin.first_seen);
            store.insert(
                HostKeyLookup {
                    hop_id: prompt.hop_id.clone(),
                    host: prompt.host.clone(),
                    port: prompt.port,
                },
                HostKeyRecord {
                    algorithm: prompt.algorithm.clone(),
                    fingerprint_sha256: prompt.sha256.clone(),
                    first_seen,
                    approved: true,
                    public_key_openssh: prompt.public_key_openssh.clone(),
                },
            );
        }
        self.inner.events.emit(RuntimeEvent::KnownHostsChanged {
            session_id: id,
            hop_id: prompt.hop_id,
            host: prompt.host,
            port: prompt.port,
        });
        slot.send(Control::ApproveHostKey);
        Ok(())
    }

    /// Declines the key awaiting approval. The session halts in `NeedsAttention`.
    pub fn reject_host_key(&self, id: Uuid) -> Result<(), RuntimeError> {
        let slot = self.slot(id)?;
        if !matches!(slot.cell.get(), SessionState::AwaitingHostKey(_)) {
            return Err(RuntimeError::NoPendingHostKey(id));
        }
        slot.send(Control::RejectHostKey);
        Ok(())
    }

    /// Reports a system wake. Bursts are merged, then live sessions are recycled once.
    ///
    /// Only `Connected` and `Reconnecting` sessions are touched. Must be called inside a Tokio
    /// runtime.
    pub fn notify_system_wake(&self) {
        let generation = self.inner.wake_generation.fetch_add(1, Ordering::SeqCst) + 1;
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            tokio::time::sleep(inner.config.wake_debounce).await;
            if inner.wake_generation.load(Ordering::SeqCst) != generation {
                return;
            }
            let slots: Vec<Arc<Slot>> = lock(&inner.sessions).values().cloned().collect();
            for slot in slots {
                if matches!(
                    slot.cell.get(),
                    SessionState::Connected | SessionState::Reconnecting { .. }
                ) {
                    slot.send(Control::Recycle);
                }
            }
        });
    }

    /// A view of every session, sorted by name.
    pub fn snapshots(&self) -> Vec<SessionSnapshot> {
        let slots: Vec<Arc<Slot>> = lock(&self.inner.sessions).values().cloned().collect();
        let mut snapshots: Vec<SessionSnapshot> = slots.iter().map(|s| s.snapshot()).collect();
        snapshots.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
        snapshots
    }

    pub fn snapshot(&self, id: Uuid) -> Result<SessionSnapshot, RuntimeError> {
        Ok(self.slot(id)?.snapshot())
    }

    /// The log buffer for a session, for querying, clearing, or subscribing.
    pub fn logs(&self, id: Uuid) -> Result<LogRingBuffer, RuntimeError> {
        Ok(self.slot(id)?.logs.clone())
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<RuntimeEvent> {
        self.inner.events.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::testing::*;
    use crate::runner::{BoxFut, Link, LinkError};
    use conduit_core::{AuthMethod, ForwardConfig, HopEntry, HostProfile, SecretRef};
    use conduit_vault::Argon2Params;
    use std::collections::HashMap as Map;
    use std::sync::atomic::Ordering as AtomicOrdering;

    /// Hands each session its own script, keyed by session id.
    #[derive(Default)]
    struct ScriptEngine {
        scripts: Mutex<Map<Uuid, Arc<Script>>>,
    }

    impl Engine for ScriptEngine {
        fn prepare(
            &self,
            ctx: SessionContext,
        ) -> BoxFut<'static, Result<Box<dyn Link>, LinkError>> {
            let script = Arc::clone(&lock(&self.scripts)[&ctx.profile.id]);
            Box::pin(async move { Ok(Box::new(ScriptLink(script)) as Box<dyn Link>) })
        }
    }

    fn temp_vault() -> Vault {
        let path = std::env::temp_dir()
            .join(format!("conduit-runtime-test-{}", Uuid::new_v4()))
            .join("vault.bin");
        // `Argon2Params::FAST` is private to the vault crate's own tests.
        let params = Argon2Params {
            memory_kib: 8 * 1024,
            time_cost: 1,
            parallelism: 1,
            derived_key_len: 32,
        };
        Vault::create_with_password(path, b"pw", params).unwrap()
    }

    fn profile(name: &str) -> SessionProfile {
        SessionProfile {
            id: Uuid::new_v4(),
            name: name.into(),
            ..Default::default()
        }
    }

    struct Fixture {
        manager: SessionManager,
        engine: Arc<ScriptEngine>,
        known_hosts: Arc<RwLock<KnownHostsStore>>,
    }

    fn fixture() -> Fixture {
        let engine = Arc::new(ScriptEngine::default());
        let known_hosts = Arc::new(RwLock::new(KnownHostsStore::default()));
        let manager = SessionManager::with_engine(
            Arc::new(RwLock::new(temp_vault())),
            Arc::clone(&known_hosts),
            ManagerConfig {
                wake_debounce: Duration::from_secs(2),
                autostart_stagger: Duration::from_secs(1),
                ..ManagerConfig::default()
            },
            Arc::clone(&engine) as Arc<dyn Engine>,
        );
        Fixture {
            manager,
            engine,
            known_hosts,
        }
    }

    impl Fixture {
        fn add(&self, profile: SessionProfile, outcomes: Vec<Result<(), LinkError>>) -> (Uuid, Arc<Script>) {
            let id = profile.id;
            let script = Script::new(outcomes);
            lock(&self.engine.scripts).insert(id, Arc::clone(&script));
            self.manager.upsert_profile(profile);
            (id, script)
        }

        fn state(&self, id: Uuid) -> SessionState {
            self.manager.snapshot(id).unwrap().state
        }

        async fn until_state(&self, id: Uuid, wanted: SessionState) {
            until(|| self.state(id) == wanted).await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn start_stop_restart_lifecycle() {
        let f = fixture();
        let (id, script) = f.add(profile("a"), vec![Ok(()), Ok(())]);
        f.manager.start(id).await.unwrap();
        f.until_state(id, SessionState::Connected).await;

        f.manager.start(id).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(script.connects(), 1, "second start is a no-op");

        f.manager.restart(id).await.unwrap();
        f.until_state(id, SessionState::Connected).await;
        assert_eq!(script.connects(), 2);
        assert_eq!(script.shutdowns.load(AtomicOrdering::SeqCst), 1);

        f.manager.stop(id).await.unwrap();
        assert_eq!(f.state(id), SessionState::Stopped);
        assert_eq!(script.shutdowns.load(AtomicOrdering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn unknown_session_is_an_error() {
        let f = fixture();
        let id = Uuid::new_v4();
        assert_eq!(f.manager.start(id).await, Err(RuntimeError::UnknownSession(id)));
    }

    #[tokio::test(start_paused = true)]
    async fn start_all_and_stop_all_cover_every_session() {
        let f = fixture();
        let (a, _) = f.add(profile("a"), vec![Ok(())]);
        let (b, _) = f.add(profile("b"), vec![Ok(())]);
        f.manager.start_all().await;
        f.until_state(a, SessionState::Connected).await;
        f.until_state(b, SessionState::Connected).await;
        f.manager.stop_all().await;
        assert_eq!(f.state(a), SessionState::Stopped);
        assert_eq!(f.state(b), SessionState::Stopped);
    }

    #[tokio::test(start_paused = true)]
    async fn autostart_is_staggered_and_skips_others() {
        let f = fixture();
        let mut first = profile("a");
        first.autostart = true;
        let mut second = profile("b");
        second.autostart = true;
        let (a, _) = f.add(first, vec![Ok(())]);
        let (b, _) = f.add(second, vec![Ok(())]);
        let (manual, manual_script) = f.add(profile("c"), vec![Ok(())]);

        let manager = f.manager.clone();
        let run = tokio::spawn(async move { manager.start_autostart_staggered().await });
        f.until_state(a, SessionState::Connected).await;
        assert_eq!(f.state(b), SessionState::Stopped, "second waits for the stagger");
        run.await.unwrap();
        f.until_state(b, SessionState::Connected).await;
        assert_eq!(f.state(manual), SessionState::Stopped);
        assert_eq!(manual_script.connects(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn wake_is_debounced_into_one_recycle() {
        let f = fixture();
        let (id, script) = f.add(profile("a"), vec![Ok(()), Ok(()), Ok(())]);
        f.manager.start(id).await.unwrap();
        f.until_state(id, SessionState::Connected).await;

        for _ in 0..5 {
            f.manager.notify_system_wake();
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        assert_eq!(script.connects(), 1, "still inside the debounce window");
        tokio::time::sleep(Duration::from_secs(3)).await;
        until(|| script.connects() == 2).await;
        f.until_state(id, SessionState::Connected).await;
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert_eq!(script.connects(), 2, "a burst recycles exactly once");
        f.manager.stop(id).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn wake_skips_stopped_and_halted_sessions() {
        let f = fixture();
        let (stopped, stopped_script) = f.add(profile("stopped"), vec![Ok(())]);
        let (halted, halted_script) = f.add(
            profile("halted"),
            vec![Err(LinkError::Attention("bad credentials".into())), Ok(())],
        );
        f.manager.start(halted).await.unwrap();
        until(|| matches!(f.state(halted), SessionState::NeedsAttention { .. })).await;

        f.manager.notify_system_wake();
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert_eq!(f.state(stopped), SessionState::Stopped);
        assert_eq!(stopped_script.connects(), 0);
        assert!(matches!(f.state(halted), SessionState::NeedsAttention { .. }));
        assert_eq!(halted_script.connects(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn wake_retries_a_reconnecting_session_early() {
        let f = fixture();
        let mut p = profile("a");
        p.tunnel.reconnect_initial_delay = Duration::from_secs(30);
        p.tunnel.reconnect_max_delay = Duration::from_secs(30);
        let (id, script) = f.add(p, vec![transient(), Ok(())]);
        f.manager.start(id).await.unwrap();
        until(|| matches!(f.state(id), SessionState::Reconnecting { .. })).await;

        f.manager.notify_system_wake();
        tokio::time::sleep(Duration::from_secs(3)).await;
        f.until_state(id, SessionState::Connected).await;
        assert_eq!(script.connects(), 2);
        f.manager.stop(id).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn approve_host_key_pins_and_resumes() {
        let f = fixture();
        let mut events = f.manager.subscribe_events();
        let (id, script) = f.add(profile("a"), vec![Err(LinkError::HostKey(host_key())), Ok(())]);
        f.manager.start(id).await.unwrap();
        until(|| matches!(f.state(id), SessionState::AwaitingHostKey(_))).await;

        assert_eq!(
            f.manager.approve_host_key(id, "SHA256:other"),
            Err(RuntimeError::FingerprintMismatch)
        );
        assert!(f.known_hosts.read().unwrap().get("hop", "example.test", 22).is_none());

        f.manager.approve_host_key(id, "SHA256:abc").unwrap();
        let pin = f
            .known_hosts
            .read()
            .unwrap()
            .get("hop", "example.test", 22)
            .cloned()
            .unwrap();
        assert!(pin.approved);
        assert_eq!(pin.fingerprint_sha256, "SHA256:abc");
        assert_eq!(pin.public_key_openssh.as_deref(), Some("ssh-ed25519 AAAAtest"));
        f.until_state(id, SessionState::Connected).await;
        assert_eq!(script.connects(), 2);

        let mut saw_pin_event = false;
        while let Ok(event) = events.try_recv() {
            saw_pin_event |= matches!(event, RuntimeEvent::KnownHostsChanged { .. });
        }
        assert!(saw_pin_event);
        f.manager.stop(id).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn approve_never_overwrites_a_different_pin() {
        let f = fixture();
        f.known_hosts.write().unwrap().insert(
            HostKeyLookup {
                hop_id: "hop".into(),
                host: "example.test".into(),
                port: 22,
            },
            HostKeyRecord {
                algorithm: "ssh-ed25519".into(),
                fingerprint_sha256: "SHA256:pinned".into(),
                public_key_openssh: None,
                first_seen: Timestamp(1),
                approved: true,
            },
        );
        let (id, _) = f.add(profile("a"), vec![Err(LinkError::HostKey(host_key()))]);
        f.manager.start(id).await.unwrap();
        until(|| matches!(f.state(id), SessionState::AwaitingHostKey(_))).await;
        assert!(matches!(
            f.manager.approve_host_key(id, "SHA256:abc"),
            Err(RuntimeError::PinConflict { .. })
        ));
        let pinned = f
            .known_hosts
            .read()
            .unwrap()
            .get("hop", "example.test", 22)
            .map(|pin| pin.fingerprint_sha256.clone());
        assert_eq!(pinned.as_deref(), Some("SHA256:pinned"));
        f.manager.stop(id).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn reject_host_key_halts_and_requires_a_prompt() {
        let f = fixture();
        let (id, _) = f.add(profile("a"), vec![Err(LinkError::HostKey(host_key()))]);
        assert_eq!(
            f.manager.reject_host_key(id),
            Err(RuntimeError::NoPendingHostKey(id))
        );
        f.manager.start(id).await.unwrap();
        until(|| matches!(f.state(id), SessionState::AwaitingHostKey(_))).await;
        f.manager.reject_host_key(id).unwrap();
        until(|| matches!(f.state(id), SessionState::NeedsAttention { .. })).await;
    }

    fn real_manager(vault: Vault) -> SessionManager {
        SessionManager::new(
            Arc::new(RwLock::new(vault)),
            Arc::new(RwLock::new(KnownHostsStore::default())),
            ManagerConfig::default(),
        )
    }

    fn hop(auth: Vec<AuthMethod>) -> HopEntry {
        HopEntry {
            hop_id: "target".into(),
            name: "target".into(),
            host: HostProfile {
                // Port 1 on loopback refuses immediately, so no real server is contacted.
                host: "127.0.0.1".into(),
                port: 1,
                user: "user".into(),
                auth,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn real_profile(auth: Vec<AuthMethod>) -> SessionProfile {
        SessionProfile {
            id: Uuid::new_v4(),
            name: "real".into(),
            hops: vec![hop(auth)],
            forward: ForwardConfig {
                http_port: 0,
                socks_port: 0,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn locked_vault_with_secret() -> (Vault, SecretRef) {
        let mut vault = temp_vault();
        let id = vault.put_secret("password", b"pw-value").unwrap();
        vault.lock();
        let secret = serde_json::from_value(serde_json::Value::String(id)).unwrap();
        (vault, secret)
    }

    #[tokio::test]
    async fn locked_vault_gates_sessions_that_need_secrets() {
        let (vault, secret) = locked_vault_with_secret();
        let manager = real_manager(vault);
        let mut p = real_profile(vec![AuthMethod::Password { secret }]);
        p.forward.http_port = 18_080;
        let id = p.id;
        manager.upsert_profile(p);
        manager.start(id).await.unwrap();
        for _ in 0..200 {
            if manager.snapshot(id).unwrap().state == SessionState::Locked {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("expected Locked, got {:?}", manager.snapshot(id).unwrap().state);
    }

    #[tokio::test]
    async fn vault_unlock_resumes_locked_sessions() {
        let (vault, secret) = locked_vault_with_secret();
        let shared = Arc::new(RwLock::new(vault));
        let manager = SessionManager::new(
            Arc::clone(&shared),
            Arc::new(RwLock::new(KnownHostsStore::default())),
            ManagerConfig::default(),
        );
        let mut p = real_profile(vec![AuthMethod::Password { secret }]);
        p.forward.http_port = 18_081;
        let id = p.id;
        manager.upsert_profile(p);
        manager.start(id).await.unwrap();
        for _ in 0..200 {
            if manager.snapshot(id).unwrap().state == SessionState::Locked {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(manager.snapshot(id).unwrap().state, SessionState::Locked);

        manager.on_vault_unlocked().await;
        assert_eq!(
            manager.snapshot(id).unwrap().state,
            SessionState::Locked,
            "still locked, so nothing restarts"
        );

        shared.write().unwrap().unlock_with_password(b"pw").unwrap();
        manager.on_vault_unlocked().await;
        for _ in 0..400 {
            let state = manager.snapshot(id).unwrap().state;
            if matches!(state, SessionState::Reconnecting { .. }) {
                manager.stop(id).await.unwrap();
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("expected a connect attempt after unlock");
    }

    #[tokio::test]
    async fn session_without_secrets_starts_while_vault_is_locked() {
        let (vault, _) = locked_vault_with_secret();
        let manager = real_manager(vault);
        let mut p = real_profile(vec![AuthMethod::KeyboardInteractive { prompts: vec![] }]);
        p.forward.http_port = 18_082;
        let id = p.id;
        manager.upsert_profile(p);
        manager.start(id).await.unwrap();
        for _ in 0..400 {
            let state = manager.snapshot(id).unwrap().state;
            assert_ne!(state, SessionState::Locked);
            if matches!(state, SessionState::Reconnecting { .. }) {
                manager.stop(id).await.unwrap();
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("expected a connect attempt");
    }
}
