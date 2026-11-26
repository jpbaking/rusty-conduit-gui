//! External TOML link mode: follow a `rusty-conduit-switch` `config.toml` on disk.
//!
//! [`spawn_toml_watcher`] polls the linked file every debounce window (clamped to
//! [`MIN_DEBOUNCE_MS`]..=[`MAX_DEBOUNCE_MS`]). When its `(mtime, len)` changes it reads the
//! bytes; when the bytes changed it waits one more window, re-reading until two reads agree, so
//! a burst of saves is applied once. Pure Rust: no OS file-notification crates.
//!
//! [`merge_external_toml`] folds a parsed file into the running [`Proxy`], keeping the app-owned
//! fields (`id`, `name`, `source`, `autostart`, `enabled`, `mitm`) and the vaulted password of
//! every profile whose name still matches. Inline passwords in the file are never kept.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use conduit_core::{
    import_rusty_conduit_switch_toml, Proxy, SwitchTomlImport, UpstreamPasswordSource,
};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Shortest poll / coalescing window.
pub const MIN_DEBOUNCE_MS: u64 = 250;
/// Longest poll / coalescing window.
pub const MAX_DEBOUNCE_MS: u64 = 10_000;

/// The poll window for a requested `debounce_ms`.
pub fn clamp_debounce(debounce_ms: u64) -> Duration {
    Duration::from_millis(debounce_ms.clamp(MIN_DEBOUNCE_MS, MAX_DEBOUNCE_MS))
}

/// What the watcher saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TomlWatchEvent {
    /// The file settled on new bytes.
    Changed(Vec<u8>),
    /// The file could not be read (reported once until it can be read again).
    Unreadable(String),
}

/// A running watcher. Dropping it (or calling [`TomlWatcherHandle::cancel`]) stops it.
#[derive(Debug)]
pub struct TomlWatcherHandle {
    token: CancellationToken,
    task: JoinHandle<()>,
}

impl TomlWatcherHandle {
    pub fn cancel(&self) {
        self.token.cancel();
    }

    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

impl Drop for TomlWatcherHandle {
    fn drop(&mut self) {
        self.token.cancel();
    }
}

type Stamp = Option<(Option<SystemTime>, u64)>;

fn stamp(path: &Path) -> Stamp {
    std::fs::metadata(path)
        .ok()
        .map(|m| (m.modified().ok(), m.len()))
}

/// Sleeps one window; `false` when cancelled.
async fn tick(token: &CancellationToken, window: Duration) -> bool {
    tokio::select! {
        _ = token.cancelled() => false,
        _ = tokio::time::sleep(window) => true,
    }
}

/// Watches `path`, calling `on_event` for every settled change. The first settled read counts
/// as a change, so a file edited while nothing watched it is still applied. `on_event` runs on
/// the watcher task; the next poll waits for it.
pub fn spawn_toml_watcher<F, Fut>(path: PathBuf, debounce_ms: u64, mut on_event: F) -> TomlWatcherHandle
where
    F: FnMut(TomlWatchEvent) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send,
{
    let window = clamp_debounce(debounce_ms);
    let token = CancellationToken::new();
    let cancel = token.clone();
    let task = tokio::spawn(async move {
        let mut last_bytes: Option<Vec<u8>> = None;
        let mut last_stamp: Stamp = None;
        let mut failing = false;
        loop {
            if !tick(&cancel, window).await {
                return;
            }
            let now = stamp(&path);
            if now.is_some() && now == last_stamp && !failing {
                continue;
            }
            let mut current = match std::fs::read(&path) {
                Ok(bytes) => bytes,
                Err(e) => {
                    if !failing {
                        failing = true;
                        on_event(TomlWatchEvent::Unreadable(e.to_string())).await;
                    }
                    last_stamp = None;
                    continue;
                }
            };
            failing = false;
            if last_bytes.as_ref() == Some(&current) {
                last_stamp = now;
                continue;
            }
            // Coalesce rapid saves: wait until two reads one window apart agree.
            let settled = loop {
                if !tick(&cancel, window).await {
                    return;
                }
                match std::fs::read(&path) {
                    Ok(next) if next == current => break true,
                    Ok(next) => current = next,
                    Err(_) => break false,
                }
            };
            if !settled {
                last_stamp = None;
                continue;
            }
            last_stamp = stamp(&path);
            last_bytes = Some(current.clone());
            on_event(TomlWatchEvent::Changed(current)).await;
        }
    });
    TomlWatcherHandle { token, task }
}

/// A linked file folded into a Proxy.
#[derive(Debug, Clone)]
pub struct ExternalTomlMerge {
    pub proxy: Proxy,
    /// Import notes, for the Proxy's log.
    pub warnings: Vec<String>,
}

/// Folds an imported `rusty-conduit-switch` file into `current`: listeners, network, profiles,
/// routing, filter, and logging come from the file; everything else stays. A profile with no
/// password source in the file keeps `current`'s vaulted password when the names match. Inline
/// passwords are dropped here (the extracted secrets are zeroized), never stored.
pub fn merge_external_toml(current: &Proxy, imported: SwitchTomlImport) -> ExternalTomlMerge {
    let SwitchTomlImport { proxy: file, extracted_secrets, mut warnings } = imported;
    // The importer notes "moved to the Vault", which link mode does not do.
    warnings.retain(|w| !w.contains("inline password moved to the Vault"));
    let mut proxy = current.clone();
    proxy.listeners = file.listeners;
    proxy.network = file.network;
    proxy.routing = file.routing;
    proxy.filter = file.filter;
    proxy.logging = file.logging;
    proxy.profiles = file.profiles;
    for profile in &mut proxy.profiles {
        if profile.password.is_some() {
            continue;
        }
        let vaulted = current
            .profiles
            .iter()
            .find(|p| p.name == profile.name)
            .and_then(|p| match &p.password {
                Some(UpstreamPasswordSource::Vault(secret)) => Some(secret.clone()),
                _ => None,
            });
        if let Some(secret) = vaulted {
            profile.password = Some(UpstreamPasswordSource::Vault(secret));
        }
    }
    for secret in &extracted_secrets {
        let kept = proxy
            .profiles
            .iter()
            .any(|p| p.name == secret.profile_name && p.password.is_some());
        warnings.push(if kept {
            format!(
                "profile `{}`: the inline password in the linked file is ignored; the vaulted \
                 password is used",
                secret.profile_name
            )
        } else {
            format!(
                "profile `{}`: the inline password in the linked file is ignored; use \
                 `password_env` or `password_file`, or import the file to vault it",
                secret.profile_name
            )
        });
    }
    drop(extracted_secrets);
    ExternalTomlMerge { proxy, warnings }
}

/// Parses `text` as a `rusty-conduit-switch` file and folds it into `current`.
pub fn merge_external_toml_text(current: &Proxy, text: &str) -> Result<ExternalTomlMerge, String> {
    let imported = import_rusty_conduit_switch_toml(text, &current.name).map_err(|e| e.to_string())?;
    Ok(merge_external_toml(current, imported))
}

/// Reads the linked file at `path` and folds it into `current`.
pub fn read_external_toml(current: &Proxy, path: &Path) -> Result<ExternalTomlMerge, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    merge_external_toml_text(current, &text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use conduit_core::{ProxyId, SecretRef, SourceMode, UpstreamKind, UpstreamProfile};
    use tokio::sync::mpsc;
    use uuid::Uuid;

    const V1: &str = r#"
http_port = 3130
socks_port = 0

[profiles.corp]
type = "http"
host = "10.0.0.2"
port = 3128

[routing]
default = "direct"

[[routing.rules]]
name = "intranet"
host_wildcard = "*.corp.example"
target = "corp"
"#;

    fn temp_file(text: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("conduit-toml-watch-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn debounce_is_clamped() {
        assert_eq!(clamp_debounce(0), Duration::from_millis(250));
        assert_eq!(clamp_debounce(1_000), Duration::from_millis(1_000));
        assert_eq!(clamp_debounce(u64::MAX), Duration::from_millis(10_000));
    }

    #[test]
    fn merge_keeps_app_fields_and_vaulted_passwords() {
        let secret = SecretRef::new();
        let current = Proxy {
            id: ProxyId::new(),
            name: "linked".into(),
            autostart: true,
            enabled: false,
            source: SourceMode::ExternalToml { path: "/x.toml".into(), debounce_ms: 500 },
            profiles: vec![UpstreamProfile {
                name: "corp".into(),
                kind: UpstreamKind::Http,
                host: Some("old".into()),
                port: Some(1),
                username: None,
                password: Some(UpstreamPasswordSource::Vault(secret.clone())),
                bypass: Vec::new(),
                color: None,
            }],
            ..Proxy::default()
        };
        let text = format!("{V1}\n[profiles.other]\ntype = \"http\"\nhost = \"h\"\nport = 1\npassword = \"inline-canary\"\n");
        let merged = merge_external_toml_text(&current, &text).unwrap();
        let p = merged.proxy;
        assert_eq!((p.id, p.name.as_str(), p.autostart, p.enabled), (current.id, "linked", true, false));
        assert_eq!(p.source, current.source);
        assert_eq!(p.listeners.http_port, 3130);
        let corp = p.profiles.iter().find(|x| x.name == "corp").unwrap();
        assert_eq!(corp.host.as_deref(), Some("10.0.0.2"));
        assert_eq!(corp.password, Some(UpstreamPasswordSource::Vault(secret)));
        let other = p.profiles.iter().find(|x| x.name == "other").unwrap();
        assert_eq!(other.password, None);
        assert!(merged.warnings.iter().any(|w| w.contains("`other`") && w.contains("ignored")));
        assert!(!format!("{p:?}{:?}", merged.warnings).contains("inline-canary"));
    }

    #[test]
    fn invalid_text_is_an_error() {
        let err = merge_external_toml_text(&Proxy::default(), "http_port = [").unwrap_err();
        assert!(err.contains("rusty-conduit-switch"), "{err}");
    }

    async fn wait(rx: &mut mpsc::UnboundedReceiver<TomlWatchEvent>) -> TomlWatchEvent {
        tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap()
    }

    #[tokio::test]
    async fn watcher_reports_settled_changes_and_unreadable_files() {
        let path = temp_file(V1);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let handle = spawn_toml_watcher(path.clone(), 0, move |event| {
            let tx = tx.clone();
            async move {
                let _ = tx.send(event);
            }
        });
        // The first settled read is a change.
        assert_eq!(wait(&mut rx).await, TomlWatchEvent::Changed(V1.as_bytes().to_vec()));

        // A burst of saves is applied once, with the last bytes.
        std::fs::write(&path, "a = 1\n").unwrap();
        std::fs::write(&path, "a = 22\n").unwrap();
        assert_eq!(wait(&mut rx).await, TomlWatchEvent::Changed(b"a = 22\n".to_vec()));

        std::fs::remove_file(&path).unwrap();
        assert!(matches!(wait(&mut rx).await, TomlWatchEvent::Unreadable(_)));
        std::fs::write(&path, "a = 333\n").unwrap();
        assert_eq!(wait(&mut rx).await, TomlWatchEvent::Changed(b"a = 333\n".to_vec()));

        handle.cancel();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !handle.is_finished() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
