//! Thin `#[tauri::command]` wrappers over [`AppController`]. No business logic lives here.
//!
//! Secrets arrive as [`SecretInput`] and are never returned. Every command is `async` so disk,
//! key-derivation, and network work stays off the UI thread.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use conduit_core::{
    HostProfile, KeyId, KeySource, MitmCaId, SecretRef, SessionProfile, VaultCaMeta, VaultKeyMeta,
};
use conduit_openssh::OpenSshBinaryInfo;
use conduit_runtime::LogLine;
use serde::Serialize;
use tauri::{AppHandle, Manager, Runtime, State};
use uuid::Uuid;

use crate::controller::export::{ExportSummary, ImportSummary};
use crate::controller::keys::{
    BackupSummary, DeleteResult, GenerateAlgorithm, ImportBackupResult, KeyView,
};
use crate::controller::mitm_ca::{CaView, MitmCaUpload};
use crate::controller::parity::{self, FilterMode, FilterTestResult, PortConflictReport};
use crate::controller::sessions::{ChainTestResult, SessionView, StateSummary};
use crate::controller::{run_blocking, AppController, AppError, SecretInput, SecretMeta, VaultStatus};
use crate::platform;
use crate::tray_bridge::quit_app;
use crate::window::{CloseChoice, ShellSnapshot, ShellState, MAIN_WINDOW};

type Ctl<'a> = State<'a, AppController>;
type CmdResult<T> = Result<T, AppError>;

/// Runs a synchronous controller method on the blocking pool.
async fn blocking<T: Send + 'static>(
    controller: &AppController,
    work: impl FnOnce(AppController) -> CmdResult<T> + Send + 'static,
) -> CmdResult<T> {
    let controller = controller.clone();
    run_blocking(move || work(controller)).await
}

// Vault lifecycle.

#[tauri::command]
pub async fn vault_status(c: Ctl<'_>) -> CmdResult<VaultStatus> {
    blocking(&c, |c| Ok(c.vault_status())).await
}

#[tauri::command]
pub async fn create_vault(c: Ctl<'_>, password: SecretInput, use_keyring: bool) -> CmdResult<VaultStatus> {
    c.create_vault(password, use_keyring).await
}

#[tauri::command]
pub async fn unlock_vault(c: Ctl<'_>, password: SecretInput) -> CmdResult<VaultStatus> {
    c.unlock_vault_with_password(password).await
}

#[tauri::command]
pub async fn unlock_vault_keyring(c: Ctl<'_>) -> CmdResult<VaultStatus> {
    c.unlock_vault_with_keyring().await
}

#[tauri::command]
pub async fn set_vault_keyring(c: Ctl<'_>, enabled: bool) -> CmdResult<VaultStatus> {
    c.set_vault_keyring(enabled).await
}

#[tauri::command]
pub async fn lock_vault(c: Ctl<'_>) -> CmdResult<VaultStatus> {
    blocking(&c, |c| Ok(c.lock_vault())).await
}

// Keys and write-only secrets.

#[tauri::command]
pub async fn import_key_pem(
    c: Ctl<'_>,
    name: String,
    pem: SecretInput,
    passphrase: Option<SecretInput>,
    source: KeySource,
) -> CmdResult<VaultKeyMeta> {
    blocking(&c, move |c| c.import_key_pem(&name, pem, passphrase, source)).await
}

#[tauri::command]
pub async fn generate_key(
    c: Ctl<'_>,
    name: String,
    algorithm: Option<GenerateAlgorithm>,
) -> CmdResult<VaultKeyMeta> {
    blocking(&c, move |c| c.generate_key(&name, algorithm.unwrap_or_default())).await
}

#[tauri::command]
pub async fn rename_key(c: Ctl<'_>, id: KeyId, name: String) -> CmdResult<VaultKeyMeta> {
    blocking(&c, move |c| c.rename_key(&id, &name)).await
}

#[tauri::command]
pub async fn delete_key(c: Ctl<'_>, id: KeyId, force: Option<bool>) -> CmdResult<DeleteResult> {
    blocking(&c, move |c| c.delete_key(&id, force.unwrap_or(false))).await
}

#[tauri::command]
pub async fn list_keys(c: Ctl<'_>) -> CmdResult<Vec<KeyView>> {
    blocking(&c, |c| Ok(c.list_keys())).await
}

#[tauri::command]
pub async fn set_password_secret(
    c: Ctl<'_>,
    existing: Option<SecretRef>,
    password: SecretInput,
) -> CmdResult<SecretMeta> {
    blocking(&c, move |c| c.set_password_secret(existing.as_ref(), password)).await
}

// MITM CAs: uploaded once into the vault, then chosen by sessions.

#[tauri::command]
pub async fn import_mitm_ca(
    c: Ctl<'_>,
    name: String,
    upload: MitmCaUpload,
    passphrase: Option<SecretInput>,
) -> CmdResult<VaultCaMeta> {
    blocking(&c, move |c| c.import_mitm_ca(&name, upload, passphrase)).await
}

#[tauri::command]
pub async fn rename_mitm_ca(c: Ctl<'_>, id: MitmCaId, name: String) -> CmdResult<VaultCaMeta> {
    blocking(&c, move |c| c.rename_mitm_ca(&id, &name)).await
}

#[tauri::command]
pub async fn delete_mitm_ca(c: Ctl<'_>, id: MitmCaId, force: Option<bool>) -> CmdResult<DeleteResult> {
    c.delete_mitm_ca(&id, force.unwrap_or(false)).await
}

#[tauri::command]
pub async fn list_mitm_cas(c: Ctl<'_>) -> CmdResult<Vec<CaView>> {
    blocking(&c, |c| Ok(c.list_mitm_cas())).await
}

#[tauri::command]
pub async fn delete_secret(c: Ctl<'_>, secret: SecretRef, force: Option<bool>) -> CmdResult<DeleteResult> {
    blocking(&c, move |c| c.delete_secret(&secret, force.unwrap_or(false))).await
}

#[tauri::command]
pub async fn export_backup(c: Ctl<'_>, path: PathBuf, passphrase: SecretInput) -> CmdResult<BackupSummary> {
    blocking(&c, move |c| c.export_backup(&path, passphrase)).await
}

#[tauri::command]
pub async fn import_backup(
    c: Ctl<'_>,
    path: PathBuf,
    passphrase: SecretInput,
) -> CmdResult<ImportBackupResult> {
    blocking(&c, move |c| c.import_backup(&path, passphrase)).await
}

// Sessions and hosts.

#[tauri::command]
pub async fn get_state_summary(c: Ctl<'_>) -> CmdResult<StateSummary> {
    blocking(&c, |c| Ok(c.get_state_summary())).await
}

#[tauri::command]
pub async fn list_sessions(c: Ctl<'_>) -> CmdResult<Vec<SessionView>> {
    blocking(&c, |c| c.list_sessions()).await
}

#[tauri::command]
pub async fn upsert_session(c: Ctl<'_>, profile: SessionProfile) -> CmdResult<SessionProfile> {
    blocking(&c, move |c| c.upsert_session(profile)).await
}

#[tauri::command]
pub async fn delete_session(c: Ctl<'_>, id: Uuid) -> CmdResult<()> {
    c.delete_session(id).await
}

#[tauri::command]
pub async fn duplicate_session(c: Ctl<'_>, id: Uuid) -> CmdResult<SessionProfile> {
    blocking(&c, move |c| c.duplicate_session(id)).await
}

#[tauri::command]
pub async fn list_hosts(c: Ctl<'_>) -> CmdResult<Vec<HostProfile>> {
    blocking(&c, |c| Ok(c.list_hosts())).await
}

#[tauri::command]
pub async fn upsert_host(c: Ctl<'_>, host: HostProfile) -> CmdResult<HostProfile> {
    blocking(&c, move |c| c.upsert_host(host)).await
}

#[tauri::command]
pub async fn delete_host(c: Ctl<'_>, id: Uuid) -> CmdResult<()> {
    blocking(&c, move |c| c.delete_host(id)).await
}

#[tauri::command]
pub async fn promote_hop_to_host(
    c: Ctl<'_>,
    session_id: Uuid,
    hop_id: String,
    name: Option<String>,
) -> CmdResult<HostProfile> {
    blocking(&c, move |c| c.promote_hop_to_host(session_id, &hop_id, name.as_deref())).await
}

// Runtime.

#[tauri::command]
pub async fn start_session(c: Ctl<'_>, id: Uuid) -> CmdResult<()> {
    c.start_session(id).await
}

#[tauri::command]
pub async fn stop_session(c: Ctl<'_>, id: Uuid) -> CmdResult<()> {
    c.stop_session(id).await
}

#[tauri::command]
pub async fn restart_session(c: Ctl<'_>, id: Uuid) -> CmdResult<()> {
    c.restart_session(id).await
}

#[tauri::command]
pub async fn start_all(c: Ctl<'_>) -> CmdResult<()> {
    c.start_all().await;
    Ok(())
}

#[tauri::command]
pub async fn stop_all(c: Ctl<'_>) -> CmdResult<()> {
    c.stop_all().await;
    Ok(())
}

#[tauri::command]
pub async fn get_session_logs(c: Ctl<'_>, id: Uuid, limit: Option<usize>) -> CmdResult<Vec<LogLine>> {
    blocking(&c, move |c| c.get_session_logs(id, limit)).await
}

#[tauri::command]
pub async fn clear_session_logs(c: Ctl<'_>, id: Uuid) -> CmdResult<()> {
    blocking(&c, move |c| c.clear_session_logs(id)).await
}

// Host keys and diagnostics.

#[tauri::command]
pub async fn approve_host_key(c: Ctl<'_>, id: Uuid, sha256: String) -> CmdResult<()> {
    blocking(&c, move |c| c.approve_host_key(id, &sha256)).await
}

#[tauri::command]
pub async fn reject_host_key(c: Ctl<'_>, id: Uuid) -> CmdResult<()> {
    blocking(&c, move |c| c.reject_host_key(id)).await
}

/// Pins the unknown key the latest Test Chain run of session `id` saw.
#[tauri::command]
pub async fn trust_tested_host_key(
    c: Ctl<'_>,
    id: Uuid,
    sha256: String,
) -> CmdResult<conduit_core::HostKeyEntry> {
    blocking(&c, move |c| c.trust_tested_host_key(id, &sha256)).await
}

#[tauri::command]
pub async fn list_host_key_pins(c: Ctl<'_>) -> CmdResult<Vec<conduit_core::HostKeyEntry>> {
    blocking(&c, |c| Ok(c.list_host_key_pins())).await
}

#[tauri::command]
pub async fn reset_host_key(c: Ctl<'_>, hop_id: String, host: String, port: u16) -> CmdResult<bool> {
    blocking(&c, move |c| c.reset_host_key(&hop_id, &host, port)).await
}

/// Pins a hop's host key from a `known_hosts` file at a path the user typed. Never a default path.
#[tauri::command]
pub async fn import_known_host(
    c: Ctl<'_>,
    hop_id: String,
    host: String,
    port: u16,
    path: String,
) -> CmdResult<conduit_core::HostKeyEntry> {
    blocking(&c, move |c| {
        c.import_known_host_from_file(&hop_id, &host, port, std::path::Path::new(&path))
    })
    .await
}

#[tauri::command]
pub async fn test_chain(c: Ctl<'_>, id: Uuid) -> CmdResult<ChainTestResult> {
    c.test_session_chain(id).await
}

// Session-editor helpers.

#[tauri::command]
pub async fn check_port_conflicts(
    c: Ctl<'_>,
    session_id: Option<Uuid>,
    bind: IpAddr,
    http_port: u16,
    socks_port: u16,
) -> CmdResult<PortConflictReport> {
    blocking(&c, move |c| Ok(c.check_port_conflicts(session_id, bind, http_port, socks_port))).await
}

#[tauri::command]
pub async fn test_filter_rules(
    mode: FilterMode,
    rules: Vec<String>,
    target: String,
) -> CmdResult<FilterTestResult> {
    Ok(parity::test_filter_rules(mode, &rules, &target))
}

/// Runs `<ssh_bin> -V`, which can take seconds, on the blocking pool.
#[tauri::command]
pub async fn check_openssh_binary(ssh_bin: Option<String>) -> CmdResult<OpenSshBinaryInfo> {
    run_blocking(move || Ok(parity::check_openssh_binary(ssh_bin))).await
}

// Config export and import.

#[tauri::command]
pub async fn export_config(
    c: Ctl<'_>,
    path: PathBuf,
    include_secrets: Option<bool>,
    passphrase: Option<SecretInput>,
) -> CmdResult<ExportSummary> {
    blocking(&c, move |c| c.export_config(&path, include_secrets.unwrap_or(false), passphrase)).await
}

#[tauri::command]
pub async fn import_config(
    c: Ctl<'_>,
    path: PathBuf,
    passphrase: Option<SecretInput>,
    replace_existing: Option<bool>,
) -> CmdResult<ImportSummary> {
    blocking(&c, move |c| c.import_config(&path, passphrase, replace_existing.unwrap_or(false))).await
}

// Desktop shell.

/// Login autostart, behind a trait so tests never write a real autostart entry.
pub trait AutostartControl: Send + Sync + 'static {
    fn is_enabled(&self) -> Result<bool, String>;
    fn set_enabled(&self, enabled: bool) -> Result<(), String>;
}

/// Managed Tauri state holding the autostart implementation.
#[derive(Clone)]
pub struct AutostartHandle(Arc<dyn AutostartControl>);

impl AutostartHandle {
    pub fn new(control: impl AutostartControl) -> Self {
        Self(Arc::new(control))
    }
}

/// Autostart state shown in Settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutostartStatus {
    pub enabled: bool,
    /// The program the login entry launches: the stable `$APPIMAGE` path when there is one.
    pub executable: String,
    pub args: Vec<String>,
}

fn autostart_status(handle: &AutostartHandle) -> CmdResult<AutostartStatus> {
    let executable = platform::autostart_executable()
        .map_err(|e| AppError::Io(format!("could not resolve the app path: {e}")))?;
    Ok(AutostartStatus {
        enabled: handle.0.is_enabled().map_err(AppError::Io)?,
        executable: executable.display().to_string(),
        args: vec![platform::FLAG_TRAY.to_owned()],
    })
}

#[tauri::command]
pub async fn get_autostart(autostart: State<'_, AutostartHandle>) -> CmdResult<AutostartStatus> {
    let handle = autostart.inner().clone();
    run_blocking(move || autostart_status(&handle)).await
}

#[tauri::command]
pub async fn set_autostart(
    autostart: State<'_, AutostartHandle>,
    enabled: bool,
) -> CmdResult<AutostartStatus> {
    let handle = autostart.inner().clone();
    run_blocking(move || {
        handle.0.set_enabled(enabled).map_err(AppError::Io)?;
        autostart_status(&handle)
    })
    .await
}

/// Called once by the page after its event listeners are attached.
#[tauri::command]
pub async fn shell_ready(shell: State<'_, ShellState>) -> CmdResult<ShellSnapshot> {
    Ok(shell.mark_ui_ready())
}

/// The user's answer to a close or quit question.
#[tauri::command]
pub async fn resolve_close<R: Runtime>(
    app: AppHandle<R>,
    shell: State<'_, ShellState>,
    choice: CloseChoice,
) -> CmdResult<()> {
    shell.clear_close_question();
    match choice {
        CloseChoice::Cancel => {}
        CloseChoice::Quit => quit_app(app),
        CloseChoice::KeepRunning => {
            if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
                window
                    .destroy()
                    .map_err(|e| AppError::Task(format!("could not close the window: {e}")))?;
            }
        }
    }
    Ok(())
}

/// The full IPC surface, shared by the app and the dispatch tests.
macro_rules! ipc_handler {
    () => {
        tauri::generate_handler![
            $crate::commands::vault_status,
            $crate::commands::create_vault,
            $crate::commands::unlock_vault,
            $crate::commands::unlock_vault_keyring,
            $crate::commands::set_vault_keyring,
            $crate::commands::lock_vault,
            $crate::commands::import_key_pem,
            $crate::commands::generate_key,
            $crate::commands::rename_key,
            $crate::commands::delete_key,
            $crate::commands::list_keys,
            $crate::commands::set_password_secret,
            $crate::commands::import_mitm_ca,
            $crate::commands::rename_mitm_ca,
            $crate::commands::delete_mitm_ca,
            $crate::commands::list_mitm_cas,
            $crate::commands::delete_secret,
            $crate::commands::export_backup,
            $crate::commands::import_backup,
            $crate::commands::get_state_summary,
            $crate::commands::list_sessions,
            $crate::commands::upsert_session,
            $crate::commands::delete_session,
            $crate::commands::duplicate_session,
            $crate::commands::list_hosts,
            $crate::commands::upsert_host,
            $crate::commands::delete_host,
            $crate::commands::promote_hop_to_host,
            $crate::commands::start_session,
            $crate::commands::stop_session,
            $crate::commands::restart_session,
            $crate::commands::start_all,
            $crate::commands::stop_all,
            $crate::commands::get_session_logs,
            $crate::commands::clear_session_logs,
            $crate::commands::approve_host_key,
            $crate::commands::reject_host_key,
            $crate::commands::trust_tested_host_key,
            $crate::commands::list_host_key_pins,
            $crate::commands::reset_host_key,
            $crate::commands::import_known_host,
            $crate::commands::test_chain,
            $crate::commands::check_port_conflicts,
            $crate::commands::test_filter_rules,
            $crate::commands::check_openssh_binary,
            $crate::commands::export_config,
            $crate::commands::import_config,
            $crate::commands::get_autostart,
            $crate::commands::set_autostart,
            $crate::commands::shell_ready,
            $crate::commands::resolve_close,
        ]
    };
}
pub(crate) use ipc_handler;

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use base64::Engine as _;
    use conduit_core::MitmConfig;
    use conduit_vault::KeyGenAlgorithm;
    use russh::keys::ssh_key::LineEnding;
    use serde_json::{json, Value};
    use tauri::ipc::{CallbackFn, InvokeBody};
    use tauri::test::{get_ipc_response, mock_builder, mock_context, noop_assets, MockRuntime, INVOKE_KEY};
    use tauri::webview::InvokeRequest;
    use tauri::{Manager, WebviewWindow, WebviewWindowBuilder};

    use super::*;
    use crate::controller::test_support::{profile, test_options, TempDir};

    const MASTER: &str = "canary-master-password-91c2";
    const PASSWORD: &str = "canary-hop-password-44ab";
    /// Protects the uploaded PKCS#12 CA.
    const MITM: &str = "canary-mitm-passphrase-0d7e";
    const KEY_PASS: &str = "canary-key-passphrase-b18f";
    const BACKUP_PASS: &str = "canary-backup-passphrase-6e30";

    /// Every registered command. The test fails if one is added without being exercised.
    const ALL_COMMANDS: &[&str] = &[
        "vault_status", "create_vault", "unlock_vault", "unlock_vault_keyring", "set_vault_keyring", "lock_vault",
        "import_key_pem", "generate_key", "rename_key", "delete_key", "list_keys",
        "set_password_secret", "import_mitm_ca", "rename_mitm_ca", "delete_mitm_ca", "list_mitm_cas",
        "delete_secret", "export_backup",
        "import_backup", "get_state_summary", "list_sessions", "upsert_session", "delete_session", "duplicate_session",
        "list_hosts", "upsert_host", "delete_host", "promote_hop_to_host", "start_session",
        "stop_session", "restart_session", "start_all", "stop_all", "get_session_logs",
        "clear_session_logs", "approve_host_key", "reject_host_key", "trust_tested_host_key",
        "list_host_key_pins",
        "reset_host_key", "import_known_host", "test_chain", "check_port_conflicts", "test_filter_rules",
        "check_openssh_binary", "export_config", "import_config",
        "get_autostart", "set_autostart", "shell_ready", "resolve_close",
    ];

    /// Keeps autostart in memory, so tests never touch the real login items.
    #[derive(Default)]
    struct MemoryAutostart(std::sync::atomic::AtomicBool);

    impl AutostartControl for MemoryAutostart {
        fn is_enabled(&self) -> Result<bool, String> {
            Ok(self.0.load(std::sync::atomic::Ordering::SeqCst))
        }

        fn set_enabled(&self, enabled: bool) -> Result<(), String> {
            self.0.store(enabled, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    /// Drives commands through Tauri's real IPC dispatch and records every response.
    struct Ipc {
        window: WebviewWindow<MockRuntime>,
        _app: tauri::App<MockRuntime>,
        transcript: Vec<String>,
        called: BTreeSet<String>,
    }

    impl Ipc {
        fn new(dir: &TempDir) -> Self {
            let controller = AppController::open(dir.path(), test_options()).unwrap();
            let app = mock_builder()
                .manage(controller)
                .manage(ShellState::default())
                .manage(AutostartHandle::new(MemoryAutostart::default()))
                .invoke_handler(ipc_handler!())
                .build(mock_context(noop_assets()))
                .unwrap();
            let window = WebviewWindowBuilder::new(&app, "main", Default::default())
                .build()
                .unwrap();
            Self { window, _app: app, transcript: Vec::new(), called: BTreeSet::new() }
        }

        fn call(&mut self, cmd: &str, body: Value) -> Result<Value, Value> {
            self.called.insert(cmd.to_owned());
            let response = get_ipc_response(
                &self.window,
                InvokeRequest {
                    cmd: cmd.into(),
                    callback: CallbackFn(0),
                    error: CallbackFn(1),
                    url: if cfg!(windows) {
                        "http://tauri.localhost"
                    } else {
                        "tauri://localhost"
                    }
                    .parse()
                    .unwrap(),
                    body: InvokeBody::Json(body),
                    headers: Default::default(),
                    invoke_key: INVOKE_KEY.to_string(),
                },
            )
            .map(|r| r.deserialize::<Value>().unwrap());
            self.transcript.push(match &response {
                Ok(value) | Err(value) => value.to_string(),
            });
            response
        }

        fn ok(&mut self, cmd: &str, body: Value) -> Value {
            self.call(cmd, body)
                .unwrap_or_else(|error| panic!("{cmd} failed: {error}"))
        }

        fn err(&mut self, cmd: &str, body: Value) -> Value {
            match self.call(cmd, body) {
                Err(error) => error,
                Ok(value) => panic!("{cmd} unexpectedly succeeded: {value}"),
            }
        }
    }

    /// Fragments that must never leave Rust: whole secrets and each base64 line of the keys.
    fn forbidden(pems: &[&str]) -> Vec<String> {
        let mut all: Vec<String> =
            [MASTER, PASSWORD, MITM, KEY_PASS, BACKUP_PASS].map(String::from).to_vec();
        all.push("PRIVATE KEY".into());
        for pem in pems {
            all.extend(
                pem.lines()
                    .filter(|l| !l.starts_with("-----") && l.len() >= 16)
                    .map(String::from),
            );
        }
        all
    }

    /// A PKCS#12 CA protected by the [`MITM`] canary, and its private key PEM.
    fn mitm_ca_p12() -> (Vec<u8>, String) {
        use p12_keystore::{Certificate, EncryptionAlgorithm, KeyStore, KeyStoreEntry, PrivateKey, PrivateKeyChain};
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, "IPC Test CA");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(30);
        let cert = params.self_signed(&key).unwrap();
        let chain = PrivateKeyChain::new(
            b"key-id".to_vec(),
            PrivateKey::from_der(&key.serialize_der()).unwrap(),
            [Certificate::from_der(cert.der()).unwrap()],
        );
        let mut store = KeyStore::new();
        store.add_entry("ca", KeyStoreEntry::PrivateKeyChain(chain));
        let bytes = store
            .writer(MITM)
            .encryption_algorithm(EncryptionAlgorithm::PbeWithHmacSha256AndAes256)
            .write()
            .unwrap();
        (bytes, key.serialize_pem())
    }

    fn assert_clean(label: &str, text: &str, forbidden: &[String]) {
        for fragment in forbidden {
            assert!(!text.contains(fragment.as_str()), "{label} leaked a secret fragment");
        }
    }

    #[test]
    fn every_ipc_command_works_and_no_response_or_file_leaks_a_secret() {
        let dir = TempDir::new();
        let mut ipc = Ipc::new(&dir);

        // Vault lifecycle.
        assert_eq!(ipc.ok("vault_status", json!({}))["initialized"], false);
        assert_eq!(ipc.err("unlock_vault", json!({ "password": MASTER }))["code"], "vault_not_initialized");
        assert_eq!(
            ipc.ok("create_vault", json!({ "password": MASTER, "useKeyring": true }))["unlocked"],
            true
        );
        assert_eq!(ipc.err("create_vault", json!({ "password": MASTER, "useKeyring": false }))["code"], "vault_exists");
        assert_eq!(ipc.ok("lock_vault", json!({}))["unlocked"], false);
        assert_eq!(ipc.err("unlock_vault", json!({ "password": PASSWORD }))["code"], "unlock_failed");
        assert_eq!(ipc.ok("unlock_vault", json!({ "password": MASTER }))["unlocked"], true);
        ipc.ok("lock_vault", json!({}));
        assert_eq!(ipc.ok("unlock_vault_keyring", json!({}))["unlocked"], true);
        assert_eq!(ipc.ok("set_vault_keyring", json!({ "enabled": false }))["keyring"], false);
        assert_eq!(ipc.ok("set_vault_keyring", json!({ "enabled": true }))["keyring"], true);

        // Keys: plain and passphrase-protected imports, plus a malformed one that must not echo.
        let (plain, _) = conduit_vault::generate_key(KeyGenAlgorithm::Ed25519).unwrap();
        let plain_pem = plain.to_openssh(LineEnding::LF).unwrap().to_string();
        let (other, _) = conduit_vault::generate_key(KeyGenAlgorithm::Ed25519).unwrap();
        let other_pem = other.to_openssh(LineEnding::LF).unwrap().to_string();
        let encrypted_pem = other
            .encrypt(&mut getrandom::SysRng, KEY_PASS)
            .unwrap()
            .to_openssh(LineEnding::LF)
            .unwrap()
            .to_string();

        let key = ipc.ok("import_key_pem", json!({ "name": "plain", "pem": plain_pem, "source": "Pasted" }));
        assert!(key["public_key_openssh"].as_str().unwrap().starts_with("ssh-ed25519 "));
        let key_id = key["id"].clone();
        let protected = ipc.ok(
            "import_key_pem",
            json!({ "name": "protected", "pem": encrypted_pem, "passphrase": KEY_PASS, "source": "Uploaded" }),
        );
        ipc.err("import_key_pem", json!({ "name": "bad", "pem": PASSWORD, "source": "Pasted" }));
        let truncated = format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{PASSWORD}\n");
        ipc.err("import_key_pem", json!({ "name": "bad", "pem": truncated, "source": "Pasted" }));

        let generated = ipc.ok("generate_key", json!({ "name": "gen", "algorithm": "ecdsa-p256" }));
        assert_eq!(generated["algorithm"], "ECDSA-P256");
        assert_eq!(ipc.ok("rename_key", json!({ "id": key_id, "name": "renamed" }))["name"], "renamed");

        // Secrets.
        let secret = ipc.ok("set_password_secret", json!({ "password": PASSWORD }));
        assert_eq!(secret["has_secret"], true);
        let rotated = ipc.ok(
            "set_password_secret",
            json!({ "existing": secret["secret_ref"], "password": PASSWORD }),
        );
        let secret_ref = rotated["secret_ref"].clone();

        // Hosts and sessions, on a closed loopback port so nothing external is contacted.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let host = ipc.ok(
            "upsert_host",
            json!({ "host": { "name": "h", "host": "127.0.0.1", "port": closed, "user": "u",
                              "auth": [{ "Key": { "key": key_id } }] } }),
        );
        assert_eq!(ipc.ok("list_hosts", json!({})).as_array().unwrap().len(), 1);

        let mut session = profile("s", closed);
        session.forward.http_port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        // MITM CA: uploaded as file contents, never as a path.
        let (p12, ca_key_pem) = mitm_ca_p12();
        let upload = json!({ "format": "pkcs12", "data": base64::engine::general_purpose::STANDARD.encode(&p12) });
        assert_eq!(
            ipc.err("import_mitm_ca", json!({ "name": "ca", "upload": upload, "passphrase": PASSWORD }))["code"],
            "invalid"
        );
        ipc.err("import_mitm_ca", json!({ "name": "ca", "upload": { "format": "path", "path": "/tmp/ca.p12" } }));
        let ca = ipc.ok("import_mitm_ca", json!({ "name": "ca", "upload": upload, "passphrase": MITM }));
        assert!(ca["subject"].as_str().unwrap().contains("IPC Test CA"));
        assert_eq!(
            ipc.err("import_mitm_ca", json!({ "name": "again", "upload": upload, "passphrase": MITM }))["code"],
            "duplicate_ca"
        );
        assert_eq!(ipc.ok("rename_mitm_ca", json!({ "id": ca["id"], "name": "corp ca" }))["name"], "corp ca");
        let ca_id = serde_json::from_value(ca["id"].clone()).unwrap();
        session.mitm = Some(MitmConfig { ca: Some(ca_id), ..MitmConfig::default() });
        let mut session_json = serde_json::to_value(&session).unwrap();
        session_json["hops"][0]["host"]["auth"] = json!([{ "Password": { "secret": secret_ref } }]);
        let saved = ipc.ok("upsert_session", json!({ "profile": session_json }));
        let id = saved["id"].clone();
        let hop_id = saved["hops"][0]["hop_id"].clone();

        let cas = ipc.ok("list_mitm_cas", json!({}));
        assert_eq!((cas[0]["used_by"].clone(), cas[0]["usage"]["sessions"][0]["name"].clone()), (json!(1), json!("s")));

        assert_eq!(ipc.ok("get_state_summary", json!({}))["session_count"], 1);
        assert_eq!(ipc.ok("list_sessions", json!({})).as_array().unwrap().len(), 1);
        assert_eq!(ipc.ok("list_keys", json!({})).as_array().unwrap().len(), 3);
        let promoted = ipc.ok("promote_hop_to_host", json!({ "sessionId": id, "hopId": hop_id, "name": "promoted" }));
        assert_eq!(promoted["name"], "promoted");

        // Runtime. The SSH port is closed, so starts end in a failed state, not a tunnel.
        ipc.ok("start_session", json!({ "id": id }));
        ipc.ok("restart_session", json!({ "id": id }));
        ipc.ok("stop_session", json!({ "id": id }));
        ipc.ok("start_all", json!({}));
        ipc.ok("stop_all", json!({}));
        assert!(ipc.ok("get_session_logs", json!({ "id": id, "limit": 50 })).is_array());
        ipc.ok("clear_session_logs", json!({ "id": id }));
        assert_eq!(ipc.ok("get_session_logs", json!({ "id": id })), json!([]));

        // Host keys and diagnostics.
        assert_eq!(ipc.err("approve_host_key", json!({ "id": id, "sha256": "SHA256:x" }))["code"], "runtime");
        assert_eq!(ipc.err("reject_host_key", json!({ "id": id }))["code"], "runtime");
        assert_eq!(ipc.ok("list_host_key_pins", json!({})), json!([]));
        assert_eq!(ipc.ok("reset_host_key", json!({ "hopId": "h", "host": "x", "port": 22 })), false);
        let user_known_hosts = dir.path().join("user-known_hosts");
        std::fs::write(
            &user_known_hosts,
            "[x]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIMAKvbC1OkNvrNiAjJ6wli5nNQS5707OnbcrowxpV2Q\n",
        )
        .unwrap();
        let imported = ipc.ok(
            "import_known_host",
            json!({ "hopId": "h", "host": "x", "port": 2222, "path": user_known_hosts }),
        );
        assert_eq!(imported["record"]["fingerprint_sha256"], "SHA256:9I6JDw93SZWDRe51mShFze57vAaKMdUWr3LkP0+FEEM");
        assert_eq!(ipc.ok("list_host_key_pins", json!({})).as_array().unwrap().len(), 1);
        assert_eq!(
            ipc.err("import_known_host", json!({ "hopId": "h", "host": "y", "port": 22, "path": user_known_hosts }))["code"],
            "not_found"
        );
        assert_eq!(ipc.ok("reset_host_key", json!({ "hopId": "h", "host": "x", "port": 2222 })), true);
        let report = ipc.ok("test_chain", json!({ "id": id }));
        assert_eq!(report["all_connected"], false);
        assert_eq!(report["hops"][0]["status"], "failed");
        assert_eq!(
            ipc.err("trust_tested_host_key", json!({ "id": id, "sha256": "SHA256:none" }))["code"],
            "not_found"
        );
        for field in ["hop_index", "hop_id", "host", "port", "error", "elapsed_ms", "host_key"] {
            assert!(report["hops"][0].get(field).is_some(), "missing {field}");
        }

        // Desktop shell.
        assert_eq!(ipc.ok("get_autostart", json!({}))["enabled"], false);
        let autostart = ipc.ok("set_autostart", json!({ "enabled": true }));
        assert_eq!(autostart["enabled"], true);
        assert_eq!(autostart["args"], json!(["--tray"]));
        let shell = ipc.ok("shell_ready", json!({}));
        assert_eq!(shell, json!({ "tray_available": true, "pending": [] }));
        ipc.ok("resolve_close", json!({ "choice": "cancel" }));
        ipc.err("resolve_close", json!({ "choice": "unknown" }));
        assert!(ipc.window.get_webview_window("main").is_some(), "cancel keeps the window");

        // Backup round trip.
        let backup = dir.path().join("backup.bundle");
        let path = backup.to_str().unwrap();
        assert_eq!(ipc.ok("export_backup", json!({ "path": path, "passphrase": BACKUP_PASS }))["key_count"], 3);
        ipc.err("import_backup", json!({ "path": path, "passphrase": PASSWORD }));
        assert_eq!(ipc.ok("import_backup", json!({ "path": path, "passphrase": BACKUP_PASS }))["skipped"], 3);

        // Session-editor helpers.
        let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let held_port = held.local_addr().unwrap().port();
        let ports = ipc.ok(
            "check_port_conflicts",
            json!({ "sessionId": id, "bind": "127.0.0.1", "httpPort": held_port, "socksPort": 0 }),
        );
        assert_eq!(ports["conflicts"][0]["kind"], "os_socket");
        drop(held);
        let filter = ipc.ok(
            "test_filter_rules",
            json!({ "mode": "block", "rules": ["*.example.com"], "target": "api.example.com" }),
        );
        assert_eq!((filter["valid"].clone(), filter["allowed"].clone()), (json!(true), json!(false)));
        let bad_rule = ipc.ok(
            "test_filter_rules",
            json!({ "mode": "allow", "rules": ["10.0.0.0/99"], "target": "x" }),
        );
        assert_eq!(bad_rule["rule_errors"][0]["index"], 0);
        ipc.err("test_filter_rules", json!({ "mode": "other", "rules": [], "target": "x" }));

        // The default program may or may not be installed, so only its name is asserted.
        assert_eq!(ipc.ok("check_openssh_binary", json!({}))["requested"], "ssh");
        assert_eq!(ipc.ok("check_openssh_binary", json!({ "sshBin": "  " }))["requested"], "ssh");
        let missing_bin = dir.path().join("no-such-ssh");
        let missing = ipc.ok("check_openssh_binary", json!({ "sshBin": missing_bin }));
        assert_eq!(missing["supported"], false);
        assert_eq!(missing["resolved_path"], Value::Null);
        assert_eq!(missing["version_raw"], Value::Null);

        // Config export and import, in both forms.
        let plain_export = dir.path().join("config-plain.json");
        let plain_path = plain_export.to_str().unwrap();
        let plain = ipc.ok("export_config", json!({ "path": plain_path }));
        assert_eq!((plain["encrypted"].clone(), plain["secret_count"].clone()), (json!(false), json!(0)));
        let replaced = ipc.ok("import_config", json!({ "path": plain_path, "replaceExisting": true }));
        assert_eq!(replaced["sessions_updated"], 1);
        assert_eq!(replaced["credentials_removed"], 0);

        let bundle_export = dir.path().join("config-bundle.json");
        let bundle_path = bundle_export.to_str().unwrap();
        ipc.err("export_config", json!({ "path": bundle_path, "includeSecrets": true }));
        let sealed = ipc.ok(
            "export_config",
            json!({ "path": bundle_path, "includeSecrets": true, "passphrase": BACKUP_PASS }),
        );
        assert_eq!(sealed["encrypted"], true);
        assert_eq!(sealed["missing_secrets"], 0);
        assert_eq!(sealed["secret_count"], 5, "three keys, one password, one MITM CA");
        assert_eq!(
            ipc.err("import_config", json!({ "path": bundle_path, "passphrase": PASSWORD }))["code"],
            "unlock_failed"
        );
        let restored = ipc.ok("import_config", json!({ "path": bundle_path, "passphrase": BACKUP_PASS }));
        assert_eq!(restored["sessions_skipped"], 1);
        assert_eq!((restored["keys_added"].clone(), restored["secrets_added"].clone()), (json!(0), json!(0)));
        assert_eq!(restored["cas_added"], 0);

        // Deletes, including the referenced-key confirmation contract.
        let refused = ipc.ok("delete_key", json!({ "id": key_id }));
        assert_eq!(refused["deleted"], false);
        assert_eq!(refused["usage"]["hosts"][0]["name"], "h");
        assert_eq!(ipc.ok("delete_key", json!({ "id": key_id, "force": true }))["deleted"], true);
        ipc.ok("delete_key", json!({ "id": protected["id"] }));
        assert_eq!(ipc.ok("delete_secret", json!({ "secret": secret_ref }))["deleted"], false);
        assert_eq!(ipc.ok("delete_secret", json!({ "secret": secret_ref, "force": true }))["deleted"], true);
        ipc.ok("delete_host", json!({ "id": host["id"] }));

        let copy = ipc.ok("duplicate_session", json!({ "id": id }));
        assert!(copy["name"].as_str().unwrap().ends_with(" (copy)"));
        assert_ne!(copy["id"], json!(id));
        ipc.ok("delete_session", json!({ "id": copy["id"] }));
        // Fails closed: the session keeps MITM on with no CA, so it cannot start until one is chosen.
        assert_eq!(ipc.ok("delete_mitm_ca", json!({ "id": ca["id"] }))["deleted"], false);
        assert_eq!(ipc.ok("delete_mitm_ca", json!({ "id": ca["id"], "force": true }))["deleted"], true);
        assert_eq!(ipc.ok("list_mitm_cas", json!({})), json!([]));

        // Read the files before the session is deleted, while they hold the most references.
        let on_disk: Vec<(String, Vec<u8>)> = ["config.json", "vault.bin", "backup.bundle", "config-plain.json", "config-bundle.json"]
            .iter()
            .map(|name| (name.to_string(), std::fs::read(dir.path().join(name)).unwrap()))
            .collect();
        ipc.ok("delete_session", json!({ "id": id }));

        let expected: BTreeSet<String> = ALL_COMMANDS.iter().map(|c| c.to_string()).collect();
        assert_eq!(ipc.called, expected, "every IPC command must be exercised");

        let forbidden = forbidden(&[&plain_pem, &other_pem, &encrypted_pem, &ca_key_pem]);
        for (index, response) in ipc.transcript.iter().enumerate() {
            assert_clean(&format!("IPC response #{index}"), response, &forbidden);
        }
        for (name, bytes) in &on_disk {
            assert_clean(name, &String::from_utf8_lossy(bytes), &forbidden);
        }
    }

    #[test]
    fn secret_input_is_redacted_and_not_serializable() {
        // Compile-time proof: this is ambiguous, so it fails to build, if `SecretInput: Serialize`.
        trait AmbiguousIfSerialize<A> {
            fn probe() {}
        }
        impl<T: ?Sized> AmbiguousIfSerialize<()> for T {}
        impl<T: ?Sized + serde::Serialize> AmbiguousIfSerialize<u8> for T {}
        <SecretInput as AmbiguousIfSerialize<_>>::probe();

        let input: SecretInput = serde_json::from_value(json!(PASSWORD)).unwrap();
        assert!(!format!("{input:?}").contains(PASSWORD));
    }

    #[test]
    fn app_state_is_reachable_from_the_mock_app() {
        let dir = TempDir::new();
        let ipc = Ipc::new(&dir);
        assert!(!ipc.window.state::<AppController>().vault_status().initialized);
    }
}
