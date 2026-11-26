//! U4 import / export: AirSwitch / ZeroOmega / SwitchyOmega `.bak` import, `config.toml`
//! import and export for the three CLIs, and External TOML link mode.
//!
//! Inline passwords found in an imported file go straight into the Vault (the vault must be
//! unlocked) and the Proxy keeps only a [`SecretRef`]. No preview, result, or export ever
//! carries a plaintext secret: exported vaulted passwords become `password_env` references.

use std::path::{Path, PathBuf};

use conduit_core::{
    detect_cli_toml_format, export_cli_toml, import_airswitch_bak, import_cli_toml,
    proxy_referenced_tunnels, CliTomlFormat, CliTomlImport, ExtractedSecret, Proxy, ProxyId,
    RoutingTablesConfig, SecretRef, SourceMode, Tunnel, UpstreamKind, UpstreamPasswordSource,
    UpstreamProfile,
};
use conduit_runtime::{clamp_debounce, read_external_toml};
use conduit_vault::VaultError;
use serde::Serialize;

use super::keys::write_private_file;
use super::proxies::ProxySaveResult;
use super::{secret_ref_from_record, AppController, AppError};

/// One imported upstream profile, as the import preview lists it. No secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportedProfileSummary {
    pub name: String,
    /// `http`, `https`, `socks5`, `socks4a`, `composite`, or `tunnel`.
    pub kind: &'static str,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    /// An inline password was found and will be stored in the Vault on commit.
    pub password_extracted: bool,
    /// `vault`, `env`, or `file` when the profile already names a password source.
    pub password_source: Option<&'static str>,
}

/// What an AirSwitch `.bak` would import. Never carries passwords.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AirSwitchPreview {
    pub suggested_name: String,
    pub profile_count: usize,
    pub rule_count: usize,
    pub extracted_password_count: usize,
    pub warnings: Vec<String>,
    pub profiles: Vec<ImportedProfileSummary>,
}

/// What committing an AirSwitch import saved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AirSwitchCommitResult {
    pub proxy: Proxy,
    pub warnings: Vec<String>,
    /// Passwords stored in the Vault.
    pub stored_passwords: usize,
}

/// What a `config.toml` would import. Never carries passwords.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TomlImportPreview {
    pub format: CliTomlFormat,
    /// `format` was detected from the file, not given.
    pub detected: bool,
    pub proxy_name: Option<String>,
    /// The Tunnel a `rusty-conduit-ssh` file creates.
    pub tunnel_name: Option<String>,
    pub profile_count: usize,
    pub rule_count: usize,
    pub extracted_password_count: usize,
    pub warnings: Vec<String>,
    /// What must be completed by hand after import.
    pub notes: Vec<String>,
    pub profiles: Vec<ImportedProfileSummary>,
}

/// What committing a `config.toml` import saved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TomlImportCommitResult {
    pub format: CliTomlFormat,
    pub proxy: Option<Proxy>,
    pub tunnel: Option<Tunnel>,
    pub warnings: Vec<String>,
    pub notes: Vec<String>,
    /// Passwords stored in the Vault.
    pub stored_passwords: usize,
}

/// An exported `config.toml`. `toml` never contains a plaintext secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TomlExportResult {
    pub format: CliTomlFormat,
    pub toml: String,
    pub notes: Vec<String>,
    /// Where it was written (owner-only), when a path was given.
    pub path: Option<PathBuf>,
}

fn kind_label(kind: &UpstreamKind) -> &'static str {
    match kind {
        UpstreamKind::Http => "http",
        UpstreamKind::Https { .. } => "https",
        UpstreamKind::Socks5 => "socks5",
        UpstreamKind::Socks4a => "socks4a",
        UpstreamKind::Composite { .. } => "composite",
        UpstreamKind::Tunnel { .. } => "tunnel",
    }
}

fn summarize(profiles: &[UpstreamProfile], secrets: &[ExtractedSecret]) -> Vec<ImportedProfileSummary> {
    profiles
        .iter()
        .map(|p| ImportedProfileSummary {
            name: p.name.clone(),
            kind: kind_label(&p.kind),
            host: p.host.clone(),
            port: p.port,
            username: p.username.clone(),
            password_extracted: secrets.iter().any(|s| s.profile_name == p.name),
            password_source: p.password.as_ref().map(|s| match s {
                UpstreamPasswordSource::Vault(_) => "vault",
                UpstreamPasswordSource::Env(_) => "env",
                UpstreamPasswordSource::File(_) => "file",
            }),
        })
        .collect()
}

/// Rules across the unified table and the split overrides.
fn rule_count(routing: &RoutingTablesConfig) -> usize {
    routing.rules.len()
        + routing.http.as_ref().map_or(0, |t| t.rules.len())
        + routing.socks.as_ref().map_or(0, |t| t.rules.len())
}

fn read_text(path: &Path) -> Result<String, AppError> {
    std::fs::read_to_string(path)
        .map_err(|e| AppError::Io(format!("cannot read {}: {e}", path.display())))
}

fn invalid(error: impl ToString) -> AppError {
    AppError::Invalid(error.to_string())
}

/// The name an imported `config.toml` gets when none is given.
fn default_toml_name(format: CliTomlFormat) -> String {
    format!("{} import", format.cli_name())
}

/// A parsed `config.toml`, normalized across the three CLIs.
struct ParsedToml {
    format: CliTomlFormat,
    detected: bool,
    proxy: Option<Proxy>,
    tunnel: Option<Tunnel>,
    secrets: Vec<ExtractedSecret>,
    warnings: Vec<String>,
    notes: Vec<String>,
}

fn parse_toml(path: &Path, format: Option<CliTomlFormat>, name: Option<&str>) -> Result<ParsedToml, AppError> {
    let text = read_text(path)?;
    let detected = format.is_none();
    let format = format.unwrap_or_else(|| detect_cli_toml_format(&text));
    let name = name
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| default_toml_name(format));
    let parsed = match import_cli_toml(&text, format, &name).map_err(invalid)? {
        CliTomlImport::RustyConduit(out) => ParsedToml {
            format,
            detected,
            proxy: Some(out.proxy),
            tunnel: None,
            secrets: Vec::new(),
            warnings: out.warnings,
            notes: Vec::new(),
        },
        CliTomlImport::RustyConduitSsh(out) => ParsedToml {
            format,
            detected,
            proxy: out.proxy,
            tunnel: Some(out.tunnel),
            secrets: Vec::new(),
            warnings: out.warnings,
            notes: out.notes,
        },
        CliTomlImport::RustyConduitSwitch(out) => ParsedToml {
            format,
            detected,
            proxy: Some(out.proxy),
            tunnel: None,
            secrets: out.extracted_secrets,
            warnings: out.warnings,
            notes: Vec::new(),
        },
    };
    Ok(parsed)
}

impl AppController {
    /// Stores every extracted password in the Vault and points its profile at the record.
    /// Refuses with [`VaultError::Locked`] before storing anything when the vault is locked.
    /// Returns the record ids written, for rollback.
    fn vault_extracted(
        &self,
        proxy: &mut Proxy,
        secrets: Vec<ExtractedSecret>,
    ) -> Result<Vec<String>, AppError> {
        if secrets.is_empty() {
            return Ok(Vec::new());
        }
        let mut vault = self.vault_write();
        if !vault.is_unlocked() {
            return Err(AppError::Vault(VaultError::Locked));
        }
        let mut stored: Vec<String> = Vec::new();
        for secret in secrets {
            let Some(profile) = proxy.profiles.iter_mut().find(|p| p.name == secret.profile_name) else {
                continue;
            };
            let id = match vault.put_upstream_password(secret.password.as_bytes()) {
                Ok(id) => id,
                Err(error) => {
                    for id in &stored {
                        let _ = vault.delete_secret(id);
                    }
                    return Err(error.into());
                }
            };
            let secret_ref: SecretRef = secret_ref_from_record(&id)?;
            profile.password = Some(UpstreamPasswordSource::Vault(secret_ref));
            stored.push(id);
        }
        Ok(stored)
    }

    /// Deletes vault records written by a commit that then failed.
    fn rollback_vaulted(&self, ids: &[String]) {
        if ids.is_empty() {
            return;
        }
        let mut vault = self.vault_write();
        for id in ids {
            let _ = vault.delete_secret(id);
        }
    }

    // -----------------------------------------------------------------------------------------
    // AirSwitch / ZeroOmega / SwitchyOmega `.bak`.
    // -----------------------------------------------------------------------------------------

    pub fn preview_airswitch_import(&self, path: &Path) -> Result<AirSwitchPreview, AppError> {
        let out = import_airswitch_bak(&read_text(path)?, None).map_err(invalid)?;
        Ok(AirSwitchPreview {
            suggested_name: out.proxy.name.clone(),
            profile_count: out.profile_count,
            rule_count: rule_count(&out.proxy.routing),
            extracted_password_count: out.extracted_secrets.len(),
            profiles: summarize(&out.proxy.profiles, &out.extracted_secrets),
            warnings: out.warnings,
        })
    }

    /// Imports a `.bak` as a new Proxy, or replaces the profiles and routing of
    /// `target_proxy_id` (its listeners, MITM, logging, and filter stay). Extracted passwords
    /// are vaulted; a locked vault is refused before anything is saved.
    pub async fn commit_airswitch_import(
        &self,
        path: PathBuf,
        proxy_name: Option<String>,
        target_proxy_id: Option<ProxyId>,
    ) -> Result<AirSwitchCommitResult, AppError> {
        let out = super::run_blocking(move || {
            import_airswitch_bak(&read_text(&path)?, None).map_err(invalid)
        })
        .await?;
        let mut proxy = match target_proxy_id {
            Some(id) => {
                let mut existing = self.proxy_profile(id)?;
                existing.profiles = out.proxy.profiles;
                existing.routing = out.proxy.routing;
                existing
            }
            None => Proxy { id: ProxyId::new(), ..out.proxy },
        };
        if let Some(name) = proxy_name.filter(|n| !n.trim().is_empty()) {
            proxy.name = name;
        }
        let controller = self.clone();
        let secrets = out.extracted_secrets;
        let (proxy, stored) = super::run_blocking(move || {
            let stored = controller.vault_extracted(&mut proxy, secrets)?;
            Ok((proxy, stored))
        })
        .await?;
        let saved = match self.upsert_proxy(proxy).await {
            Ok(saved) => saved,
            Err(error) => {
                self.rollback_vaulted(&stored);
                return Err(error);
            }
        };
        Ok(AirSwitchCommitResult {
            proxy: saved.profile,
            warnings: out.warnings,
            stored_passwords: stored.len(),
        })
    }

    // -----------------------------------------------------------------------------------------
    // CLI `config.toml`.
    // -----------------------------------------------------------------------------------------

    /// What `path` would import. `format` is detected when `None`.
    pub fn preview_toml_import(
        &self,
        path: &Path,
        format: Option<CliTomlFormat>,
    ) -> Result<TomlImportPreview, AppError> {
        let parsed = parse_toml(path, format, None)?;
        let (profiles, rules) = parsed.proxy.as_ref().map_or((Vec::new(), 0), |p| {
            (summarize(&p.profiles, &parsed.secrets), rule_count(&p.routing))
        });
        Ok(TomlImportPreview {
            format: parsed.format,
            detected: parsed.detected,
            proxy_name: parsed.proxy.as_ref().map(|p| p.name.clone()),
            tunnel_name: parsed.tunnel.as_ref().map(|t| t.name.clone()),
            profile_count: profiles.len(),
            rule_count: rules,
            extracted_password_count: parsed.secrets.len(),
            warnings: parsed.warnings,
            notes: parsed.notes,
            profiles,
        })
    }

    /// Imports `path`: vaults extracted passwords, saves the Tunnel (for `rusty-conduit-ssh`)
    /// and then the Proxy, pointed at the saved Tunnel.
    pub async fn commit_toml_import(
        &self,
        path: PathBuf,
        format: Option<CliTomlFormat>,
        name: Option<String>,
    ) -> Result<TomlImportCommitResult, AppError> {
        let parsed = super::run_blocking(move || parse_toml(&path, format, name.as_deref())).await?;
        let ParsedToml { format, proxy, tunnel, secrets, warnings, notes, .. } = parsed;
        let Some(mut proxy) = proxy else {
            let tunnel = match tunnel {
                Some(tunnel) => Some(self.upsert_tunnel(tunnel)?),
                None => None,
            };
            return Ok(TomlImportCommitResult {
                format,
                proxy: None,
                tunnel,
                warnings,
                notes,
                stored_passwords: 0,
            });
        };
        proxy.id = ProxyId::new();

        let controller = self.clone();
        let (mut proxy, stored) = super::run_blocking(move || {
            let stored = controller.vault_extracted(&mut proxy, secrets)?;
            Ok((proxy, stored))
        })
        .await?;

        let saved_tunnel = match tunnel {
            Some(tunnel) => {
                let imported_id = tunnel.id;
                match self.upsert_tunnel(tunnel) {
                    Ok(saved) => {
                        for profile in &mut proxy.profiles {
                            if let UpstreamKind::Tunnel { tunnel_id } = &mut profile.kind {
                                if *tunnel_id == imported_id {
                                    *tunnel_id = saved.id;
                                }
                            }
                        }
                        Some(saved)
                    }
                    Err(error) => {
                        self.rollback_vaulted(&stored);
                        return Err(error);
                    }
                }
            }
            None => None,
        };

        let saved = match self.upsert_proxy(proxy).await {
            Ok(saved) => saved,
            Err(error) => {
                self.rollback_vaulted(&stored);
                if let Some(tunnel) = &saved_tunnel {
                    let _ = self.delete_tunnel(tunnel.id, true).await;
                }
                return Err(error);
            }
        };
        Ok(TomlImportCommitResult {
            format,
            proxy: Some(saved.profile),
            tunnel: saved_tunnel,
            warnings,
            notes,
            stored_passwords: stored.len(),
        })
    }

    /// Exports a saved Proxy as a `config.toml`, writing it owner-only to `path` when given.
    pub fn export_proxy_toml(
        &self,
        proxy_id: ProxyId,
        format: CliTomlFormat,
        path: Option<PathBuf>,
    ) -> Result<TomlExportResult, AppError> {
        let config = self.config_snapshot();
        let proxy = config
            .proxies
            .iter()
            .find(|p| p.id == proxy_id)
            .ok_or_else(|| AppError::NotFound { kind: "proxy", id: proxy_id.to_string() })?;
        let referenced = proxy_referenced_tunnels(proxy);
        let tunnels: Vec<Tunnel> = config
            .tunnels
            .iter()
            .filter(|t| referenced.contains(&t.id))
            .cloned()
            .collect();
        let export = export_cli_toml(format, proxy, &tunnels).map_err(invalid)?;
        if let Some(path) = &path {
            write_private_file(path, export.toml.as_bytes())?;
        }
        Ok(TomlExportResult { format, toml: export.toml, notes: export.notes, path })
    }

    // -----------------------------------------------------------------------------------------
    // External TOML link mode.
    // -----------------------------------------------------------------------------------------

    /// Links a Proxy to a `rusty-conduit-switch` file: it must parse now; its settings are
    /// applied and the running Proxy then follows the file.
    pub async fn link_proxy_external_toml(
        &self,
        proxy_id: ProxyId,
        path: PathBuf,
        debounce_ms: u64,
    ) -> Result<ProxySaveResult, AppError> {
        let current = self.proxy_profile(proxy_id)?;
        let debounce_ms = u64::try_from(clamp_debounce(debounce_ms).as_millis()).unwrap_or(u64::MAX);
        let read_path = path.clone();
        let mut proxy = super::run_blocking(move || {
            read_external_toml(&current, &read_path).map(|m| m.proxy).map_err(AppError::Invalid)
        })
        .await?;
        proxy.source = SourceMode::ExternalToml { path, debounce_ms };
        self.upsert_proxy(proxy).await
    }

    /// Returns a Proxy to Managed mode, keeping its current settings; its watcher stops.
    pub async fn unlink_proxy_external_toml(&self, proxy_id: ProxyId) -> Result<ProxySaveResult, AppError> {
        let mut proxy = self.proxy_profile(proxy_id)?;
        proxy.source = SourceMode::Managed;
        self.upsert_proxy(proxy).await
    }

    /// Reads the linked file now and applies it (saved, and hot-reloaded when running).
    pub async fn reload_proxy_external_toml(&self, proxy_id: ProxyId) -> Result<ProxySaveResult, AppError> {
        let current = self.proxy_profile(proxy_id)?;
        let SourceMode::ExternalToml { path, .. } = current.source.clone() else {
            return Err(AppError::Invalid("this proxy is not linked to an external TOML file".into()));
        };
        let proxy = super::run_blocking(move || {
            read_external_toml(&current, &path).map(|m| m.proxy).map_err(AppError::Invalid)
        })
        .await?;
        self.upsert_proxy(proxy).await
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::*;
    use conduit_core::RouteOneOrMany;
    use serde_json::json;
    use std::time::Duration;

    const AIR_SECRET: &str = "airswitch-canary-hunter2";
    const SWITCH_SECRET: &str = "switch-canary-s3cret";

    fn bak() -> String {
        json!({
            "-startupProfileName": "auto switch",
            "+Work Proxy": {
                "profileType": "FixedProfile",
                "fallbackProxy": { "scheme": "http", "host": "proxy.corp.example", "port": 3128 },
                "auth": { "fallbackProxy": { "username": "alice", "password": AIR_SECRET } }
            },
            "+auto switch": {
                "profileType": "SwitchProfile",
                "defaultProfileName": "direct",
                "rules": [
                    { "condition": { "conditionType": "HostWildcardCondition", "pattern": "*.corp.example" },
                      "profileName": "Work Proxy" }
                ]
            }
        })
        .to_string()
    }

    fn switch_toml(port: u16) -> String {
        format!(
            "bind = \"127.0.0.1\"\nhttp_port = {port}\nsocks_port = 0\n\n\
             [profiles.corp]\ntype = \"http\"\nhost = \"10.0.0.2\"\nport = 3128\n\
             username = \"alice\"\npassword = \"{SWITCH_SECRET}\"\n\n\
             [routing]\ndefault = \"direct\"\n\n\
             [[routing.rules]]\nhost_wildcard = \"*.corp.example\"\ntarget = \"corp\"\n"
        )
    }

    const CONDUIT_TOML: &str = "http_port = 8181\nsocks_port = 1191\nblock = [\"*.ads.example\"]\n";

    const SSH_TOML: &str = "http_port = 3139\nsocks_port = 0\n\n[ssh]\ntarget = \"alice@bastion.example\"\nport = 2222\n";

    fn write(dir: &TempDir, name: &str, text: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, text).unwrap();
        path
    }

    fn vault_password(c: &AppController, proxy: &Proxy, profile: &str) -> String {
        let p = proxy.profiles.iter().find(|p| p.name == profile).unwrap();
        let Some(UpstreamPasswordSource::Vault(secret)) = &p.password else {
            panic!("profile {profile} is not vaulted: {:?}", p.password);
        };
        let bytes = c.vault_read().get_upstream_password(&secret.to_string()).unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn airswitch_preview_hides_passwords_and_commit_vaults_them() {
        let dir = TempDir::new();
        let files = TempDir::new();
        let path = write(&files, "switchy.bak", &bak());
        let c = controller(&dir);

        let preview = c.preview_airswitch_import(&path).unwrap();
        assert_eq!(preview.suggested_name, "auto switch");
        assert_eq!((preview.profile_count, preview.rule_count), (1, 1));
        assert_eq!(preview.extracted_password_count, 1);
        assert!(preview.profiles[0].password_extracted);
        assert!(!serde_json::to_string(&preview).unwrap().contains(AIR_SECRET));

        // A locked (here: never created) vault refuses before anything is saved.
        let error = c.commit_airswitch_import(path.clone(), None, None).await.unwrap_err();
        assert!(matches!(error, AppError::Vault(VaultError::Locked)), "{error:?}");
        assert!(c.config_snapshot().proxies.is_empty());

        let c = unlocked(&dir).await;
        let out = c.commit_airswitch_import(path.clone(), Some("Work".into()), None).await.unwrap();
        assert_eq!(out.stored_passwords, 1);
        assert_eq!(out.proxy.name, "Work");
        assert_eq!(vault_password(&c, &out.proxy, "work_proxy"), AIR_SECRET);
        assert!(!serde_json::to_string(&out).unwrap().contains(AIR_SECRET));
        let saved = c.config_snapshot();
        assert_eq!(saved.proxies.len(), 1);
        assert!(!serde_json::to_string(&saved).unwrap().contains(AIR_SECRET));
        assert!(c.proxies().snapshot(out.proxy.id).is_ok());

        // Updating an existing Proxy keeps its id and listeners.
        let mut existing = out.proxy.clone();
        existing.listeners.http_port = 4321;
        c.upsert_proxy(existing).await.unwrap();
        let again = c.commit_airswitch_import(path, None, Some(out.proxy.id)).await.unwrap();
        assert_eq!(again.proxy.id, out.proxy.id);
        assert_eq!(again.proxy.name, "Work");
        assert_eq!(again.proxy.listeners.http_port, 4321);
        assert_eq!(c.config_snapshot().proxies.len(), 1);
    }

    #[tokio::test]
    async fn switch_toml_import_vaults_inline_passwords_and_exports_env_refs() {
        let dir = TempDir::new();
        let files = TempDir::new();
        let path = write(&files, "switch.toml", &switch_toml(3901));
        let c = unlocked(&dir).await;

        let preview = c.preview_toml_import(&path, None).unwrap();
        assert_eq!(preview.format, CliTomlFormat::RustyConduitSwitch);
        assert!(preview.detected);
        assert_eq!((preview.profile_count, preview.rule_count, preview.extracted_password_count), (1, 1, 1));
        assert!(!serde_json::to_string(&preview).unwrap().contains(SWITCH_SECRET));

        let out = c.commit_toml_import(path, None, Some("switchy".into())).await.unwrap();
        let proxy = out.proxy.clone().unwrap();
        assert_eq!(proxy.name, "switchy");
        assert_eq!(out.stored_passwords, 1);
        assert_eq!(vault_password(&c, &proxy, "corp"), SWITCH_SECRET);
        assert!(!serde_json::to_string(&c.config_snapshot()).unwrap().contains(SWITCH_SECRET));

        let target = files.path().join("out.toml");
        let export = c
            .export_proxy_toml(proxy.id, CliTomlFormat::RustyConduitSwitch, Some(target.clone()))
            .unwrap();
        assert!(!export.toml.contains(SWITCH_SECRET));
        assert!(export.toml.contains("password_env"), "{}", export.toml);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), export.toml);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&target).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // A Proxy with rules is not a `rusty-conduit` file.
        assert!(matches!(
            c.export_proxy_toml(proxy.id, CliTomlFormat::RustyConduit, None),
            Err(AppError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn switch_toml_with_passwords_needs_an_unlocked_vault() {
        let dir = TempDir::new();
        let files = TempDir::new();
        let path = write(&files, "switch.toml", &switch_toml(3902));
        let c = controller(&dir);
        let error = c.commit_toml_import(path, None, None).await.unwrap_err();
        assert!(matches!(error, AppError::Vault(VaultError::Locked)), "{error:?}");
        assert!(c.config_snapshot().proxies.is_empty());
    }

    #[tokio::test]
    async fn conduit_toml_round_trips() {
        let dir = TempDir::new();
        let files = TempDir::new();
        let path = write(&files, "conduit.toml", CONDUIT_TOML);
        let c = controller(&dir);

        let preview = c.preview_toml_import(&path, None).unwrap();
        assert_eq!(preview.format, CliTomlFormat::RustyConduit);
        assert_eq!(preview.proxy_name.as_deref(), Some("rusty-conduit import"));
        let out = c.commit_toml_import(path, None, None).await.unwrap();
        let proxy = out.proxy.unwrap();
        assert_eq!((proxy.listeners.http_port, proxy.listeners.socks_port), (8181, 1191));
        assert!(out.tunnel.is_none());

        let export = c.export_proxy_toml(proxy.id, CliTomlFormat::RustyConduit, None).unwrap();
        assert!(export.toml.contains("http_port = 8181"), "{}", export.toml);
        assert!(export.path.is_none());
    }

    #[tokio::test]
    async fn ssh_toml_creates_a_tunnel_and_a_proxy_routed_to_it() {
        let dir = TempDir::new();
        let files = TempDir::new();
        let path = write(&files, "ssh.toml", SSH_TOML);
        let c = controller(&dir);

        let preview = c.preview_toml_import(&path, None).unwrap();
        assert_eq!(preview.format, CliTomlFormat::RustyConduitSsh);
        assert_eq!(preview.tunnel_name.as_deref(), Some("rusty-conduit-ssh import"));

        let out = c
            .commit_toml_import(path, Some(CliTomlFormat::RustyConduitSsh), Some("bastion".into()))
            .await
            .unwrap();
        let tunnel = out.tunnel.unwrap();
        let proxy = out.proxy.unwrap();
        let config = c.config_snapshot();
        assert!(config.tunnels.iter().any(|t| t.id == tunnel.id));
        assert!(proxy
            .profiles
            .iter()
            .any(|p| p.kind == UpstreamKind::Tunnel { tunnel_id: tunnel.id }));

        let export = c.export_proxy_toml(proxy.id, CliTomlFormat::RustyConduitSsh, None).unwrap();
        assert!(export.toml.contains("[ssh]"), "{}", export.toml);
    }

    #[tokio::test]
    async fn bad_files_are_reported() {
        let dir = TempDir::new();
        let files = TempDir::new();
        let c = controller(&dir);
        let missing = files.path().join("nope.toml");
        assert!(matches!(c.preview_toml_import(&missing, None), Err(AppError::Io(_))));
        let garbage = write(&files, "bad.bak", "not a backup");
        assert!(matches!(c.preview_airswitch_import(&garbage), Err(AppError::Invalid(_))));
        let bad = write(&files, "bad.toml", "[profiles.x]\ntype = \"warp\"\n");
        assert!(matches!(
            c.preview_toml_import(&bad, Some(CliTomlFormat::RustyConduitSwitch)),
            Err(AppError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn external_toml_link_reload_and_unlink() {
        let dir = TempDir::new();
        let files = TempDir::new();
        let c = unlocked(&dir).await;
        let path = write(&files, "linked.toml", &switch_toml(3903));
        // Import first, so `corp` has a vaulted password the link keeps.
        let imported = c.commit_toml_import(path.clone(), None, Some("linked".into())).await.unwrap();
        let proxy = imported.proxy.unwrap();
        let id = proxy.id;

        // Bad files are refused and change nothing.
        let bad = write(&files, "bad.toml", "http_port = [\n");
        assert!(matches!(
            c.link_proxy_external_toml(id, bad, 500).await,
            Err(AppError::Invalid(_))
        ));
        assert_eq!(c.proxy_profile(id).unwrap().source, SourceMode::Managed);
        assert!(matches!(c.reload_proxy_external_toml(id).await, Err(AppError::Invalid(_))));

        let linked = c.link_proxy_external_toml(id, path.clone(), 1).await.unwrap();
        assert_eq!(
            linked.profile.source,
            SourceMode::ExternalToml { path: path.clone(), debounce_ms: 250 }
        );
        assert_eq!(vault_password(&c, &linked.profile, "corp"), SWITCH_SECRET);

        // Reload picks up the edited file now.
        let edited = switch_toml(3903).replace("*.corp.example", "*.other.example");
        std::fs::write(&path, edited).unwrap();
        let reloaded = c.reload_proxy_external_toml(id).await.unwrap();
        assert_eq!(
            reloaded.profile.routing.rules[0].host_wildcard,
            Some(RouteOneOrMany::One("*.other.example".into()))
        );
        assert_eq!(vault_password(&c, &reloaded.profile, "corp"), SWITCH_SECRET);
        assert_eq!(c.proxy_profile(id).unwrap(), reloaded.profile);

        // Running and linked: the watcher hot-reloads edits.
        c.start_proxy(id).await.unwrap();
        let generation = c.proxies().snapshot(id).unwrap().config_generation;
        let edited = switch_toml(3903).replace("*.corp.example", "*.third.example");
        std::fs::write(&path, edited).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while c.proxies().snapshot(id).unwrap().config_generation == generation {
            assert!(std::time::Instant::now() < deadline, "the watcher did not reload");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let unlinked = c.unlink_proxy_external_toml(id).await.unwrap();
        assert_eq!(unlinked.profile.source, SourceMode::Managed);
        assert_eq!(c.proxy_profile(id).unwrap().source, SourceMode::Managed);
        assert!(matches!(c.reload_proxy_external_toml(id).await, Err(AppError::Invalid(_))));
        c.stop_proxy(id).await.unwrap();
        assert!(!serde_json::to_string(&c.config_snapshot()).unwrap().contains(SWITCH_SECRET));
    }
}
