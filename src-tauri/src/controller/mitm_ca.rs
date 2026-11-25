//! MITM CA vault operations: upload, list, rename, and delete.
//!
//! An uploaded CA is read once, decrypted with its passphrase, checked with the engine's own
//! loader, and stored in the vault as normalized PEM: the certificate chain, then the private
//! key as unencrypted PKCS#8. The vault's encryption protects it from then on, so neither the
//! files it came from nor their passphrase are needed again.

use std::fmt;

use base64::Engine as _;
use conduit_core::{AppConfig, MitmCaId, Timestamp, VaultCaMeta};
use conduit_vault::VaultError;
use rusty_conduit_ssh::mitm::ca::{CaError, CaMaterial};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::keys::{require_name, DeleteResult, Usage, UsageRef};
use super::{run_blocking, usage_is_empty, AppController, AppError, SecretInput};

pub(crate) const MITM_CA_RECORD: &str = "mitm_ca";
/// Larger than any real CA bundle, small enough to refuse a wrong file quickly.
const MAX_UPLOAD_BYTES: usize = 1024 * 1024;

/// A CA as the WebView sends it: file contents, never paths.
#[derive(Deserialize)]
#[serde(tag = "format", rename_all = "lowercase")]
pub enum MitmCaUpload {
    /// PEM certificate (or chain) and PEM private key, as text.
    Pem { cert: String, key: SecretInput },
    /// A PKCS#12 bundle, base64-encoded.
    Pkcs12 { data: SecretInput },
}

impl fmt::Debug for MitmCaUpload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pem { .. } => "MitmCaUpload::Pem(<redacted>)",
            Self::Pkcs12 { .. } => "MitmCaUpload::Pkcs12(<redacted>)",
        })
    }
}

/// A vault CA with its "Used by N" indicator. Contains no key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaView {
    #[serde(flatten)]
    pub meta: VaultCaMeta,
    pub used_by: usize,
    pub usage: Usage,
}

/// Public facts read from a CA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CaFacts {
    pub subject: String,
    pub not_after: Timestamp,
    pub fingerprint_sha256: String,
}

fn unusable(error: CaError) -> AppError {
    AppError::Invalid(format!("this CA cannot be used: {error}"))
}

fn too_large() -> AppError {
    AppError::Invalid("that file is too large to be a CA".into())
}

/// `SHA256:<base64>`, the same form as key fingerprints.
fn fingerprint(der: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    format!("SHA256:{}", base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest))
}

fn facts(ca: &CaMaterial) -> CaFacts {
    CaFacts {
        subject: ca.subject().to_owned(),
        not_after: Timestamp(ca.not_after().unix_timestamp()),
        fingerprint_sha256: fingerprint(ca.cert().as_ref()),
    }
}

/// One PEM block with LF line endings. Zeroized on drop, since it may hold a private key.
fn pem_block(label: &str, der: &[u8]) -> Zeroizing<String> {
    let body = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(der));
    let mut out = Zeroizing::new(String::with_capacity(body.len() + body.len() / 64 + 64));
    out.push_str(&format!("-----BEGIN {label}-----\n"));
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// Decrypts an upload, checks the engine would accept it now, and returns it as normalized PEM.
pub(crate) fn normalize(
    upload: &MitmCaUpload,
    passphrase: Option<&str>,
) -> Result<(Zeroizing<String>, CaFacts), AppError> {
    let ca = match upload {
        MitmCaUpload::Pem { cert, key } => {
            if cert.len() + key.as_str().len() > MAX_UPLOAD_BYTES {
                return Err(too_large());
            }
            CaMaterial::from_pem(cert.as_bytes(), key.as_bytes(), passphrase)
        }
        MitmCaUpload::Pkcs12 { data } => {
            if data.as_str().len() > MAX_UPLOAD_BYTES * 4 / 3 + 4 {
                return Err(too_large());
            }
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(data.as_str().trim())
                .map(Zeroizing::new)
                .map_err(|_| AppError::Invalid("the PKCS#12 file could not be read".into()))?;
            CaMaterial::from_pkcs12(&bytes, passphrase)
        }
    }
    .map_err(unusable)?
    .validate()
    .map_err(unusable)?;

    let key = ca.key_pair().map_err(unusable)?;
    // Written here rather than by `serialize_pem`, which uses CRLF on Windows: the stored PEM
    // has the same LF line endings on every platform.
    let key_der = Zeroizing::new(key.serialize_der());
    let key_pem = pem_block("PRIVATE KEY", &key_der);
    let mut pem = Zeroizing::new(String::new());
    for cert in ca.chain() {
        pem.push_str(&pem_block("CERTIFICATE", cert.as_ref()));
    }
    pem.push_str(&key_pem);
    Ok((pem, facts(&ca)))
}

/// Reads the facts of a stored (normalized) CA. An expired CA is still read.
pub(crate) fn stored_facts(pem: &[u8]) -> Result<CaFacts, AppError> {
    CaMaterial::from_pem(pem, pem, None).map(|ca| facts(&ca)).map_err(unusable)
}

pub(crate) fn ca_usage(config: &AppConfig, id: &MitmCaId) -> Usage {
    let sessions = config
        .sessions
        .iter()
        .filter(|s| s.mitm.as_ref().and_then(|m| m.ca.as_ref()) == Some(id))
        .map(|s| UsageRef { id: s.id, name: s.name.clone() })
        .collect();
    Usage { hosts: Vec::new(), sessions }
}

pub(crate) fn ca_id_from_record(id: &str) -> Result<MitmCaId, AppError> {
    serde_json::from_value(serde_json::Value::String(id.to_owned()))
        .map_err(|e| AppError::Invalid(format!("invalid CA id: {e}")))
}

impl AppController {
    /// Validates, decrypts if needed, and vaults an uploaded MITM CA.
    pub fn import_mitm_ca(
        &self,
        name: &str,
        upload: MitmCaUpload,
        passphrase: Option<SecretInput>,
    ) -> Result<VaultCaMeta, AppError> {
        let name = require_name(name)?;
        if !self.vault_read().is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        let passphrase = passphrase.filter(|p| !p.as_str().is_empty());
        let (pem, facts) = normalize(&upload, passphrase.as_ref().map(SecretInput::as_str))?;
        drop(upload);
        self.store_ca(name, &pem, facts, Timestamp::now())
    }

    /// Stores a normalized CA and records its metadata. Rolls the vault back if saving fails.
    pub(crate) fn store_ca(
        &self,
        name: String,
        pem: &str,
        facts: CaFacts,
        created_at: Timestamp,
    ) -> Result<VaultCaMeta, AppError> {
        let duplicate = self
            .config_snapshot()
            .mitm_cas
            .iter()
            .any(|c| c.fingerprint_sha256 == facts.fingerprint_sha256);
        if duplicate {
            return Err(AppError::DuplicateCa { fingerprint: facts.fingerprint_sha256 });
        }
        let record = self.vault_write().put_secret(MITM_CA_RECORD, pem.as_bytes())?;
        let meta = VaultCaMeta {
            id: ca_id_from_record(&record)?,
            name,
            subject: facts.subject,
            not_after: facts.not_after,
            fingerprint_sha256: facts.fingerprint_sha256,
            created_at,
        };
        let stored = meta.clone();
        if let Err(error) = self.mutate_config(move |config| {
            config.mitm_cas.push(stored);
            Ok(())
        }) {
            let _ = self.vault_write().delete_secret(&record);
            return Err(error);
        }
        Ok(meta)
    }

    pub fn list_mitm_cas(&self) -> Vec<CaView> {
        let config = self.config_snapshot();
        config
            .mitm_cas
            .iter()
            .map(|meta| {
                let usage = ca_usage(&config, &meta.id);
                CaView { meta: meta.clone(), used_by: usage.sessions.len(), usage }
            })
            .collect()
    }

    pub fn rename_mitm_ca(&self, id: &MitmCaId, name: &str) -> Result<VaultCaMeta, AppError> {
        let name = require_name(name)?;
        self.mutate_config(|config| {
            let ca = config
                .mitm_cas
                .iter_mut()
                .find(|c| c.id == *id)
                .ok_or_else(|| AppError::NotFound { kind: "MITM CA", id: id.to_string() })?;
            ca.name = name;
            Ok(ca.clone())
        })
    }

    /// Deletes a CA. If a session uses it and `force` is false, nothing changes and the
    /// sessions are returned. With `force`, those sessions are left with MITM on and no CA, and
    /// any that are running are stopped, because a running session holds the CA in memory and
    /// would otherwise keep signing with it. They cannot start again until a CA is chosen or
    /// MITM is turned off.
    pub async fn delete_mitm_ca(&self, id: &MitmCaId, force: bool) -> Result<DeleteResult, AppError> {
        let controller = self.clone();
        let ca = id.clone();
        let outcome = run_blocking(move || controller.detach_mitm_ca(&ca, force)).await?;
        if !outcome.deleted {
            return Ok(outcome);
        }
        for session in &outcome.usage.sessions {
            match self.manager().stop(session.id).await {
                Ok(()) | Err(conduit_runtime::RuntimeError::UnknownSession(_)) => {}
                Err(error) => return Err(error.into()),
            }
        }
        let controller = self.clone();
        let record = id.to_string();
        run_blocking(move || match controller.vault_write().delete_secret(&record) {
            Ok(()) | Err(VaultError::SecretNotFound { .. }) => Ok(()),
            Err(error) => Err(error.into()),
        })
        .await?;
        Ok(outcome)
    }

    /// The config half of [`Self::delete_mitm_ca`]: drops the CA and every reference to it.
    fn detach_mitm_ca(&self, id: &MitmCaId, force: bool) -> Result<DeleteResult, AppError> {
        let config = self.config_snapshot();
        if !config.mitm_cas.iter().any(|c| c.id == *id) {
            return Err(AppError::NotFound { kind: "MITM CA", id: id.to_string() });
        }
        let usage = ca_usage(&config, id);
        let used_by = usage.sessions.len();
        if !usage_is_empty(&usage) && !force {
            return Ok(DeleteResult { deleted: false, used_by, usage });
        }
        if !self.vault_read().is_unlocked() {
            return Err(VaultError::Locked.into());
        }
        let changed = self.mutate_config(|config| {
            config.mitm_cas.retain(|c| c.id != *id);
            let mut changed = Vec::new();
            for session in &mut config.sessions {
                if let Some(mitm) = session.mitm.as_mut().filter(|m| m.ca.as_ref() == Some(id)) {
                    mitm.ca = None;
                    changed.push(session.clone());
                }
            }
            Ok(changed)
        })?;
        self.sync_profiles(changed);
        Ok(DeleteResult { deleted: true, used_by, usage })
    }
}

#[cfg(test)]
pub(crate) mod test_ca {
    //! CA fixtures shared by the controller tests.

    use p12_keystore::{Certificate, KeyStore, KeyStoreEntry, PrivateKey, PrivateKeyChain};
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
    use time::{Duration, OffsetDateTime};

    pub struct TestCa {
        pub cert_pem: String,
        pub key_pem: String,
        pub cert_der: Vec<u8>,
        pub key_der: Vec<u8>,
    }

    pub fn ca_with(common_name: &str, not_before: OffsetDateTime, not_after: OffsetDateTime) -> TestCa {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, common_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = not_before;
        params.not_after = not_after;
        let cert = params.self_signed(&key).unwrap();
        TestCa {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            cert_der: cert.der().to_vec(),
            key_der: key.serialize_der(),
        }
    }

    pub fn valid_ca(common_name: &str) -> TestCa {
        let now = OffsetDateTime::now_utc();
        ca_with(common_name, now - Duration::days(1), now + Duration::days(30))
    }

    /// The CA as a passphrase-protected PKCS#12 bundle.
    pub fn pkcs12(ca: &TestCa, passphrase: &str) -> Vec<u8> {
        let chain = PrivateKeyChain::new(
            b"ca".to_vec(),
            PrivateKey::from_der(&ca.key_der).unwrap(),
            [Certificate::from_der(&ca.cert_der).unwrap()],
        );
        let mut store = KeyStore::new();
        store.add_entry("ca", KeyStoreEntry::PrivateKeyChain(chain));
        store.writer(passphrase).write().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::test_ca::*;
    use super::*;
    use conduit_core::MitmConfig;
    use time::{Duration, OffsetDateTime};

    fn pem_upload(ca: &TestCa) -> MitmCaUpload {
        MitmCaUpload::Pem { cert: ca.cert_pem.clone(), key: SecretInput::new(ca.key_pem.as_str()) }
    }

    fn p12_upload(ca: &TestCa, passphrase: &str) -> MitmCaUpload {
        let data = base64::engine::general_purpose::STANDARD.encode(pkcs12(ca, passphrase));
        MitmCaUpload::Pkcs12 { data: SecretInput::new(data) }
    }

    fn session_with_ca(c: &AppController, ca: &MitmCaId) -> conduit_core::SessionProfile {
        let mut session = profile("mitm", 22);
        session.mitm = Some(MitmConfig { ca: Some(ca.clone()), ..MitmConfig::default() });
        c.upsert_session(session).unwrap()
    }

    #[tokio::test]
    async fn pem_upload_is_stored_normalized_and_needs_no_files() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        let ca = valid_ca("Upload Test CA");
        let meta = c.import_mitm_ca("corp", pem_upload(&ca), None).unwrap();
        assert_eq!(meta.name, "corp");
        assert_eq!(meta.subject, "CN=Upload Test CA");
        assert_eq!(meta.fingerprint_sha256, fingerprint(&ca.cert_der));

        let stored = c.vault_read().get_secret(&meta.id.to_string()).unwrap();
        let text = std::str::from_utf8(&stored).unwrap();
        assert!(text.starts_with("-----BEGIN CERTIFICATE-----\n"), "{text}");
        assert!(text.contains("-----BEGIN PRIVATE KEY-----\n"), "{text}");
        // The engine loads the stored text as both its certificate and its key.
        let reloaded = CaMaterial::from_pem(&stored, &stored, None).unwrap().validate().unwrap();
        assert_eq!(reloaded.cert().as_ref(), ca.cert_der.as_slice());

        let config = c.config_snapshot();
        assert_eq!(config.mitm_cas, vec![meta]);
        assert!(!serde_json::to_string(&config).unwrap().contains("PRIVATE KEY"));
    }

    #[tokio::test]
    async fn pkcs12_upload_is_decrypted_with_its_passphrase() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        let ca = valid_ca("P12 Test CA");
        let wrong = c.import_mitm_ca("p12", p12_upload(&ca, "right"), Some(SecretInput::new("wrong")));
        assert!(matches!(wrong, Err(AppError::Invalid(_))), "{wrong:?}");
        let meta = c
            .import_mitm_ca("p12", p12_upload(&ca, "right"), Some(SecretInput::new("right")))
            .unwrap();
        let stored = c.vault_read().get_secret(&meta.id.to_string()).unwrap();
        assert!(!std::str::from_utf8(&stored).unwrap().contains("ENCRYPTED"));
        assert_eq!(stored_facts(&stored).unwrap().fingerprint_sha256, meta.fingerprint_sha256);
    }

    #[tokio::test]
    async fn unusable_uploads_are_refused() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        let now = OffsetDateTime::now_utc();
        let expired = ca_with("Old", now - Duration::days(30), now - Duration::days(1));
        assert!(matches!(c.import_mitm_ca("old", pem_upload(&expired), None), Err(AppError::Invalid(_))));
        let ca = valid_ca("Mismatched");
        let other = valid_ca("Other");
        let mismatched = MitmCaUpload::Pem { cert: ca.cert_pem, key: SecretInput::new(other.key_pem) };
        assert!(matches!(c.import_mitm_ca("bad", mismatched, None), Err(AppError::Invalid(_))));
        let garbage = MitmCaUpload::Pkcs12 { data: SecretInput::new("not base64!") };
        assert!(matches!(c.import_mitm_ca("bad", garbage, None), Err(AppError::Invalid(_))));
        assert!(c.config_snapshot().mitm_cas.is_empty());
        assert!(c.vault_read().list_keys().is_empty());
    }

    #[tokio::test]
    async fn duplicate_and_locked_uploads_are_refused() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        let ca = valid_ca("Dup");
        c.import_mitm_ca("one", pem_upload(&ca), None).unwrap();
        assert!(matches!(
            c.import_mitm_ca("two", pem_upload(&ca), None),
            Err(AppError::DuplicateCa { .. })
        ));
        c.lock_vault();
        assert!(matches!(
            c.import_mitm_ca("three", pem_upload(&valid_ca("Locked")), None),
            Err(AppError::Vault(VaultError::Locked))
        ));
        assert_eq!(c.list_mitm_cas().len(), 1);
    }

    #[tokio::test]
    async fn rename_list_usage_and_delete() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        let meta = c.import_mitm_ca("corp", pem_upload(&valid_ca("Corp")), None).unwrap();
        let session = session_with_ca(&c, &meta.id);

        assert_eq!(c.rename_mitm_ca(&meta.id, "  renamed ").unwrap().name, "renamed");
        let views = c.list_mitm_cas();
        assert_eq!(views[0].used_by, 1);
        assert_eq!(views[0].usage.sessions[0].id, session.id);

        let refused = c.delete_mitm_ca(&meta.id, false).await.unwrap();
        assert!(!refused.deleted);
        assert_eq!(refused.used_by, 1);
        assert_eq!(c.list_mitm_cas().len(), 1);

        assert!(c.delete_mitm_ca(&meta.id, true).await.unwrap().deleted);
        assert!(c.list_mitm_cas().is_empty());
        assert!(c.vault_read().list_keys().is_empty());
        let saved = c.session_profile(session.id).unwrap();
        assert_eq!(saved.mitm.unwrap().ca, None);
        // It cannot start without a CA, but can once MITM is turned off.
        assert!(matches!(
            c.start_session(session.id).await,
            Err(AppError::Runtime(conduit_runtime::RuntimeError::InvalidProfile(_)))
        ));
        let mut off = c.session_profile(session.id).unwrap();
        off.mitm = None;
        c.upsert_session(off).unwrap();
        c.start_session(session.id).await.unwrap();
        c.stop_session(session.id).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn force_delete_stops_a_running_session_that_uses_the_ca() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        let meta = c.import_mitm_ca("corp", pem_upload(&valid_ca("Running")), None).unwrap();
        let node = spawn_node().await;
        let mut running = node.session("running");
        let secret = c.set_password_secret(None, SecretInput::new(SERVER_PASSWORD)).unwrap();
        running.hops[0].host.auth = vec![conduit_core::AuthMethod::Password { secret: secret.secret_ref }];
        running.mitm = Some(MitmConfig { ca: Some(meta.id.clone()), ..MitmConfig::default() });
        let id = c.upsert_session(running).unwrap().id;
        let bystander = c.upsert_session(profile("no-mitm", 22)).unwrap().id;

        c.start_session(id).await.unwrap();
        let prompt = wait_for_prompt(&c, id).await;
        c.approve_host_key(id, &prompt.sha256).unwrap();
        wait_for_state(&c, id, conduit_runtime::SessionState::Connected).await;

        assert!(c.delete_mitm_ca(&meta.id, true).await.unwrap().deleted);
        let state = c.manager().snapshot(id).unwrap().state;
        assert_eq!(state, conduit_runtime::SessionState::Stopped);
        assert!(c.vault_read().get_secret(&meta.id.to_string()).is_err());
        assert!(c.manager().snapshot(bystander).is_ok());
        assert!(c.start_session(id).await.is_err(), "no CA, so no restart");
    }

    #[tokio::test]
    async fn sessions_must_name_a_ca_in_the_vault() {
        let dir = TempDir::new();
        let c = unlocked(&dir).await;
        let mut s = profile("mitm", 22);
        s.mitm = Some(MitmConfig { ca: Some(MitmCaId::new()), ..MitmConfig::default() });
        assert!(matches!(c.upsert_session(s.clone()), Err(AppError::NotFound { .. })));
        s.mitm = Some(MitmConfig::default());
        assert!(matches!(c.upsert_session(s), Err(AppError::Validate(_))));
    }
}
