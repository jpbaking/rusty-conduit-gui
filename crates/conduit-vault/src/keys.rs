//! `conduit-vault` — SSH private-key import, generation, metadata extraction, and encrypted backup.
//!
//! Keys are stored inside `vault.bin` like every other secret (wrapped by the random DEK), but they
//! carry structured metadata. To keep a single, well-understood wire format, every key — whether it
//! was imported from OpenSSH/PEM/PKCS#8 or generated in-app — is normalized to an unencrypted
//! OpenSSH private key before storage. The vault's own envelope encryption then protects it.
//!
//! Import verifies a passphrase on encrypted keys (OpenSSH `bcrypt`/AES, or PKCS#5) and rejects a
//! wrong one. Generation produces `Ed25519` (default) or `ECDSA-NISTP256` keypairs. Metadata
//! ([`KeyInfo`]) mirrors [`conduit_core::VaultKeyMeta`]: algorithm, SHA-256 fingerprint, and the
//! copy-pasteable OpenSSH public key. A full backup can be exported to, and imported from, a
//! passphrase-encrypted bundle ([`export_backup`] / [`import_backup`]).

use std::fmt;

use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use russh::keys::{Algorithm, EcdsaCurve, HashAlg, PrivateKey};
use russh::keys::ssh_key::LineEnding;
use thiserror::Error;

use pkcs8::DecodePrivateKey;

use crate::crypto::{
    decrypt_record, derive_master_key, encrypt_record, Dek, Argon2Params,
    DEK_BYTES, SALT_BYTES,
};
use crate::VaultError;

/// Backup bundle magic (`b"CVBK"`), verified on load.
const BACKUP_MAGIC: [u8; 4] = *b"CVBK";
/// On-disk backup format version.
const BACKUP_VERSION: u8 = 1;
/// Record type bound into the backup payload's XChaCha20 AAD.
const BACKUP_RECORD_ID: &[u8] = b"conduit-vault::backup";
const BACKUP_RECORD_TYPE: &[u8] = b"payload";

/// Errors raised by key operations. Kept distinct so callers can react to a wrong passphrase or a
/// malformed key without leaking secret material.
#[derive(Debug, Error)]
enum KeyError {
    #[error("the provided passphrase is incorrect")]
    WrongPassphrase,
    #[error("the key is encrypted; a passphrase is required to import it")]
    PassphraseRequired,
    #[error("failed to parse key: {reason}")]
    Parse { reason: String },
    #[error("cryptographic error while handling key: {reason}")]
    Crypto { reason: String },
}

impl From<KeyError> for VaultError {
    fn from(e: KeyError) -> Self {
        match e {
            KeyError::WrongPassphrase => VaultError::Key {
                reason: "wrong passphrase".into(),
            },
            KeyError::PassphraseRequired => VaultError::Key {
                reason: "passphrase required for encrypted key".into(),
            },
            KeyError::Parse { reason } => VaultError::Key { reason },
            KeyError::Crypto { reason } => VaultError::Crypto { reason },
        }
    }
}

/// Friendly, human-readable name for an SSH key algorithm (stored in [`conduit_core::VaultKeyMeta`]).
pub fn algorithm_name(algo: &Algorithm) -> String {
    match algo {
        Algorithm::Ed25519 => "Ed25519".to_string(),
        Algorithm::Ecdsa { curve } => match curve {
            EcdsaCurve::NistP256 => "ECDSA-P256".to_string(),
            EcdsaCurve::NistP384 => "ECDSA-P384".to_string(),
            EcdsaCurve::NistP521 => "ECDSA-P521".to_string(),
        },
        Algorithm::Rsa { .. } => "RSA".to_string(),
        Algorithm::Dsa => "DSA".to_string(),
        _ => algo.as_str().to_string(),
    }
}

/// Metadata extracted from a private key, mirroring the key-related fields of
/// [`conduit_core::VaultKeyMeta`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyInfo {
    /// Friendly algorithm name (e.g. `Ed25519`, `ECDSA-P256`).
    pub algorithm: String,
    /// SHA-256 fingerprint in `ssh-keygen` format (`SHA256:<base64>`), padding stripped.
    pub fingerprint_sha256: String,
    /// The public key as a single OpenSSH line, safe to paste into `authorized_keys`.
    pub public_key_openssh: String,
}

/// Extract algorithm, SHA-256 fingerprint, and OpenSSH public key from a private key.
pub fn key_info(key: &PrivateKey) -> Result<KeyInfo, VaultError> {
    let algorithm = algorithm_name(&key.algorithm());

    // ssh-key's fingerprint Display already yields `SHA256:<base64>` with padding stripped,
    // matching `ssh-keygen -l`.
    let fingerprint_sha256 = key.fingerprint(HashAlg::Sha256).to_string();

    let public_key_openssh = key
        .public_key()
        .to_openssh()
        .map_err(|e| VaultError::Crypto {
            reason: format!("failed to encode public key: {e}"),
        })?;

    Ok(KeyInfo {
        algorithm,
        fingerprint_sha256,
        public_key_openssh,
    })
}

/// Key generation algorithms supported by the in-app generator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyGenAlgorithm {
    /// Ed25519 (the default).
    Ed25519,
    /// NIST P-256 ECDSA.
    EcdsaP256,
}

/// Generate a fresh in-app keypair. The private key is returned as an unencrypted OpenSSH key
/// (the vault envelope provides the actual protection) alongside its [`KeyInfo`].
pub fn generate_key(algo: KeyGenAlgorithm) -> Result<(PrivateKey, KeyInfo), VaultError> {
    // Build the keypair from OS-generated randomness rather than ssh-key's RNG, so we never depend
    // on ssh-key's `rand_core` feature.
    let key = match algo {
        KeyGenAlgorithm::Ed25519 => {
            use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};

            let mut seed = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(&mut seed[..]);
            let keypair = Ed25519Keypair::from_seed(&seed);
            PrivateKey::new(KeypairData::Ed25519(keypair), "").map_err(|e| KeyError::Crypto {
                reason: format!("failed to build Ed25519 keypair: {e}"),
            })?
        }
        KeyGenAlgorithm::EcdsaP256 => {
            use elliptic_curve::sec1::ToSec1Point;
            use russh::keys::ssh_key::private::{EcdsaKeypair, EcdsaPrivateKey, KeypairData};

            let mut bytes = [0u8; 32];
            OsRng.fill_bytes(&mut bytes);
            let sk = p256::SecretKey::from_slice(&bytes).map_err(|_| KeyError::Crypto {
                reason: "generated an invalid P-256 scalar".into(),
            })?;
            let point = sk.public_key().to_sec1_point(false);
            let keypair = EcdsaKeypair::NistP256 {
                private: EcdsaPrivateKey::from(sk),
                public: point,
            };
            PrivateKey::new(KeypairData::Ecdsa(keypair), "").map_err(|e| KeyError::Crypto {
                reason: format!("failed to build ECDSA keypair: {e}"),
            })?
        }
    };

    let info = key_info(&key)?;
    Ok((key, info))
}

/// Import a private key from OpenSSH, traditional PEM (SEC1), or PKCS#8/PKCS#5 form.
///
/// If the key is encrypted, `passphrase` must be supplied and is verified; a wrong passphrase
/// yields [`VaultError::Key`]. The returned key is the decrypted, normalized OpenSSH private key,
/// together with its [`KeyInfo`].
pub fn import_key(input: &str, passphrase: Option<&[u8]>) -> Result<(PrivateKey, KeyInfo), VaultError> {
    let trimmed = input.trim();

    if trimmed.contains("OPENSSH PRIVATE KEY") {
        return import_openssh(trimmed, passphrase);
    }
    if trimmed.contains("EC PRIVATE KEY") {
        return import_sec1(trimmed);
    }
    // `BEGIN PRIVATE KEY` (PKCS#8, unencrypted) or `BEGIN ENCRYPTED PRIVATE KEY` (PKCS#5).
    if trimmed.contains("PRIVATE KEY") {
        return import_pkcs8(trimmed, passphrase);
    }

    Err(VaultError::Key {
        reason: "unrecognized key format (expected OpenSSH, SEC1, or PKCS#8)".into(),
    })
}

/// Import an OpenSSH private key, verifying the passphrase if it is encrypted.
fn import_openssh(pem: &str, passphrase: Option<&[u8]>) -> Result<(PrivateKey, KeyInfo), VaultError> {
    let key = PrivateKey::from_openssh(pem).map_err(|e| KeyError::Parse {
        reason: format!("failed to parse OpenSSH key: {e}"),
    })?;

    if key.is_encrypted() {
        let pw = passphrase.ok_or(KeyError::PassphraseRequired)?;
        // A wrong passphrase fails decryption; surface it distinctly.
        let decrypted = key.decrypt(pw).map_err(|_| KeyError::WrongPassphrase)?;
        let info = key_info(&decrypted)?;
        return Ok((decrypted, info));
    }

    let info = key_info(&key)?;
    Ok((key, info))
}

/// Import a traditional SEC1 EC private key (`-----BEGIN EC PRIVATE KEY-----`).
fn import_sec1(pem: &str) -> Result<(PrivateKey, KeyInfo), VaultError> {
    let sk = p256::SecretKey::from_sec1_pem(pem).map_err(|e| KeyError::Parse {
        reason: format!("failed to parse SEC1 EC key: {e}"),
    })?;
    build_ecdsa_key(&sk)
}

/// Import a PKCS#8 (`BEGIN PRIVATE KEY`) or PKCS#5 (`BEGIN ENCRYPTED PRIVATE KEY`) key.
fn import_pkcs8(pem: &str, passphrase: Option<&[u8]>) -> Result<(PrivateKey, KeyInfo), VaultError> {
    let info = if pem.contains("ENCRYPTED PRIVATE KEY") {
        let pw = passphrase.ok_or(KeyError::PassphraseRequired)?;
        // PKCS#5 encrypted envelope: parse and decrypt in one step; a wrong passphrase fails.
        pkcs8::PrivateKeyInfoOwned::from_pkcs8_encrypted_pem(pem, pw)
            .map_err(|_| KeyError::WrongPassphrase)?
    } else {
        pkcs8::PrivateKeyInfoOwned::from_pkcs8_pem(pem).map_err(|e| KeyError::Parse {
            reason: format!("failed to parse PKCS#8 key: {e}"),
        })?
    };
    import_pkcs8_by_oid(&info)
}

/// Dispatch a decrypted PKCS#8 `PrivateKeyInfo` to the right importer by its algorithm OID.
fn import_pkcs8_by_oid(
    info: &pkcs8::PrivateKeyInfoOwned,
) -> Result<(PrivateKey, KeyInfo), VaultError> {
    let oid = info.algorithm.oid.to_string();
    match oid.as_str() {
        "1.3.101.112" => import_pkcs8_ed25519(info),
        "1.2.840.10045.2.1" => import_pkcs8_ecdsa(info),
        other => Err(VaultError::Key {
            reason: format!("unsupported PKCS#8 algorithm OID {other}"),
        }),
    }
}

/// Extract the 32-byte Ed25519 seed from a PKCS#8 `PrivateKeyInfo` and build the keypair.
fn import_pkcs8_ed25519(
    info: &pkcs8::PrivateKeyInfoOwned,
) -> Result<(PrivateKey, KeyInfo), VaultError> {
    use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};

    let der = info.private_key.as_bytes();
    // The DER is `04 20 <32-byte seed>`; the seed is the final 32 bytes.
    if der.len() < 32 {
        return Err(KeyError::Parse {
            reason: "Ed25519 PKCS#8 secret is shorter than 32 bytes".into(),
        }
        .into());
    }
    let seed = der
        .get(der.len() - 32..)
        .ok_or_else(|| KeyError::Parse {
            reason: "Ed25519 PKCS#8 seed is not 32 bytes".into(),
        })?;
    let keypair = Ed25519Keypair::from_seed(seed.try_into().map_err(|_| KeyError::Parse {
        reason: "Ed25519 PKCS#8 seed is not 32 bytes".into(),
    })?);
    let key = PrivateKey::new(KeypairData::Ed25519(keypair), "").map_err(|e| KeyError::Parse {
        reason: format!("failed to build Ed25519 keypair: {e}"),
    })?;
    let info = key_info(&key)?;
    Ok((key, info))
}

/// Derive an ECDSA keypair from the SEC1 structure embedded in a PKCS#8 key.
fn import_pkcs8_ecdsa(
    info: &pkcs8::PrivateKeyInfoOwned,
) -> Result<(PrivateKey, KeyInfo), VaultError> {
    let sec1_der = info.private_key.as_bytes();
    let sk = p256::SecretKey::from_sec1_der(sec1_der).map_err(|e| KeyError::Parse {
        reason: format!("failed to parse SEC1 structure in PKCS#8 key: {e}"),
    })?;
    build_ecdsa_key(&sk)
}

/// Build an ECDSA private key from a `p256::SecretKey`, normalizing to OpenSSH.
fn build_ecdsa_key(
    sk: &p256::SecretKey,
) -> Result<(PrivateKey, KeyInfo), VaultError> {
    use elliptic_curve::sec1::ToSec1Point;
    use russh::keys::ssh_key::private::{EcdsaKeypair, EcdsaPrivateKey, KeypairData};

    let point = sk.public_key().to_sec1_point(false);
    let keypair = EcdsaKeypair::NistP256 {
        private: EcdsaPrivateKey::from(sk.clone()),
        public: point,
    };
    let key = PrivateKey::new(KeypairData::Ecdsa(keypair), "").map_err(|e| KeyError::Crypto {
        reason: format!("failed to build ECDSA keypair: {e}"),
    })?;
    let info = key_info(&key)?;
    Ok((key, info))
}

// ---------------------------------------------------------------------------
// Passphrase-encrypted full backup.
// ---------------------------------------------------------------------------

/// A single key entry inside a backup bundle. The private key is stored as normalized OpenSSH PEM;
/// the vault envelope (or the backup passphrase) is what protects it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupKey {
    /// User-supplied name for the key.
    pub name: String,
    /// Friendly algorithm name (see [`algorithm_name`]).
    pub algorithm: String,
    /// SHA-256 fingerprint (`SHA256:<base64>`).
    pub fingerprint_sha256: String,
    /// OpenSSH public key line.
    pub public_key_openssh: String,
    /// Normalized OpenSSH private key PEM.
    pub private_key_openssh: String,
    /// Where the key came from (`Uploaded` / `Pasted` / `Generated`).
    pub source: String,
    /// Creation time, Unix epoch seconds.
    pub created_at: i64,
}

impl fmt::Debug for BackupKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackupKey")
            .field("name", &self.name)
            .field("algorithm", &self.algorithm)
            .field("fingerprint_sha256", &self.fingerprint_sha256)
            .field("public_key_openssh", &self.public_key_openssh)
            .field("private_key_openssh", &"<redacted>")
            .field("source", &self.source)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl BackupKey {
    /// Build a backup entry from a normalized OpenSSH key and its metadata.
    pub fn from_key(name: &str, key: &PrivateKey, info: &KeyInfo, source: &str, created_at: i64) -> Self {
        // A normalized OpenSSH key always serializes without error.
        let private_key_openssh = key
            .to_openssh(LineEnding::LF)
            .expect("valid OpenSSH key serializes without error")
            .to_string();
        BackupKey {
            name: name.to_string(),
            algorithm: info.algorithm.clone(),
            fingerprint_sha256: info.fingerprint_sha256.clone(),
            public_key_openssh: info.public_key_openssh.clone(),
            private_key_openssh,
            source: source.to_string(),
            created_at,
        }
    }
}

/// The on-disk backup document: magic, version, Argon2id params, salt, the wrapped backup key, and
/// the encrypted payload. Contains no key material in plaintext.
#[derive(Serialize, Deserialize)]
struct BackupFile {
    magic: [u8; 4],
    version: u8,
    argon2: Argon2Params,
    salt: [u8; SALT_BYTES],
    wrapped_key: Vec<u8>,
    payload: Vec<u8>,
}

/// The decrypted backup payload: the list of keys.
#[derive(Serialize, Deserialize)]
struct BackupPayload {
    keys: Vec<BackupKey>,
}

/// Export a set of keys to a passphrase-encrypted backup bundle.
///
/// The bundle wraps a random 256-bit key with an Argon2id master key derived from `passphrase`,
/// then encrypts the JSON key list with that key. Reuses the vault's envelope primitives so the
/// format stays consistent with `vault.bin`.
pub fn export_backup(
    keys: &[BackupKey],
    passphrase: &[u8],
    params: Argon2Params,
) -> Result<Vec<u8>, VaultError> {
    let payload = BackupPayload {
        keys: keys.to_vec(),
    };
    let json = serde_json::to_vec_pretty(&payload).map_err(|source| VaultError::Crypto {
        reason: format!("failed to serialize backup payload: {source}"),
    })?;

    let mut salt = [0u8; SALT_BYTES];
    OsRng.fill_bytes(&mut salt);

    let master_key = derive_master_key(passphrase, &params, &salt)?;
    let mut backup_key = Zeroizing::new([0u8; DEK_BYTES]);
    OsRng.fill_bytes(&mut backup_key[..]);
    let dek = Dek::from_bytes(&backup_key[..])?;

    let wrapped_key = crate::crypto::wrap_dek_with_key(&dek, &*master_key);
    let payload_ct = encrypt_record(
        &dek,
        BACKUP_RECORD_ID,
        BACKUP_RECORD_TYPE,
        &json,
    );

    let file = BackupFile {
        magic: BACKUP_MAGIC,
        version: BACKUP_VERSION,
        argon2: params,
        salt,
        wrapped_key,
        payload: payload_ct,
    };
    serde_json::to_vec(&file).map_err(|source| VaultError::Crypto {
        reason: format!("failed to serialize backup bundle: {source}"),
    })
}

/// Import keys from a passphrase-encrypted backup bundle. A wrong passphrase or tampered bundle
/// yields [`VaultError::Key`] / [`VaultError::UnlockFailed`].
pub fn import_backup(
    data: &[u8],
    passphrase: &[u8],
) -> Result<Vec<BackupKey>, VaultError> {
    let file: BackupFile = serde_json::from_slice(data).map_err(|source| VaultError::InvalidFormat {
        reason: format!("backup bundle is not valid JSON: {source}"),
    })?;

    if file.magic != BACKUP_MAGIC {
        return Err(VaultError::InvalidFormat {
            reason: "backup bundle has an unknown magic".into(),
        });
    }
    if file.version != BACKUP_VERSION {
        return Err(VaultError::InvalidFormat {
            reason: format!("unsupported backup version {}", file.version),
        });
    }

    let master_key = derive_master_key(passphrase, &file.argon2, &file.salt)?;
    // A wrong password or tampered bundle fails authentication here.
    let dek = crate::crypto::unwrap_dek(&file.wrapped_key, &*master_key)?;

    let json = decrypt_record(
        &dek,
        BACKUP_RECORD_ID,
        BACKUP_RECORD_TYPE,
        &file.payload,
    )?;

    let payload: BackupPayload = serde_json::from_slice(&json).map_err(|source| VaultError::InvalidFormat {
        reason: format!("backup payload is not valid JSON: {source}"),
    })?;
    Ok(payload.keys)
}

impl fmt::Debug for BackupFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never serialize the wrapped key or payload bytes.
        f.debug_struct("BackupFile")
            .field("magic", &self.magic)
            .field("version", &self.version)
            .field("argon2", &self.argon2)
            .field("salt", &"<redacted>")
            .field("wrapped_key", &"<redacted>")
            .field("payload", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_ed25519_produces_valid_metadata() {
        let (key, info) = generate_key(KeyGenAlgorithm::Ed25519).unwrap();
        assert_eq!(info.algorithm, "Ed25519");
        assert!(info.fingerprint_sha256.starts_with("SHA256:"));
        assert!(info.public_key_openssh.starts_with("ssh-ed25519 "));
        // The fingerprint must equal the re-parsed key's fingerprint.
        let reparsed = PrivateKey::from_openssh(
            key.to_openssh(LineEnding::LF).unwrap().as_bytes(),
        )
        .unwrap();
        assert_eq!(info.fingerprint_sha256, reparsed.fingerprint(HashAlg::Sha256).to_string());
    }

    #[test]
    fn generate_ecdsa_p256_produces_valid_metadata() {
        let (key, info) = generate_key(KeyGenAlgorithm::EcdsaP256).unwrap();
        assert_eq!(info.algorithm, "ECDSA-P256");
        assert!(info.fingerprint_sha256.starts_with("SHA256:"));
        assert!(info.public_key_openssh.starts_with("ecdsa-sha2-nistp256 "));
        // Round-trips through OpenSSH.
        let reparsed = PrivateKey::from_openssh(
            key.to_openssh(LineEnding::LF).unwrap().as_bytes(),
        )
        .unwrap();
        assert_eq!(info.fingerprint_sha256, reparsed.fingerprint(HashAlg::Sha256).to_string());
    }

    #[test]
    fn two_generations_differ() {
        let (_, a) = generate_key(KeyGenAlgorithm::Ed25519).unwrap();
        let (_, b) = generate_key(KeyGenAlgorithm::Ed25519).unwrap();
        assert_ne!(a.fingerprint_sha256, b.fingerprint_sha256);
    }

    #[test]
    fn import_openssh_unencrypted() {
        let (generated, expected) = generate_key(KeyGenAlgorithm::Ed25519).unwrap();
        let pem = generated.to_openssh(LineEnding::LF).unwrap();
        let (key, info) = import_key(&pem, None).unwrap();
        assert_eq!(info.algorithm, "Ed25519");
        assert_eq!(info.fingerprint_sha256, expected.fingerprint_sha256);
        assert!(info.public_key_openssh.starts_with("ssh-ed25519 "));
        assert!(!key.is_encrypted());
    }

    #[test]
    fn import_pkcs8_ed25519_matches_reference() {
        use base64::Engine;
        // RFC 8410 Section 10.3 Ed25519 test vector (PKCS#8 DER with 32-byte seed).
        let mut der = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        der.extend_from_slice(&[0x42u8; 32]);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n");

        let (key, info) = import_key(&pem, None).unwrap();
        assert_eq!(info.algorithm, "Ed25519");
        let pem_out = key.to_openssh(LineEnding::LF).unwrap();
        let reparsed = PrivateKey::from_openssh(pem_out.as_bytes()).unwrap();
        assert_eq!(info.fingerprint_sha256, reparsed.fingerprint(HashAlg::Sha256).to_string());
    }

    #[test]
    fn import_sec1_ecdsa_matches_openssh_fingerprint() {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let sk = p256::SecretKey::from_slice(&bytes).unwrap();
        let pem = sk.to_sec1_pem(pkcs8::LineEnding::LF).unwrap();

        let (key, info) = import_key(&pem, None).unwrap();
        assert_eq!(info.algorithm, "ECDSA-P256");
        assert!(info.public_key_openssh.starts_with("ecdsa-sha2-nistp256 "));
        let pem_out = key.to_openssh(LineEnding::LF).unwrap();
        let reparsed = PrivateKey::from_openssh(pem_out.as_bytes()).unwrap();
        assert_eq!(info.fingerprint_sha256, reparsed.fingerprint(HashAlg::Sha256).to_string());
    }

    #[test]
    fn import_pkcs8_ecdsa_matches_openssh_fingerprint() {
        use pkcs8::EncodePrivateKey;
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let sk = p256::SecretKey::from_slice(&bytes).unwrap();
        let pem = sk.to_pkcs8_pem(pkcs8::LineEnding::LF).unwrap();

        let (key, info) = import_key(&pem, None).unwrap();
        assert_eq!(info.algorithm, "ECDSA-P256");
        let pem_out = key.to_openssh(LineEnding::LF).unwrap();
        let reparsed = PrivateKey::from_openssh(pem_out.as_bytes()).unwrap();
        assert_eq!(info.fingerprint_sha256, reparsed.fingerprint(HashAlg::Sha256).to_string());
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        // Encrypt an Ed25519 key with a known passphrase, then import with the wrong one.
        let (key, info) = generate_key(KeyGenAlgorithm::Ed25519).unwrap();
        let enc = key
            .encrypt(&mut getrandom::SysRng, "right-pass")
            .expect("encrypt");
        assert!(enc.is_encrypted());
        // The encrypted PEM must round-trip through the OpenSSH parser as encrypted.
        let pem = enc.to_openssh(LineEnding::LF).unwrap();
        // A wrong passphrase fails decryption.
        let err = import_key(&pem, Some(b"wrong-pass")).unwrap_err();
        assert!(matches!(err, VaultError::Key { .. }));
        // The correct passphrase succeeds and matches the original fingerprint.
        let (_, info2) = import_key(&pem, Some(b"right-pass")).unwrap();
        assert_eq!(info.fingerprint_sha256, info2.fingerprint_sha256);
    }

    #[test]
    fn encrypted_key_requires_passphrase() {
        let key = generate_key(KeyGenAlgorithm::Ed25519).unwrap().0;
        let enc = key
            .encrypt(&mut getrandom::SysRng, "pass")
            .unwrap();
        let pem = enc.to_openssh(LineEnding::LF).unwrap();
        assert!(matches!(
            import_key(&pem, None),
            Err(VaultError::Key { .. })
        ));
    }

    #[test]
    fn backup_round_trips_keys() {
        let k1 = generate_key(KeyGenAlgorithm::Ed25519).unwrap();
        let k2 = generate_key(KeyGenAlgorithm::EcdsaP256).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let keys = vec![
            BackupKey::from_key("ed", &k1.0, &k1.1, "Generated", now),
            BackupKey::from_key("ec", &k2.0, &k2.1, "Generated", now),
        ];

        let bundle = export_backup(&keys, b"backup-pass", Argon2Params::FAST).unwrap();

        let imported = import_backup(&bundle, b"backup-pass").unwrap();
        assert_eq!(imported.len(), 2);
        assert_eq!(imported[0].fingerprint_sha256, k1.1.fingerprint_sha256);
        assert_eq!(imported[1].algorithm, "ECDSA-P256");

        // Wrong passphrase fails.
        assert!(matches!(
            import_backup(&bundle, b"wrong"),
            Err(VaultError::Key { .. }) | Err(VaultError::UnlockFailed)
        ));
    }

    #[test]
    fn backup_rejects_huge_argon_memory_before_deriving() {
        let bundle = export_backup(&[], b"pass", Argon2Params::FAST).unwrap();
        let mut file: serde_json::Value = serde_json::from_slice(&bundle).unwrap();
        file["argon2"]["memory_kib"] = serde_json::json!(u32::MAX);
        let edited = serde_json::to_vec(&file).unwrap();
        let started = std::time::Instant::now();
        assert!(matches!(
            import_backup(&edited, b"pass"),
            Err(VaultError::InvalidFormat { .. })
        ));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn backup_rejects_bad_magic() {
        let bundle = export_backup(&[], b"pass", Argon2Params::FAST).unwrap();
        let mut bad = bundle;
        bad[0] ^= 0xFF; // corrupt magic
        assert!(matches!(
            import_backup(&bad, b"pass"),
            Err(VaultError::InvalidFormat { .. })
        ));
    }
}
