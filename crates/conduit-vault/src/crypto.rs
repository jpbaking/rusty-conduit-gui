//! `conduit-vault` — cryptographic primitives for envelope encryption.
//!
//! The vault wraps every secret with a random 256-bit data encryption key (`Dek`). That DEK is
//! itself wrapped (encrypted) either by an OS keyring or by a master key derived from a password
//! with Argon2id, and the wrapped DEK plus the Argon2id parameters and salt live in the on-disk
//! vault header. Each record is encrypted independently with a fresh 24-byte XChaCha20 nonce and
//! additional authenticated data binding `(record_id, record_type, vault_version)`.
//!
//! No secret bytes ever leave the vault in plaintext; decrypted material is returned wrapped in
//! [`secrecy`] / [`zeroize`] types that zeroize on drop.

use std::fmt;

use argon2::password_hash::{PasswordHash, PasswordHasher, SaltString};
use argon2::{Algorithm, Argon2, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::VaultError;

/// On-disk vault magic bytes (`b"CVLT"`), verified on load.
pub const VAULT_MAGIC: [u8; 4] = *b"CVLT";
/// Current on-disk format version, bound into every record's AAD.
pub const VAULT_VERSION: u8 = 1;
/// Size of the data encryption key in bytes (256-bit).
pub const DEK_BYTES: usize = 32;
/// Size of the XChaCha20 nonce in bytes (24 bytes).
pub const NONCE_BYTES: usize = 24;
/// Size of the Argon2id salt in bytes.
pub const SALT_BYTES: usize = 16;

/// AAD domain-separation tag bound into every record ciphertext. Kept in one place so the
/// record AAD and the DEK-wrapping AAD can never drift.
const DEK_WRAP_AAD: &[u8] = b"conduit-vault::dek-wrap::v1";

/// A random 256-bit data encryption key. The raw bytes live inside a [`SecretBox`] and are
/// zeroized on drop; [`Debug`] never reveals them.
pub struct Dek(SecretBox<[u8; DEK_BYTES]>);

impl Dek {
    /// Generate a cryptographically random 256-bit DEK from the OS CSPRNG.
    pub fn random() -> Self {
        let mut bytes = [0u8; DEK_BYTES];
        OsRng.fill_bytes(&mut bytes);
        Dek(SecretBox::new(Box::new(bytes)))
    }

    /// Reconstruct a DEK from exactly [`DEK_BYTES`] raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.len() != DEK_BYTES {
            return Err(VaultError::Crypto {
                reason: format!("DEK must be {DEK_BYTES} bytes, got {}", bytes.len()),
            });
        }
        let mut arr = [0u8; DEK_BYTES];
        arr.copy_from_slice(bytes);
        Ok(Dek(SecretBox::new(Box::new(arr))))
    }

    /// Serialize the DEK to raw bytes (for keyring storage or header wrapping).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.expose_secret().to_vec()
    }

    /// Borrow the raw key bytes for the duration of `f`. The bytes are never copied out of the
    /// [`SecretBox`], so there is no extra plaintext to zeroize.
    pub fn with_key<T>(&self, f: impl FnOnce(&[u8]) -> T) -> T {
        f(self.0.expose_secret())
    }
}

impl Zeroize for Dek {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for Dek {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Dek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Dek").field(&"<redacted>").finish()
    }
}

/// Argon2id parameters, stored in the vault header so unwrapping is reproducible.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Memory cost in KiB. Baseline is 128 MiB.
    pub memory_kib: u32,
    /// Time cost (iterations).
    pub time_cost: u32,
    /// Parallelism (lanes).
    pub parallelism: u8,
    /// Derived key length in bytes.
    pub derived_key_len: usize,
}

impl Argon2Params {
    /// Calibrated production baseline: 128 MiB, `t=3`, `p=1`. Stored in the vault header.
    pub const BASELINE: Self = Self {
        memory_kib: 128 * 1024,
        time_cost: 3,
        parallelism: 1,
        derived_key_len: 32,
    };

    /// A fast, low-memory parameter set intended only for `#[cfg(test)]` so test suites do not
    /// pay the 128 MiB / 3-iteration cost. Never used in production builds.
    #[cfg(test)]
    pub const FAST: Self = Self {
        memory_kib: 16 * 1024,
        time_cost: 1,
        parallelism: 1,
        derived_key_len: 32,
    };

    /// Build the [`Argon2`] builder for these parameters.
    pub fn to_argon2(&self) -> Result<Argon2<'static>, VaultError> {
        use argon2::Params;
        Params::new(self.memory_kib, self.time_cost, self.parallelism as u32, Some(self.derived_key_len))
            .map(|p| Argon2::new(Algorithm::Argon2id, Version::V0x13, p))
            .map_err(|e| VaultError::Crypto {
                reason: format!("invalid Argon2 parameters: {e}"),
            })
    }
}

/// The on-disk vault header: magic, format version, Argon2id parameters, salt, and the wrapped
/// DEK. Contains no plaintext secret and no usable key on its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultHeader {
    /// `b"CVLT"`.
    pub magic: [u8; 4],
    /// On-disk format version.
    pub version: u8,
    /// Argon2id parameters used to derive the master key.
    pub argon2: Argon2Params,
    /// Argon2id salt (random per vault).
    pub salt: [u8; SALT_BYTES],
    /// The DEK wrapped (encrypted) with the master key derived from the password.
    pub wrapped_dek: Vec<u8>,
}

impl VaultHeader {
    /// Build a header for a fresh DEK, wrapping it under a master key derived from `password`.
    pub fn new(dek: &Dek, params: &Argon2Params, password: &[u8]) -> Self {
        let mut salt = [0u8; SALT_BYTES];
        OsRng.fill_bytes(&mut salt);
        let wrapped_dek = wrap_dek(dek, params, password, &salt);
        VaultHeader {
            magic: VAULT_MAGIC,
            version: VAULT_VERSION,
            argon2: *params,
            salt,
            wrapped_dek,
        }
    }

    /// Validate the magic bytes and format version.
    pub fn validate(&self) -> Result<(), VaultError> {
        if self.magic != VAULT_MAGIC {
            return Err(VaultError::InvalidFormat {
                reason: "bad magic bytes: not a conduit vault".into(),
            });
        }
        if self.version != VAULT_VERSION {
            return Err(VaultError::InvalidFormat {
                reason: format!("unsupported vault version {version}", version = self.version),
            });
        }
        Ok(())
    }

    /// Derive the master key from `password` and unwrap the DEK. A wrong password yields
    /// [`VaultError::UnlockFailed`].
    pub fn unwrap_dek(&self, password: &[u8]) -> Result<Dek, VaultError> {
        self.validate()?;
        let master_key = derive_master_key(password, &self.argon2, &self.salt)?;
        let dek = unwrap_dek(&self.wrapped_dek, &*master_key)?;
        Ok(dek)
    }
}

/// Generate a random 256-bit DEK.
pub fn generate_dek() -> Dek {
    Dek::random()
}

/// Derive a 32-byte master key from `password`, `params`, and `salt` using Argon2id.
///
/// The derived key is wrapped in [`Zeroizing`] so it is zeroized when it goes out of scope.
pub fn derive_master_key(
    password: &[u8],
    params: &Argon2Params,
    salt: &[u8],
) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let argon2 = params.to_argon2()?;
    let salt_b64 = SaltString::encode_b64(salt).map_err(|e| VaultError::Crypto {
        reason: format!("failed to encode salt: {e}"),
    })?;
    let hash: PasswordHash = argon2
        .hash_password(password, &salt_b64)
        .map_err(|e| VaultError::Crypto {
            reason: format!("Argon2id key derivation failed: {e}"),
        })?;
    let output = hash
        .hash
        .ok_or_else(|| VaultError::Crypto {
            reason: "Argon2id produced no derived key".into(),
        })?;
    let bytes = output.as_bytes();
    if bytes.len() != 32 {
        return Err(VaultError::Crypto {
            reason: format!("derived key length is {}, expected 32", bytes.len()),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(Zeroizing::new(out))
}

/// Wrap (encrypt) a DEK with a master key derived from `password` + `salt`.
///
/// The output is the 24-byte random nonce concatenated with the XChaCha20-Poly1305 ciphertext.
pub fn wrap_dek(dek: &Dek, params: &Argon2Params, password: &[u8], salt: &[u8]) -> Vec<u8> {
    let master_key = derive_master_key(password, params, salt)
        .expect("parameters are valid; derivation cannot fail here");
    wrap_dek_with_key(dek, &*master_key)
}

/// Wrap a DEK with an already-derived 32-byte master key.
pub fn wrap_dek_with_key(dek: &Dek, master_key: &[u8]) -> Vec<u8> {
    dek.with_key(|key_bytes| {
        let cipher = XChaCha20Poly1305::new_from_slice(master_key).expect("32-byte master key");
        let mut nonce = [0u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce);
        let nonce_ref = XNonce::from_slice(&nonce);
        let ct = cipher
            .encrypt(
                nonce_ref,
                Payload {
                    msg: key_bytes,
                    aad: DEK_WRAP_AAD,
                },
            )
            .expect("DEK wrapping cannot fail for well-formed input");
        let mut out = Vec::with_capacity(NONCE_BYTES + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    })
}

/// Unwrap a DEK produced by [`wrap_dek_with_key`] with the matching master key.
/// A mismatched key (wrong password) yields [`VaultError::UnlockFailed`].
pub fn unwrap_dek(wrapped: &[u8], master_key: &[u8]) -> Result<Dek, VaultError> {
    let cipher = XChaCha20Poly1305::new_from_slice(master_key).map_err(|_| VaultError::Crypto {
        reason: "master key must be exactly 32 bytes".into(),
    })?;
    if wrapped.len() < NONCE_BYTES {
        return Err(VaultError::UnlockFailed);
    }
    let (nonce_bytes, ct) = wrapped.split_at(NONCE_BYTES);
    let nonce_ref = XNonce::from_slice(nonce_bytes);
    let pt = cipher
        .decrypt(
            nonce_ref,
            Payload {
                msg: ct,
                aad: DEK_WRAP_AAD,
            },
        )
        .map_err(|_| VaultError::UnlockFailed)?;
    Dek::from_bytes(&pt)
}

/// Build the additional authenticated data binding `(record_id, record_type, vault_version)`.
///
/// Length-prefixing each component makes the binding unambiguous: swapping any of the three
/// values changes the AAD and therefore fails authentication.
pub fn build_record_aad(record_id: &[u8], record_type: &[u8], version: u8) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + record_id.len() + 8 + record_type.len() + 1);
    aad.extend_from_slice(&(record_id.len() as u64).to_le_bytes());
    aad.extend_from_slice(record_id);
    aad.extend_from_slice(&(record_type.len() as u64).to_le_bytes());
    aad.extend_from_slice(record_type);
    aad.push(version);
    aad
}

/// Encrypt one record with a fresh 24-byte nonce and AAD binding `(record_id, record_type, version)`.
///
/// The returned buffer is the 24-byte nonce concatenated with the XChaCha20-Poly1305 ciphertext,
/// so decryption can recover the nonce.
pub fn encrypt_record(
    dek: &Dek,
    record_id: &[u8],
    record_type: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    dek.with_key(|key_bytes| {
        let cipher = XChaCha20Poly1305::new_from_slice(key_bytes).expect("32-byte DEK");
        let mut nonce = [0u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce);
        let nonce_ref = XNonce::from_slice(&nonce);
        let aad = build_record_aad(record_id, record_type, VAULT_VERSION);
        let ct = cipher
            .encrypt(
                nonce_ref,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .expect("record encryption cannot fail for well-formed input");
        let mut out = Vec::with_capacity(NONCE_BYTES + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    })
}

/// Decrypt one record. The input is the `nonce || ciphertext` buffer produced by
/// [`encrypt_record`]. A tampered ciphertext or a mismatched `(record_id, record_type, version)`
/// yields [`VaultError::UnlockFailed`]. The plaintext is returned zeroized on drop.
pub fn decrypt_record(
    dek: &Dek,
    record_id: &[u8],
    record_type: &[u8],
    nonce_and_ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    if nonce_and_ct.len() < NONCE_BYTES {
        return Err(VaultError::UnlockFailed);
    }
    let (nonce_bytes, ct) = nonce_and_ct.split_at(NONCE_BYTES);
    let aad = build_record_aad(record_id, record_type, VAULT_VERSION);
    dek.with_key(|key_bytes| -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let cipher = XChaCha20Poly1305::new_from_slice(key_bytes).expect("32-byte DEK");
        let nonce_ref = XNonce::from_slice(nonce_bytes);
        let pt = cipher
            .decrypt(
                nonce_ref,
                Payload {
                    msg: ct,
                    aad: &aad,
                },
            )
            .map_err(|_| VaultError::UnlockFailed)?;
        Ok(Zeroizing::new(pt))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_dek() -> Dek {
        Dek::random()
    }

    #[test]
    fn dek_round_trips_through_bytes() {
        let dek = sample_dek();
        let bytes = dek.to_bytes();
        assert_eq!(bytes.len(), DEK_BYTES);
        let restored = Dek::from_bytes(&bytes).unwrap();
        assert_eq!(restored.to_bytes(), dek.to_bytes());
    }

    #[test]
    fn dek_from_wrong_length_bytes_is_an_error() {
        assert!(Dek::from_bytes(&[0u8; 16]).is_err());
        assert!(Dek::from_bytes(&[0u8; 33]).is_err());
    }

    #[test]
    fn dek_debug_never_leaks_bytes() {
        let dek = sample_dek();
        let rendered = format!("{dek:?}");
        // The Debug output must be the fixed redaction marker only — never the key bytes.
        assert_eq!(rendered, "Dek(\"<redacted>\")");
        // And it must not contain the actual DEK bytes in any form.
        let hex = dek
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert!(!rendered.contains(&hex));
    }

    #[test]
    fn header_wraps_and_unwraps_the_dek() {
        let dek = sample_dek();
        let header = VaultHeader::new(&dek, &Argon2Params::FAST, b"correct horse");
        assert_eq!(header.magic, VAULT_MAGIC);
        assert_eq!(header.version, VAULT_VERSION);
        let restored = header.unwrap_dek(b"correct horse").unwrap();
        assert_eq!(restored.to_bytes(), dek.to_bytes());
    }

    #[test]
    fn wrong_password_fails_unlock() {
        let dek = sample_dek();
        let header = VaultHeader::new(&dek, &Argon2Params::FAST, b"correct horse");
        let err = header.unwrap_dek(b"a totally different password").unwrap_err();
        assert!(matches!(err, VaultError::UnlockFailed));
    }

    #[test]
    fn tampered_wrapped_dek_fails() {
        let dek = sample_dek();
        let mut header = VaultHeader::new(&dek, &Argon2Params::FAST, b"password");
        // Flip a byte in the wrapped DEK (nonce is first; flip it).
        header.wrapped_dek[0] ^= 0x01;
        let err = header.unwrap_dek(b"password").unwrap_err();
        assert!(matches!(err, VaultError::UnlockFailed));
    }

    #[test]
    fn header_rejects_bad_magic() {
        let dek = sample_dek();
        let mut header = VaultHeader::new(&dek, &Argon2Params::FAST, b"password");
        header.magic = [0u8; 4];
        assert!(matches!(
            header.validate(),
            Err(VaultError::InvalidFormat { .. })
        ));
    }

    #[test]
    fn record_encrypt_decrypt_round_trip() {
        let dek = sample_dek();
        let plaintext = b"ssh-private-key-material";
        let ct = encrypt_record(&dek, b"rec-1", b"key", plaintext);
        assert_ne!(&ct[..], plaintext);
        let pt = decrypt_record(&dek, b"rec-1", b"key", &ct).unwrap();
        assert_eq!(&pt[..], plaintext);
    }

    #[test]
    fn record_wrong_aad_fails() {
        let dek = sample_dek();
        let ct = encrypt_record(&dek, b"rec-1", b"key", b"secret");
        // Wrong record_id in the AAD.
        assert!(matches!(
            decrypt_record(&dek, b"rec-2", b"key", &ct),
            Err(VaultError::UnlockFailed)
        ));
        // Wrong record_type in the AAD.
        assert!(matches!(
            decrypt_record(&dek, b"rec-1", b"password", &ct),
            Err(VaultError::UnlockFailed)
        ));
    }

    #[test]
    fn record_wrong_dek_fails() {
        let ct = encrypt_record(&sample_dek(), b"rec-1", b"key", b"secret");
        assert!(matches!(
            decrypt_record(&sample_dek(), b"rec-1", b"key", &ct),
            Err(VaultError::UnlockFailed)
        ));
    }

    #[test]
    fn derive_master_key_is_deterministic_for_same_salt() {
        let salt = [7u8; SALT_BYTES];
        let a = derive_master_key(b"pw", &Argon2Params::FAST, &salt).unwrap();
        let b = derive_master_key(b"pw", &Argon2Params::FAST, &salt).unwrap();
        assert_eq!(&a[..], &b[..]);
        let c = derive_master_key(b"other", &Argon2Params::FAST, &salt).unwrap();
        assert_ne!(&a[..], &c[..]);
    }
}
