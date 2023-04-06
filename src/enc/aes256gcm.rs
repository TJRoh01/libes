use super::generics::Encryption;
use crate::EciesError;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::KeyInit;

#[cfg(feature = "ECIES-MAC")]
use crate::markers::{EciesMacDecryptionSupport, EciesMacEncryptionSupport};
#[cfg(feature = "ECIES-MAC")]
impl EciesMacEncryptionSupport for Aes256Gcm {}
#[cfg(feature = "ECIES-MAC")]
impl EciesMacDecryptionSupport for Aes256Gcm {}

#[cfg(feature = "ECIES-AEAD")]
use crate::markers::{EciesAeadDecryptionSupport, EciesAeadEncryptionSupport};
#[cfg(feature = "ECIES-AEAD")]
impl EciesAeadEncryptionSupport for Aes256Gcm {}
#[cfg(feature = "ECIES-AEAD")]
impl EciesAeadDecryptionSupport for Aes256Gcm {}

#[cfg(feature = "ECIES-SYN")]
use crate::markers::{EciesSynDecryptionSupport, EciesSynEncryptionSupport};
#[cfg(feature = "ECIES-SYN")]
impl EciesSynEncryptionSupport for Aes256Gcm {}
#[cfg(feature = "ECIES-SYN")]
impl EciesSynDecryptionSupport for Aes256Gcm {}

/// Marker for using the `AES256-GCM` algorithm for encryption
///
/// AES256-GCM is provided by [aes-gcm](https://crates.io/crates/aes-gcm)
pub struct Aes256Gcm;

impl Encryption for Aes256Gcm {
    const ENCRYPTION_KEY_LEN: usize = 32;
    const ENCRYPTION_NONCE_LEN: usize = 12;

    fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, EciesError> {
        let enc = aes_gcm::Aes256Gcm::new_from_slice(key)
            .map_err(|_| EciesError::BadData)?;

        enc.encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad: b"",
            },
        )
            .map_err(|_| EciesError::EncryptionError)
    }

    fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, EciesError> {
        let dec = aes_gcm::Aes256Gcm::new_from_slice(key)
            .map_err(|_| EciesError::BadData)?;

        dec.decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad: b"",
            },
        )
            .map_err(|_| EciesError::DecryptionError)
    }
}
