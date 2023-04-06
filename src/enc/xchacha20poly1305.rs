use chacha20poly1305::KeyInit;
use chacha20poly1305::aead::{Aead, Payload};
use super::generics::Encryption;

#[cfg(feature = "ECIES-MAC")]
use crate::markers::{EciesMacEncryptionSupport, EciesMacDecryptionSupport};
#[cfg(feature = "ECIES-MAC")]
impl EciesMacEncryptionSupport for XChaCha20Poly1305 {}
#[cfg(feature = "ECIES-MAC")]
impl EciesMacDecryptionSupport for XChaCha20Poly1305 {}

#[cfg(feature = "ECIES-AEAD")]
use crate::markers::{EciesAeadEncryptionSupport, EciesAeadDecryptionSupport};
#[cfg(feature = "ECIES-AEAD")]
impl EciesAeadEncryptionSupport for XChaCha20Poly1305 {}
#[cfg(feature = "ECIES-AEAD")]
impl EciesAeadDecryptionSupport for XChaCha20Poly1305 {}

#[cfg(feature = "ECIES-SYN")]
use crate::markers::{EciesSynEncryptionSupport, EciesSynDecryptionSupport};
#[cfg(feature = "ECIES-SYN")]
impl EciesSynEncryptionSupport for XChaCha20Poly1305 {}
#[cfg(feature = "ECIES-SYN")]
impl EciesSynDecryptionSupport for XChaCha20Poly1305 {}

/// Marker for using the `XChaCha20-Poly1305` algorithm for encryption
///
/// XChaCha20-Poly1305 is provided by [chacha20poly1305](https://crates.io/crates/chacha20poly1305)
pub struct XChaCha20Poly1305;

impl Encryption for XChaCha20Poly1305 {
    const ENC_KEY_LEN: usize = 32;
    const ENC_NONCE_LEN: usize = 24;

    fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let enc = chacha20poly1305::XChaCha20Poly1305::new_from_slice(key).unwrap();
        enc.encrypt(nonce.into(), Payload { msg: plaintext, aad: b"" }).unwrap()
    }

    fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
        let dec = chacha20poly1305::XChaCha20Poly1305::new_from_slice(key).unwrap();
        dec.decrypt(nonce.into(), Payload { msg: ciphertext, aad: b"" }).map_err(|_| ())
    }
}