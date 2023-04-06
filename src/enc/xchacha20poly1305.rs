use chacha20poly1305::KeyInit;
use chacha20poly1305::aead::{Aead, Payload};
use super::generics::{Encryption, SynCompatible};

pub struct XChaCha20Poly1305;

impl SynCompatible for XChaCha20Poly1305 {}

impl Encryption for XChaCha20Poly1305 {
    const ENC_KEY_LEN: usize = 32;
    const ENC_NONCE_LEN: usize = 24;

    fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let enc = chacha20poly1305::XChaCha20Poly1305::new_from_slice(key).unwrap();
        enc.encrypt(nonce.into(), Payload { msg: plaintext, aad: b"" }).unwrap()
    }

    fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Vec<u8> {
        let dec = chacha20poly1305::XChaCha20Poly1305::new_from_slice(key).unwrap();
        dec.decrypt(nonce.into(), Payload { msg: ciphertext, aad: b"" }).unwrap()
    }
}