use crate::{Ecies, Encryption};

pub struct XChaCha20Poly1305;

impl<K, M> Encryption for Ecies<K, XChaCha20Poly1305, M> {
    const ENC_KEY_LEN: usize = 32;
    const ENC_NONCE_LEN: usize = 24;
}