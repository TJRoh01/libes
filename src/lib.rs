use std::marker::PhantomData;
use crate::generics::{DeriveKeyMaterial, GenNonce, SplitEncKey, SplitMacKey};

fn test_zone() {
    type X25519XChaChaPoly1305HmacSha256 = Ecies<ec::X25519, aead::XChaCha20Poly1305, auth::HmacSha256>;

    let a = X25519XChaChaPoly1305HmacSha256::new([0u8; 32]);
    let b = X25519XChaChaPoly1305HmacSha256::generate_ephemeral_key();
    let c = a.key_exchange(b.1);
    let d = X25519XChaChaPoly1305HmacSha256::derive_key_material(c);
    let e = X25519XChaChaPoly1305HmacSha256::get_enc_key(&d);
    let f = X25519XChaChaPoly1305HmacSha256::get_mac_key(&d);
    let g = X25519XChaChaPoly1305HmacSha256::get_nonce();
    // encrypt(key, iv; plaintext) -> ciphertext
    // mac(key; iv, ephemeral_ok, ciphertext; params in this order) -> mac
}

mod generics;
pub mod ec;
pub mod aead;
pub mod enc;
pub mod auth;

pub struct Ecies<K, E, M> {
    recipient_public_key: K,
    key: PhantomData<K>,
    enc: PhantomData<E>,
    mac: PhantomData<M>
}

trait Init<K, E, M> {
    fn new<KeyMaterial: Into<K>>(key_material: KeyMaterial) -> Self;
}

impl<K, E, M> Init<K, E, M> for Ecies<K, E, M> {
    fn new<KeyMaterial: Into<K>>(key_material: KeyMaterial) -> Self {
        Self {
            recipient_public_key: key_material.into(),
            key: PhantomData,
            enc: PhantomData,
            mac: PhantomData
        }
    }
}

trait GenerateEphemeralKey {
    type EphemeralPublicKey;
    type EphemeralSecretKey;

    fn generate_ephemeral_key() -> (Self::EphemeralPublicKey, Self::EphemeralSecretKey);
}

trait KeyExchange {
    type EphemeralSecretKey;

    fn key_exchange(&self, ephemeral_sk: Self::EphemeralSecretKey) -> Vec<u8>;
}

trait Encryption {
    const ENC_KEY_LEN: usize;
    const ENC_NONCE_LEN: usize;
}

trait Mac {
    const MAC_KEY_LEN: usize;
}