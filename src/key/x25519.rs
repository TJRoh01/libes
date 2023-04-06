use rand_core::OsRng;
use crate::key::generics::GenericSecretKey;
use super::generics::{Key, GenerateEphemeralKey, KeyExchange};

pub struct X25519(x25519_dalek::PublicKey);

impl From<[u8; 32]> for X25519 {
    fn from(x: [u8; 32]) -> Self { Self(x25519_dalek::PublicKey::from(x)) }
}

impl From<Vec<u8>> for X25519 {
    fn from(x: Vec<u8>) -> Self {
        let bytes: [u8; 32] = x.try_into().unwrap();
        bytes.into()
    }
}

impl From<x25519_dalek::PublicKey> for X25519 {
    fn from(x: x25519_dalek::PublicKey) -> Self { Self(x) }
}

impl From<[u8; 32]> for GenericSecretKey<x25519_dalek::StaticSecret> {
    fn from(x: [u8; 32]) -> Self { Self(x25519_dalek::StaticSecret::from(x)) }
}

impl From<Vec<u8>> for GenericSecretKey<x25519_dalek::StaticSecret> {
    fn from(x: Vec<u8>) -> Self {
        let bytes: [u8; 32] = x.try_into().unwrap();
        bytes.into()
    }
}

impl From<x25519_dalek::StaticSecret> for GenericSecretKey<x25519_dalek::StaticSecret> {
    fn from(x: x25519_dalek::StaticSecret) -> Self { Self(x) }
}

impl Key for X25519 {
    const EC_KEY_LEN: usize = 32;
    type SecretKey = x25519_dalek::StaticSecret;

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl GenerateEphemeralKey for X25519 {
    fn get_ephemeral_key() -> (Self, GenericSecretKey<Self::SecretKey>) {
        let sk = x25519_dalek::StaticSecret::new(OsRng);
        (Self(x25519_dalek::PublicKey::from(&sk)), GenericSecretKey(sk))
    }
}

impl KeyExchange for X25519 {
    fn key_exchange(&self, sk: GenericSecretKey<Self::SecretKey>) -> Vec<u8> {
        sk.0.diffie_hellman(&self.0).to_bytes().to_vec()
    }
}