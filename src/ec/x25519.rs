use rand_core::OsRng;
use crate::{Ecies, GenerateEphemeralKey, KeyExchange};

pub struct X25519(x25519_dalek::PublicKey);

impl<E, M> GenerateEphemeralKey for Ecies<X25519, E, M> {
    type EphemeralPublicKey = x25519_dalek::PublicKey;
    type EphemeralSecretKey = x25519_dalek::EphemeralSecret;

    fn generate_ephemeral_key() -> (Self::EphemeralPublicKey, Self::EphemeralSecretKey) {
        let sk = x25519_dalek::EphemeralSecret::new(OsRng);
        (x25519_dalek::PublicKey::from(&sk), sk)
    }
}

impl<E, M> KeyExchange for Ecies<X25519, E, M> {
    type EphemeralSecretKey = x25519_dalek::EphemeralSecret;

    fn key_exchange(&self, ephemeral_sk: Self::EphemeralSecretKey) -> Vec<u8> {
        ephemeral_sk.diffie_hellman(&self.recipient_public_key.0).to_bytes().to_vec()
    }
}

impl From<[u8; 32]> for X25519 {
    fn from(x: [u8; 32]) -> Self { Self(x25519_dalek::PublicKey::from(x)) }
}