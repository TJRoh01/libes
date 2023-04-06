use rand_core::OsRng;
use x25519_dalek::StaticSecret;
use super::{SecretKeyFrom, generics::{Key, GenerateEphemeralKey, KeyExchange}};

#[cfg(feature = "ECIES-MAC")]
use crate::markers::EciesMacSupport;
#[cfg(feature = "ECIES-MAC")]
impl EciesMacSupport for X25519 {}

#[cfg(feature = "ECIES-AEAD")]
use crate::markers::EciesAeadSupport;
#[cfg(feature = "ECIES-AEAD")]
impl EciesAeadSupport for X25519 {}

#[cfg(feature = "ECIES-SYN")]
use crate::markers::EciesSynSupport;
#[cfg(feature = "ECIES-SYN")]
impl EciesSynSupport for X25519 {}

pub struct X25519(x25519_dalek::PublicKey);

impl From<[u8; 32]> for X25519 {
    fn from(x: [u8; 32]) -> Self { Self(x25519_dalek::PublicKey::from(x)) }
}

impl From<&[u8]> for X25519 {
    fn from(x: &[u8]) -> Self {
        let bytes: [u8; 32] = x.try_into().unwrap();
        bytes.into()
    }
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

impl SecretKeyFrom<[u8; 32]> for X25519 {
    fn sk_from(x: [u8; 32]) -> Self::SecretKey {
        x25519_dalek::StaticSecret::from(x)
    }
}

impl SecretKeyFrom<&[u8]> for X25519 {
    fn sk_from(x: &[u8]) -> Self::SecretKey {
        let bytes: [u8; 32] = x.try_into().unwrap();
        bytes.into()
    }
}

impl SecretKeyFrom<Vec<u8>> for X25519 {
    fn sk_from(x: Vec<u8>) -> Self::SecretKey {
        let bytes: [u8; 32] = x.try_into().unwrap();
        bytes.into()
    }
}


impl SecretKeyFrom<x25519_dalek::StaticSecret> for X25519 {
    fn sk_from(x: StaticSecret) -> Self::SecretKey { x }
}

impl Key for X25519 {
    const EC_KEY_LEN: usize = 32;
    type SecretKey = x25519_dalek::StaticSecret;

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl GenerateEphemeralKey for X25519 {
    fn get_ephemeral_key() -> (Self, Self::SecretKey) {
        let sk = x25519_dalek::StaticSecret::new(OsRng);
        (Self(x25519_dalek::PublicKey::from(&sk)), sk)
    }
}

impl KeyExchange for X25519 {
    fn key_exchange(&self, sk: Self::SecretKey) -> Vec<u8> {
        sk.diffie_hellman(&self.0).to_bytes().to_vec()
    }
}