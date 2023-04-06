use rand_core::OsRng;
use super::{TryPublicKeyFrom, TrySecretKeyFrom, generics::{Key, GenerateEphemeralKey, KeyExchange}};

#[cfg(feature = "ECIES-MAC")]
use crate::markers::{EciesMacEncryptionSupport, EciesMacDecryptionSupport};
#[cfg(feature = "ECIES-MAC")]
impl EciesMacEncryptionSupport for X25519 {}
#[cfg(feature = "ECIES-MAC")]
impl EciesMacDecryptionSupport for X25519 {}

#[cfg(feature = "ECIES-AEAD")]
use crate::markers::{EciesAeadEncryptionSupport, EciesAeadDecryptionSupport};
#[cfg(feature = "ECIES-AEAD")]
impl EciesAeadEncryptionSupport for X25519 {}
#[cfg(feature = "ECIES-AEAD")]
impl EciesAeadDecryptionSupport for X25519 {}

#[cfg(feature = "ECIES-SYN")]
use crate::markers::{EciesSynEncryptionSupport, EciesSynDecryptionSupport};
#[cfg(feature = "ECIES-SYN")]
impl EciesSynEncryptionSupport for X25519 {}
#[cfg(feature = "ECIES-SYN")]
impl EciesSynDecryptionSupport for X25519 {}

/// Marker for using the `x25519` algorithm for elliptic curve operations
///
/// x25519 is provided by [x25519-dalek](https://crates.io/crates/x25519-dalek)
pub struct X25519(x25519_dalek::PublicKey);

impl TryPublicKeyFrom<[u8; 32]> for X25519 {
    fn try_pk_from(x: [u8; 32]) -> Result<Self, ()> {
        Ok(Self(x25519_dalek::PublicKey::from(x)))
    }
}

impl TryPublicKeyFrom<&[u8]> for X25519 {
    fn try_pk_from(x: &[u8]) -> Result<Self, ()> {
        let bytes: [u8; 32] = x.try_into().map_err(|_| ())?;
        X25519::try_pk_from(bytes)
    }
}

impl TryPublicKeyFrom<Vec<u8>> for X25519 {
    fn try_pk_from(x: Vec<u8>) -> Result<Self, ()> {
        let bytes: [u8; 32] = x.try_into().map_err(|_| ())?;
        X25519::try_pk_from(bytes)
    }
}

impl TryPublicKeyFrom<x25519_dalek::PublicKey> for X25519 {
    fn try_pk_from(x: x25519_dalek::PublicKey) -> Result<Self, ()> { Ok(Self(x)) }
}

impl TrySecretKeyFrom<[u8; 32]> for X25519 {
    fn try_sk_from(x: [u8; 32]) -> Result<Self::SecretKey, ()> {
        Ok(x25519_dalek::StaticSecret::from(x))
    }
}

impl TrySecretKeyFrom<&[u8]> for X25519 {
    fn try_sk_from(x: &[u8]) -> Result<Self::SecretKey, ()> {
        let bytes: [u8; 32] = x.try_into().map_err(|_| ())?;
        X25519::try_sk_from(bytes)
    }
}

impl TrySecretKeyFrom<Vec<u8>> for X25519 {
    fn try_sk_from(x: Vec<u8>) -> Result<Self::SecretKey, ()> {
        let bytes: [u8; 32] = x.try_into().map_err(|_| ())?;
        X25519::try_sk_from(bytes)
    }
}

impl TrySecretKeyFrom<x25519_dalek::StaticSecret> for X25519 {
    fn try_sk_from(x: x25519_dalek::StaticSecret) -> Result<Self::SecretKey, ()> { Ok(x) }
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