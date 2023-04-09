use super::conversion::{PublicKeyFrom, SecretKeyFrom, TryPublicKeyFrom, TrySecretKeyFrom};
use super::generics::{GenerateEphemeralKey, Key, KeyExchange};
use crate::KeyError;
use rand_core::OsRng;

#[cfg(feature = "ECIES-MAC")]
use crate::markers::{EciesMacDecryptionSupport, EciesMacEncryptionSupport};
#[cfg(feature = "ECIES-MAC")]
impl EciesMacEncryptionSupport for X25519 {}
#[cfg(feature = "ECIES-MAC")]
impl EciesMacDecryptionSupport for X25519 {}

#[cfg(feature = "ECIES-AEAD")]
use crate::markers::{EciesAeadDecryptionSupport, EciesAeadEncryptionSupport};
#[cfg(feature = "ECIES-AEAD")]
impl EciesAeadEncryptionSupport for X25519 {}
#[cfg(feature = "ECIES-AEAD")]
impl EciesAeadDecryptionSupport for X25519 {}

#[cfg(feature = "ECIES-SYN")]
use crate::markers::{EciesSynDecryptionSupport, EciesSynEncryptionSupport};
#[cfg(feature = "ECIES-SYN")]
impl EciesSynEncryptionSupport for X25519 {}
#[cfg(feature = "ECIES-SYN")]
impl EciesSynDecryptionSupport for X25519 {}

/// Marker for using the `x25519` algorithm for elliptic curve operations
///
/// x25519 is provided by [x25519-dalek](https://crates.io/crates/x25519-dalek)
pub struct X25519(x25519_dalek::PublicKey);

impl PublicKeyFrom<x25519_dalek::PublicKey> for X25519 {
    fn pk_from(x: x25519_dalek::PublicKey) -> Self {
        Self(x)
    }
}

impl PublicKeyFrom<[u8; 32]> for X25519 {
    fn pk_from(x: [u8; 32]) -> Self {
        Self(x25519_dalek::PublicKey::from(x))
    }
}

impl TryPublicKeyFrom<&[u8]> for X25519 {
    fn try_pk_from(x: &[u8]) -> Result<Self, KeyError> {
        let bytes: [u8; 32] = x.try_into().map_err(|_| KeyError::BadData)?;
        Ok(Self::pk_from(bytes))
    }
}

impl TryPublicKeyFrom<Vec<u8>> for X25519 {
    fn try_pk_from(x: Vec<u8>) -> Result<Self, KeyError> {
        Self::try_pk_from(x.as_slice())
    }
}

impl SecretKeyFrom<x25519_dalek::StaticSecret> for X25519 {
    fn sk_from(x: x25519_dalek::StaticSecret) -> Self::SecretKey {
        x
    }
}

impl SecretKeyFrom<[u8; 32]> for X25519 {
    fn sk_from(x: [u8; 32]) -> Self::SecretKey {
        x25519_dalek::StaticSecret::from(x)
    }
}

impl TrySecretKeyFrom<&[u8]> for X25519 {
    fn try_sk_from(x: &[u8]) -> Result<Self::SecretKey, KeyError> {
        let bytes: [u8; 32] = x.try_into().map_err(|_| KeyError::BadData)?;
        Ok(Self::sk_from(bytes))
    }
}

impl TrySecretKeyFrom<Vec<u8>> for X25519 {
    fn try_sk_from(x: Vec<u8>) -> Result<Self::SecretKey, KeyError> {
        Self::try_sk_from(x.as_slice())
    }
}

impl Key for X25519 {
    const EC_PUBLIC_KEY_LEN: usize = 32;
    type SecretKey = x25519_dalek::StaticSecret;

    fn as_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    fn from_bytes(x: &[u8]) -> Self {
        let fixed_arr: [u8; 32] = x.try_into().expect("invalid length");
        Self(x25519_dalek::PublicKey::from(fixed_arr))
    }

    fn from_rng() -> (Self, Self::SecretKey) {
        let sk = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let pk = x25519_dalek::PublicKey::from(&sk);

        (Self(pk), sk)
    }
}

impl GenerateEphemeralKey for X25519 {
    fn get_ephemeral_key() -> (Self, Self::SecretKey) {
        let sk = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        (Self(x25519_dalek::PublicKey::from(&sk)), sk)
    }
}

impl KeyExchange for X25519 {
    fn key_exchange(&self, sk: Self::SecretKey) -> Vec<u8> {
        sk.diffie_hellman(&self.0).to_bytes().to_vec()
    }
}
