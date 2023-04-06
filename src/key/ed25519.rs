use super::conversion::{PublicKeyFrom, SecretKeyFrom, TryPublicKeyFrom, TrySecretKeyFrom};
use super::generics::{GenerateEphemeralKey, Key, KeyExchange};
use crate::KeyError;
use rand_core::OsRng;
use sha2::{Digest, Sha512};

#[cfg(feature = "ECIES-MAC")]
use crate::markers::{EciesMacDecryptionSupport, EciesMacEncryptionSupport};
#[cfg(feature = "ECIES-MAC")]
impl EciesMacEncryptionSupport for Ed25519 {}
#[cfg(feature = "ECIES-MAC")]
impl EciesMacDecryptionSupport for Ed25519 {}

#[cfg(feature = "ECIES-AEAD")]
use crate::markers::{EciesAeadDecryptionSupport, EciesAeadEncryptionSupport};
#[cfg(feature = "ECIES-AEAD")]
impl EciesAeadEncryptionSupport for Ed25519 {}
#[cfg(feature = "ECIES-AEAD")]
impl EciesAeadDecryptionSupport for Ed25519 {}

#[cfg(feature = "ECIES-SYN")]
use crate::markers::{EciesSynDecryptionSupport, EciesSynEncryptionSupport};
#[cfg(feature = "ECIES-SYN")]
impl EciesSynEncryptionSupport for Ed25519 {}
#[cfg(feature = "ECIES-SYN")]
impl EciesSynDecryptionSupport for Ed25519 {}

/// Marker for using the `ed25519` algorithm for elliptic curve operations
///
/// ed25519 is provided by [ed25519-dalek](https://crates.io/crates/ed25519-dalek), [x25519-dalek](https://crates.io/crates/x25519-dalek), and [curve25519-dalek](https://crates.io/crates/curve25519-dalek)
pub struct Ed25519(x25519_dalek::PublicKey);

impl PublicKeyFrom<ed25519_dalek::PublicKey> for Ed25519 {
    fn pk_from(x: ed25519_dalek::PublicKey) -> Self {
        let ed25519 = curve25519_dalek::edwards::CompressedEdwardsY(x.to_bytes());
        let x25519 = ed25519
            .decompress()
            .ok_or(KeyError::BadData)
            .expect("The compressed point is invalid")
            .to_montgomery();
        let x = x25519_dalek::PublicKey::from(x25519.to_bytes());

        Self(x)
    }
}

impl TryPublicKeyFrom<[u8; 32]> for Ed25519 {
    fn try_pk_from(x: [u8; 32]) -> Result<Self, KeyError> {
        let ed25519 = curve25519_dalek::edwards::CompressedEdwardsY(x);
        let x25519 = ed25519
            .decompress()
            .ok_or(KeyError::BadData)?
            .to_montgomery();
        let x = x25519_dalek::PublicKey::from(x25519.to_bytes());

        Ok(Self(x))
    }
}

impl TryPublicKeyFrom<&[u8]> for Ed25519 {
    fn try_pk_from(x: &[u8]) -> Result<Self, KeyError> {
        let bytes: [u8; 32] = x.try_into().map_err(|_| KeyError::BadData)?;
        Self::try_pk_from(bytes)
    }
}

impl TryPublicKeyFrom<Vec<u8>> for Ed25519 {
    fn try_pk_from(x: Vec<u8>) -> Result<Self, KeyError> {
        Self::try_pk_from(x.as_slice())
    }
}

impl SecretKeyFrom<ed25519_dalek::SecretKey> for Ed25519 {
    fn sk_from(x: ed25519_dalek::SecretKey) -> Self::SecretKey {
        let hash: [u8; 32] = Sha512::digest(x.as_bytes()).as_slice()[..32]
            .try_into()
            .expect("Hashing error");
        x25519_dalek::StaticSecret::from(hash)
    }
}

impl SecretKeyFrom<x25519_dalek::StaticSecret> for Ed25519 {
    fn sk_from(x: x25519_dalek::StaticSecret) -> Self::SecretKey {
        x
    }
}

impl SecretKeyFrom<[u8; 32]> for Ed25519 {
    fn sk_from(x: [u8; 32]) -> Self::SecretKey {
        let hash: [u8; 32] = Sha512::digest(x.as_slice()).as_slice()[..32]
            .try_into()
            .expect("Hashing error");
        x25519_dalek::StaticSecret::from(hash)
    }
}

impl TrySecretKeyFrom<&[u8]> for Ed25519 {
    fn try_sk_from(x: &[u8]) -> Result<Self::SecretKey, KeyError> {
        let bytes: [u8; 32] = x.try_into().map_err(|_| KeyError::BadData)?;
        Ok(Self::sk_from(bytes))
    }
}

impl TrySecretKeyFrom<Vec<u8>> for Ed25519 {
    fn try_sk_from(x: Vec<u8>) -> Result<Self::SecretKey, KeyError> {
        Self::try_sk_from(x.as_slice())
    }
}

impl Key for Ed25519 {
    const EC_PUBLIC_KEY_LEN: usize = 32;
    type SecretKey = x25519_dalek::StaticSecret;

    fn as_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    fn from_bytes(x: &[u8]) -> Self {
        let fixed_arr: [u8; 32] = x.try_into().expect("invalid length");
        Self(x25519_dalek::PublicKey::from(fixed_arr))
    }
}

impl GenerateEphemeralKey for Ed25519 {
    fn get_ephemeral_key() -> (Self, Self::SecretKey) {
        let sk = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        (Self(x25519_dalek::PublicKey::from(&sk)), sk)
    }
}

impl KeyExchange for Ed25519 {
    fn key_exchange(&self, sk: Self::SecretKey) -> Vec<u8> {
        sk.diffie_hellman(&self.0).to_bytes().to_vec()
    }
}
