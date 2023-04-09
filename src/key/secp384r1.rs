use p384::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use super::conversion::{PublicKeyFrom, SecretKeyFrom, TryPublicKeyFrom};
use super::generics::{GenerateEphemeralKey, Key, KeyExchange};
use crate::KeyError;
use rand_core::OsRng;
use crate::key::conversion::SecretKeyFromRef;

#[cfg(feature = "ECIES-MAC")]
use crate::markers::{EciesMacDecryptionSupport, EciesMacEncryptionSupport};
#[cfg(feature = "ECIES-MAC")]
impl EciesMacEncryptionSupport for Secp384r1 {}
#[cfg(feature = "ECIES-MAC")]
impl EciesMacDecryptionSupport for Secp384r1 {}

#[cfg(feature = "ECIES-AEAD")]
use crate::markers::{EciesAeadDecryptionSupport, EciesAeadEncryptionSupport};
#[cfg(feature = "ECIES-AEAD")]
impl EciesAeadEncryptionSupport for Secp384r1 {}
#[cfg(feature = "ECIES-AEAD")]
impl EciesAeadDecryptionSupport for Secp384r1 {}

#[cfg(feature = "ECIES-SYN")]
use crate::markers::{EciesSynDecryptionSupport, EciesSynEncryptionSupport};
#[cfg(feature = "ECIES-SYN")]
impl EciesSynEncryptionSupport for Secp384r1 {}
#[cfg(feature = "ECIES-SYN")]
impl EciesSynDecryptionSupport for Secp384r1 {}

/// Marker for using the `P-384/secp384r1` algorithm for elliptic curve operations
///
/// P-384/secp384r1 is provided by [p384](https://crates.io/crates/p384)
pub struct Secp384r1(p384::PublicKey);

impl PublicKeyFrom<p384::PublicKey> for Secp384r1 {
    fn pk_from(x: p384::PublicKey) -> Self {
        Self(x)
    }
}

impl PublicKeyFrom<[u8; 49]> for Secp384r1 {
    fn pk_from(x: [u8; Self::EC_PUBLIC_KEY_LEN]) -> Self {
        Self(p384::PublicKey::from_encoded_point(&p384::EncodedPoint::from_bytes(x).expect("key initialization error")).unwrap())
    }
}

impl TryPublicKeyFrom<&[u8]> for Secp384r1 {
    fn try_pk_from(x: &[u8]) -> Result<Self, KeyError> {
        let bytes: [u8; Self::EC_PUBLIC_KEY_LEN] = x.try_into().map_err(|_| KeyError::BadData)?;
        Ok(Self::pk_from(bytes))
    }
}

impl TryPublicKeyFrom<Vec<u8>> for Secp384r1 {
    fn try_pk_from(x: Vec<u8>) -> Result<Self, KeyError> {
        Self::try_pk_from(x.as_slice())
    }
}

impl SecretKeyFrom<p384::ecdh::EphemeralSecret> for Secp384r1 {
    fn sk_from(x: p384::ecdh::EphemeralSecret) -> Self::SecretKey {
        x
    }
}

impl SecretKeyFromRef<p384::ecdh::EphemeralSecret> for Secp384r1 {
    fn sk_from_ref(x: &p384::ecdh::EphemeralSecret) -> &Self::SecretKey {
        x
    }
}

impl Key for Secp384r1 {
    const EC_PUBLIC_KEY_LEN: usize = 49;
    type SecretKey = p384::ecdh::EphemeralSecret;

    fn as_bytes(&self) -> Vec<u8> {
        self.0.to_encoded_point(true).as_bytes().to_vec()
    }

    fn from_bytes(x: &[u8]) -> Self {
        let fixed_arr: [u8; Self::EC_PUBLIC_KEY_LEN] = x.try_into().expect("invalid length");
        Self(p384::PublicKey::from_encoded_point(&p384::EncodedPoint::from_bytes(fixed_arr).expect("key initialization error")).unwrap())
    }
}

impl GenerateEphemeralKey for Secp384r1 {
    fn get_ephemeral_key() -> (Self, Self::SecretKey) {
        let sk = Self::SecretKey::random(&mut OsRng);
        (Self(sk.public_key()), sk)
    }
}

impl KeyExchange for Secp384r1 {
    fn key_exchange(&self, sk: &Self::SecretKey) -> Vec<u8> {
        sk.diffie_hellman(&self.0).raw_secret_bytes().to_vec()
    }
}