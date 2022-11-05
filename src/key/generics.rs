use super::conversion::TryPublicKeyFrom;
use crate::EciesError;
use hkdf::Hkdf;
use sha2::Sha256;

// Elliptic curve key implementation
pub trait Key {
    const EC_KEY_LEN: usize;
    type SecretKey;

    fn as_bytes(&self) -> &[u8];
}

// ECDH key exchange implementation
pub trait KeyExchange: Key {
    fn key_exchange(&self, sk: Self::SecretKey) -> Vec<u8>;
}

// Provide ephemeral key pair from a CSPRNG
pub trait GenerateEphemeralKey: Key + Sized {
    fn get_ephemeral_key() -> (Self, Self::SecretKey);
}

impl<K: TryPublicKeyFrom<Vec<u8>> + Key> TakeEphemeralKey for K {}

// Provide public ephemeral key by taking it from the front of some data
pub trait TakeEphemeralKey: TryPublicKeyFrom<Vec<u8>> + Key + Sized {
    fn get_ephemeral_key(x: &mut Vec<u8>) -> Result<Self, EciesError> {
        if x.len() < Self::EC_KEY_LEN {
            return Err(EciesError::BadData);
        }

        Self::try_pk_from(x.drain(..Self::EC_KEY_LEN).collect::<Vec<u8>>())
            .map_err(|_| EciesError::BadData)
    }
}

impl<K: Key> DeriveKeyMaterial for K {}

// Provide key material by applying HKDF to some initial key material
pub trait DeriveKeyMaterial: Key {
    fn derive_key_material(&self, mut shared_secret: Vec<u8>, len: usize) -> Vec<u8> {
        // Tie the shared secret to self, usually ephemeral_pk,
        // to encapsulate self in the Derived Key Material
        shared_secret.extend_from_slice(self.as_bytes());

        let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_slice());
        let mut out = vec![0u8; len];

        hkdf.expand(b"", &mut out)
            .expect("Could not derive enough Key Material");

        out.to_vec()
    }
}
