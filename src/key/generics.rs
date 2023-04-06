use crate::EciesError;
use hkdf::Hkdf;
use sha2::Sha256;

// Elliptic curve key implementation
pub trait Key {
    const EC_PUBLIC_KEY_LEN: usize;
    type SecretKey;

    fn as_bytes(&self) -> &[u8];
    fn from_bytes(x: &[u8]) -> Self;
}

// ECDH key exchange implementation
pub trait KeyExchange: Key {
    fn key_exchange(&self, sk: Self::SecretKey) -> Vec<u8>;
}

// Provide ephemeral key pair from a CSPRNG
pub trait GenerateEphemeralKey: Key + Sized {
    fn get_ephemeral_key() -> (Self, Self::SecretKey);
}

impl<K: Key> TakeEphemeralKey for K {}

// Provide public ephemeral key by taking it from the front of some data
pub trait TakeEphemeralKey: Key + Sized {
    fn get_ephemeral_key(x: &mut Vec<u8>) -> Result<Self, EciesError> {
        if x.len() < Self::EC_PUBLIC_KEY_LEN {
            return Err(EciesError::BadData);
        }

        Ok(Self::from_bytes(
            &x.drain(..Self::EC_PUBLIC_KEY_LEN).collect::<Vec<u8>>(),
        ))
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
