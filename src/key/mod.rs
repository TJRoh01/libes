mod x25519;

use hkdf::Hkdf;
use sha2::Sha256;
pub use x25519::X25519;

pub trait Key {
    const EC_KEY_LEN: usize;
    type SecretKey;

    fn as_bytes(&self) -> &[u8];
}

pub trait GenerateEphemeralKey: Key + Sized {
    fn get_ephemeral_key() -> (Self, Self::SecretKey);
}

impl<K: Key> SplitEphemeralKey for K
where
    K: From<Vec<u8>>
{
    fn get_ephemeral_key(x: &mut Vec<u8>) -> Self {
        x.drain(..Self::EC_KEY_LEN).collect::<Vec<u8>>().into()
    }
}

pub trait SplitEphemeralKey: Key + Sized {
    fn get_ephemeral_key(x: &mut Vec<u8>) -> Self;
}

pub trait KeyExchange: Key {
    fn key_exchange(&self, sk: Self::SecretKey) -> Vec<u8>;
}

impl<K: Key> DeriveKeyMaterial for K {}

pub trait DeriveKeyMaterial: Key {
    fn derive_key_material(&self, mut shared_secret: Vec<u8>, len: usize) -> Vec<u8> {
        // Tie the shared secret to self, usually ephemeral_pk,
        // to encapsulate self in the Derived Key Material
        shared_secret.extend_from_slice(self.as_bytes());

        let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_slice());
        let mut out = vec![0u8; len];

        hkdf.expand(b"", &mut out).expect("Could not derive enough Key Material");
        out.to_vec()
    }
}