use hkdf::Hkdf;
use sha2::Sha256;

/// Attempt a value -> `PublicKey` conversion that consumes the input value. The opposite of [TryIntoPublicKey].
pub trait TryPublicKeyFrom<T>: Key + Sized {
    fn try_pk_from(x: T) -> Result<Self, ()>;
}

/// Attempt a value -> `PublicKey` conversion that consumes the input value. The opposite of [TryPublicKeyFrom].
pub trait TryIntoPublicKey<U: Key> {
    fn try_into_pk(self) -> Result<U, ()>;
}

impl<T, U> TryIntoPublicKey<U> for T
where
    U: TryPublicKeyFrom<T>,
{
    fn try_into_pk(self) -> Result<U, ()> {
        U::try_pk_from(self)
    }
}

/// Attempt a value -> `SecretKey` conversion that consumes the input value. The opposite of [TryIntoSecretKey].
pub trait TrySecretKeyFrom<T>: Key {
    fn try_sk_from(x: T) -> Result<Self::SecretKey, ()>;
}

/// Attempt a value -> `SecretKey` conversion that consumes the input value. The opposite of [TrySecretKeyFrom].
pub trait TryIntoSecretKey<U: Key> {
    fn try_into_sk(self) -> Result<U::SecretKey, ()>;
}

impl<T, U> TryIntoSecretKey<U> for T
where
    U: TrySecretKeyFrom<T>,
{
    fn try_into_sk(self) -> Result<U::SecretKey, ()> {
        U::try_sk_from(self)
    }
}

pub trait Key {
    const EC_KEY_LEN: usize;
    type SecretKey;

    fn as_bytes(&self) -> &[u8];
}

pub trait GenerateEphemeralKey: Key + Sized {
    fn get_ephemeral_key() -> (Self, Self::SecretKey);
}

impl<K: TryPublicKeyFrom<Vec<u8>> + Key> SplitEphemeralKey for K {}

pub trait SplitEphemeralKey: TryPublicKeyFrom<Vec<u8>> + Key + Sized {
    fn get_ephemeral_key(x: &mut Vec<u8>) -> Self {
        Self::try_pk_from(x.drain(..Self::EC_KEY_LEN).collect::<Vec<u8>>()).unwrap()
    }
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

        hkdf.expand(b"", &mut out)
            .expect("Could not derive enough Key Material");

        out.to_vec()
    }
}
