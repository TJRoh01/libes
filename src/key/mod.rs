//! Markers for Elliptic Curve algorithms supported by `libes`

pub(crate) mod generics;
use generics::Key;

#[cfg(feature = "x25519")]
mod x25519;
#[cfg(feature = "x25519")]
pub use x25519::X25519;


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
        U: TryPublicKeyFrom<T>
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
    U: TrySecretKeyFrom<T>
{
    fn try_into_sk(self) -> Result<U::SecretKey, ()> {
        U::try_sk_from(self)
    }
}