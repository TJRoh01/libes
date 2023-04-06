//! Markers for Elliptic Curve algorithms supported by `libes`

use generics::Key;

/// A value -> `PublicKey` conversion that consumes the input value. The opposite of [IntoPublicKey].
pub trait PublicKeyFrom<T>: Key {
    fn pk_from(x: T) -> Self;
}

/// A value -> `PublicKey` conversion that consumes the input value. The opposite of [PublicKeyFrom].
pub trait IntoPublicKey<U: Key> {
    fn into_pk(self) -> U;
}

impl<T, U> IntoPublicKey<U> for T
    where
        U: PublicKeyFrom<T>
{
    fn into_pk(self) -> U {
        U::pk_from(self)
    }
}

/// A value -> `SecretKey` conversion that consumes the input value. The opposite of [IntoSecretKey].
pub trait SecretKeyFrom<T>: Key {
    fn sk_from(x: T) -> Self::SecretKey;
}

/// A value -> `SecretKey` conversion that consumes the input value. The opposite of [SecretKeyFrom].
pub trait IntoSecretKey<U: Key> {
    fn into_sk(self) -> U::SecretKey;
}

impl<T, U> IntoSecretKey<U> for T
where
    U: SecretKeyFrom<T>
{
    fn into_sk(self) -> U::SecretKey {
        U::sk_from(self)
    }
}

pub(crate) mod generics;

#[cfg(feature = "x25519")]
mod x25519;
#[cfg(feature = "x25519")]
pub use x25519::X25519;
use crate::key::generics::Key;