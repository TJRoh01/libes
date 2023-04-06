use super::generics::Key;
use crate::KeyError;

/// A value -> `PublicKey` conversion that consumes the input value. The opposite of [IntoPublicKey].
pub trait PublicKeyFrom<T>: Key + Sized {
    fn pk_from(x: T) -> Self;
}

impl<T: Key> PublicKeyFrom<T> for T {
    fn pk_from(x: T) -> Self {
        x
    }
}

/// A value -> `PublicKey` conversion that consumes the input value. The opposite of [PublicKeyFrom].
pub trait IntoPublicKey<U: Key> {
    fn into_pk(self) -> U;
}

impl<T, U> IntoPublicKey<U> for T
where
    U: PublicKeyFrom<T>,
{
    fn into_pk(self) -> U {
        U::pk_from(self)
    }
}

/// Attempt a value -> `PublicKey` conversion that consumes the input value. The opposite of [TryIntoPublicKey].
pub trait TryPublicKeyFrom<T>: Key + Sized {
    fn try_pk_from(x: T) -> Result<Self, KeyError>;
}

/// Attempt a value -> `PublicKey` conversion that consumes the input value. The opposite of [TryPublicKeyFrom].
pub trait TryIntoPublicKey<U: Key> {
    fn try_into_pk(self) -> Result<U, KeyError>;
}

impl<T, U> TryIntoPublicKey<U> for T
where
    U: TryPublicKeyFrom<T>,
{
    fn try_into_pk(self) -> Result<U, KeyError> {
        U::try_pk_from(self)
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
    U: SecretKeyFrom<T>,
{
    fn into_sk(self) -> U::SecretKey {
        U::sk_from(self)
    }
}

/// Attempt a value -> `SecretKey` conversion that consumes the input value. The opposite of [TryIntoSecretKey].
pub trait TrySecretKeyFrom<T>: Key {
    fn try_sk_from(x: T) -> Result<Self::SecretKey, KeyError>;
}

/// Attempt a value -> `SecretKey` conversion that consumes the input value. The opposite of [TrySecretKeyFrom].
pub trait TryIntoSecretKey<U: Key> {
    fn try_into_sk(self) -> Result<U::SecretKey, KeyError>;
}

impl<T, U> TryIntoSecretKey<U> for T
where
    U: TrySecretKeyFrom<T>,
{
    fn try_into_sk(self) -> Result<U::SecretKey, KeyError> {
        U::try_sk_from(self)
    }
}
