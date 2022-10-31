pub trait SecretKeyFrom<T>: Key {
    fn sk_from(x: T) -> Self::SecretKey;
}

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