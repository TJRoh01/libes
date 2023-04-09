//! Markers for Elliptic Curve algorithms supported by `libes`

pub mod conversion;
pub(crate) mod generics;

#[cfg(feature = "x25519")]
mod x25519;
#[cfg(feature = "x25519")]
pub use x25519::X25519;

#[cfg(feature = "ed25519")]
mod ed25519;
#[cfg(feature = "ed25519")]
pub use ed25519::Ed25519;

#[cfg(feature = "secp256r1")]
mod secp256r1;

#[cfg(feature = "secp256r1")]
pub use secp256r1::Secp256r1;

#[cfg(feature = "secp256k1")]
mod secp256k1;

#[cfg(feature = "secp256k1")]
pub use secp256k1::Secp256k1;