//! Markers for Encryption algorithms supported by `libes`

pub(crate) mod generics;

#[cfg(feature = "XChaCha20-Poly1305")]
mod xchacha20poly1305;
#[cfg(feature = "XChaCha20-Poly1305")]
pub use xchacha20poly1305::XChaCha20Poly1305;
