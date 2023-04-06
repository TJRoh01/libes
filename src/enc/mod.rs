//! Markers for Encryption algorithms supported by `libes`

pub(crate) mod generics;

#[cfg(feature = "ChaCha20-Poly1305")]
mod chacha20poly1305;
#[cfg(feature = "ChaCha20-Poly1305")]
pub use self::chacha20poly1305::ChaCha20Poly1305;

#[cfg(feature = "XChaCha20-Poly1305")]
mod xchacha20poly1305;
#[cfg(feature = "XChaCha20-Poly1305")]
pub use xchacha20poly1305::XChaCha20Poly1305;

#[cfg(feature = "AES256-GCM")]
mod aes256gcm;
#[cfg(feature = "AES256-GCM")]
pub use aes256gcm::Aes256Gcm;
