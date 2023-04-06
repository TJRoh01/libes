//! Markers for Authentication algorithms supported by `libes`

pub(crate) mod generics;

#[cfg(feature = "ECIES-AEAD")]
/// Marker for using the `ECIES-AEAD` variant for authentication
pub struct Aead;

#[cfg(feature = "ECIES-SYN")]
/// Marker for using the `ECIES-SYN` variant for authentication
pub struct Syn;

#[cfg(all(feature = "ECIES-MAC", feature = "HMAC-SHA256"))]
mod hmacsha256;
#[cfg(all(feature = "ECIES-MAC", feature = "HMAC-SHA256"))]
pub use hmacsha256::HmacSha256;
