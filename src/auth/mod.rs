pub(crate) mod generics;

#[cfg(feature = "ECIES-AEAD")]
pub struct Aead;

#[cfg(feature = "ECIES-SYN")]
pub struct Syn;

#[cfg(all(feature = "ECIES-MAC", feature = "HMAC-SHA256"))]
mod hmacsha256;
#[cfg(all(feature = "ECIES-MAC", feature = "HMAC-SHA256"))]
pub use hmacsha256::HmacSha256;