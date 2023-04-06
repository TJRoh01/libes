//! Markers for Elliptic Curve algorithms supported by `libes`

pub(crate) mod generics;

#[cfg(feature = "x25519")]
mod x25519;

#[cfg_attr(doc_cfg, doc(cfg(feature = "x25519")))]
#[cfg(feature = "x25519")]
pub use x25519::X25519;
