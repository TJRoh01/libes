#[cfg(feature = "ECIES-MAC")]
pub trait EciesMacSupport {}

#[cfg(feature = "ECIES-AEAD")]
pub trait EciesAeadSupport {}

#[cfg(feature = "ECIES-SYN")]
pub trait EciesSynSupport {}