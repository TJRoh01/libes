//! Support marker traits

#[cfg(feature = "ECIES-MAC")]
/// Implementors of this trait support the `ECIES-MAC` encryption variant
pub trait EciesMacEncryptionSupport {}

#[cfg(feature = "ECIES-MAC")]
/// Implementors of this trait support the `ECIES-MAC` decryption variant
pub trait EciesMacDecryptionSupport {}

#[cfg(feature = "ECIES-AEAD")]
/// Implementors of this trait support the `ECIES-AEAD` encryption variant
pub trait EciesAeadEncryptionSupport {}

#[cfg(feature = "ECIES-AEAD")]
/// Implementors of this trait support the `ECIES-AEAD` decryption variant
pub trait EciesAeadDecryptionSupport {}

#[cfg(feature = "ECIES-SYN")]
/// Implementors of this trait support the `ECIES-SYN` encryption variant
pub trait EciesSynEncryptionSupport {}

#[cfg(feature = "ECIES-SYN")]
/// Implementors of this trait support the `ECIES-SYN` decryption variant
pub trait EciesSynDecryptionSupport {}
