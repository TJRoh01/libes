use crate::EciesError;
use rand_core::{OsRng, RngCore};

// Symmetric encryption implementation
pub trait Encryption {
    const ENCRYPTION_KEY_LEN: usize;
    const ENCRYPTION_NONCE_LEN: usize;

    fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, EciesError>;
    fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, EciesError>;
}

impl<E: Encryption> GenerateNonce for E {}

// Provide nonce from a CSPRNG
pub trait GenerateNonce: Encryption {
    fn get_nonce() -> Vec<u8> {
        let mut buf = vec![0u8; Self::ENCRYPTION_NONCE_LEN];
        OsRng.fill_bytes(&mut buf);

        buf
    }
}

impl<E: Encryption> TakeNonce for E {}

// Provide nonce by taking it from the front of some data
pub trait TakeNonce: Encryption {
    fn get_nonce(x: &mut Vec<u8>) -> Result<Vec<u8>, EciesError> {
        if x.len() < Self::ENCRYPTION_NONCE_LEN {
            return Err(EciesError::BadData);
        }

        Ok(x.drain(..Self::ENCRYPTION_NONCE_LEN).collect())
    }
}

impl<E: Encryption> TakeEncryptionKey for E {}

// Provide encryption key by taking it from the front of some data
pub trait TakeEncryptionKey: Encryption {
    fn get_encryption_key(x: &mut Vec<u8>) -> Result<Vec<u8>, EciesError> {
        if x.len() < Self::ENCRYPTION_KEY_LEN {
            return Err(EciesError::BadData);
        }

        Ok(x.drain(..Self::ENCRYPTION_KEY_LEN).collect())
    }
}
