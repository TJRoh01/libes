use crate::EciesError;

// MAC implementation
pub trait Mac {
    const MAC_LEN: usize;
    const MAC_KEY_LEN: usize;

    fn digest(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, EciesError>;
    fn verify(key: &[u8], nonce: &[u8], ciphertext: &[u8], tag: &[u8]) -> Result<(), EciesError>;
}

impl<M: Mac> TakeMac for M {}

// Provide MAC by taking it from the front of some data
pub trait TakeMac: Mac {
    fn get_mac(x: &mut Vec<u8>) -> Result<Vec<u8>, EciesError> {
        if x.len() < Self::MAC_LEN {
            return Err(EciesError::BadData);
        }

        Ok(x.drain(..Self::MAC_LEN).collect())
    }
}

impl<M: Mac> TakeMacKey for M {}

// Provide MAC key by taking it from the front of some data
pub trait TakeMacKey: Mac {
    fn get_mac_key(x: &mut Vec<u8>) -> Result<Vec<u8>, EciesError> {
        if x.len() < Self::MAC_KEY_LEN {
            return Err(EciesError::BadData);
        }

        Ok(x.drain(..Self::MAC_KEY_LEN).collect())
    }
}
