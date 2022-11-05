use crate::Error;

pub trait Mac {
    const MAC_KEY_LEN: usize;
    const MAC_LEN: usize;

    fn digest(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error>;
    fn verify(key: &[u8], nonce: &[u8], ciphertext: &[u8], tag: &[u8]) -> Result<(), Error>;
}

impl<M: Mac> SplitMacKey for M {}

pub trait SplitMacKey: Mac {
    fn get_mac_key(x: &mut Vec<u8>) -> Result<Vec<u8>, Error> {
        if x.len() < Self::MAC_KEY_LEN {
            return Err(Error::BadData)
        }

        Ok(x.drain(..Self::MAC_KEY_LEN).collect())
    }
}

impl<M: Mac> SplitMac for M {}

pub trait SplitMac: Mac {
    fn get_mac(x: &mut Vec<u8>) -> Result<Vec<u8>, Error> {
        if x.len() < Self::MAC_LEN {
            return Err(Error::BadData)
        }

        Ok(x.drain(..Self::MAC_LEN).collect())
    }
}
