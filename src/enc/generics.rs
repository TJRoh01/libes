use rand_core::{OsRng, RngCore};

pub trait Encryption {
    const ENC_KEY_LEN: usize;
    const ENC_NONCE_LEN: usize;

    fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Vec<u8>;
    fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ()>;
}

impl<E: Encryption> GenNonce for E {}

pub trait GenNonce: Encryption {
    fn get_nonce() -> Vec<u8> {
        let mut buf = vec![0u8; Self::ENC_NONCE_LEN];

        OsRng.fill_bytes(&mut buf);
        buf
    }
}

impl<E: Encryption> SplitNonce for E {}

pub trait SplitNonce: Encryption {
    fn get_nonce(x: &mut Vec<u8>) -> Vec<u8> {
        x.drain(..Self::ENC_NONCE_LEN).collect()
    }
}

impl<E: Encryption> SplitEncKey for E {}

pub trait SplitEncKey: Encryption {
    fn get_enc_key(x: &mut Vec<u8>) -> Vec<u8> {
        x.drain(..Self::ENC_KEY_LEN).collect()
    }
}
