pub struct Aead;
pub struct Syn;

mod hmacsha256;
pub use hmacsha256::HmacSha256;

pub trait Mac {
    const MAC_KEY_LEN: usize;
    const MAC_LEN: usize;

    fn digest(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Vec<u8>;
    fn verify(key: &[u8], nonce: &[u8], ciphertext: &[u8], tag: &[u8]) -> bool;
}

impl<M: Mac> SplitMacKey for M {}

pub trait SplitMacKey: Mac {
    fn get_mac_key(x: &mut Vec<u8>) -> Vec<u8> {
        x.drain(..Self::MAC_KEY_LEN).collect()
    }
}

impl<M: Mac> SplitMac for M {}

pub trait SplitMac: Mac {
    fn get_mac(x: &mut Vec<u8>) -> Vec<u8> {
        x.drain(..Self::MAC_LEN).collect()
    }
}