use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use super::generics::Mac;

pub struct HmacSha256;

impl Mac for HmacSha256 {
    const MAC_KEY_LEN: usize = 32;
    const MAC_LEN: usize = 32;

    fn digest(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        mac.update(nonce);
        mac.update(ciphertext);

        mac.finalize().into_bytes().as_slice().to_vec()
    }

    fn verify(key: &[u8], nonce: &[u8], ciphertext: &[u8], tag: &[u8]) -> bool {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();

        mac.update(nonce);
        mac.update(ciphertext);

        if let Ok(()) = mac.verify_slice(tag) {
            true
        } else {
            false
        }
    }
}