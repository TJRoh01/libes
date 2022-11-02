use super::generics::Mac;
use hmac::{Hmac, Mac as _};
use sha2::Sha256;

/// Marker for using the `ECIES-MAC` variant with the `HMAC-SHA256` algorithm for authentication
///
/// HMAC-SHA256 is provided by [hmac](https://crates.io/crates/hmac) and [sha2](https://crates.io/crates/sha2)
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

    fn verify(key: &[u8], nonce: &[u8], ciphertext: &[u8], tag: &[u8]) -> Result<(), ()> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();

        mac.update(nonce);
        mac.update(ciphertext);

        mac.verify_slice(tag).map_err(|_| ())
    }
}
