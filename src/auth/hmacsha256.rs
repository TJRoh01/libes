use crate::{Ecies, Mac};

pub struct HmacSha256;

impl<K, E> Mac for Ecies<K, E, HmacSha256> {
    const MAC_KEY_LEN: usize = 32;
    const DER_NONCE: bool = false;
}