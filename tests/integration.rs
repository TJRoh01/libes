use rand_core::OsRng;
use libes;
use libes::auth::HmacSha256;
use libes::Ecies;
use libes::enc::XChaCha20Poly1305;
use libes::key::X25519;

const LOREM_IPSUM: &'static [u8] = include_bytes!("lorem_ipsum.txt");

#[test]
fn x25519_xchachapoly1305_hmacsha256() {
    type X25519XChaCha20Poly1305HmacSha256 = Ecies::<X25519, XChaCha20Poly1305, HmacSha256>;

    let sk = x25519_dalek::StaticSecret::new(OsRng);
    let pk = x25519_dalek::PublicKey::from(&sk);
    let enc = X25519XChaCha20Poly1305HmacSha256::new(pk);

    let ciphertext = enc.encrypt_mac(LOREM_IPSUM);
    let plaintext = X25519XChaCha20Poly1305HmacSha256::decrypt_mac(sk, ciphertext);

    assert_eq!(LOREM_IPSUM, plaintext.as_slice());
}