use p384::elliptic_curve::sec1::ToEncodedPoint;
use rand_core::OsRng;

use libes::auth::{Aead, HmacSha256, Syn};
use libes::Ecies;
use libes::enc::Aes256Gcm;
use libes::key::conversion::TryPublicKeyFrom;
use libes::key::Secp384r1;

const LOREM_IPSUM: &'static [u8] = include_bytes!("lorem_ipsum.txt");

#[test]
fn secp384r1_aes256gcm_hmacsha256() {
    // Alias Ecies with algorithms
    type Scheme = Ecies<Secp384r1, Aes256Gcm, HmacSha256>;

    // Generate receiver key pair
    let sk = p384::ecdh::EphemeralSecret::random(&mut OsRng);
    let pk = sk.public_key();

    // Emulate transmitting as bytes
    let pk_bytes = pk.to_encoded_point(true).as_bytes().to_vec();

    // Check converting back into keys
    let pk2 = Secp384r1::try_pk_from(pk_bytes).expect("pk is not correct");

    // Instantiate Ecies & Encrypt
    let enc = Scheme::new(pk2);
    let ciphertext = enc.encrypt(LOREM_IPSUM).expect("encryption failed");

    // Decrypt
    let plaintext = Scheme::decrypt(&sk, &ciphertext).expect("decryption failed");

    assert_eq!(LOREM_IPSUM.to_vec(), plaintext);
}

#[test]
fn secp384r1_aes256gcm_aead() {
    // Alias Ecies with algorithms
    type Scheme = Ecies<Secp384r1, Aes256Gcm, Aead>;

    // Generate receiver key pair
    let sk = p384::ecdh::EphemeralSecret::random(&mut OsRng);
    let pk = sk.public_key();

    // Emulate transmitting as bytes
    let pk_bytes = pk.to_encoded_point(true).as_bytes().to_vec();

    // Check converting back into keys
    let pk2 = Secp384r1::try_pk_from(pk_bytes).expect("pk is not correct");

    // Instantiate Ecies & Encrypt
    let enc = Scheme::new(pk2);
    let ciphertext = enc.encrypt(LOREM_IPSUM).expect("encryption failed");

    // Decrypt
    let plaintext = Scheme::decrypt(&sk, &ciphertext).expect("decryption failed");

    assert_eq!(LOREM_IPSUM.to_vec(), plaintext);
}

#[test]
fn secp384r1_aes256gcm_syn() {
    // Alias Ecies with algorithms
    type Scheme = Ecies<Secp384r1, Aes256Gcm, Syn>;

    // Generate receiver key pair
    let sk = p384::ecdh::EphemeralSecret::random(&mut OsRng);
    let pk = sk.public_key();

    // Emulate transmitting as bytes
    let pk_bytes = pk.to_encoded_point(true).as_bytes().to_vec();

    // Check converting back into keys
    let pk2 = Secp384r1::try_pk_from(pk_bytes).expect("pk is not correct");

    // Instantiate Ecies & Encrypt
    let enc = Scheme::new(pk2);
    let ciphertext = enc.encrypt(LOREM_IPSUM).expect("encryption failed");

    // Decrypt
    let plaintext = Scheme::decrypt(&sk, &ciphertext).expect("decryption failed");

    assert_eq!(LOREM_IPSUM.to_vec(), plaintext);
}