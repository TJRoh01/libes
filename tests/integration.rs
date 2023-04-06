use rand_core::OsRng;

use libes::auth::{Aead, HmacSha256, Syn};
use libes::enc::{Aes256Gcm, XChaCha20Poly1305};
use libes::key::conversion::{TryPublicKeyFrom, TrySecretKeyFrom};
use libes::key::{Ed25519, X25519};
use libes::Ecies;

const LOREM_IPSUM: &'static [u8] = include_bytes!("lorem_ipsum.txt");

#[test]
fn x25519_xchachapoly1305_hmacsha256() {
    // Alias Ecies with algorithms
    type X25519XChaCha20Poly1305HmacSha256 = Ecies<X25519, XChaCha20Poly1305, HmacSha256>;

    // Generate receiver key pair
    let sk = x25519_dalek::StaticSecret::new(OsRng);
    let pk = x25519_dalek::PublicKey::from(&sk);

    // Emulate transmitting as bytes
    let sk_bytes = sk.to_bytes().to_vec();
    let pk_bytes = pk.to_bytes().to_vec();

    // Check converting back into keys
    let sk2 = X25519::try_sk_from(sk_bytes).expect("sk is not correct");
    let pk2 = X25519::try_pk_from(pk_bytes).expect("pk is not correct");

    // Instantiate Ecies & Encrypt
    let enc = X25519XChaCha20Poly1305HmacSha256::new(pk2);
    let ciphertext = enc.encrypt(LOREM_IPSUM).expect("encryption failed");

    // Decrypt
    let plaintext =
        X25519XChaCha20Poly1305HmacSha256::decrypt(sk2, &ciphertext).expect("decryption failed");

    assert_eq!(LOREM_IPSUM.to_vec(), plaintext);
}

#[test]
fn x25519_xchachapoly1305_aead() {
    // Alias Ecies with algorithms
    type X25519XChaCha20Poly1305Aead = Ecies<X25519, XChaCha20Poly1305, Aead>;

    // Generate receiver key pair
    let sk = x25519_dalek::StaticSecret::new(OsRng);
    let pk = x25519_dalek::PublicKey::from(&sk);

    // Emulate transmitting as bytes
    let sk_bytes = sk.to_bytes().to_vec();
    let pk_bytes = pk.to_bytes().to_vec();

    // Check converting back into keys
    let sk2 = X25519::try_sk_from(sk_bytes).expect("sk is not correct");
    let pk2 = X25519::try_pk_from(pk_bytes).expect("pk is not correct");

    // Instantiate Ecies & Encrypt
    let enc = X25519XChaCha20Poly1305Aead::new(pk2);
    let ciphertext = enc.encrypt(LOREM_IPSUM).expect("encryption failed");

    // Decrypt
    let plaintext =
        X25519XChaCha20Poly1305Aead::decrypt(sk2, &ciphertext).expect("decryption failed");

    assert_eq!(LOREM_IPSUM.to_vec(), plaintext);
}

#[test]
fn x25519_xchachapoly1305_syn() {
    // Alias Ecies with algorithms
    type X25519XChaCha20Poly1305Syn = Ecies<X25519, XChaCha20Poly1305, Syn>;

    // Generate receiver key pair
    let sk = x25519_dalek::StaticSecret::new(OsRng);
    let pk = x25519_dalek::PublicKey::from(&sk);

    // Emulate transmitting as bytes
    let sk_bytes = sk.to_bytes().to_vec();
    let pk_bytes = pk.to_bytes().to_vec();

    // Check converting back into keys
    let sk2 = X25519::try_sk_from(sk_bytes).expect("sk is not correct");
    let pk2 = X25519::try_pk_from(pk_bytes).expect("pk is not correct");

    // Instantiate Ecies & Encrypt
    let enc = X25519XChaCha20Poly1305Syn::new(pk2);
    let ciphertext = enc.encrypt(LOREM_IPSUM).expect("encryption failed");

    // Decrypt
    let plaintext =
        X25519XChaCha20Poly1305Syn::decrypt(sk2, &ciphertext).expect("decryption failed");

    assert_eq!(LOREM_IPSUM.to_vec(), plaintext);
}

#[test]
fn ed25519_xchachapoly1305_hmacsha256() {
    // Alias Ecies with algorithms
    type Ed25519XChaCha20Poly1305HmacSha256 = Ecies<Ed25519, XChaCha20Poly1305, HmacSha256>;

    let mut rng = rand::rngs::OsRng {};

    // Generate receiver key pair
    let kp = ed25519_dalek::Keypair::generate(&mut rng);

    let sk = kp.secret;
    let pk = kp.public;

    // Emulate transmitting as bytes
    let sk_bytes = sk.to_bytes().to_vec();
    let pk_bytes = pk.to_bytes().to_vec();

    // Check converting back into keys
    let sk2 = Ed25519::try_sk_from(sk_bytes).expect("sk is not correct");
    let pk2 = Ed25519::try_pk_from(pk_bytes).expect("pk is not correct");

    // Instantiate Ecies & Encrypt
    let enc = Ed25519XChaCha20Poly1305HmacSha256::new(pk2);
    let ciphertext = enc.encrypt(LOREM_IPSUM).expect("encryption failed");

    // Decrypt
    let plaintext =
        Ed25519XChaCha20Poly1305HmacSha256::decrypt(sk2, &ciphertext).expect("decryption failed");

    assert_eq!(LOREM_IPSUM.to_vec(), plaintext);
}

#[test]
fn ed25519_xchachapoly1305_aead() {
    // Alias Ecies with algorithms
    type Ed25519XChaCha20Poly1305Aead = Ecies<Ed25519, XChaCha20Poly1305, Aead>;

    let mut rng = rand::rngs::OsRng {};

    // Generate receiver key pair
    let kp = ed25519_dalek::Keypair::generate(&mut rng);

    let sk = kp.secret;
    let pk = kp.public;

    // Emulate transmitting as bytes
    let sk_bytes = sk.to_bytes().to_vec();
    let pk_bytes = pk.to_bytes().to_vec();

    // Check converting back into keys
    let sk2 = Ed25519::try_sk_from(sk_bytes).expect("sk is not correct");
    let pk2 = Ed25519::try_pk_from(pk_bytes).expect("pk is not correct");

    // Instantiate Ecies & Encrypt
    let enc = Ed25519XChaCha20Poly1305Aead::new(pk2);
    let ciphertext = enc.encrypt(LOREM_IPSUM).expect("encryption failed");

    // Decrypt
    let plaintext =
        Ed25519XChaCha20Poly1305Aead::decrypt(sk2, &ciphertext).expect("decryption failed");

    assert_eq!(LOREM_IPSUM.to_vec(), plaintext);
}

#[test]
fn ed25519_xchachapoly1305_syn() {
    // Alias Ecies with algorithms
    type Ed25519XChaCha20Poly1305Syn = Ecies<Ed25519, XChaCha20Poly1305, Syn>;

    let mut rng = rand::rngs::OsRng {};

    // Generate receiver key pair
    let kp = ed25519_dalek::Keypair::generate(&mut rng);

    let sk = kp.secret;
    let pk = kp.public;

    // Emulate transmitting as bytes
    let sk_bytes = sk.to_bytes().to_vec();
    let pk_bytes = pk.to_bytes().to_vec();

    // Check converting back into keys
    let sk2 = Ed25519::try_sk_from(sk_bytes).expect("sk is not correct");
    let pk2 = Ed25519::try_pk_from(pk_bytes).expect("pk is not correct");

    // Instantiate Ecies & Encrypt
    let enc = Ed25519XChaCha20Poly1305Syn::new(pk2);
    let ciphertext = enc.encrypt(LOREM_IPSUM).expect("encryption failed");

    // Decrypt
    let plaintext =
        Ed25519XChaCha20Poly1305Syn::decrypt(sk2, &ciphertext).expect("decryption failed");

    assert_eq!(LOREM_IPSUM.to_vec(), plaintext);
}

#[test]
fn x25519_aes256gcm_hmacsha256() {
    // Alias Ecies with algorithms
    type X25519Aes256GcmHmacSha256 = Ecies<X25519, Aes256Gcm, HmacSha256>;

    // Generate receiver key pair
    let sk = x25519_dalek::StaticSecret::new(OsRng);
    let pk = x25519_dalek::PublicKey::from(&sk);

    // Emulate transmitting as bytes
    let sk_bytes = sk.to_bytes().to_vec();
    let pk_bytes = pk.to_bytes().to_vec();

    // Check converting back into keys
    let sk2 = X25519::try_sk_from(sk_bytes).expect("sk is not correct");
    let pk2 = X25519::try_pk_from(pk_bytes).expect("pk is not correct");

    // Instantiate Ecies & Encrypt
    let enc = X25519Aes256GcmHmacSha256::new(pk2);
    let ciphertext = enc.encrypt(LOREM_IPSUM).expect("encryption failed");

    // Decrypt
    let plaintext =
        X25519Aes256GcmHmacSha256::decrypt(sk2, &ciphertext).expect("decryption failed");

    assert_eq!(LOREM_IPSUM.to_vec(), plaintext);
}

#[test]
fn x25519_aes256gcm_aead() {
    // Alias Ecies with algorithms
    type X25519Aes256GcmAead = Ecies<X25519, Aes256Gcm, Aead>;

    // Generate receiver key pair
    let sk = x25519_dalek::StaticSecret::new(OsRng);
    let pk = x25519_dalek::PublicKey::from(&sk);

    // Emulate transmitting as bytes
    let sk_bytes = sk.to_bytes().to_vec();
    let pk_bytes = pk.to_bytes().to_vec();

    // Check converting back into keys
    let sk2 = X25519::try_sk_from(sk_bytes).expect("sk is not correct");
    let pk2 = X25519::try_pk_from(pk_bytes).expect("pk is not correct");

    // Instantiate Ecies & Encrypt
    let enc = X25519Aes256GcmAead::new(pk2);
    let ciphertext = enc.encrypt(LOREM_IPSUM).expect("encryption failed");

    // Decrypt
    let plaintext =
        X25519Aes256GcmAead::decrypt(sk2, &ciphertext).expect("decryption failed");

    assert_eq!(LOREM_IPSUM.to_vec(), plaintext);
}

#[test]
fn ed25519_aes256gcm_hmacsha256() {
    // Alias Ecies with algorithms
    type Ed25519Aes256GcmHmacSha256 = Ecies<Ed25519, Aes256Gcm, HmacSha256>;

    let mut rng = rand::rngs::OsRng {};

    // Generate receiver key pair
    let kp = ed25519_dalek::Keypair::generate(&mut rng);

    let sk = kp.secret;
    let pk = kp.public;

    // Emulate transmitting as bytes
    let sk_bytes = sk.to_bytes().to_vec();
    let pk_bytes = pk.to_bytes().to_vec();

    // Check converting back into keys
    let sk2 = Ed25519::try_sk_from(sk_bytes).expect("sk is not correct");
    let pk2 = Ed25519::try_pk_from(pk_bytes).expect("pk is not correct");

    // Instantiate Ecies & Encrypt
    let enc = Ed25519Aes256GcmHmacSha256::new(pk2);
    let ciphertext = enc.encrypt(LOREM_IPSUM).expect("encryption failed");

    // Decrypt
    let plaintext =
        Ed25519Aes256GcmHmacSha256::decrypt(sk2, &ciphertext).expect("decryption failed");

    assert_eq!(LOREM_IPSUM.to_vec(), plaintext);
}

#[test]
fn ed25519_aes256gcm_aead() {
    // Alias Ecies with algorithms
    type Ed25519Aes256GcmAead = Ecies<Ed25519, Aes256Gcm, Aead>;

    let mut rng = rand::rngs::OsRng {};

    // Generate receiver key pair
    let kp = ed25519_dalek::Keypair::generate(&mut rng);

    let sk = kp.secret;
    let pk = kp.public;

    // Emulate transmitting as bytes
    let sk_bytes = sk.to_bytes().to_vec();
    let pk_bytes = pk.to_bytes().to_vec();

    // Check converting back into keys
    let sk2 = Ed25519::try_sk_from(sk_bytes).expect("sk is not correct");
    let pk2 = Ed25519::try_pk_from(pk_bytes).expect("pk is not correct");

    // Instantiate Ecies & Encrypt
    let enc = Ed25519Aes256GcmAead::new(pk2);
    let ciphertext = enc.encrypt(LOREM_IPSUM).expect("encryption failed");

    // Decrypt
    let plaintext =
        Ed25519Aes256GcmAead::decrypt(sk2, &ciphertext).expect("decryption failed");

    assert_eq!(LOREM_IPSUM.to_vec(), plaintext);
}