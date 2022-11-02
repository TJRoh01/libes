//! # libes
//! ![Crates.io](https://img.shields.io/crates/l/libes?style=flat)
//! [![GitHub last commit](https://img.shields.io/github/last-commit/TJRoh01/libes?style=flat)](https://github.com/TJRoh01/libes)
//! [![Crates.io](https://img.shields.io/crates/v/libes?style=flat)](https://crates.io/crates/libes)
//! [![docs.rs](https://img.shields.io/docsrs/libes/latest?style=flat)](https://docs.rs/libes/latest/libes)
//! [![Libraries.io](https://img.shields.io/librariesio/release/cargo/libes?style=flat)](https://libraries.io/cargo/libes)
//!
//! **lib**rary of **e**ncryption **s**chemes is a collection of ECIES variants.
//!
//! The goal of this is library is to become a one-stop shop for everything ECIES.
//!
//! For project details like ECIES variant flowcharts, explanations, license, and release tracks
//! please see the README.md on [GitHub](https://github.com/TJRoh01/libes/blob/main/README.md).
//!
//! ## The mechanics of libes
//! Internally, libes is built up using generics. This allows the library to add support for
//! algorithms with only a couple lines of code per algorithm to glue the dependency providing that
//! algorithm with the private trait system. Then all the procedures are
//! automatically & appropriately implemented with the help of generics & constraints.
//! This significantly reduces the risk for human error,
//! and ensures that the behavior is uniform between all supported algorithms.
//!
//! Externally, this is abstracted for the user with the struct [Ecies<K, E, A>] where:
//! - `K` is an **Elliptic Curve** algorithm from [key]
//! - `E` is an **Encryption** algorithm from [enc]
//! - `A` is an **Authentication** algorithm from [auth]
//!
//! [Ecies<K, E, A>] can be instantiated using the associated function
//! [new(recipient_public_key)][Ecies::new()],
//! and then the method [encrypt(plaintext)][Ecies::encrypt()]
//! will become available to use for **encryption**. The instantiated struct can be
//! **safely reused** to encrypt multiple messages for the same recipient.
//! The struct also has an associated function
//! [decrypt(recipient_secret_key, ciphertext)][Ecies::decrypt()] for **decryption**.
//!
//! The library user is responsible for choosing `K` & `E` that are compatible with `A`,
//! otherwise encryption and/or decryption functionality will not be available on the struct.
//!
//! Compatibility can be determined by checking whether `K` & `E` implement:
//! - [EciesMacEncryptionSupport]/[EciesMacDecryptionSupport] if `A` is of variant `ECIES-MAC` e.g. [HmacSha256][auth::HmacSha256]
//! - [EciesAeadEncryptionSupport]/[EciesAeadDecryptionSupport] if `A` is [Aead][auth::Aead]
//! - [EciesSynEncryptionSupport]/[EciesSynDecryptionSupport] if `A` is [Syn][auth::Syn]
//!
//! ## Example usage
//! 1. We decide that we want to use the `ECIES-AEAD` variant
//! 2. We need to choose an **Elliptic Curve** algorithm from [key] and an **Encryption** algorithm from [enc] that are compatible with `ECIES-AEAD`
//! 3. Both [key::X25519] and [enc::XChaCha20Poly1305] implement [EciesAeadEncryptionSupport] and [EciesAeadDecryptionSupport], so we can choose to use those algorithms
//! 4. We will use [auth::Aead] to mark that it is our **Authentication** algorithm of choice
//! 5. We enable the corresponding features for the libes dependency to compile our chosen functionality
//!     - ```toml
//!       [dependencies.libes]
//!       version = "*"
//!       features = ["ECIES-AEAD", "x25519", "XChaCha20-Poly1305"]
//!       ```
//!
//! And now for the code:
//! ```rust
//! # fn main() -> Result<(), ()> {
//! use libes::{auth, Ecies, enc, key};
//!
//! // Create an alias for Ecies with our chosen algorithms
//! type MyEcies = Ecies<key::X25519, enc::XChaCha20Poly1305, auth::Aead>;
//!
//! // Alice generates a elliptic key pair, then sends the public key to Bob
//! let alice_secret_key = x25519_dalek::StaticSecret::new(rand_core::OsRng);
//! let alice_public_key = x25519_dalek::PublicKey::from(&alice_secret_key);
//!
//! // Bob receives the public key, and instantiates MyEcies with it
//! let encryptor = MyEcies::new(alice_public_key)?;
//!
//! // Then Bob encrypts his message, and sends it to Alice
//! let message = b"Hello Alice";
//! let encrypted_message = encryptor.encrypt(message);
//!
//! // Alice receives the encrypted message, and decrypts it using MyEcies and her secret key
//! let decrypted_message = MyEcies::decrypt(alice_secret_key, &encrypted_message)?;
//!
//! // The decrypted message equals the original message
//! assert_eq!(message, decrypted_message.as_slice());
//! # Ok(())
//! # }
//! ```
//!
//! ## Algorithm support
//! Matrix entries are of form `Encryption & Decryption` or `Encryption`/`Decryption`
//!
//! ### Support icon legend
//! - 🚀 Completed
//! - 🏗️ Development
//! - 📅 Planned
//! - 🤔 Planning
//! - 🚫 Can/Will not implement
//!
//! ### Elliptic Curve Support Matrix
//! |     Algorithm/ECIES Variant     | ECIES-MAC | ECIES-AEAD | ECIES-SYN |
//! |:-----------------:|:---------:|:----------:|:---------:|
//! |      x25519       |    🚀    |    🚀     |    🚀     |
//! |      ed25519      |    🏗️️    |    /🏗️     |    🏗️      |
//! | K-256 / secp256k1 |    📅     |     📅     |    📅     |
//! | P-256 / secp256r1 |    📅     |     📅     |    📅     |
//! | P-384 / secp384r1 |    🤔     |     🤔     |    🤔     |
//! | P-521 / secp521r1 |    🤔     |     🤔     |    🤔     |
//!
//! ### Encryption Support Matrix
//! |     Algorithm/ECIES Variant      | ECIES-MAC | ECIES-AEAD | ECIES-SYN |
//! |:------------------:|:---------:|:----------:|:---------:|
//! | ChaCha20-Poly1305  |  🚫[^1]/🚫[^2]   |   🚫[^1]/🚫[^2]   |  🚫[^1]/🚫[^2]   |
//! | XChaCha20-Poly1305 |    🚀    |    🚀     |    🚀     |
//! |      AES-GCM       |    📅    |     📅     |    📅     |
//!
//! ### Authentication Support Matrix
//! |  Algorithm/ECIES Variant  | ECIES-MAC |
//! |:-----------:|:---------:|
//! | HMAC-SHA256 |    🚀    |
//! | HMAC-SHA512 |    🤔     |
//!
//! [^1]: ChaCha20 uses a 96-bit nonce,
//! which when generated using a random function has an unsatisfactory
//! risk of collision. XChaCha20 uses a 192-bit nonce
//! where that is no longer an issue.
//!
//! [^2]: Will not encourage using potentially weak encryption [^1]
//! by implementing decryption for it

pub mod auth;
pub mod enc;
pub mod key;
pub mod markers;

#[cfg(not(any(feature = "ECIES-MAC", feature = "ECIES-AEAD", feature = "ECIES-SYN")))]
compile_error!(
    "At least one variant feature must be activated: 'ECIES-MAC', 'ECIES_AEAD', or 'ECIES-SYN'"
);

#[cfg(feature = "ECIES-MAC")]
use auth::generics::{Mac, SplitMac, SplitMacKey};
#[cfg(feature = "ECIES-MAC")]
use markers::{EciesMacDecryptionSupport, EciesMacEncryptionSupport};

#[cfg(feature = "ECIES-AEAD")]
use auth::Aead;
#[cfg(feature = "ECIES-AEAD")]
use markers::{EciesAeadDecryptionSupport, EciesAeadEncryptionSupport};

#[cfg(feature = "ECIES-SYN")]
use auth::Syn;
#[cfg(feature = "ECIES-SYN")]
use markers::{EciesSynDecryptionSupport, EciesSynEncryptionSupport};

#[cfg(any(feature = "ECIES-MAC", feature = "ECIES-AEAD"))]
use enc::generics::GenNonce;

#[cfg(any(feature = "ECIES-MAC", feature = "ECIES-AEAD", feature = "ECIES-SYN"))]
use enc::generics::{Encryption, SplitEncKey, SplitNonce};
#[cfg(any(feature = "ECIES-MAC", feature = "ECIES-AEAD", feature = "ECIES-SYN"))]
use key::generics::{
    DeriveKeyMaterial, GenerateEphemeralKey, KeyExchange, SplitEphemeralKey, TryIntoSecretKey,
};

use key::generics::{Key, TryIntoPublicKey};
use std::marker::PhantomData;

/// Generic `ECIES` instance
pub struct Ecies<K, E, A> {
    recipient_pk: K,
    k: PhantomData<K>,
    e: PhantomData<E>,
    a: PhantomData<A>,
}

impl<K: Key, E, A> Ecies<K, E, A> {
    /// Create a new `ECIES<K, E, A>` instance given a `recipient_public_key` compatible with `K`
    pub fn new<T: TryIntoPublicKey<K>>(recipient_public_key: T) -> Result<Self, ()> {
        Ok(Self {
            recipient_pk: recipient_public_key.try_into_pk()?,
            k: PhantomData,
            e: PhantomData,
            a: PhantomData,
        })
    }
}

#[cfg(feature = "ECIES-MAC")]
impl<K, E, A> Ecies<K, E, A>
where
    K: EciesMacEncryptionSupport + Key + GenerateEphemeralKey + KeyExchange + DeriveKeyMaterial,
    E: EciesMacEncryptionSupport + Encryption + GenNonce + SplitEncKey,
    A: Mac + SplitMacKey,
{
    /// Encrypt `plaintext` using the `ECIES-MAC` variant
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        // Generate
        let (ephemeral_pk, ephemeral_sk) = K::get_ephemeral_key();
        let nonce = E::get_nonce();

        // Derive
        let shared_secret = K::key_exchange(&self.recipient_pk, ephemeral_sk);
        let mut derived_key = K::derive_key_material(
            &ephemeral_pk,
            shared_secret,
            E::ENC_KEY_LEN + A::MAC_KEY_LEN,
        );
        let enc_key = E::get_enc_key(&mut derived_key);
        let mac_key = A::get_mac_key(&mut derived_key);

        // Process
        let ciphertext = E::encrypt(&enc_key, &nonce, plaintext);
        let mac = A::digest(&mac_key, &nonce, &ciphertext);

        // Output
        let mut out = Vec::new();
        out.extend_from_slice(ephemeral_pk.as_bytes());
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(mac.as_slice());
        out.extend_from_slice(ciphertext.as_slice());

        out
    }
}

#[cfg(feature = "ECIES-MAC")]
impl<K, E, A> Ecies<K, E, A>
where
    K: EciesMacDecryptionSupport + Key + SplitEphemeralKey + KeyExchange + DeriveKeyMaterial,
    E: EciesMacDecryptionSupport + Encryption + SplitNonce + SplitEncKey,
    A: Mac + SplitMac,
{
    /// Decrypt `ciphertext` using the `ECIES-MAC` variant, given the `recipient_secret_key` it was
    /// encrypted for
    pub fn decrypt<T: TryIntoSecretKey<K>>(
        recipient_secret_key: T,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ()> {
        let mut ciphertext = ciphertext.to_vec();

        let ephemeral_pk = K::get_ephemeral_key(&mut ciphertext);
        let nonce = E::get_nonce(&mut ciphertext);
        let mac = A::get_mac(&mut ciphertext);

        let shared_secret = K::key_exchange(&ephemeral_pk, recipient_secret_key.try_into_sk()?);
        let mut derived_key = K::derive_key_material(
            &ephemeral_pk,
            shared_secret,
            E::ENC_KEY_LEN + A::MAC_KEY_LEN,
        );
        let enc_key = E::get_enc_key(&mut derived_key);
        let mac_key = A::get_mac_key(&mut derived_key);

        A::verify(&mac_key, &nonce, &ciphertext, &mac)?;
        E::decrypt(&enc_key, &nonce, &ciphertext)
    }
}

#[cfg(feature = "ECIES-AEAD")]
impl<K, E> Ecies<K, E, Aead>
where
    K: EciesAeadEncryptionSupport + Key + GenerateEphemeralKey + KeyExchange + DeriveKeyMaterial,
    E: EciesAeadEncryptionSupport + Encryption + GenNonce + SplitEncKey,
{
    /// Encrypt `plaintext` using the `ECIES-AEAD` variant
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        // Generate
        let (ephemeral_pk, ephemeral_sk) = K::get_ephemeral_key();
        let nonce = E::get_nonce();

        // Derive
        let shared_secret = K::key_exchange(&self.recipient_pk, ephemeral_sk);
        let mut derived_key = K::derive_key_material(&ephemeral_pk, shared_secret, E::ENC_KEY_LEN);
        let enc_key = E::get_enc_key(&mut derived_key);

        // Process
        let ciphertext = E::encrypt(&enc_key, &nonce, plaintext);

        // Output
        let mut out = Vec::new();
        out.extend_from_slice(ephemeral_pk.as_bytes());
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(ciphertext.as_slice());

        out
    }
}

#[cfg(feature = "ECIES-AEAD")]
impl<K, E> Ecies<K, E, Aead>
where
    K: EciesAeadDecryptionSupport + Key + SplitEphemeralKey + KeyExchange + DeriveKeyMaterial,
    E: EciesAeadDecryptionSupport + Encryption + SplitNonce + SplitEncKey,
{
    /// Decrypt `ciphertext` using the `ECIES-AEAD` variant, given the `recipient_secret_key` it was
    /// encrypted for
    pub fn decrypt<T: TryIntoSecretKey<K>>(
        recipient_secret_key: T,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ()> {
        let mut ciphertext = ciphertext.to_vec();

        let ephemeral_pk = K::get_ephemeral_key(&mut ciphertext);
        let nonce = E::get_nonce(&mut ciphertext);

        let shared_secret = K::key_exchange(&ephemeral_pk, recipient_secret_key.try_into_sk()?);
        let mut derived_key = K::derive_key_material(&ephemeral_pk, shared_secret, E::ENC_KEY_LEN);
        let enc_key = E::get_enc_key(&mut derived_key);

        E::decrypt(&enc_key, &nonce, &ciphertext)
    }
}

#[cfg(feature = "ECIES-SYN")]
impl<K, E> Ecies<K, E, Syn>
where
    K: EciesSynEncryptionSupport + Key + GenerateEphemeralKey + KeyExchange + DeriveKeyMaterial,
    E: EciesSynEncryptionSupport + Encryption + SplitNonce + SplitEncKey,
{
    /// Encrypt `plaintext` using the `ECIES-SYN` variant
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        // Generate
        let (ephemeral_pk, ephemeral_sk) = K::get_ephemeral_key();

        // Derive
        let shared_secret = K::key_exchange(&self.recipient_pk, ephemeral_sk);
        let mut derived_key = K::derive_key_material(
            &ephemeral_pk,
            shared_secret,
            E::ENC_KEY_LEN + E::ENC_NONCE_LEN,
        );
        let enc_key = E::get_enc_key(&mut derived_key);
        let nonce = E::get_nonce(&mut derived_key);

        // Process
        let ciphertext = E::encrypt(&enc_key, &nonce, plaintext);

        // Output
        let mut out = Vec::new();
        out.extend_from_slice(ephemeral_pk.as_bytes());
        out.extend_from_slice(ciphertext.as_slice());

        out
    }
}

#[cfg(feature = "ECIES-SYN")]
impl<K, E> Ecies<K, E, Syn>
where
    K: EciesSynDecryptionSupport + Key + SplitEphemeralKey + KeyExchange + DeriveKeyMaterial,
    E: EciesSynDecryptionSupport + Encryption + SplitNonce + SplitEncKey,
{
    /// Decrypt `ciphertext` using the `ECIES-SYN` variant, given the `recipient_secret_key` it was
    /// encrypted for
    pub fn decrypt<T: TryIntoSecretKey<K>>(
        recipient_secret_key: T,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ()> {
        let mut ciphertext = ciphertext.to_vec();

        let ephemeral_pk = K::get_ephemeral_key(&mut ciphertext);

        let shared_secret = K::key_exchange(&ephemeral_pk, recipient_secret_key.try_into_sk()?);
        let mut derived_key = K::derive_key_material(
            &ephemeral_pk,
            shared_secret,
            E::ENC_KEY_LEN + E::ENC_NONCE_LEN,
        );
        let enc_key = E::get_enc_key(&mut derived_key);
        let nonce = E::get_nonce(&mut derived_key);

        E::decrypt(&enc_key, &nonce, &ciphertext)
    }
}
