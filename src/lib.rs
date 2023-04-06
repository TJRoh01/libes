//! # libes
//! ![Crates.io](https://img.shields.io/crates/l/libes?style=flat)
//! [![GitHub last commit](https://img.shields.io/github/last-commit/TJRoh01/libes?style=flat)](https://github.com/TJRoh01/libes)
//! [![Crates.io](https://img.shields.io/crates/v/libes?style=flat)](https://crates.io/crates/libes)
//! [![docs.rs](https://img.shields.io/docsrs/libes/latest?style=flat)](https://docs.rs/libes/latest/libes)
//! [![Libraries.io](https://img.shields.io/librariesio/release/cargo/libes?style=flat)](https://libraries.io/cargo/libes)
//!
//! **lib**rary of **e**ncryption **s**cheme(s) is a collection of ECIES variants.
//!
//! The goal of this is library is to become a one-stop shop for everything ECIES.
//!
//! ## Algorithm support
//! Matrix entries are of form Encryption/Decryption
//!
//! ### Support icon legend
//! - 🚀 Completed
//! - 🏗️ Development
//! - 📅 Planned
//! - 🤔 Planning
//! - 🚫 Can/Will not implement
//!
//! ### Elliptic Curve Support Matrix
//! |     Algorithm     | ECIES-MAC | ECIES-AEAD | ECIES-SYN |
//! |:-----------------:|:---------:|:----------:|:---------:|
//! |      x25519       |    🚀/🚀    |    🚀/🚀     |    🚀/🚀     |
//! |      ed25519      |    🏗️/🏗️    |    🏗️/🏗️     |    🏗️/🏗️      |
//! | K-256 / secp256k1 |    🤔/🤔     |     🤔/🤔     |    🤔/🤔     |
//! | P-256 / secp256r1 |    🤔/🤔     |     🤔/🤔     |    🤔/🤔     |
//! | P-384 / secp384r1 |    🤔/🤔     |     🤔/🤔     |    🤔/🤔     |
//! | P-521 / secp521r1 |    🤔/🤔     |     🤔/🤔     |    🤔/🤔     |
//!
//! ### Encryption Support Matrix
//! |     Algorithm      | ECIES-MAC | ECIES-AEAD | ECIES-SYN |
//! |:------------------:|:---------:|:----------:|:---------:|
//! | ChaCha20-Poly1305  |  🚫[^1]/🚫[^2]   |   🚫[^1]/🚫[^2]   |  🚫[^1]/🚫[^2]   |
//! | XChaCha20-Poly1305 |    🚀/🚀    |    🚀/🚀     |    🚀/🚀     |
//! |      AES-GCM       |    🤔/🤔     |     🤔/🤔     |    🤔/🤔     |
//!
//! ### Authentication Support Matrix
//! |  Algorithm  | ECIES-MAC |
//! |:-----------:|:---------:|
//! | HMAC-SHA256 |    🚀/🚀    |
//! | HMAC-SHA512 |    🤔/🤔     |
//!
//! [^1]: ChaCha20 uses a 96-bit nonce,
//! which when generated using a random function has an unsatisfactory
//! risk of collision. XChaCha20 uses a 192-bit nonce
//! where that is no longer an issue.
//!
//! [^2]: Will not encourage using potentially weak encryption [^1]
//! by implementing decryption for it

pub mod markers;
pub mod key;
pub mod enc;
pub mod auth;

#[cfg(not(any(feature = "ECIES-MAC", feature = "ECIES-AEAD", feature = "ECIES-SYN")))]
compile_error!("At least one variant feature must be activated: 'ECIES-MAC', 'ECIES_AEAD', or 'ECIES-SYN'");

#[cfg(feature = "ECIES-MAC")]
use markers::{EciesMacEncryptionSupport, EciesMacDecryptionSupport};
#[cfg(feature = "ECIES-MAC")]
use auth::generics::{Mac, SplitMac, SplitMacKey};

#[cfg(feature = "ECIES-AEAD")]
use markers::{EciesAeadEncryptionSupport, EciesAeadDecryptionSupport};
#[cfg(feature = "ECIES-AEAD")]
use auth::Aead;

#[cfg(feature = "ECIES-SYN")]
use markers::{EciesSynEncryptionSupport, EciesSynDecryptionSupport};
#[cfg(feature = "ECIES-SYN")]
use auth::Syn;

#[cfg(any(feature = "ECIES-MAC", feature = "ECIES-AEAD"))]
use enc::generics::GenNonce;

#[cfg(any(feature = "ECIES-MAC", feature = "ECIES-AEAD", feature = "ECIES-SYN"))]
use key::{TryIntoPublicKey, TryIntoSecretKey, generics::{DeriveKeyMaterial, GenerateEphemeralKey, Key, KeyExchange, SplitEphemeralKey}};
#[cfg(any(feature = "ECIES-MAC", feature = "ECIES-AEAD", feature = "ECIES-SYN"))]
use enc::generics::{Encryption, SplitEncKey, SplitNonce};

use std::marker::PhantomData;

/// Generic `ECIES` instance
pub struct Ecies<K, E, A> {
    recipient_pk: K,
    k: PhantomData<K>,
    e: PhantomData<E>,
    a: PhantomData<A>
}

impl<K: Key, E, A> Ecies<K, E, A> {
    /// Create a new `ECIES<K, E, A>` instance given `recipient_pk: Recipient Public Key` compatible with `K: Key`
    pub fn new<T: TryIntoPublicKey<K>>(recipient_pk: T) -> Result<Self, ()> {
        Ok(Self {
            recipient_pk: recipient_pk.try_into_pk()?,
            k: PhantomData,
            e: PhantomData,
            a: PhantomData
        })
    }
}

#[cfg(feature = "ECIES-MAC")]
impl<K, E, A> Ecies<K, E, A>
where
    K: EciesMacEncryptionSupport + Key + GenerateEphemeralKey + KeyExchange + DeriveKeyMaterial,
    E: EciesMacEncryptionSupport + Encryption + GenNonce + SplitEncKey,
    A: Mac + SplitMacKey
{
    /// Encrypt `plaintext` using the `ECIES-MAC` variant
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        // Generate
        let (ephemeral_pk, ephemeral_sk) = K::get_ephemeral_key();
        let nonce = E::get_nonce();

        // Derive
        let shared_secret = K::key_exchange(&self.recipient_pk, ephemeral_sk);
        let mut derived_key = K::derive_key_material(&ephemeral_pk, shared_secret, E::ENC_KEY_LEN + A::MAC_KEY_LEN);
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
    A: Mac + SplitMac
{
    /// Decrypt `ciphertext` using the `ECIES-MAC` variant
    pub fn decrypt<T: TryIntoSecretKey<K>>(sk: T, ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
        let mut ciphertext = ciphertext.to_vec();

        let ephemeral_pk = K::get_ephemeral_key(&mut ciphertext);
        let nonce = E::get_nonce(&mut ciphertext);
        let mac = A::get_mac(&mut ciphertext);

        let shared_secret = K::key_exchange(&ephemeral_pk, sk.try_into_sk()?);
        let mut derived_key = K::derive_key_material(&ephemeral_pk, shared_secret, E::ENC_KEY_LEN + A::MAC_KEY_LEN);
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
    E: EciesAeadEncryptionSupport + Encryption + GenNonce + SplitEncKey
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
    E: EciesAeadDecryptionSupport + Encryption + SplitNonce + SplitEncKey
{
    /// Decrypt `ciphertext` using the `ECIES-AEAD` variant
    pub fn decrypt<T: TryIntoSecretKey<K>>(sk: T, ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
        let mut ciphertext = ciphertext.to_vec();

        let ephemeral_pk = K::get_ephemeral_key(&mut ciphertext);
        let nonce = E::get_nonce(&mut ciphertext);

        let shared_secret = K::key_exchange(&ephemeral_pk, sk.try_into_sk()?);
        let mut derived_key = K::derive_key_material(&ephemeral_pk, shared_secret, E::ENC_KEY_LEN);
        let enc_key = E::get_enc_key(&mut derived_key);

        E::decrypt(&enc_key, &nonce, &ciphertext)
    }
}

#[cfg(feature = "ECIES-SYN")]
impl<K, E> Ecies<K, E, Syn>
where
    K: EciesSynEncryptionSupport + Key + GenerateEphemeralKey + KeyExchange + DeriveKeyMaterial,
    E: EciesSynEncryptionSupport + Encryption + SplitNonce + SplitEncKey
{
    /// Encrypt `plaintext` using the `ECIES-SYN` variant
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        // Generate
        let (ephemeral_pk, ephemeral_sk) = K::get_ephemeral_key();

        // Derive
        let shared_secret = K::key_exchange(&self.recipient_pk, ephemeral_sk);
        let mut derived_key = K::derive_key_material(&ephemeral_pk, shared_secret, E::ENC_KEY_LEN + E::ENC_NONCE_LEN);
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
    E: EciesSynDecryptionSupport + Encryption + SplitNonce + SplitEncKey
{
    /// Decrypt `ciphertext` using the `ECIES-SYN` variant
    pub fn decrypt<T: TryIntoSecretKey<K>>(sk: T, ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
        let mut ciphertext = ciphertext.to_vec();

        let ephemeral_pk = K::get_ephemeral_key(&mut ciphertext);

        let shared_secret = K::key_exchange(&ephemeral_pk, sk.try_into_sk()?);
        let mut derived_key = K::derive_key_material(&ephemeral_pk, shared_secret, E::ENC_KEY_LEN + E::ENC_NONCE_LEN);
        let enc_key = E::get_enc_key(&mut derived_key);
        let nonce = E::get_nonce(&mut derived_key);

        E::decrypt(&enc_key, &nonce, &ciphertext)
    }
}