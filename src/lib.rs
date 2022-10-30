mod markers;
pub mod key;
pub mod enc;
pub mod auth;

#[cfg(not(any(feature = "ECIES-MAC", feature = "ECIES-AEAD", feature = "ECIES-SYN")))]
compile_error!("At least one variant feature must be activated: 'ECIES-MAC', 'ECIES_AEAD', or 'ECIES-SYN'");

#[cfg(feature = "ECIES-MAC")]
use markers::EciesMacSupport;
#[cfg(feature = "ECIES-MAC")]
use auth::generics::{Mac, SplitMac, SplitMacKey};

#[cfg(feature = "ECIES-AEAD")]
use markers::EciesAeadSupport;
#[cfg(feature = "ECIES-AEAD")]
use auth::Aead;

#[cfg(feature = "ECIES-SYN")]
use markers::EciesSynSupport;
#[cfg(feature = "ECIES-SYN")]
use auth::Syn;

#[cfg(any(feature = "ECIES-MAC", feature = "ECIES-AEAD"))]
use enc::generics::GenNonce;

use std::marker::PhantomData;

#[cfg(any(feature = "ECIES-MAC", feature = "ECIES-AEAD", feature = "ECIES-SYN"))]
use key::generics::{DeriveKeyMaterial, GenerateEphemeralKey, GenericSecretKey, Key, KeyExchange, SplitEphemeralKey};
#[cfg(any(feature = "ECIES-MAC", feature = "ECIES-AEAD", feature = "ECIES-SYN"))]
use enc::generics::{Encryption, SplitEncKey, SplitNonce};

pub struct Ecies<K, E, A> {
    recipient_pk: K,
    k: PhantomData<K>,
    e: PhantomData<E>,
    a: PhantomData<A>
}

impl<K, E, A> Ecies<K, E, A>
{
    pub fn new<T: Into<K>>(key: T) -> Self {
        Self {
            recipient_pk: key.into(),
            k: PhantomData,
            e: PhantomData,
            a: PhantomData
        }
    }
}

#[cfg(feature = "ECIES-MAC")]
impl<K, E, A> Ecies<K, E, A>
where
    K: Key + GenerateEphemeralKey + KeyExchange + DeriveKeyMaterial,
    E: Encryption + GenNonce + SplitEncKey,
    A: Mac + SplitMacKey
{
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
        K: Key + SplitEphemeralKey + KeyExchange + DeriveKeyMaterial + EciesMacSupport,
        E: Encryption + SplitNonce + SplitEncKey + EciesMacSupport,
        A: Mac + SplitMac
{
    pub fn decrypt<T: Into<GenericSecretKey<K::SecretKey>>>(sk: T, ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
        let mut ciphertext = ciphertext.to_vec();

        let ephemeral_pk = K::get_ephemeral_key(&mut ciphertext);
        let nonce = E::get_nonce(&mut ciphertext);
        let mac = A::get_mac(&mut ciphertext);

        let shared_secret = K::key_exchange(&ephemeral_pk, sk.into());
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
        K: Key + GenerateEphemeralKey + KeyExchange + DeriveKeyMaterial + EciesAeadSupport,
        E: Encryption + GenNonce + SplitEncKey + EciesAeadSupport
{
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
        K: Key + SplitEphemeralKey + KeyExchange + DeriveKeyMaterial + EciesAeadSupport,
        E: Encryption + SplitNonce + SplitEncKey + EciesAeadSupport
{
    pub fn decrypt<T: Into<GenericSecretKey<K::SecretKey>>>(sk: T, ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
        let mut ciphertext = ciphertext.to_vec();

        let ephemeral_pk = K::get_ephemeral_key(&mut ciphertext);
        let nonce = E::get_nonce(&mut ciphertext);

        let shared_secret = K::key_exchange(&ephemeral_pk, sk.into());
        let mut derived_key = K::derive_key_material(&ephemeral_pk, shared_secret, E::ENC_KEY_LEN);
        let enc_key = E::get_enc_key(&mut derived_key);

        E::decrypt(&enc_key, &nonce, &ciphertext)
    }
}

#[cfg(feature = "ECIES-SYN")]
impl<K, E> Ecies<K, E, Syn>
    where
        K: Key + GenerateEphemeralKey + KeyExchange + DeriveKeyMaterial + EciesSynSupport,
        E: Encryption + SplitNonce + SplitEncKey + EciesSynSupport
{
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
        K: Key + SplitEphemeralKey + KeyExchange + DeriveKeyMaterial,
        E: Encryption + SplitNonce + SplitEncKey
{
    pub fn decrypt<T: Into<GenericSecretKey<K::SecretKey>>>(sk: T, ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
        let mut ciphertext = ciphertext.to_vec();

        let ephemeral_pk = K::get_ephemeral_key(&mut ciphertext);

        let shared_secret = K::key_exchange(&ephemeral_pk, sk.into());
        let mut derived_key = K::derive_key_material(&ephemeral_pk, shared_secret, E::ENC_KEY_LEN + E::ENC_NONCE_LEN);
        let enc_key = E::get_enc_key(&mut derived_key);
        let nonce = E::get_nonce(&mut derived_key);

        E::decrypt(&enc_key, &nonce, &ciphertext)
    }
}