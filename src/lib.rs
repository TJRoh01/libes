use std::marker::PhantomData;
use crate::auth::{Aead, Syn, generics::{Mac, SplitMac, SplitMacKey}};
use crate::enc::generics::{Encryption, GenNonce, SplitEncKey, SplitNonce};
use crate::key::generics::{DeriveKeyMaterial, GenerateEphemeralKey, GenericSecretKey, Key, KeyExchange, SplitEphemeralKey};

pub mod key;
pub mod enc;
pub mod auth;

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

impl<K, E, A> Ecies<K, E, A>
where
    K: Key + GenerateEphemeralKey + KeyExchange + DeriveKeyMaterial,
    E: Encryption + GenNonce + SplitEncKey,
    A: Mac + SplitMacKey
{
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let (ephemeral_pk, ephemeral_sk) = K::get_ephemeral_key();
        let shared_secret = K::key_exchange(&self.recipient_pk, ephemeral_sk);
        let mut derived_key = K::derive_key_material(&ephemeral_pk, shared_secret, E::ENC_KEY_LEN + A::MAC_KEY_LEN);
        let enc_key = E::get_enc_key(&mut derived_key);
        let mac_key = A::get_mac_key(&mut derived_key);
        let nonce = E::get_nonce();
        let ciphertext = E::encrypt(&enc_key, &nonce, plaintext);
        let mac = A::digest(&mac_key, &nonce, &ciphertext);

        let mut res = Vec::new();
        res.extend_from_slice(ephemeral_pk.as_bytes());
        res.extend_from_slice(nonce.as_slice());
        res.extend_from_slice(mac.as_slice());
        res.extend_from_slice(ciphertext.as_slice());

        res
    }
}

impl<K, E, A> Ecies<K, E, A>
    where
        K: Key + SplitEphemeralKey + KeyExchange + DeriveKeyMaterial,
        E: Encryption + SplitNonce + SplitEncKey,
        A: Mac + SplitMac
{
    pub fn decrypt<T: Into<GenericSecretKey<K::SecretKey>>>(sk: T, mut ciphertext: Vec<u8>) -> Vec<u8> {
        let ephemeral_pk = K::get_ephemeral_key(&mut ciphertext);
        let nonce = E::get_nonce(&mut ciphertext);
        let mac = A::get_mac(&mut ciphertext);

        let shared_secret = K::key_exchange(&ephemeral_pk, sk.into());
        let mut derived_key = K::derive_key_material(&ephemeral_pk, shared_secret, E::ENC_KEY_LEN + A::MAC_KEY_LEN);
        let enc_key = E::get_enc_key(&mut derived_key);
        let mac_key = A::get_mac_key(&mut derived_key);

        if !A::verify(&mac_key, &nonce, &ciphertext, &mac) {
            panic!("Invalid auth tag");
        }

        E::decrypt(&enc_key, &nonce, &ciphertext)
    }
}

impl<K, E> Ecies<K, E, Aead>
    where
        K: Key + GenerateEphemeralKey + KeyExchange + DeriveKeyMaterial,
        E: Encryption + GenNonce + SplitEncKey
{
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let (ephemeral_pk, ephemeral_sk) = K::get_ephemeral_key();
        let shared_secret = K::key_exchange(&self.recipient_pk, ephemeral_sk);
        let mut derived_key = K::derive_key_material(&ephemeral_pk, shared_secret, E::ENC_KEY_LEN);
        let enc_key = E::get_enc_key(&mut derived_key);
        let nonce = E::get_nonce();
        let ciphertext = E::encrypt(&enc_key, &nonce, plaintext);

        let mut res = Vec::new();
        res.extend_from_slice(ephemeral_pk.as_bytes());
        res.extend_from_slice(nonce.as_slice());
        res.extend_from_slice(ciphertext.as_slice());

        res
    }
}

impl<K, E> Ecies<K, E, Aead>
    where
        K: Key + SplitEphemeralKey + KeyExchange + DeriveKeyMaterial,
        E: Encryption + SplitNonce + SplitEncKey
{
    pub fn decrypt<T: Into<GenericSecretKey<K::SecretKey>>>(sk: T, mut ciphertext: Vec<u8>) -> Vec<u8> {
        let ephemeral_pk = K::get_ephemeral_key(&mut ciphertext);
        let nonce = E::get_nonce(&mut ciphertext);

        let shared_secret = K::key_exchange(&ephemeral_pk, sk.into());
        let mut derived_key = K::derive_key_material(&ephemeral_pk, shared_secret, E::ENC_KEY_LEN);
        let enc_key = E::get_enc_key(&mut derived_key);

        E::decrypt(&enc_key, &nonce, &ciphertext)
    }
}

impl<K, E> Ecies<K, E, Syn>
    where
        K: Key + GenerateEphemeralKey + KeyExchange + DeriveKeyMaterial,
        E: Encryption + SplitNonce + SplitEncKey
{
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let (ephemeral_pk, ephemeral_sk) = K::get_ephemeral_key();
        let shared_secret = K::key_exchange(&self.recipient_pk, ephemeral_sk);
        let mut derived_key = K::derive_key_material(&ephemeral_pk, shared_secret, E::ENC_KEY_LEN + E::ENC_NONCE_LEN);
        let enc_key = E::get_enc_key(&mut derived_key);
        let nonce = E::get_nonce(&mut derived_key);
        let ciphertext = E::encrypt(&enc_key, &nonce, plaintext);

        let mut res = Vec::new();
        res.extend_from_slice(ephemeral_pk.as_bytes());
        res.extend_from_slice(ciphertext.as_slice());

        res
    }
}

impl<K, E> Ecies<K, E, Syn>
    where
        K: Key + SplitEphemeralKey + KeyExchange + DeriveKeyMaterial,
        E: Encryption + SplitNonce + SplitEncKey
{
    pub fn decrypt<T: Into<GenericSecretKey<K::SecretKey>>>(sk: T, mut ciphertext: Vec<u8>) -> Vec<u8> {
        let ephemeral_pk = K::get_ephemeral_key(&mut ciphertext);

        let shared_secret = K::key_exchange(&ephemeral_pk, sk.into());
        let mut derived_key = K::derive_key_material(&ephemeral_pk, shared_secret, E::ENC_KEY_LEN + E::ENC_NONCE_LEN);
        let enc_key = E::get_enc_key(&mut derived_key);
        let nonce = E::get_nonce(&mut derived_key);

        E::decrypt(&enc_key, &nonce, &ciphertext)
    }
}