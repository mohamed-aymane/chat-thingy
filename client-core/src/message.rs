use borsh::{BorshSerialize, BorshDeserialize};
use chacha20poly1305::{XChaCha20Poly1305, Key};
use chacha20poly1305::aead::{Aead, NewAead};
use x25519_dalek::x25519;
use ed25519_dalek::SecretKey;
use blake2::{Blake2b512, Digest};
use rand::RngCore;

use common::keys::{KeyPair, PublicKey};

use crate::{
    error::{ChatError as Error, CipherError},
    types::{PlainMessage, CipherMessage, CipherBlob, CipherSpec}
};

pub fn encrypt(eph_src: &KeyPair, eph_pk: &PublicKey,
               dest: &PublicKey, msg: &PlainMessage,
               enc_type: &CipherSpec) -> Result<CipherMessage, Error> {
    let blob;
    match enc_type {
        // Choosing setup
        CipherSpec::x25519_xchacha20poly1305_blake2 => {
            let (src_sk, dest_pk);
            // Getting secret key of ephemeral key
            match eph_src {
                KeyPair::ED25519(k) => {
                    src_sk = k.secret.to_bytes();
                }
            }
            // Getting ephemeral public key of our peer
            match dest {
                PublicKey::ED25519(k) => {
                    dest_pk = k.clone();
                }
            }

            // Our shared secret
            let secret = x25519(src_sk, dest_pk);
            // Deriving our secret for more secure secret
            let mut kdf = Blake2b512::new();
            kdf.update(&secret);

            let secret = kdf.finalize();

            // Our shared secret key used for encryption
            let key = Key::from_slice(secret.as_slice());

            // Serializing message
            let ser_msg = match msg.try_to_vec() {
                Ok(v) => v,
                Err(_) => return Err(Error::Serializing)
            };

            // Encrypting message
            let mut nonce = [0_u8; 24]; // Nonce size for XChaCha20Poly1305 is 24 bytes
            let mut seed: rand::rngs::StdRng = rand::SeedableRng::from_entropy();
            match seed.try_fill_bytes(&mut nonce) {
                Ok(_) => (),
                Err(_) => return Err(Error::RandGeneration)
            }

            let cipher  = XChaCha20Poly1305::new(key);
            let enc_msg = match cipher.encrypt(&nonce.into(), ser_msg.as_ref()) {
                Ok(v) => v,
                Err(_) => return Err(Error::Cipher(CipherError::EncryptError))
            };

            blob = CipherBlob {
                eph_dest_pk: dest.to_owned(),
                ciph_type: enc_type.clone(),
                nonce: nonce.to_vec(),
                msg: enc_msg
            };
        },
    }

    let ser_blob = match blob.try_to_vec() {
        Ok(v) => v,
        Err(_) => return Err(Error::Serializing)
    };

    // Sign our serialized blob to check integrity
    let sig = eph_src.sign(&ser_blob);
    

    let ciph_msg = CipherMessage {
        eph_pk: eph_pk.clone(),
        sig,
        blob: ser_blob
    };

    Ok(ciph_msg)
}

pub fn decrypt(eph_src: &PublicKey, eph_dest: &KeyPair, ciph_blob: &CipherBlob) -> Result<PlainMessage, Error> {
    // Decrypting message
    let dec_msg;
    match ciph_blob.ciph_type {
        CipherSpec::x25519_xchacha20poly1305_blake2 => {
            let (dest_sk, src_pk);
            // Getting ephemeral public key of our peer
            match eph_src {
                PublicKey::ED25519(k) => {
                    src_pk = k.clone();
                }
            }

            // Getting secret key of ephemeral key
            match eph_dest {
                KeyPair::ED25519(k) => {
                    dest_sk = k.secret.to_bytes();
                }
            }

            // Our shared secret
            let secret = x25519(dest_sk, src_pk);
            // Derived secret
            let mut kdf = Blake2b512::new();
            kdf.update(&secret);
            
            let secret = kdf.finalize();

            // Our shared secret key used for encryption
            let key = Key::from_slice(secret.as_slice());

            // Decrypting message
            let nonce: [u8; 24] = match ciph_blob.nonce.clone().try_into() {
                Ok(v) => v,
                Err(_) => return Err(Error::Cipher(CipherError::DecryptError))
            };

            let cipher  = XChaCha20Poly1305::new(key);
            dec_msg     = match cipher.decrypt(&nonce.into(), ciph_blob.msg.as_ref()) {
                Ok(v) => v,
                Err(_) => return Err(Error::Cipher(CipherError::DecryptError))
            };
        }
    }

    let msg = match PlainMessage::try_from_slice(&dec_msg) {
        Ok(v) => v,
        Err(_) => return Err(Error::Deserializing)
    };
    
    Ok(msg)
}
