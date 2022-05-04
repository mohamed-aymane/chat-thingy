use zeroize::{Zeroizing, Zeroize};
use rand::{rngs::OsRng, RngCore};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use chacha20poly1305::aead::{Aead, NewAead};
use borsh::{BorshSerialize, BorshDeserialize};

use crate::error::{ChatError, CipherError};

use common::keys::KeyPair;

#[derive(BorshSerialize, BorshDeserialize, Debug)]
struct CipherBlock {
    nonce: Vec<u8>,
    data: Vec<u8>
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct EphemeralKeypair {
    pub keypair: KeyPair,
    pub acknowledged: bool
}

pub fn encrypt_secret(secret: &Zeroizing<[u8; 32]>, eph_keys: &Vec<EphemeralKeypair>) -> Result<Vec<u8>, ChatError> {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);

    let mut ser_prof = match eph_keys.try_to_vec() {
        Ok(v) => v,
        Err(_) => return Err(ChatError::Serializing)
    };

    let cipher  = XChaCha20Poly1305::new(secret[..32].as_ref().into());
    let enc_msg = match cipher.encrypt(&nonce.into(), ser_prof.as_ref()) {
        Ok(v) => v,
        Err(_) => return Err(ChatError::Cipher(CipherError::EncryptError))
    };
    ser_prof.zeroize();

    let ciph_block = CipherBlock { nonce: nonce.to_vec(), data: enc_msg };
    Ok(match ciph_block.try_to_vec() {
        Ok(v) => v,
        Err(_) => return Err(ChatError::Deserializing)
    })
}

pub fn decrypt_secret(secret: &Zeroizing<[u8; 32]>, ciph_vec: &[u8]) -> Result<Vec<EphemeralKeypair>, ChatError> {
    let ciph_blob = match CipherBlock::try_from_slice(ciph_vec) {
        Ok(v) => v,
        Err(_) => return Err(ChatError::Serializing)
    };

    let nonce: [u8; 24] = match ciph_blob.nonce.try_into() {
        Ok(v) => v,
        Err(_) => return Err(ChatError::Cipher(CipherError::DecryptError))
    };

    let cipher      = XChaCha20Poly1305::new(secret[..32].as_ref().into());
    let mut dec_msg = match cipher.decrypt(&XNonce::from(nonce), ciph_blob.data.as_ref()) {
        Ok(v) => v,
        Err(_) => return Err(ChatError::Cipher(CipherError::DecryptError))
    };

    Ok(match Vec::try_from_slice(&dec_msg) {
        Ok(v) => {
            dec_msg.zeroize();
            v
        },
        Err(_) => {
            dec_msg.zeroize();
            return Err(ChatError::Deserializing)
        }
    })
}
