use common::{keys::PublicKey, hash::Hash};
use borsh::{BorshSerialize, BorshDeserialize};

#[repr(u8)]
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
#[allow(non_camel_case_types)]
/// Cipher setup
pub enum CipherSpec {
    x25519_xchacha20poly1305_blake2
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
/// Cipher message, payload sent and received from peers
pub struct CipherMessage {
    /// Source ephemeral address
    pub eph_pk: PublicKey,
    /// Signature of blob
    pub sig: Vec<u8>,
    /// The blob, which contains the message
    pub blob: Vec<u8>
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct CipherBlob {
    /// Destination ephemeral public key
    pub eph_dest_pk: PublicKey,
    /// key exchange, kdf, AEAD triple used for encryption of message
    pub ciph_type: CipherSpec,
    /// Nonce of the AEAD
    pub nonce: Vec<u8>,
    /// The encrypted message itself, which translates to PlainMessage after decrypting it
    pub msg: Vec<u8>
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct PlainMessage {
    /// The message
    pub msg: MessageType,
    /// Next public key for key exchange
    pub next_key: Option<PublicKey>,
    /// Acknowledging we received public key for next key exchange
    pub next_peer_key_ack: Option<PublicKey>
}

#[repr(u8)]
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum MessageType {
    NewText { msg: Vec<u8> },
    File { hash: Hash, secret: Vec<u8> }
}

#[repr(u8)]
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum Message {
    Message(MessageType),
    MessageSignatureVerificationError,
    MessageDecryptionError
}

