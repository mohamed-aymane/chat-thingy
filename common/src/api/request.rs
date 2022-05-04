use borsh::{BorshSerialize, BorshDeserialize};

use crate::keys::PublicKey;

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct Subscribe {
    pub sig: Vec<u8>,
    pub public_key: PublicKey
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct VerifiedRequest {
    pub sig: Vec<u8>,
    pub req: Vec<u8>,
    pub public_key: PublicKey
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct GenericRequest {
    pub challenge: Vec<u8>
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct SendMessage {
    pub message: Vec<u8>,
    pub destination: Vec<u8>,
    pub challenge: Vec<u8>
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MessageReceived {
    pub id: i64,
    pub challenge: Vec<u8>
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MessageNotification {
    pub id: i64,
    pub challenge: Vec<u8>
}
