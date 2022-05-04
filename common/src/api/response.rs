use borsh::{BorshSerialize, BorshDeserialize};

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub enum Status {
    Ok,
    UnknewnPublicKey,
    UnknewnDestPublicKey,
    InvalidChallengeKey,
    SigError,
    ReqErr
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct Version(pub f64);

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct Challenge {
    pub challenge: Vec<u8>,
    pub status: Status
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct Subscribe {
    pub status: Status,
    pub challenge: Vec<u8>
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct Unsubscribe {
    pub status: Status
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct SendMessage {
    pub status: Status
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MessageEvent {
    pub status: Status
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct MessageReceived {
    pub status: Status
}
