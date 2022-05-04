use borsh::{ BorshSerialize, BorshDeserialize };

#[repr(u8)]
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum Hash {
    Sha256([u8; 32])
}
