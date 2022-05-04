use std::{
    error::Error,
    fmt
};
use borsh::{ BorshSerialize, BorshDeserialize };
use ed25519_dalek::{Verifier, Keypair, Signature, Signer};
use base64::encode;
use zeroize::Zeroize;

#[repr(u8)]
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub enum PublicKey {
    ED25519([u8; 32])
}

impl PublicKey {
    pub fn verify_sig(&self, msg: &[u8], sig: &[u8]) -> Result<bool, Box<dyn Error + Send + Sync>> {
        match self {
            PublicKey::ED25519(v) => {
                let pk   = ed25519_dalek::PublicKey::from_bytes(v)?;
                let sign = ed25519_dalek::Signature::from_bytes(sig)?;
                match pk.verify(msg, &sign) {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
        }
    }

    #[inline]
    pub fn export(&self) -> String {
        match self {
            PublicKey::ED25519(v) => format!("ed25519({})", encode(v))
        }
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.export())
    }
}

#[repr(u8)]
#[derive(Debug)]
pub enum KeyPair {
    ED25519(ed25519_dalek::Keypair)
}

impl KeyPair {
    pub fn generate() -> KeyPair {
        let mut csprng = rand::rngs::OsRng {};
        let keypair: Keypair = ed25519_dalek::Keypair::generate(&mut csprng);
        KeyPair::ED25519(keypair)
    }

    pub fn public_key(&self) -> PublicKey {
        match self {
            KeyPair::ED25519(k) => PublicKey::ED25519(k.public.to_bytes())
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        match self {
            KeyPair::ED25519(k) => {
                k.sign(msg).to_bytes().to_vec()
            }
        }
    }

    pub fn get_copy(&self) -> KeyPair {
        match self {
            KeyPair::ED25519(k) => {
                let mut buf = k.to_bytes();
                let kp      = ed25519_dalek::Keypair::from_bytes(&buf).expect("Moving keypair should work");
                buf.zeroize();
                KeyPair::ED25519(kp)
            }
        }
    }

    pub fn zeroize(&mut self) {
        match self {
            KeyPair::ED25519(k) => k.secret.zeroize()
        }
    }
}

impl BorshSerialize for KeyPair {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        match self {
            KeyPair::ED25519(k) => {
                0u8.serialize(writer)?;
                k.to_bytes().serialize(writer)
            }
        }
    }
}

impl BorshDeserialize for KeyPair {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        if buf.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unexpected length of input",
            ));
        }
        let flag = buf[0];
        *buf = &buf[1..];
        if flag == 0 && buf.len() == 64 {
            let mut bin_kp: [u8; 64] = [0_u8; 64];
            if !u8::copy_from_bytes(buf, &mut bin_kp)? {
                for i in 0..64 {
                    bin_kp[i] = u8::deserialize(buf)?;
                }
            }
            let kp = match ed25519_dalek::Keypair::from_bytes(&bin_kp) {
                Ok(v) => {
                    v
                },
                Err(_) => {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid rerpesentation: Error parsing ed25519 keyair"));
                }
            };
            bin_kp.zeroize();

            Ok(KeyPair::ED25519(kp))
        } else {
            let msg = format!(
                "Invalid rerpesentation: Keypair with flag {} does not exist",
                flag
            );
            Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, msg))
        }
    }
}
