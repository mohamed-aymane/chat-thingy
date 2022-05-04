use std::error::Error;


#[derive(Debug)]
pub enum ChatError {
    Cipher(CipherError),
    Serializing,
    Deserializing,
    RandGeneration,
    SigVerification,
    PasswordDerivation,
    SpawnTask,
    Database
}

#[derive(Debug)]
pub enum CipherError {
    UnknewnCipherType,
    DecryptError,
    EncryptError
}

impl Error for ChatError {
    fn description(&self) -> &str {
        match self {
            ChatError::Serializing => "Object serialization failed",
            ChatError::Deserializing => "Object deserialization failed",
            ChatError::Cipher(cipherr) => match cipherr {
                CipherError::UnknewnCipherType => "Unknewn cipher type",
                CipherError::EncryptError => "Can't encrypt payload",
                CipherError::DecryptError => "Can't decrypt payload"
            },
            ChatError::RandGeneration => "Generating random bytes",
            ChatError::SigVerification => "Peer signature is invalid",
            ChatError::PasswordDerivation => "Deriving a secret from given password failed",
            ChatError::SpawnTask => "Spawning new task failded",
            ChatError::Database => "Database communication failed",
        }
    }
}

impl std::fmt::Display for ChatError {
    #[allow(deprecated)]
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}
