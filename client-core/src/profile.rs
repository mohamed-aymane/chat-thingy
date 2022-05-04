use std::collections::HashMap;
use std::sync::Arc;

use common::keys::KeyPair;
use tokio::sync::{oneshot, mpsc, RwLock};
use tracing::error;
use zeroize::{Zeroizing, Zeroize};
use rand::{rngs::OsRng, RngCore};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use chacha20poly1305::aead::{Aead, NewAead};
use borsh::{BorshSerialize, BorshDeserialize};

use crate::client::ClientEventHandler;
use crate::database::{SessionDB, Database, profile};
use crate::error::{ChatError, CipherError};
use crate::r#loop::{TaskStatus, LoopSet, Task};

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct CipherBlock {
    nonce: Vec<u8>,
    data: Vec<u8>,
    salt: Vec<u8>
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct ProfileSecret {
    pub keypair: KeyPair,
    pub enc_secret: EphSecret
}

pub struct EphSecret(pub Zeroizing<[u8; 32]>);

impl BorshSerialize for EphSecret {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.0.serialize(writer)
    }
}

impl BorshDeserialize for EphSecret {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        if buf.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unexpected length of input",
            ));
        }
        if buf.len() == 32 {
            let mut bin_sec: [u8; 32] = [0_u8; 32];
            if !u8::copy_from_bytes(buf, &mut bin_sec)? {
                for i in 0..32 {
                    bin_sec[i] = u8::deserialize(buf)?;
                }
            }
            let eph_secret = EphSecret(Zeroizing::new(bin_sec));

            Ok(eph_secret)
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid rerpesentation for ephemeral encrypt secret"))
        }
    }
}

#[derive(Debug)]
pub enum ChangeProfile {
    Ok,
    Err(String)
}

#[derive(Debug)]
pub enum AddProfile {
    Ok,
    Err(String)
}

pub async fn get_all(db: SessionDB, tx: oneshot::Sender<TaskStatus>) {
    let mut profiles = vec![]; 
    match profile::get_all_name(&db).await {
        Ok(v) => {
            for i in v {
                profiles.push(i.name);
            }
        },
        Err(e) => error!("Error getting list of profile from session db: {}", e),
    }

    tx.send(TaskStatus::GetProfiles(profiles)).ok();
}

pub async fn add_profile(loop_set: &mut LoopSet, profile_name: String, profile_pass: Zeroizing<String>, tx: oneshot::Sender<TaskStatus>) {
    match profile::get_session(&loop_set.sess_db, &profile_name.as_str()).await {
        Ok(s) => {
            match s {
                None => {
                    let profile = match tokio::task::spawn_blocking(move || {
                        let mut eph_secret = [0_u8; 32];
                        OsRng.fill_bytes(&mut eph_secret);
                        ProfileSecret { keypair: KeyPair::generate(), enc_secret: EphSecret(Zeroizing::new(eph_secret)) }
                    }).await {
                        Ok(v) => v,
                        Err(e) => {
                            tx.send(TaskStatus::AddProfile(AddProfile::Err(format!("Error occured while creating profile identity: {}", e)))).ok();
                            return;
                        }
                    };

                    let (secret, salt) = match argon2_hash(profile_pass, None).await {
                        Ok(v) => v,
                        Err(e) => {
                            tx.send(TaskStatus::AddProfile(AddProfile::Err(format!("Error occured while loading session: {}", e)))).ok();
                            return;
                        }
                    };
                    let enc_blob = match encrypt_pk(secret, salt, profile).await {
                        Ok(v) => v,
                        Err(e) => {
                            tx.send(TaskStatus::AddProfile(AddProfile::Err(format!("Error encrypting session: {}", e)))).ok();
                            return;
                        }
                    };

                    match profile::add(&loop_set.sess_db, &profile_name, &enc_blob).await {
                        Ok(_) => (),
                        Err(e) => {
                            tx.send(TaskStatus::AddProfile(AddProfile::Err(format!("Error saving session to database: {}", e)))).ok();
                            return;
                        }
                    }
                },
                Some(_) => {
                    tx.send(TaskStatus::AddProfile(AddProfile::Err(format!("Session with name {} already exists", profile_name)))).ok();
                    return;
                }
            }
        },
        Err(e) => {
            error!("Error getting session settings from session db: {}", e);
            tx.send(TaskStatus::AddProfile(AddProfile::Err("Error getting session settings from session database".to_owned()))).ok();
            return;
        }
    }

    tx.send(TaskStatus::AddProfile(AddProfile::Ok)).ok();
}

pub async fn change_profile(loop_set: &mut LoopSet, profile_settings: Option<(String, Zeroizing<String>)>, tx: oneshot::Sender<TaskStatus>) -> Option<mpsc::Sender<Task>> {
    let mut task_sender = None;
    match profile_settings {
        Some(v) => {
            match profile::get_session(&loop_set.sess_db, v.0.as_str()).await {
                Ok(s) => {
                    match s {
                        Some(session) => {
                            let ciph_blob = match CipherBlock::try_from_slice(&session.enc_keypair) {
                                Ok(v) => v,
                                Err(e) => {
                                    tx.send(TaskStatus::ChangeProfile(ChangeProfile::Err(format!("Error serializing keypair blob: {}", e)))).ok();
                                    return task_sender;
                                }
                            };

                            let (secret, _) = match argon2_hash(v.1, Some(ciph_blob.salt.clone())).await {
                                Ok(v) => v,
                                Err(e) => {
                                    tx.send(TaskStatus::ChangeProfile(ChangeProfile::Err(format!("Error occured while loading session: {}", e)))).ok();
                                    return task_sender;
                                }
                            };

                            let session = match decrypt_pk(secret.to_owned(), ciph_blob).await {
                                Ok(v) => v,
                                Err(e) => {
                                    tx.send(TaskStatus::ChangeProfile(ChangeProfile::Err(format!("Error occured while loading session: {}", e)))).ok();
                                    return task_sender;
                                }
                            };

                            let sess_dir = format!("{}/{}", loop_set.work_dir, v.0);
                            tokio::fs::create_dir_all(&format!("{}/data", sess_dir)).await.ok();
                            
                            let db = match Database::new(&sess_dir).await {
                                Ok(v) => v,
                                Err(e) => {
                                    tx.send(TaskStatus::ChangeProfile(ChangeProfile::Err(format!("Error opening database for {}: {}", v.0, e)))).ok();
                                    return None;
                                }
                            };

                            let tasks = Arc::new(RwLock::new(HashMap::new()));

                            let (cl_tx, rx) = mpsc::channel(1000);

                            let mut client_event_handler = ClientEventHandler {
                                db,
                                servers: Arc::new(RwLock::new(HashMap::new())),
                                tasks: tasks.clone(),
                                eph_keypair: Arc::new(RwLock::new(HashMap::new())),
                                profile_secret: Arc::new(session),
                                channel: rx
                            };

                            match client_event_handler.init().await {
                                Ok(_) => (),
                                Err(e) => {
                                    error!("Error starting client event handler: {}", e);
                                    tx.send(TaskStatus::ChangeProfile(ChangeProfile::Err(format!("Error starting client event handler: {}", e)))).ok();
                                    return None;
                                },
                            }

                            tasks.write().await.insert("".to_owned(), 
                            vec![tokio::spawn(async move {
                                client_event_handler.events_loop().await;
                            })]);

                            task_sender = Some(cl_tx);
                            tx.send(TaskStatus::ChangeProfile(ChangeProfile::Ok)).ok();
                            return task_sender
                        },
                        None => {
                            tx.send(TaskStatus::ChangeProfile(ChangeProfile::Err(format!("Session {} not found", v.0)))).ok();
                            return task_sender;
                        }
                    }
                },
                Err(e) => {
                    error!("Error getting session settings from session db: {}", e);
                    tx.send(TaskStatus::ChangeProfile(ChangeProfile::Err("Error getting session settings from session database".to_owned()))).ok();
                    return None;
                }
            }
        },
        None => None
    }
}

pub fn argon2_conf<'a>() -> argon2::Config<'a> {
    argon2::Config {
        variant: argon2::Variant::Argon2id,
        hash_length: 32,
        lanes: 8,
        mem_cost: 16 * 1024,
        time_cost: 8,
        ..Default::default()
    }
}

pub async fn argon2_hash(mut secret: Zeroizing<String>, pre_salt: Option<Vec<u8>>) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), ChatError> {
    match tokio::task::spawn_blocking(move || {
        let argon2_conf = argon2_conf();


        let mut salt = [0u8; 32];
        match pre_salt {
            Some(v) => salt = match v.try_into() {
                Ok(v) => v,
                Err(_) => {
                    return Err(ChatError::PasswordDerivation)
                }
            },
            None => OsRng.fill_bytes(&mut salt)
        }

        let key = match argon2::hash_raw(secret.as_bytes(), &salt, &argon2_conf) {
            Ok(v) => v,
            Err(_) => {
                secret.zeroize();
                return Err(ChatError::PasswordDerivation)
            }
        };
        secret.zeroize();
        Ok((Zeroizing::new(key), salt.to_vec()))
    }).await {
        Ok(v) => (v),
        Err(_) => return Err(ChatError::SpawnTask)
    }
}

pub async fn encrypt_pk(secret: Zeroizing<Vec<u8>>, salt: Vec<u8>, profile: ProfileSecret) -> Result<Vec<u8>, ChatError> {
    match tokio::task::spawn_blocking(move || {
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);

        let mut ser_prof = match profile.try_to_vec() {
            Ok(v) => v,
            Err(_) => return Err(ChatError::Serializing)
        };

        let cipher  = XChaCha20Poly1305::new(secret[..32].as_ref().into());
        let enc_msg = match cipher.encrypt(&nonce.into(), ser_prof.as_ref()) {
            Ok(v) => v,
            Err(_) => return Err(ChatError::Cipher(CipherError::EncryptError))
        };
        ser_prof.zeroize();

        let ciph_block = CipherBlock { nonce: nonce.to_vec(), data: enc_msg, salt };
        Ok(match ciph_block.try_to_vec() {
            Ok(v) => v,
            Err(_) => return Err(ChatError::Deserializing)
        })
    }).await {
        Ok(v) => v,
        Err(_) => return Err(ChatError::SpawnTask)
    }
}

pub async fn decrypt_pk(secret: Zeroizing<Vec<u8>>, ciph_blob: CipherBlock) -> Result<ProfileSecret, ChatError> {
    match tokio::task::spawn_blocking(move || {

        let nonce: [u8; 24] = match ciph_blob.nonce.try_into() {
            Ok(v) => v,
            Err(_) => return Err(ChatError::Cipher(CipherError::DecryptError))
        };

        let cipher      = XChaCha20Poly1305::new(secret[..32].as_ref().into());
        let mut dec_msg = match cipher.decrypt(&XNonce::from(nonce), ciph_blob.data.as_ref()) {
            Ok(v) => v,
            Err(_) => return Err(ChatError::Cipher(CipherError::DecryptError))
        };

        Ok(match ProfileSecret::try_from_slice(&dec_msg) {
            Ok(v) => {
                dec_msg.zeroize();
                v
            },
            Err(_) => {
                dec_msg.zeroize();
                return Err(ChatError::Deserializing)
            }
        })
    }).await {
        Ok(v) => v,
        Err(_) => return Err(ChatError::SpawnTask)
    }
}
