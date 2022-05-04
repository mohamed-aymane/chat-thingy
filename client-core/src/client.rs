use std::{sync::Arc, collections::HashMap};
use base64::decode;
use borsh::{BorshDeserialize, BorshSerialize};
use reqwest_eventsource::{EventSource, Event};
use tokio::{
    sync::{RwLock, oneshot, mpsc},
    task::JoinHandle,
    time::Duration
};
use reqwest::{ClientBuilder, Client};
use lazy_static::lazy_static;
use futures::stream::StreamExt;
use tracing::{error, info};

use common::{
    keys::PublicKey,
    api::{response, request::{self, MessageNotification, VerifiedRequest}}
};
use zeroize::Zeroizing;
use crate::{
    database::{Database, server::{self, Server}, contact, message},
    error::ChatError, r#loop::{TaskStatus, TaskType, Task}, profile::ProfileSecret, types::{CipherMessage, CipherBlob, Message},
    ephemeral_keys::{EphemeralKeypair, encrypt_secret, decrypt_secret}
};

lazy_static! {
    static ref PING_INTERVAL: Duration  = Duration::from_secs(10);
    static ref SLEEP_INTERVAL: Duration = Duration::from_secs(5);
}

pub struct ClientEventHandler {
    pub db: Database,
    pub servers: Arc<RwLock<HashMap<String, Server>>>,
    pub tasks: Arc<RwLock<HashMap<String, Vec<JoinHandle<()>>>>>,
    pub eph_keypair: Arc<RwLock<HashMap<u32, Vec<EphemeralKeypair>>>>,
    pub profile_secret: Arc<ProfileSecret>,
    pub channel: mpsc::Receiver<Task>
}

fn client_builder(allow_insecure_con: bool) -> Client {
    ClientBuilder::new()
        .gzip(true)
        .brotli(true)
        .deflate(true)
        .danger_accept_invalid_certs(allow_insecure_con)
        .danger_accept_invalid_hostnames(allow_insecure_con)
        .user_agent("Chat-thingy")
        .use_native_tls()
        .build().expect("Should build")
}

impl ClientEventHandler {
    pub async fn init(&self) -> Result<(), ChatError> {
        let db = self.db.clone();
        let servers = match server::get_all(&db).await {
            Ok(v) => v,
            Err(_) => return Err(ChatError::Database)
        };
        {
            let mut lock = self.servers.write().await;
            *lock = servers;
        }

        let mut servers_list = Vec::new();
        self.servers.read().await.iter().for_each(|x| servers_list.push((x.0.clone(), x.1.clone())));

        ClientEventHandler::spawn_server_tasks(self.db.clone(), self.servers.clone(),
                            self.tasks.clone(), self.eph_keypair.clone(), self.profile_secret.clone(), servers_list)
                            .await;

        Ok(())
    }

    pub async fn events_loop(&mut self) {
        loop {
            match self.channel.recv().await {
                Some(v) => match v.typ {
                    TaskType::AddServer(host, port, allow_insecure_con) => {
                        let (pk, sig);
                        {
                            pk = self.profile_secret.keypair.public_key();
                            let ser_pk = match pk.try_to_vec() {
                                Ok(v) => v,
                                Err(e) => {
                                    v.resp.send(TaskStatus::AddServer(crate::client::AddServer::Error(format!("Failed to serialize public key: {}", e)))).ok();
                                    continue;
                                },
                            };
                            sig = self.profile_secret.keypair.sign(&ser_pk);
                        }
                        let tasks          = self.tasks.clone();
                        let servers        = self.servers.clone();
                        let db             = self.db.clone();
                        let profile_secret = self.profile_secret.clone();
                        let eph_keypair    = self.eph_keypair.clone();
                        tokio::spawn(async move {
                            add_server(db, servers, tasks, eph_keypair, profile_secret, pk, sig, &host, port, allow_insecure_con, v.resp).await;
                        });
                    },
                    TaskType::GetServersActivity => {
                        let servers = self.servers.clone();
                        tokio::spawn(async move {
                            get_server_activity(servers, v.resp).await;
                        });
                    },
                    TaskType::AddContact(name, pk, server) => {
                        let servers = self.servers.clone();
                        let db      = self.db.clone();
                        tokio::spawn(async move {
                            add_contact(db, servers, &name, &pk, &server, v.resp).await;
                        });
                    }
                    _ => ()
                },
                None => break
            }
        }
    }

    fn load_keys(db: Database, eph_keypair: Arc<RwLock<HashMap<u32, Vec<EphemeralKeypair>>>>, secret: &Zeroizing<[u8; 32]>, user_id: u32) {
        match futures::executor::block_on(contact::get_eph_keypair(&db, user_id)) {
            Ok(v) => {
                match decrypt_secret(secret, &v) {
                    Ok(v) => {
                        futures::executor::block_on(eph_keypair.write()).insert(user_id, v);
                    },
                    Err(e) => error!("Error decrypting ephemeral keypairs: {}", e)
                }
            },
            Err(e) => {
                error!("Error getting encrypted ephemeral keypairs from database for contact with id {}: {}", user_id, e);
            }
        }
    }

    async fn spawn_server_tasks(db: Database,
                        servers: Arc<RwLock<HashMap<String, Server>>>,
                        tasks: Arc<RwLock<HashMap<String, Vec<JoinHandle<()>>>>>,
                        eph_keypair: Arc<RwLock<HashMap<u32, Vec<EphemeralKeypair>>>>,
                        profile_secret: Arc<ProfileSecret>,
                        servers_list: Vec<(String, Server)>) {
        for (server, server_info) in servers_list {
            let allow_insecure_con = server_info.allow_insecure;
            let client             = client_builder(allow_insecure_con);
            {
                let mut lock = servers.write().await;
                lock.insert(server.clone(), server_info);
            }
            {
                let mut lock       = tasks.write().await;
                let mut serv_tasks = vec![];
                let serv           = server.clone();
                let servers_clone  = servers.clone();
                let client_clone   = client.clone();
                serv_tasks.push(tokio::spawn(async move {
                    ClientEventHandler::health_check(servers_clone, client_clone, serv).await;
                }));

                let serv           = server.clone();
                let servers        = servers.clone();
                let db             = db.clone();
                let profile_secret = profile_secret.clone();
                let eph_keypair    = eph_keypair.clone();
                let client_clone   = client.clone();
                serv_tasks.push(tokio::spawn(async move {
                    ClientEventHandler::message_reader(db, profile_secret, servers, eph_keypair, client_clone, serv).await;
                }));
                lock.insert(server, serv_tasks);
            }
        }
    }

    async fn health_check(servers: Arc<RwLock<HashMap<String, Server>>>, client: Client, server: String) {
        loop {
            match client.get(format!("{}/ping", server)).send().await {
                Ok(_) => {
                    let time = chrono::offset::Utc::now().timestamp();
                    match servers.write().await.get_mut(&server) {
                        Some(v) => {
                            v.last_seen = time;
                        },
                        None => ()
                    }
                },
                Err(_) => ()
            }
            tokio::time::sleep(*PING_INTERVAL).await;
        }
    }

    async fn message_reader(db: Database,
                            secret: Arc<ProfileSecret>,
                            servers: Arc<RwLock<HashMap<String, Server>>>,
                            eph_keypair: Arc<RwLock<HashMap<u32, Vec<EphemeralKeypair>>>>,
                            client: Client, server: String) {
        loop {
            let req_body;
            {
                let lock = servers.read().await;
                match lock.get(&server) {
                    Some(v) => {
                        let unser_req = MessageNotification { id: v.last_id, challenge: v.challenge_key.clone() };
                        let event_req = match unser_req.try_to_vec() {
                            Ok(v) => v,
                            Err(_) => {
                                return;
                            }
                        };
                        let sig   = secret.keypair.sign(&event_req);
                        let unser = VerifiedRequest {
                            sig,
                            public_key: secret.keypair.public_key(),
                            req: event_req
                        };
                        req_body  = match unser.try_to_vec() {
                            Ok(v) => v,
                            Err(_) => {
                                return;
                            }
                        }
                    },
                    None => {
                        // Something is wrong, silently exiting from task
                        return;
                    }
                }
            }

            let req = client.post(format!("{}/msgevent", server))
                .body(req_body);
            let mut es = match EventSource::new(req) {
                Ok(v)  => v,
                Err(_) => {
                    tokio::time::sleep(*PING_INTERVAL).await;
                    continue;
                }
            };
            while let Some(event) = es.next().await {
                match event {
                    Ok(Event::Open) => (),
                    Ok(Event::Message(message)) => {
                        if message.event != "m" {
                            continue;
                        }
                        let secret      = secret.clone();
                        let servers     = servers.clone();
                        let eph_keypair = eph_keypair.clone();
                        let db          = db.clone();
                        let server      = server.clone();
                        let task        = tokio::task::spawn_blocking(move || {
                            println!("got message {} {}", message.event, message.id);
                            // First we get message id and timestamp
                            let (msg_id, msg_timestamp);
                            {
                                let id_timestamp = message.id.split(",").collect::<Vec<&str>>();
                                if id_timestamp.len() != 2 {
                                    error!("Server {} sent unknewn message id timestamp format {}", server, message.id);
                                    return;
                                }
                                let (msg_id_str, msg_timestamp_str) = (id_timestamp[0], id_timestamp[1]);
                                match (msg_id_str.parse::<i64>(), msg_timestamp_str.parse::<i64>()) {
                                    (Ok(a), Ok(b)) => {
                                        msg_id        = a;
                                        msg_timestamp = b;
                                    },
                                    _ => {
                                        error!("Server {} sent message with unexpected id {} or timestamp {}", server, msg_id_str, msg_timestamp_str);
                                        return;
                                    },
                                };
                            }

                            // Verifying if server is not trying to give us old messages
                            match futures::executor::block_on(servers.read()).get(&server) {
                                Some(v) => {
                                    if msg_id <= v.last_id {
                                        error!("Server {} is sending old messages", server);
                                        return;
                                    }
                                }
                                None => {
                                    // Unreachable
                                }
                            }

                            // Next we deserialize cipher message
                            let ciph_msg = match decode(&message.data) {
                                Ok(v) => {
                                    // Then we need to deserialize cipher message
                                    match CipherMessage::try_from_slice(&v) {
                                        Ok(v) => v,
                                        Err(_) => {
                                            // Can't deserialize message, it's lost forever
                                            // Hope it's nothing important
                                            return;
                                        }
                                    }
                                },
                                Err(_) => {
                                    // Nothing we can do, message is just skipped
                                    return;
                                }
                            };

                            // No more need for message
                            drop(message);

                            // Checking if a user has said public key
                            let user;
                            {
                                let ser_pk = match ciph_msg.eph_pk.try_to_vec() {
                                    Ok(v) => v,
                                    Err(e) => {
                                        error!("Error serializing public key: {}", e);
                                        return;
                                    }
                                };
                                user = match futures::executor::block_on(contact::get_contact_from_ack_eph_pk(&db, &ser_pk)) {
                                    Ok(Some(v)) => v,
                                    Ok(None) => {
                                        // if ephemeral public key doesn't exist
                                        // Perhaps this is a first message
                                        match futures::executor::block_on(contact::get_contact_from_pk(&db, &ser_pk, &server)) {
                                            Ok(Some(v)) => {
                                                // We can't reuse public key if we already have an
                                                // ephemeral key
                                                match futures::executor::block_on(contact::has_eph_pk(&db, &ser_pk, &server)) {
                                                    Ok(false) => v,
                                                    Ok(true) => {
                                                        info!("Contact with public key {} trying to reuse his general public key for key exchange", ciph_msg.eph_pk);
                                                        return;
                                                    },
                                                    Err(e) => {
                                                        info!("Error on contact has ephemeral public key: {}", e);
                                                        return;
                                                    }
                                                }
                                            },
                                            Ok(None) => {
                                                info!("Got message from unknewn user {}", ciph_msg.eph_pk);
                                                return;
                                            },
                                            Err(e) => {
                                                // By default if public key is not in contact list
                                                // We will ignore message
                                                error!("Error getting user with public key {} from database: {}", ciph_msg.eph_pk, e);
                                                return;
                                            }
                                        }
                                    },
                                    Err(e) => {
                                        error!("Error getting user with ephemeral public key {} from database: {}", ciph_msg.eph_pk, e);
                                        return;
                                    }
                                }
                            }

                            let ser_msg;
                            match ciph_msg.eph_pk.verify_sig(&ciph_msg.blob, &ciph_msg.sig) {
                                Ok(true) => {
                                    // Deserializing cipher blob
                                    let ciph_blob = match CipherBlob::try_from_slice(&ciph_msg.blob) {
                                        Ok(v) => v,
                                        Err(_) => {
                                            error!("Error deserializing incoming message from user {} (id {})", user.name, user.id);
                                            return;
                                        }
                                    };

                                    let src_eph_pk = ciph_msg.eph_pk.clone();
                                    drop(ciph_msg);

                                    // Looking for our destination keypair
                                    let mut keypair = None;
                                    for _ in 0..2 {
                                        match futures::executor::block_on(eph_keypair.read()).get(&user.id) {
                                            Some(v) => {
                                                for kp in v {
                                                    if kp.acknowledged == true && kp.keypair.public_key() == ciph_blob.eph_dest_pk {
                                                        keypair = Some(kp.keypair.get_copy());
                                                    }
                                                }
                                                break;
                                            },
                                            None => {
                                                ClientEventHandler::load_keys(db.clone(), eph_keypair.clone(), &secret.enc_secret.0, user.id);
                                            }
                                        }
                                    }
                                    match keypair {
                                        Some(v) => {
                                            match crate::message::decrypt(&src_eph_pk, &v, &ciph_blob) {
                                                Ok(plain_msg) => {
                                                    drop(ciph_blob);

                                                    // Checking if we got an ack for one of our
                                                    // keypairs for next key exchange
                                                    match plain_msg.next_peer_key_ack {
                                                        Some(pk) => {
                                                            match futures::executor::block_on(eph_keypair.write()).get_mut(&user.id) {
                                                                Some(v) => {
                                                                    let mut id = None;
                                                                    for i in 0..v.len() {
                                                                        if v[i].acknowledged == false && v[i].keypair.public_key() == pk {
                                                                            v[i].acknowledged = true;
                                                                            id = Some(i);
                                                                        }
                                                                    }
                                                                    match id {
                                                                        Some(id) => {
                                                                            match encrypt_secret(&secret.enc_secret.0, &v) {
                                                                                Ok(enc_ephemeral_keys) => {
                                                                                    match futures::executor::block_on(contact::update_eph_keypair(&db, user.id, &enc_ephemeral_keys)) {
                                                                                        Ok(_) => (),
                                                                                        Err(e) => {
                                                                                            v[id].acknowledged = false;
                                                                                            error!("Error updating ephemeral keypair with contact {} (id {}) in database: {}", user.name, user.id, e);
                                                                                        }
                                                                                    }
                                                                                },
                                                                                Err(e) => {
                                                                                    v[id].acknowledged = false;
                                                                                    error!("Error encrypting ephemeral keypairs with contact {} (id {}): {}", user.name, user.id, e);
                                                                                }
                                                                            };
                                                                        },
                                                                        None => ()
                                                                    }
                                                                    while v.len() > 3 {
                                                                        v.remove(0);
                                                                    }
                                                                },
                                                                None => ()
                                                            }
                                                        },
                                                        None => ()
                                                    }

                                                    // Checking if we have an ephemeral key for
                                                    // next key exchange
                                                    match plain_msg.next_key {
                                                        Some(v) => {
                                                            match v.try_to_vec() {
                                                                Ok(ser_eph_pk) => {
                                                                    match futures::executor::block_on(contact::update_eph_peer_pk(&db, user.id, &ser_eph_pk)) {
                                                                        Ok(_) => (),
                                                                        Err(e) => {
                                                                            error!("Error updating user's {} (id {}) ephemeral keys: {}", user.name, user.id, e);
                                                                        }
                                                                    }
                                                                },
                                                                Err(e) => error!("Error serializing user's {} (id {}) ephemeral key: {}", user.name, user.id, e)
                                                            }
                                                        },
                                                        None => ()
                                                    }

                                                    // Now we store message to database
                                                    ser_msg = Message::Message(plain_msg.msg).try_to_vec();
                                                },
                                                Err(e) => {
                                                    error!("Error in decrypting message from user {} (id {}): {}", user.name, user.id, e);
                                                    ser_msg = Message::MessageDecryptionError.try_to_vec();
                                                }
                                            }
                                        },
                                        None => {
                                            error!("Error in key exchange: user {} (id {}) sent an ephemeral key {} that has not been negotiated", user.name, user.id, ciph_blob.eph_dest_pk);
                                            ser_msg = Message::MessageDecryptionError.try_to_vec();
                                        }
                                    }
                                },
                                _ => {
                                    // Failed to verify message authenticity
                                    error!("Error verifying signature of message from user {} (id {})", user.name, user.id);
                                    ser_msg = Message::MessageSignatureVerificationError.try_to_vec();
                                }
                            }
                            match ser_msg {
                                Ok(v) => {
                                    match futures::executor::block_on(message::add(&db, user.id, msg_id, msg_timestamp, false, &v)) {
                                        Ok(_) => {
                                            // Updating last message id we got from server
                                            match futures::executor::block_on(servers.write()).get_mut(&server) {
                                                Some(v) => {
                                                    v.last_id = msg_id;
                                                }
                                                None => {
                                                    // Unreachable
                                                }
                                            }
                                        },
                                        Err(e) => {
                                            error!("Error saving received message from user {} (id {}) to database: {}", user.name, user.id, e);
                                        }
                                    }
                                },
                                Err(e) => {
                                    error!("Error in message serializing from user {} (id {}): {}", user.name, user.id, e);
                                }
                            }
                        }).await;
                        match task {
                            Ok(_) => (),
                            Err(e) => error!("Error spawning message worker task: {}", e)
                        }
                    },
                    Err(err) => {
                        error!("Error in server {} message events: {}", server, err);
                        es.close();
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum AddServer {
    Ok,
    ServerError(String),
    NoProfile(String),
    ErrorSubscribing(String),
    Error(String)
}

pub async fn user_req(req: impl std::future::Future<Output = Result<reqwest::Response, reqwest::Error>>, server: &str) -> Result<bytes::Bytes, TaskStatus> {
    match req.await {
        Ok(v) => {
            match v.bytes().await {
                Ok(v) => {
                    Ok(v)
                },
                Err(e) => {
                    Err(TaskStatus::AddServer(AddServer::ServerError(format!("Error reading response from {}: {}", server, e))))
                }
            }
        },
        Err(e) => {
            Err(TaskStatus::AddServer(AddServer::ServerError(format!("Error connecting to {}: {}", server, e))))
        }
    }
}

async fn get_server_version(client: &Client, server: &str) -> Result<(), TaskStatus> {
    match user_req(client.get(format!("https://{}/version", server)).send(), &server).await {
        Ok(v) => {
            match common::api::response::Version::try_from_slice(&v) {
                Ok(v) => {
                    if v.0 < common::api::MIN_SUPPORTED_VER {
                        Err(TaskStatus::AddServer(
                                AddServer::ServerError(format!("Server {} is using old version ({:.2}), while minimum supported is {:.2}", server, v.0, common::api::MIN_SUPPORTED_VER))
                                ))
                    } else {
                        Ok(())
                    }
                },
                Err(e) => {
                    Err(TaskStatus::AddServer(AddServer::ServerError(format!("Error parsing version response from {}: {}", server, e))))
                }
            }
        },
        Err(e) => {
            Err(e)
        },
    }
}

async fn server_subscribe(client: &Client, server: &str, public_key: PublicKey, pk_sig: Vec<u8>) -> Result<response::Subscribe, TaskStatus> {
    let req = request::Subscribe { sig: pk_sig, public_key };
    let req = match req.try_to_vec() {
        Ok(v) => v,
        Err(e) => return Err(TaskStatus::AddServer(AddServer::Error(format!("Error creating request: {}", e))))
    };

    match user_req(client.post(format!("https://{}/sub", server)).body(req).send(), &server).await {
        Ok(v) => {
            match common::api::response::Subscribe::try_from_slice(&v) {
                Ok(v) => {
                    match v.status {
                        response::Status::Ok => Ok(v),
                        e @ _ => Err(TaskStatus::AddServer(AddServer::ServerError(format!("Server {} sent unexpected status: {:?}", server, e))))
                    }
                },
                Err(e) => {
                    Err(TaskStatus::AddServer(AddServer::ServerError(format!("Error parsing subscribe response from {}: {}", server, e))))
                }
            }
        },
        Err(e) => {
            Err(e)
        },
    }
}

pub async fn add_server(db: Database,
                        servers: Arc<RwLock<HashMap<String, Server>>>,
                        tasks: Arc<RwLock<HashMap<String, Vec<JoinHandle<()>>>>>,
                        eph_keypair: Arc<RwLock<HashMap<u32, Vec<EphemeralKeypair>>>>,
                        profile_secret: Arc<ProfileSecret>,
                        public_key: PublicKey, pk_sig: Vec<u8>,
                        host: &str, port: u16, allow_insecure_con: bool, tx: oneshot::Sender<TaskStatus>) {
    let client = client_builder(allow_insecure_con);
    let server = format!("{}:{}", host, port);

    if servers.read().await.contains_key(&format!("https://{}", server)) {
        tx.send(TaskStatus::AddServer(AddServer::Error(format!("Server {} already added", server)))).ok();
        return;
    }

    // Connecting to server and checking version
    match get_server_version(&client, &server).await {
        Ok(_) => {
            // Now sending our subscribe request
            let sub = match server_subscribe(&client, &server, public_key, pk_sig).await {
                Ok(v) => v,
                Err(e) => {
                    tx.send(e).ok();
                    return;
                }
            };
            let server = format!("https://{}", server);
            match crate::database::server::add_server(&db, &server, allow_insecure_con, &sub.challenge).await {
                Ok(_) => {
                    tx.send(TaskStatus::AddServer(AddServer::Ok)).ok();
                    // Now we spawn tasks for server
                    let server_info = Server {
                        allow_insecure: allow_insecure_con,
                        challenge_key: sub.challenge,
                        last_id: 0,
                        last_seen: 0
                    };
                    ClientEventHandler::spawn_server_tasks(db, servers, tasks, eph_keypair , profile_secret, vec![(server, server_info)]).await;
                },
                Err(e) => {
                    tx.send(TaskStatus::AddServer(AddServer::Error(format!("Fatal error when storing server {} session info to local database: {}", server, e)))).ok();
                }
            }
        },
        Err(e) => {
            tx.send(e).ok();
        }
    }
}

#[derive(Debug)]
pub struct ServersActivity(pub Vec<(String, i64)>);

pub async fn get_server_activity(servers: Arc<RwLock<HashMap<String, Server>>>, tx: oneshot::Sender<TaskStatus>) {
    let mut activity = Vec::new();
    for i in servers.read().await.iter() {
        activity.push((i.0.clone(), i.1.last_seen));
    }

    tx.send(TaskStatus::GetServersActivity(ServersActivity(activity))).ok();
}

#[derive(Debug)]
pub enum AddContact {
    Ok,
    ContactExists(String),
    ServerNotUsed(String),
    Err(String)
}

pub async fn add_contact(db: Database, servers: Arc<RwLock<HashMap<String, Server>>>, name: &str, pk: &PublicKey, server: &str, tx: oneshot::Sender<TaskStatus>) {
    match servers.read().await.contains_key(server) {
        true => {
            let ser_pk = match pk.try_to_vec() {
                Ok(v) => v,
                Err(e) => {
                    tx.send(TaskStatus::AddContact(AddContact::Err(format!("Error serializing public_key: {}", e)))).ok();
                    return;
                }
            };

            let db_err;
            match contact::exists(&db, &ser_pk, server).await {
                Ok(false) => {
                    match contact::add(&db, name, &ser_pk, server).await {
                        Ok(_) => {
                            tx.send(TaskStatus::AddContact(AddContact::Ok)).ok();
                            return;
                        },
                        Err(e) => db_err = e
                    }
                },
                Ok(true) => {
                    tx.send(TaskStatus::AddContact(AddContact::Err(format!("Contact {} already added with the same specified server", name)))).ok();
                    return;
                },
                Err(e) => db_err = e
            }

            tx.send(TaskStatus::AddContact(AddContact::Err(format!("Error database communication: {}", db_err)))).ok();
            return;
        },
        false => {
            tx.send(TaskStatus::AddContact(AddContact::ServerNotUsed(format!("You don't have the server {} in your server list, you must add it first", server)))).ok();
        }
    }
}
