pub mod profile;
pub mod server;
pub mod contact;
pub mod message;

use sqlx::{sqlite::{SqliteConnectOptions, SqlitePool, Sqlite}, Pool};
use std::{error::Error, str::FromStr};

#[derive(Debug, Clone)]
pub struct SessionDB {
    pub con: Pool<Sqlite>
}

impl SessionDB {
    pub async fn new(dir: &str) -> Result<SessionDB, Box<dyn Error + Send + Sync>> {
        let db = SessionDB { con: SessionDB::connect(dir).await? };
        db.create_if_not_exists().await?;
        Ok(db)
    }

    async fn connect(dir: &str) -> Result<Pool<Sqlite>, Box<dyn Error + Send + Sync>> {
        let opt = SqliteConnectOptions::from_str(&format!("sqlite://{}{}", dir, "/session.db"))?
            .create_if_missing(true);

        Ok(SqlitePool::connect_with(opt).await?)
    }

    pub async fn create_if_not_exists(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        sqlx::query("create table if not exists session (
                     name text primary key,
                     enc_keypair blob not null
                 )")
            .execute(&self.con)
            .await?;

        Ok(())
    }
}


#[derive(Debug, Clone)]
pub struct Database {
    pub con: Pool<Sqlite>
}

impl Database {
    pub async fn new(session_dir: &str) -> Result<Database, Box<dyn Error + Send + Sync>> {
        let db = Database { con: Database::connect(session_dir).await? };
        db.create_if_not_exists().await?;
        Ok(db)
    }

    async fn connect(session_dir: &str) -> Result<Pool<Sqlite>, Box<dyn Error + Send + Sync>> {
        let opt = SqliteConnectOptions::from_str(&format!("sqlite://{}/storage.db", session_dir))?
            .create_if_missing(true);

        Ok(SqlitePool::connect_with(opt).await?)
    }

    pub async fn create_if_not_exists(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        sqlx::query("create table if not exists server (
                     id primary key,
                     server text not null,
                     allow_insecure bool not null,
                     challenge_key blob not null,
                     last_id blob not null
                 )")
            .execute(&self.con)
            .await?;

        sqlx::query("create table if not exists contact (
                     id primary key,
                     public_key blob unique not null,
                     name text not null,
                     server integer not null,
                     eph_keypair blob,
                     foreign key(server) references server(id)
                 )")
            .execute(&self.con)
            .await?;

        sqlx::query("create table if not exists ephemeral_peer_public_key (
                     id integer,
                     key_id integer auto increment,
                     public_key blob unique not null,
                     acknowledged bool not null,
                     primary key(id, key_id),
                     foreign key(id) references contact(id) on delete cascade
                 )")
            .execute(&self.con)
            .await?;

        sqlx::query("create table if not exists message (
                     contact integer not null,
                     message_id integer auto increment,
                     server_msg_id integer not null,
                     source bool not null,
                     content blob not null,
                     timestamp integer not null,
                     primary key(id, message_id),
                     foreign key(contact) references contact(id) on delete cascade
                 )")
            .execute(&self.con)
            .await?;

        sqlx::query("create table if not exists last_read (
                     contact primary key,
                     last_read integer not null,
                     foreign key(contact) references contact(id) on delete cascade
                 )")
            .execute(&self.con)
            .await?;

        sqlx::query("create or replace trigger server_last_read_message after insert 
                     on message
                     begin
                        update server set last_id = new.server_msg_id where id = (select server from contact where user.id = new.contact);
                     end;)")
            .execute(&self.con)
            .await?;

        sqlx::query("create or replace trigger server_remove_old_ephemeral_public_key after insert 
                     on ephemeral_peer_public_key
                     begin
                        delete from ephemeral_peer_public_key where id = new.id and
                            (acknowledged = false or key_id not in 
                                (select key_id from ephemeral_peer_public_key where ephemeral_peer_public_key.id = new.id and acknowledged = true order by key_id desc limit 2))
                     end;)")
            .execute(&self.con)
            .await?;

        Ok(())
    }
}
