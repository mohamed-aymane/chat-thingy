use super::Database;
use std::{error::Error, collections::HashMap};

#[derive(sqlx::FromRow)]
struct InnerServer {
    pub server: String,
    pub allow_insecure: bool,
    pub challenge_key: Vec<u8>,
    pub last_id: i64
}

#[derive(Clone)]
pub struct Server {
    pub allow_insecure: bool,
    pub challenge_key: Vec<u8>,
    pub last_id: i64,
    pub last_seen: i64
}

pub async fn add_server(con: &Database, server: &str, allow_insecure: bool, challenge_key: &[u8]) -> Result<(), Box<dyn Error + Sync + Send>> {
    if sqlx::query(r#"insert into server(server, allow_insecure, challenge_key, last_id) values (?1, ?2, ?3, 0)"#)
        .bind(server)
        .bind(allow_insecure)
        .bind(challenge_key)
        .execute(&con.con)
        .await?
        .rows_affected() == 0 {
        return Err(Box::new( std::io::Error::new( std::io::ErrorKind::Other, "Error adding server to database" ) ));
    }
    Ok(())
}


pub async fn update_challenge_key(con: &Database, server: &str, challenge_key: &[u8]) -> Result<(), Box<dyn Error + Sync + Send>> {
    if sqlx::query(r#"update server set challenge_key = ?1 where server = ?2"#)
        .bind(challenge_key)
        .bind(server)
        .execute(&con.con)
        .await?
        .rows_affected() == 0 {
        return Err(Box::new( std::io::Error::new( std::io::ErrorKind::Other, format!("Error updating challenge key for server {}", server) ) ));
    }
    Ok(())
}

pub async fn update_insecure_policy(con: &Database, server: &str, allow_insecure: bool) -> Result<(), Box<dyn Error + Sync + Send>> {
    if sqlx::query(r#"update server set allow_insecure = ?1 where server = ?2"#)
        .bind(allow_insecure)
        .bind(server)
        .execute(&con.con)
        .await?
        .rows_affected() == 0 {
        return Err(Box::new( std::io::Error::new( std::io::ErrorKind::Other, format!("Error updating insecure policy for server {}", server) ) ));
    }
    Ok(())
}

pub async fn get_all(con: &Database) -> Result<HashMap<String, Server>, Box<dyn Error + Sync + Send>> {
    let rez = sqlx::query_as::<_, InnerServer>(r#"select server, allow_insecure, challenge_key, last_id from server"#)
        .fetch_all(&con.con)
        .await?;

    let mut servers = HashMap::new();
    for i in rez {
        servers.insert(i.server, Server {
            allow_insecure: i.allow_insecure,
            challenge_key: i.challenge_key,
            last_id: i.last_id,
            last_seen: 0
        });
    }

    Ok(servers)
}
