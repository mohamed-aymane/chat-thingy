use super::Database;
use std::error::Error;

#[derive(sqlx::FromRow)]
pub struct SessionChallenge {
    pub key: Vec<u8>,
    pub timestamp: i64
}

pub async fn set(con: &Database, pubkey: &[u8], key: &[u8], timestamp: i64) -> Result<(), Box<dyn Error + Sync + Send>> {
    if sqlx::query(r#"insert into challenge ("user", key, timestamp) values ((select id from "user" where public_key = $1), $2, $3) on conflict("user")
                      do update set key = $2, timestamp = $3"#)
        .bind(pubkey)
        .bind(key)
        .bind(timestamp)
        .execute(&con.con)
        .await?
        .rows_affected() == 0 {
        return Err(Box::new( std::io::Error::new( std::io::ErrorKind::Other, "Error adding session challenge to database" ) ));
    }
    Ok(())
}

pub async fn get(con: &Database, pubkey: &[u8]) -> Result<Option<SessionChallenge>, Box<dyn Error + Sync + Send>> {
    let rez = sqlx::query_as::<_, SessionChallenge>(r#"select key, timestamp from challenge where "user" = (select id from user where public_key = $1)"#)
        .bind(pubkey)
        .fetch_all(&con.con)
        .await?;
    for challenge in rez {
        return Ok(Some(challenge));
    }
    Ok(None)
}
