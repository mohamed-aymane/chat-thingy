use super::SessionDB;
use std::error::Error;

#[derive(sqlx::FromRow)]
pub struct SessionName {
    pub name: String,
}

#[derive(sqlx::FromRow)]
pub struct Session {
    pub name: String,
    pub enc_keypair: Vec<u8>
}

pub async fn add(con: &SessionDB, name: &str, enc_blob: &[u8]) -> Result<(), Box<dyn Error + Sync + Send>> {
    if sqlx::query(r#"insert into session (name, enc_keypair) values (?1, ?2)"#)
        .bind(name)
        .bind(enc_blob)
        .execute(&con.con)
        .await?
        .rows_affected() == 0 {
        return Err(Box::new( std::io::Error::new( std::io::ErrorKind::Other, "Error adding session challenge to database" ) ));
    }
    Ok(())
}

pub async fn get_all_name(con: &SessionDB) -> Result<Vec<SessionName>, Box<dyn Error + Sync + Send>> {
    let rez = sqlx::query_as::<_, SessionName>(r#"select name from session"#)
        .fetch_all(&con.con)
        .await?;

    Ok(rez)
}

pub async fn get_session(con: &SessionDB, name: &str) -> Result<Option<Session>, Box<dyn Error + Sync + Send>> {
    let rez = sqlx::query_as::<_, Session>(r#"select name, enc_keypair from session where name = ?1"#)
        .bind(name)
        .fetch_all(&con.con)
        .await?;
    for challenge in rez {
        return Ok(Some(challenge));
    }
    Ok(None)
}
