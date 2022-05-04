use super::Database;
use std::error::Error;


pub async fn create(con: &Database, pubkey: &[u8]) -> Result<(), Box<dyn Error + Sync + Send>> {
    if sqlx::query(r#"insert into "user" (public_key) values ($1)"#)
        .bind(pubkey)
        .execute(&con.con)
        .await?
        .rows_affected() == 0 {
        return Err(Box::new( std::io::Error::new( std::io::ErrorKind::Other, "Error adding user to database" ) ));
    }
    Ok(())
}

pub async fn remove(con: &Database, pubkey: &[u8]) -> Result<(), Box<dyn Error + Sync + Send>> {
    if sqlx::query(r#"delete from "user" where public_key = $1"#)
        .bind(pubkey)
        .execute(&con.con)
        .await?
        .rows_affected() == 0 {
        return Err(Box::new( std::io::Error::new( std::io::ErrorKind::Other, "Error removing user from database" ) ));
    }
    Ok(())
}

pub async fn exists(con: &Database, pubkey: &[u8]) -> Result<bool, Box<dyn Error + Sync + Send>> {
    let rez = sqlx::query(r#"select 1 from "user" where public_key = $1"#)
        .bind(pubkey)
        .fetch_all(&con.con)
        .await?;
    for _ in rez {
        return Ok(true);
    }
    Ok(false)
}
