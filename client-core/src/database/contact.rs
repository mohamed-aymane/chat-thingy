use super::Database;
use std::error::Error;

#[derive(sqlx::FromRow)]
pub struct Contact {
    pub id: u32,
    pub name: String
}

#[derive(sqlx::FromRow)]
struct EphKeypairs {
    eph_keypair: Vec<u8>
}

pub async fn exists(con: &Database, pubkey: &[u8], server: &str) -> Result<bool, Box<dyn Error + Sync + Send>> {
    let rez = sqlx::query(r#"select 1 from contact where public_key = ?1 and server = (select id from server where server = ?2)"#)
        .bind(pubkey)
        .bind(server)
        .fetch_all(&con.con)
        .await?;
    for _ in rez {
        return Ok(true);
    }
    Ok(false)
}

pub async fn add(con: &Database, name: &str, pk: &[u8], server: &str) -> Result<(), Box<dyn Error + Sync + Send>> {
    if sqlx::query(r#"insert into contact (name, public_key, server) values (?1, ?2, (select id from server where server = ?3))"#)
        .bind(name)
        .bind(pk)
        .bind(server)
        .execute(&con.con)
        .await?
        .rows_affected() == 0 {
        return Err(Box::new( std::io::Error::new( std::io::ErrorKind::Other, "Error adding contact to database" ) ));
    }
    Ok(())
}

pub async fn get_contact_from_pk(con: &Database, pk: &[u8], server: &str) -> Result<Option<Contact>, Box<dyn Error + Sync + Send>> {
    let rez = sqlx::query_as::<_, Contact>(r#"select id, name from contact where public_key = ?1 and server = (select id from server where server = ?2)"#)
        .bind(pk)
        .bind(server)
        .fetch_one(&con.con)
        .await;

    match rez {
        Ok(v) => Ok(Some(v)),
        Err(e) => {
            match e {
                sqlx::Error::RowNotFound => Ok(None),
                e @ _ => Err(Box::new(e))
            }
        }
    }
}

pub async fn get_contact_from_ack_eph_pk(con: &Database, pk: &[u8]) -> Result<Option<Contact>, Box<dyn Error + Sync + Send>> {
    let rez = sqlx::query_as::<_, Contact>(r#"select id, name from contact where id = (select id from ephemeral_peer_public_key where public_key = ?1)"#)
        .bind(pk)
        .fetch_one(&con.con)
        .await;

    match rez {
        Ok(v) => Ok(Some(v)),
        Err(e) => {
            match e {
                sqlx::Error::RowNotFound => Ok(None),
                e @ _ => Err(Box::new(e))
            }
        }
    }
}

pub async fn has_eph_pk(con: &Database, pubkey: &[u8], server: &str) -> Result<bool, Box<dyn Error + Sync + Send>> {
    let rez = sqlx::query(r#"select 1 from ephemeral_peer_public_key where id = (select id from contact where public_key = ?1 and server = (select id from server where server = ?2))"#)
        .bind(pubkey)
        .bind(server)
        .fetch_one(&con.con)
        .await;
    
    match rez {
        Ok(_) => Ok(true),
        Err(e) => {
            match e {
                sqlx::Error::RowNotFound => Ok(false),
                e @ _ => Err(Box::new(e))
            }
        }
    }
}

pub async fn update_eph_keypair(con: &Database, contact_id: u32, eph_keypair: &[u8]) -> Result<(), Box<dyn Error + Sync + Send>> {
    if sqlx::query(r#"update contact set eph_keypair = ?1 where id = ?2"#)
        .bind(eph_keypair)
        .bind(contact_id)
        .execute(&con.con)
        .await?
        .rows_affected() == 0 {
        return Err(Box::new( std::io::Error::new( std::io::ErrorKind::Other, "Error updating ephemeral keypairs in database" ) ));
    }
    Ok(())
}

pub async fn get_eph_keypair(con: &Database, contact_id: u32) -> Result<Vec<u8>, Box<dyn Error + Sync + Send>> {
    let rez = sqlx::query_as::<_, EphKeypairs>(r#"select eph_keypair from contact where id = ?1"#)
        .bind(contact_id)
        .fetch_one(&con.con)
        .await?;
    Ok(rez.eph_keypair)
}

pub async fn update_eph_peer_pk(con: &Database, contact_id: u32, eph_peer_pk: &[u8]) -> Result<(), Box<dyn Error + Sync + Send>> {
    if sqlx::query(r#"insert into ephemeral_peer_public_key (id, public_key) values (?1, ?2)"#)
        .bind(contact_id)
        .bind(eph_peer_pk)
        .execute(&con.con)
        .await?
        .rows_affected() == 0 {
        return Err(Box::new( std::io::Error::new( std::io::ErrorKind::Other, "Error updating ephemeral peer public keys in database" ) ));
    }
    Ok(())
}
