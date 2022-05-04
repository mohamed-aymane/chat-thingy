use super::Database;
use std::error::Error;

pub async fn add(con: &Database, user_id: u32, msg_id: i64, msg_timestamp: i64, source: bool, ser_msg: &[u8]) -> Result<(), Box<dyn Error + Sync + Send>> {
    if sqlx::query(r#"insert into message (contact, server_msg_id, source, content, timestamp) values (?1, ?2, ?3, ?4, ?5)"#)
        .bind(user_id)
        .bind(msg_id)
        .bind(msg_timestamp)
        .bind(source)
        .bind(ser_msg)
        .execute(&con.con)
        .await?
        .rows_affected() == 0 {
        return Err(Box::new( std::io::Error::new( std::io::ErrorKind::Other, "Error adding new message to database" ) ));
    }
    Ok(())
}
