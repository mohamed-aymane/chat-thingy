use super::Database;
use std::error::Error;
use async_stream::stream;
use sqlx::postgres::PgListener;
use futures::{ Stream, TryStreamExt };
use base64::encode;

#[derive(sqlx::FromRow)]
pub struct Message {
    pub id: i64,
    pub message: Vec<u8>,
    pub timestamp: i64
}

pub async fn add(con: &Database, dest: &[u8], message: &[u8]) -> Result<(), Box<dyn Error + Sync + Send>> {
    if sqlx::query(r#"insert into message ("user", message) values ((select id from "user" where public_key = $1), $2, $3)"#)
        .bind(dest)
        .bind(message)
        .bind(chrono::Utc::now().timestamp())
        .execute(&con.con)
        .await?
        .rows_affected() == 0 {
        return Err(Box::new( std::io::Error::new( std::io::ErrorKind::Other, "Error adding message to database" ) ));
    }
    Ok(())
}

pub async fn remove(con: &Database, dest: &[u8], id: i64) -> Result<(), Box<dyn Error + Sync + Send>> {
    if sqlx::query(r#"insert into message ("user", id) values ((select id from "user" where public_key = $1), $2)"#)
        .bind(dest)
        .bind(id)
        .execute(&con.con)
        .await?
        .rows_affected() == 0 {
        return Err(Box::new( std::io::Error::new( std::io::ErrorKind::Other, "Error removing message to database" ) ));
    }
    Ok(())
}

pub async fn poll<'a>(con: &'a Database, pk: Vec<u8>, from: i64) -> impl Stream<Item = Result<Message, Box<dyn Error + Send + Sync>>> + 'a + Unpin {
    Box::pin(stream! {
        let mut listener = PgListener::connect_with(&con.con.clone()).await?;
        match listener.listen(&encode(&pk)).await {
            Ok(_) => (),
            Err(e) => {
                yield Err(Box::new(e) as Box<dyn Error + Send + Sync>);
                return;
            }
        }
        let mut last      = 0;
        let mut available = 0;
        loop {
            if last < available || last == 0 {
                let mut rez = sqlx::query_as::<_, Message>(r#"select id, message, timestamp from message where "user" = (select id from "user" where public_key = $1) and id > $1"#)
                    .bind(pk.as_slice())
                    .bind(from)
                    .fetch(&con.con);
                let next = rez.try_next().await;
                match next? {
                    Some(data) => {
                        last = data.id;
                        yield Ok(data)
                    },
                    None => break
                }
            }
            while let Some(notification) = listener.try_recv().await? {
                match notification.payload().parse::<i64>() {
                    Ok(v) => available = v,
                    Err(e) => {
                        yield Err(Box::new( std::io::Error::new( std::io::ErrorKind::Other, format!("Error parsing message id from notification: {}", e) ) ));
                        break;
                    }
                };
            }
        }
    })
}
