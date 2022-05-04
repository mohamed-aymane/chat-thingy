mod server;
mod database;

use std::error::Error;
use tracing::error;

pub struct Config {
    pub database_url: String,
    pub certificate_path: String,
    pub key_path: String,
    pub port: u16
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    tracing_subscriber::fmt().with_thread_names(true).with_max_level(tracing::Level::DEBUG).init();
   
    let conf = Config {
        database_url: "postgres://chat-thingy:chatchat@172.16.224.190/chat".to_owned(),
        certificate_path: "./cert.pem".to_owned(),
        key_path: "./key.pem".to_owned(),
        port: 9999
    };

    let db = match database::Database::new(&conf).await {
        Ok(v) => v,
        Err(e) => {
            error!("Error connecting to database: {}", e);
            return Err(e);
        }
    };
    server::serve(db, &conf).await;

    Ok(())
}
