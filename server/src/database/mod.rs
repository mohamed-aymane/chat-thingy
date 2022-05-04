pub mod user;
pub mod challenge;
pub mod message;

use sqlx::{Postgres, Pool};
use std::error::Error;

use crate::Config;

#[derive(Debug, Clone)]
pub struct Database {
    pub con: Pool<Postgres>
}

impl Database {
    pub async fn new(conf: &Config) -> Result<Database, Box<dyn Error + Send + Sync>> {
        let pool = sqlx::PgPool::connect(&conf.database_url).await?;
        Ok(Database { con: pool })
    }
}

