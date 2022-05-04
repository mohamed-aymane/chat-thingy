use std::error::Error;

use common::api::response::Status;
use crate::database::{Database, challenge};

pub async fn session_valid(db: &Database, pk: &[u8], signed_challenge: &[u8]) -> Result<Status, Box<dyn Error + Send + Sync>> {
    match challenge::get(&db, pk).await {
        Ok(challenge) => {
            match challenge {
                Some(ch) => {
                    if signed_challenge.eq(&ch.key) &&
                        chrono::Utc::now().timestamp() - ch.timestamp < 3600 {
                        return Ok(Status::Ok);
                    } else {
                        return Ok(Status::InvalidChallengeKey);
                    }
                }
                None => {
                    return Ok(Status::UnknewnPublicKey);
                }
            }
        },
        Err(_) => ()
    }

    Ok(Status::ReqErr)
}
