use std::error::Error;

use common::keys::PublicKey;

use crate::{r#loop::{TaskStatus, TaskType}, client::AddContact};
use super::TaskRequest;

pub fn add(task_handle: &TaskRequest, name: &str, pk: &PublicKey, server: &str) -> Result<AddContact, Box<dyn Error + Send + Sync>> {
    match super::send(task_handle, TaskType::AddContact(name.to_owned(), pk.to_owned(), server.to_owned())) {
        Ok(v) => {
            match v {
                TaskStatus::AddContact(r) => Ok(r),
                _ => panic!("Wrong call in Add server")
            }
        },
        Err(e) => Err(e)
    }
}
