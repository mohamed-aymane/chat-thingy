use std::error::Error;

use crate::{r#loop::{TaskStatus, TaskType}, client::AddServer};
use super::TaskRequest;

pub fn add(task_handle: &TaskRequest, host: &str, port: u16, allow_insecure_con: bool) -> Result<AddServer, Box<dyn Error + Send + Sync>> {
    match super::send(task_handle, TaskType::AddServer(host.to_owned(), port, allow_insecure_con)) {
        Ok(v) => {
            match v {
                TaskStatus::AddServer(r) => Ok(r),
                _ => panic!("Wrong call in Add server")
            }
        },
        Err(e) => Err(e)
    }
}

pub fn get_activity(task_handle: &TaskRequest) -> Result<Vec<(String, i64)>, Box<dyn Error + Send + Sync>> {
    match super::send(task_handle, TaskType::GetServersActivity) {
        Ok(v) => {
            match v {
                TaskStatus::GetServersActivity(r) => Ok(r.0),
                _ => panic!("Wrong call in Add server")
            }
        },
        Err(e) => Err(e)
    }
}
