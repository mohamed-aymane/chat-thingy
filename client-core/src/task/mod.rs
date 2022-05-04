pub mod profile;
pub mod server;
pub mod contact;

use std::error::Error;
use tokio::sync::{mpsc, oneshot};

use crate::r#loop::{Task, TaskType, TaskStatus};

pub struct TaskRequest {
    pub tx: mpsc::Sender<Task>
}

pub fn send(task_handle: &TaskRequest, typ: TaskType) -> Result<TaskStatus, Box<dyn Error + Send + Sync>> {
    let handle = task_handle.tx.clone();

    let (tx, rx) = oneshot::channel();

    match handle.blocking_send(Task {
        typ,
        resp: tx
    }) {
        Ok(_) => (),
        Err(e) => return Err(Box::new( std::io::Error::new( std::io::ErrorKind::Other, format!("Error sending task: {}", e) ) ))
    };

    Ok(match rx.blocking_recv() {
        Ok(v) => v,
        Err(e) => return Err(Box::new( std::io::Error::new( std::io::ErrorKind::Other, format!("Error getting task response: {}", e) ) ))
    })
}
