use std::sync::Arc;
use tokio::{
    sync::{mpsc, oneshot, RwLock}, task::JoinHandle
};
use std::{error::Error, collections::HashMap};
use zeroize::Zeroizing;

use common::keys::PublicKey;

use crate::database::SessionDB;

pub struct Task {
pub typ: TaskType,
    pub resp: oneshot::Sender<TaskStatus>
}

pub enum TaskType {
    GetProfiles,
    AddProfile(String, Zeroizing<String>),
    ChangeProfile(Option<(String, Zeroizing<String>)>),
    AddServer(String, u16, bool),
    GetServersActivity,
    AddContact(String, PublicKey, String),
    //EditServer(String),
    //SendMessage(Vec<u8>),
    //UploadFile(Vec<u8>)
}

#[derive(Debug)]
pub enum TaskStatus {
    GetProfiles(Vec<String>),
    AddProfile(crate::profile::AddProfile),
    ChangeProfile(crate::profile::ChangeProfile),
    AddServer(crate::client::AddServer),
    GetServersActivity(crate::client::ServersActivity),
    AddContact(crate::client::AddContact),
}

pub struct LoopSet {
    pub profile_tasks: Arc<RwLock<HashMap<u64, JoinHandle<()>>>>,
    pub sess_db: SessionDB,
    pub session_task_tx: Option<mpsc::Sender<Task>>,
    pub work_dir: String
}

async fn suspend_profile_tasks(loop_set: &mut LoopSet) {
    if loop_set.profile_tasks.read().await.is_empty() {
        return;
    }

    // Aborting tasks
    for i in &mut loop_set.profile_tasks.write().await.iter_mut() {
        i.1.abort();
    }
    // Waiting for them to stop and removing them from hashmap
    for i in &mut loop_set.profile_tasks.write().await.drain().take(1) {
        i.1.await.ok();
    }
}

#[tokio::main]
async fn start(mut loop_set: LoopSet, mut rx: mpsc::Receiver<Task>) -> Result<(), Box<dyn Error + Send + Sync>> {
    loop {
        match rx.recv().await {
            Some(task) => {
                match &task.typ {
                    TaskType::GetProfiles => {
                        let db = loop_set.sess_db.clone();
                        tokio::task::spawn(async move {
                            crate::profile::get_all(db, task.resp).await;
                        });
                    }
                    TaskType::AddProfile(name, pass) => {
                        crate::profile::add_profile(&mut loop_set, name.clone(), pass.clone(), task.resp).await;
                    },
                    TaskType::ChangeProfile(ch) => {
                        // We first suspend all current profile tasks
                        suspend_profile_tasks(&mut loop_set).await;
                        // Then we change profile
                        match crate::profile::change_profile(&mut loop_set, ch.clone(), task.resp).await {
                            Some(a) => {
                                loop_set.session_task_tx = Some(a);
                            },
                            None => ()
                        }
                    },
                    TaskType::AddServer(_, _, _) | TaskType::GetServersActivity
                        | TaskType::AddContact(_, _, _) => {
                        match loop_set.session_task_tx.clone() {
                            Some(v) => {
                                if !v.is_closed() {
                                    match v.send(task).await {
                                        Ok(_) => (),
                                        Err(_) => ()
                                    }
                                    continue;
                                }
                            },
                            None => ()
                        }
                        task.resp.send(TaskStatus::AddServer(crate::client::AddServer::NoProfile("You must be connected to a profile before performing this task".to_owned()))).ok();
                    },
                }
            },
            // Something wrong exiting
            None => {
                for i in &mut loop_set.profile_tasks.write().await.iter_mut() {
                    i.1.abort();
                }
                break
            }
        }
    };


    Ok(())
}

#[tokio::main]
pub async fn init(home_dir: &str) -> Result<crate::task::TaskRequest, Box<dyn Error + Send + Sync>> {
    let home_dir = home_dir.to_owned();

    let loop_set = LoopSet {
        profile_tasks: Arc::new(RwLock::new(HashMap::new())),
        sess_db: futures::executor::block_on(SessionDB::new(home_dir.as_str()))?,
        session_task_tx: None,
        work_dir: home_dir
    };

    let (tx, rx) = mpsc::channel(100);

    std::thread::spawn(move || {
        start(loop_set, rx).ok();
    });

    Ok(crate::task::TaskRequest { tx })
}

