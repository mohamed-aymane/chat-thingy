use zeroize::Zeroizing;

use crate::r#loop::{TaskStatus, TaskType};
use super::TaskRequest;
use std::error::Error;

pub fn get_profiles(task_handle: &TaskRequest) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
    match super::send(task_handle, TaskType::GetProfiles) {
        Ok(v) => {
            match v {
                TaskStatus::GetProfiles(v) => Ok(v),
                _ => panic!("Wrong call in Get profiles")
            }
        },
        Err(e) => return Err(e)
    }
}

pub fn add_profile(task_handle: &TaskRequest, name: &str, pass: Zeroizing<String>) -> Result<(), Box<dyn Error + Send + Sync>> {
    match super::send(task_handle, TaskType::AddProfile(name.to_owned(), pass)) {
        Ok(v) => {
            match v {
                TaskStatus::AddProfile(r) => match r {
                    crate::profile::AddProfile::Ok => return Ok(()),
                    crate::profile::AddProfile::Err(e) => return Err(Box::new( std::io::Error::new( std::io::ErrorKind::Other, e) ) ),
                },
                _ => panic!("Wrong call in Get profiles")
            }
        },
        Err(e) => return Err(e)
    }
}

pub fn change_profile(task_handle: &TaskRequest, set: Option<(String, Zeroizing<String>)>) -> Result<(), Box<dyn Error + Send + Sync>> {
    match super::send(task_handle, TaskType::ChangeProfile(set)) {
        Ok(v) => {
            match v {
                TaskStatus::ChangeProfile(r) => match r {
                    crate::profile::ChangeProfile::Ok => return Ok(()),
                    crate::profile::ChangeProfile::Err(e) => return Err(Box::new( std::io::Error::new( std::io::ErrorKind::Other, e) ) ),
                },
                _ => panic!("Wrong call in Change profiles")
            }
        },
        Err(e) => return Err(e)
    }
}
