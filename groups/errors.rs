use base::{requests::response::MicroserviceError, Status};

use crate::users::internal::UidInternal;

use super::internal::GidInternal;

pub enum GroupEndpointError {
    NonExistentGroup,
    InvalidField(&'static str),
    UserAlreadyInGroup(UidInternal, GidInternal),
    UserNotInGroup(UidInternal, GidInternal),
    ReadingDenied,
    ModificationDenied,
    CreationDenied,
    DeletionDenied
}

impl MicroserviceError for GroupEndpointError {
    fn err_code(&self) -> u16 {
        match self {
            GroupEndpointError::NonExistentGroup => 0x0200,
            GroupEndpointError::UserAlreadyInGroup(_,_) => 0x0201,
            GroupEndpointError::InvalidField(_) => 0x0202,
            GroupEndpointError::UserNotInGroup(_,_) => 0x0203,
            GroupEndpointError::ReadingDenied => 0x0204,
            GroupEndpointError::ModificationDenied => 0x0205,
            GroupEndpointError::CreationDenied => 0x0206,
            GroupEndpointError::DeletionDenied => 0x0207,
        }
    }

    fn user_message(&self) -> String {
        match self {
            GroupEndpointError::NonExistentGroup => format!("Group does not exist"),
            GroupEndpointError::UserAlreadyInGroup(_, _) => format!("User already in group"),
            GroupEndpointError::UserNotInGroup(_, _) => format!("User not in group"),
            GroupEndpointError::InvalidField(msg) => format!("Invalid field: {}", msg),
            GroupEndpointError::ReadingDenied => format!("Reading group information denied"),
            GroupEndpointError::ModificationDenied => format!("Chaning group information denined"),
            GroupEndpointError::CreationDenied => format!("Creating group denied"),
            GroupEndpointError::DeletionDenied => format!("Deleting group denied"),
        }
    }

    fn detailed_message(&self) -> String {
        match self {
            GroupEndpointError::NonExistentGroup => format!("Group does not exist"),
            GroupEndpointError::UserAlreadyInGroup(uid, gid) => format!("User [{}] already in group [{}]", uid, gid),
            GroupEndpointError::UserNotInGroup(uid, gid) => format!("User [{}] not in group [{}]", uid, gid),
            GroupEndpointError::InvalidField(msg) => format!("Invalid field provided: {}", msg),
            GroupEndpointError::ReadingDenied => format!("Reading group information denied"),
            GroupEndpointError::ModificationDenied => format!("Chaning group information denined"),
            GroupEndpointError::CreationDenied => format!("Creating group denied"),
            GroupEndpointError::DeletionDenied => format!("Deleting group denied"),
        }
    }

    fn status(&self) -> base::Status {
        match self {
            GroupEndpointError::NonExistentGroup => Status::NotFound,
            GroupEndpointError::UserAlreadyInGroup(_, _) => Status::BadRequest,
            GroupEndpointError::UserNotInGroup(_, _) => Status::BadRequest,
            GroupEndpointError::InvalidField(_) => Status::BadRequest,
            GroupEndpointError::ReadingDenied => Status::Forbidden,
            GroupEndpointError::ModificationDenied => Status::Forbidden,
            GroupEndpointError::CreationDenied => Status::Forbidden,
            GroupEndpointError::DeletionDenied => Status::Forbidden,
        }
    }

    fn err_prefix() -> u16 {
        unimplemented!()
    }
}
