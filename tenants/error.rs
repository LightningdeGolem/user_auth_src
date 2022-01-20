use base::{Status, requests::response::MicroserviceError};
use user_auth_structs::TenantRef;

use super::internal::TidInternal;

#[derive(Debug)]
pub enum TenantEndpointError {
    Creation(CreationError),
    MalformedTenantRef(String),
    TenantNonExistent(TenantRef),
    TenantNotAuthorized(TenantRef),
    TenantRequired,
    SupergroupNotFound(TidInternal),
    AdminGroupNotFound(TidInternal),
    ReadingDenied,
    ModificationDenied,
}

impl MicroserviceError for TenantEndpointError {
    fn err_code(&self) -> u16 {
        match self {
            TenantEndpointError::Creation(e) => e.err_code(),
            TenantEndpointError::MalformedTenantRef(_)  => 0x0110,
            TenantEndpointError::TenantNonExistent(_)   => 0x0111,
            TenantEndpointError::TenantNotAuthorized(_) => 0x0112,
            TenantEndpointError::TenantRequired         => 0x0113,
            TenantEndpointError::SupergroupNotFound(_)  => 0x0114,
            TenantEndpointError::AdminGroupNotFound(_)  => 0x0115,
            TenantEndpointError::ReadingDenied          => 0x0116,
            TenantEndpointError::ModificationDenied     => 0x0117,
        }
    }

    fn user_message(&self) -> String {
        match self {
            TenantEndpointError::Creation(e) => e.user_message(),
            TenantEndpointError::MalformedTenantRef(r) => format!(
                "Malformed tenant reference [{}].", r
            ),
            TenantEndpointError::TenantNonExistent(_)   => format!("Tenant does not exist"),
            TenantEndpointError::TenantNotAuthorized(_) => format!("Tenant not authorized"),
            TenantEndpointError::TenantRequired         => format!("Tenant reference required"),
            TenantEndpointError::SupergroupNotFound(_)  => String::new(),
            TenantEndpointError::AdminGroupNotFound(_)  => String::new(),
            TenantEndpointError::ReadingDenied          => format!("Permission denied"),
            TenantEndpointError::ModificationDenied     => format!("Permission denied"),
        }
    }

    fn detailed_message(&self) -> String {
        match self {
            TenantEndpointError::Creation(e) => e.detailed_message(),
            TenantEndpointError::MalformedTenantRef(r) => format!(
                "Malformed tenant reference [{}].", r
            ),
            TenantEndpointError::TenantNonExistent(tr) => format!(
                "Tenant [{}] does not exist.", tr
            ),
            TenantEndpointError::TenantNotAuthorized(tr) => format!(
                "Tenant [{}] not authorized for this user.", tr
            ),
            TenantEndpointError::TenantRequired => format!(
                "Tenant reference not provided - required for this user."
            ),
            TenantEndpointError::SupergroupNotFound(uid) => format!("Supergroup [internal={}] not found", uid),
            TenantEndpointError::AdminGroupNotFound(uid) => format!("Admingroup not found for tenant [{}]", uid),
            TenantEndpointError::ReadingDenied => format!("Permission denied: reading tenant information"),
            TenantEndpointError::ModificationDenied => format!("Permission denied: changing tenant information"),
        }
    }

    fn status(&self) -> base::Status {
        match self {
            TenantEndpointError::Creation(e)            => e.status(),
            TenantEndpointError::MalformedTenantRef(_)  => Status::NotFound,
            TenantEndpointError::TenantNonExistent(_)   => Status::NotFound,
            TenantEndpointError::TenantNotAuthorized(_) => Status::Forbidden,
            TenantEndpointError::TenantRequired         => Status::BadRequest,
            TenantEndpointError::SupergroupNotFound(_)  => Status::InternalServerError,
            TenantEndpointError::AdminGroupNotFound(_)  => Status::InternalServerError,
            TenantEndpointError::ReadingDenied          => Status::Forbidden,
            TenantEndpointError::ModificationDenied     => Status::Forbidden,
        }
    }

    fn err_prefix() -> u16 {
        unimplemented!()
    }
}

#[derive(Debug)]
pub enum CreationError {
    Denied,
    MissingSuperuser,
}

impl MicroserviceError for CreationError {
    fn err_code(&self) -> u16 {
        match self {
            CreationError::Denied => 0x0100,
            CreationError::MissingSuperuser => 0x0101,
        }
    }

    fn user_message(&self) -> String {
        match self {
            CreationError::Denied => format!("Permission denied"),
            CreationError::MissingSuperuser => {
                format!("Please specify either `superuser` or `superuser_id`")
            }
        }
    }

    fn detailed_message(&self) -> String {
        match self {
            CreationError::Denied => format!("Tenant creation denied"),
            CreationError::MissingSuperuser => format!("Missing superuser in creation request"),
        }
    }

    fn status(&self) -> base::Status {
        match self {
            CreationError::Denied => Status::Forbidden,
            CreationError::MissingSuperuser => Status::BadRequest,
        }
    }

    fn err_prefix() -> u16 {
        unimplemented!()
    }
}
