#![feature(decl_macro)]
use std::{path::PathBuf, sync::Mutex};
use base::requests::response::{MicroserviceError, MicroserviceErrorResponse};
use cache::PasswordResetTokenCache;
use groups::errors::GroupEndpointError;
use serde::Deserialize;
use tenants::TenantEndpointError;
use users::UserEndpointError;

mod groups;
mod tenants;
mod users;
mod utils;
mod cache;

#[macro_use]
extern crate rocket;
extern crate cached;

type ConfigType = UserAuthConf;

#[derive(Deserialize)]
pub struct UserAuthConf {
    default_password_hash_id:         u16,
    password_reset_template_filename: PathBuf,
    password_reset_uri:               String
}

pub type UserAuthErrResponse = MicroserviceErrorResponse<UserAuthError>;

pub enum UserAuthError {
    UserEndpoint(UserEndpointError),
    TenantEndpoint(TenantEndpointError),
    GroupEndpoint(GroupEndpointError),
}
impl From<UserEndpointError> for UserAuthError {
    fn from(e: UserEndpointError) -> Self {
        Self::UserEndpoint(e)
    }
}
impl From<TenantEndpointError> for UserAuthError {
    fn from(e: TenantEndpointError) -> Self {
        Self::TenantEndpoint(e)
    }
}
impl From<GroupEndpointError> for UserAuthError {
    fn from(e: GroupEndpointError) -> Self {
        Self::GroupEndpoint(e)
    }
}
impl MicroserviceError for UserAuthError {
    fn err_code(&self) -> u16 {
        match self {
            UserAuthError::UserEndpoint(e) => e.err_code(),
            UserAuthError::TenantEndpoint(e) => e.err_code(),
            UserAuthError::GroupEndpoint(e) => e.err_code(),
        }
    }

    fn user_message(&self) -> String {
        match self {
            UserAuthError::UserEndpoint(e) => e.user_message(),
            UserAuthError::TenantEndpoint(e) => e.user_message(),
            UserAuthError::GroupEndpoint(e) => e.user_message(),
        }
    }

    fn detailed_message(&self) -> String {
        match self {
            UserAuthError::UserEndpoint(e) => e.detailed_message(),
            UserAuthError::TenantEndpoint(e) => e.detailed_message(),
            UserAuthError::GroupEndpoint(e) => e.detailed_message(),
        }
    }

    fn status(&self) -> base::Status {
        match self {
            UserAuthError::UserEndpoint(e) => e.status(),
            UserAuthError::TenantEndpoint(e) => e.status(),
            UserAuthError::GroupEndpoint(e) => e.status(),
        }
    }

    fn err_prefix() -> u16 {
        0x0001
    }
}

fn main() {

    // set up a password reset token cache to maintain password reset tokens
    let password_reset_token_cache = PasswordResetTokenCache::new();

    let init = base::init::<ConfigType>("user_auth");
    
    init.rocket
        .mount("/user", users::endpoints::get_endpoints())
        .mount("/tenant", tenants::endpoints::get_endpoints())
        .mount("/group", groups::endpoints::get_endpoints())
        .manage(Mutex::new(password_reset_token_cache))
        .launch();
}
