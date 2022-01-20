use crate::users::structures::CreateUser;
use serde::Deserialize;
use user_auth_structs::UserRef;


#[derive(Deserialize)]
pub struct CreateTenant {
    pub name: String,
    pub superuser: Option<CreateUser>,
    pub superuser_id: Option<UserRef>,
}
