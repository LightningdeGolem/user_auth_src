use super::InvalidField;
use crate::utils::timezone::is_valid_timezone;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use user_auth_structs::User;


pub fn user_from_json(json: Value) -> Result<CreateUser, InvalidField> {
    let user: CreateUser =
        serde_json::from_value(json).map_err(|e| InvalidField::Deserialization(e))?;
    if user.firstname.len() > 45 {
        return Err(InvalidField::TooLong {
            field: "firstname",
            max: 45,
        });
    }
    if user.firstname.len() == 0 {
        return Err(InvalidField::Empty("firstname"));
    }
    if user.lastname.len() > 45 {
        return Err(InvalidField::TooLong {
            field: "lastname",
            max: 45,
        });
    }
    if user.lastname.len() == 0 {
        return Err(InvalidField::Empty("lastname"));
    }
    if user.username.len() > 16 {
        return Err(InvalidField::TooLong {
            field: "username",
            max: 16,
        });
    }
    if user.username.len() == 0 {
        return Err(InvalidField::Empty("username"));
    }
    if let Some(email) = &user.email {
        if email.len() > 45 {
            return Err(InvalidField::TooLong {
                field: "email",
                max: 45,
            });
        }
    }
    if !is_valid_timezone(&user.timezone) {
        return Err(InvalidField::InvalidTimezone);
    }
    Ok(user)
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct CreateUser {
    pub username: String,
    pub password: String,
    pub firstname: String,
    pub lastname: String,
    pub email: Option<String>,
    pub timezone: String,
}

impl From<User> for CreateUser {
    fn from(user: User) -> Self {
        Self {
            username: user.username,
            password: String::new(),
            firstname: user.firstname,
            lastname: user.lastname,
            email: user.email,
            timezone: user.timezone,
        }
    }
}

#[allow(dead_code)]
pub struct RawUser {
    pub id: u64,
    pub username: String,
    pub password: String,
    pub password_hash_id: u16,
    pub firstname: String,
    pub lastname: String,
    pub email: String,
    pub timezone: String,
    pub is_deleted: u8,
    pub is_superuser: u8,
}
