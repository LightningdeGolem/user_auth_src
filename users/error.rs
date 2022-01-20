use std::fmt::Display;
use base::{requests::response::MicroserviceError, Status};

#[derive(Debug)]
pub enum UserEndpointError {
    ReadingDenied,
    ModificationDenied,
    UserNonExistent,
    IncorrectPassword,
    CreationDenied,
    DeletionDenied,
    UsernameTaken,
    InvalidField(InvalidField),
    NoEmailForPasswordReset,
    FailedToSendEmail,
    InvalidOrExpiredPasswordResetToken(String),
    UseOtherEndpoint(&'static str),
}

#[derive(Debug)]
pub enum InvalidField {
    Deserialization(serde_json::Error),
    TooLong { field: &'static str, max: usize },
    TooShort { field: &'static str, min: usize },
    Empty(&'static str),
    InvalidTimezone,
}

impl Display for InvalidField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvalidField::Deserialization(e) => write!(f, "JSON error: {}", e),
            InvalidField::TooLong { field, max } => {
                write!(f, "Field {} is too long (max = {})", field, max)
            }
            InvalidField::TooShort { field, min } => {
                write!(f, "Field {} is too short (min = {})", field, min)
            }
            InvalidField::Empty(field) => write!(f, "Field cannot be empty: {}", field),
            InvalidField::InvalidTimezone => write!(f, "Invalid timezone"),
        }
    }
}

impl Display for UserEndpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadingDenied => {
                write!(f, "You do not have permission to view that user's data")
            }
            Self::ModificationDenied => {
                write!(f, "You do not have permission to change that user's data")
            }
            Self::UserNonExistent => write!(f, "User does not exist"),
            Self::IncorrectPassword => write!(f, "Password incorrect"),
            Self::CreationDenied => write!(f, "Permission denied"),
            Self::UsernameTaken => write!(f, "Username is taken"),
            Self::InvalidField(err) => err.fmt(f),
            Self::NoEmailForPasswordReset => write!(f, "No email address for user."),
            Self::FailedToSendEmail => write!(f, "Failed to send email."),
            Self::InvalidOrExpiredPasswordResetToken(token) => write!(f,
                "Invalid or expired password reset token [{}].", token
            ),
            Self::UseOtherEndpoint(endpoint) => write!(f,
                "Please use the other endpoint: {}", endpoint
            ),
            Self::DeletionDenied => write!(f, "You do not have permission to delete that user!"),
        }
    }
}

impl MicroserviceError for UserEndpointError {
    fn err_code(&self) -> u16 {
        match self {
            Self::ReadingDenied                         => 0x0000,
            Self::ModificationDenied                    => 0x0001,
            Self::UserNonExistent                       => 0x0002,
            Self::IncorrectPassword                     => 0x0003,
            Self::CreationDenied                        => 0x0004,
            Self::UsernameTaken                         => 0x0005,
            Self::InvalidField(_)                       => 0x0006,
            Self::NoEmailForPasswordReset               => 0x0007,
            Self::FailedToSendEmail                     => 0x0008,
            Self::InvalidOrExpiredPasswordResetToken(_) => 0x0009,
            Self::UseOtherEndpoint(_)                   => 0x000A,
            Self::DeletionDenied                        => 0x000B,
        }
    }

    fn user_message(&self) -> String {
        match self {
            Self::ReadingDenied => format!("Permission denied"),
            Self::ModificationDenied => format!("Permission denied"),
            Self::UserNonExistent => format!("User does not exist"),
            Self::IncorrectPassword => format!("Password is incorrect"),
            Self::CreationDenied => format!("Permission denied"),
            Self::UsernameTaken => format!("Username is taken"),
            Self::InvalidField(invalid_field) => invalid_field.to_string(),
            Self::NoEmailForPasswordReset => format!("No email address for user."),
            Self::FailedToSendEmail => format!("Failed to send email."),
            Self::InvalidOrExpiredPasswordResetToken(token) => format!(
                "Invalid or expired password reset token [{}].", token
            ),
            Self::UseOtherEndpoint(endpoint) => {
                format!("Please use {} instead", endpoint)
            }
            Self::DeletionDenied => format!("Permission denied"),
        }
    }

    fn detailed_message(&self) -> String {
        match self {
            Self::ReadingDenied => format!("Reading user info denied"),
            Self::ModificationDenied => format!("Writing user info denied"),
            Self::UserNonExistent => format!("User does not exist"),
            Self::IncorrectPassword => format!("Password is incorrect"),
            Self::CreationDenied => format!("Creating user denied"),
            Self::UsernameTaken => format!("Username is taken"),
            Self::InvalidField(invalid_field) => invalid_field.to_string(),
            Self::NoEmailForPasswordReset => format!("No email address for user."),
            Self::FailedToSendEmail => format!("Failed to send email."),
            Self::InvalidOrExpiredPasswordResetToken(token) => format!(
                "Invalid or expired password reset token [{}].", token
            ),
            Self::UseOtherEndpoint(endpoint) => format!("Use {} instead", endpoint),
            Self::DeletionDenied => format!("Deleting user denied"),
        }
    }

    fn status(&self) -> base::Status {
        match self {
            Self::ReadingDenied                         => Status::Forbidden,
            Self::ModificationDenied                    => Status::Forbidden,
            Self::UserNonExistent                       => Status::NotFound,
            Self::IncorrectPassword                     => Status::Forbidden,
            Self::CreationDenied                        => Status::Forbidden,
            Self::UsernameTaken                         => Status::Conflict,
            Self::InvalidField(_)                       => Status::BadRequest,
            Self::NoEmailForPasswordReset               => Status::BadRequest,
            Self::FailedToSendEmail                     => Status::BadGateway,
            Self::InvalidOrExpiredPasswordResetToken(_) => Status::BadRequest,
            Self::UseOtherEndpoint(_)                   => Status::BadRequest,
            Self::DeletionDenied                        => Status::Forbidden,
        }
    }

    fn err_prefix() -> u16 {
        unimplemented!()
    }
}
