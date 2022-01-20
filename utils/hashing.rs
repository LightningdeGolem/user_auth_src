use std::{fmt::Display, time::Instant};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use base::{log, requests::RequestLogger};

pub enum HashError {
    UnknownHashId,
    Argon2(argon2::password_hash::Error),
}

impl Display for HashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownHashId => {
                write!(f, "Unknown hash")
            }
            Self::Argon2(e) => e.fmt(f),
        }
    }
}

fn hash_argon2(plain: &[u8]) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let hashed = argon2.hash_password_simple(plain, salt.as_ref())?;
    Ok(hashed.to_string())
}

fn verify_argon2(hash: &str, plain: &[u8]) -> Result<bool, argon2::password_hash::Error> {
    let argon2 = Argon2::default();
    let hash = PasswordHash::new(hash)?;
    match argon2.verify_password(plain, &hash) {
        Ok(_) => Ok(true),
        Err(e) => match e {
            argon2::password_hash::Error::Password => Ok(false),
            e => Err(e),
        },
    }
}

pub fn hash_password(plaintext: &str, hash_id: u16, logger: &RequestLogger)
-> Result<String, HashError> {
    let start_datetime = Instant::now();
    let hash = match hash_id {
        0 => Ok(plaintext.to_string()),
        1 => hash_argon2(plaintext.as_bytes()).map_err(|e| HashError::Argon2(e)),
        _ => Err(HashError::UnknownHashId),
    };
    let duration = Instant::now().duration_since(start_datetime).as_millis();
    log!("Created password hash {f:yellow}[{}ms]", duration);
    hash
}

pub fn verify_password(plaintext: &str, hash: &str, hash_id: u16, logger: &RequestLogger)
-> Result<bool, HashError> {
    let start_datetime = Instant::now();
    let valid = match hash_id {
        0 => Ok(plaintext == hash),
        1 => verify_argon2(hash, plaintext.as_bytes()).map_err(|e| HashError::Argon2(e)),
        _ => Err(HashError::UnknownHashId),
    };
    let duration = Instant::now().duration_since(start_datetime).as_millis();
    log!(
        "Validated password hash {f:yellow}[{}ms]{f:white}: {}",
        duration, match valid {
            Ok(v)  => if v {"SUCCESS"} else {"FAILED"},
            Err(_) => "ERROR"
        }
    );
    valid
}
