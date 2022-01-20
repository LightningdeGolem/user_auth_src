use base::logger::LogError;
use base::references::InternalReference;
use base::{err_response, requests::UserRequest, sql, DbConn};
use serde_json::Value;
use cached::proc_macro::cached;
use user_auth_structs::UserRef;
use crate::{
    UserAuthError, UserAuthErrResponse, tenants,
    users::structures::user_from_json,
    utils::hashing
};
use token_auth_structs::LoggedInUser;
use super::{structures::CreateUser, User, UserEndpointError};

pub type UidInternal = u64;

#[cached(size=512, option=true, convert="{reference.clone()}", key="InternalReference<UserRef>")]
/// Converts an external user id to an internal user id
fn decode_user_ref_cached(db: &mut DbConn, reference: &InternalReference<UserRef>)
-> Option<UidInternal> {
    let ret: (UidInternal,) = db.query_first(&sql!("
        SELECT id FROM auth_users
        WHERE user_ref {=} AND is_deleted = 0", *reference
    ))?;
    Some(ret.0)
}

pub fn decode_user_ref(db: &mut DbConn, reference: UserRef) -> Result<UidInternal, UserAuthErrResponse>{
    decode_user_ref_cached(db, &InternalReference::new(reference))
        .ok_or(UserAuthErrResponse::new(UserEndpointError::UserNonExistent))
}

/// Checks if user has the read permission over another
pub fn has_read_perm(db: &mut DbConn, u1: &LoggedInUser, u2_id: UidInternal) -> Result<(), UserAuthErrResponse> {
    let u1_id = decode_user_ref(db, u1.user.user_ref.clone()).unwrap();
    if u1_id == u2_id{
        return Ok(());
    }
    if u1.user.is_superuser {
        return Ok(());
    }


    let u2_tenants = tenants::internal::get_user_tenant_refs(u2_id, db);
    if u2_tenants.contains(&u1.tenant_info.tenant_ref){
        Ok(())
    }
    else{
        err_response!(UserEndpointError::ReadingDenied)
    }

}

/// Checks if user has the write permission over another
pub fn has_write_perm(db: &mut DbConn, u1: &LoggedInUser, u2_id: UidInternal) -> Result<(), UserAuthErrResponse> {
    let u1_id = decode_user_ref(db, u1.user.user_ref.clone()).unwrap();
    if u1_id == u2_id{
        return Ok(());
    }
    if u1.user.is_superuser {
        return Ok(());
    }

    let u2_tenants = tenants::internal::get_user_tenant_refs(u2_id, db);
    if u1.tenant_info.is_tenant_admin && u2_tenants.contains(&u1.tenant_info.tenant_ref){
        Ok(())
    }
    else{
        err_response!(UserEndpointError::ModificationDenied)
    }
}

pub fn delete_user(db: &mut DbConn, user_id: UidInternal){
    db.query_drop(
        &sql!("UPDATE auth_users SET is_deleted = 1 WHERE id = {}", user_id)
    );
}

/// Checks if a username is taken
pub fn is_username_taken(username: &str, conn: &mut DbConn) -> bool {
    conn.query_count(&sql!(
        "SELECT COUNT(*) FROM auth_users WHERE username {=}",
        username
    )) > 0
}

/// Retrieves a user from the database - does not do a permission check
pub fn get_user(user_id: UidInternal, db: &mut DbConn) -> Result<User, UserAuthErrResponse> {
    
    db.query_first(&sql!("
        SELECT user_ref, username, firstname, lastname, email, timezone, is_superuser
        FROM auth_users
        WHERE id {=} AND is_deleted = 0", user_id
    )).map(|(user_ref, username, firstname, lastname, email, timezone, is_superuser):
        (InternalReference<UserRef>, String, String, String, Option<String>, String, bool)| User {
            user_ref: user_ref.inner(),
            username, firstname, lastname, email, timezone, is_superuser
        }
    ).ok_or(
        UserAuthError::from(UserEndpointError::UserNonExistent).into()
    )
}

/// Retrieves the user security info by username: user id, password hash and password hash id
pub fn get_user_sec_info(username: &String, db: &mut DbConn)
-> Result<(UidInternal, String, u16), UserAuthError> {

    db.query_first(&sql!(
        "SELECT id, password, password_hash_id
        FROM auth_users
        WHERE username {=} AND is_deleted = 0", username
    )).ok_or(
        UserAuthError::from(UserEndpointError::UserNonExistent)
    )
}

/// Update a user's hashed password and hash id
pub fn update_password(user_id: u64, new_hash: &String, hash_id: u16, db: &mut DbConn) {
    db.query_drop(&sql!("
        UPDATE auth_users
        SET password = {}, password_hash_id = {} 
        WHERE id {=}",
        new_hash, hash_id, user_id
    ))
}

/// Creates a user - doesn't check permissions
pub fn create_user(
    user: CreateUser,
    request: &mut UserRequest<crate::ConfigType>,
) -> Result<(User, UidInternal), UserAuthErrResponse> {
    let hash_id = request.specific_config().default_password_hash_id;

    let hashed_password = hashing::hash_password(&user.password, hash_id, &request.logger())
        .log_expect(&request.logger(), "Password hashing failure");

    if !is_username_taken(&user.username, request.db()) {
        let user_ref = InternalReference::<UserRef>::gen_unique_rand(|suggested| {
            request.db().query_count(&sql!(
                "SELECT COUNT(*) FROM auth_users WHERE user_ref {=}",
                (*suggested)
            )) == 0
        });

        let user_id = request.db().query_insert(&sql!(
            "INSERT INTO auth_users (user_ref, username, password, password_hash_id, firstname, lastname, email, timezone, is_superuser) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {})",
            user_ref, user.username, hashed_password, hash_id, user.firstname, user.lastname, user.email, user.timezone, 0
        ));

        Ok((User {
            user_ref: user_ref.inner(),
            firstname: user.firstname.clone(),
            lastname: user.lastname.clone(),
            username: user.username.clone(),
            email: user.email.clone(),
            timezone: user.timezone.clone(),
            is_superuser: false,
        }, user_id))
    } else {
        err_response!(UserEndpointError::UsernameTaken)
    }
}

/// Updates user values - doesn't check permissions
pub fn patch_user(id: UidInternal, changes: Value, db: &mut DbConn) -> Result<(), UserAuthErrResponse> {
    let user = get_user(id, db)?;

    let user: CreateUser = user.into();

    let new_user_json = base::replace_json::replace_existing_get_value(user.clone(), &changes);
    let new_user = user_from_json(new_user_json)
        .map_err(|e| UserAuthErrResponse::new(UserEndpointError::InvalidField(e)))?;

    if user == new_user {
        return Ok(());
    }

    if let Some(_) = changes.get("password") {
        return err_response!(UserEndpointError::UseOtherEndpoint(
            "/users/self/change_password"
        ));
    }

    if user.username != new_user.username && is_username_taken(&new_user.username, db) {
        return err_response!(UserEndpointError::UsernameTaken);
    }

    db.query_drop(&sql!(
        "
        UPDATE auth_users SET
            username = {},
            firstname = {},
            lastname = {},
            email = {},
            timezone = {} 
        WHERE id = {}
        ",
        new_user.username,
        new_user.firstname,
        new_user.lastname,
        new_user.email,
        new_user.timezone,
        id
    ));

    Ok(())
}
