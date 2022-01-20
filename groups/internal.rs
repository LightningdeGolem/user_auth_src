use std::str::FromStr;

use base::{DbConn, db::error_handling::DatabaseErrHandler, err_response, references::InternalReference, replace_json, sql};
use serde_json::Value;
use user_auth_structs::{Group, GroupRef, TenantRef, User, UserRef};


use crate::{UserAuthErrResponse, groups::errors::GroupEndpointError, tenants::internal::TidInternal, users::internal::UidInternal};
use cached::proc_macro::cached;
use super::structures::*;

pub type GidInternal = u64;


#[cached(size=512, option=true, convert="{reference.clone()}", key="InternalReference<GroupRef>")]
/// Converts an external user id to an internal user id
fn decode_group_ref_cached(db: &mut DbConn, reference: &InternalReference<GroupRef>) -> Option<GidInternal>{
    let ret: (GidInternal,) = db.query_first(&sql!("SELECT id FROM auth_groups WHERE group_ref {=}", *reference))?;
    Some(ret.0)
}

pub fn decode_group_ref(db: &mut DbConn, reference: GroupRef) -> Result<GidInternal, UserAuthErrResponse>{
    decode_group_ref_cached(db, &InternalReference::new(reference))
        .ok_or(UserAuthErrResponse::new(GroupEndpointError::NonExistentGroup))
}

#[cached(size=512, convert="{group_id.clone()}", key="GidInternal")]
pub fn get_group_tenant(db: &mut DbConn, group_id: GidInternal) -> TenantRef{
    let ret: (InternalReference<TenantRef>,) = db.query_first(&sql!("
        SELECT tenant_ref 
        FROM auth_groups, auth_tenants 
        WHERE 
            auth_groups.id {=} and 
            auth_groups.tenant_id = auth_tenants.id;
    ", group_id)).unwrap();
    ret.0.inner()
}

pub fn get_group(id: GidInternal, db: &mut DbConn) -> Result<RawGroup, UserAuthErrResponse> {
    let db_err = db.err_handler();
    let results = db.query_map(
        &sql!(
            "SELECT 
                auth_groups.group_ref,
                auth_groups.name,
                auth_tenants.tenant_ref,
                auth_groups.group_type
            FROM auth_groups, auth_tenants
            WHERE
                auth_groups.id {=} AND 
                auth_groups.tenant_id = auth_tenants.id
            ",
            id
        ),
        |(group_ref, name, tenant, group_type): (InternalReference<GroupRef>, Option<String>, InternalReference<TenantRef>, String)| {
            let group_type =
                GroupType::from_str(&group_type).db_expect_or(&db_err, GroupType::Normal);
            RawGroup {
                group_ref: group_ref.inner(),
                name,
                tenant: tenant.inner(),
                group_type,
            }
        },
    );

    match results.into_iter().next() {
        Some(group) => Ok(group),
        None => err_response!(GroupEndpointError::NonExistentGroup),
    }
}

pub fn get_non_special_group(id: GidInternal, db: &mut DbConn) -> Result<Group, UserAuthErrResponse> {
    let group = get_group(id,db)?;
    match group.group_type{
        GroupType::Normal => Ok(group.into()),
        _ => {err_response!(GroupEndpointError::NonExistentGroup)}
    }
}

/// Will check if user is already in group
pub fn add_user_to_group(group_id: GidInternal, user_id: UidInternal, db: &mut DbConn) -> Result<(), UserAuthErrResponse>{
    if get_user_ids_in_group(group_id, db)?.contains(&user_id) {
        return err_response!(GroupEndpointError::UserAlreadyInGroup(user_id, group_id));
    }
    db.query_drop(&sql!("INSERT INTO auth_usergroups (user_id, group_id) VALUES ({}, {})", user_id, group_id));
    Ok(())
}

/// Will check if user is in group
pub fn remove_user_from_group(group_id: GidInternal, user_id: UidInternal, db: &mut DbConn) -> Result<(), UserAuthErrResponse>{
    if !get_user_ids_in_group(group_id, db)?.contains(&user_id) {
        return err_response!(GroupEndpointError::UserNotInGroup(user_id, group_id));
    }
    db.query_drop(&sql!("
        DELETE FROM auth_usergroups WHERE (user_id {=}) and (group_id {=})
    ", user_id, group_id));
    Ok(())
}

pub fn get_user_ids_in_group(group_id: GidInternal, db: &mut DbConn) -> Result<Vec<UidInternal>, UserAuthErrResponse>{
    let results: Vec<UidInternal> = db.query_map(
        &sql!(
            "SELECT 
                auth_users.id
            FROM auth_users, auth_usergroups
            WHERE
                is_deleted = 0 AND
                auth_usergroups.user_id = auth_users.id
                AND auth_usergroups.group_id {=}
            ",
            group_id
        ),
        |(user_id,): (UidInternal,)| {
            user_id
        },
    );

    Ok(results)
}

pub fn get_users_in_group(group_id: GidInternal, db: &mut DbConn) -> Result<Vec<User>, UserAuthErrResponse> {
    let results: Vec<User> = db.query_map(
        &sql!(
            "SELECT 
                auth_users.user_ref,
                username,
                firstname,
                lastname,
                email,
                timezone,
                is_superuser
            FROM auth_users, auth_usergroups
            WHERE
                is_deleted = 0 AND
                auth_usergroups.user_id = auth_users.id
                AND auth_usergroups.group_id {=}
            ",
            group_id
        ),
        |(user_ref, username, firstname, lastname, email, timezone, is_superuser): (
            InternalReference<UserRef>,
            String,
            String,
            String,
            Option<String>,
            String,
            u8,
        )| {
            let is_superuser = is_superuser == 1;
            User {
                user_ref: user_ref.inner(),
                username,
                firstname,
                lastname,
                email,
                timezone,
                is_superuser,
            }
        },
    );

    Ok(results)
}

pub fn get_user_group_refs(user_id: UidInternal, tenant_id: TidInternal, db: &mut DbConn) -> Vec<GroupRef>{
    db.query_map(&sql!("
        SELECT group_ref
        FROM auth_groups, auth_tenants, auth_usergroups
        WHERE
            auth_groups.tenant_id = auth_tenants.id and
            auth_tenants.id {=} and 
            auth_usergroups.user_id {=}
            and auth_usergroups.group_id = auth_groups.id
    ",
        tenant_id,
        user_id
    ),
        |(group_ref,): (InternalReference<GroupRef>,)| group_ref.inner()
    )
}

pub fn create_group(group: CreateGroup, db: &mut DbConn) -> Result<(GroupRef, GidInternal), UserAuthErrResponse> {
    validate_create_group(&group).map_err(|e|{UserAuthErrResponse::new(GroupEndpointError::InvalidField(e))})?;

    let group_ref = InternalReference::<GroupRef>::gen_unique_rand(|suggested| {
        db.query_count(&sql!(
            "SELECT COUNT(*) FROM auth_groups WHERE group_ref {=}",
            (*suggested)
        )) == 0
    });
    let tenant_id= crate::tenants::internal::decode_tenant_ref(db, group.tenant)?;


    let group_id = db.query_insert(&sql!(
        "INSERT INTO auth_groups (group_ref, name, group_type, tenant_id) VALUES ({}, {}, {}, {})",
        group_ref,
        group.name,
        GroupType::Normal,
        tenant_id
    ));

    Ok((group_ref.inner(), group_id))
}

pub fn patch_group(gid: GidInternal, changes: Value, db: &mut DbConn) -> Result<(), UserAuthErrResponse> {
    let group = get_non_special_group(gid, db)?;
    let group: CreateGroup = group.into();


    if changes.get("tenant").is_some(){
        return err_response!(GroupEndpointError::InvalidField("Cannot change group tenant id!"));
    }

    let new_group = replace_json::replace_existing(group, &changes);
    validate_create_group(&new_group).map_err(|e|{UserAuthErrResponse::new(GroupEndpointError::InvalidField(e))})?;
    

    db.query_drop(&sql!(
        "UPDATE auth_groups SET
            name = {}
        WHERE id = {}",
        new_group.name,
        gid
    ));

    Ok(())
}

pub fn delete_group(gid: GidInternal, db: &mut DbConn) -> Result<(), UserAuthErrResponse>{
    get_non_special_group(gid, db)?;

    
    db.start_transaction();

    db.query_drop(&sql!(
        "DELETE FROM auth_usergroups WHERE group_id {=}", gid
    ));
    db.query_drop(&sql!(
        "DELETE FROM auth_groups WHERE id {=}", gid
    ));

    db.commit();
    Ok(())
}
