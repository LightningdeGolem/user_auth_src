use std::str::FromStr;

use super::structures::*;
use crate::groups::internal::GidInternal;
use crate::groups::structures::RawGroup;
use crate::users::internal::UidInternal;
use crate::{
    groups::{self, structures::GroupType},
    tenants::{CreationError, TenantEndpointError},
    users, UserAuthErrResponse,
};
use base::db::error_handling::DatabaseErrHandler;
use base::references::InternalReference;
use base::{
    err_response, log, log_important,
    requests::UserRequest, sql, DbConn,
};

use cached::proc_macro::cached;
use user_auth_structs::{Group, GroupRef, Tenant, TenantRef, User, UserRef};



pub type TidInternal = u64;

#[cached(size=512, option=true, convert="{reference.clone()}", key="InternalReference<TenantRef>")]
/// Converts a user reference to an internal user id
fn decode_tenant_ref_cached(db: &mut DbConn, reference: &InternalReference<TenantRef>) -> Option<TidInternal>{
    let ret: (TidInternal,) = db.query_first(&sql!("SELECT id FROM auth_tenants WHERE tenant_ref {=}", *reference))?;
    Some(ret.0)
}

pub fn decode_tenant_ref(db: &mut DbConn, reference: TenantRef) -> Result<TidInternal, UserAuthErrResponse>{
    decode_tenant_ref_cached(db, &InternalReference::new(reference.clone()))
        .ok_or(UserAuthErrResponse::new(TenantEndpointError::TenantNonExistent(reference.clone())))
}

#[cached(size=512, convert="{internal}", key="TidInternal")]
/// Converts an external user id to an internal user id
pub fn encode_tenant_ref(db: &mut DbConn, internal: TidInternal) -> TenantRef{
    let ret: (InternalReference<TenantRef>,) = db.query_first(&sql!("SELECT tenant_ref FROM auth_tenants WHERE id {=}", internal)).ok_or("Unknwon tenant internal ID").db_expect(&db.err_handler());
    ret.0.inner()
}

// ///Does not check if user or tenant exists
// pub fn is_user_in_tenant(tenant_id: TidInternal, user_id: UidInternal, db: &mut DbConn) -> bool{
//     db.query_count(&sql!(
//         "
//             SELECT COUNT(*) FROM auth_usergroups
//             WHERE
//                 user_id {=} AND
//                 group_id = (
//                     SELECT id FROM auth_groups
//                     WHERE group_type {=} AND
//                     tenant_id {=}
//                 )
//         ",
//         user_id, GroupType::SuperGroup, tenant_id
//     )) == 1
// }

// ///Does not check if user or tenant exists
// pub fn is_user_tenant_admin(tenant_id: TidInternal, user_id: UidInternal, db: &mut DbConn) -> bool{
//     db.query_count(&sql!(
//         "
//             SELECT COUNT(*) FROM auth_usergroups
//             WHERE
//                 user_id {=} AND
//                 group_id = (
//                     SELECT id FROM auth_groups
//                     WHERE group_type {=} AND
//                     tenant_id {=}
//                 )
//         ",
//         user_id, GroupType::AdminGroup, tenant_id
//     )) == 1
// }

pub fn get_tenant_group_ids(
    tenant_id: TidInternal,
    group_type: GroupType,
    db: &mut DbConn,
) -> Result<Vec<GidInternal>, UserAuthErrResponse> {
    let results = db.query_map(
        &sql!(
            "SELECT id FROM auth_groups WHERE tenant_id {=} AND group_type {=}",
            tenant_id,
            group_type
        ),
        |(id,): (GidInternal,)| id,
    );

    Ok(results)
}

pub fn get_tenant_group_refs(
    tenant_id: TidInternal,
    group_type: GroupType,
    db: &mut DbConn,
) -> Result<Vec<GroupRef>, UserAuthErrResponse> {
    let results = db.query_map(
        &sql!(
            "SELECT group_ref FROM auth_groups WHERE tenant_id {=} AND group_type {=}",
            tenant_id,
            group_type
        ),
        |(id,): (InternalReference<GroupRef>,)| id.inner(),
    );

    Ok(results)
}

pub fn get_tenant_groups(
    tenant_id: TidInternal,
    group_type: GroupType,
    tenant_ref: &TenantRef,
    db: &mut DbConn,
) -> Result<Vec<RawGroup>, UserAuthErrResponse> {
    let db_err = db.err_handler();
    let results = db.query_map(
        &sql!(
            "SELECT group_ref, name, group_type FROM auth_groups WHERE tenant_id {=} AND group_type {=}",
            tenant_id,
            group_type
        ),
        |(group_ref,name,gtype): (InternalReference<GroupRef>, Option<String>, String)| {
            let group_type = GroupType::from_str(&gtype).db_expect_or(&db_err, GroupType::Normal);
            let group_ref = group_ref.inner();
            RawGroup{
                group_ref,
                name: name,
                group_type: group_type,
                tenant: tenant_ref.clone()
            }
        },
    );

    Ok(results)
}

pub fn get_tenant_non_special_groups(tenant_id: TidInternal, tenant_ref: &TenantRef, db: &mut DbConn) -> Result<Vec<Group>, UserAuthErrResponse>{
    Ok(
        get_tenant_groups(tenant_id, GroupType::Normal, tenant_ref, db)?
            .into_iter()
            .map(|g|g.into())
            .collect()
    )
}

pub fn get_tenant(id: TidInternal, db: &mut DbConn) -> Tenant {
    let results = db.query_map(
        &sql!("SELECT tenant_ref, name FROM auth_tenants WHERE id {=}", id),
        |(tenant_ref, name): (InternalReference<TenantRef>, String)| 
            Tenant { tenant_ref: tenant_ref.inner(), name },
    );

    results.into_iter().next().ok_or("Internal ID not found in table!").db_expect(&db.err_handler())
}

pub fn get_tenant_supergroup(id: TidInternal, db: &mut DbConn) -> Result<GidInternal, UserAuthErrResponse>{
    get_tenant_group_ids(id, GroupType::SuperGroup, db)?
        .into_iter()
        .next()
        .ok_or(UserAuthErrResponse::new(TenantEndpointError::SupergroupNotFound(id)))
}

pub fn get_tenant_supergroup_ref(id: TidInternal, db: &mut DbConn) -> Result<GroupRef, UserAuthErrResponse>{
    get_tenant_group_refs(id, GroupType::SuperGroup, db)?
        .into_iter()
        .next()
        .ok_or(UserAuthErrResponse::new(TenantEndpointError::SupergroupNotFound(id)))
}

pub fn get_tenant_admingroup(id: TidInternal, db: &mut DbConn) -> Result<GidInternal, UserAuthErrResponse>{
    get_tenant_group_ids(id, GroupType::AdminGroup, db)?
        .into_iter()
        .next()
        .ok_or(UserAuthErrResponse::new(TenantEndpointError::AdminGroupNotFound(id)))
}

pub fn get_tenant_admingroup_ref(id: TidInternal, db: &mut DbConn) -> Result<GroupRef, UserAuthErrResponse>{
    get_tenant_group_refs(id, GroupType::AdminGroup, db)?
        .into_iter()
        .next()
        .ok_or(UserAuthErrResponse::new(TenantEndpointError::AdminGroupNotFound(id)))
}


pub fn get_tenant_users(id: TidInternal, db: &mut DbConn) -> Result<Vec<User>, UserAuthErrResponse> {
    let supergroup = get_tenant_supergroup(id, db)?;
    groups::internal::get_users_in_group(supergroup, db)
}

pub fn get_tenant_admins(id: TidInternal, db: &mut DbConn) -> Result<Vec<User>, UserAuthErrResponse> {
    match get_tenant_group_ids(id, GroupType::AdminGroup, db)?
        .into_iter()
        .next()
    {
        Some(supergroup) => groups::internal::get_users_in_group(supergroup, db),
        None => err_response!(TenantEndpointError::SupergroupNotFound(id)),
    }
}

pub fn get_user_tenant_refs(user_id: UidInternal, db: &mut DbConn) -> Vec<TenantRef>{
    let results = db.query_map(&sql!("
        SELECT tenant_ref
        FROM auth_tenants, auth_usergroups, auth_groups
        WHERE 
            auth_groups.tenant_id = auth_tenants.id and 
            auth_usergroups.group_id = auth_groups.id and 
            auth_groups.group_type = 's' and 
            auth_usergroups.user_id {=};
    ",user_id),
    |(tenant_ref,):(InternalReference<TenantRef>,)|{
        tenant_ref.inner()
    });

    results
}

pub fn create_tenant(
    tenant: CreateTenant,
    request: &mut UserRequest<crate::ConfigType>,
) -> Result<(TenantRef, TidInternal, UserRef), UserAuthErrResponse> {
    let logger = request.logger();

    if tenant.superuser.is_none() && tenant.superuser_id.is_none() {
        return err_response!(TenantEndpointError::Creation(
            CreationError::MissingSuperuser
        ));
    }

    request.db().start_transaction();

    log_important!("Creating tenant {}...", tenant.name);
    log!("  Creating in tenant table...");

    let tenant_ref = InternalReference::<TenantRef>::gen_unique_rand(|suggested| {
        request.db().query_count(&sql!(
            "SELECT COUNT(*) FROM auth_tenants WHERE tenant_ref {=}",
            (*suggested)
        )) == 0
    });

    let tenant_id= request.db().query_insert(&sql!(
        "INSERT INTO auth_tenants (tenant_ref, name) VALUES ({}, {})",
        tenant_ref,
        tenant.name
    ));

    log!("  ...Success [id={}]", tenant_id);

    log!("  Creating supergroup...");

    let supergroup_ref = InternalReference::<GroupRef>::gen_unique_rand(|suggested| {
        request.db().query_count(&sql!(
            "SELECT COUNT(*) FROM auth_groups WHERE group_ref {=}",
            (*suggested)
        )) == 0
    });

    let supergroup_id = request.db().query_insert(&sql!(
        "INSERT INTO auth_groups (group_ref, name, group_type, tenant_id) VALUES ({}, NULL, {}, {})",
        supergroup_ref,
        (GroupType::SuperGroup),
        tenant_id
    ));

    log!("  ...Success [id={}]", supergroup_id);
    log!("  Creating admin group...");

    let admingroup_ref = InternalReference::<GroupRef>::gen_unique_rand(|suggested| {
        request.db().query_count(&sql!(
            "SELECT COUNT(*) FROM auth_groups WHERE group_ref {=}",
            (*suggested)
        )) == 0
    });

    let admingroup_id = request.db().query_insert(&sql!(
        "INSERT INTO auth_groups (group_ref, name, group_type, tenant_id) VALUES ({}, NULL, {}, {})",
        admingroup_ref,
        (GroupType::AdminGroup),
        tenant_id
    ));

    log!("  ...Success [id={}]", admingroup_id);

    let (superuser_ref, superuser_id) = match tenant.superuser_id {
        Some(user_ref) => {
            let user_id = users::internal::decode_user_ref(request.db(), user_ref.clone())?;
            users::internal::get_user(user_id, request.db())?;
            (user_ref, user_id)
        }
        None => {
            let new_user = tenant.superuser.unwrap();
            let new_user = users::internal::create_user(new_user, request)?;
            (new_user.0.user_ref, new_user.1)
        }
    };

    request.db().query_drop(&sql!(
        "
        INSERT INTO auth_usergroups (user_id, group_id) VALUES ({},{})
    ",
        superuser_id,
        supergroup_id
    ));

    request.db().query_drop(&sql!(
        "
        INSERT INTO auth_usergroups (user_id, group_id) VALUES ({},{})
    ",
        superuser_id,
        admingroup_id
    ));

    request.db().commit();
    Ok((tenant_ref.inner(), tenant_id, superuser_ref))
}
