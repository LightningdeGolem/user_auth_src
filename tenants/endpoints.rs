use crate::{UserAuthErrResponse, groups, tenants::{CreationError, TenantEndpointError}, users::internal::decode_user_ref, utils::cache_updater::update_user_info};
use base::{Status, err_response, requests::{response::text_response::JsonBody, UserRequest}};
use rocket::{response::status::Created, Route};
use rocket_contrib::json::Json;
use user_auth_structs::{Group, Tenant, TenantRef, User, UserRef};

use super::internal::{self, decode_tenant_ref};
use super::structures::*;

pub fn get_endpoints() -> Vec<Route> {
    routes![create_tenant, get_tenant, get_tenant_users, get_tenant_admins, add_user_to_tenant, make_user_tenant_admin, delete_user_from_tenant, demote_tenant_admin, get_tenant_groups]
}

#[get("/<tenant_ref>")]
pub fn get_tenant(
    tenant_ref: TenantRef,
    mut request: UserRequest<crate::ConfigType>,
) -> Result<Json<Tenant>, UserAuthErrResponse> {
    //==PERMISSION CHECK==
    if !request.user().is_superuser && !request.user_login_info().is_in_tenant(&tenant_ref){
        return err_response!(TenantEndpointError::ReadingDenied);
    }
    let tenant_id = decode_tenant_ref(request.db(), tenant_ref)?;
    Ok(Json(
        internal::get_tenant(tenant_id, request.db())
    ))
}

#[get("/<tenant_ref>/users")]
pub fn get_tenant_users(
    tenant_ref: TenantRef,
    mut request: UserRequest<crate::ConfigType>,
) -> Result<Json<Vec<User>>, UserAuthErrResponse> {
    //==PERMISSION CHECK==
    if !request.user().is_superuser && !request.user_login_info().is_in_tenant(&tenant_ref){
        return err_response!(TenantEndpointError::ReadingDenied);
    }

    let tenant_id = decode_tenant_ref(request.db(), tenant_ref)?;
    internal::get_tenant_users(tenant_id, request.db()).map(|u| Json(u))
}

#[get("/<tenant_ref>/admins")]
pub fn get_tenant_admins(
    tenant_ref: TenantRef,
    mut request: UserRequest<crate::ConfigType>,
) -> Result<Json<Vec<User>>, UserAuthErrResponse> {
    //==PERMISSION CHECK==
    if !request.user().is_superuser && !request.user_login_info().is_admin_in_tenant(&tenant_ref){
        return err_response!(TenantEndpointError::ReadingDenied);
    }

    let tenant_id = decode_tenant_ref(request.db(), tenant_ref)?;
    internal::get_tenant_admins(tenant_id, request.db()).map(|u| Json(u))
}

#[get("/<tenant_ref>/groups")]
pub fn get_tenant_groups(
    tenant_ref: TenantRef,
    mut request: UserRequest<crate::ConfigType>,
) -> Result<Json<Vec<Group>>, UserAuthErrResponse> {
    //==PERMISSION CHECK==
    if !request.user().is_superuser && !request.user_login_info().is_admin_in_tenant(&tenant_ref){
        return err_response!(TenantEndpointError::ReadingDenied);
    }

    let tenant_id = decode_tenant_ref(request.db(), tenant_ref.clone())?;
    internal::get_tenant_non_special_groups(tenant_id, &tenant_ref,request.db())
        .map(|u| Json(u))
}

#[post("/", data = "<tenant>")]
pub fn create_tenant(
    tenant: JsonBody<CreateTenant>,
    mut request: UserRequest<crate::ConfigType>,
) -> Result<Created<()>, UserAuthErrResponse> {
    if !request.user().is_superuser {
        return err_response!(TenantEndpointError::Creation(CreationError::Denied));
    }
    internal::create_tenant(tenant.0, &mut request)
        .map(|id| Created(format!("/tenants/{}", id.0), None))
}

#[post("/<tenant_ref>/users/<user_ref>")]
pub fn add_user_to_tenant(tenant_ref: TenantRef, user_ref: UserRef, mut request: UserRequest<crate::ConfigType>)
    -> Result<Status, UserAuthErrResponse>{
    //==PERMISSION CHECK==
    if !request.user().is_superuser {
        return err_response!(TenantEndpointError::ModificationDenied);
    }


    let tenant_id = decode_tenant_ref(request.db(), tenant_ref)?;
    let user_id = decode_user_ref(request.db(), user_ref)?;

    let supergroup = internal::get_tenant_supergroup(tenant_id, request.db())?;;
    groups::internal::add_user_to_group(supergroup, user_id, request.db())?;

    Ok(Status::NoContent)
}

#[delete("/<tenant_ref>/users/<user_ref>")]
pub fn delete_user_from_tenant(tenant_ref: TenantRef, user_ref: UserRef, mut request: UserRequest<crate::ConfigType>)
    -> Result<Status, UserAuthErrResponse>
{
    //==PERMISSION CHECK==
    if !request.user().is_superuser {
        return err_response!(TenantEndpointError::ModificationDenied);
    }

    let tenant_id = decode_tenant_ref(request.db(), tenant_ref)?;
    let user_id = decode_user_ref(request.db(), user_ref)?;

    let supergroup = internal::get_tenant_supergroup(tenant_id, request.db())?;;
    groups::internal::remove_user_from_group(supergroup, user_id, request.db())?;

    // TODO: log out user

    Ok(Status::NoContent)
}

#[post("/<tenant_ref>/admins/<user_ref>")]
pub fn make_user_tenant_admin(tenant_ref: TenantRef, user_ref: UserRef, mut request: UserRequest<crate::ConfigType>)
    -> Result<Status, UserAuthErrResponse>
{
    //==PERMISSION CHECK==
    if !request.user().is_superuser && !request.user_login_info().is_admin_in_tenant(&tenant_ref){
        return err_response!(TenantEndpointError::ModificationDenied);
    }

    let tenant_id = decode_tenant_ref(request.db(), tenant_ref)?;
    let user_id= decode_user_ref(request.db(), user_ref)?;


    let supergroup = internal::get_tenant_admingroup(tenant_id, request.db())?;;
    groups::internal::add_user_to_group(supergroup, user_id, request.db())?;

    update_user_info(&request.create_http_client(), request.user_login_info().clone(), request.db())?;

    Ok(Status::NoContent)
}

#[delete("/<tenant_ref>/admins/<user_ref>")]
pub fn demote_tenant_admin(tenant_ref: TenantRef, user_ref: UserRef, mut request: UserRequest<crate::ConfigType>)
    -> Result<Status, UserAuthErrResponse>
{
    //==PERMISSION CHECK==
    if !request.user().is_superuser && !request.user_login_info().is_admin_in_tenant(&tenant_ref){
        return err_response!(TenantEndpointError::ModificationDenied);
    }

    let tenant_id = decode_tenant_ref(request.db(), tenant_ref)?;
    let user_id = decode_user_ref(request.db(), user_ref)?;

    let supergroup = internal::get_tenant_admingroup(tenant_id, request.db())?;;
    groups::internal::remove_user_from_group(supergroup, user_id, request.db())?;

    update_user_info(&request.create_http_client(), request.user_login_info().clone(), request.db())?;

    Ok(Status::NoContent)
}