use base::{Status, err_response, requests::{response::text_response::JsonBody, UserRequest}};
use rocket::{response::status::Created, Route};
use rocket_contrib::json::Json;
use serde_json::Value;
use user_auth_structs::{Group, GroupRef, User, UserRef};

use crate::{UserAuthErrResponse, tenants, users, utils::cache_updater::update_user_info};

use super::{errors::GroupEndpointError, internal::{self, decode_group_ref, get_group_tenant}};
use super::structures::*;

pub fn get_endpoints() -> Vec<Route> {
    routes![get_group, get_users_in_group, create_group, add_user_to_group, patch_group, remove_user_from_group, delete_group]
}

#[get("/<group_ref>")]
pub fn get_group(
    group_ref: GroupRef,
    mut request: UserRequest<crate::ConfigType>,
) -> Result<Json<Group>, UserAuthErrResponse> {
    //==CHECK PERMISSIONS==
    let group_id = decode_group_ref(request.db(), group_ref.clone())?;
    let group_tenant = get_group_tenant(request.db(), group_id);
    if 
        !request.user().is_superuser &&
        !request.user_login_info().is_admin_in_tenant(&group_tenant) &&
        !request.user_login_info().is_in_group(&group_ref)
    {
        return err_response!(GroupEndpointError::ReadingDenied);
    }


    internal::get_non_special_group(group_id, request.db()).map(|g| Json(g))
}

#[get("/<group_ref>/users")]
pub fn get_users_in_group(
    group_ref: GroupRef,
    mut request: UserRequest<crate::ConfigType>,
) -> Result<Json<Vec<User>>, UserAuthErrResponse> {
    //==CHECK PERMISSIONS==
    let group_id = decode_group_ref(request.db(), group_ref.clone())?;
    let group_tenant = get_group_tenant(request.db(), group_id);
    if 
        !request.user().is_superuser &&
        !request.user_login_info().is_admin_in_tenant(&group_tenant) &&
        !request.user_login_info().is_in_group(&group_ref)
    {
        return err_response!(GroupEndpointError::ReadingDenied);
    }


    internal::get_non_special_group(group_id, request.db())?;
    internal::get_users_in_group(group_id, request.db()).map(|u| Json(u))
}

#[post("/", data = "<group>")]
pub fn create_group(
    group: JsonBody<CreateGroup>,
    mut request: UserRequest<crate::ConfigType>,
) -> Result<Created<()>, UserAuthErrResponse> {
    let group = group.0;

    //==CHECK PERMISSIONS==
    if 
        !request.user().is_superuser &&
        !request.user_login_info().is_admin_in_tenant(&group.tenant)
    {
        return err_response!(GroupEndpointError::CreationDenied);
    }


    tenants::internal::decode_tenant_ref(request.db(), group.tenant.clone())?;

    let info = internal::create_group(group, request.db())?;

    Ok(Created(format!("/groups/{}", info.0), None))
}

#[post("/<group_ref>/users/<user_ref>")]
pub fn add_user_to_group(
    group_ref: GroupRef,
    user_ref: UserRef,
    mut request: UserRequest<crate::ConfigType>,
) -> Result<Status, UserAuthErrResponse> {
    //==CHECK PERMISSIONS==
    let user_id = users::internal::decode_user_ref(request.db(), user_ref)?;
    let group_id = decode_group_ref(request.db(), group_ref)?;
    let group_tenant = get_group_tenant(request.db(), group_id);
    if 
        !request.user().is_superuser &&
        !request.user_login_info().is_admin_in_tenant(&group_tenant)
    {
        return err_response!(GroupEndpointError::ModificationDenied);
    }
    else{
        let user_tenants = tenants::internal::get_user_tenant_refs(user_id, request.db());
        if !request.user_login_info().is_in_these_tenants(&user_tenants){
            return err_response!(GroupEndpointError::ModificationDenied);
        }
    }
    

    
    internal::add_user_to_group(group_id, user_id, request.db())?;
    update_user_info(&request.create_http_client(), request.user_login_info().clone(), request.db())?;
    Ok(Status::NoContent)
}

#[delete("/<group_ref>/users/<user_ref>")]
pub fn remove_user_from_group(
    group_ref: GroupRef,
    user_ref: UserRef,
    mut request: UserRequest<crate::ConfigType>,
) -> Result<Status, UserAuthErrResponse> {
    //==CHECK PERMISSIONS==
    let user_id = users::internal::decode_user_ref(request.db(), user_ref)?;
    let group_id = decode_group_ref(request.db(), group_ref)?;
    let group_tenant = get_group_tenant(request.db(), group_id);
    if 
        !request.user().is_superuser &&
        !request.user_login_info().is_admin_in_tenant(&group_tenant)
    {
        return err_response!(GroupEndpointError::ModificationDenied);
    }

    
    internal::remove_user_from_group(group_id, user_id, request.db())?;
    update_user_info(&request.create_http_client(), request.user_login_info().clone(), request.db())?;
    Ok(Status::NoContent)
}

#[patch("/<group_ref>", data="<changes>")]
pub fn patch_group(
    group_ref: GroupRef,
    changes: JsonBody<Value>,
    mut request: UserRequest<crate::ConfigType>,
) -> Result<Status, UserAuthErrResponse> {
    //==CHECK PERMISSIONS==
    let group_id = decode_group_ref(request.db(), group_ref)?;
    let group_tenant = get_group_tenant(request.db(), group_id);
    if 
        !request.user().is_superuser &&
        !request.user_login_info().is_admin_in_tenant(&group_tenant)
    {
        return err_response!(GroupEndpointError::ModificationDenied);
    }

    
    internal::patch_group(group_id, changes.0, request.db())?;
    Ok(Status::NoContent)
}

#[delete("/<group_ref>")]
pub fn delete_group(
    group_ref: GroupRef,
    mut request: UserRequest<crate::ConfigType>,
) -> Result<Status, UserAuthErrResponse> {
    //==CHECK PERMISSIONS==
    let group_id = decode_group_ref(request.db(), group_ref)?;
    let group_tenant = get_group_tenant(request.db(), group_id);
    if 
        !request.user().is_superuser &&
        !request.user_login_info().is_admin_in_tenant(&group_tenant)
    {
        return err_response!(GroupEndpointError::DeletionDenied);
    }
    
    internal::delete_group(group_id, request.db())?;
    update_user_info(&request.create_http_client(), request.user_login_info().clone(), request.db())?;

    Ok(Status::NoContent)
}
