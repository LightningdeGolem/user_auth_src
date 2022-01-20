use base::requests::response::text_response::JsonBody;
use base::{err_response, requests::UserRequest, Status};
use rocket::{response::status::Created, Route};
use rocket_contrib::json::Json;
use serde_json::Value;
use user_auth_structs::{TenantRef, UserRef, UserSelf};

use super::internal::decode_user_ref;
use super::structures::*;
use super::*;
use crate::UserAuthErrResponse;
use crate::groups;
use crate::tenants;
use crate::utils::cache_updater::update_user_info;

mod login;

pub fn get_endpoints() -> Vec<Route> {
    routes![
        get_user,
        get_self,
        create_user,
        patch_user,
        patch_self,
        delete_user,
        login::login,
        password::reset_request,
        password::reset_action,
        password::change_password
    ]
}

#[get("/<user_ref>")]
pub fn get_user(
    user_ref: UserRef,
    mut request: UserRequest<crate::ConfigType>,
) -> Result<Json<User>, UserAuthErrResponse> {
    //==PERMISSION CHECK==
    let user_id= internal::decode_user_ref(request.db(), user_ref)?;
    let login_info = request.user_login_info().clone();
    internal::has_read_perm(request.db(), &login_info, user_id)?;

    
    internal::get_user(user_id, request.db()).map(|u| Json(u))
}

#[get("/self")]
pub fn get_self(request: UserRequest<crate::ConfigType>)
-> Result<Json<UserSelf>, UserAuthErrResponse> {

    let user = request.user_login_info().clone();

    Ok(Json(UserSelf {
        user_ref:    user.user.user_ref,
        username:    user.user.username,
        firstname:   user.user.firstname,
        lastname:    user.user.lastname,
        email:       user.user.email,
        timezone:    user.user.timezone,
        tenant_ref:  user.tenant_info.tenant_ref,
        tenant_name: user.tenant_info.tenant_name,
    }))
}

#[post("/?<tenant>", data = "<user>")]
pub fn create_user(
    user: JsonBody<Value>,
    tenant: Option<TenantRef>,
    mut request: UserRequest<crate::ConfigType>,
) -> Result<Created<Json<User>>, UserAuthErrResponse> {
    //==PERMISSION CHECK==
    if !request.user().is_superuser{
        let info = request.user_login_info();
        if let Some(requested_tenant) = &tenant{
            if !(info.tenant_info.is_tenant_admin && info.tenant_info.tenant_ref == *requested_tenant){
                return err_response!(UserEndpointError::CreationDenied);
            }
        }
        else{
            return err_response!(UserEndpointError::CreationDenied);
        }
    }


    let user = user_from_json(user.0)
        .map_err(|e| UserAuthErrResponse::new(UserEndpointError::InvalidField(e)))?;
    
    match tenant{
        Some(tenant_ref) => {
            if !request.user().is_superuser {
                return err_response!(UserEndpointError::CreationDenied);
            }
            request.db().start_transaction();

            let tenant_id = tenants::internal::decode_tenant_ref(request.db(), tenant_ref)?;
            let supergroup_id = tenants::internal::get_tenant_supergroup(tenant_id, request.db())?;

            let (user, user_id) = internal::create_user(user, &mut request)?;

            groups::internal::add_user_to_group(supergroup_id, user_id, request.db())?;

            request.db().commit();
            Ok(Created(format!("/users/{}", user.user_ref), Some(Json(user))))
        },
        None => {
            if !request.user().is_superuser {
                return err_response!(UserEndpointError::CreationDenied);
            }
        
            internal::create_user(user, &mut request)
                .map(|(u,_)| Created(format!("/users/{}", u.user_ref), Some(Json(u))))
        },
    }
    
}
#[delete("/<user_ref>")]
pub fn delete_user(
    user_ref: UserRef,
    mut request: UserRequest<crate::ConfigType>
) -> Result<Status, UserAuthErrResponse>{
    //==PERMISSION CHECK==
    if !request.user().is_superuser{
        return err_response!(UserEndpointError::DeletionDenied);
    }


    let user_id = decode_user_ref(request.db(), user_ref)?;
    internal::delete_user(request.db(), user_id);

    // TODO: need to remove user tokens

    Ok(Status::NoContent)
}

#[patch("/<user_ref>", data = "<changes>")]
pub fn patch_user(
    user_ref: UserRef,
    changes: JsonBody<Value>,
    mut request: UserRequest<crate::ConfigType>,
) -> Result<Status, UserAuthErrResponse> {
    //==PERMISSION CHECK==
    let user_id= internal::decode_user_ref(request.db(), user_ref)?;
    let login_info = request.user_login_info().clone();
    internal::has_write_perm(request.db(),&login_info, user_id)?;

    let e = internal::patch_user(user_id, changes.0, request.db()).map(|_| Status::NoContent);
    update_user_info(&request.create_http_client(), request.user_login_info().clone(), request.db())?;
    e
}

#[patch("/self", data = "<changes>")]
pub fn patch_self(
    changes: JsonBody<Value>,
    request: UserRequest<crate::ConfigType>,
) -> Result<Status, UserAuthErrResponse> {
    patch_user(request.user_ref(), changes, request)
}
