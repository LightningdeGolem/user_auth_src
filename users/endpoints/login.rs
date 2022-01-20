use std::str::FromStr;
use rocket_contrib::json::JsonValue;
use serde::Deserialize;
use serde_json::json;
use token_auth_structs::{LoggedInUser, TenantLoginInfo};
use user_auth_structs::TenantRef;
use sdk_base::Client;
use users::internal;
use base::{
    log, log_important,
    requests::{response::text_response::JsonBody, OpenRequest}
};
use crate::{
    UserAuthErrResponse, groups,
    tenants::{self, TenantEndpointError}, 
    users::{self, endpoints::password}
};

#[derive(Deserialize)]
pub struct LoginData {
    password: String,
}

#[post("/login/<long_username>?<tenant>", data = "<login_data>")]
pub fn login(
    long_username: String,
    login_data:    JsonBody<LoginData>,
    tenant:        Option<TenantRef>,
    mut request:   OpenRequest<crate::ConfigType>
) -> Result<JsonValue, UserAuthErrResponse> {
    let logger = request.logger();
    let mut db = request.db_owned();

    log_important!("{f:green}Login request received for username [{}]...", long_username);

    let login_data    = login_data.0;
    let config        = request.specific_config();
    let global_config = request.global_config();

    // deblock the long username (in format "<username>:<tenant_ref>")
    // if no tenant_ref is supplied in user name, then allow use of optional query parameter
    let (username, mut tenant_ref) = if long_username.contains(":") {
        let splits: Vec<&str> = long_username.split(":").collect();
        let tenant_ref = TenantRef::from_str(splits[1]).map_err(|_|
            UserAuthErrResponse::new(
                TenantEndpointError::MalformedTenantRef(String::from(splits[1]))
            )
        )?;
        (String::from(splits[0]), Some(tenant_ref))
    }
    else {
        (long_username, tenant)
    };

    // check password and get user id
    let user_id = password::check_password(
        &username, &login_data.password, &config, &logger, &mut db
    )?;

    // get full user from database (no security information included)
    let user = internal::get_user(user_id, &mut db)?;

    // store user reference in the request store for logging purposes
    request.get_request_storage().update_user_ref(&user.user_ref);

    // if this is not a super user then validate a passed tenant_ref against the tenants that
    // this user has access to, and if the is no passed tenant_ref, default it if we can.
    if !user.is_superuser {
        let user_tenants = tenants::internal::get_user_tenant_refs(user_id, &mut db);
        if let Some(t_ref) = &tenant_ref {
            if !user_tenants.contains(&t_ref) {
                return Err(UserAuthErrResponse::new(
                    TenantEndpointError::TenantNotAuthorized(t_ref.clone())
                ));
            }   
        }
        else {
            // if there is more than one tenant then require a tenant ref
            if user_tenants.len() > 1 {
                return Err(UserAuthErrResponse::new(
                    TenantEndpointError::TenantRequired
                ));
            }
            tenant_ref = user_tenants.iter().next().cloned();
        }
    }

    // now unwrap the tenant_ref, failing if we don't have one
    let tenant_ref = tenant_ref.ok_or(
        UserAuthErrResponse::new(TenantEndpointError::TenantRequired)
    )?;

    // map the tenant reference to a tenant id
    let tenant_id = tenants::internal::decode_tenant_ref(&mut db, tenant_ref.clone())?;

    // load up user groups and tenant admin group
    let mut user_groups = groups::internal::get_user_group_refs(user_id, tenant_id, &mut db);
    let tenant_admingroup = tenants::internal::get_tenant_admingroup_ref(tenant_id, &mut db)?;

    // if this is a super user then add both the super group and admin group to list of groups
    if user.is_superuser {
        if !user_groups.contains(&tenant_admingroup) {
            user_groups.push(tenant_admingroup.clone());
        }
        let tenant_supergroup = tenants::internal::get_tenant_supergroup_ref(tenant_id, &mut db)?;
        if !user_groups.contains(&tenant_supergroup) {
            user_groups.push(tenant_supergroup);
        }
    }

    // determine if this user is a tenant admin
    let is_tenant_admin = user_groups.contains(&tenant_admingroup);

    // JAHS added - temporary solution to get the tenant name and store in TenantLoginInfo
    let tenant_name = tenants::internal::get_tenant(tenant_id, &mut db).name;

    let user_info = LoggedInUser{
        user,
        tenant_info: TenantLoginInfo{
            tenant_ref,
            tenant_name,
            is_tenant_admin,
            groups: user_groups,
        }
    };

    let http_client = Client::new(
        String::new(), logger.request_id(), global_config.microservice_locations.clone()
    );
    log!("Contacting token server microservice to obtain token...");
    let token = token_server_sdk::create_token(&http_client, user_info)??;
    log!("...token received from token server.");

    log_important!("{f:green}Login successful, responding with token.");

    Ok(json!({
        "token": token
    }).into())
}
