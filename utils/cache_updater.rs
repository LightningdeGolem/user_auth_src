use base::DbConn;
use sdk_base::Client;
use token_auth_structs::{LoggedInUser, TenantLoginInfo};

use crate::{UserAuthErrResponse, groups, tenants, users};


pub fn update_user_info(client: &Client, current_info: LoggedInUser, db: &mut DbConn) -> Result<(), UserAuthErrResponse>{
    let tenant_ref = current_info.tenant_info.tenant_ref;
    let tenant_id = tenants::internal::decode_tenant_ref(db, tenant_ref.clone())?;

    let user_ref = current_info.user.user_ref;
    let user_id = users::internal::decode_user_ref(db, user_ref.clone())?;


    let user = users::internal::get_user(user_id, db)?;
    let user_groups = groups::internal::get_user_group_refs(user_id, tenant_id, db);
    let tenant_admingroup = tenants::internal::get_tenant_admingroup_ref(tenant_id, db)?;

    let is_tenant_admin = user_groups.contains(&tenant_admingroup);

    // JAHS added - temporary solution to get the tenant name and store in TenantLoginInfo
    let tenant_name = tenants::internal::get_tenant(tenant_id, db).name;

    let user_info = LoggedInUser {
        user,
        tenant_info: TenantLoginInfo {
            tenant_ref,
            tenant_name,
            is_tenant_admin,
            groups: user_groups,
        }
    };

    token_server_sdk::update_user(client, user_ref, user_info)??;

    Ok(())
}