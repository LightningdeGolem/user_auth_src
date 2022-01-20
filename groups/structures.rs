use std::str::FromStr;

use base::db::to_sql::AsSql;
use serde::{Deserialize, Serialize};
use user_auth_structs::{Group, GroupRef, TenantRef};

#[derive(Serialize, Deserialize, Clone)]
pub struct CreateGroup {
    pub name: String,
    pub tenant: TenantRef,
}

impl From<Group> for CreateGroup{
    fn from(g: Group) -> Self {
        Self{
            name: g.name,
            tenant: g.tenant
        }
    }
}

pub fn validate_create_group(group: &CreateGroup) -> Result<(), &'static str>{
    if group.name.len() == 0{
        return Err("Group name cannot be empty");
    }
    else if group.name.len() > 45{
        return Err("Group name cannot be longer than 45 characters");
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
pub struct RawGroup {
    pub group_ref: GroupRef,
    pub group_type: GroupType,
    pub name: Option<String>,
    pub tenant: TenantRef,
}

impl Into<Group> for RawGroup{
    fn into(self) -> Group {
        Group{
            group_ref: self.group_ref,
            name: self.name.unwrap(),
            tenant: self.tenant
        }
    }
}

#[derive(Serialize, Deserialize)]
pub enum GroupType {
    Normal,
    SuperGroup,
    AdminGroup,
}

impl FromStr for GroupType {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "n" => Ok(Self::Normal),
            "s" => Ok(Self::SuperGroup),
            "a" => Ok(Self::AdminGroup),
            _ => Err("Invalid group type in database"),
        }
    }
}

impl AsSql for GroupType {
    fn as_sql(&self) -> String {
        AsSql::as_sql(match self {
            Self::Normal => &"n",
            Self::SuperGroup => &"s",
            Self::AdminGroup => &"a",
        })
    }

    fn get_eq_operator(&self) -> &'static str {
        "="
    }
}
