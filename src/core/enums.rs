// src/core/enums.rs

use sea_orm::entity::prelude::*;
use sea_orm::{DeriveActiveEnum, EnumIter};
use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

/// 用户角色枚举
/// 支持 SeaORM 映射、Serde 序列化、Strum 字符串转换
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    EnumIter,
    DeriveActiveEnum,
    Serialize,
    Deserialize,
    Display,
    EnumString,
)]
#[strum(serialize_all = "lowercase")]
#[serde(rename_all = "lowercase")]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum UserRole {
    #[sea_orm(string_value = "admin")]
    Admin,

    #[sea_orm(string_value = "user")]
    User,
}
