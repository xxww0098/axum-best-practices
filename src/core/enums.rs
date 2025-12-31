// src/core/enums.rs

use sea_orm::entity::prelude::*;
use sea_orm::{DeriveActiveEnum, EnumIter};
use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

/// 用户角色枚举
/// 同时支持：
/// 1. 数据库映射 (SeaORM) - 存为字符串 "admin" / "user"
/// 2. JSON 序列化 (Serde) - 前端交互
/// 3. 字符串转换 (Strum) - 代码逻辑判断
#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize, Display, EnumString)]
#[strum(serialize_all = "lowercase")] // to_string() 输出小写
#[serde(rename_all = "lowercase")]    // JSON 输出小写
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")] // 映射到数据库 varchar/text
pub enum UserRole {
    #[sea_orm(string_value = "admin")]
    Admin,

    #[sea_orm(string_value = "user")]
    User,
}