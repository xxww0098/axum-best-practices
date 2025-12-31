// src/dtos/user.rs
use crate::dtos::PHONE_REGEX;
use crate::core::enums::UserRole;
use serde::{Deserialize, Serialize}; // ✅ 引入 Deserialize
use validator::Validate;
use crate::entity::users;

// ✅ 增加 Deserialize 和 Clone (Clone 用于缓存操作时的所有权转移)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserProfile {
    pub id: String,
    pub username: String,
    pub phone: Option<String>,
    pub role: UserRole,
    pub is_active: bool,
    pub created_at: String,
}

impl From<users::Model> for UserProfile {
    fn from(user: users::Model) -> Self {
        Self {
            id: user.id.to_string(),
            username: user.username,
            phone: user.phone,
            role: user.role,
            is_active: user.is_active,
            created_at: user.created_at.to_string(),
        }
    }
}

#[derive(Deserialize, Validate)]
pub struct UpdateUserRequest {
    #[validate(regex(path = *PHONE_REGEX, message = "Invalid phone number format"))]
    pub phone: Option<String>,
}