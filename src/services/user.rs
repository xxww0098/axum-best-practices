// src/services/user.rs
use crate::{
    core::{constants::CACHE_EXPIRE_USER_PROFILE, error::AppError},
    dtos::user::{UpdateUserRequest, UserProfile},
    entity::users,
    state::AppState,
    utils::cache, // 引入缓存模块，用于后续的缓存操作（如获取或设置用户资料缓存）
};
use sea_orm::*;
use uuid::Uuid;

/// 获取用户资料 (Cache-Aside)
/// 优先读缓存，未命中读 DB 并回填
pub async fn get_user_profile(state: &AppState, user_id: &str) -> Result<UserProfile, AppError> {
    let key = cache::user_profile_key(user_id);
    let db = state.db.clone();
    let uid_str = user_id.to_string();

    cache::get_or_fetch(
        &state.redis,
        &key,
        CACHE_EXPIRE_USER_PROFILE,
        || async move {
            let uid = Uuid::parse_str(&uid_str)
                .map_err(|_| AppError::AuthError("Invalid User ID format".to_string()))?;

            let user = users::Entity::find_by_id(uid)
                .one(&db)
                .await?
                .ok_or(AppError::NotFound("User not found".to_string()))?;

            Ok(user.into())
        },
    )
    .await
}

/// 更新用户资料 (Write-Through)
/// 更新 DB 后同步更新缓存
pub async fn update_user_profile(
    state: &AppState,
    user_id: &str,
    req: UpdateUserRequest,
) -> Result<UserProfile, AppError> {
    let uid = Uuid::parse_str(user_id)
        .map_err(|_| AppError::AuthError("Invalid User ID format".to_string()))?;

    let user = users::Entity::find_by_id(uid)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound("User not found".to_string()))?;

    let mut user_active: users::ActiveModel = user.into();

    if let Some(phone) = req.phone {
        user_active.phone = Set(Some(phone));
    }

    // 1. 更新 DB
    let updated_user = user_active.update(&state.db).await?;
    let profile: UserProfile = updated_user.into();

    // 2. 更新缓存
    let key = cache::user_profile_key(user_id);
    cache::set(&state.redis, &key, &profile, CACHE_EXPIRE_USER_PROFILE).await;

    Ok(profile)
}
