// src/services/user.rs
use sea_orm::*;
use uuid::Uuid;
use crate::{
    core::{
        error::AppError, 
        constants::{REDIS_PREFIX_USER_PROFILE, CACHE_EXPIRE_USER_PROFILE}
    },
    dtos::user::{UserProfile, UpdateUserRequest},
    entity::users,
    state::AppState,
    utils::cache, // 引入缓存模块，用于后续的缓存操作（如获取或设置用户资料缓存）
};

/// 获取用户资料信息。这个函数实现了缓存优先的逻辑：首先尝试从Redis缓存中读取用户资料，
/// 如果缓存命中则直接返回缓存数据；如果缓存未命中，则从数据库中查询用户信息，
/// 并将查询结果存入Redis缓存，以便后续快速访问。
///
/// # 参数
/// - `state`: 应用程序状态，包含数据库连接和Redis客户端等资源。
/// - `user_id`: 用户ID字符串，通常来自JWT token中的sub字段。
///
/// # 返回值
/// - `Ok(UserProfile)`: 成功时返回用户资料数据。
/// - `Err(AppError)`: 失败时返回相应的错误类型，如用户不存在、数据库查询失败等。
pub async fn get_user_profile(state: &AppState, user_id: &str) -> Result<UserProfile, AppError> {
    // 根据Redis键前缀和用户ID拼接出完整的Redis缓存键。这是缓存策略的一部分，确保每个用户有独立的缓存键。
    // user_id 参数是从Handler传递过来的，来源于JWT claims中的sub字段（即用户标识）
    let key = format!("{}{}", REDIS_PREFIX_USER_PROFILE, user_id);
    
    // 为了在闭包中使用，需要克隆一下变量。因为闭包可能在不同的线程中执行，需要获取变量的所有权。
    let db = state.db.clone();
    let uid_str = user_id.to_string();

    // 调用通用缓存逻辑：首先尝试从Redis缓存中获取数据，如果缓存未命中，则执行闭包中的数据库查询逻辑。
    cache::get_or_fetch(
        &state.redis, 
        &key, 
        CACHE_EXPIRE_USER_PROFILE, 
        || async move {
            // 只有缓存未命中时才会执行这里的代码。这部分代码负责从数据库中查询用户信息。
            let uid = Uuid::parse_str(&uid_str)
                .map_err(|_| AppError::AuthError("Invalid User ID format".to_string()))?;
            
            let user = users::Entity::find_by_id(uid)
                .one(&db)
                .await?
                .ok_or(AppError::NotFound("User not found".to_string()))?;

            Ok(user.into())
        }
    ).await
}

/// 更新用户资料信息。这个函数首先从数据库中查找指定用户，然后更新提供的字段，
/// 最后同步更新Redis缓存，确保缓存数据与数据库保持一致（Write Through策略）。
///
/// # 参数
/// - `state`: 应用程序状态，包含数据库连接和Redis客户端等资源。
/// - `user_id`: 用户ID字符串，需要更新的用户标识。
/// - `req`: 更新请求数据，包含需要修改的字段（如手机号等）。
///
/// # 返回值
/// - `Ok(UserProfile)`: 成功时返回更新后的用户资料数据。
/// - `Err(AppError)`: 失败时返回相应的错误类型，如用户不存在、数据库更新失败等。
pub async fn update_user_profile(
    state: &AppState,
    user_id: &str,
    req: UpdateUserRequest
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
    
    // 第一步：先更新数据库中的用户信息。这里使用SeaORM的ActiveModel进行更新。
    let updated_user = user_active.update(&state.db).await?;
    let profile: UserProfile = updated_user.into();

    // 第二步：同步更新Redis缓存（Write Through策略）。确保缓存与数据库的数据一致性，避免脏读。
    let key = format!("{}{}", REDIS_PREFIX_USER_PROFILE, user_id);
    cache::set(&state.redis, &key, &profile, CACHE_EXPIRE_USER_PROFILE).await;

    Ok(profile)
}