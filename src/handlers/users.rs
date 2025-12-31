// src/handlers/users.rs
use axum::{extract::{State, Json}, response::IntoResponse};
use validator::Validate;

use crate::{
    core::error::AppError,
    dtos::{auth::Claims, user::UpdateUserRequest, response::ApiResponse},
    services::user as UserService,
    state::AppState,
    rate_limit,
};

/// 获取当前用户资料的处理器。返回登录用户的个人资料信息。
///
/// # 功能说明
/// - 从JWT Claims中提取用户ID
/// - 对用户ID进行请求频率限制（防止过度请求）
/// - 调用用户服务获取用户资料
///
/// # 参数
/// - `claims`: JWT令牌中解析出的用户信息，包含用户ID（sub字段）
/// - `state`: 应用程序状态
///
/// # 返回值
/// - `Ok(impl IntoResponse)`: 成功返回用户资料
/// - `Err(AppError)`: 获取失败，返回相应的错误信息
pub async fn get_me(
    claims: Claims,
    State(state): State<AppState>
) -> Result<impl IntoResponse, AppError> {

    // 请求频率限制：每个用户ID每60秒最多可以读取资料60次
    rate_limit!(&state.redis, "read_me", &claims.sub, 60, 60);

    // 调用用户服务获取用户资料（会先检查Redis缓存）
    let profile = UserService::get_user_profile(&state, &claims.sub).await?;
    // 返回用户资料数据
    Ok(ApiResponse::with_data(profile))
}

/// 更新当前用户资料的处理器。处理登录用户的个人资料更新请求。
///
/// # 功能说明
/// - 从JWT Claims中提取用户ID
/// - 验证请求数据格式
/// - 对用户ID进行请求频率限制（防止过度请求）
/// - 调用用户服务更新用户资料（同时更新数据库和缓存）
///
/// # 参数
/// - `claims`: JWT令牌中解析出的用户信息，包含用户ID（sub字段）
/// - `state`: 应用程序状态
/// - `payload`: 更新请求数据，包含需要修改的字段（如手机号等）
///
/// # 返回值
/// - `Ok(impl IntoResponse)`: 更新成功，返回更新后的用户资料
/// - `Err(AppError)`: 更新失败，返回相应的错误信息
pub async fn update_me(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<UpdateUserRequest>,
) -> Result<impl IntoResponse, AppError> {

    // 验证请求数据格式
    payload.validate()?;

    // 请求频率限制：每个用户ID每60秒最多可以更新资料10次
    rate_limit!(&state.redis, "update_me", &claims.sub, 10, 60);

    // 调用用户服务更新用户资料（同时更新数据库和Redis缓存）
    let profile = UserService::update_user_profile(&state, &claims.sub, payload).await?;
    // 返回更新后的用户资料数据
    Ok(ApiResponse::with_data(profile))
}