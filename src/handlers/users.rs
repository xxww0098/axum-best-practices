// src/handlers/users.rs
use axum::{
    extract::{Json, State},
    response::IntoResponse,
};
use validator::Validate;

use crate::{
    core::error::AppError,
    dtos::{auth::Claims, response::ApiResponse, user::UpdateUserRequest},
    services::user as UserService,
    state::AppState,
    utils::limiter::check_rate_limit,
};

/// 获取当前用户资料
pub async fn get_me(
    claims: Claims,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    // 限流: 60次/分
    check_rate_limit(&state.redis, "read_me", &claims.sub, 60, 60).await?;

    let profile = UserService::get_user_profile(&state, &claims.sub).await?;
    Ok(ApiResponse::with_data(profile))
}

/// 更新当前用户资料
pub async fn update_me(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<UpdateUserRequest>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;

    // 限流: 10次/分
    check_rate_limit(&state.redis, "update_me", &claims.sub, 10, 60).await?;

    let profile = UserService::update_user_profile(&state, &claims.sub, payload).await?;
    Ok(ApiResponse::with_data(profile))
}
