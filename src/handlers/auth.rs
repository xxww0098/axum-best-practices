// src/handlers/auth.rs
use axum::{
    extract::{Json, State},
    response::IntoResponse,
};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use validator::Validate;

use crate::{
    core::error::AppError,
    dtos::{
        auth::{LoginRequest, RefreshRequest, RegisterRequest},
        response::ApiResponse,
    },
    services::auth as AuthService,
    state::AppState,
    utils::limiter::check_rate_limit,
};

/// 用户注册
pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;

    // 限流: 5次/分
    check_rate_limit(&state.redis, "register", &payload.username, 5, 60).await?;

    AuthService::register(&state, payload).await?;

    Ok(ApiResponse::<()>::with_code(
        axum::http::StatusCode::CREATED,
        "User registered successfully",
        None,
    ))
}

/// 用户登录
pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;

    // 限流: 5次/分
    check_rate_limit(&state.redis, "login", &payload.account, 5, 60).await?;

    let response = AuthService::login(&state, payload).await?;

    Ok(ApiResponse::with_data(response))
}

/// 刷新令牌
pub async fn refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshRequest>,
) -> Result<impl IntoResponse, AppError> {
    let response = AuthService::refresh(&state, payload.refresh_token).await?;
    Ok(ApiResponse::with_data(response))
}

/// 用户登出
pub async fn logout(
    State(state): State<AppState>,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse, AppError> {
    let token = bearer.token();
    AuthService::logout(&state, token).await?;

    Ok(ApiResponse::<()>::with_message("Logged out successfully"))
}
