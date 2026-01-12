// src/middleware/auth.rs
use axum::{
    extract::{Request, State},
    http::header,
    middleware::Next,
    response::Response,
};
use redis::AsyncCommands;
use std::str::FromStr;

use crate::{
    core::{enums::UserRole, error::AppError},
    state::AppState,
    utils::jwt::{decode_jwt, extract_bearer_token},
};

/// 检查 Token 是否被撤销 (黑名单)
pub async fn check_token_revocation(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    // 1. 提取 Token，无 Token 则放行 (由后续处理)
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| extract_bearer_token(value));

    let Some(token_str) = token else {
        return Ok(next.run(req).await);
    };

    // 2. 检查 Redis 黑名单
    let redis_key = format!("blacklist:token:{}", token_str);
    let mut redis_conn = state.redis.clone();

    let is_blacklisted: bool = redis_conn
        .exists(&redis_key)
        .await
        .map_err(AppError::RedisError)?;

    if is_blacklisted {
        tracing::warn!("🚫 Blocked blacklisted token");
        return Err(AppError::AuthError("Token has been revoked".to_string()));
    }

    Ok(next.run(req).await)
}

/// 管理员权限检查
pub async fn admin_guard(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    // 1. 提取并验证 Token
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| extract_bearer_token(value))
        .ok_or(AppError::AuthError("Missing token".to_string()))?;

    let claims = decode_jwt(token, &state.config)?;

    // 2. 检查角色
    let role_enum = UserRole::from_str(&claims.role).unwrap_or(UserRole::User);

    if role_enum != UserRole::Admin {
        tracing::warn!("🚫 Admin access denied: {}", claims.username);
        return Err(AppError::Forbidden(
            "Requires Administrator privileges".to_string(),
        ));
    }

    Ok(next.run(req).await)
}
