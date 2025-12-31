// src/middleware/auth.rs
use axum::{
    extract::{Request, State},
    http::header,
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use redis::AsyncCommands;
use secrecy::ExposeSecret;
use std::str::FromStr;

use crate::{
    core::{error::AppError, enums::UserRole},
    dtos::auth::Claims,
    state::AppState,
};

/// 令牌撤销检查中间件。验证请求中的JWT令牌是否已被撤销（加入黑名单）。
///
/// 这个中间件主要用于在令牌仍有效但已被用户主动撤销（如登出）时拒绝请求。
/// 如果请求中没有携带令牌，则直接放行，由其他中间件或处理器处理认证逻辑。
///
/// # 功能说明
/// - 从请求头中提取Bearer令牌
/// - 检查Redis黑名单，判断令牌是否已被撤销
/// - 如果令牌已被撤销，返回401 Unauthorized错误
///
/// # 参数
/// - `state`: 应用程序状态，包含Redis客户端
/// - `req`: HTTP请求
/// - `next`: 下一个中间件或处理器的调用链
///
/// # 返回值
/// - `Ok(Response)`: 令牌有效或无令牌，继续处理请求
/// - `Err(AppError)`: 令牌已被撤销，返回认证错误
pub async fn check_token_revocation(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    // 从请求头中提取Authorization字段的值，并解析出Bearer令牌
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    // 如果请求中没有携带令牌，直接放行
    // 这允许其他中间件或处理器来处理认证逻辑
    let Some(token_str) = token else {
        return Ok(next.run(req).await);
    };

    // 构建Redis黑名单键，格式为 "blacklist:token:{token_string}"
    let redis_key = format!("blacklist:token:{}", token_str);
    let mut redis_conn = state.redis.clone();

    // 检查令牌是否在黑名单中
    let is_blacklisted: bool = redis_conn
        .exists(&redis_key)
        .await
        .map_err(|e| AppError::RedisError(e))?;

    if is_blacklisted {
        tracing::warn!("🚫 Blocked blacklisted token");
        return Err(AppError::AuthError("Token has been revoked".to_string()));
    }

    // 令牌未被撤销，继续处理请求
    Ok(next.run(req).await)
}

/// 管理员权限守卫中间件。验证请求中的用户是否具有管理员权限。
///
/// 这个中间件用于保护需要管理员权限的端点，确保只有具有Admin角色的用户才能访问。
/// 与 check_token_revocation 不同，这个中间件要求请求必须携带有效的令牌。
///
/// # 功能说明
/// - 从请求头中提取并验证Bearer令牌
/// - 解码JWT并获取用户角色信息
/// - 检查用户角色是否为Admin
/// - 如果不是管理员，返回403 Forbidden错误
///
/// # 参数
/// - `state`: 应用程序状态，包含JWT密钥
/// - `req`: HTTP请求
/// - `next`: 下一个中间件或处理器的调用链
///
/// # 返回值
/// - `Ok(Response)`: 用户是管理员，继续处理请求
/// - `Err(AppError)`: 无管理员权限，返回403 Forbidden错误
pub async fn admin_guard(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    // 提取Bearer令牌。如果没有令牌，直接返回认证错误
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(AppError::AuthError("Missing token".to_string()))?;

    // 使用JWT密钥创建解码密钥
    let secret = state.config.jwt_secret.expose_secret().as_bytes();
    let decoding_key = DecodingKey::from_secret(secret);

    // 解码并验证JWT令牌
    let token_data = decode::<Claims>(token, &decoding_key, &Validation::default())
        .map_err(|_| AppError::AuthError("Invalid token".to_string()))?;

    // 将字符串角色转换为UserRole枚举。如果转换失败，默认为User角色
    let role_enum = UserRole::from_str(&token_data.claims.role).unwrap_or(UserRole::User);

    // 检查用户是否具有管理员权限
    if role_enum != UserRole::Admin {
        tracing::warn!("🚫 Admin access denied: {}", token_data.claims.username);
        return Err(AppError::Forbidden("Requires Administrator privileges".to_string()));
    }

    // 用户是管理员，继续处理请求
    Ok(next.run(req).await)
}