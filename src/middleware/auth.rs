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

/// 基础鉴权中间件（黑名单检查）。这个中间件检查请求中的 JWT 令牌是否在 Redis 黑名单中。
/// 主要用于处理用户登出后的令牌失效，防止已注销的令牌继续访问受保护资源。
/// 如果没有提供令牌，中间件会直接放行请求，让后续的处理器或提取器处理认证逻辑。
///
/// # 工作原理
/// 1. 从 HTTP Authorization 头部提取 Bearer 令牌。
/// 2. 如果未提供令牌，直接放行（允许公开访问的端点）。
/// 3. 检查令牌是否在 Redis 黑名单中（key格式：blacklist:token:{token}）。
/// 4. 如果在黑名单中，返回 401 未授权错误；否则放行请求。
///
/// # 使用场景
/// - 保护需要登录访问的 API 端点。
/// - 实现即时登出功能（将令牌加入黑名单）。
/// - 与 Claims 提取器配合使用，提供完整的认证方案。
pub async fn auth_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    // 从 HTTP Authorization 头部尝试提取 Bearer 令牌。使用链式调用处理可能的错误：
    // 1. 检查 Authorization 头部是否存在。
    // 2. 将头部值转换为字符串。
    // 3. 去除 "Bearer " 前缀，获取纯令牌字符串。
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    let Some(token_str) = token else {
        // 如果没有提供令牌，直接放行请求。这种设计允许公共端点不需要认证，
        // 而受保护端点可以通过 Claims 提取器或其他中间件进行强制认证。
        return Ok(next.run(req).await);
    };

    let redis_key = format!("blacklist:token:{}", token_str);
    let mut redis_conn = state.redis.clone();

    // 查询 Redis 检查令牌是否在黑名单中。使用 EXISTS 命令快速检查键是否存在。
    // 如果 Redis 查询失败，返回 Redis 错误；如果令牌在黑名单中，返回认证错误。
    let is_blacklisted: bool = redis_conn
        .exists(&redis_key)
        .await
        .map_err(|e| AppError::RedisError(e))?;

    if is_blacklisted {
        tracing::warn!("🚫 Blocked blacklisted token");
        return Err(AppError::AuthError("Token has been revoked".to_string()));
    }

    Ok(next.run(req).await)
}

/// 管理员权限守卫中间件。这个中间件强制验证 JWT 令牌，并检查用户角色是否为管理员（Admin）。
/// 用于保护仅限管理员访问的 API 端点，确保只有具有管理员权限的用户才能访问。
///
/// # 工作原理
/// 1. 从 HTTP Authorization 头部提取 Bearer 令牌（必须提供）。
/// 2. 使用 JWT 密钥验证令牌签名和有效性。
/// 3. 从令牌声明中提取用户角色信息。
/// 4. 检查角色是否为 Admin，如果不是则返回 403 禁止访问错误。
///
/// # 使用方式
/// 在路由层使用 `.layer(middleware::from_fn_with_state(state.clone(), admin_guard))` 包装需要管理员权限的路由。
///
/// # 注意
/// - 与 `auth_middleware` 不同，此中间件要求必须提供有效的令牌。
/// - 令牌必须在有效期内且签名正确。
/// - 用户角色必须明确设置为 Admin（不是 User 或其他角色）。
pub async fn admin_guard(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(AppError::AuthError("Missing token".to_string()))?;

    // 从应用程序状态中获取 JWT 密钥。使用 secrecy 库安全地暴露密钥字节，
    // 然后创建 JWT 解码密钥用于验证令牌签名。
    let secret = state.config.jwt_secret.expose_secret().as_bytes();
    let decoding_key = DecodingKey::from_secret(secret);

    let token_data = decode::<Claims>(token, &decoding_key, &Validation::default())
        .map_err(|_| AppError::AuthError("Invalid token".to_string()))?;

    // 校验用户角色。从令牌声明中提取角色字符串，转换为 UserRole 枚举。
    // 如果转换失败（如角色值无效），默认设置为普通用户（User），然后检查是否为管理员（Admin）。
    let role_enum = UserRole::from_str(&token_data.claims.role).unwrap_or(UserRole::User);

    if role_enum != UserRole::Admin {
        tracing::warn!("🚫 Admin access denied: {}", token_data.claims.username);
        return Err(AppError::Forbidden("Requires Administrator privileges".to_string()));
    }

    Ok(next.run(req).await)
}