// src/core/error.rs
use axum::{http::StatusCode, response::{IntoResponse, Response}};
use thiserror::Error;
use crate::dtos::response::ApiResponse;

/// 应用程序统一错误类型。这个枚举定义了所有可能发生的错误类型，
/// 覆盖了数据库、缓存、验证、认证、授权等各个层面的错误。
///
/// 通过实现 `IntoResponse` trait，任何 `AppError` 都可以直接转换为HTTP响应，
/// 确保错误信息以统一的格式返回给客户端。
#[derive(Error, Debug)]
pub enum AppError {
    /// 数据库相关错误。包装 SeaORM 的 `DbErr`，自动转换。
    #[error("Database error: {0}")]
    DatabaseError(#[from] sea_orm::DbErr),

    /// Redis缓存相关错误。包装 redis crate 的 `RedisError`，自动转换。
    #[error("Redis error: {0}")]
    RedisError(#[from] redis::RedisError),

    /// 输入验证错误。包装 validator crate 的 `ValidationErrors`，自动转换。
    #[error("Validation error: {0}")]
    ValidationError(#[from] validator::ValidationErrors),

    /// 认证错误。如令牌无效、用户名密码错误等。返回401 Unauthorized。
    #[error("Authentication failed: {0}")]
    AuthError(String),

    /// 授权错误。如权限不足、需要管理员权限等。返回403 Forbidden。
    #[error("Permission denied: {0}")]
    Forbidden(String),

    /// 资源未找到错误。如用户不存在等。返回404 Not Found。
    #[error("Resource not found: {0}")]
    NotFound(String),

    /// 资源冲突错误。如用户名已存在等。返回409 Conflict。
    #[error("Conflict: {0}")]
    Conflict(String),

    /// 请求频率限制错误。返回429 Too Many Requests。
    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),

    /// 服务器内部错误。用于未预期的错误情况。返回500 Internal Server Error。
    #[error("Internal server error: {0}")]
    InternalServerError(String),
}

/// 实现 `IntoResponse` trait，将 `AppError` 转换为HTTP响应。
///
/// 这个实现确保所有错误都以统一的 `ApiResponse` 格式返回给客户端，
/// 并根据错误类型映射到正确的HTTP状态码。同时记录错误日志以便调试。
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // 根据错误类型确定HTTP状态码和返回给客户端的错误消息。
        // 对于内部错误（如数据库、Redis），返回通用的错误消息，避免泄露敏感信息。
        let (status, msg) = match &self {
            AppError::DatabaseError(e) => {
                // 记录详细的数据库错误日志，便于排查问题
                tracing::error!("❌ Database Error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Database service error".to_string())
            },
            AppError::RedisError(e) => {
                // 记录详细的Redis错误日志
                tracing::error!("❌ Redis Error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Cache service error".to_string())
            },
            AppError::InternalServerError(msg) => {
                // 记录内部服务器错误日志
                tracing::error!("❌ Internal Error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            },
            // 验证错误：直接返回验证失败的详细信息
            AppError::ValidationError(e) => (StatusCode::BAD_REQUEST, e.to_string()),
            // 认证错误：返回具体的认证失败消息
            AppError::AuthError(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            // 授权错误：返回具体的权限不足消息
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            // 资源未找到：返回具体的资源消息
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            // 资源冲突：返回具体的冲突消息
            AppError::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
            // 请求频率限制：返回具体的限流消息
            AppError::RateLimitExceeded(msg) => (StatusCode::TOO_MANY_REQUESTS, msg.clone()),
        };

        // 使用统一的 ApiResponse 格式返回错误，确保API响应的一致性
        ApiResponse::<()>::with_error(status, &msg).into_response()
    }
}