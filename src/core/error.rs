// src/core/error.rs
use crate::dtos::response::ApiResponse;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

/// 应用程序统一错误类型
/// 覆盖数据库、缓存、验证、认证、授权等错误
#[derive(Error, Debug)]
pub enum AppError {
    /// 数据库错误 (SeaORM)
    #[error("Database error: {0}")]
    DatabaseError(#[from] sea_orm::DbErr),

    /// Redis 错误
    #[error("Redis error: {0}")]
    RedisError(#[from] redis::RedisError),

    /// 验证错误 (Validator)
    #[error("Validation error: {0}")]
    ValidationError(#[from] validator::ValidationErrors),

    /// 认证失败 (401)
    #[error("Authentication failed: {0}")]
    AuthError(String),

    /// 权限不足 (403)
    #[error("Permission denied: {0}")]
    Forbidden(String),

    /// 资源未找到 (404)
    #[error("Resource not found: {0}")]
    NotFound(String),

    /// 资源冲突 (409)
    #[error("Conflict: {0}")]
    Conflict(String),

    /// 请求过于频繁 (429) - 携带重试等待秒数
    #[error("Rate limit exceeded. Try again in {0} seconds.")]
    RateLimitExceeded(u64),

    /// 内部服务器错误 (500)
    #[error("Internal server error: {0}")]
    InternalServerError(String),
}

/// 实现 `IntoResponse` 以支持 Axum 错误处理
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // 特殊处理 RateLimitExceeded 以添加 Header
        if let AppError::RateLimitExceeded(retry_after) = self {
            let msg = format!("Rate limit exceeded. Try again in {} seconds.", retry_after);
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(axum::http::header::RETRY_AFTER, retry_after.to_string())],
                axum::Json(ApiResponse::<()>::with_error(
                    StatusCode::TOO_MANY_REQUESTS,
                    &msg,
                )),
            )
                .into_response();
        }

        let (status, msg) = match &self {
            AppError::DatabaseError(e) => {
                tracing::error!("❌ Database Error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Database service error".to_string(),
                )
            }
            AppError::RedisError(e) => {
                tracing::error!("❌ Redis Error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Cache service error".to_string(),
                )
            }
            AppError::InternalServerError(msg) => {
                tracing::error!("❌ Internal Error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
            // 业务逻辑错误直接返回消息
            AppError::ValidationError(e) => (StatusCode::BAD_REQUEST, e.to_string()),
            AppError::AuthError(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
            // 已在上方特殊处理
            AppError::RateLimitExceeded(_) => unreachable!(),
        };

        ApiResponse::<()>::with_error(status, &msg).into_response()
    }
}
