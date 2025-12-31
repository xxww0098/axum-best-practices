use axum::{http::StatusCode, response::{IntoResponse, Response}};
use thiserror::Error;
use crate::dtos::response::Res;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sea_orm::DbErr), // ✨ 自动转换 SeaORM 错误

    #[error("Redis error: {0}")]
    RedisError(#[from] redis::RedisError), // ✨ 自动转换 Redis 错误

    #[error("Validation error: {0}")]
    ValidationError(#[from] validator::ValidationErrors),

    #[error("Authentication failed: {0}")]
    AuthError(String),

    #[error("Permission denied: {0}")]
    Forbidden(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),

    #[error("Internal server error: {0}")]
    InternalServerError(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // 🔍 生产环境建议对 InternalServerError 进行脱敏处理
        // 这里为了开发方便，打印详细错误
        let (status, msg) = match &self {
            AppError::DatabaseError(e) => {
                tracing::error!("❌ Database Error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Database service error".to_string())
            },
            AppError::RedisError(e) => {
                tracing::error!("❌ Redis Error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Cache service error".to_string())
            },
            AppError::InternalServerError(msg) => {
                tracing::error!("❌ Internal Error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            },
            AppError::ValidationError(e) => (StatusCode::BAD_REQUEST, e.to_string()),
            AppError::AuthError(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
            AppError::RateLimitExceeded(msg) => (StatusCode::TOO_MANY_REQUESTS, msg.clone()),
        };

        Res::<()>::with_error(status, &msg).into_response()
    }
}