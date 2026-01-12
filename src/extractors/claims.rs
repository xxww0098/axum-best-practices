use axum::{RequestPartsExt, extract::FromRequestParts, http::request::Parts};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};

use crate::{core::error::AppError, dtos::auth::Claims, state::AppState, utils::jwt::decode_jwt};

/// 自定义提取器：自动解析并验证 Bearer Token
impl FromRequestParts<AppState> for Claims {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // 1. 提取 Authorization Header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| {
                AppError::AuthError("Missing or invalid Authorization header".to_string())
            })?;

        // 2. 验证 Token
        let claims = decode_jwt(bearer.token(), &state.config).map_err(|e| {
            tracing::warn!("Token validation failed: {}", e);
            e
        })?;

        Ok(claims)
    }
}
