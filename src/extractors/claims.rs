use axum::{
    extract::FromRequestParts,
    http::request::Parts,
    RequestPartsExt,
};
// Removed: use async_trait::async_trait; 
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use secrecy::ExposeSecret;

use crate::{
    core::error::AppError,
    dtos::auth::Claims,
    state::AppState,
};

/// 自定义提取器：自动从 Header 中解析 Token 并验证
/// 如果验证失败，请求将直接被拒绝，不会进入 Handler
// Fix: Removed #[async_trait] - axum 0.8 FromRequestParts does not use it
impl FromRequestParts<AppState> for Claims {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        // 1. 尝试提取 Authorization: Bearer <token>
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AppError::AuthError("Missing or invalid Authorization header".to_string()))?;

        // 2. 从 AppState 中获取密钥 (依赖注入)
        let secret = state.config.jwt_secret.expose_secret().as_bytes();
        let decoding_key = DecodingKey::from_secret(secret);

        // 3. 解码并验证 Token
        let token_data = decode::<Claims>(bearer.token(), &decoding_key, &Validation::default())
            .map_err(|e| {
                tracing::warn!("⚠️ Token validation failed: {}", e);
                AppError::AuthError("Invalid or expired token".to_string())
            })?;

        // 4. (可选) 这里可以加入 Redis 黑名单校验
        // let redis_key = format!("blacklist:{}", bearer.token());
        // ...

        Ok(token_data.claims)
    }
}