use jsonwebtoken::{DecodingKey, Validation, decode};
use secrecy::ExposeSecret;

use crate::{core::config::Config, core::error::AppError, dtos::auth::Claims};

/// 提取 Bearer Token
pub fn extract_bearer_token(auth_value: &str) -> Option<&str> {
    auth_value.strip_prefix("Bearer ")
}

/// 解码并验证 JWT
pub fn decode_jwt(token: &str, config: &Config) -> Result<Claims, AppError> {
    let secret = config.jwt_secret.expose_secret().as_bytes();
    let decoding_key = DecodingKey::from_secret(secret);

    decode::<Claims>(token, &decoding_key, &Validation::default())
        .map(|data| data.claims)
        .map_err(|_| AppError::AuthError("Invalid or expired token".to_string()))
}
