use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(length(min = 3, message = "Username must be at least 3 characters"))]
    pub username: String,
    
    #[validate(length(min = 6, message = "Password must be at least 6 characters"))]
    pub password: String,
    
    #[validate(regex(path = *crate::dtos::PHONE_REGEX, message = "Invalid phone format"))]
    pub phone: Option<String>,
}

#[derive(Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(length(min = 1, message = "Account cannot be empty"))]
    pub account: String,
    #[validate(length(min = 1, message = "Password cannot be empty"))]
    pub password: String,
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub username: String,
    pub role: String,
    pub exp: usize,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
}