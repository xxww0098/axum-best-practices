use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use chrono::{Duration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode};
use rand::rngs::OsRng;
use redis::AsyncCommands;
use sea_orm::*;
use secrecy::ExposeSecret;
use uuid::Uuid;

use crate::{
    core::{config::Config, constants::*, enums::UserRole, error::AppError},
    dtos::auth::{Claims, LoginRequest, LoginResponse, RegisterRequest},
    entity::users,
    state::AppState,
    utils::{jwt::decode_jwt, limiter::check_rate_limit},
};

// --- 辅助函数 ---
fn refresh_key(token: &str) -> String {
    format!("{}{}", REDIS_PREFIX_REFRESH, token)
}
fn blacklist_key(token: &str) -> String {
    format!("{}{}", REDIS_PREFIX_BLACKLIST, token)
}

/// 生成 JWT Access Token
fn generate_access_token(
    config: &Config,
    user_id: &str,
    username: &str,
    role: UserRole,
) -> Result<String, AppError> {
    let now = Utc::now();
    let exp = (now + Duration::seconds(config.jwt_expiration)).timestamp() as usize;

    let claims = Claims {
        sub: user_id.to_string(),
        username: username.to_string(),
        role: role.to_string(),
        exp,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.expose_secret().as_bytes()),
    )
    .map_err(|e| AppError::InternalServerError(format!("Token generation failed: {}", e)))
}

// --- 业务逻辑 ---

/// 用户注册
pub async fn register(state: &AppState, req: RegisterRequest) -> Result<(), AppError> {
    // 1. 密码哈希 (Argon2)
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(req.password.as_bytes(), &salt)
        .map_err(|e| AppError::InternalServerError(format!("Hash failed: {}", e)))?
        .to_string();

    // 2. 构建模型
    let new_user = users::ActiveModel {
        username: Set(req.username),
        password_hash: Set(password_hash),
        phone: Set(req.phone),
        role: Set(UserRole::User),
        is_active: Set(true),
        ..Default::default()
    };

    // 3. 插入数据库 (处理唯一性冲突)
    users::Entity::insert(new_user)
        .exec(&state.db)
        .await
        .map_err(|e| {
            if e.to_string().contains("duplicate key") {
                AppError::Conflict("Username or Phone already exists".to_string())
            } else {
                AppError::DatabaseError(e)
            }
        })?;

    Ok(())
}

/// 用户登录
pub async fn login(state: &AppState, req: LoginRequest) -> Result<LoginResponse, AppError> {
    // 1. 查找用户 (用户名或手机号)
    let user = users::Entity::find()
        .filter(
            Condition::any()
                .add(users::Column::Username.eq(&req.account))
                .add(users::Column::Phone.eq(&req.account)),
        )
        .one(&state.db)
        .await?
        .ok_or(AppError::AuthError("Invalid credentials".to_string()))?;

    // 2. 校验密码
    let parsed_hash = PasswordHash::new(&user.password_hash)
        .map_err(|_| AppError::InternalServerError("Auth failed".to_string()))?;

    Argon2::default()
        .verify_password(req.password.as_bytes(), &parsed_hash)
        .map_err(|_| AppError::AuthError("Invalid credentials".to_string()))?;

    if !user.is_active {
        return Err(AppError::Forbidden("Account is disabled".to_string()));
    }

    // 3. 生成令牌对
    let access_token = generate_access_token(
        &state.config,
        &user.id.to_string(),
        &user.username,
        user.role.clone(),
    )?;
    let refresh_token = Uuid::new_v4().to_string();

    // 4. 存储 Refresh Token 到 Redis
    let mut redis = state.redis.clone();
    let _: () = redis
        .set_ex(
            refresh_key(&refresh_token),
            user.id.to_string(),
            state.config.refresh_token_expiration as u64,
        )
        .await?;

    Ok(LoginResponse {
        access_token,
        refresh_token,
    })
}

/// 刷新令牌 (Token Rotation)
pub async fn refresh(state: &AppState, old_token: String) -> Result<LoginResponse, AppError> {
    let redis_key_old = refresh_key(&old_token);
    let mut redis = state.redis.clone();

    // 1. 获取关联用户ID
    let user_id_raw: String = redis
        .get(&redis_key_old)
        .await
        .map_err(|_| AppError::AuthError("Invalid or expired refresh token".to_string()))?;

    // 2. 检查令牌轮转状态 (是否已使用)
    let (user_id, is_used) = if let Some(stripped) = user_id_raw.strip_prefix(REDIS_PREFIX_USED) {
        (stripped, true)
    } else {
        (user_id_raw.as_str(), false)
    };

    // 刷新限流: 10次/分
    check_rate_limit(&state.redis, "refresh_token", user_id, 10, 60).await?;

    if is_used {
        tracing::warn!("🚨 Refresh token reused! User: {}", user_id);
        return Err(AppError::Conflict(
            "Token reused. Please login again.".to_string(),
        ));
    }

    // 3. 验证用户状态
    let uid = Uuid::parse_str(user_id)
        .map_err(|_| AppError::InternalServerError("ID error".to_string()))?;
    let user = users::Entity::find_by_id(uid)
        .one(&state.db)
        .await?
        .ok_or(AppError::AuthError("User not found".to_string()))?;

    if !user.is_active {
        return Err(AppError::Forbidden("User inactive".to_string()));
    }

    // 4. 标记旧令牌为已使用 (宽限期)
    let used_val = format!("{}{}", REDIS_PREFIX_USED, user_id);
    let res: Result<(), redis::RedisError> = redis
        .set_ex(&redis_key_old, used_val, ROTATION_GRACE_PERIOD)
        .await;
    if let Err(e) = res {
        tracing::warn!("Failed to mark token as used: {}", e);
    }

    // 5. 生成新令牌对
    let new_access = generate_access_token(&state.config, user_id, &user.username, user.role)?;
    let new_refresh = Uuid::new_v4().to_string();

    let _: () = redis
        .set_ex(
            refresh_key(&new_refresh),
            user_id,
            state.config.refresh_token_expiration as u64,
        )
        .await?;

    Ok(LoginResponse {
        access_token: new_access,
        refresh_token: new_refresh,
    })
}

/// 用户登出 (令牌加入黑名单)
pub async fn logout(state: &AppState, token: &str) -> Result<(), AppError> {
    if let Ok(claims) = decode_jwt(token, &state.config) {
        let ttl = claims.exp as i64 - Utc::now().timestamp();

        if ttl > 0 {
            let mut redis = state.redis.clone();
            let key = blacklist_key(token);
            let _: () = redis.set_ex(key, "logout", ttl as u64).await?;
        }
    }
    Ok(())
}
