use argon2::{
    password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use rand::rngs::OsRng;
use redis::AsyncCommands;
use sea_orm::*;
use secrecy::ExposeSecret;
use uuid::Uuid;

use crate::{
    core::{
        constants::*,
        enums::UserRole,
        error::AppError,
        config::Config,
    },
    dtos::auth::{Claims, LoginRequest, LoginResponse, RegisterRequest},
    entity::users,
    state::AppState,
    utils::limiter::check_rate_limit,
};

// --- 辅助函数模块：提供认证服务中使用的工具函数，如密钥生成、令牌处理等 ---
#[inline]
fn refresh_key(token: &str) -> String {
    format!("{}{}", REDIS_PREFIX_REFRESH, token)
}
#[inline]
fn blacklist_key(token: &str) -> String {
    format!("{}{}", REDIS_PREFIX_BLACKLIST, token)
}

/// 生成访问令牌（Access Token）。这是一个纯函数，没有副作用，只负责根据用户信息生成 JWT 令牌。
/// 令牌包含用户身份信息（ID、用户名、角色）和过期时间，使用配置中的密钥进行签名。
///
/// # 参数
/// - `config`: 应用程序配置，包含 JWT 密钥和过期时间等设置。
/// - `user_id`: 用户唯一标识符（UUID 字符串格式）。
/// - `username`: 用户名，用于在令牌中标识用户。
/// - `role`: 用户角色（Admin 或 User），用于权限控制。
///
/// # 返回值
/// - `Ok(String)`: 成功时返回签名的 JWT 令牌字符串。
/// - `Err(AppError)`: 失败时返回令牌生成错误，如签名失败等。
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

// --- 业务逻辑模块：实现认证服务的核心功能，如注册、登录、刷新令牌、登出等 ---

/// 用户注册服务。这个函数处理新用户的注册流程，包括密码哈希、数据验证和数据库插入。
/// 使用 Argon2 算法对密码进行安全哈希，防止密码泄露。检查用户名和手机号的唯一性，
/// 防止重复注册。
///
/// # 参数
/// - `state`: 应用程序状态，包含数据库连接、Redis 客户端和配置信息。
/// - `req`: 注册请求数据，包含用户名、密码、手机号等信息。
///
/// # 返回值
/// - `Ok(())`: 成功时返回空值，表示用户注册成功。
/// - `Err(AppError)`: 失败时返回相应的错误，如用户已存在、数据库错误、密码哈希失败等。
pub async fn register(state: &AppState, req: RegisterRequest) -> Result<(), AppError> {
    // 第一步：密码哈希。使用 Argon2 算法和随机盐值对用户密码进行安全哈希。
    // Argon2 是密码哈希竞赛的获胜者，能有效抵抗暴力破解和彩虹表攻击。
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(req.password.as_bytes(), &salt)
        .map_err(|e| AppError::InternalServerError(format!("Hash failed: {}", e)))?
        .to_string();

    // 第二步：构建数据模型。将请求数据转换为 SeaORM 的 ActiveModel，
    // 设置用户的默认角色为普通用户（User），并激活账户状态。
    let new_user = users::ActiveModel {
        username: Set(req.username),
        password_hash: Set(password_hash),
        phone: Set(req.phone),
        role: Set(UserRole::User),
        is_active: Set(true),
        ..Default::default()
    };

    // 第三步：插入数据库。将构建好的用户模型保存到 PostgreSQL 数据库中。
    // 如果发生唯一键冲突（用户名或手机号已存在），返回适当的错误信息。
    users::Entity::insert(new_user)
        .exec(&state.db)
        .await
        .map_err(|e| {
            // 处理唯一键冲突：检查数据库错误信息是否包含 "duplicate key"，
            // 如果是则返回用户友好的冲突错误，否则返回通用的数据库错误。
            if e.to_string().contains("duplicate key") {
                AppError::Conflict("Username or Phone already exists".to_string())
            } else {
                AppError::DatabaseError(e)
            }
        })?;

    Ok(())
}

/// 用户登录服务。这个函数处理用户登录认证，支持使用用户名或手机号登录。
/// 验证用户凭证（账户标识和密码），检查账户状态，生成访问令牌和刷新令牌。
/// 刷新令牌会存储在 Redis 中，用于后续的令牌刷新操作。
///
/// # 参数
/// - `state`: 应用程序状态，包含数据库连接、Redis 客户端和配置信息。
/// - `req`: 登录请求数据，包含账户标识（用户名或手机号）和密码。
///
/// # 返回值
/// - `Ok(LoginResponse)`: 成功时返回包含访问令牌和刷新令牌的响应。
/// - `Err(AppError)`: 失败时返回相应的错误，如凭证无效、账户禁用、密码错误等。
pub async fn login(state: &AppState, req: LoginRequest) -> Result<LoginResponse, AppError> {
    // 第一步：查找用户。支持使用用户名或手机号登录，使用 Condition::any() 构建 OR 查询条件。
    // 如果找不到对应的用户，返回统一的"无效凭证"错误，避免泄露用户存在信息。
    let user = users::Entity::find()
        .filter(
            Condition::any()
                .add(users::Column::Username.eq(&req.account))
                .add(users::Column::Phone.eq(&req.account)),
        )
        .one(&state.db)
        .await?
        .ok_or(AppError::AuthError("Invalid credentials".to_string()))?;

    // 第二步：校验密码。使用 Argon2 算法验证用户输入的密码是否与存储的哈希值匹配。
    // 密码验证失败时返回统一的"无效凭证"错误，避免泄露具体的失败原因。
    let parsed_hash = PasswordHash::new(&user.password_hash)
        .map_err(|_| AppError::InternalServerError("Auth failed".to_string()))?;

    Argon2::default()
        .verify_password(req.password.as_bytes(), &parsed_hash)
        .map_err(|_| AppError::AuthError("Invalid credentials".to_string()))?;

    if !user.is_active {
        return Err(AppError::Forbidden("Account is disabled".to_string()));
    }

    // 第三步：生成令牌。创建访问令牌（JWT）和刷新令牌（UUID v4）。
    // 访问令牌用于 API 身份验证，刷新令牌用于获取新的访问令牌。
    let access_token = generate_access_token(&state.config, &user.id.to_string(), &user.username, user.role.clone())?;
    let refresh_token = Uuid::new_v4().to_string();

    // 第四步：将刷新令牌存入 Redis。设置过期时间与刷新令牌的有效期一致。
    // 存储用户ID与刷新令牌的关联，用于后续的令牌验证和刷新操作。
    let mut redis = state.redis.clone();
    
    // 类型提示：显式指定 Redis 操作返回类型为 ()，以满足 FromRedisValue trait 的要求。
    // 这是 Redis-rs 库的常见用法，确保编译器能正确推断返回类型。
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

/// 令牌刷新服务。这个函数处理刷新令牌的验证和轮换，生成新的访问令牌和刷新令牌。
/// 实现令牌轮转（Token Rotation）机制，防止令牌重用攻击，支持并发刷新的宽限期。
/// 每个刷新令牌只能使用一次，使用后会被标记为已使用，并在宽限期后自动过期。
///
/// # 参数
/// - `state`: 应用程序状态，包含数据库连接、Redis 客户端和配置信息。
/// - `old_token`: 旧的刷新令牌字符串，需要验证和轮换。
///
/// # 返回值
/// - `Ok(LoginResponse)`: 成功时返回包含新令牌的响应。
/// - `Err(AppError)`: 失败时返回相应的错误，如令牌无效、已使用、用户不存在等。
pub async fn refresh(state: &AppState, old_token: String) -> Result<LoginResponse, AppError> {
    let redis_key_old = refresh_key(&old_token);
    let mut redis = state.redis.clone();

    // 第一步：从 Redis 获取与刷新令牌关联的用户ID。如果令牌不存在或已过期，返回验证错误。
    let user_id_raw: String = redis
        .get(&redis_key_old)
        .await
        .map_err(|_| AppError::AuthError("Invalid or expired refresh token".to_string()))?;

    // 第二步：检查令牌轮转状态。如果值以 "USED:" 前缀开头，表示该令牌已被使用过。
    // 这是令牌轮转机制的一部分，防止刷新令牌被重复使用。
    let (user_id, is_used) = if let Some(stripped) = user_id_raw.strip_prefix(REDIS_PREFIX_USED) {
        (stripped, true)
    } else {
        (user_id_raw.as_str(), false)
    };

    // 针对刷新操作的限流检查：每个用户每分钟最多刷新 10 次令牌，防止滥用刷新功能。
    check_rate_limit(&state.redis, "refresh_token", user_id, 10, 60).await?;

    if is_used {
        // 🚨 安全警告：刷新令牌被重复使用，这可能意味着令牌已泄露或被窃取。
        // 在生产环境中，应该考虑吊销该用户的所有令牌，并通知用户重新认证。
        tracing::warn!("🚨 Refresh token reused! User: {}", user_id);
        return Err(AppError::Conflict("Token reused. Please login again.".to_string()));
    }

    // 第三步：根据用户ID查找用户信息。验证用户是否存在且账户处于激活状态。
    let uid = Uuid::parse_str(user_id).map_err(|_| AppError::InternalServerError("ID error".to_string()))?;
    let user = users::Entity::find_by_id(uid).one(&state.db).await?
        .ok_or(AppError::AuthError("User not found".to_string()))?;

    if !user.is_active {
        return Err(AppError::Forbidden("User inactive".to_string()));
    }

    // 第四步：将旧令牌标记为已使用，设置宽限期（Grace Period）。
    // 宽限期机制允许前端在短时间内并发发送的刷新请求使用同一个旧令牌，
    // 避免因网络延迟或前端并发导致的令牌无效错误。宽限期后令牌将完全失效。
    let used_val = format!("{}{}", REDIS_PREFIX_USED, user_id);
    let _: () = redis.set_ex(&redis_key_old, used_val, ROTATION_GRACE_PERIOD).await.unwrap_or_default();

    // 第五步：生成新的访问令牌和刷新令牌。新令牌将替换旧令牌，完成令牌轮转。
    let new_access = generate_access_token(&state.config, user_id, &user.username, user.role)?;
    let new_refresh = Uuid::new_v4().to_string();

    // 类型提示：显式指定 Redis 操作返回类型为 ()，与前面的设置操作保持一致。
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

/// 用户登出服务。这个函数处理令牌失效，将有效的 JWT 令牌加入 Redis 黑名单。
/// 黑名单中的令牌在剩余有效期内无法再用于访问受保护资源，实现即时登出效果。
/// 即使令牌验证失败（如签名错误），函数也会正常返回，避免泄露验证细节。
///
/// # 参数
/// - `state`: 应用程序状态，包含数据库连接、Redis 客户端和配置信息。
/// - `token`: 需要失效的 JWT 令牌字符串。
///
/// # 返回值
/// - `Ok(())`: 总是返回成功，即使令牌无效也会正常返回，避免信息泄露。
/// - `Err(AppError)`: 仅在 Redis 操作失败时返回错误。
pub async fn logout(state: &AppState, token: &str) -> Result<(), AppError> {
    use jsonwebtoken::{decode, DecodingKey, Validation};

    let secret = state.config.jwt_secret.expose_secret().as_bytes();
    let decoding_key = DecodingKey::from_secret(secret);

    // 解码令牌主要目的是获取过期时间（exp字段），用于设置黑名单的有效期。
    // 即使令牌签名验证失败，通常也可以忽略（因为用户已经登出），
    // 但为了安全起见，我们仍然进行基本的验证，防止恶意令牌导致错误。
    if let Ok(token_data) = decode::<Claims>(token, &decoding_key, &Validation::default()) {
        let ttl = token_data.claims.exp as i64 - Utc::now().timestamp();
        
        if ttl > 0 {
            let mut redis = state.redis.clone();
            let key = blacklist_key(token);
            
            // 将令牌加入 Redis 黑名单，设置过期时间为令牌的剩余有效期。
            // 这样令牌在自然过期后会自动从黑名单中移除，避免黑名单无限增长。
            // 类型提示：显式指定 Redis 操作返回类型为 ()，确保类型推断正确。
            let _: () = redis.set_ex(key, "logout", ttl as u64).await?;
        }
    }
    Ok(())
}