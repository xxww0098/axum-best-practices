// ==========================================
// Redis Key 前缀定义：这些常量用于构建Redis缓存键的前缀部分，确保键名的一致性和可管理性。
// ==========================================

/// Refresh Token 前缀：用于存储刷新令牌的Redis键前缀。
pub const REDIS_PREFIX_REFRESH: &str = "refresh_token:";

/// 黑名单前缀：用于存储已注销或无效令牌的Redis键前缀。
pub const REDIS_PREFIX_BLACKLIST: &str = "blacklist:token:";

/// 已使用 Token 前缀：用于标记已使用过的令牌，防止重复使用。
pub const REDIS_PREFIX_USED: &str = "USED:";

// 用户资料缓存前缀：用于缓存用户资料的Redis键前缀。注意末尾的冒号，确保键名格式正确。
pub const REDIS_PREFIX_USER_PROFILE: &str = "cache:user:profile:";

// ==========================================
// 业务逻辑常量：这些常量控制应用程序的核心业务逻辑，如令牌轮换宽限期、缓存过期时间等。
// ==========================================

/// Token 轮换宽限期（秒）：在令牌轮换期间允许旧令牌继续使用的宽限时间，单位为秒。
pub const ROTATION_GRACE_PERIOD: u64 = 10;

// 用户资料缓存过期时间（24小时）：用户资料在Redis缓存中存储的有效时间，单位为秒。
pub const CACHE_EXPIRE_USER_PROFILE: u64 = 60 * 60 * 24;

#[allow(dead_code)]
pub const MIN_PASSWORD_LEN: usize = 6;

#[allow(dead_code)]
pub const PHONE_LEN: usize = 11;