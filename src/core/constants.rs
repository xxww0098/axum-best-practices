// ==========================================
// Redis Key 前缀
// ==========================================

/// Refresh Token 前缀
pub const REDIS_PREFIX_REFRESH: &str = "refresh_token:";

/// 黑名单前缀 (用于注销/无效令牌)
pub const REDIS_PREFIX_BLACKLIST: &str = "blacklist:token:";

/// 已使用 Token 前缀 (防止重用)
pub const REDIS_PREFIX_USED: &str = "USED:";

// ==========================================
// 业务逻辑常量
// ==========================================

/// Token 轮换宽限期 (秒)
pub const ROTATION_GRACE_PERIOD: u64 = 10;

/// 用户资料缓存过期时间 (24小时)
pub const CACHE_EXPIRE_USER_PROFILE: u64 = 60 * 60 * 24;
