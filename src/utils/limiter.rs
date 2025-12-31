use redis::Script;
use redis::aio::ConnectionManager;
use crate::core::error::AppError;

/// Lua 脚本实现滑动窗口限流或固定窗口限流
pub async fn check_rate_limit(
    redis_manager: &ConnectionManager,
    action_key: &str,
    user_id: &str,
    limit: usize,
    window: u64,
) -> Result<(), AppError> {
    let redis_key = format!("rate_limit:{}:{}", action_key, user_id);
    let mut conn = redis_manager.clone();

    // 原子操作：自增并设置过期时间（如果是第一次）
    let script = Script::new(r#"
        local count = redis.call("INCR", KEYS[1])
        if count == 1 then
            redis.call("EXPIRE", KEYS[1], ARGV[1])
        end
        return count
    "#);

    let count: usize = script
        .key(&redis_key)
        .arg(window)
        .invoke_async(&mut conn)
        .await?; // thiserror 自动处理错误

    if count > limit {
        tracing::warn!("⛔ Rate limit exceeded: User {} on {} ({}/{})", user_id, action_key, count, limit);
        return Err(AppError::RateLimitExceeded(
            format!("Rate limit exceeded. Try again in {} seconds.", window)
        ));
    }

    Ok(())
}