use crate::core::error::AppError;
use redis::Script;
use redis::aio::ConnectionManager;
use std::sync::OnceLock;

/// Lua 脚本 (Token Bucket)
/// Keys: [rate_limit_key]
/// Args: [capacity, rate, ttl]
/// Return: [allowed(0/1), remaining_tokens, retry_after]
static RATE_LIMIT_SCRIPT: OnceLock<Script> = OnceLock::new();

fn get_script() -> &'static Script {
    RATE_LIMIT_SCRIPT.get_or_init(|| {
        Script::new(
            r#"
            local key = KEYS[1]
            local capacity = tonumber(ARGV[1])
            local rate = tonumber(ARGV[2]) -- tokens per second
            local ttl = tonumber(ARGV[3])

            -- 1. 获取当前 Redis 时间 (秒, 微秒)
            local time_info = redis.call("TIME")
            local now_sec = tonumber(time_info[1])
            local now_micros = tonumber(time_info[2])
            local now = now_sec + (now_micros / 1000000)

            -- 2. 获取上次状态
            local state = redis.call("HMGET", key, "tokens", "last_refill")
            local tokens = tonumber(state[1])
            local last_refill = tonumber(state[2])

            -- 3. 初始化或计算 Refill
            if not tokens or not last_refill then
                tokens = capacity
                last_refill = now
            else
                local delta = math.max(0, now - last_refill)
                local refill = delta * rate
                tokens = math.min(capacity, tokens + refill)
                last_refill = now
            end

            -- 4. 尝试扣减 (Cost = 1)
            local allowed = 0
            local retry_after = 0

            if tokens >= 1.0 then
                tokens = tokens - 1.0
                allowed = 1
            else
                allowed = 0
                -- 计算需要多久才能凑齐 1 个 token
                -- required = 1 - tokens
                -- time = required / rate
                retry_after = (1.0 - tokens) / rate
            end

            -- 5. 更新状态
            redis.call("HMSET", key, "tokens", tokens, "last_refill", last_refill)
            redis.call("EXPIRE", key, ttl)

            return {allowed, tokens, retry_after}
            "#,
        )
    })
}

/// 令牌桶限流 (Token Bucket)
/// 平滑限流，避免固定窗口的边界突刺问题
pub async fn check_rate_limit(
    redis_manager: &ConnectionManager,
    action_key: &str,
    user_id: &str,
    limit: usize,
    window: u64,
) -> Result<(), AppError> {
    // 加上 v1 版本前缀，避免旧数据干扰
    let redis_key = format!("rate_limit:v1:{}:{}", action_key, user_id);
    let mut conn = redis_manager.clone();

    // 计算速率 (Tokens / Sec)
    // 比如 limit=10, window=60s => rate = 0.166... tokens/s
    let rate = limit as f64 / window as f64;
    // TTL 设为窗口的 2 倍，保证数据不过早失效
    let ttl = window * 2;

    let script = get_script();

    // 返回值: (allowed, remaining, retry_after)
    // 注意: redis-rs 对 Lua 返回的 number 会转为 rust 的 integer 或 float
    // 这里我们用 tuple 接收
    let result: (i32, f64, f64) = script
        .key(&redis_key)
        .arg(limit) // capacity
        .arg(rate)
        .arg(ttl)
        .invoke_async(&mut conn)
        .await?;

    let allowed = result.0 == 1;
    let _remaining = result.1;
    let retry_after = result.2;

    if !allowed {
        // 向上取整，给用户一个整数等待时间
        let wait_seconds = (retry_after.ceil() as u64).max(1);

        tracing::warn!(
            "⛔ Rate limit exceeded: User {} on {} (Need wait {}s)",
            user_id,
            action_key,
            wait_seconds
        );

        return Err(AppError::RateLimitExceeded(wait_seconds));
    }

    Ok(())
}
