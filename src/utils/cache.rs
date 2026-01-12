use crate::core::error::AppError;
use redis::{AsyncCommands, aio::ConnectionManager};
use serde::{Serialize, de::DeserializeOwned};
use std::future::Future;

/// 生成用户资料缓存键
#[inline]
pub fn user_profile_key(user_id: &str) -> String {
    format!("cache:user:profile:{}", user_id)
}

/// 缓存优先获取 (Cache-Aside Pattern)
/// 优先读 Redis，未命中则执行 fetcher 查询 DB 并回填缓存
pub async fn get_or_fetch<T, F, Fut>(
    manager: &ConnectionManager,
    key: &str,
    ttl_seconds: u64,
    fetcher: F,
) -> Result<T, AppError>
where
    T: Serialize + DeserializeOwned + Send + Sync,
    F: FnOnce() -> Fut + Send,
    Fut: Future<Output = Result<T, AppError>> + Send,
{
    let mut redis = manager.clone();

    // 1. 读缓存 (Soft Fail: Redis 错误仅记录日志)
    match redis.get::<_, String>(key).await {
        Ok(json_str) if !json_str.is_empty() => match serde_json::from_str::<T>(&json_str) {
            Ok(data) => {
                tracing::debug!("✅ Cache hit: {}", key);
                return Ok(data);
            }
            Err(e) => tracing::warn!("⚠️ Cache deserialize failed for {}: {}", key, e),
        },
        Err(e) => tracing::warn!("⚠️ Redis get failed for {}: {}", key, e),
        _ => {} // Miss
    };

    // 2. 读 DB
    tracing::debug!("🔍 Cache miss, fetching from DB: {}", key);
    let data = fetcher().await?;

    // 3. 写回缓存 (异步，不阻塞返回)
    match serde_json::to_string(&data) {
        Ok(json_str) => {
            if let Err(e) = redis.set_ex::<_, _, ()>(key, json_str, ttl_seconds).await {
                tracing::warn!("⚠️ Redis set failed for {}: {}", key, e);
            } else {
                tracing::debug!("💾 Cache set: {}", key);
            }
        }
        Err(e) => tracing::error!("❌ Data serialization failed: {}", e),
    }

    Ok(data)
}

/// 写入缓存 (覆盖)
pub async fn set<T>(manager: &ConnectionManager, key: &str, data: &T, ttl_seconds: u64)
where
    T: Serialize + Send + Sync,
{
    let mut redis = manager.clone();
    match serde_json::to_string(data) {
        Ok(json_str) => {
            if let Err(e) = redis.set_ex::<_, _, ()>(key, json_str, ttl_seconds).await {
                tracing::warn!("⚠️ Redis set failed for {}: {}", key, e);
            } else {
                tracing::debug!("🔄 Cache updated: {}", key);
            }
        }
        Err(e) => tracing::error!("❌ Serialization failed: {}", e),
    }
}

/// 删除缓存
#[allow(dead_code)]
pub async fn del(manager: &ConnectionManager, key: &str) {
    let mut redis = manager.clone();
    if let Err(e) = redis.del::<_, ()>(key).await {
        tracing::warn!("⚠️ Redis delete failed for {}: {}", key, e);
    } else {
        tracing::debug!("🗑️ Cache deleted: {}", key);
    }
}
