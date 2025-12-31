use redis::{aio::ConnectionManager, AsyncCommands};
use serde::{de::DeserializeOwned, Serialize};
use std::future::Future;
use crate::core::error::AppError;

/// 通用缓存获取函数（Cache-Aside 模式）：优先从缓存读取，缓存未命中时从数据库获取并回填缓存。
///
/// 这是缓存旁路模式的标准实现：首先尝试从Redis缓存中读取数据，如果读取成功则直接返回；
/// 如果缓存未命中（或Redis故障），则执行提供的数据库查询闭包（fetcher）来获取数据，
/// 并将结果写入Redis缓存，以便后续请求可以快速访问。
///
/// # 参数
/// - `key`: Redis 键名，用于唯一标识缓存数据。
/// - `ttl_seconds`: 缓存过期时间（秒），设置缓存数据的存活时间。
/// - `fetcher`: 数据库查询闭包（当缓存未命中时执行），返回需要缓存的数据。
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

    // 第一步：尝试从 Redis 读取缓存数据。如果读取成功且数据有效，则直接返回缓存数据。
    // 使用 match 处理错误，Redis 故障不应阻断业务（Soft Fail 策略）。即使 Redis 出现故障，应用程序也应继续运行，降级为直接查询数据库。
    match redis.get::<_, String>(key).await {
        Ok(json_str) if !json_str.is_empty() => {
            match serde_json::from_str::<T>(&json_str) {
                Ok(data) => {
                    tracing::debug!("✅ Cache hit: {}", key);
                    return Ok(data);
                }
                Err(e) => tracing::warn!("⚠️ Cache deserialize failed for {}: {}", key, e),
            }
        }
        Err(e) => tracing::warn!("⚠️ Redis get failed for {}: {}", key, e),
        _ => {} // Key 不存在，继续向下执行。这种情况属于正常的缓存未命中，需要执行数据库查询。
    };

    // 第二步：缓存未命中（或 Redis 故障），执行 fetcher 查询数据库。这是缓存旁路模式的核心：当缓存不可用时，直接从数据源获取数据。
    tracing::debug!("🔍 Cache miss, fetching from DB: {}", key);
    let data = fetcher().await?;

    // 第三步：将查询结果回填到 Redis 缓存中。这样后续请求就可以直接从缓存中获取数据，提高性能。
    // 同样，写入失败不报错，只记录日志。这是 Soft Fail 策略的一部分，确保缓存故障不影响主要业务流程。
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

/// 通用缓存更新函数（直接覆盖）：将数据直接写入 Redis 缓存，覆盖已存在的键值。
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

/// 通用缓存删除函数：从 Redis 缓存中删除指定的键。用于缓存失效或数据更新时的清理操作。
#[allow(dead_code)]
pub async fn del(manager: &ConnectionManager, key: &str) {
    let mut redis = manager.clone();
    if let Err(e) = redis.del::<_, ()>(key).await {
        tracing::warn!("⚠️ Redis delete failed for {}: {}", key, e);
    } else {
        tracing::debug!("🗑️ Cache deleted: {}", key);
    }
}