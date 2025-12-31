pub mod limiter;
pub mod cache; // 新增模块注册：缓存模块，提供通用的缓存操作功能。

/// 限流宏：提供便捷的速率限制检查功能，防止 API 滥用。
/// 用法: rate_limit!(&state.redis, "action_name", &user_id, max_count, window_seconds); 其中参数依次为：Redis 连接、操作名称、用户标识、最大请求次数、时间窗口（秒）。
#[macro_export]
macro_rules! rate_limit {
    ($redis:expr, $action:expr, $key:expr, $limit:expr, $window:expr) => {
        if let Err(e) = $crate::utils::limiter::check_rate_limit($redis, $action, $key, $limit, $window).await {
            // 将限流器的错误转换为 AppError 类型，保持错误处理的一致性。
            return Err(e.into());
        }
    };
}