use sea_orm::DatabaseConnection;
use redis::aio::ConnectionManager;
use std::sync::Arc;
use crate::core::config::Config;

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub redis: ConnectionManager,
    /// 全局配置，使用 Arc 包装以实现廉价克隆
    pub config: Arc<Config>,
}

impl AppState {
    pub fn new(db: DatabaseConnection, redis: ConnectionManager, config: Config) -> Self {
        Self {
            db,
            redis,
            config: Arc::new(config),
        }
    }
}