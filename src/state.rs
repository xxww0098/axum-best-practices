use crate::core::config::Config;
use redis::aio::ConnectionManager;
use sea_orm::DatabaseConnection;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub redis: ConnectionManager,
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
