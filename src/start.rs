// src/start.rs
use anyhow::Result;
use sea_orm::{ConnectOptions, Database};
use secrecy::ExposeSecret;
use std::{net::SocketAddr, time::Duration};
use tokio::net::TcpListener;
use tokio::signal;

use crate::{
    core::{config::Config, log},
    routes,
    state::AppState,
};

/// 启动应用程序
/// 初始化配置、日志、数据库、Redis，并启动 HTTP 服务器
pub async fn run() -> Result<()> {
    // 1. 加载配置
    let config = Config::new();

    // 2. 初始化日志
    let _guard = log::init(&config.rust_log);
    tracing::info!("🔍 Config loaded successfully.");

    // 3. 连接数据库 (Postgres)
    let mut opt = ConnectOptions::new(config.database_url.expose_secret());
    opt.max_connections(100)
        .min_connections(5)
        .connect_timeout(Duration::from_secs(10))
        .sqlx_logging(false);

    let db = Database::connect(opt).await.map_err(|e| {
        tracing::error!("❌ Failed to connect to Database: {}", e);
        e
    })?;
    tracing::info!("✅ Database connected.");

    // 4. 连接 Redis
    let client = redis::Client::open(config.redis_url.expose_secret()).map_err(|e| {
        tracing::error!("❌ Invalid Redis URL: {}", e);
        e
    })?;
    let redis_manager = client.get_connection_manager().await.map_err(|e| {
        tracing::error!("❌ Failed to connect to Redis: {}", e);
        e
    })?;
    tracing::info!("✅ Redis connected.");

    // 5. 创建应用状态
    let state = AppState::new(db, redis_manager, config.clone());

    // 6. 绑定端口
    let addr_str = format!("{}:{}", config.host, config.port);
    let addr: SocketAddr = addr_str.parse().map_err(|e| {
        tracing::error!("❌ Invalid address configuration {}: {}", addr_str, e);
        e
    })?;

    tracing::info!("🚀 Server listening on http://{}", addr);

    let listener = TcpListener::bind(addr).await.map_err(|e| {
        tracing::error!("❌ Failed to bind to address {}: {}", addr, e);
        e
    })?;

    // 7. 创建路由
    let app = routes::create_router(state);

    // 8. 启动服务器 (支持优雅关闭)
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| {
            tracing::error!("❌ Server error: {}", e);
            e
        })?;

    Ok(())
}

/// 监听关闭信号 (Ctrl+C / SIGTERM)
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("🛑 Signal received, starting graceful shutdown...");
}
