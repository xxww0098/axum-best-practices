use std::{net::SocketAddr, time::Duration};
use sea_orm::{Database, ConnectOptions};
use secrecy::ExposeSecret;
use tokio::net::TcpListener;
use tokio::signal;

use crate::{
    core::{config::Config, log},
    routes,
    state::AppState,
};

pub async fn run() {
    // 1. 初始化配置 (不再是全局变量)
    let config = Config::new();
    
    // 2. 初始化日志
    let _guard = log::init(&config.rust_log);
    tracing::info!("🔍 Config loaded successfully.");

    // 3. 连接数据库
    let mut opt = ConnectOptions::new(config.database_url.expose_secret());
    opt.max_connections(100)
        .min_connections(5)
        .connect_timeout(Duration::from_secs(10))
        .sqlx_logging(false); // 生产环境减少噪音

    let db = Database::connect(opt)
        .await
        .expect("❌ Failed to connect to Database");
    tracing::info!("✅ Database connected.");

    // 4. 连接 Redis
    // `ExposeSecret::expose_secret()` already yields a `&str` for `SecretString`.
    // Avoid calling `as_str()` (triggers the unstable `str_as_str` lint on some toolchains).
    let client = redis::Client::open(config.redis_url.expose_secret())
        .expect("❌ Invalid Redis URL");
    let redis_manager = client.get_connection_manager()
        .await
        .expect("❌ Failed to connect to Redis");
    tracing::info!("✅ Redis connected.");

    // 5. 构建应用状态 (注入 Config)
    let state = AppState::new(db, redis_manager, config.clone());

    // 6. 绑定端口
    let addr_str = format!("{}:{}", config.server_host, config.server_port);
    let addr: SocketAddr = addr_str.parse().expect("❌ Invalid address configuration");
    
    tracing::info!("🚀 Server listening on http://{}", addr);

    let listener = TcpListener::bind(addr).await.unwrap();
    let app = routes::create_router(state);

    // 7. 启动服务 (带平滑关闭)
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

/// 监听 Ctrl+C 和 Terminate 信号，实现平滑关闭
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