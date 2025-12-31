// src/start.rs
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

/// 启动并运行应用程序。这是应用程序的入口点，负责初始化所有必要的组件，
/// 包括配置加载、日志系统、数据库连接、Redis连接，以及HTTP服务器。
///
/// 这个函数执行以下步骤：
/// 1. 加载应用程序配置
/// 2. 初始化日志系统
/// 3. 建立数据库连接池
/// 4. 建立Redis连接
/// 5. 创建应用程序状态
/// 6. 配置并启动HTTP服务器
/// 7. 监听系统信号以实现优雅关闭
pub async fn run() {
    // 第一步：加载应用程序配置。配置从环境变量中读取，包括数据库URL、Redis URL、JWT密钥等。
    let config = Config::new();

    // 第二步：初始化日志系统。返回的 guard 用于在作用域结束时保持日志系统的活跃状态。
    let _guard = log::init(&config.rust_log);
    tracing::info!("🔍 Config loaded successfully.");

    // 第三步：配置并建立数据库连接池。
    // ConnectOptions 允许我们精细控制连接池的行为，如最大/最小连接数、连接超时等。
    let mut opt = ConnectOptions::new(config.database_url.expose_secret());
    opt.max_connections(100)      // 最大连接数：连接池中最多保持100个连接
        .min_connections(5)       // 最小连接数：连接池中至少保持5个连接
        .connect_timeout(Duration::from_secs(10))  // 连接超时：10秒内必须建立连接
        .sqlx_logging(false);     // 禁用SQLx的日志，避免日志过于冗长

    // 建立数据库连接。如果连接失败，程序会直接panic（在生产环境中应该使用更优雅的错误处理）。
    let db = Database::connect(opt)
        .await
        .expect("❌ Failed to connect to Database");
    tracing::info!("✅ Database connected.");

    // 第四步：建立Redis连接。这里使用连接管理器（ConnectionManager），
    // 它提供了自动重连等高级功能，适合在异步环境中使用。
    let client = redis::Client::open(config.redis_url.expose_secret())
        .expect("❌ Invalid Redis URL");
    let redis_manager = client.get_connection_manager()
        .await
        .expect("❌ Failed to connect to Redis");
    tracing::info!("✅ Redis connected.");

    // 第五步：创建应用程序状态。这个状态对象会在所有请求处理器之间共享，
    // 包含数据库连接池、Redis客户端和配置信息。
    let state = AppState::new(db, redis_manager, config.clone());

    // 第六步：配置服务器监听地址。从配置中读取主机和端口，解析为SocketAddr。
    let addr_str = format!("{}:{}", config.host, config.port);
    let addr: SocketAddr = addr_str.parse().expect("❌ Invalid address configuration");

    tracing::info!("🚀 Server listening on http://{}", addr);

    // 创建TCP监听器，用于接受传入的连接请求。
    let listener = TcpListener::bind(addr).await.unwrap();
    // 创建路由器，配置所有的HTTP端点。
    let app = routes::create_router(state);

    // 第七步：启动HTTP服务器，并配置优雅关闭。
    // with_graceful_shutdown 允许在接收到关闭信号时完成正在处理的请求，
    // 然后再关闭服务器，避免中断正在处理的请求。
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

/// 监听系统关闭信号。这个函数会阻塞当前任务，直到接收到关闭信号为止。
/// 支持的信号包括：
/// - Ctrl+C（SIGINT）：在终端中按下 Ctrl+C
/// - SIGTERM：Unix系统中的终止信号（如 kill 命令）
///
/// # 返回值
/// 当接收到任一关闭信号时，函数返回，触发优雅关闭流程。
async fn shutdown_signal() {
    // 监听 Ctrl+C 信号（SIGINT）。这是用户在终端中手动中断程序的常用方式。
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    // 监听 SIGTERM 信号。这是Unix系统中请求程序正常终止的标准方式。
    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    // 在非Unix系统（如Windows）上，使用一个永不完成的future作为占位符。
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    // 使用 tokio::select! 宏同时等待多个异步操作。
    // 只要其中任一操作完成，就会立即取消并清理其他操作。
    tokio::select! {
        _ = ctrl_c => {},   // Ctrl+C 被按下
        _ = terminate => {}, // SIGTERM 信号被接收
    }

    tracing::info!("🛑 Signal received, starting graceful shutdown...");
}