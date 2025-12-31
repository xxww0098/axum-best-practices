// src/routes.rs
use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use tower_http::{
    cors::CorsLayer,
    trace::{TraceLayer, DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse},
};
use tracing::Level;

use crate::{handlers, state::AppState, middleware as app_middleware};

/// 创建并配置应用程序的路由器。这个函数构建了整个应用的HTTP路由结构，
/// 包括认证路由、用户路由、管理员路由，以及全局中间件层（如CORS和请求追踪）。
///
/// # 参数
/// - `state`: 应用程序状态，包含数据库连接、Redis客户端等共享资源。
///
/// # 返回值
/// - `Router`: 配置完成的Axum路由器，可直接用于启动HTTP服务。
pub fn create_router(state: AppState) -> Router {
    // 认证相关路由：登录、刷新令牌、登出。这些端点不需要认证即可访问。
    let auth_routes = Router::new()
        .route("/login", post(handlers::auth::login))
        .route("/refresh", post(handlers::auth::refresh))
        .route("/logout", post(handlers::auth::logout));

    // 用户相关路由：获取个人信息、更新个人信息。这些端点需要有效的JWT令牌。
    // 使用 check_token_revocation 中间件来验证令牌是否已被撤销（黑名单检查）。
    let user_routes = Router::new()
        .route("/me", get(handlers::users::get_me))
        .route("/me", post(handlers::users::update_me))
        // 检查令牌是否已被撤销（如用户登出后令牌应失效）
        .layer(middleware::from_fn_with_state(
            state.clone(),
            app_middleware::auth::check_token_revocation,
        ));

    // 管理员路由：用户注册等管理功能。这些端点需要管理员权限。
    // 中间件按顺序执行：先检查是否为管理员，再检查令牌是否被撤销。
    let admin_routes = Router::new()
        .route("/register", post(handlers::auth::register))
        // 第一层：验证用户是否具有管理员权限
        .layer(middleware::from_fn_with_state(
            state.clone(),
            app_middleware::auth::admin_guard,
        ))
        // 第二层：检查令牌是否已被撤销
        .layer(middleware::from_fn_with_state(
            state.clone(),
            app_middleware::auth::check_token_revocation,
        ));

    // 构建主路由器，整合所有子路由并应用全局中间件。
    // 注意：中间件的执行顺序与定义顺序相反，最后定义的中间件最先执行。
    Router::new()
        .route("/", get(|| async { "🚀 Axum Server is Running!" }))
        .nest("/auth", auth_routes)
        .nest("/users", user_routes)
        .nest("/admin", admin_routes)
        // 追踪层：记录HTTP请求的详细信息，包括请求开始、请求接收、响应发送等事件
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_request(DefaultOnRequest::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO))
        )
        // CORS层：允许跨域请求，使用 permissive() 配置允许任何来源（开发环境适用）
        .layer(CorsLayer::permissive())
        // 注入应用程序状态，使所有处理器都能访问共享资源
        .with_state(state)
}