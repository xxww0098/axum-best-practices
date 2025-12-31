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

// 引入自定义中间件模块，重命名为 app_middleware 以避免与 axum::middleware 命名冲突。
// 这是 Rust 模块系统的常见做法，确保代码清晰可读。
use crate::{handlers, state::AppState, middleware as app_middleware};

/// 创建应用程序路由器。这个函数定义所有 API 端点的路由结构，配置中间件链，
/// 并设置全局功能如日志记录和 CORS。
///
/// # 路由结构
/// 1. 认证路由 (`/auth/*`) - 公开访问：登录、刷新令牌、登出。
/// 2. 用户路由 (`/users/*`) - 需登录访问：获取/更新用户资料。
/// 3. 管理员路由 (`/admin/*`) - 需管理员权限：用户注册。
///
/// # 中间件设计
/// - 用户路由：应用基础鉴权中间件（检查令牌黑名单）。
/// - 管理员路由：应用两层中间件链（从外到内：黑名单检查 → 管理员权限验证）。
/// - 全局中间件：请求日志记录和 CORS 支持。
///
/// # 参数
/// - `state`: 应用程序状态，包含数据库连接、Redis 客户端和配置信息。
///
/// # 返回值
/// - 配置完整的 Axum Router，可用于启动 HTTP 服务器。
pub fn create_router(state: AppState) -> Router {
    // 认证模块路由：公开访问的认证端点，不需要任何中间件保护。
    // 注意：用户注册功能已移至管理员路由，需要管理员权限才能访问，提高了系统安全性。
    let auth_routes = Router::new()
        .route("/login", post(handlers::auth::login))
        .route("/refresh", post(handlers::auth::refresh)) // 刷新令牌端点：虽然理论上也需要黑名单检查，但刷新处理器内部已包含完整的安全验证逻辑，因此这里不需要额外中间件。
        .route("/logout", post(handlers::auth::logout));

    // 用户模块路由：需要登录才能访问的用户资料管理端点。
    let user_routes = Router::new()
        .route("/me", get(handlers::users::get_me))
        .route("/me", post(handlers::users::update_me))
        // ✨ 应用基础鉴权 (检查 Token 黑名单)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            app_middleware::auth::auth_middleware,
        ));

    // --- 管理员模块路由 (需登录 + Admin权限) ---
    let admin_routes = Router::new()
        .route("/register", post(handlers::auth::register)) // 只有管理员能创建用户
        // ✨ 中间件链 (执行顺序：从下往上，即 2 -> 1 -> Handler)
        
        // 1. (内层) 权限守卫：检查是否为 Admin
        //    如果 Token 有效但不是 Admin，这里会拦截
        .layer(middleware::from_fn_with_state(
            state.clone(),
            app_middleware::auth::admin_guard,
        ))
        
        // 2. (外层) 基础鉴权：检查 Token 是否在黑名单
        //    请求最先到达这里。如果 Token 已注销，直接拒绝，不会进入 admin_guard
        .layer(middleware::from_fn_with_state(
            state.clone(),
            app_middleware::auth::auth_middleware,
        ));

    // --- 路由组合 ---
    Router::new()
        .route("/", get(|| async { "🚀 Axum Server is Running!" }))
        .nest("/auth", auth_routes)
        .nest("/users", user_routes)
        .nest("/admin", admin_routes)
        
        // 全局日志与 CORS
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_request(DefaultOnRequest::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO))
        )
        .layer(CorsLayer::permissive())
        .with_state(state)
}