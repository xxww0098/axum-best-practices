// src/routes.rs
use axum::{
    Router, middleware,
    routing::{get, post},
};
use tower_http::{
    cors::CorsLayer,
    trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer},
};
use tracing::Level;

use crate::{handlers, middleware as app_middleware, state::AppState};

/// 创建路由
pub fn create_router(state: AppState) -> Router {
    // 公开路由
    let auth_routes = Router::new()
        .route("/login", post(handlers::auth::login))
        .route("/refresh", post(handlers::auth::refresh))
        .route("/logout", post(handlers::auth::logout));

    // 用户路由 (需认证)
    let user_routes = Router::new()
        .route("/me", get(handlers::users::get_me))
        .route("/me", post(handlers::users::update_me))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            app_middleware::auth::check_token_revocation,
        ));

    // 管理员路由 (需 Admin 权限)
    let admin_routes = Router::new()
        .route("/register", post(handlers::auth::register))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            app_middleware::auth::admin_guard,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            app_middleware::auth::check_token_revocation,
        ));

    // 路由组合 & 全局中间件
    Router::new()
        .route("/", get(|| async { "🚀 Axum Server is Running!" }))
        .nest("/auth", auth_routes)
        .nest("/users", user_routes)
        .nest("/admin", admin_routes)
        // 日志追踪
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_request(DefaultOnRequest::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        // CORS
        .layer(CorsLayer::permissive())
        .with_state(state)
}
