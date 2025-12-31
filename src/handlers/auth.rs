// src/handlers/auth.rs
use axum::{
    extract::{Json, State},
    response::IntoResponse,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use validator::Validate;

use crate::{
    core::error::AppError,
    dtos::{
        auth::{LoginRequest, RefreshRequest, RegisterRequest},
        response::ApiResponse,
    },
    services::auth as AuthService,
    state::AppState,
    rate_limit,
};

/// 用户注册处理器。处理新用户的注册请求。
///
/// # 功能说明
/// - 验证请求数据格式（使用 validator crate）
/// - 对用户名进行请求频率限制（防止暴力注册）
/// - 调用认证服务创建新用户
///
/// # 参数
/// - `state`: 应用程序状态，包含数据库、Redis等资源
/// - `payload`: 注册请求数据，包含用户名、密码等信息
///
/// # 返回值
/// - `Ok(impl IntoResponse)`: 注册成功，返回201 Created状态码
/// - `Err(AppError)`: 注册失败，返回相应的错误信息
pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;

    // 请求频率限制：每个用户名每60秒最多可以注册5次
    rate_limit!(&state.redis, "register", &payload.username, 5, 60);

    // 调用认证服务执行用户注册逻辑
    AuthService::register(&state, payload).await?;

    // 返回创建成功的响应，状态码为201 Created
    Ok(ApiResponse::<()>::with_code(
        axum::http::StatusCode::CREATED,
        "User registered successfully",
        None,
    ))
}

/// 用户登录处理器。处理用户的登录请求。
///
/// # 功能说明
/// - 验证请求数据格式
/// - 对账号进行请求频率限制（防止暴力破解）
/// - 验证用户凭据（用户名/邮箱和密码）
/// - 生成JWT访问令牌和刷新令牌
///
/// # 参数
/// - `state`: 应用程序状态
/// - `payload`: 登录请求数据，包含账号和密码
///
/// # 返回值
/// - `Ok(impl IntoResponse)`: 登录成功，返回访问令牌和刷新令牌
/// - `Err(AppError)`: 登录失败，返回相应的错误信息
pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;

    // 请求频率限制：每个账号每60秒最多可以登录5次
    rate_limit!(&state.redis, "login", &payload.account, 5, 60);

    // 调用认证服务执行登录逻辑，返回令牌对
    let response = AuthService::login(&state, payload).await?;

    // 返回令牌对（访问令牌和刷新令牌）
    Ok(ApiResponse::with_data(response))
}

/// 令牌刷新处理器。处理使用刷新令牌获取新的访问令牌的请求。
///
/// # 功能说明
/// - 验证刷新令牌的有效性
/// - 生成新的访问令牌和刷新令牌
///
/// # 参数
/// - `state`: 应用程序状态
/// - `payload`: 刷新令牌请求数据
///
/// # 返回值
/// - `Ok(impl IntoResponse)`: 刷新成功，返回新的令牌对
/// - `Err(AppError)`: 刷新失败，返回相应的错误信息
pub async fn refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshRequest>,
) -> Result<impl IntoResponse, AppError> {
    // 调用认证服务执行令牌刷新逻辑
    let response = AuthService::refresh(&state, payload.refresh_token).await?;
    // 返回新的令牌对
    Ok(ApiResponse::with_data(response))
}

/// 用户登出处理器。处理用户的登出请求。
///
/// # 功能说明
/// - 从请求头中提取Bearer令牌
/// - 将令牌加入黑名单，使其失效
///
/// # 参数
/// - `state`: 应用程序状态
/// - `bearer`: 从Authorization头中提取的Bearer令牌
///
/// # 返回值
/// - `Ok(impl IntoResponse)`: 登出成功
/// - `Err(AppError)`: 登出失败，返回相应的错误信息
pub async fn logout(
    State(state): State<AppState>,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse, AppError> {

    // 提取令牌字符串
    let token = bearer.token();
    // 调用认证服务执行登出逻辑，将令牌加入黑名单
    AuthService::logout(&state, token).await?;

    // 返回登出成功的消息
    Ok(ApiResponse::<()>::with_message("Logged out successfully"))
}