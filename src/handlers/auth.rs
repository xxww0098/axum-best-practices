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
        response::Res,
    },
    services::auth as AuthService,
    state::AppState,
    rate_limit, // 引入限流宏，用于在关键操作（如注册、登录）前检查请求频率，防止滥用。
};

/// 用户注册处理器。这个函数处理 HTTP POST 请求，接收用户注册信息，
/// 验证输入数据，检查请求频率限制，然后调用认证服务创建新用户。
///
/// # 参数
/// - `state`: 应用程序状态，包含数据库连接、Redis 客户端等共享资源。
/// - `payload`: 注册请求数据，包含用户名、密码、邮箱等信息，使用 JSON 格式传输。
///
/// # 返回值
/// - `Ok(impl IntoResponse)`: 成功时返回 HTTP 201 Created 状态码和成功消息。
/// - `Err(AppError)`: 失败时返回相应的错误，如输入验证失败、限流触发、用户已存在等。
pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;
    
    rate_limit!(&state.redis, "register", &payload.username, 5, 60);

    AuthService::register(&state, payload).await?;

    Ok(Res::<()>::with_code(
        axum::http::StatusCode::CREATED,
        "User registered successfully",
        None,
    ))
}

/// 用户登录处理器。这个函数处理 HTTP POST 请求，接收用户登录凭证（用户名/邮箱和密码），
/// 验证输入数据，检查请求频率限制，然后调用认证服务进行身份验证。
/// 验证成功后返回访问令牌（Access Token）和刷新令牌（Refresh Token）。
///
/// # 参数
/// - `state`: 应用程序状态，包含数据库连接、Redis 客户端等共享资源。
/// - `payload`: 登录请求数据，包含用户账户标识和密码，使用 JSON 格式传输。
///
/// # 返回值
/// - `Ok(impl IntoResponse)`: 成功时返回包含令牌信息的 JSON 响应。
/// - `Err(AppError)`: 失败时返回相应的错误，如输入验证失败、限流触发、密码错误等。
pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;
    
    rate_limit!(&state.redis, "login", &payload.account, 10, 60);

    let response = AuthService::login(&state, payload).await?;

    Ok(Res::with_data(response))
}

/// 令牌刷新处理器。这个函数处理 HTTP POST 请求，接收有效的刷新令牌（Refresh Token），
/// 调用认证服务生成新的访问令牌（Access Token）和刷新令牌（Refresh Token）。
/// 注意：刷新令牌只能使用一次，使用后会立即失效，防止令牌重用攻击。
///
/// # 参数
/// - `state`: 应用程序状态，包含数据库连接、Redis 客户端等共享资源。
/// - `payload`: 刷新请求数据，包含当前有效的刷新令牌，使用 JSON 格式传输。
///
/// # 返回值
/// - `Ok(impl IntoResponse)`: 成功时返回包含新令牌信息的 JSON 响应。
/// - `Err(AppError)`: 失败时返回相应的错误，如令牌无效、已使用、过期等。
pub async fn refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshRequest>,
) -> Result<impl IntoResponse, AppError> {
    // 刷新逻辑内部已经实现了限流检查，这里不需要再次添加限流。
    // 这是为了防止令牌刷新操作被滥用，同时避免在处理器层重复限流。
    let response = AuthService::refresh(&state, payload.refresh_token).await?;
    Ok(Res::with_data(response))
}

/// 用户登出处理器。这个函数处理 HTTP POST 请求，从 Authorization 头部提取 Bearer 令牌，
/// 调用认证服务将令牌加入黑名单，使该令牌失效，无法再用于访问受保护资源。
///
/// # 参数
/// - `state`: 应用程序状态，包含数据库连接、Redis 客户端等共享资源。
/// - `TypedHeader(Authorization(bearer))`: 从 HTTP Authorization 头部提取的 Bearer 令牌。
///   如果请求中没有提供有效的 Authorization 头部，框架会自动返回 401 Unauthorized 错误。
///
/// # 返回值
/// - `Ok(impl IntoResponse)`: 成功时返回登出成功消息。
/// - `Err(AppError)`: 失败时返回相应的错误，如令牌格式无效、服务调用失败等。
pub async fn logout(
    State(state): State<AppState>,
    // 直接提取 Bearer Token，使用 TypedHeader 提取器。如果请求中没有 Authorization 头部，
    // 或者头部格式不正确，Axum 框架会自动返回 401 Unauthorized 错误，这符合 API 设计的预期行为。
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse, AppError> {
    
    let token = bearer.token();
    AuthService::logout(&state, token).await?;

    Ok(Res::<()>::with_msg("Logged out successfully"))
}