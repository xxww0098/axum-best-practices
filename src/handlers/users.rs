use axum::{extract::{State, Json}, response::IntoResponse};
use validator::Validate;

use crate::{
    core::error::AppError,
    dtos::{auth::Claims, user::UpdateUserRequest, response::Res},
    services::user as UserService,
    state::AppState,
    rate_limit, // ✨ 引入限流宏，用于在用户信息读取和更新操作前检查请求频率，防止过度请求。
};

/// 获取当前用户信息处理器。这个函数处理 HTTP GET 请求，返回当前已认证用户的详细资料。
/// 函数通过 Claims 提取器自动获取当前用户的身份信息，确保只有已登录用户才能访问。
/// 包含请求频率限制，防止用户信息被过度查询。
///
/// # 参数
/// - `claims`: JWT 令牌中的声明信息，由 Claims 提取器自动注入，包含用户ID、角色等信息。
/// - `state`: 应用程序状态，包含数据库连接、Redis 客户端等共享资源。
///
/// # 返回值
/// - `Ok(impl IntoResponse)`: 成功时返回包含用户详细资料的 JSON 响应。
/// - `Err(AppError)`: 失败时返回相应的错误，如用户不存在、数据库查询失败、限流触发等。
pub async fn get_me(
    claims: Claims,
    State(state): State<AppState>
) -> Result<impl IntoResponse, AppError> {
    
    // 使用限流宏检查请求频率：每个用户每分钟最多访问 60 次。
    // 这是为了防止恶意用户频繁查询用户信息，保护系统资源和数据安全。
    rate_limit!(&state.redis, "read_me", &claims.sub, 60, 60);

    let profile = UserService::get_user_profile(&state, &claims.sub).await?;
    Ok(Res::with_data(profile))
}

/// 更新当前用户信息处理器。这个函数处理 HTTP PUT/PATCH 请求，更新当前已认证用户的信息。
/// 函数通过 Claims 提取器自动获取当前用户的身份信息，确保只有已登录用户才能更新自己的资料。
/// 包含输入验证和请求频率限制，确保数据安全和系统稳定。
///
/// # 参数
/// - `claims`: JWT 令牌中的声明信息，由 Claims 提取器自动注入，包含用户ID、角色等信息。
/// - `state`: 应用程序状态，包含数据库连接、Redis 客户端等共享资源。
/// - `payload`: 更新请求数据，包含需要修改的用户信息字段，使用 JSON 格式传输。
///
/// # 返回值
/// - `Ok(impl IntoResponse)`: 成功时返回包含更新后用户资料的 JSON 响应。
/// - `Err(AppError)`: 失败时返回相应的错误，如输入验证失败、数据库更新失败、限流触发等。
pub async fn update_me(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<UpdateUserRequest>,
) -> Result<impl IntoResponse, AppError> {
    
    // 使用 validator 库验证请求参数，确保输入数据符合业务规则和安全要求。
    // 例如，手机号格式、邮箱格式等验证，防止无效或恶意数据进入系统。
    payload.validate()?;

    rate_limit!(&state.redis, "update_me", &claims.sub, 10, 60);

    let profile = UserService::update_user_profile(&state, &claims.sub, payload).await?;
    Ok(Res::with_data(profile))
}