// src/dtos/response.rs
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

/// 统一的API响应格式。所有API端点都使用这个结构体返回响应，
/// 确保响应格式的一致性。
///
/// # 字段说明
/// - `code`: HTTP状态码（如200、400、401、404、500等）
/// - `message`: 响应消息，描述请求的处理结果
/// - `data`: 响应数据，泛型类型T可以是任意可序列化的类型。使用Option包装，
///   当无数据时该字段不会被序列化到JSON中
#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub code: u16,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

impl<T> ApiResponse<T>
where
    T: Serialize,
{
    /// 创建一个成功响应，携带数据。返回200状态码和"success"消息。
    ///
    /// # 参数
    /// - `data`: 要返回的数据
    pub fn with_data(data: T) -> Self {
        Self {
            code: StatusCode::OK.as_u16(),
            message: "success".to_string(),
            data: Some(data),
        }
    }

    /// 创建一个自定义响应，允许指定状态码、消息和数据。
    ///
    /// # 参数
    /// - `code`: HTTP状态码
    /// - `message`: 响应消息
    /// - `data`: 可选的响应数据
    pub fn with_code(code: StatusCode, message: &str, data: Option<T>) -> Self {
        Self {
            code: code.as_u16(),
            message: message.to_string(),
            data,
        }
    }
}

// 为 `ApiResponse<()>` 类型提供特定的构造方法，用于不需要返回数据的场景（如删除操作）
impl ApiResponse<()> {
    /// 创建一个成功响应，只返回消息，不携带数据。
    ///
    /// # 参数
    /// - `message`: 响应消息
    pub fn with_message(message: &str) -> Self {
        Self {
            code: StatusCode::OK.as_u16(),
            message: message.to_string(),
            data: None,
        }
    }

    /// 创建一个错误响应。
    ///
    /// # 参数
    /// - `code`: HTTP错误状态码
    /// - `message`: 错误消息
    pub fn with_error(code: StatusCode, message: &str) -> Self {
        Self {
            code: code.as_u16(),
            message: message.to_string(),
            data: None,
        }
    }
}

/// 实现 `IntoResponse` trait，将 `ApiResponse` 转换为HTTP响应。
///
/// 这个实现确保 `ApiResponse` 可以直接作为Axum处理器的返回值，
/// 自动序列化为JSON并设置正确的HTTP状态码。
impl<T> IntoResponse for ApiResponse<T>
where
    T: Serialize,
{
    fn into_response(self) -> Response {
        // 将 code 字段转换为 HTTP 状态码。
        // 如果转换失败（如无效的状态码），默认返回500 Internal Server Error。
        let status = StatusCode::from_u16(self.code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        // 将响应序列化为JSON，并与状态码一起返回
        (status, Json(self)).into_response()
    }
}