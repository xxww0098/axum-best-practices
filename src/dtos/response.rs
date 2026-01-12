// src/dtos/response.rs
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

/// 统一 API 响应格式
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
    /// 成功响应 (200 OK)
    pub fn with_data(data: T) -> Self {
        Self {
            code: StatusCode::OK.as_u16(),
            message: "success".to_string(),
            data: Some(data),
        }
    }

    /// 自定义响应
    pub fn with_code(code: StatusCode, message: &str, data: Option<T>) -> Self {
        Self {
            code: code.as_u16(),
            message: message.to_string(),
            data,
        }
    }
}

impl ApiResponse<()> {
    /// 消息响应 (无数据)
    pub fn with_message(message: &str) -> Self {
        Self {
            code: StatusCode::OK.as_u16(),
            message: message.to_string(),
            data: None,
        }
    }

    /// 错误响应
    pub fn with_error(code: StatusCode, message: &str) -> Self {
        Self {
            code: code.as_u16(),
            message: message.to_string(),
            data: None,
        }
    }
}

/// 实现 IntoResponse，自动转换为 HTTP 响应
impl<T> IntoResponse for ApiResponse<T>
where
    T: Serialize,
{
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(self)).into_response()
    }
}
