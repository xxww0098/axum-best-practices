use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Res<T> {
    pub code: u16,
    pub msg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

impl<T> Res<T>
where
    T: Serialize,
{
    pub fn with_data(data: T) -> Self {
        Self {
            code: StatusCode::OK.as_u16(),
            msg: "success".to_string(),
            data: Some(data),
        }
    }

    pub fn with_code(code: StatusCode, msg: &str, data: Option<T>) -> Self {
        Self {
            code: code.as_u16(),
            msg: msg.to_string(),
            data,
        }
    }
}

impl Res<()> {
    pub fn with_msg(msg: &str) -> Self {
        Self {
            code: StatusCode::OK.as_u16(),
            msg: msg.to_string(),
            data: None,
        }
    }

    pub fn with_error(code: StatusCode, msg: &str) -> Self {
        Self {
            code: code.as_u16(),
            msg: msg.to_string(),
            data: None,
        }
    }
}

impl<T> IntoResponse for Res<T>
where
    T: Serialize,
{
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(self)).into_response()
    }
}