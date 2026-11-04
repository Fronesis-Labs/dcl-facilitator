//! API error type. Every error is an explicit, non-success HTTP status.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("not implemented")]
    NotImplemented,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            ApiError::NotImplemented => (StatusCode::NOT_IMPLEMENTED, "not_implemented"),
        };
        (status, Json(json!({ "error": code }))).into_response()
    }
}
