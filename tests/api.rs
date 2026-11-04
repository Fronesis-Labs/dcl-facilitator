use axum::body::Body;
use axum::http::{Request, StatusCode};
use dcl_facilitator::api;
use http_body_util::BodyExt;
use tower::ServiceExt;

async fn call(method: &str, uri: &str) -> (StatusCode, String) {
    let response = api::router(api::AppState::without_rpc())
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

#[tokio::test]
async fn health_is_ok() {
    let (status, body) = call("GET", "/health").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("ok"));
}

#[tokio::test]
async fn supported_advertises_nothing_yet() {
    let (status, body) = call("GET", "/supported").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, r#"{"kinds":[]}"#);
}

/// An empty body is not a payment. Unconfigured settle cannot succeed.
#[tokio::test]
async fn empty_verify_is_invalid_and_settle_cannot_succeed() {
    let (status, body) = call("POST", "/verify").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("\"isValid\":false"), "{body}");
    assert!(!body.contains("\"isValid\":true"), "{body}");
    assert!(!body.contains("success"), "{body}");

    let (status, body) = call("POST", "/settle").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("\"success\":false"), "{body}");
    assert!(!body.contains("\"success\":true"), "{body}");
    assert!(!body.contains("isValid"), "{body}");
}
