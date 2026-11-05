use axum::body::Body;
use axum::http::{Request, StatusCode};
use dcl_facilitator::api::{self, AppState};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

async fn post_fixture(name: &str) -> (StatusCode, Value) {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let raw = std::fs::read(path).unwrap();
    let response = api::router(AppState::without_rpc())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/verify")
                .header("content-type", "application/json")
                .body(Body::from(raw))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    (status, body)
}

#[tokio::test]
async fn fixtures_reject_without_calling_a_facilitator_or_reporting_success() {
    let cases = [
        ("verify_wrong_network.json", "invalid_network"),
        (
            "verify_amount_mismatch.json",
            "invalid_exact_evm_payload_authorization_value_mismatch",
        ),
        (
            "verify_expired.json",
            "invalid_exact_evm_payload_authorization_valid_before",
        ),
        (
            "verify_timeout_exceeded.json",
            "invalid_exact_evm_payload_authorization_valid_before",
        ),
        (
            "verify_bad_signature.json",
            "invalid_exact_evm_payload_signature",
        ),
    ];
    for (name, reason) in cases {
        let (status, body) = post_fixture(name).await;
        assert_eq!(status, StatusCode::OK, "{name}");
        assert_eq!(body["isValid"], false, "{name}: {body}");
        assert_eq!(body["invalidReason"], reason, "{name}: {body}");
        assert!(body.get("success").is_none(), "{name}");
    }
}
