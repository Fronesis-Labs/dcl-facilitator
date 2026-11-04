//! HTTP surface: /health, /supported, /verify, /settle.
//!
//! `/verify` is read-only. `/settle` broadcasts only a transaction that was
//! already stored. `/supported` stays empty until settlement is proven.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::rejection::JsonRejection;
use axum::extract::{Json, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Value};

use crate::chain::{BaseRpc, Relayer};
use crate::recover;
use crate::settle::{self, SettleEnv, UNEXPECTED_SETTLE};
use crate::store::Store;
use crate::verify::{self, INVALID_PAYLOAD, UNEXPECTED};

#[derive(Clone)]
pub struct AppState {
    rpc: Option<BaseRpc>,
    store: Option<Store>,
    relayer: Option<Relayer>,
    oracle: Option<[u8; 20]>,
    max_fee_per_gas: Option<u128>,
    receipt_timeout: Duration,
}

impl AppState {
    pub fn without_rpc() -> Self {
        Self::new(None, None, None, None, None, Duration::from_secs(20))
    }

    pub fn with_rpc(url: &str) -> Result<Self, std::io::Error> {
        BaseRpc::connect(url)
            .map(|rpc| Self::new(Some(rpc), None, None, None, None, Duration::from_secs(20)))
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "failed to build the Base RPC client",
                )
            })
    }

    pub fn new(
        rpc: Option<BaseRpc>,
        store: Option<Store>,
        relayer: Option<Relayer>,
        oracle: Option<[u8; 20]>,
        max_fee_per_gas: Option<u128>,
        receipt_timeout: Duration,
    ) -> Self {
        Self {
            rpc,
            store,
            relayer,
            oracle,
            max_fee_per_gas,
            receipt_timeout,
        }
    }

    fn settle_env(&self) -> Option<SettleEnv<'_>> {
        Some(SettleEnv {
            rpc: self.rpc.as_ref()?,
            store: self.store.as_ref()?,
            relayer: self.relayer.as_ref()?,
            oracle: self.oracle?,
            max_fee_per_gas: self.max_fee_per_gas?,
            receipt_timeout: self.receipt_timeout,
            stop: None,
        })
    }

    /// Starts the recovery worker when settle dependencies are configured.
    pub fn spawn_recovery(&self) -> Option<recover::Handle> {
        let rpc = self.rpc.clone()?;
        let store = self.store.clone()?;
        let relayer = self.relayer.clone()?;
        let oracle = self.oracle?;
        let max_fee_per_gas = self.max_fee_per_gas?;
        Some(recover::Handle::spawn(
            rpc,
            store,
            relayer,
            oracle,
            max_fee_per_gas,
            self.receipt_timeout,
            Arc::new(recover::unix_now),
        ))
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/supported", get(supported))
        .route("/verify", post(verify))
        .route("/settle", post(settle))
        .with_state(state)
}

/// Liveness only. TODO(M3): add a readiness check that exercises the RPC
/// provider and the store, so "ok" means the payment path can actually work.
async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

/// Advertises nothing until settlement exists. Verify is not a settlement offer.
async fn supported() -> Json<Value> {
    Json(json!({ "kinds": [] }))
}

async fn verify(
    State(state): State<AppState>,
    body: Result<Json<Value>, JsonRejection>,
) -> (StatusCode, Json<Value>) {
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => {
            return (
                StatusCode::OK,
                Json(json!({
                    "isValid": false,
                    "invalidReason": UNEXPECTED,
                })),
            );
        }
    };
    let response = match body {
        Ok(Json(value)) => verify::verify_body(&value, now, state.rpc.as_ref()).await,
        Err(_) => json!({
            "isValid": false,
            "invalidReason": INVALID_PAYLOAD,
        }),
    };
    let valid = response
        .get("isValid")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let reason = response
        .get("invalidReason")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    tracing::debug!(valid, reason, "verify");
    (StatusCode::OK, Json(response))
}

async fn settle(
    State(state): State<AppState>,
    body: Result<Json<Value>, JsonRejection>,
) -> (StatusCode, Json<Value>) {
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => return (StatusCode::OK, Json(settle::rejected(UNEXPECTED_SETTLE))),
    };
    let value = match body {
        Ok(Json(value)) => value,
        Err(_) => return (StatusCode::OK, Json(settle::rejected(INVALID_PAYLOAD))),
    };
    let Some(env) = state.settle_env() else {
        return (StatusCode::OK, Json(settle::rejected(UNEXPECTED_SETTLE)));
    };
    let response = settle::settle_body(&value, now, &env).await;
    let success = response
        .get("success")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let reason = response
        .get("errorReason")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    tracing::debug!(success, reason, "settle");
    (StatusCode::OK, Json(response))
}
