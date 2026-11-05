//! Local x402 v2 `/verify` for exact EIP-3009 on Base mainnet.
//!
//! Spec: coinbase/x402 `specs/x402-specification-v2.md` section 7.1 and
//! `specs/schemes/exact/scheme_exact_evm.md` (EIP-3009). This path is
//! read-only: it does not write the payment store, mark a payment settled,
//! or submit a transaction.

use serde_json::{json, Value};

use crate::chain::{
    recover_signer, signing_digest, to_checksum, Authorization, BaseRpc, ChainError, EIP712_NAME,
    EIP712_VERSION, NETWORK, USDC_ADDRESS,
};

pub const INVALID_PAYLOAD: &str = "invalid_payload";
pub const INVALID_X402_VERSION: &str = "invalid_x402_version";
pub const INVALID_SCHEME: &str = "invalid_scheme";
pub const INVALID_NETWORK: &str = "invalid_network";
pub const INVALID_PAYMENT_REQUIREMENTS: &str = "invalid_payment_requirements";
pub const INVALID_SIGNATURE: &str = "invalid_exact_evm_payload_signature";
pub const INVALID_RECIPIENT: &str = "invalid_exact_evm_payload_recipient_mismatch";
pub const INVALID_VALUE: &str = "invalid_exact_evm_payload_authorization_value_mismatch";
pub const INVALID_VALID_AFTER: &str = "invalid_exact_evm_payload_authorization_valid_after";
pub const INVALID_VALID_BEFORE: &str = "invalid_exact_evm_payload_authorization_valid_before";
/// Reference facilitator code for a used EIP-3009 nonce. The v2 spec lists
/// no separate reason for this case (`go/mechanisms/evm/exact/facilitator`).
pub const NONCE_ALREADY_USED: &str = "invalid_exact_evm_nonce_already_used";
/// x402 v2 section 9. The verify example uses this code when the payer cannot cover `amount`.
pub const INSUFFICIENT_FUNDS: &str = "insufficient_funds";
/// Reference facilitator code when `eth_call` of `transferWithAuthorization` reverts.
pub const SIMULATION_FAILED: &str = "invalid_exact_evm_transaction_simulation_failed";
pub const UNEXPECTED: &str = "unexpected_verify_error";

/// Reference facilitator buffer: `validBefore` must be at least this many seconds
/// ahead of now, or the authorization is treated as expired.
pub(crate) const MIN_VALID_BEFORE_LEAD: u64 = 6;

const SCHEME: &str = "exact";
const TRANSFER_METHOD: &str = "eip3009";
const PAYMENT_FLOW: &str = "authorization";

struct Terms {
    scheme: String,
    network: String,
    amount: [u8; 32],
    asset: [u8; 20],
    pay_to: [u8; 20],
    max_timeout: u64,
    name: String,
    version: String,
    transfer_method: Option<String>,
    payment_flow: Option<String>,
}

pub(crate) struct Checked {
    pub(crate) authorization: Authorization,
    pub(crate) signature: [u8; 65],
    pub(crate) payer: String,
}

pub async fn verify_body(body: &Value, now: u64, rpc: Option<&BaseRpc>) -> Value {
    match authorize(body, now, rpc).await {
        Ok(checked) => valid(checked.payer),
        Err((reason, payer)) => invalid(reason, payer),
    }
}

/// Local and read-only checks shared by `/verify` and `/settle`.
pub(crate) async fn authorize(
    body: &Value,
    now: u64,
    rpc: Option<&BaseRpc>,
) -> Result<Checked, (String, Option<String>)> {
    let checked = accept_local(body, now)?;
    accept_chain(checked, rpc).await
}

/// Parse, time window, and EIP-712 recovery. No RPC and no payment row.
pub(crate) fn accept_local(body: &Value, now: u64) -> Result<Checked, (String, Option<String>)> {
    admit(body, now, true)
}

/// Structural checks and EIP-712 recovery without the `validBefore` lead.
/// This only identifies a settlement that was already signed and stored.
/// It does not authorize a new relayer signature.
pub(crate) fn accept_replay(body: &Value) -> Result<Checked, (String, Option<String>)> {
    admit(body, 0, false)
}

fn admit(body: &Value, now: u64, window: bool) -> Result<Checked, (String, Option<String>)> {
    let checked = check_local(body, now, window)?;
    let digest = signing_digest(&checked.authorization);
    match recover_signer(&digest, &checked.signature) {
        Ok(signer) if signer == checked.authorization.from => Ok(checked),
        _ => Err(fail(INVALID_SIGNATURE, Some(checked.payer))),
    }
}

/// `authorizationState`, `balanceOf`, and transfer simulation.
pub(crate) async fn accept_chain(
    checked: Checked,
    rpc: Option<&BaseRpc>,
) -> Result<Checked, (String, Option<String>)> {
    let Some(rpc) = rpc else {
        return Err(fail(UNEXPECTED, Some(checked.payer)));
    };
    match rpc
        .authorization_used(checked.authorization.from, checked.authorization.nonce)
        .await
    {
        Ok(true) => return Err(fail(NONCE_ALREADY_USED, Some(checked.payer))),
        Ok(false) => {}
        Err(_) => {
            tracing::warn!("authorizationState eth_call failed");
            return Err(fail(UNEXPECTED, Some(checked.payer)));
        }
    }
    let balance = match rpc.balance_of(checked.authorization.from).await {
        Ok(balance) => balance,
        Err(_) => {
            tracing::warn!("balanceOf eth_call failed");
            return Err(fail(UNEXPECTED, Some(checked.payer)));
        }
    };
    if balance < checked.authorization.value {
        return Err(fail(INSUFFICIENT_FUNDS, Some(checked.payer)));
    }
    match rpc
        .simulate_transfer(&checked.authorization, &checked.signature)
        .await
    {
        Ok(()) => Ok(checked),
        Err(ChainError::Reverted) => Err(fail(SIMULATION_FAILED, Some(checked.payer))),
        Err(_) => {
            tracing::warn!("transferWithAuthorization eth_call failed");
            Err(fail(UNEXPECTED, Some(checked.payer)))
        }
    }
}

fn check_local(body: &Value, now: u64, window: bool) -> Result<Checked, (String, Option<String>)> {
    let root = body
        .as_object()
        .ok_or_else(|| fail(INVALID_PAYLOAD, None))?;
    require_version(root.get("x402Version"))?;

    let payload = object_field(root.get("paymentPayload"), INVALID_PAYLOAD)?;
    require_version(payload.get("x402Version"))?;
    if let Some(resource) = payload.get("resource") {
        if !resource.is_object() {
            return Err(fail(INVALID_PAYLOAD, None));
        }
    }
    if let Some(extensions) = payload.get("extensions") {
        if !extensions.is_object() {
            return Err(fail(INVALID_PAYLOAD, None));
        }
    }

    let accepted = parse_terms(object_field(payload.get("accepted"), INVALID_PAYLOAD)?)?;
    let requirements = parse_terms(object_field(
        root.get("paymentRequirements"),
        INVALID_PAYMENT_REQUIREMENTS,
    )?)?;
    if !same_terms(&accepted, &requirements) {
        return Err(fail(INVALID_PAYMENT_REQUIREMENTS, None));
    }
    if accepted.scheme != SCHEME {
        return Err(fail(INVALID_SCHEME, None));
    }
    if accepted.network != NETWORK {
        return Err(fail(INVALID_NETWORK, None));
    }
    if accepted.asset != USDC_ADDRESS
        || accepted.name != EIP712_NAME
        || accepted.version != EIP712_VERSION
        || accepted.amount == [0u8; 32]
        || accepted.pay_to == [0u8; 20]
        || accepted.max_timeout == 0
    {
        return Err(fail(INVALID_PAYMENT_REQUIREMENTS, None));
    }
    if accepted
        .transfer_method
        .as_deref()
        .unwrap_or(TRANSFER_METHOD)
        != TRANSFER_METHOD
        || accepted.payment_flow.as_deref().unwrap_or(PAYMENT_FLOW) != PAYMENT_FLOW
    {
        return Err(fail(INVALID_PAYMENT_REQUIREMENTS, None));
    }

    let exact = object_field(payload.get("payload"), INVALID_PAYLOAD)?;
    let authorization = object_field(exact.get("authorization"), INVALID_PAYLOAD)?;
    let from = parse_address(required_str(authorization.get("from"))?)
        .map_err(|_| fail(INVALID_PAYLOAD, None))?;
    let payer = to_checksum(&from);
    let to = parse_address(required_str(authorization.get("to"))?)
        .map_err(|_| fail(INVALID_PAYLOAD, Some(payer.clone())))?;
    let value = parse_u256(required_str(authorization.get("value"))?)
        .ok_or_else(|| fail(INVALID_PAYLOAD, Some(payer.clone())))?;
    let valid_after = parse_u256(required_str(authorization.get("validAfter"))?)
        .ok_or_else(|| fail(INVALID_PAYLOAD, Some(payer.clone())))?;
    let valid_before = parse_u256(required_str(authorization.get("validBefore"))?)
        .ok_or_else(|| fail(INVALID_PAYLOAD, Some(payer.clone())))?;
    let nonce = parse_bytes32(required_str(authorization.get("nonce"))?)
        .ok_or_else(|| fail(INVALID_PAYLOAD, Some(payer.clone())))?;
    let signature = parse_signature(required_str(exact.get("signature"))?)
        .ok_or_else(|| fail(INVALID_SIGNATURE, Some(payer.clone())))?;

    if to != accepted.pay_to {
        return Err(fail(INVALID_RECIPIENT, Some(payer)));
    }
    if value != accepted.amount {
        return Err(fail(INVALID_VALUE, Some(payer)));
    }
    if valid_after >= valid_before {
        return Err(fail(INVALID_PAYLOAD, Some(payer)));
    }
    if window {
        let now_word = u64_word(now);
        if valid_after >= now_word {
            return Err(fail(INVALID_VALID_AFTER, Some(payer)));
        }
        // Circle requires `now < validBefore`. The reference facilitator also rejects
        // a deadline closer than 6 seconds. The v2 spec defines `maxTimeoutSeconds`
        // as the maximum completion time, and clients set `validBefore = now + maxTimeoutSeconds`,
        // so a later deadline does not meet the requirement.
        let earliest = u64_word(now.saturating_add(MIN_VALID_BEFORE_LEAD));
        let latest = u64_word(now.saturating_add(accepted.max_timeout));
        if valid_before < earliest || valid_before > latest {
            return Err(fail(INVALID_VALID_BEFORE, Some(payer)));
        }
    }

    Ok(Checked {
        authorization: Authorization {
            from,
            to,
            value,
            valid_after,
            valid_before,
            nonce,
        },
        signature,
        payer,
    })
}

fn parse_terms(value: &serde_json::Map<String, Value>) -> Result<Terms, (String, Option<String>)> {
    let extra = object_field(value.get("extra"), INVALID_PAYMENT_REQUIREMENTS)?;
    let name = required_str(extra.get("name"))?.to_string();
    let version = required_str(extra.get("version"))?.to_string();
    if name.is_empty() || version.is_empty() {
        return Err(fail(INVALID_PAYMENT_REQUIREMENTS, None));
    }
    Ok(Terms {
        scheme: required_str(value.get("scheme"))?.to_string(),
        network: required_str(value.get("network"))?.to_string(),
        amount: parse_u256(required_str(value.get("amount"))?)
            .ok_or_else(|| fail(INVALID_PAYMENT_REQUIREMENTS, None))?,
        asset: parse_address(required_str(value.get("asset"))?)
            .map_err(|_| fail(INVALID_PAYMENT_REQUIREMENTS, None))?,
        pay_to: parse_address(required_str(value.get("payTo"))?)
            .map_err(|_| fail(INVALID_PAYMENT_REQUIREMENTS, None))?,
        max_timeout: required_u64(value.get("maxTimeoutSeconds"))?,
        name,
        version,
        transfer_method: optional_string(extra.get("assetTransferMethod"))?,
        payment_flow: optional_string(extra.get("paymentFlow"))?,
    })
}

fn same_terms(left: &Terms, right: &Terms) -> bool {
    left.scheme == right.scheme
        && left.network == right.network
        && left.amount == right.amount
        && left.asset == right.asset
        && left.pay_to == right.pay_to
        && left.max_timeout == right.max_timeout
        && left.name == right.name
        && left.version == right.version
        && left.transfer_method == right.transfer_method
        && left.payment_flow == right.payment_flow
}

fn require_version(value: Option<&Value>) -> Result<(), (String, Option<String>)> {
    match value.and_then(Value::as_u64) {
        Some(2) => Ok(()),
        Some(_) => Err(fail(INVALID_X402_VERSION, None)),
        None => Err(fail(INVALID_PAYLOAD, None)),
    }
}

fn object_field<'a>(
    value: Option<&'a Value>,
    reason: &str,
) -> Result<&'a serde_json::Map<String, Value>, (String, Option<String>)> {
    value
        .and_then(Value::as_object)
        .ok_or_else(|| fail(reason, None))
}

fn required_str(value: Option<&Value>) -> Result<&str, (String, Option<String>)> {
    value
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| fail(INVALID_PAYLOAD, None))
}

fn required_u64(value: Option<&Value>) -> Result<u64, (String, Option<String>)> {
    value
        .and_then(Value::as_u64)
        .ok_or_else(|| fail(INVALID_PAYMENT_REQUIREMENTS, None))
}

fn optional_string(value: Option<&Value>) -> Result<Option<String>, (String, Option<String>)> {
    match value {
        None => Ok(None),
        Some(Value::String(s)) if !s.is_empty() => Ok(Some(s.clone())),
        _ => Err(fail(INVALID_PAYMENT_REQUIREMENTS, None)),
    }
}

fn parse_address(value: &str) -> Result<[u8; 20], ()> {
    let hex = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .ok_or(())?;
    if hex.len() != 40 {
        return Err(());
    }
    let bytes = decode_hex(hex).ok_or(())?;
    let mut address = [0u8; 20];
    address.copy_from_slice(&bytes);
    Ok(address)
}

fn parse_bytes32(value: &str) -> Option<[u8; 32]> {
    let hex = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))?;
    if hex.len() != 64 {
        return None;
    }
    let bytes = decode_hex(hex)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn parse_signature(value: &str) -> Option<[u8; 65]> {
    let hex = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))?;
    if hex.len() != 130 {
        return None;
    }
    let bytes = decode_hex(hex)?;
    let mut out = [0u8; 65];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn parse_u256(value: &str) -> Option<[u8; 32]> {
    if value.is_empty() || value.len() > 78 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if value.len() > 1 && value.starts_with('0') {
        return None;
    }
    let mut out = [0u8; 32];
    for byte in value.bytes() {
        let mut carry = (byte - b'0') as u16;
        for slot in out.iter_mut().rev() {
            let next = u16::from(*slot) * 10 + carry;
            *slot = (next & 0xff) as u8;
            carry = next >> 8;
        }
        if carry != 0 {
            return None;
        }
    }
    Some(out)
}

fn u64_word(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        out.push((hex_val(bytes[i])? << 4) | hex_val(bytes[i + 1])?);
        i += 2;
    }
    Some(out)
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn fail(reason: &str, payer: Option<String>) -> (String, Option<String>) {
    (reason.to_string(), payer)
}

fn invalid(reason: impl Into<String>, payer: Option<String>) -> Value {
    let mut body = json!({
        "isValid": false,
        "invalidReason": reason.into(),
    });
    if let Some(payer) = payer {
        body["payer"] = json!(payer);
    }
    body
}

fn valid(payer: String) -> Value {
    json!({
        "isValid": true,
        "payer": payer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{
        signing_digest, test_address, test_sign, to_checksum, Authorization, BaseRpc, USDC_ADDRESS,
    };
    use axum::routing::post;
    use axum::{Json, Router};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const NOW: u64 = 1_700_000_000;

    #[derive(Clone, Copy)]
    enum Mock {
        Ready,
        NonceUsed,
        InsufficientBalance,
        SimulationReverts,
        BalanceRpcError,
    }

    #[tokio::test]
    async fn valid_authorization_is_accepted_only_when_unused() {
        let (body, payer) = signed_body(0, NOW + 30, "10000", None);
        let (rpc, calls) = mock_rpc(Mock::Ready).await;
        let response = verify_body(&body, NOW, Some(&rpc)).await;
        assert_eq!(response["isValid"], true);
        assert_eq!(response["payer"], payer);
        assert!(response.get("invalidReason").is_none());
        assert!(response.get("success").is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn used_nonce_is_rejected_and_not_settled() {
        let (body, payer) = signed_body(0, NOW + 30, "10000", None);
        let (rpc, _) = mock_rpc(Mock::NonceUsed).await;
        let response = verify_body(&body, NOW, Some(&rpc)).await;
        assert_eq!(response["isValid"], false);
        assert_eq!(response["invalidReason"], NONCE_ALREADY_USED);
        assert_eq!(response["payer"], payer);
        assert!(response.get("success").is_none());
    }

    #[tokio::test]
    async fn missing_rpc_does_not_accept_a_valid_signature() {
        let (body, _) = signed_body(0, NOW + 30, "10000", None);
        let response = verify_body(&body, NOW, None).await;
        assert_eq!(response["isValid"], false);
        assert_eq!(response["invalidReason"], UNEXPECTED);
    }

    #[tokio::test]
    async fn not_yet_valid_and_expired_signatures_are_rejected() {
        let (early, _) = signed_body(NOW, NOW + 60, "10000", None);
        let early = verify_body(&early, NOW, None).await;
        assert_eq!(early["invalidReason"], INVALID_VALID_AFTER);

        let (late, _) = signed_body(0, NOW, "10000", None);
        let late = verify_body(&late, NOW, None).await;
        assert_eq!(late["invalidReason"], INVALID_VALID_BEFORE);
    }

    #[tokio::test]
    async fn timeout_window_must_fit_max_timeout_and_settlement_lead() {
        let (too_long, _) = signed_body(0, NOW + 120, "10000", None);
        let too_long = verify_body(&too_long, NOW, None).await;
        assert_eq!(too_long["invalidReason"], INVALID_VALID_BEFORE);
        assert_eq!(too_long["isValid"], false);

        let (too_soon, _) = signed_body(0, NOW + 5, "10000", None);
        let too_soon = verify_body(&too_soon, NOW, None).await;
        assert_eq!(too_soon["invalidReason"], INVALID_VALID_BEFORE);
    }

    #[tokio::test]
    async fn insufficient_balance_is_rejected_before_simulation() {
        let (body, payer) = signed_body(0, NOW + 30, "10000", None);
        let (rpc, calls) = mock_rpc(Mock::InsufficientBalance).await;
        let response = verify_body(&body, NOW, Some(&rpc)).await;
        assert_eq!(response["isValid"], false);
        assert_eq!(response["invalidReason"], INSUFFICIENT_FUNDS);
        assert_eq!(response["payer"], payer);
        assert!(response.get("success").is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn failed_transfer_simulation_is_not_a_transport_error() {
        let (body, _) = signed_body(0, NOW + 30, "10000", None);
        let (rpc, calls) = mock_rpc(Mock::SimulationReverts).await;
        let response = verify_body(&body, NOW, Some(&rpc)).await;
        assert_eq!(response["isValid"], false);
        assert_eq!(response["invalidReason"], SIMULATION_FAILED);
        assert!(response.get("success").is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn balance_rpc_error_is_fail_closed() {
        let (body, _) = signed_body(0, NOW + 30, "10000", None);
        let (rpc, _) = mock_rpc(Mock::BalanceRpcError).await;
        let response = verify_body(&body, NOW, Some(&rpc)).await;
        assert_eq!(response["isValid"], false);
        assert_eq!(response["invalidReason"], UNEXPECTED);
        assert!(response.get("success").is_none());
    }

    #[tokio::test]
    async fn rpc_failure_is_fail_closed() {
        let (body, _) = signed_body(0, NOW + 30, "10000", None);
        let rpc = BaseRpc::connect("http://127.0.0.1:1").unwrap();
        let response = verify_body(&body, NOW, Some(&rpc)).await;
        assert_eq!(response["isValid"], false);
        assert_eq!(response["invalidReason"], UNEXPECTED);
        assert!(response.get("success").is_none());
    }

    fn signed_body(
        valid_after: u64,
        valid_before: u64,
        amount: &str,
        value_override: Option<&str>,
    ) -> (Value, String) {
        let secret = [0x42u8; 32];
        let from = test_address(&secret);
        let to = [0x22u8; 20];
        let nonce = [0xabu8; 32];
        let value = parse_u256(value_override.unwrap_or(amount)).unwrap();
        let auth = Authorization {
            from,
            to,
            value,
            valid_after: u64_word(valid_after),
            valid_before: u64_word(valid_before),
            nonce,
        };
        let signature = test_sign(&secret, &signing_digest(&auth));
        let payer = to_checksum(&from);
        let pay_to = to_checksum(&to);
        let body = json!({
            "x402Version": 2,
            "paymentPayload": {
                "x402Version": 2,
                "accepted": terms(&pay_to, amount),
                "payload": {
                    "signature": format!("0x{}", hex_encode(&signature)),
                    "authorization": {
                        "from": payer,
                        "to": pay_to,
                        "value": value_override.unwrap_or(amount),
                        "validAfter": valid_after.to_string(),
                        "validBefore": valid_before.to_string(),
                        "nonce": format!("0x{}", hex_encode(&nonce))
                    }
                }
            },
            "paymentRequirements": terms(&pay_to, amount)
        });
        (body, payer)
    }

    fn terms(pay_to: &str, amount: &str) -> Value {
        json!({
            "scheme": "exact",
            "network": NETWORK,
            "amount": amount,
            "asset": to_checksum(&USDC_ADDRESS),
            "payTo": pay_to,
            "maxTimeoutSeconds": 60,
            "extra": { "name": EIP712_NAME, "version": EIP712_VERSION }
        })
    }

    async fn mock_rpc(mode: Mock) -> (BaseRpc, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let app = Router::new().route(
            "/",
            post(move |Json(request): Json<Value>| {
                let seen = seen.clone();
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(request["method"], "eth_call");
                    assert_ne!(request["method"], "eth_sendRawTransaction");
                    let data = request["params"][0]["data"].as_str().unwrap_or("");
                    let state = hex_prefix(crate::chain::authorization_state_selector());
                    let balance = hex_prefix(crate::chain::balance_of_selector());
                    let transfer = hex_prefix(crate::chain::transfer_with_authorization_selector());
                    if data.starts_with(&state) {
                        let used = matches!(mode, Mock::NonceUsed);
                        let word = if used {
                            format!("0x{}1", "0".repeat(63))
                        } else {
                            format!("0x{}", "0".repeat(64))
                        };
                        return Json(json!({"jsonrpc": "2.0", "id": 1, "result": word}));
                    }
                    if data.starts_with(&balance) {
                        if matches!(mode, Mock::BalanceRpcError) {
                            return Json(json!({
                                "jsonrpc": "2.0",
                                "id": 1,
                                "error": { "code": -32000, "message": "unavailable" }
                            }));
                        }
                        let word = if matches!(mode, Mock::InsufficientBalance) {
                            format!("0x{}", "0".repeat(64))
                        } else {
                            format!("0x{}2710", "0".repeat(60))
                        };
                        return Json(json!({"jsonrpc": "2.0", "id": 1, "result": word}));
                    }
                    if data.starts_with(&transfer) {
                        if matches!(mode, Mock::SimulationReverts) {
                            return Json(json!({
                                "jsonrpc": "2.0",
                                "id": 1,
                                "error": { "code": 3, "message": "execution reverted" }
                            }));
                        }
                        return Json(json!({"jsonrpc": "2.0", "id": 1, "result": "0x"}));
                    }
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "error": { "code": -32602, "message": "unexpected call" }
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let url = format!("http://{address}");
        let probe = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(200))
            .build()
            .unwrap();
        for _ in 0..50 {
            if probe.get(&url).send().await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let rpc = BaseRpc::connect(&url).unwrap();
        (rpc, calls)
    }

    fn hex_prefix(selector: [u8; 4]) -> String {
        format!("0x{}", hex_encode(&selector))
    }

    fn hex_encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }
}
