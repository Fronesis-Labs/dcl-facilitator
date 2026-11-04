//! JSON-RPC client for Base. Verification uses `eth_call` only.
//! Settlement adds chain id, gas, broadcast, and receipt reads.

use std::time::Duration;

use serde_json::{json, Value};

use super::eip3009::{
    authorization_state_calldata, balance_of_calldata, to_checksum, transfer_with_authorization_calldata,
    Authorization, ChainError, USDC_ADDRESS,
};

#[derive(Clone)]
pub struct BaseRpc {
    http: reqwest::Client,
    url: String,
}

impl BaseRpc {
    pub fn connect(url: &str) -> Result<Self, ChainError> {
        Self::connect_timeout(url, Duration::from_secs(10))
    }

    pub fn connect_timeout(url: &str, timeout: Duration) -> Result<Self, ChainError> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| ChainError::Rpc)?;
        Ok(Self {
            http,
            url: url.to_string(),
        })
    }

    /// `true` when Circle `authorizationState` says the nonce is used or canceled.
    pub async fn authorization_used(
        &self,
        authorizer: [u8; 20],
        nonce: [u8; 32],
    ) -> Result<bool, ChainError> {
        let result = self
            .eth_call(&authorization_state_calldata(authorizer, nonce))
            .await?;
        decode_bool_word(&result)
    }

    /// ERC-20 `balanceOf` for the payer. A revert is an RPC failure: USDC
    /// `balanceOf` does not revert on a normal account.
    pub async fn balance_of(&self, account: [u8; 20]) -> Result<[u8; 32], ChainError> {
        let result = self.eth_call(&balance_of_calldata(account)).await?;
        decode_uint256(&result)
    }

    /// Read-only simulation of `transferWithAuthorization`. A contract revert
    /// is [`ChainError::Reverted`]. A transport or decode failure is [`ChainError::Rpc`].
    pub async fn simulate_transfer(
        &self,
        authorization: &Authorization,
        signature: &[u8; 65],
    ) -> Result<(), ChainError> {
        let data = transfer_with_authorization_calldata(authorization, signature);
        let _ = self.eth_call(&data).await?;
        Ok(())
    }

    pub async fn chain_id(&self) -> Result<u64, ChainError> {
        let value = self.result("eth_chainId", json!([])).await?;
        parse_u64(value.as_str().ok_or(ChainError::Rpc)?)
    }

    pub async fn native_balance(&self, account: [u8; 20]) -> Result<[u8; 32], ChainError> {
        let value = self
            .result("eth_getBalance", json!([to_checksum(&account), "latest"]))
            .await?;
        parse_word(value.as_str().ok_or(ChainError::Rpc)?)
    }

    /// Next nonce, including transactions the node still has pending.
    pub async fn pending_nonce(&self, account: [u8; 20]) -> Result<u64, ChainError> {
        let value = self
            .result(
                "eth_getTransactionCount",
                json!([to_checksum(&account), "pending"]),
            )
            .await?;
        parse_u64(value.as_str().ok_or(ChainError::Rpc)?)
    }

    pub async fn estimate_gas(&self, from: [u8; 20], data: &[u8]) -> Result<u64, ChainError> {
        let value = self
            .result(
                "eth_estimateGas",
                json!([{
                    "from": to_checksum(&from),
                    "to": to_checksum(&USDC_ADDRESS),
                    "value": "0x0",
                    "data": format!("0x{}", hex_encode(data)),
                }]),
            )
            .await?;
        parse_u64(value.as_str().ok_or(ChainError::Rpc)?)
    }

    pub async fn max_priority_fee(&self) -> Result<u128, ChainError> {
        let value = self.result("eth_maxPriorityFeePerGas", json!([])).await?;
        parse_u128(value.as_str().ok_or(ChainError::Rpc)?)
    }

    pub async fn block(&self, id: &str) -> Result<RpcBlock, ChainError> {
        let value = self
            .result("eth_getBlockByNumber", json!([id, false]))
            .await?;
        let block = value.as_object().ok_or(ChainError::Rpc)?;
        let hash = parse_hash(required_str(block.get("hash"))?)?;
        let base_fee = match block.get("baseFeePerGas") {
            Some(fee) => Some(parse_u128(fee.as_str().ok_or(ChainError::Rpc)?)?),
            None => None,
        };
        Ok(RpcBlock { hash, base_fee })
    }

    pub async fn send_raw(&self, raw: &[u8]) -> Result<[u8; 32], ChainError> {
        let value = self
            .result(
                "eth_sendRawTransaction",
                json!([format!("0x{}", hex_encode(raw))]),
            )
            .await?;
        parse_hash(value.as_str().ok_or(ChainError::Rpc)?)
    }

    pub async fn transaction(&self, hash: [u8; 32]) -> Result<Option<RpcTransaction>, ChainError> {
        let value = self
            .result(
                "eth_getTransactionByHash",
                json!([format!("0x{}", hex_encode(&hash))]),
            )
            .await?;
        if value.is_null() {
            return Ok(None);
        }
        let tx = value.as_object().ok_or(ChainError::Rpc)?;
        let to = match tx.get("to") {
            Some(Value::Null) | None => None,
            Some(value) => Some(parse_address(value.as_str().ok_or(ChainError::Rpc)?)?),
        };
        Ok(Some(RpcTransaction {
            hash: parse_hash(required_str(tx.get("hash"))?)?,
            from: parse_address(required_str(tx.get("from"))?)?,
            to,
            nonce: parse_u64(required_str(tx.get("nonce"))?)?,
            value: parse_word(required_str(tx.get("value"))?)?,
            input: parse_bytes(required_str(tx.get("input"))?)?,
        }))
    }

    pub async fn receipt(&self, hash: [u8; 32]) -> Result<Option<RpcReceipt>, ChainError> {
        let value = self
            .result(
                "eth_getTransactionReceipt",
                json!([format!("0x{}", hex_encode(&hash))]),
            )
            .await?;
        if value.is_null() {
            return Ok(None);
        }
        let receipt = value.as_object().ok_or(ChainError::Rpc)?;
        let logs_value = receipt.get("logs").and_then(Value::as_array).ok_or(ChainError::Rpc)?;
        let mut logs = Vec::with_capacity(logs_value.len());
        for log in logs_value {
            let log = log.as_object().ok_or(ChainError::Rpc)?;
            let topics_value = log.get("topics").and_then(Value::as_array).ok_or(ChainError::Rpc)?;
            let mut topics = Vec::with_capacity(topics_value.len());
            for topic in topics_value {
                topics.push(parse_hash(topic.as_str().ok_or(ChainError::Rpc)?)?);
            }
            logs.push(RpcLog {
                address: parse_address(required_str(log.get("address"))?)?,
                topics,
                data: parse_bytes(required_str(log.get("data"))?)?,
                index: parse_u64(required_str(log.get("logIndex"))?)?,
            });
        }
        Ok(Some(RpcReceipt {
            hash: parse_hash(required_str(receipt.get("transactionHash"))?)?,
            status: parse_u64(required_str(receipt.get("status"))?)?,
            block_number: parse_u64(required_str(receipt.get("blockNumber"))?)?,
            block_hash: parse_hash(required_str(receipt.get("blockHash"))?)?,
            logs,
        }))
    }

    async fn result(&self, method: &str, params: Value) -> Result<Value, ChainError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let response = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|_| ChainError::Rpc)?;
        if !response.status().is_success() {
            return Err(ChainError::Rpc);
        }
        let payload: Value = response.json().await.map_err(|_| ChainError::Rpc)?;
        if payload.get("error").is_some() {
            return Err(ChainError::Rpc);
        }
        payload.get("result").cloned().ok_or(ChainError::Rpc)
    }

    async fn eth_call(&self, data: &[u8]) -> Result<String, ChainError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_call",
            "params": [
                {
                    "to": to_checksum(&USDC_ADDRESS),
                    "data": format!("0x{}", hex_encode(data))
                },
                "latest"
            ]
        });
        let response = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|_| ChainError::Rpc)?;
        if !response.status().is_success() {
            return Err(ChainError::Rpc);
        }
        let payload: Value = response.json().await.map_err(|_| ChainError::Rpc)?;
        if payload.get("error").is_some() {
            return Err(ChainError::Reverted);
        }
        payload
            .get("result")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or(ChainError::Rpc)
    }
}

pub struct RpcBlock {
    pub hash: [u8; 32],
    pub base_fee: Option<u128>,
}

pub struct RpcTransaction {
    pub hash: [u8; 32],
    pub from: [u8; 20],
    pub to: Option<[u8; 20]>,
    pub nonce: u64,
    pub value: [u8; 32],
    pub input: Vec<u8>,
}

pub struct RpcLog {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
    pub index: u64,
}

pub struct RpcReceipt {
    pub hash: [u8; 32],
    pub status: u64,
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub logs: Vec<RpcLog>,
}

fn required_str(value: Option<&Value>) -> Result<&str, ChainError> {
    value.and_then(Value::as_str).ok_or(ChainError::Rpc)
}

fn parse_u64(value: &str) -> Result<u64, ChainError> {
    let word = parse_word(value)?;
    if word[..24].iter().any(|byte| *byte != 0) {
        return Err(ChainError::Rpc);
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&word[24..]);
    Ok(u64::from_be_bytes(bytes))
}

fn parse_u128(value: &str) -> Result<u128, ChainError> {
    let word = parse_word(value)?;
    if word[..16].iter().any(|byte| *byte != 0) {
        return Err(ChainError::Rpc);
    }
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&word[16..]);
    Ok(u128::from_be_bytes(bytes))
}

fn parse_word(value: &str) -> Result<[u8; 32], ChainError> {
    let hex = strip_hex(value)?;
    if hex.len() > 64 {
        return Err(ChainError::Rpc);
    }
    let padded = if hex.len() % 2 == 1 {
        format!("0{hex}")
    } else {
        hex.to_string()
    };
    let bytes = hex_decode(&padded).ok_or(ChainError::Rpc)?;
    let mut word = [0u8; 32];
    word[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(word)
}

fn parse_hash(value: &str) -> Result<[u8; 32], ChainError> {
    let hex = strip_hex(value)?;
    if hex.len() != 64 {
        return Err(ChainError::Rpc);
    }
    let bytes = hex_decode(hex).ok_or(ChainError::Rpc)?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}

fn parse_address(value: &str) -> Result<[u8; 20], ChainError> {
    let hex = strip_hex(value)?;
    if hex.len() != 40 {
        return Err(ChainError::Rpc);
    }
    let bytes = hex_decode(hex).ok_or(ChainError::Rpc)?;
    let mut address = [0u8; 20];
    address.copy_from_slice(&bytes);
    Ok(address)
}

fn parse_bytes(value: &str) -> Result<Vec<u8>, ChainError> {
    let hex = strip_hex(value)?;
    if hex.len() % 2 != 0 {
        return Err(ChainError::Rpc);
    }
    hex_decode(hex).ok_or(ChainError::Rpc)
}

fn strip_hex(value: &str) -> Result<&str, ChainError> {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .ok_or(ChainError::Rpc)
}

fn decode_uint256(result: &str) -> Result<[u8; 32], ChainError> {
    let hex = result
        .strip_prefix("0x")
        .or_else(|| result.strip_prefix("0X"))
        .ok_or(ChainError::Rpc)?;
    if hex.is_empty() || hex.len() > 64 || hex.len() % 2 != 0 {
        return Err(ChainError::Rpc);
    }
    let bytes = hex_decode(hex).ok_or(ChainError::Rpc)?;
    let mut word = [0u8; 32];
    word[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(word)
}

fn decode_bool_word(result: &str) -> Result<bool, ChainError> {
    let hex = result
        .strip_prefix("0x")
        .or_else(|| result.strip_prefix("0X"))
        .ok_or(ChainError::Rpc)?;
    if hex.is_empty() || hex.len() > 64 || hex.len() % 2 != 0 {
        return Err(ChainError::Rpc);
    }
    let bytes = hex_decode(hex).ok_or(ChainError::Rpc)?;
    let mut word = [0u8; 32];
    word[32 - bytes.len()..].copy_from_slice(&bytes);
    if word[..31].iter().any(|byte| *byte != 0) {
        return Err(ChainError::Rpc);
    }
    match word[31] {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ChainError::Rpc),
    }
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

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::decode_bool_word;
    use crate::chain::ChainError;

    #[test]
    fn bool_word_is_strict() {
        let unused = format!("0x{}", "0".repeat(64));
        assert_eq!(decode_bool_word(&unused).unwrap(), false);
        let mut used = "0".repeat(63);
        used.push('1');
        assert_eq!(decode_bool_word(&format!("0x{used}")).unwrap(), true);
        assert!(matches!(
            decode_bool_word("0x02"),
            Err(ChainError::Rpc)
        ));
        assert!(decode_bool_word("0x").is_err());
    }
}
