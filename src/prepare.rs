//! Offline `decisionEvidence` for an x402 v2 payment body.
//!
//! This builds the unsigned object `/settle` parses. It does not sign, and it
//! does not open a database, an RPC connection, or a relayer key.

use std::fmt;
use std::io::{self, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::evidence::{
    action_id_from_digest, hex_encode, unsigned_decision_evidence_value, DecisionBody,
    DecisionReason, EvidenceId, Verdict,
};
use crate::settle::{authorization_identity, payment_context, settlement_action};
use crate::verify;

/// Unsigned evidence plus the digest an Oracle signs. No signature is included.
pub struct UnsignedDecision {
    pub evidence: Value,
    pub decision_digest: [u8; 32],
}

#[derive(Debug)]
pub enum PrepareError {
    Usage,
    Payment(String),
    Reason,
    EvidenceId,
    Decision,
    Io,
    Time,
}

impl fmt::Display for PrepareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage => formatter.write_str(
                "usage: dcl-facilitator evidence --reason <text> [--verdict COMMIT|NO_COMMIT] [--evidence-id 0x<64 hex>] [--now <unix seconds>] [--body <file>]",
            ),
            Self::Payment(reason) => write!(formatter, "payment body was not accepted: {reason}"),
            Self::Reason => formatter.write_str("reason must be 1 to 1024 bytes"),
            Self::EvidenceId => formatter.write_str("evidence id must be 0x followed by 64 hex characters"),
            Self::Decision => formatter.write_str("could not build decision evidence"),
            Self::Io => formatter.write_str("could not read the payment body"),
            Self::Time => formatter.write_str("system time is unavailable"),
        }
    }
}

impl std::error::Error for PrepareError {}

struct Options {
    reason: String,
    verdict: Verdict,
    evidence_id: Option<[u8; 32]>,
    now: u64,
    body_path: Option<String>,
}

/// Build the unsigned `decisionEvidence` object from a payment body.
///
/// `evidence_id` defaults to the authorization nonce when omitted. The result
/// has no `signature` field.
pub fn prepare_decision(
    payment: &Value,
    now: u64,
    verdict: Verdict,
    reason: &str,
    evidence_id: Option<[u8; 32]>,
) -> Result<UnsignedDecision, PrepareError> {
    let checked = verify::accept_local(payment, now)
        .map_err(|(reason, _payer)| PrepareError::Payment(reason))?;
    let action = settlement_action(&checked);
    let context = payment_context(&checked).map_err(|()| PrepareError::Decision)?;
    let authorization = authorization_identity(&checked);
    let evidence_id = EvidenceId::new(evidence_id.unwrap_or(checked.authorization.nonce));
    let reason = DecisionReason::try_new(reason).map_err(|_| PrepareError::Reason)?;
    let action_id = action_id_from_digest(&action).map_err(|_| PrepareError::Decision)?;
    let body = DecisionBody::new(
        action_id,
        action,
        context,
        authorization,
        verdict,
        reason,
        evidence_id,
    )
    .map_err(|_| PrepareError::Decision)?;
    let decision_digest = body.decision_digest().map_err(|_| PrepareError::Decision)?;
    Ok(UnsignedDecision {
        evidence: unsigned_decision_evidence_value(&body),
        decision_digest,
    })
}

/// Read a payment body and write the unsigned evidence JSON to stdout.
pub fn write_evidence(args: &[String]) -> Result<(), PrepareError> {
    let options = parse_args(args)?;
    let raw = match &options.body_path {
        Some(path) => std::fs::read_to_string(path).map_err(|_| PrepareError::Io)?,
        None => {
            let mut raw = String::new();
            io::stdin()
                .read_to_string(&mut raw)
                .map_err(|_| PrepareError::Io)?;
            raw
        }
    };
    let payment: Value = serde_json::from_str(&raw)
        .map_err(|_| PrepareError::Payment("invalid_payload".to_string()))?;
    let prepared = prepare_decision(
        &payment,
        options.now,
        options.verdict,
        &options.reason,
        options.evidence_id,
    )?;
    let output = json!({
        "decisionDigest": format!("0x{}", hex_encode(&prepared.decision_digest)),
        "decisionEvidence": prepared.evidence,
    });
    let mut stdout = io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, &output).map_err(|_| PrepareError::Io)?;
    writeln!(stdout).map_err(|_| PrepareError::Io)?;
    Ok(())
}

fn parse_args(args: &[String]) -> Result<Options, PrepareError> {
    let mut reason = None;
    let mut verdict = Verdict::Commit;
    let mut evidence_id = None;
    let mut now = None;
    let mut body_path = None;
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        let value = args.get(index + 1).ok_or(PrepareError::Usage)?;
        match arg {
            "--reason" => reason = Some(value.clone()),
            "--verdict" => {
                verdict = match value.as_str() {
                    "COMMIT" => Verdict::Commit,
                    "NO_COMMIT" => Verdict::NoCommit,
                    _ => return Err(PrepareError::Usage),
                };
            }
            "--evidence-id" => evidence_id = Some(parse_word(value)?),
            "--now" => {
                now = Some(value.parse::<u64>().map_err(|_| PrepareError::Usage)?);
            }
            "--body" => body_path = Some(value.clone()),
            _ => return Err(PrepareError::Usage),
        }
        index += 2;
    }
    let reason = reason.ok_or(PrepareError::Usage)?;
    let now = match now {
        Some(now) => now,
        None => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PrepareError::Time)?
            .as_secs(),
    };
    Ok(Options {
        reason,
        verdict,
        evidence_id,
        now,
        body_path,
    })
}

fn parse_word(value: &str) -> Result<[u8; 32], PrepareError> {
    let hex = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .ok_or(PrepareError::EvidenceId)?;
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(PrepareError::EvidenceId);
    }
    let bytes = hex.as_bytes();
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        let high = hex_nibble(bytes[index * 2])?;
        let low = hex_nibble(bytes[index * 2 + 1])?;
        *byte = (high << 4) | low;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, PrepareError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(PrepareError::EvidenceId),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{
        signing_digest, test_address, test_sign, to_checksum, Authorization, EIP712_NAME,
        EIP712_VERSION, NETWORK, USDC_ADDRESS,
    };
    use crate::evidence::{
        assess_decision, parse_decision_evidence, ExpectedBinding, Verdict as DecisionVerdict,
    };

    const NOW: u64 = 1_700_000_000;
    const EVIDENCE_ID: [u8; 32] = [0x11; 32];
    const ORACLE_SECRET: [u8; 32] = [0x7u8; 32];

    #[test]
    fn unsigned_evidence_is_accepted_once_an_oracle_signs_the_digest() {
        let payment = payment_body("10000", [0xab; 32]);
        let prepared = prepare_decision(
            &payment,
            NOW,
            DecisionVerdict::Commit,
            "allowed",
            Some(EVIDENCE_ID),
        )
        .unwrap();
        assert!(prepared.evidence.get("signature").is_none());
        assert_eq!(prepared.evidence["verdict"], "COMMIT");
        assert_eq!(prepared.evidence["authorization"]["chainId"], 8453);
        assert_eq!(prepared.evidence["context"]["network"], NETWORK);

        let mut evidence = prepared.evidence.clone();
        let signature = test_sign(&ORACLE_SECRET, &prepared.decision_digest);
        evidence["signature"] = json!(format!("0x{}", hex_encode(&signature)));
        let parsed = parse_decision_evidence(&evidence).unwrap();
        let checked = verify::accept_local(&payment, NOW).unwrap();
        let expected = ExpectedBinding::for_payment(
            payment_context(&checked).unwrap(),
            authorization_identity(&checked),
            settlement_action(&checked),
        )
        .unwrap();
        let record = assess_decision(&parsed, &expected, &test_address(&ORACLE_SECRET)).unwrap();
        assert_eq!(record.verdict(), DecisionVerdict::Commit);
        assert_eq!(record.decision_digest(), prepared.decision_digest);
    }

    #[test]
    fn changing_the_authorization_value_changes_the_digest() {
        let left = prepare_decision(
            &payment_body("10000", [0xab; 32]),
            NOW,
            DecisionVerdict::Commit,
            "allowed",
            Some(EVIDENCE_ID),
        )
        .unwrap();
        let right = prepare_decision(
            &payment_body("10001", [0xab; 32]),
            NOW,
            DecisionVerdict::Commit,
            "allowed",
            Some(EVIDENCE_ID),
        )
        .unwrap();
        assert_ne!(left.decision_digest, right.decision_digest);
        assert_ne!(
            left.evidence["actionDigest"],
            right.evidence["actionDigest"]
        );
        assert_ne!(
            left.evidence["authorization"]["value"],
            right.evidence["authorization"]["value"]
        );
    }

    fn payment_body(amount: &str, nonce: [u8; 32]) -> Value {
        let secret = [0x42u8; 32];
        let from = test_address(&secret);
        let to = [0x22u8; 20];
        let mut value = [0u8; 32];
        let parsed: u64 = amount.parse().unwrap();
        value[24..].copy_from_slice(&parsed.to_be_bytes());
        let auth = Authorization {
            from,
            to,
            value,
            valid_after: [0u8; 32],
            valid_before: {
                let mut word = [0u8; 32];
                word[24..].copy_from_slice(&(NOW + 30).to_be_bytes());
                word
            },
            nonce,
        };
        let signature = test_sign(&secret, &signing_digest(&auth));
        let payer = to_checksum(&from);
        let pay_to = to_checksum(&to);
        let terms = json!({
            "scheme": "exact",
            "network": NETWORK,
            "amount": amount,
            "asset": to_checksum(&USDC_ADDRESS),
            "payTo": pay_to,
            "maxTimeoutSeconds": 60,
            "extra": { "name": EIP712_NAME, "version": EIP712_VERSION }
        });
        json!({
            "x402Version": 2,
            "paymentPayload": {
                "x402Version": 2,
                "accepted": terms,
                "payload": {
                    "signature": format!("0x{}", hex_encode(&signature)),
                    "authorization": {
                        "from": payer,
                        "to": pay_to,
                        "value": amount,
                        "validAfter": "0",
                        "validBefore": (NOW + 30).to_string(),
                        "nonce": format!("0x{}", hex_encode(&nonce))
                    }
                }
            },
            "paymentRequirements": terms
        })
    }
}
