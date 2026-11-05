//! Decision, settlement, and audit records.
//!
//! [`DclDecisionEvidence`] is the only Oracle decision this module accepts.
//! [`UsdcSettlementEvidence`] records a Base USDC transfer. [`AuditEvidence`]
//! is a journal link. The three types do not convert into each other.
//!
//! Validation is local. It does not call an Oracle service and it does not
//! move the settlement state machine. The live settlement path checks the
//! signature here, then consumes the decision in the same SQLite transaction
//! as the payment transition. [`VerifiedCommit`] is not
//! [`crate::leibniz::Commit`] and is not an input to `begin_settlement`.

use std::collections::HashMap;
use std::sync::Mutex;

use serde_json::{json, Value};

use crate::chain::{keccak, recover_signer};
use crate::leibniz::{ActionDigest, PaymentContext};

const AUTHORIZATION_DOMAIN: &[u8] = b"DCL_AUTHORIZATION_IDENTITY_V1";
const DECISION_DOMAIN: &[u8] = b"DCL_DECISION_EVIDENCE_V1";
const ACTION_ID_DOMAIN: &[u8] = b"DCL_ACTION_ID_V1";
const MAX_ACTION_ID_BYTES: usize = 256;
const MAX_REASON_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecisionError {
    #[error("decision evidence is malformed")]
    Malformed,
    #[error("oracle signature is missing or invalid")]
    InvalidSignature,
    #[error("decision evidence is not bound to this payment authorization")]
    NotBound,
    #[error("decision evidence was already used for different signed content")]
    Reused,
    #[error("this payment already consumed a decision")]
    Consumed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verdict {
    Commit,
    NoCommit,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ActionId(String);

impl ActionId {
    pub fn try_new(value: impl Into<String>) -> Result<Self, DecisionError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_ACTION_ID_BYTES {
            return Err(DecisionError::Malformed);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DecisionReason(String);

impl DecisionReason {
    pub fn try_new(value: impl Into<String>) -> Result<Self, DecisionError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_REASON_BYTES {
            return Err(DecisionError::Malformed);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EvidenceId([u8; 32]);

impl EvidenceId {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Chain id, USDC contract, and the EIP-3009 authorization fields that bind a decision.
///
/// The payer signature is not part of this identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizationIdentity {
    chain_id: u64,
    verifying_contract: [u8; 20],
    payer: [u8; 20],
    recipient: [u8; 20],
    value: [u8; 32],
    valid_after: [u8; 32],
    valid_before: [u8; 32],
    nonce: [u8; 32],
}

impl AuthorizationIdentity {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: u64,
        verifying_contract: [u8; 20],
        payer: [u8; 20],
        recipient: [u8; 20],
        value: [u8; 32],
        valid_after: [u8; 32],
        valid_before: [u8; 32],
        nonce: [u8; 32],
    ) -> Self {
        Self {
            chain_id,
            verifying_contract,
            payer,
            recipient,
            value,
            valid_after,
            valid_before,
            nonce,
        }
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn verifying_contract(&self) -> [u8; 20] {
        self.verifying_contract
    }

    pub fn payer(&self) -> [u8; 20] {
        self.payer
    }

    pub fn recipient(&self) -> [u8; 20] {
        self.recipient
    }

    pub fn value(&self) -> [u8; 32] {
        self.value
    }

    pub fn valid_after(&self) -> [u8; 32] {
        self.valid_after
    }

    pub fn valid_before(&self) -> [u8; 32] {
        self.valid_before
    }

    pub fn nonce(&self) -> [u8; 32] {
        self.nonce
    }

    /// `keccak256` of the versioned authorization-identity words.
    pub fn digest(&self) -> [u8; 32] {
        keccak(&concat_words(&[
            keccak(AUTHORIZATION_DOMAIN),
            word_u64(self.chain_id),
            word_address(self.verifying_contract),
            word_address(self.payer),
            word_address(self.recipient),
            self.value,
            self.valid_after,
            self.valid_before,
            self.nonce,
        ]))
    }
}

/// Signed content of a DCL decision, before the Oracle signature is attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionBody {
    action_id: ActionId,
    action_digest: ActionDigest,
    payment_context: PaymentContext,
    authorization: AuthorizationIdentity,
    verdict: Verdict,
    reason: DecisionReason,
    evidence_id: EvidenceId,
}

impl DecisionBody {
    pub fn new(
        action_id: ActionId,
        action_digest: ActionDigest,
        payment_context: PaymentContext,
        authorization: AuthorizationIdentity,
        verdict: Verdict,
        reason: DecisionReason,
        evidence_id: EvidenceId,
    ) -> Result<Self, DecisionError> {
        if action_digest.is_unspecified() {
            return Err(DecisionError::Malformed);
        }
        Ok(Self {
            action_id,
            action_digest,
            payment_context,
            authorization,
            verdict,
            reason,
            evidence_id,
        })
    }

    pub fn action_id(&self) -> &ActionId {
        &self.action_id
    }

    pub fn action_digest(&self) -> &ActionDigest {
        &self.action_digest
    }

    pub fn payment_context(&self) -> &PaymentContext {
        &self.payment_context
    }

    pub fn authorization(&self) -> &AuthorizationIdentity {
        &self.authorization
    }

    pub fn verdict(&self) -> Verdict {
        self.verdict
    }

    pub fn reason(&self) -> &DecisionReason {
        &self.reason
    }

    pub fn evidence_id(&self) -> EvidenceId {
        self.evidence_id
    }

    pub fn decision_digest(&self) -> Result<[u8; 32], DecisionError> {
        let context = canonical_payment_context(&self.payment_context)?;
        Ok(keccak(&concat_words(&[
            keccak(DECISION_DOMAIN),
            verdict_word(self.verdict),
            keccak(self.action_id.as_str().as_bytes()),
            *self.action_digest.as_bytes(),
            self.authorization.digest(),
            keccak(&context),
            keccak(self.reason.as_str().as_bytes()),
            *self.evidence_id.as_bytes(),
        ])))
    }
}

/// Oracle signature over one [`DecisionBody`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DclDecisionEvidence {
    body: DecisionBody,
    signature: [u8; 65],
}

impl DclDecisionEvidence {
    pub fn certify(body: DecisionBody, signature: &[u8]) -> Result<Self, DecisionError> {
        if signature.len() != 65 {
            return Err(DecisionError::InvalidSignature);
        }
        let mut owned = [0u8; 65];
        owned.copy_from_slice(signature);
        Ok(Self {
            body,
            signature: owned,
        })
    }

    pub fn body(&self) -> &DecisionBody {
        &self.body
    }

    pub fn signature(&self) -> &[u8; 65] {
        &self.signature
    }

    pub fn decision_digest(&self) -> Result<[u8; 32], DecisionError> {
        self.body.decision_digest()
    }
}

/// Receipt identity for one USDC `transferWithAuthorization`. Not an Oracle decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsdcSettlementEvidence {
    chain_id: u64,
    authorization_digest: [u8; 32],
    tx_hash: [u8; 32],
    receipt_status: u64,
    block_number: u64,
    block_hash: [u8; 32],
    transfer_log_index: Option<u64>,
}

impl UsdcSettlementEvidence {
    pub fn new(
        chain_id: u64,
        authorization_digest: [u8; 32],
        tx_hash: [u8; 32],
        receipt_status: u64,
        block_number: u64,
        block_hash: [u8; 32],
        transfer_log_index: Option<u64>,
    ) -> Self {
        Self {
            chain_id,
            authorization_digest,
            tx_hash,
            receipt_status,
            block_number,
            block_hash,
            transfer_log_index,
        }
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn authorization_digest(&self) -> [u8; 32] {
        self.authorization_digest
    }

    pub fn tx_hash(&self) -> [u8; 32] {
        self.tx_hash
    }

    pub fn receipt_status(&self) -> u64 {
        self.receipt_status
    }

    pub fn block_number(&self) -> u64 {
        self.block_number
    }

    pub fn block_hash(&self) -> [u8; 32] {
        self.block_hash
    }

    pub fn transfer_log_index(&self) -> Option<u64> {
        self.transfer_log_index
    }
}

/// One journal link. Hash-chain verification is a later milestone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvidence {
    sequence: u64,
    event_id: [u8; 32],
    previous_link: [u8; 32],
    link: [u8; 32],
}

impl AuditEvidence {
    pub fn new(sequence: u64, event_id: [u8; 32], previous_link: [u8; 32], link: [u8; 32]) -> Self {
        Self {
            sequence,
            event_id,
            previous_link,
            link,
        }
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn event_id(&self) -> [u8; 32] {
        self.event_id
    }

    pub fn previous_link(&self) -> [u8; 32] {
        self.previous_link
    }

    pub fn link(&self) -> [u8; 32] {
        self.link
    }
}

/// Live payment a decision must match before it can be consumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedBinding {
    context: PaymentContext,
    authorization: AuthorizationIdentity,
    action_id: ActionId,
    action_digest: ActionDigest,
}

impl ExpectedBinding {
    /// Binding the facilitator computes from the live payment. `action_id` is
    /// `hex(keccak("DCL_ACTION_ID_V1" || action_digest))`: 64 lowercase hex
    /// characters, no `0x` prefix. It is not copied from the evidence.
    pub(crate) fn for_payment(
        context: PaymentContext,
        authorization: AuthorizationIdentity,
        action_digest: ActionDigest,
    ) -> Result<Self, DecisionError> {
        let action_id = action_id_from_digest(&action_digest)?;
        Self::new(context, authorization, action_id, action_digest)
    }

    pub fn new(
        context: PaymentContext,
        authorization: AuthorizationIdentity,
        action_id: ActionId,
        action_digest: ActionDigest,
    ) -> Result<Self, DecisionError> {
        if action_digest.is_unspecified() {
            return Err(DecisionError::Malformed);
        }
        Ok(Self {
            context,
            authorization,
            action_id,
            action_digest,
        })
    }

    pub fn context(&self) -> &PaymentContext {
        &self.context
    }

    pub fn authorization(&self) -> &AuthorizationIdentity {
        &self.authorization
    }

    pub fn action_id(&self) -> &ActionId {
        &self.action_id
    }

    pub fn action_digest(&self) -> &ActionDigest {
        &self.action_digest
    }
}

/// Permission to settle, produced only for a verified `COMMIT`.
///
/// Distinct from [`crate::leibniz::Commit`]. The settlement machine does not
/// accept this token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCommit {
    evidence_id: EvidenceId,
    decision_digest: [u8; 32],
    authorization_digest: [u8; 32],
}

impl VerifiedCommit {
    pub fn evidence_id(&self) -> EvidenceId {
        self.evidence_id
    }

    pub fn decision_digest(&self) -> [u8; 32] {
        self.decision_digest
    }

    pub fn authorization_digest(&self) -> [u8; 32] {
        self.authorization_digest
    }
}

/// Verified refusal. It has no settlement token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedNoCommit {
    evidence_id: EvidenceId,
    decision_digest: [u8; 32],
    authorization_digest: [u8; 32],
}

impl VerifiedNoCommit {
    pub fn evidence_id(&self) -> EvidenceId {
        self.evidence_id
    }

    pub fn decision_digest(&self) -> [u8; 32] {
        self.decision_digest
    }

    pub fn authorization_digest(&self) -> [u8; 32] {
        self.authorization_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionOutcome {
    Commit(VerifiedCommit),
    NoCommit(VerifiedNoCommit),
}

/// Idempotency key `(network, payer, nonce)` after address and nonce normalization.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PaymentKey {
    network: String,
    payer: String,
    nonce: String,
}

impl PaymentKey {
    pub(crate) fn new(
        network: impl Into<String>,
        payer: impl Into<String>,
        nonce: impl Into<String>,
    ) -> Self {
        Self {
            network: network.into(),
            payer: payer.into(),
            nonce: nonce.into(),
        }
    }

    pub fn network(&self) -> &str {
        &self.network
    }

    pub fn payer(&self) -> &str {
        &self.payer
    }

    pub fn nonce(&self) -> &str {
        &self.nonce
    }
}

/// Facts stored when a decision is consumed.
///
/// An idempotent replay matches evidence id, authorization digest, payment key,
/// verdict, and decision digest. Any other signed content under the same id is
/// [`DecisionError::Reused`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumptionRecord {
    evidence_id: EvidenceId,
    authorization_digest: [u8; 32],
    payment_key: PaymentKey,
    verdict: Verdict,
    decision_digest: [u8; 32],
}

impl ConsumptionRecord {
    pub(crate) fn from_parts(
        evidence_id: EvidenceId,
        authorization_digest: [u8; 32],
        payment_key: PaymentKey,
        verdict: Verdict,
        decision_digest: [u8; 32],
    ) -> Self {
        Self {
            evidence_id,
            authorization_digest,
            payment_key,
            verdict,
            decision_digest,
        }
    }

    pub fn evidence_id(&self) -> EvidenceId {
        self.evidence_id
    }

    pub fn authorization_digest(&self) -> [u8; 32] {
        self.authorization_digest
    }

    pub fn payment_key(&self) -> &PaymentKey {
        &self.payment_key
    }

    pub fn verdict(&self) -> Verdict {
        self.verdict
    }

    pub fn decision_digest(&self) -> [u8; 32] {
        self.decision_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumeEffect {
    Fresh,
    Replay,
}

/// Atomic consumption of one decision.
///
/// `consume` is one critical section: read the existing evidence id and payment
/// key, compare the stored record, and insert, without an interleaving writer.
/// A SQLite implementation must do that comparison and both unique inserts in
/// one transaction. The record is trusted; [`validate_decision`] checks the
/// signature and the binding before it calls `consume`.
pub trait DecisionConsumption: Send + Sync {
    fn consume(&self, record: &ConsumptionRecord) -> Result<ConsumeEffect, DecisionError>;
}

/// In-memory [`DecisionConsumption`]. The mutex is held for the whole compare-and-insert.
#[derive(Debug, Default)]
pub struct MemoryConsumption {
    inner: Mutex<MemoryState>,
}

#[derive(Debug, Default)]
struct MemoryState {
    by_id: HashMap<EvidenceId, ConsumptionRecord>,
    by_payment: HashMap<PaymentKey, EvidenceId>,
}

impl MemoryConsumption {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, evidence_id: &EvidenceId) -> Option<ConsumptionRecord> {
        let state = self.lock();
        state.by_id.get(evidence_id).cloned()
    }

    pub fn len(&self) -> usize {
        self.lock().by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MemoryState> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl DecisionConsumption for MemoryConsumption {
    fn consume(&self, record: &ConsumptionRecord) -> Result<ConsumeEffect, DecisionError> {
        let mut state = self.lock();
        if let Some(stored) = state.by_id.get(&record.evidence_id) {
            if same_consumption(stored, record) {
                return Ok(ConsumeEffect::Replay);
            }
            return Err(DecisionError::Reused);
        }
        if state.by_payment.contains_key(&record.payment_key) {
            return Err(DecisionError::Consumed);
        }
        state
            .by_payment
            .insert(record.payment_key.clone(), record.evidence_id);
        state.by_id.insert(record.evidence_id, record.clone());
        Ok(ConsumeEffect::Fresh)
    }
}

pub(crate) fn same_consumption(stored: &ConsumptionRecord, record: &ConsumptionRecord) -> bool {
    stored.evidence_id == record.evidence_id
        && stored.authorization_digest == record.authorization_digest
        && stored.payment_key == record.payment_key
        && stored.verdict == record.verdict
        && stored.decision_digest == record.decision_digest
}

/// Check the Oracle signature and binding. Does not consume.
///
/// Live settlement consumes the returned record in the same SQLite
/// transaction as `Rejected` or as `Settling` plus the raw transaction.
/// [`validate_decision`] is the in-memory form of that check plus consume.
pub(crate) fn assess_decision(
    evidence: &DclDecisionEvidence,
    expected: &ExpectedBinding,
    oracle: &[u8; 20],
) -> Result<ConsumptionRecord, DecisionError> {
    let bound = bound_record(evidence, expected)?;
    let digest = evidence.decision_digest()?;
    let signer = recover_signer(&digest, evidence.signature())
        .map_err(|_| DecisionError::InvalidSignature)?;
    if signer != *oracle {
        return Err(DecisionError::InvalidSignature);
    }
    Ok(ConsumptionRecord::from_parts(
        evidence.body.evidence_id,
        bound.authorization_digest,
        bound.payment_key,
        evidence.body.verdict,
        digest,
    ))
}

/// Check the Oracle signature and consume the decision if it is bound to `expected`.
pub fn validate_decision(
    evidence: &DclDecisionEvidence,
    expected: &ExpectedBinding,
    oracle: &[u8; 20],
    consumption: &impl DecisionConsumption,
) -> Result<DecisionOutcome, DecisionError> {
    let record = assess_decision(evidence, expected, oracle)?;
    let verdict = record.verdict();
    consumption.consume(&record)?;
    Ok(outcome_from(verdict, record))
}

/// `lowercase hex(keccak256(b"DCL_ACTION_ID_V1" || action_digest))`.
///
/// The digest is the raw 32-byte action digest. The result has no `0x` prefix.
pub(crate) fn action_id_from_digest(action: &ActionDigest) -> Result<ActionId, DecisionError> {
    let mut preimage = Vec::with_capacity(ACTION_ID_DOMAIN.len() + 32);
    preimage.extend_from_slice(ACTION_ID_DOMAIN);
    preimage.extend_from_slice(action.as_bytes());
    ActionId::try_new(hex_encode(&keccak(&preimage)))
}

/// Authorization digest of one stored payment, using the context's chain,
/// asset, payer, recipient, and nonce plus the signed value window.
pub(crate) fn authorization_digest_for(
    context: &PaymentContext,
    value: [u8; 32],
    valid_after: [u8; 32],
    valid_before: [u8; 32],
) -> Result<[u8; 32], DecisionError> {
    let payer = decode_address(&canonical_address(context.payer())?)?;
    let recipient = decode_address(&canonical_address(context.pay_to())?)?;
    let asset = decode_address(&canonical_address(context.asset())?)?;
    let nonce = decode_word(&canonical_nonce(context.nonce())?)?;
    let chain = chain_of_network(context.network())?;
    Ok(AuthorizationIdentity::new(
        chain,
        asset,
        payer,
        recipient,
        value,
        valid_after,
        valid_before,
        nonce,
    )
    .digest())
}

struct Bound {
    authorization_digest: [u8; 32],
    payment_key: PaymentKey,
}

fn bound_record(
    evidence: &DclDecisionEvidence,
    expected: &ExpectedBinding,
) -> Result<Bound, DecisionError> {
    let evidence_context = canonical_payment_context(evidence.body.payment_context())?;
    let expected_context = canonical_payment_context(&expected.context)?;
    if evidence_context != expected_context {
        return Err(DecisionError::NotBound);
    }
    if evidence.body.action_id != expected.action_id
        || evidence.body.action_digest != expected.action_digest
        || evidence.body.authorization != expected.authorization
    {
        return Err(DecisionError::NotBound);
    }
    let payment_key = payment_key_of(evidence.body.payment_context())?;
    consistent(
        &payment_key,
        evidence.body.payment_context(),
        &evidence.body.authorization,
    )?;
    Ok(Bound {
        authorization_digest: evidence.body.authorization.digest(),
        payment_key,
    })
}

fn outcome_from(verdict: Verdict, record: ConsumptionRecord) -> DecisionOutcome {
    match verdict {
        Verdict::Commit => DecisionOutcome::Commit(VerifiedCommit {
            evidence_id: record.evidence_id,
            decision_digest: record.decision_digest,
            authorization_digest: record.authorization_digest,
        }),
        Verdict::NoCommit => DecisionOutcome::NoCommit(VerifiedNoCommit {
            evidence_id: record.evidence_id,
            decision_digest: record.decision_digest,
            authorization_digest: record.authorization_digest,
        }),
    }
}

fn consistent(
    payment_key: &PaymentKey,
    context: &PaymentContext,
    authorization: &AuthorizationIdentity,
) -> Result<(), DecisionError> {
    if chain_of_network(context.network())? != authorization.chain_id {
        return Err(DecisionError::NotBound);
    }
    if payment_key.payer != address_hex(&authorization.payer)
        || canonical_address(context.pay_to())? != address_hex(&authorization.recipient)
        || canonical_address(context.asset())? != address_hex(&authorization.verifying_contract)
        || decode_word(&payment_key.nonce)? != authorization.nonce
    {
        return Err(DecisionError::NotBound);
    }
    Ok(())
}

pub(crate) fn payment_key_of(context: &PaymentContext) -> Result<PaymentKey, DecisionError> {
    Ok(PaymentKey {
        network: context.network().to_string(),
        payer: canonical_address(context.payer())?,
        nonce: canonical_nonce(context.nonce())?,
    })
}

fn chain_of_network(network: &str) -> Result<u64, DecisionError> {
    let rest = network
        .strip_prefix("eip155:")
        .ok_or(DecisionError::NotBound)?;
    if rest.is_empty()
        || !rest.bytes().all(|byte| byte.is_ascii_digit())
        || (rest.len() > 1 && rest.starts_with('0'))
    {
        return Err(DecisionError::NotBound);
    }
    rest.parse().map_err(|_| DecisionError::NotBound)
}

/// Length-prefixed UTF-8 fields: network, payer, payTo, asset, nonce.
///
/// Each field is a big-endian `u32` byte length followed by that many bytes.
/// Payer, payTo, and asset are lowercase `0x` plus 40 hex characters. Nonce is
/// lowercase `0x` plus 64 hex characters.
fn canonical_payment_context(context: &PaymentContext) -> Result<Vec<u8>, DecisionError> {
    let payer = canonical_address(context.payer())?;
    let pay_to = canonical_address(context.pay_to())?;
    let asset = canonical_address(context.asset())?;
    let nonce = canonical_nonce(context.nonce())?;
    let mut out = Vec::new();
    for field in [
        context.network(),
        payer.as_str(),
        pay_to.as_str(),
        asset.as_str(),
        nonce.as_str(),
    ] {
        push_length_prefixed(&mut out, field)?;
    }
    Ok(out)
}

fn push_length_prefixed(out: &mut Vec<u8>, field: &str) -> Result<(), DecisionError> {
    let bytes = field.as_bytes();
    let len = u32::try_from(bytes.len()).map_err(|_| DecisionError::Malformed)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn decode_address(canonical: &str) -> Result<[u8; 20], DecisionError> {
    let hex = lowercase_hex(canonical, 20)?;
    let bytes = hex.as_bytes();
    let mut out = [0u8; 20];
    for (index, byte) in out.iter_mut().enumerate() {
        let high = hex_nibble(bytes[index * 2])?;
        let low = hex_nibble(bytes[index * 2 + 1])?;
        *byte = (high << 4) | low;
    }
    Ok(out)
}

fn canonical_address(value: &str) -> Result<String, DecisionError> {
    Ok(format!("0x{}", lowercase_hex(value, 20)?))
}

fn canonical_nonce(value: &str) -> Result<String, DecisionError> {
    Ok(format!("0x{}", lowercase_hex(value, 32)?))
}

fn lowercase_hex(value: &str, width: usize) -> Result<String, DecisionError> {
    let hex = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .ok_or(DecisionError::Malformed)?;
    if hex.len() != width * 2 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(DecisionError::Malformed);
    }
    Ok(hex.to_ascii_lowercase())
}

fn decode_word(canonical: &str) -> Result<[u8; 32], DecisionError> {
    let hex = lowercase_hex(canonical, 32)?;
    let bytes = hex.as_bytes();
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        let high = hex_nibble(bytes[index * 2])?;
        let low = hex_nibble(bytes[index * 2 + 1])?;
        *byte = (high << 4) | low;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, DecisionError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(DecisionError::Malformed),
    }
}

fn address_hex(address: &[u8; 20]) -> String {
    format!("0x{}", hex_encode(address))
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn verdict_word(verdict: Verdict) -> [u8; 32] {
    match verdict {
        Verdict::Commit => keccak(b"COMMIT"),
        Verdict::NoCommit => keccak(b"NO_COMMIT"),
    }
}

fn word_u64(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

fn word_address(address: [u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(&address);
    word
}

fn concat_words(words: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(words.len() * 32);
    for word in words {
        out.extend_from_slice(word);
    }
    out
}

fn verdict_label(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Commit => "COMMIT",
        Verdict::NoCommit => "NO_COMMIT",
    }
}

fn parse_verdict(value: &str) -> Result<Verdict, DecisionError> {
    match value {
        "COMMIT" => Ok(Verdict::Commit),
        "NO_COMMIT" => Ok(Verdict::NoCommit),
        _ => Err(DecisionError::Malformed),
    }
}

/// Oracle decision carried on `POST /settle` as `decisionEvidence`.
///
/// Address fields are `0x` plus 40 hex characters. 32-byte fields are `0x`
/// plus 64 hex characters. `actionId` is the 64-character lowercase hex from
/// [`action_id_from_digest`], without a prefix.
pub(crate) fn parse_decision_evidence(value: &Value) -> Result<DclDecisionEvidence, DecisionError> {
    let object = value.as_object().ok_or(DecisionError::Malformed)?;
    let action_id = ActionId::try_new(required_str(object.get("actionId"))?.to_string())?;
    let action_digest = ActionDigest::new(parse_word(required_str(object.get("actionDigest"))?)?);
    let context_value = object.get("context").ok_or(DecisionError::Malformed)?;
    let context_object = context_value.as_object().ok_or(DecisionError::Malformed)?;
    let context = PaymentContext::try_new(
        required_str(context_object.get("network"))?,
        required_str(context_object.get("payer"))?,
        required_str(context_object.get("payTo"))?,
        required_str(context_object.get("asset"))?,
        required_str(context_object.get("nonce"))?,
    )
    .map_err(|_| DecisionError::Malformed)?;
    let authorization_value = object
        .get("authorization")
        .ok_or(DecisionError::Malformed)?;
    let authorization_object = authorization_value
        .as_object()
        .ok_or(DecisionError::Malformed)?;
    let chain_id = authorization_object
        .get("chainId")
        .and_then(Value::as_u64)
        .ok_or(DecisionError::Malformed)?;
    let authorization = AuthorizationIdentity::new(
        chain_id,
        parse_address(required_str(authorization_object.get("verifyingContract"))?)?,
        parse_address(required_str(authorization_object.get("payer"))?)?,
        parse_address(required_str(authorization_object.get("recipient"))?)?,
        parse_word(required_str(authorization_object.get("value"))?)?,
        parse_word(required_str(authorization_object.get("validAfter"))?)?,
        parse_word(required_str(authorization_object.get("validBefore"))?)?,
        parse_word(required_str(authorization_object.get("nonce"))?)?,
    );
    let verdict = parse_verdict(required_str(object.get("verdict"))?)?;
    let reason = DecisionReason::try_new(required_str(object.get("reason"))?)?;
    let evidence_id = EvidenceId::new(parse_word(required_str(object.get("evidenceId"))?)?);
    let body = DecisionBody::new(
        action_id,
        action_digest,
        context,
        authorization,
        verdict,
        reason,
        evidence_id,
    )?;
    let signature = parse_signature(required_str(object.get("signature"))?)?;
    DclDecisionEvidence::certify(body, &signature)
}

fn required_str(value: Option<&Value>) -> Result<&str, DecisionError> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or(DecisionError::Malformed)
}

fn parse_address(value: &str) -> Result<[u8; 20], DecisionError> {
    decode_address(&canonical_address(value)?)
}

fn parse_word(value: &str) -> Result<[u8; 32], DecisionError> {
    decode_word(&format!("0x{}", lowercase_hex(value, 32)?))
}

fn parse_signature(value: &str) -> Result<[u8; 65], DecisionError> {
    let hex = lowercase_hex(value, 65)?;
    let bytes = hex.as_bytes();
    let mut out = [0u8; 65];
    for (index, byte) in out.iter_mut().enumerate() {
        let high = hex_nibble(bytes[index * 2])?;
        let low = hex_nibble(bytes[index * 2 + 1])?;
        *byte = (high << 4) | low;
    }
    Ok(out)
}

/// `decisionEvidence` object without a signature. Field formatting matches
/// [`parse_decision_evidence`].
pub(crate) fn unsigned_decision_evidence_value(body: &DecisionBody) -> Value {
    let authorization = body.authorization();
    let context = body.payment_context();
    json!({
        "actionId": body.action_id().as_str(),
        "actionDigest": format!("0x{}", hex_encode(body.action_digest().as_bytes())),
        "verdict": verdict_label(body.verdict()),
        "reason": body.reason().as_str(),
        "evidenceId": format!("0x{}", hex_encode(body.evidence_id().as_bytes())),
        "context": {
            "network": context.network(),
            "payer": context.payer(),
            "payTo": context.pay_to(),
            "asset": context.asset(),
            "nonce": context.nonce(),
        },
        "authorization": {
            "chainId": authorization.chain_id(),
            "verifyingContract": address_hex(&authorization.verifying_contract()),
            "payer": address_hex(&authorization.payer()),
            "recipient": address_hex(&authorization.recipient()),
            "value": format!("0x{}", hex_encode(&authorization.value())),
            "validAfter": format!("0x{}", hex_encode(&authorization.valid_after())),
            "validBefore": format!("0x{}", hex_encode(&authorization.valid_before())),
            "nonce": format!("0x{}", hex_encode(&authorization.nonce())),
        }
    })
}

#[cfg(test)]
pub(crate) fn decision_evidence_value(evidence: &DclDecisionEvidence) -> Value {
    let mut unsigned = unsigned_decision_evidence_value(evidence.body());
    let map = unsigned.as_object_mut().expect("decision evidence object");
    let mut signed = serde_json::Map::new();
    for (key, value) in map.iter() {
        if key == "context" {
            signed.insert(
                "signature".to_string(),
                json!(format!("0x{}", hex_encode(evidence.signature()))),
            );
        }
        signed.insert(key.clone(), value.clone());
    }
    Value::Object(signed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{
        signing_digest, test_address, test_sign, to_checksum, Authorization, BASE_CHAIN_ID,
        NETWORK, USDC_ADDRESS,
    };
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn word(value: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[24..].copy_from_slice(&value.to_be_bytes());
        out
    }

    fn action(tag: u8) -> ActionDigest {
        let mut bytes = [0u8; 32];
        bytes[0] = tag;
        ActionDigest::new(bytes)
    }

    fn authorization() -> AuthorizationIdentity {
        AuthorizationIdentity::new(
            BASE_CHAIN_ID,
            USDC_ADDRESS,
            test_address(&[0x42; 32]),
            [0x22; 20],
            word(9),
            word(10),
            word(1_900_000_000),
            [0x11; 32],
        )
    }

    fn context_for(authorization: &AuthorizationIdentity, checksum: bool) -> PaymentContext {
        let render = |address: [u8; 20]| {
            if checksum {
                to_checksum(&address)
            } else {
                address_hex(&address)
            }
        };
        PaymentContext::try_new(
            NETWORK,
            render(authorization.payer()),
            render(authorization.recipient()),
            render(authorization.verifying_contract()),
            format!("0x{}", hex_encode(&authorization.nonce())),
        )
        .unwrap()
    }

    fn body_with(
        authorization: AuthorizationIdentity,
        context: PaymentContext,
        verdict: Verdict,
        reason: &str,
        evidence_id: [u8; 32],
    ) -> DecisionBody {
        DecisionBody::new(
            ActionId::try_new("action-1").unwrap(),
            action(1),
            context,
            authorization,
            verdict,
            DecisionReason::try_new(reason).unwrap(),
            EvidenceId::new(evidence_id),
        )
        .unwrap()
    }

    fn signed(body: DecisionBody, secret: &[u8; 32]) -> DclDecisionEvidence {
        let digest = body.decision_digest().unwrap();
        DclDecisionEvidence::certify(body, &test_sign(secret, &digest)).unwrap()
    }

    fn expected_for(body: &DecisionBody) -> ExpectedBinding {
        ExpectedBinding::new(
            body.payment_context().clone(),
            *body.authorization(),
            body.action_id().clone(),
            *body.action_digest(),
        )
        .unwrap()
    }

    fn sample() -> (DclDecisionEvidence, ExpectedBinding, [u8; 20]) {
        let secret = [0x7u8; 32];
        let authorization = authorization();
        let body = body_with(
            authorization,
            context_for(&authorization, true),
            Verdict::Commit,
            "allowed",
            [0xab; 32],
        );
        let expected = expected_for(&body);
        let evidence = signed(body, &secret);
        (evidence, expected, test_address(&secret))
    }

    #[test]
    fn canonical_context_is_length_prefixed_and_lowercases_asset() {
        let authorization = authorization();
        let context = context_for(&authorization, true);
        let encoded = canonical_payment_context(&context).unwrap();
        let asset = address_hex(&USDC_ADDRESS);
        assert_eq!(asset.len(), 42);
        assert!(to_checksum(&USDC_ADDRESS)
            .chars()
            .any(|ch| ch.is_ascii_uppercase()));
        assert_ne!(context.asset(), asset);

        let mut expected = Vec::new();
        for field in [
            NETWORK,
            address_hex(&authorization.payer()).as_str(),
            address_hex(&authorization.recipient()).as_str(),
            asset.as_str(),
            format!("0x{}", hex_encode(&authorization.nonce())).as_str(),
        ] {
            expected.extend_from_slice(&(field.len() as u32).to_be_bytes());
            expected.extend_from_slice(field.as_bytes());
        }
        assert_eq!(encoded, expected);
        assert_eq!(&encoded[..4], &11u32.to_be_bytes());
        assert_eq!(&encoded[4..15], NETWORK.as_bytes());
    }

    #[test]
    fn authorization_digest_is_its_own_domain() {
        let identity = authorization();
        let digest = identity.digest();
        let manual = keccak(&concat_words(&[
            keccak(AUTHORIZATION_DOMAIN),
            word_u64(identity.chain_id()),
            word_address(identity.verifying_contract()),
            word_address(identity.payer()),
            word_address(identity.recipient()),
            identity.value(),
            identity.valid_after(),
            identity.valid_before(),
            identity.nonce(),
        ]));
        assert_eq!(digest, manual);

        let eip3009 = signing_digest(&Authorization {
            from: identity.payer(),
            to: identity.recipient(),
            value: identity.value(),
            valid_after: identity.valid_after(),
            valid_before: identity.valid_before(),
            nonce: identity.nonce(),
        });
        let mut fingerprint = Vec::new();
        fingerprint.extend_from_slice(NETWORK.as_bytes());
        fingerprint.extend_from_slice(&identity.verifying_contract());
        fingerprint.extend_from_slice(&identity.payer());
        fingerprint.extend_from_slice(&identity.recipient());
        fingerprint.extend_from_slice(&identity.value());
        fingerprint.extend_from_slice(&identity.valid_after());
        fingerprint.extend_from_slice(&identity.valid_before());
        fingerprint.extend_from_slice(&identity.nonce());
        fingerprint.extend_from_slice(&[0u8; 65]);
        assert_ne!(digest, eip3009);
        assert_ne!(digest, keccak(&fingerprint));
    }

    #[test]
    fn commit_replays_only_when_the_stored_decision_digest_matches() {
        let (evidence, expected, oracle) = sample();
        let consumption = MemoryConsumption::new();
        let first = validate_decision(&evidence, &expected, &oracle, &consumption).unwrap();
        let DecisionOutcome::Commit(token) = &first else {
            panic!("expected commit");
        };
        let stored = consumption.get(&token.evidence_id()).unwrap();
        assert_eq!(stored.decision_digest(), token.decision_digest());
        assert_eq!(stored.authorization_digest(), token.authorization_digest());
        assert_eq!(stored.verdict(), Verdict::Commit);
        assert_eq!(
            stored.payment_key().payer(),
            address_hex(&authorization().payer())
        );
        assert_eq!(consumption.len(), 1);

        let second = validate_decision(&evidence, &expected, &oracle, &consumption).unwrap();
        assert_eq!(first, second);
        assert_eq!(consumption.len(), 1);

        let lowercase = context_for(evidence.body().authorization(), false);
        let mut replay_body = evidence.body().clone();
        replay_body.payment_context = lowercase;
        let replay = signed(replay_body, &[0x7u8; 32]);
        assert_eq!(
            validate_decision(&replay, &expected, &oracle, &consumption).unwrap(),
            first
        );
        assert_eq!(consumption.len(), 1);
    }

    #[test]
    fn same_id_with_different_signed_content_is_reused() {
        let (evidence, expected, oracle) = sample();
        let consumption = MemoryConsumption::new();
        validate_decision(&evidence, &expected, &oracle, &consumption).unwrap();
        let original = consumption.get(&evidence.body().evidence_id()).unwrap();

        let mut changed = evidence.body().clone();
        changed.reason = DecisionReason::try_new("a different reason").unwrap();
        let changed_expected = expected_for(&changed);
        let resigned = signed(changed, &[0x7u8; 32]);
        assert_ne!(
            resigned.decision_digest().unwrap(),
            original.decision_digest()
        );
        assert_eq!(
            validate_decision(&resigned, &changed_expected, &oracle, &consumption),
            Err(DecisionError::Reused)
        );
        assert_eq!(
            consumption.get(&evidence.body().evidence_id()).unwrap(),
            original
        );
        assert_eq!(consumption.len(), 1);
    }

    #[test]
    fn a_second_evidence_id_for_the_same_payment_is_consumed() {
        let (evidence, expected, oracle) = sample();
        let consumption = MemoryConsumption::new();
        validate_decision(&evidence, &expected, &oracle, &consumption).unwrap();

        let mut other = evidence.body().clone();
        other.evidence_id = EvidenceId::new([0xcd; 32]);
        let other = signed(other, &[0x7u8; 32]);
        assert_eq!(
            validate_decision(&other, &expected, &oracle, &consumption),
            Err(DecisionError::Consumed)
        );
        assert_eq!(consumption.len(), 1);
    }

    #[test]
    fn invalid_or_missing_signatures_fail_closed() {
        let (evidence, expected, oracle) = sample();
        let consumption = MemoryConsumption::new();
        assert_eq!(
            DclDecisionEvidence::certify(evidence.body().clone(), &[]).unwrap_err(),
            DecisionError::InvalidSignature
        );
        assert_eq!(
            DclDecisionEvidence::certify(evidence.body().clone(), &[0u8; 64]).unwrap_err(),
            DecisionError::InvalidSignature
        );

        let mut blank = evidence.signature;
        blank.fill(0);
        let blank = DclDecisionEvidence::certify(evidence.body().clone(), &blank).unwrap();
        assert_eq!(
            validate_decision(&blank, &expected, &oracle, &consumption),
            Err(DecisionError::InvalidSignature)
        );

        let other_key = signed(evidence.body().clone(), &[0x8u8; 32]);
        assert_eq!(
            validate_decision(&other_key, &expected, &oracle, &consumption),
            Err(DecisionError::InvalidSignature)
        );

        let mut high_s = evidence.signature;
        high_s[63] = 0xff;
        let high_s = DclDecisionEvidence::certify(evidence.body().clone(), &high_s).unwrap();
        assert_eq!(
            validate_decision(&high_s, &expected, &oracle, &consumption),
            Err(DecisionError::InvalidSignature)
        );
        assert!(consumption.is_empty());
    }

    #[test]
    fn no_commit_never_yields_a_commit_token() {
        let secret = [0x7u8; 32];
        let authorization = authorization();
        let body = body_with(
            authorization,
            context_for(&authorization, true),
            Verdict::NoCommit,
            "refused",
            [0xab; 32],
        );
        let expected = expected_for(&body);
        let evidence = signed(body, &secret);
        let consumption = MemoryConsumption::new();
        let outcome =
            validate_decision(&evidence, &expected, &test_address(&secret), &consumption).unwrap();
        assert!(matches!(outcome, DecisionOutcome::NoCommit(_)));
        assert_eq!(
            consumption
                .get(&EvidenceId::new([0xab; 32]))
                .unwrap()
                .verdict(),
            Verdict::NoCommit
        );

        let mut later = evidence.body().clone();
        later.verdict = Verdict::Commit;
        later.evidence_id = EvidenceId::new([0xef; 32]);
        let later = signed(later, &secret);
        assert_eq!(
            validate_decision(&later, &expected, &test_address(&secret), &consumption),
            Err(DecisionError::Consumed)
        );
    }

    #[test]
    fn evidence_must_match_the_exact_authorization() {
        let (evidence, _, oracle) = sample();
        let consumption = MemoryConsumption::new();
        let mut other = authorization();
        other.value = word(10);
        let mismatched = ExpectedBinding::new(
            evidence.body().payment_context().clone(),
            other,
            evidence.body().action_id().clone(),
            *evidence.body().action_digest(),
        )
        .unwrap();
        assert_eq!(
            validate_decision(&evidence, &mismatched, &oracle, &consumption),
            Err(DecisionError::NotBound)
        );

        let mut shifted = evidence.body().clone();
        shifted.authorization.nonce = [0x12; 32];
        shifted.payment_context = context_for(&shifted.authorization, true);
        let shifted_evidence = signed(shifted.clone(), &[0x7u8; 32]);
        let shifted_expected = expected_for(&shifted);
        assert_eq!(
            validate_decision(
                &shifted_evidence,
                &expected_for(evidence.body()),
                &oracle,
                &consumption
            ),
            Err(DecisionError::NotBound)
        );
        validate_decision(
            &evidence,
            &expected_for(evidence.body()),
            &oracle,
            &consumption,
        )
        .unwrap();
        assert_eq!(
            validate_decision(&shifted_evidence, &shifted_expected, &oracle, &consumption),
            Err(DecisionError::Reused)
        );
        assert_eq!(consumption.len(), 1);
    }

    #[test]
    fn inconsistent_context_is_not_bound() {
        let (evidence, expected, oracle) = sample();
        let consumption = MemoryConsumption::new();
        let mut broken = evidence.body().clone();
        broken.authorization.chain_id = 1;
        let broken_expected = ExpectedBinding::new(
            broken.payment_context.clone(),
            broken.authorization,
            broken.action_id.clone(),
            broken.action_digest,
        )
        .unwrap();
        let broken = signed(broken, &[0x7u8; 32]);
        assert_eq!(
            validate_decision(&broken, &broken_expected, &oracle, &consumption),
            Err(DecisionError::NotBound)
        );
        assert_eq!(
            validate_decision(&evidence, &expected, &oracle, &consumption).unwrap(),
            validate_decision(&evidence, &expected, &oracle, &consumption).unwrap()
        );
    }

    #[test]
    fn malformed_identity_is_rejected_before_consumption() {
        assert_eq!(ActionId::try_new("").unwrap_err(), DecisionError::Malformed);
        assert_eq!(
            DecisionReason::try_new("").unwrap_err(),
            DecisionError::Malformed
        );
        assert_eq!(
            DecisionBody::new(
                ActionId::try_new("action-1").unwrap(),
                ActionDigest::new([0u8; 32]),
                context_for(&authorization(), true),
                authorization(),
                Verdict::Commit,
                DecisionReason::try_new("allowed").unwrap(),
                EvidenceId::new([1u8; 32]),
            )
            .unwrap_err(),
            DecisionError::Malformed
        );

        let (evidence, _, oracle) = sample();
        let consumption = MemoryConsumption::new();
        let current = evidence.body().payment_context();
        let context = PaymentContext::try_new(
            current.network(),
            current.payer(),
            current.pay_to(),
            "usdc",
            current.nonce(),
        )
        .unwrap();
        let mut body = evidence.body().clone();
        body.payment_context = context;
        let evidence = DclDecisionEvidence::certify(body, &[0x11; 65]).unwrap();
        let expected = expected_for(evidence.body());
        assert_eq!(evidence.decision_digest(), Err(DecisionError::Malformed));
        assert_eq!(
            validate_decision(&evidence, &expected, &oracle, &consumption),
            Err(DecisionError::Malformed)
        );
        assert!(consumption.is_empty());
    }

    #[test]
    fn concurrent_requests_consume_one_evidence_once() {
        let (evidence, expected, oracle) = sample();
        let consumption = Arc::new(MemoryConsumption::new());
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let consumption = Arc::clone(&consumption);
            let barrier = Arc::clone(&barrier);
            let evidence = evidence.clone();
            let expected = expected.clone();
            handles.push(thread::spawn(move || {
                barrier.wait();
                validate_decision(&evidence, &expected, &oracle, consumption.as_ref())
            }));
        }
        let outcomes: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert!(outcomes.iter().all(|outcome| outcome.is_ok()));
        assert_eq!(consumption.len(), 1);

        let consumption = Arc::new(MemoryConsumption::new());
        let barrier = Arc::new(Barrier::new(2));
        let mut raced = Vec::new();
        for tag in [0x11u8, 0x22] {
            let consumption = Arc::clone(&consumption);
            let barrier = Arc::clone(&barrier);
            let expected = expected.clone();
            let mut body = evidence.body().clone();
            body.evidence_id = EvidenceId::new([tag; 32]);
            let evidence = signed(body, &[0x7u8; 32]);
            raced.push(thread::spawn(move || {
                barrier.wait();
                validate_decision(&evidence, &expected, &oracle, consumption.as_ref())
            }));
        }
        let raced: Vec<_> = raced
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        let committed = raced.iter().filter(|outcome| outcome.is_ok()).count();
        let consumed = raced
            .iter()
            .filter(|outcome| outcome == &&Err(DecisionError::Consumed))
            .count();
        assert_eq!(committed, 1);
        assert_eq!(consumed, 1);
        assert_eq!(consumption.len(), 1);
    }

    #[test]
    fn records_stay_distinct_from_each_other_and_from_leibniz_commit() {
        let settlement = UsdcSettlementEvidence::new(
            BASE_CHAIN_ID,
            [1u8; 32],
            [2u8; 32],
            1,
            9,
            [3u8; 32],
            Some(4),
        );
        let audit = AuditEvidence::new(1, [4u8; 32], [0u8; 32], [5u8; 32]);
        assert_eq!(settlement.tx_hash(), [2u8; 32]);
        assert_eq!(audit.sequence(), 1);
        assert_ne!(
            std::any::TypeId::of::<DclDecisionEvidence>(),
            std::any::TypeId::of::<UsdcSettlementEvidence>()
        );
        assert_ne!(
            std::any::TypeId::of::<DclDecisionEvidence>(),
            std::any::TypeId::of::<AuditEvidence>()
        );
        assert_ne!(
            std::any::TypeId::of::<UsdcSettlementEvidence>(),
            std::any::TypeId::of::<AuditEvidence>()
        );
        assert_ne!(
            std::any::TypeId::of::<VerifiedCommit>(),
            std::any::TypeId::of::<crate::leibniz::Commit>()
        );
    }

    #[test]
    fn facilitator_binding_uses_the_derived_action_id() {
        let secret = [0x7u8; 32];
        let authorization = authorization();
        let context = context_for(&authorization, true);
        let digest = action(4);
        let action_id = action_id_from_digest(&digest).unwrap();
        let mut preimage = b"DCL_ACTION_ID_V1".to_vec();
        preimage.extend_from_slice(digest.as_bytes());
        assert_eq!(action_id.as_str(), hex_encode(&keccak(&preimage)));
        assert_eq!(action_id.as_str().len(), 64);

        let body = DecisionBody::new(
            action_id,
            digest,
            context.clone(),
            authorization,
            Verdict::Commit,
            DecisionReason::try_new("allowed").unwrap(),
            EvidenceId::new([0x44; 32]),
        )
        .unwrap();
        let evidence = signed(body, &secret);
        let parsed = parse_decision_evidence(&decision_evidence_value(&evidence)).unwrap();
        assert_eq!(parsed, evidence);
        let expected = ExpectedBinding::for_payment(context, authorization, digest).unwrap();
        let record = assess_decision(&parsed, &expected, &test_address(&secret)).unwrap();
        assert_eq!(record.verdict(), Verdict::Commit);

        let wrong = ExpectedBinding::new(
            expected.context().clone(),
            *expected.authorization(),
            ActionId::try_new("action-1").unwrap(),
            *expected.action_digest(),
        )
        .unwrap();
        assert_eq!(
            assess_decision(&parsed, &wrong, &test_address(&secret)),
            Err(DecisionError::NotBound)
        );
    }
}
