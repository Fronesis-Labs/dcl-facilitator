//! Native Base settlement for an x402 v2 EIP-3009 authorization.
//!
//! The relayer signs one EIP-1559 transaction only after a durable verified
//! Oracle `COMMIT` has been revalidated. Signing promotes that row to
//! `consumed`, stores the raw transaction, and moves the payment to `Settling`
//! in one database commit. Broadcast uses the bytes read back from that row,
//! and only when the consumed `COMMIT`, payer signature, and settlement
//! evidence match. Recovery may sign only that same stored verified `COMMIT`.
//! It does not request a new Oracle decision. A local policy gate cannot
//! authorize a signature or a broadcast. A successful response is returned
//! only after a validated receipt is stored. Broadcast does not run a DCL
//! action.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::time::Instant;

use serde_json::{json, Value};

use crate::chain::{
    keccak, parse_signed_tx, recover_sender, recover_signer, signing_digest, to_checksum,
    transaction_hash, transfer_with_authorization_calldata, Authorization, BaseRpc, ChainError,
    Relayer, RpcReceipt, RpcTransaction, SignedTx, UnsignedTx, BASE_CHAIN_ID, NETWORK,
    USDC_ADDRESS,
};
use crate::evidence::{
    assess_decision, parse_decision_evidence, same_consumption, AuthorizationIdentity,
    ExpectedBinding, Verdict as DecisionVerdict,
};
use crate::leibniz::{ActionDigest, Commit, Decision, NoCommit, PaymentContext};
use crate::machine::PaymentState;
use crate::store::{
    PutOutcome, ReceiptObservation, SettlementEvidence, SignedCommit, SignedSettlement, Store,
    StoreError, StoredCommit, StoredDecision,
};
use crate::verify::{self, Checked, MIN_VALID_BEFORE_LEAD};

pub const UNEXPECTED_SETTLE: &str = "unexpected_settle_error";

pub struct SettleEnv<'a> {
    pub rpc: &'a BaseRpc,
    pub store: &'a Store,
    pub relayer: &'a Relayer,
    /// Oracle address that must have signed `decisionEvidence`. Settlement
    /// does not run when this check cannot be performed.
    pub oracle: [u8; 20],
    pub max_fee_per_gas: u128,
    pub receipt_timeout: Duration,
    /// Set by the recovery worker on shutdown. Receipt polling stops without
    /// treating the attempt as reverted or signing another transaction.
    pub stop: Option<&'a AtomicBool>,
}

/// Test seam that stops settlement after a durable point. The variants exist
/// only in the test build, where the suite constructs each one.
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum StopAfter {
    Commit,
    Broadcast,
    /// Receipt validated, terminal row not written yet.
    Confirmed,
}

#[cfg(test)]
type Halt = Option<StopAfter>;

#[cfg(not(test))]
#[derive(Clone, Copy)]
struct Halt;

#[cfg(test)]
fn halt_none() -> Halt {
    None
}

#[cfg(not(test))]
fn halt_none() -> Halt {
    Halt
}

#[cfg(test)]
fn halted(stop: Halt, point: StopAfter) -> bool {
    matches!(stop, Some(found) if found == point)
}

#[cfg(not(test))]
fn halted(stop: Halt) -> bool {
    match stop {
        Halt => false,
    }
}

fn halted_commit(stop: Halt) -> bool {
    #[cfg(test)]
    {
        halted(stop, StopAfter::Commit)
    }
    #[cfg(not(test))]
    {
        halted(stop)
    }
}

fn halted_broadcast(stop: Halt) -> bool {
    #[cfg(test)]
    {
        halted(stop, StopAfter::Broadcast)
    }
    #[cfg(not(test))]
    {
        halted(stop)
    }
}

fn halted_confirmed(stop: Halt) -> bool {
    #[cfg(test)]
    {
        halted(stop, StopAfter::Confirmed)
    }
    #[cfg(not(test))]
    {
        halted(stop)
    }
}

pub async fn settle_body(body: &Value, now: u64, env: &SettleEnv<'_>) -> Value {
    drive(body, now, env, halt_none()).await
}

pub fn rejected(reason: &str) -> Value {
    failure(reason, None, None)
}

async fn drive(body: &Value, now: u64, env: &SettleEnv<'_>, stop: Halt) -> Value {
    let (checked, blocked) = match verify::accept_local(body, now) {
        Ok(checked) => (checked, None),
        Err((reason, payer)) => match verify::accept_replay(body) {
            Ok(checked) => (checked, Some((reason, payer))),
            Err(_) => return failure(&reason, payer.as_deref(), None),
        },
    };
    let payer = checked.payer.clone();
    if blocked.is_none() && env.max_fee_per_gas == 0 {
        return failure(UNEXPECTED_SETTLE, Some(&payer), None);
    }
    let action = settlement_action(&checked);
    let context = match payment_context(&checked) {
        Ok(context) => context,
        Err(()) => return failure(UNEXPECTED_SETTLE, Some(&payer), None),
    };
    // Fixed before the same-payment lock. Time spent waiting is part of this
    // instant, so a wait cannot extend past `validBefore` minus the lead or
    // past the configured receipt timeout.
    let deadline = settle_deadline(
        now,
        &checked.authorization.valid_before,
        env.receipt_timeout,
    );
    let _payment = env.store.lock_payment(&context).await;
    match existing_payment(env, &checked, &context, &action, now, deadline).await {
        Ok(Some(response)) => return response,
        Ok(None) => {
            if let Some((reason, payer)) = blocked {
                return failure(&reason, payer.as_deref(), None);
            }
        }
        Err(()) => return failure(UNEXPECTED_SETTLE, Some(&payer), None),
    }
    let submitted = match body.get("decisionEvidence") {
        Some(value) => match parse_decision_evidence(value) {
            Ok(decision) => Some(decision),
            Err(_) => return failure(UNEXPECTED_SETTLE, Some(&payer), None),
        },
        None => None,
    };
    let expected = match expected_binding(&checked, &context, &action) {
        Ok(expected) => expected,
        Err(()) => return failure(UNEXPECTED_SETTLE, Some(&payer), None),
    };
    let submitted_record = match &submitted {
        Some(decision) => match assess_decision(decision, &expected, &env.oracle) {
            Ok(record) => Some(record),
            Err(_) => return failure(UNEXPECTED_SETTLE, Some(&payer), None),
        },
        None => None,
    };
    if let (Some(decision), Some(record)) = (&submitted, &submitted_record) {
        if record.verdict() == DecisionVerdict::NoCommit {
            let refusal = Decision::NoCommit(NoCommit::for_oracle(
                &context,
                &action,
                decision.body().reason().as_str(),
            ));
            if env
                .store
                .refuse(&context, &action, &refusal, record, decision)
                .await
                .is_err()
            {
                return failure(UNEXPECTED_SETTLE, Some(&payer), None);
            }
            return failure(UNEXPECTED_SETTLE, Some(&payer), None);
        }
    }
    let stored = match env.store.stored_commit(&context).await {
        Ok(stored) => stored,
        Err(_) => return failure(UNEXPECTED_SETTLE, Some(&payer), None),
    };
    match &stored {
        StoredCommit::Incomplete | StoredCommit::NoCommit => {
            return failure(UNEXPECTED_SETTLE, Some(&payer), None);
        }
        StoredCommit::Absent if submitted.is_none() => {
            return failure(UNEXPECTED_SETTLE, Some(&payer), None);
        }
        StoredCommit::Verified(existing) => {
            if let Some(record) = &submitted_record {
                if record.evidence_id() != existing.evidence.body().evidence_id()
                    || record.decision_digest() != existing.decision_digest
                {
                    return failure(UNEXPECTED_SETTLE, Some(&payer), None);
                }
            }
        }
        StoredCommit::Absent | StoredCommit::Consumed(_) => {}
    }
    let checked = match verify::accept_chain(checked, Some(env.rpc)).await {
        Ok(checked) => checked,
        Err((reason, payer)) => return failure(&reason, payer.as_deref(), None),
    };
    match env.rpc.chain_id().await {
        Ok(BASE_CHAIN_ID) => {}
        _ => return failure(UNEXPECTED_SETTLE, Some(&payer), None),
    }
    let calldata = transfer_with_authorization_calldata(&checked.authorization, &checked.signature);
    let plan = match preflight(env, &calldata).await {
        Ok(plan) => plan,
        Err(()) => return failure(UNEXPECTED_SETTLE, Some(&payer), None),
    };
    // Preflight has already consumed part of the absolute deadline. A closed
    // window never enters `Settling` and never broadcasts.
    if !deadline_open(deadline) {
        return failure(UNEXPECTED_SETTLE, Some(&payer), None);
    }
    let payment = match env.store.record_received(context.clone(), action).await {
        Ok(PutOutcome::Created(payment) | PutOutcome::Existing(payment)) => payment,
        Err(StoreError::Conflict) => return failure(UNEXPECTED_SETTLE, Some(&payer), None),
        Err(_) => return failure(UNEXPECTED_SETTLE, Some(&payer), None),
    };

    let payment = if payment.state() == PaymentState::Received {
        match env.store.mark_verified(&context, &action).await {
            Ok(payment) => payment,
            Err(_) => return failure(UNEXPECTED_SETTLE, Some(&payer), None),
        }
    } else {
        payment
    };
    let payment = if payment.state() == PaymentState::Verified {
        let (Some(decision), Some(record)) = (&submitted, &submitted_record) else {
            return failure(UNEXPECTED_SETTLE, Some(&payer), None);
        };
        let commit = Commit::for_oracle(&context, &action, decision.body().reason().as_str());
        match env
            .store
            .persist_verified_commit(
                &context,
                &action,
                &commit,
                record,
                decision,
                &checked.signature,
            )
            .await
        {
            Ok(payment) => payment,
            Err(_) => return failure(UNEXPECTED_SETTLE, Some(&payer), None),
        }
    } else {
        payment
    };

    match payment.state() {
        PaymentState::Settled => {
            let hash = evidence_hash(env.store, &context).await;
            return success(&payer, hash);
        }
        PaymentState::SettleFailed => {
            let hash = evidence_hash(env.store, &context).await;
            return failure(UNEXPECTED_SETTLE, Some(&payer), hash);
        }
        PaymentState::Rejected => return failure(UNEXPECTED_SETTLE, Some(&payer), None),
        PaymentState::Settling | PaymentState::SettlementUnknown => {
            return resume(
                env,
                &checked,
                &context,
                &action,
                payment.state(),
                now,
                deadline,
            )
            .await;
        }
        PaymentState::Committed => {}
        _ => return failure(UNEXPECTED_SETTLE, Some(&payer), None),
    }
    match env.store.evidence(&context).await {
        Ok(Some(_)) => {
            return resume(
                env,
                &checked,
                &context,
                &action,
                payment.state(),
                now,
                deadline,
            )
            .await
        }
        Ok(None) => {}
        Err(_) => return failure(UNEXPECTED_SETTLE, Some(&payer), None),
    }

    if !deadline_open(deadline) {
        return failure(UNEXPECTED_SETTLE, Some(&payer), None);
    }
    let Some((commit, record, decision)) =
        admit_verified_commit(env, &checked, &context, &action).await
    else {
        return failure(UNEXPECTED_SETTLE, Some(&payer), None);
    };
    if let Some(submitted_record) = &submitted_record {
        if !same_consumption(submitted_record, &record) {
            return failure(UNEXPECTED_SETTLE, Some(&payer), None);
        }
    }
    sign_verified_commit(
        env,
        Admitted {
            checked: &checked,
            context: &context,
            action: &action,
            commit: &commit,
            record: &record,
            decision: &decision,
        },
        calldata,
        plan,
        deadline,
        stop,
    )
    .await
}

async fn existing_payment(
    env: &SettleEnv<'_>,
    checked: &Checked,
    context: &PaymentContext,
    action: &ActionDigest,
    now: u64,
    deadline: Instant,
) -> Result<Option<Value>, ()> {
    let payment = match env
        .store
        .get(context.network(), context.payer(), context.nonce())
        .await
    {
        Ok(payment) => payment,
        Err(StoreError::NotFound) => return Ok(None),
        Err(_) => return Err(()),
    };
    if payment.action() != action || payment.context() != context {
        return Ok(Some(failure(UNEXPECTED_SETTLE, Some(&checked.payer), None)));
    }
    match payment.state() {
        PaymentState::Settled => {
            let hash = evidence_hash(env.store, context).await;
            Ok(Some(success(&checked.payer, hash)))
        }
        PaymentState::SettleFailed => {
            let hash = evidence_hash(env.store, context).await;
            Ok(Some(failure(UNEXPECTED_SETTLE, Some(&checked.payer), hash)))
        }
        PaymentState::Rejected => Ok(Some(failure(UNEXPECTED_SETTLE, Some(&checked.payer), None))),
        PaymentState::Settling | PaymentState::SettlementUnknown => {
            if env.rpc.chain_id().await.ok() != Some(BASE_CHAIN_ID) {
                return Ok(Some(failure(
                    UNEXPECTED_SETTLE,
                    Some(&checked.payer),
                    evidence_hash(env.store, context).await,
                )));
            }
            Ok(Some(
                resume(
                    env,
                    checked,
                    context,
                    action,
                    payment.state(),
                    now,
                    deadline,
                )
                .await,
            ))
        }
        PaymentState::Received | PaymentState::Verified | PaymentState::Committed => Ok(None),
    }
}

async fn resume(
    env: &SettleEnv<'_>,
    checked: &Checked,
    context: &PaymentContext,
    action: &ActionDigest,
    state: PaymentState,
    now: u64,
    deadline: Instant,
) -> Value {
    let evidence = match env.store.evidence(context).await {
        Ok(Some(evidence)) => evidence,
        _ => {
            remember_unknown(env, context, action, state).await;
            return failure(UNEXPECTED_SETTLE, Some(&checked.payer), None);
        }
    };
    resume_evidence(env, checked, context, action, evidence, now, deadline).await
}

/// Revalidate the stored Oracle decision and the exact raw transaction.
///
/// The binding is rebuilt from the authorization stored with the payment.
/// The signature is checked against `ORACLE_ADDRESS`. Nothing here asks the
/// Oracle for a new decision.
async fn stored_oracle_binds_raw(
    env: &SettleEnv<'_>,
    context: &PaymentContext,
    raw: &[u8],
    hash: [u8; 32],
) -> bool {
    let payment = match env
        .store
        .get(context.network(), context.payer(), context.nonce())
        .await
    {
        Ok(payment) if payment.context() == context => payment,
        _ => return false,
    };
    let stored = match stored_checked(env, context).await {
        Some(stored) if settlement_action(&stored) == *payment.action() => stored,
        _ => return false,
    };
    let decision = match env.store.stored_commit(context).await {
        Ok(StoredCommit::Consumed(decision)) => decision,
        _ => return false,
    };
    let Some(raw_tx_hash) = decision.raw_tx_hash else {
        return false;
    };
    let Some(payer_signature) = decision.payer_signature else {
        return false;
    };
    if payer_signature != stored.signature {
        return false;
    }
    if raw_tx_hash != hash || transaction_hash(raw) != raw_tx_hash {
        return false;
    }
    let recomputed = match decision.evidence.decision_digest() {
        Ok(digest) if digest == decision.decision_digest => digest,
        _ => return false,
    };
    let expected = match expected_binding(&stored, payment.context(), payment.action()) {
        Ok(expected) => expected,
        Err(()) => return false,
    };
    let record = match assess_decision(&decision.evidence, &expected, &env.oracle) {
        Ok(record) => record,
        Err(_) => return false,
    };
    if record.verdict() != DecisionVerdict::Commit || record.decision_digest() != recomputed {
        return false;
    }
    let parsed = match parse_signed_tx(raw) {
        Ok(parsed) => parsed,
        Err(_) => return false,
    };
    if parsed.chain_id != BASE_CHAIN_ID || parsed.to != USDC_ADDRESS || parsed.value != 0 {
        return false;
    }
    let calldata = transfer_with_authorization_calldata(&stored.authorization, &stored.signature);
    if parsed.data != calldata {
        return false;
    }
    let signer = match recover_signer(&signing_digest(&stored.authorization), &stored.signature) {
        Ok(signer) => signer,
        Err(_) => return false,
    };
    if signer != stored.authorization.from {
        return false;
    }
    matches!(
        env.store.evidence(context).await,
        Ok(Some(evidence))
            if evidence.raw_tx == raw
                && evidence.tx_hash == hash
                && evidence.calldata == calldata
    )
}

fn expected_binding(
    checked: &Checked,
    context: &PaymentContext,
    action: &ActionDigest,
) -> Result<ExpectedBinding, ()> {
    ExpectedBinding::for_payment(context.clone(), authorization_identity(checked), *action)
        .map_err(|_| ())
}

pub(crate) fn authorization_identity(checked: &Checked) -> AuthorizationIdentity {
    let auth = &checked.authorization;
    AuthorizationIdentity::new(
        BASE_CHAIN_ID,
        USDC_ADDRESS,
        auth.from,
        auth.to,
        auth.value,
        auth.valid_after,
        auth.valid_before,
        auth.nonce,
    )
}

async fn resume_evidence(
    env: &SettleEnv<'_>,
    checked: &Checked,
    context: &PaymentContext,
    action: &ActionDigest,
    evidence: SettlementEvidence,
    now: u64,
    deadline: Instant,
) -> Value {
    let hash = evidence.tx_hash;
    if !stored_oracle_binds_raw(env, context, &evidence.raw_tx, hash).await {
        tracing::warn!(
            "refusing to resume a settlement whose stored oracle evidence does not bind"
        );
        return failure(UNEXPECTED_SETTLE, Some(&checked.payer), Some(hash));
    }
    if transaction_hash(&evidence.raw_tx) != hash {
        remember_unknown(env, context, action, PaymentState::Settling).await;
        return failure(UNEXPECTED_SETTLE, Some(&checked.payer), Some(hash));
    }
    match env.rpc.receipt(hash).await {
        Ok(Some(_)) => {
            return finish_hash(env, checked, context, action, hash, deadline, halt_none()).await
        }
        Ok(None) => {}
        Err(_) => {
            remember_unknown(env, context, action, PaymentState::Settling).await;
            return failure(UNEXPECTED_SETTLE, Some(&checked.payer), Some(hash));
        }
    }
    match env.rpc.transaction(hash).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            if authorization_expired(now, &checked.authorization.valid_before) {
                let _ = env.store.expire_unmined(context, action).await;
                return failure(UNEXPECTED_SETTLE, Some(&checked.payer), Some(hash));
            }
            if !deadline_open(deadline) {
                remember_unknown(env, context, action, PaymentState::Settling).await;
                return failure(UNEXPECTED_SETTLE, Some(&checked.payer), Some(hash));
            }
            if broadcast_stored(env, context, &evidence.raw_tx, hash)
                .await
                .is_err()
            {
                remember_unknown(env, context, action, PaymentState::Settling).await;
                return failure(UNEXPECTED_SETTLE, Some(&checked.payer), Some(hash));
            }
        }
        Err(_) => {
            remember_unknown(env, context, action, PaymentState::Settling).await;
            return failure(UNEXPECTED_SETTLE, Some(&checked.payer), Some(hash));
        }
    }
    finish_hash(env, checked, context, action, hash, deadline, halt_none()).await
}

async fn finish_hash(
    env: &SettleEnv<'_>,
    checked: &Checked,
    context: &PaymentContext,
    action: &ActionDigest,
    hash: [u8; 32],
    deadline: Instant,
    stop: Halt,
) -> Value {
    let verdict = match judge(env, checked, context, hash, deadline).await {
        Ok(verdict) => verdict,
        Err(()) => {
            remember_unknown(env, context, action, PaymentState::Settling).await;
            return failure(UNEXPECTED_SETTLE, Some(&checked.payer), Some(hash));
        }
    };
    if halted_confirmed(stop) {
        if let Verdict::Confirmed(_) = verdict {
            return failure(UNEXPECTED_SETTLE, Some(&checked.payer), Some(hash));
        }
    }
    let current = match env
        .store
        .get(context.network(), context.payer(), context.nonce())
        .await
    {
        Ok(payment) => payment.state(),
        Err(_) => {
            return failure(UNEXPECTED_SETTLE, Some(&checked.payer), Some(hash));
        }
    };
    match verdict {
        Verdict::Confirmed(observation) => {
            if env
                .store
                .conclude(context, action, &observation, PaymentState::Settled)
                .await
                .is_err()
            {
                remember_unknown(env, context, action, current).await;
                return failure(UNEXPECTED_SETTLE, Some(&checked.payer), Some(hash));
            }
            success(&checked.payer, Some(hash))
        }
        Verdict::Reverted(observation) => {
            if env
                .store
                .conclude(context, action, &observation, PaymentState::SettleFailed)
                .await
                .is_err()
            {
                remember_unknown(env, context, action, current).await;
            }
            failure(UNEXPECTED_SETTLE, Some(&checked.payer), Some(hash))
        }
        Verdict::Inconclusive => {
            remember_unknown(env, context, action, current).await;
            failure(UNEXPECTED_SETTLE, Some(&checked.payer), Some(hash))
        }
    }
}

async fn judge(
    env: &SettleEnv<'_>,
    checked: &Checked,
    context: &PaymentContext,
    hash: [u8; 32],
    deadline: Instant,
) -> Result<Verdict, ()> {
    if env.rpc.chain_id().await.map_err(|_| ())? != BASE_CHAIN_ID {
        return Ok(Verdict::Inconclusive);
    }
    let evidence = env
        .store
        .evidence(context)
        .await
        .map_err(|_| ())?
        .ok_or(())?;
    if evidence.tx_hash != hash || transaction_hash(&evidence.raw_tx) != hash {
        return Ok(Verdict::Inconclusive);
    }
    // The deadline was fixed before preflight. Reaching it is not a revert,
    // so a broadcast payment with no receipt stays unresolved.
    let receipt = match wait_receipt(env, hash, deadline).await {
        Ok(Some(receipt)) => receipt,
        Ok(None) | Err(_) => return Ok(Verdict::Inconclusive),
    };
    let transaction = match env.rpc.transaction(hash).await {
        Ok(Some(transaction)) => transaction,
        Ok(None) | Err(_) => return Ok(Verdict::Inconclusive),
    };
    let canonical = match env
        .rpc
        .block(&format!("0x{:x}", receipt.block_number))
        .await
    {
        Ok(block) => block.hash == receipt.block_hash,
        Err(_) => false,
    };
    if !identity_matches(
        &transaction,
        &receipt,
        &evidence,
        env.relayer.address(),
        hash,
    ) || !canonical
    {
        return Ok(Verdict::Inconclusive);
    }
    if receipt.status == 0 {
        return Ok(Verdict::Reverted(ReceiptObservation {
            status: 0,
            block_number: receipt.block_number,
            block_hash: receipt.block_hash,
            transfer_log_index: None,
        }));
    }
    if receipt.status != 1 {
        return Ok(Verdict::Inconclusive);
    }
    let Some(log_index) = matching_transfer(&receipt, &checked.authorization) else {
        return Ok(Verdict::Inconclusive);
    };
    match env
        .rpc
        .authorization_used(checked.authorization.from, checked.authorization.nonce)
        .await
    {
        Ok(true) => Ok(Verdict::Confirmed(ReceiptObservation {
            status: 1,
            block_number: receipt.block_number,
            block_hash: receipt.block_hash,
            transfer_log_index: Some(log_index),
        })),
        _ => Ok(Verdict::Inconclusive),
    }
}

fn identity_matches(
    transaction: &RpcTransaction,
    receipt: &RpcReceipt,
    evidence: &SettlementEvidence,
    relayer: [u8; 20],
    hash: [u8; 32],
) -> bool {
    transaction.hash == hash
        && receipt.hash == hash
        && transaction.from == relayer
        && transaction.to == Some(USDC_ADDRESS)
        && transaction.nonce == evidence.relayer_nonce
        && transaction.value == [0u8; 32]
        && transaction.input == evidence.calldata
}

fn matching_transfer(receipt: &RpcReceipt, authorization: &Authorization) -> Option<u64> {
    let topic = keccak(b"Transfer(address,address,uint256)");
    let from = pad_address(authorization.from);
    let to = pad_address(authorization.to);
    receipt.logs.iter().find_map(|log| {
        if log.address != USDC_ADDRESS || log.topics.len() < 3 {
            return None;
        }
        if log.topics[0] != topic || log.topics[1] != from || log.topics[2] != to {
            return None;
        }
        if log.data.as_slice() != authorization.value {
            return None;
        }
        Some(log.index)
    })
}

async fn wait_receipt(
    env: &SettleEnv<'_>,
    hash: [u8; 32],
    deadline: Instant,
) -> Result<Option<RpcReceipt>, ChainError> {
    loop {
        if env.stop.is_some_and(|stop| stop.load(Ordering::SeqCst)) {
            return Ok(None);
        }
        if let Some(receipt) = env.rpc.receipt(hash).await? {
            return Ok(Some(receipt));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

pub(crate) enum Pass {
    Idle,
    Progress,
    Inconclusive,
}

/// One pass over persisted attempts.
///
/// `SettlementUnknown` rows are resumed from their consumed transaction and
/// are not signed again. A `Committed` payment is signed only when it has a
/// complete stored verified `COMMIT` and no settlement evidence.
pub(crate) async fn recover_pass(env: &SettleEnv<'_>, now: u64) -> Pass {
    let payments = match env.store.proven_unknown().await {
        Ok(payments) => payments,
        Err(_) => return Pass::Inconclusive,
    };
    let mut progress = false;
    let mut inconclusive = false;
    for payment in payments {
        if env.stop.is_some_and(|stop| stop.load(Ordering::SeqCst)) {
            break;
        }
        match recover_payment(env, payment.context(), now).await {
            Attempt::Terminal => progress = true,
            Attempt::Inconclusive => inconclusive = true,
        }
    }
    let awaiting = match env.store.verified_commits_awaiting_signature().await {
        Ok(payments) => payments,
        Err(_) => return Pass::Inconclusive,
    };
    for payment in awaiting {
        if env.stop.is_some_and(|stop| stop.load(Ordering::SeqCst)) {
            break;
        }
        match recover_signature(env, payment.context(), now).await {
            Attempt::Terminal => progress = true,
            Attempt::Inconclusive => inconclusive = true,
        }
    }
    if inconclusive {
        Pass::Inconclusive
    } else if progress {
        Pass::Progress
    } else {
        Pass::Idle
    }
}

enum Attempt {
    Terminal,
    Inconclusive,
}

async fn recover_payment(env: &SettleEnv<'_>, context: &PaymentContext, now: u64) -> Attempt {
    let _guard = env.store.lock_payment(context).await;
    let payment = match env
        .store
        .get(context.network(), context.payer(), context.nonce())
        .await
    {
        Ok(payment) => payment,
        Err(_) => return Attempt::Inconclusive,
    };
    if payment.context() != context {
        return Attempt::Inconclusive;
    }
    match payment.state() {
        PaymentState::Settled | PaymentState::SettleFailed => return Attempt::Terminal,
        PaymentState::SettlementUnknown => {}
        _ => return Attempt::Inconclusive,
    }
    let Some(checked) = stored_checked(env, context).await else {
        return Attempt::Inconclusive;
    };
    if settlement_action(&checked) != *payment.action() {
        tracing::warn!("stored authorization does not match the payment action");
        return Attempt::Inconclusive;
    }
    let deadline = settle_deadline(
        now,
        &checked.authorization.valid_before,
        env.receipt_timeout,
    );
    let _ = resume(
        env,
        &checked,
        context,
        payment.action(),
        PaymentState::SettlementUnknown,
        now,
        deadline,
    )
    .await;
    match env
        .store
        .get(context.network(), context.payer(), context.nonce())
        .await
    {
        Ok(payment)
            if matches!(
                payment.state(),
                PaymentState::Settled | PaymentState::SettleFailed
            ) =>
        {
            Attempt::Terminal
        }
        _ => Attempt::Inconclusive,
    }
}

async fn recover_signature(env: &SettleEnv<'_>, context: &PaymentContext, now: u64) -> Attempt {
    let _guard = env.store.lock_payment(context).await;
    let payment = match env
        .store
        .get(context.network(), context.payer(), context.nonce())
        .await
    {
        Ok(payment) if payment.context() == context => payment,
        _ => return Attempt::Inconclusive,
    };
    if payment.state() != PaymentState::Committed {
        return Attempt::Inconclusive;
    }
    match env.store.evidence(context).await {
        Ok(None) => {}
        _ => return Attempt::Inconclusive,
    }
    let stored = match env.store.stored_commit(context).await {
        Ok(StoredCommit::Verified(stored)) => stored,
        _ => return Attempt::Inconclusive,
    };
    let Some(checked) = checked_from_commit(context, &stored) else {
        return Attempt::Inconclusive;
    };
    let action = *payment.action();
    if settlement_action(&checked) != action {
        return Attempt::Inconclusive;
    }
    if env.rpc.chain_id().await.ok() != Some(BASE_CHAIN_ID) {
        return Attempt::Inconclusive;
    }
    let deadline = settle_deadline(
        now,
        &checked.authorization.valid_before,
        env.receipt_timeout,
    );
    if !deadline_open(deadline) {
        return Attempt::Inconclusive;
    }
    let calldata = transfer_with_authorization_calldata(&checked.authorization, &checked.signature);
    let Ok(plan) = preflight(env, &calldata).await else {
        return Attempt::Inconclusive;
    };
    let Some((commit, record, decision)) =
        admit_verified_commit(env, &checked, context, &action).await
    else {
        return Attempt::Inconclusive;
    };
    let _ = sign_verified_commit(
        env,
        Admitted {
            checked: &checked,
            context,
            action: &action,
            commit: &commit,
            record: &record,
            decision: &decision,
        },
        calldata,
        plan,
        deadline,
        halt_none(),
    )
    .await;
    match env
        .store
        .get(context.network(), context.payer(), context.nonce())
        .await
    {
        Ok(payment)
            if matches!(
                payment.state(),
                PaymentState::Settled | PaymentState::SettleFailed
            ) =>
        {
            Attempt::Terminal
        }
        _ => Attempt::Inconclusive,
    }
}

/// Revalidate the stored verified `COMMIT` before any relayer signature.
async fn admit_verified_commit(
    env: &SettleEnv<'_>,
    checked: &Checked,
    context: &PaymentContext,
    action: &ActionDigest,
) -> Option<(
    Commit,
    crate::evidence::ConsumptionRecord,
    crate::evidence::DclDecisionEvidence,
)> {
    let StoredCommit::Verified(stored) = env.store.stored_commit(context).await.ok()? else {
        return None;
    };
    let payer_signature = stored.payer_signature?;
    if payer_signature != checked.signature || !payer_signature_binds(checked) {
        return None;
    }
    let recomputed = stored.evidence.decision_digest().ok()?;
    if recomputed != stored.decision_digest {
        return None;
    }
    let expected = expected_binding(checked, context, action).ok()?;
    let record = assess_decision(&stored.evidence, &expected, &env.oracle).ok()?;
    if record.verdict() != DecisionVerdict::Commit || record.decision_digest() != recomputed {
        return None;
    }
    let commit = Commit::for_oracle(context, action, stored.evidence.body().reason().as_str());
    if !commit.binds(context, action) {
        return None;
    }
    Some((commit, record, stored.evidence))
}

fn checked_from_commit(context: &PaymentContext, stored: &StoredDecision) -> Option<Checked> {
    let authorization = stored.evidence.body().authorization();
    let signature = stored.payer_signature?;
    Some(Checked {
        authorization: Authorization {
            from: authorization.payer(),
            to: authorization.recipient(),
            value: authorization.value(),
            valid_after: authorization.valid_after(),
            valid_before: authorization.valid_before(),
            nonce: authorization.nonce(),
        },
        signature,
        payer: context.payer().to_string(),
    })
}

fn payer_signature_binds(checked: &Checked) -> bool {
    recover_signer(&signing_digest(&checked.authorization), &checked.signature)
        .ok()
        .is_some_and(|signer| signer == checked.authorization.from)
}

struct Admitted<'a> {
    checked: &'a Checked,
    context: &'a PaymentContext,
    action: &'a ActionDigest,
    commit: &'a Commit,
    record: &'a crate::evidence::ConsumptionRecord,
    decision: &'a crate::evidence::DclDecisionEvidence,
}

async fn sign_verified_commit(
    env: &SettleEnv<'_>,
    admitted: Admitted<'_>,
    calldata: Vec<u8>,
    plan: GasPlan,
    deadline: Instant,
    stop: Halt,
) -> Value {
    let Admitted {
        checked,
        context,
        action,
        commit,
        record,
        decision,
    } = admitted;
    let payer = checked.payer.clone();
    let claim = match env.store.claim_signing(context).await {
        Ok(claim) => claim,
        Err(_) => return failure(UNEXPECTED_SETTLE, Some(&payer), None),
    };
    let signed = {
        let _nonce = env.store.lock_nonces().await;
        let pending = match env.rpc.pending_nonce(env.relayer.address()).await {
            Ok(pending) => pending,
            Err(_) => {
                let _ = env.store.release_signing_claim(&claim).await;
                return failure(UNEXPECTED_SETTLE, Some(&payer), None);
            }
        };
        let nonce = match env
            .store
            .next_relayer_nonce(&to_checksum(&env.relayer.address()), pending)
            .await
        {
            Ok(nonce) => nonce,
            Err(_) => {
                let _ = env.store.release_signing_claim(&claim).await;
                return failure(UNEXPECTED_SETTLE, Some(&payer), None);
            }
        };
        let signed = match env.relayer.sign(&UnsignedTx {
            chain_id: BASE_CHAIN_ID,
            nonce,
            max_priority_fee: plan.tip,
            max_fee: plan.max_fee,
            gas_limit: plan.gas_limit,
            to: USDC_ADDRESS,
            value: 0,
            data: calldata.clone(),
        }) {
            Ok(signed) => signed,
            Err(_) => {
                let _ = env.store.release_signing_claim(&claim).await;
                return failure(UNEXPECTED_SETTLE, Some(&payer), None);
            }
        };
        // The lease is not refreshed here. A pause that outlives it lets
        // another process take the claim; this token then fails `commit_signed`.
        #[cfg(test)]
        if let Some(gate) = env.store.sign_gate().await {
            gate.entered.store(true, Ordering::SeqCst);
            while !gate.release.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        if !signed_matches(&signed, &calldata, nonce, plan, env) {
            let _ = env.store.release_signing_claim(&claim).await;
            return failure(UNEXPECTED_SETTLE, Some(&payer), None);
        }
        let draft = SignedSettlement {
            value: checked.authorization.value,
            valid_after: checked.authorization.valid_after,
            valid_before: checked.authorization.valid_before,
            signature: checked.signature,
            calldata,
            relayer_address: to_checksum(&env.relayer.address()),
            relayer_nonce: nonce,
            tx_hash: signed.hash,
            raw_tx: signed.raw.clone(),
        };
        if env
            .store
            .commit_signed(SignedCommit {
                context,
                action,
                commit,
                signed: &draft,
                record,
                evidence: decision,
                claim: &claim,
            })
            .await
            .is_err()
        {
            let _ = env.store.release_signing_claim(&claim).await;
            return failure(UNEXPECTED_SETTLE, Some(&payer), None);
        }
        signed
    };
    // Broadcast only the row that committed. A crash after this read still
    // has the same bytes; a crash before it never reached the network.
    let persisted = match env.store.evidence(context).await {
        Ok(Some(evidence)) if evidence.raw_tx == signed.raw && evidence.tx_hash == signed.hash => {
            evidence
        }
        _ => {
            let _ = env.store.mark_unknown(context, action).await;
            return failure(UNEXPECTED_SETTLE, Some(&payer), Some(signed.hash));
        }
    };
    if halted_commit(stop) {
        return failure(UNEXPECTED_SETTLE, Some(&payer), Some(persisted.tx_hash));
    }
    if let Err(()) = broadcast_stored(env, context, &persisted.raw_tx, persisted.tx_hash).await {
        let _ = env.store.mark_unknown(context, action).await;
        return failure(UNEXPECTED_SETTLE, Some(&payer), Some(persisted.tx_hash));
    }
    if halted_broadcast(stop) {
        return failure(UNEXPECTED_SETTLE, Some(&payer), Some(persisted.tx_hash));
    }
    finish_hash(
        env,
        checked,
        context,
        action,
        persisted.tx_hash,
        deadline,
        stop,
    )
    .await
}

async fn stored_checked(
    env: &SettleEnv<'_>,
    context: &PaymentContext,
) -> Option<crate::verify::Checked> {
    let stored = env.store.stored_authorization(context).await.ok()??;
    let from = address_bytes(&stored.payer)?;
    let to = address_bytes(&stored.pay_to)?;
    let nonce = word_bytes(&stored.nonce)?;
    Some(crate::verify::Checked {
        authorization: Authorization {
            from,
            to,
            value: stored.value,
            valid_after: stored.valid_after,
            valid_before: stored.valid_before,
            nonce,
        },
        signature: stored.signature,
        payer: stored.payer,
    })
}

fn address_bytes(value: &str) -> Option<[u8; 20]> {
    fixed_hex(value, 20).and_then(|bytes| bytes.try_into().ok())
}

fn word_bytes(value: &str) -> Option<[u8; 32]> {
    fixed_hex(value, 32).and_then(|bytes| bytes.try_into().ok())
}

fn fixed_hex(value: &str, width: usize) -> Option<Vec<u8>> {
    let hex = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))?;
    if hex.len() != width * 2 {
        return None;
    }
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(width);
    let mut index = 0;
    while index < bytes.len() {
        let high = hex_nibble(bytes[index])?;
        let low = hex_nibble(bytes[index + 1])?;
        out.push((high << 4) | low);
        index += 2;
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// One absolute poll deadline for this request, fixed before the payment lock.
/// Later waits use what remains of this instant; they do not start the
/// configured budget again. The budget is still `min(configured timeout,
/// validBefore - 6 seconds - now)`.
fn settle_deadline(now: u64, valid_before: &[u8; 32], configured: Duration) -> Instant {
    match receipt_budget(now, valid_before, configured) {
        Ok(budget) => Instant::now() + budget,
        Err(()) => Instant::now(),
    }
}

fn deadline_open(deadline: Instant) -> bool {
    Instant::now() < deadline
}

/// The EIP-3009 authorization itself is no longer valid. This is stronger
/// than the receipt poll deadline, which stops six seconds earlier.
fn authorization_expired(now: u64, valid_before: &[u8; 32]) -> bool {
    unix_seconds(valid_before).is_some_and(|deadline| now >= deadline)
}

/// How long a receipt poll may run without crossing `validBefore` minus the
/// six-second lead. `Err` means that wait does not fit, so settlement must not
/// start. A far-future `validBefore` uses the configured timeout unchanged.
fn receipt_budget(now: u64, valid_before: &[u8; 32], configured: Duration) -> Result<Duration, ()> {
    if configured.is_zero() {
        return Err(());
    }
    let Some(deadline) = unix_seconds(valid_before) else {
        return Ok(configured);
    };
    let latest = deadline.checked_sub(MIN_VALID_BEFORE_LEAD).ok_or(())?;
    if now >= latest {
        return Err(());
    }
    Ok(configured.min(Duration::from_secs(latest - now)))
}

fn unix_seconds(word: &[u8; 32]) -> Option<u64> {
    if word[..24].iter().any(|byte| *byte != 0) {
        return None;
    }
    let mut seconds = [0u8; 8];
    seconds.copy_from_slice(&word[24..]);
    Some(u64::from_be_bytes(seconds))
}

async fn broadcast_stored(
    env: &SettleEnv<'_>,
    context: &PaymentContext,
    raw: &[u8],
    hash: [u8; 32],
) -> Result<(), ()> {
    if !stored_oracle_binds_raw(env, context, raw, hash).await {
        return Err(());
    }
    if transaction_hash(raw) != hash {
        return Err(());
    }
    let parsed = parse_signed_tx(raw).map_err(|_| ())?;
    if parsed.chain_id != BASE_CHAIN_ID
        || parsed.to != USDC_ADDRESS
        || parsed.value != 0
        || parsed.max_fee > env.max_fee_per_gas
    {
        return Err(());
    }
    match env.rpc.send_raw(raw).await {
        Ok(returned) if returned == hash => Ok(()),
        _ => Err(()),
    }
}

async fn remember_unknown(
    env: &SettleEnv<'_>,
    context: &PaymentContext,
    action: &ActionDigest,
    state: PaymentState,
) {
    if state == PaymentState::Settling {
        let _ = env.store.mark_unknown(context, action).await;
    }
}

async fn evidence_hash(store: &Store, context: &PaymentContext) -> Option<[u8; 32]> {
    store
        .evidence(context)
        .await
        .ok()
        .flatten()
        .map(|evidence| evidence.tx_hash)
}

enum Verdict {
    Confirmed(ReceiptObservation),
    Reverted(ReceiptObservation),
    Inconclusive,
}

struct GasPlan {
    tip: u128,
    max_fee: u128,
    gas_limit: u64,
}

async fn preflight(env: &SettleEnv<'_>, calldata: &[u8]) -> Result<GasPlan, ()> {
    let block = env.rpc.block("latest").await.map_err(|_| ())?;
    let base = block.base_fee.ok_or(())?;
    let tip = env.rpc.max_priority_fee().await.map_err(|_| ())?;
    let max_fee = base
        .checked_mul(2)
        .and_then(|fee| fee.checked_add(tip))
        .ok_or(())?;
    if max_fee > env.max_fee_per_gas || tip > max_fee {
        return Err(());
    }
    let estimate = env
        .rpc
        .estimate_gas(env.relayer.address(), calldata)
        .await
        .map_err(|_| ())?;
    if estimate == 0 {
        return Err(());
    }
    let gas_limit = estimate.checked_add(estimate / 5).ok_or(())?;
    let cost = u128::from(gas_limit).checked_mul(max_fee).ok_or(())?;
    let balance = env
        .rpc
        .native_balance(env.relayer.address())
        .await
        .map_err(|_| ())?;
    if balance < u128_word(cost) {
        return Err(());
    }
    Ok(GasPlan {
        tip,
        max_fee,
        gas_limit,
    })
}

fn signed_matches(
    signed: &SignedTx,
    calldata: &[u8],
    nonce: u64,
    plan: GasPlan,
    env: &SettleEnv<'_>,
) -> bool {
    if transaction_hash(&signed.raw) != signed.hash {
        return false;
    }
    let Ok(parsed) = parse_signed_tx(&signed.raw) else {
        return false;
    };
    let Ok(sender) = recover_sender(&signed.raw) else {
        return false;
    };
    parsed.chain_id == BASE_CHAIN_ID
        && parsed.data == calldata
        && parsed.nonce == nonce
        && parsed.value == 0
        && parsed.to == USDC_ADDRESS
        && parsed.max_fee == plan.max_fee
        && parsed.max_priority_fee == plan.tip
        && parsed.max_fee <= env.max_fee_per_gas
        && sender == env.relayer.address()
}

pub(crate) fn settlement_action(checked: &Checked) -> ActionDigest {
    let auth = &checked.authorization;
    let mut bytes = Vec::with_capacity(20 + 20 + 20 + 32 * 4 + 65);
    bytes.extend_from_slice(NETWORK.as_bytes());
    bytes.extend_from_slice(&USDC_ADDRESS);
    bytes.extend_from_slice(&auth.from);
    bytes.extend_from_slice(&auth.to);
    bytes.extend_from_slice(&auth.value);
    bytes.extend_from_slice(&auth.valid_after);
    bytes.extend_from_slice(&auth.valid_before);
    bytes.extend_from_slice(&auth.nonce);
    bytes.extend_from_slice(&checked.signature);
    ActionDigest::new(keccak(&bytes))
}

pub(crate) fn payment_context(checked: &Checked) -> Result<PaymentContext, ()> {
    PaymentContext::try_new(
        NETWORK,
        &checked.payer,
        to_checksum(&checked.authorization.to),
        to_checksum(&USDC_ADDRESS),
        format!("0x{}", hex_encode(&checked.authorization.nonce)),
    )
    .map_err(|_| ())
}

fn pad_address(address: [u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(&address);
    word
}

fn u128_word(value: u128) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[16..].copy_from_slice(&value.to_be_bytes());
    word
}

fn failure(reason: &str, payer: Option<&str>, tx: Option<[u8; 32]>) -> Value {
    let mut body = json!({
        "success": false,
        "network": NETWORK,
        "transaction": tx.map(hash_hex).unwrap_or_default(),
        "errorReason": reason,
    });
    if let Some(payer) = payer {
        body["payer"] = json!(payer);
    }
    body
}

fn success(payer: &str, tx: Option<[u8; 32]>) -> Value {
    let Some(tx) = tx else {
        return failure(UNEXPECTED_SETTLE, Some(payer), None);
    };
    json!({
        "success": true,
        "network": NETWORK,
        "payer": payer,
        "transaction": hash_hex(tx),
    })
}

fn hash_hex(hash: [u8; 32]) -> String {
    format!("0x{}", hex_encode(&hash))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{signing_digest, test_address, test_sign, EIP712_NAME, EIP712_VERSION};
    use crate::store::StoredCommit;
    use crate::verify::INVALID_SIGNATURE;
    use axum::routing::post;
    use axum::{Json, Router};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    const NOW: u64 = 1_700_000_000;
    const CEILING: u128 = 10_000_000_000;
    /// Fixture budget for settlements that are not testing the deadline.
    /// Long enough that a busy machine can finish preflight before it closes.
    /// The production default is unchanged.
    const TEST_RECEIPT_TIMEOUT: Duration = Duration::from_secs(20);

    #[derive(Clone, Copy, Debug)]
    enum Outcome {
        Success,
        Revert,
        BadTransfer,
        BadSender,
        NonCanonical,
        ReceiptError,
        WithheldReceipt,
        Dropped,
        BadNonce,
        BadCalldata,
        AuthorizationUnused,
    }

    struct World {
        rpc: BaseRpc,
        store: Store,
        path: PathBuf,
        relayer: Relayer,
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
        release_receipt: Arc<AtomicBool>,
        receipt_poll: Arc<Mutex<Vec<Instant>>>,
        rpc_errors: Arc<AtomicUsize>,
    }

    #[tokio::test]
    async fn confirmed_receipt_settles_once() {
        let world = world(Outcome::Success, 0).await;
        let body = payment_body([0xab; 32], "10000");
        let response = settle(&world, &body, None).await;
        assert_eq!(response["success"], true);
        assert!(response.get("errorReason").is_none(), "{response}");
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.sent.lock().unwrap().len(), 1);
        let payment = loaded(&world, &body).await;
        assert_eq!(payment.state(), PaymentState::Settled);

        let again = settle(&world, &body, None).await;
        assert_eq!(again["transaction"], response["transaction"]);
        assert_eq!(again["success"], true);
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.sent.lock().unwrap().len(), 1);
        world.store.close().await;
    }

    #[tokio::test]
    async fn no_commit_does_not_broadcast() {
        let world = world(Outcome::Success, 0).await;
        let body = refusal_body([0xab; 32], "10000");
        let response = settle(&world, &body, None).await;
        assert_eq!(response["success"], false);
        assert_eq!(world.relayer.sign_count(), 0);
        assert!(world.sent.lock().unwrap().is_empty());
        assert_eq!(loaded(&world, &body).await.state(), PaymentState::Rejected);
        world.store.close().await;
        let store = Store::open(world_path(&world)).await.unwrap();
        assert_eq!(
            store
                .get(NETWORK, &loaded_payer(&body), &loaded_nonce(&body))
                .await
                .unwrap()
                .state(),
            PaymentState::Rejected
        );
        assert_eq!(store.consumption_count().await.unwrap(), 1);
        store.close().await;
    }

    #[tokio::test]
    async fn missing_or_invalid_oracle_evidence_does_not_sign() {
        let world = world(Outcome::Success, 0).await;
        let mut missing = payment_body([0xac; 32], "10000");
        missing.as_object_mut().unwrap().remove("decisionEvidence");
        let missing = settle(&world, &missing, None).await;
        assert_eq!(missing["success"], false);
        assert_eq!(world.relayer.sign_count(), 0);
        assert_eq!(world.store.payment_count().await.unwrap(), 0);

        let mut bad = payment_body([0xad; 32], "10000");
        let signature = bad["decisionEvidence"]["signature"]
            .as_str()
            .unwrap()
            .to_string();
        let mut corrupted = signature.into_bytes();
        let digit = corrupted.get_mut(4).unwrap();
        *digit = if *digit == b'0' { b'1' } else { b'0' };
        bad["decisionEvidence"]["signature"] = json!(String::from_utf8(corrupted).unwrap());
        let bad = settle(&world, &bad, None).await;
        assert_eq!(bad["success"], false);
        assert_eq!(world.relayer.sign_count(), 0);
        assert!(world.sent.lock().unwrap().is_empty());
        assert_eq!(world.store.payment_count().await.unwrap(), 0);
        world.store.close().await;
    }

    #[tokio::test]
    async fn legacy_attempt_without_oracle_commit_is_not_broadcast() {
        let mut world = world(Outcome::Success, 0).await;
        let body = payment_body([0xae; 32], "10000");
        let stopped = settle(&world, &body, Some(StopAfter::Commit)).await;
        assert_eq!(stopped["success"], false, "{stopped}");
        assert_eq!(world.relayer.sign_count(), 1);
        assert!(world.sent.lock().unwrap().is_empty());
        world.store.delete_consumptions().await.unwrap();

        let again = settle(&world, &body, None).await;
        assert_eq!(again["success"], false, "{again}");
        assert!(world.sent.lock().unwrap().is_empty());
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(loaded(&world, &body).await.state(), PaymentState::Settling);

        reopen(&mut world).await;
        assert_eq!(
            loaded(&world, &body).await.state(),
            PaymentState::SettlementUnknown
        );
        let pass = crate::settle::recover_pass(&recovery_env(&world), NOW).await;
        assert!(matches!(pass, crate::settle::Pass::Idle));
        assert!(world.sent.lock().unwrap().is_empty());
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(
            loaded(&world, &body).await.state(),
            PaymentState::SettlementUnknown
        );
        world.store.close().await;
    }

    #[tokio::test]
    async fn forged_commit_record_is_not_broadcast() {
        let (mut world, body) = committed_unsent([0x71; 32]).await;
        world
            .store
            .overwrite_decision_digest(&[0x01; 32])
            .await
            .unwrap();
        assert_retry_does_not_send(&mut world, &body).await;
    }

    #[tokio::test]
    async fn modified_oracle_signature_or_body_is_not_broadcast() {
        let (mut world, body) = committed_unsent([0x72; 32]).await;
        world
            .store
            .overwrite_oracle_signature(&[0x44; 65])
            .await
            .unwrap();
        assert_retry_does_not_send(&mut world, &body).await;

        let (mut world, body) = committed_unsent([0x73; 32]).await;
        world
            .store
            .overwrite_decision_reason("tampered decision body")
            .await
            .unwrap();
        assert_retry_does_not_send(&mut world, &body).await;
    }

    #[tokio::test]
    async fn raw_transaction_hash_mismatch_is_not_broadcast() {
        let (mut world, body) = committed_unsent([0x74; 32]).await;
        world
            .store
            .overwrite_raw_tx_hash(&[0x9a; 32])
            .await
            .unwrap();
        assert_retry_does_not_send(&mut world, &body).await;
    }

    #[tokio::test]
    async fn calldata_mismatch_is_not_broadcast_with_a_valid_oracle_commit() {
        let (mut world, body) = committed_unsent([0x75; 32]).await;
        let calldata = vec![0x12, 0x34, 0x56];
        let forged = world
            .relayer
            .sign(&UnsignedTx {
                chain_id: BASE_CHAIN_ID,
                nonce: 7,
                max_priority_fee: 1,
                max_fee: 2,
                gas_limit: 60_000,
                to: USDC_ADDRESS,
                value: 0,
                data: calldata.clone(),
            })
            .unwrap();
        world
            .store
            .overwrite_raw_transaction(&forged.raw, &forged.hash, &calldata)
            .await
            .unwrap();
        assert_retry_does_not_send(&mut world, &body).await;
    }

    #[tokio::test]
    async fn payer_signature_mismatch_is_not_broadcast() {
        let (mut world, body) = committed_unsent([0x76; 32]).await;
        world
            .store
            .overwrite_payer_signature(&[0x55; 65])
            .await
            .unwrap();
        assert_retry_does_not_send(&mut world, &body).await;
    }

    #[tokio::test]
    async fn legacy_row_without_oracle_evidence_is_not_broadcast() {
        let (mut world, body) = committed_unsent([0x77; 32]).await;
        world.store.clear_oracle_evidence().await.unwrap();
        assert_retry_does_not_send(&mut world, &body).await;
    }

    #[tokio::test]
    async fn no_commit_followed_by_commit_does_not_sign() {
        let world = world(Outcome::Success, 0).await;
        let refusal = refusal_body([0x78; 32], "10000");
        let first = settle(&world, &refusal, None).await;
        assert_eq!(first["success"], false, "{first}");
        let later = payment_body([0x78; 32], "10000");
        let second = settle(&world, &later, None).await;
        assert_eq!(second["success"], false, "{second}");
        assert_eq!(world.relayer.sign_count(), 0);
        assert!(world.sent.lock().unwrap().is_empty());
        let payment = loaded(&world, &refusal).await;
        assert_eq!(payment.state(), PaymentState::Rejected);
        let states = world
            .store
            .event_to_states(payment.context())
            .await
            .unwrap();
        assert!(!states.contains(&PaymentState::Committed));
        assert_eq!(world.store.consumption_count().await.unwrap(), 1);
        world.store.close().await;
    }

    #[tokio::test]
    async fn persisted_no_commit_blocks_commit_before_signing() {
        let world = world(Outcome::Success, 0).await;
        let mut body = unsigned_body([0x79; 32], "10000", NOW + 30);
        let evidence = signed_decision(&body, DecisionVerdict::NoCommit);
        let checked = verify::accept_local(&body, NOW).unwrap();
        let context = payment_context(&checked).unwrap();
        let action = settlement_action(&checked);
        world
            .store
            .record_received(context.clone(), action)
            .await
            .unwrap();
        world.store.mark_verified(&context, &action).await.unwrap();
        world.store.plant_consumption(&evidence).await.unwrap();
        attach_decision(&mut body, DecisionVerdict::Commit);
        let response = settle(&world, &body, None).await;
        assert_eq!(response["success"], false, "{response}");
        assert_eq!(world.relayer.sign_count(), 0);
        assert!(world.sent.lock().unwrap().is_empty());
        assert_eq!(loaded(&world, &body).await.state(), PaymentState::Verified);
        let states = world.store.event_to_states(&context).await.unwrap();
        assert!(!states.contains(&PaymentState::Committed));
        world.store.close().await;
    }

    #[tokio::test]
    async fn legacy_committed_without_decision_does_not_sign() {
        let world = world(Outcome::Success, 0).await;
        let body = payment_body([0x81; 32], "10000");
        let checked = verify::accept_local(&body, NOW).unwrap();
        let context = payment_context(&checked).unwrap();
        let action = settlement_action(&checked);
        world
            .store
            .record_received(context.clone(), action)
            .await
            .unwrap();
        world.store.mark_verified(&context, &action).await.unwrap();
        world
            .store
            .set_payment_state(&context, "committed")
            .await
            .unwrap();

        let response = settle(&world, &body, None).await;
        assert_eq!(response["success"], false, "{response}");
        assert_eq!(world.relayer.sign_count(), 0);
        assert!(world.sent.lock().unwrap().is_empty());
        assert_eq!(loaded(&world, &body).await.state(), PaymentState::Committed);
        assert!(world.store.evidence(&context).await.unwrap().is_none());

        let pass = crate::settle::recover_pass(&recovery_env(&world), NOW).await;
        assert!(matches!(pass, crate::settle::Pass::Idle));
        assert_eq!(world.relayer.sign_count(), 0);
        assert!(world.sent.lock().unwrap().is_empty());
        world.store.close().await;
    }

    #[tokio::test]
    async fn incomplete_legacy_decision_does_not_sign() {
        let world = world(Outcome::Success, 0).await;
        let body = payment_body([0x82; 32], "10000");
        persist_verified_only(&world, &body).await;
        let context = loaded(&world, &body).await.context().clone();
        world
            .store
            .mark_decision_incomplete(&context)
            .await
            .unwrap();

        let response = settle(&world, &body, None).await;
        assert_eq!(response["success"], false, "{response}");
        assert_eq!(world.relayer.sign_count(), 0);
        assert!(world.sent.lock().unwrap().is_empty());
        assert_eq!(loaded(&world, &body).await.state(), PaymentState::Committed);
        assert!(matches!(
            world.store.stored_commit(&context).await.unwrap(),
            StoredCommit::Incomplete
        ));

        let pass = crate::settle::recover_pass(&recovery_env(&world), NOW).await;
        assert!(matches!(pass, crate::settle::Pass::Idle));
        assert_eq!(world.relayer.sign_count(), 0);
        world.store.close().await;
    }

    #[tokio::test]
    async fn stored_verified_commit_is_signed_after_interruption() {
        let world = world(Outcome::Success, 0).await;
        let body = payment_body([0x83; 32], "10000");
        persist_verified_only(&world, &body).await;
        assert_eq!(loaded(&world, &body).await.state(), PaymentState::Committed);

        let response = settle(&world, &body, None).await;
        assert_eq!(response["success"], true, "{response}");
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.sent.lock().unwrap().len(), 1);
        assert_eq!(loaded(&world, &body).await.state(), PaymentState::Settled);

        let again = settle(&world, &body, None).await;
        assert_eq!(again["success"], true, "{again}");
        assert_eq!(again["transaction"], response["transaction"]);
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.sent.lock().unwrap().len(), 1);
        world.store.close().await;
    }

    #[tokio::test]
    async fn recovery_signs_a_stored_verified_commit_only() {
        let world = world(Outcome::Success, 0).await;
        let body = payment_body([0x84; 32], "10000");
        persist_verified_only(&world, &body).await;
        let pass = crate::settle::recover_pass(&recovery_env(&world), NOW).await;
        assert!(matches!(pass, crate::settle::Pass::Progress));
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.sent.lock().unwrap().len(), 1);
        assert_eq!(loaded(&world, &body).await.state(), PaymentState::Settled);

        let again = crate::settle::recover_pass(&recovery_env(&world), NOW).await;
        assert!(matches!(again, crate::settle::Pass::Idle));
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.sent.lock().unwrap().len(), 1);
        world.store.close().await;
    }

    #[tokio::test]
    async fn two_processes_sign_a_verified_commit_once() {
        let world = world(Outcome::Success, 0).await;
        let body = payment_body([0x87; 32], "10000");
        persist_verified_only(&world, &body).await;
        let other = Store::open(&world.path).await.unwrap();
        let (left, right) = tokio::join!(
            settle_with(&world.store, &world.rpc, &world.relayer, &body),
            settle_with(&other, &world.rpc, &world.relayer, &body)
        );
        assert_eq!(world.relayer.sign_count(), 1, "{left} {right}");
        let sent = world.sent.lock().unwrap().clone();
        assert!(!sent.is_empty(), "{left} {right}");
        assert!(sent.iter().all(|raw| raw == &sent[0]));
        assert_eq!(loaded(&world, &body).await.state(), PaymentState::Settled);
        let transaction = if left["success"] == true {
            left["transaction"].clone()
        } else {
            right["transaction"].clone()
        };
        let retry = settle(&world, &body, None).await;
        assert_eq!(retry["success"], true, "{retry}");
        assert_eq!(retry["transaction"], transaction);
        assert_eq!(world.relayer.sign_count(), 1);
        other.close().await;
        world.store.close().await;
    }

    #[tokio::test]
    async fn oracle_commit_is_accepted_once() {
        let mut body = unsigned_body([0x91; 32], "10000", NOW + 30);
        let issued = oracle_issue(&body);
        assert_eq!(issued["verdict"], "COMMIT");
        let evidence = issued["decisionEvidence"].clone();
        assert!(evidence
            .get("signature")
            .and_then(|value| value.as_str())
            .is_some());

        let checked = verify::accept_local(&body, NOW).unwrap();
        let expected = crate::evidence::ExpectedBinding::for_payment(
            payment_context(&checked).unwrap(),
            authorization_identity(&checked),
            settlement_action(&checked),
        )
        .unwrap();
        let parsed = crate::evidence::parse_decision_evidence(&evidence).unwrap();
        let record = crate::evidence::assess_decision(&parsed, &expected, &test_oracle()).unwrap();
        assert_eq!(record.verdict(), crate::evidence::Verdict::Commit);
        assert_eq!(record.decision_digest(), parsed.decision_digest().unwrap());

        let mut tampered = evidence.clone();
        tampered["reason"] = json!("tampered");
        let tampered = crate::evidence::parse_decision_evidence(&tampered).unwrap();
        assert_eq!(
            crate::evidence::assess_decision(&tampered, &expected, &test_oracle()),
            Err(crate::evidence::DecisionError::InvalidSignature)
        );

        let mut shifted = evidence.clone();
        shifted["authorization"]["value"] = json!("0x".to_string() + &"00".repeat(31) + "01");
        let shifted = crate::evidence::parse_decision_evidence(&shifted).unwrap();
        assert!(crate::evidence::assess_decision(&shifted, &expected, &test_oracle()).is_err());

        let refused = oracle_issue(&unsigned_body([0x92; 32], "1000001", NOW + 30));
        assert_eq!(refused["verdict"], "NO_COMMIT");
        assert!(refused["decisionEvidence"]["signature"].is_null());
        assert!(crate::evidence::parse_decision_evidence(&refused["decisionEvidence"]).is_err());

        body["decisionEvidence"] = evidence;
        let settled = world(Outcome::Success, 0).await;
        let first = settle(&settled, &body, None).await;
        assert_eq!(first["success"], true, "{first}");
        let again = settle(&settled, &body, None).await;
        assert_eq!(again["success"], true, "{again}");
        assert_eq!(again["transaction"], first["transaction"]);
        assert_eq!(settled.relayer.sign_count(), 1);
        assert_eq!(settled.sent.lock().unwrap().len(), 1);
        settled.store.close().await;

        let parallel = world(Outcome::Success, 0).await;
        let mut parallel_body = unsigned_body([0x93; 32], "10000", NOW + 30);
        let parallel_issued = oracle_issue(&parallel_body);
        parallel_body["decisionEvidence"] = parallel_issued["decisionEvidence"].clone();
        let other = Store::open(world_path(&parallel)).await.unwrap();
        let (left, right) = tokio::join!(
            settle_with(
                &parallel.store,
                &parallel.rpc,
                &parallel.relayer,
                &parallel_body
            ),
            settle_with(&other, &parallel.rpc, &parallel.relayer, &parallel_body)
        );
        assert_eq!(parallel.relayer.sign_count(), 1, "{left} {right}");
        let sent = parallel.sent.lock().unwrap().clone();
        assert_eq!(sent.len(), 1, "{left} {right}");
        let parallel_sent = if left["success"] == true {
            left["transaction"].as_str().unwrap().to_string()
        } else {
            right["transaction"].as_str().unwrap().to_string()
        };
        let retry = settle_with(&other, &parallel.rpc, &parallel.relayer, &parallel_body).await;
        assert_eq!(retry["success"], true, "{retry}");
        assert_eq!(retry["transaction"], parallel_sent);
        assert_eq!(parallel.relayer.sign_count(), 1);
        assert_eq!(parallel.sent.lock().unwrap().as_slice(), sent.as_slice());
        other.close().await;
        parallel.store.close().await;
    }

    #[tokio::test]
    async fn expired_lease_during_paused_sign_persists_only_the_new_claim() {
        let world = world(Outcome::Success, 0).await;
        let body = payment_body([0x89; 32], "10000");
        persist_verified_only(&world, &body).await;
        let gate = world.store.arm_sign_gate().await;
        let store_a = world.store.clone();
        let rpc_a = world.rpc.clone();
        let relayer_a = world.relayer.clone();
        let body_a = body.clone();
        let paused =
            tokio::spawn(async move { settle_with(&store_a, &rpc_a, &relayer_a, &body_a).await });
        let started = Instant::now();
        while !gate.entered.load(Ordering::SeqCst) {
            if started.elapsed() > Duration::from_secs(5) {
                panic!("signer did not pause");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(world.relayer.sign_count(), 1);
        assert!(world.sent.lock().unwrap().is_empty());
        world.store.expire_signing_claims().await.unwrap();

        let other = Store::open(&world.path).await.unwrap();
        let completed = settle_with(&other, &world.rpc, &world.relayer, &body).await;
        assert_eq!(completed["success"], true, "{completed}");
        gate.release.store(true, Ordering::SeqCst);
        let abandoned = paused.await.unwrap();
        assert_eq!(abandoned["success"], false, "{abandoned}");
        assert_ne!(abandoned["transaction"], completed["transaction"]);

        let sent = world.sent.lock().unwrap().clone();
        assert_eq!(sent.len(), 1);
        let context = loaded(&world, &body).await.context().clone();
        let stored = world.store.evidence(&context).await.unwrap().unwrap();
        assert_eq!(stored.raw_tx, sent[0]);
        assert_eq!(loaded(&world, &body).await.state(), PaymentState::Settled);
        assert_eq!(world.relayer.sign_count(), 2);

        let retry = settle_with(&other, &world.rpc, &world.relayer, &body).await;
        assert_eq!(retry["success"], true, "{retry}");
        assert_eq!(retry["transaction"], completed["transaction"]);
        assert_eq!(world.sent.lock().unwrap().as_slice(), sent.as_slice());
        assert_eq!(world.relayer.sign_count(), 2);
        other.close().await;
        world.store.close().await;
    }

    #[tokio::test]
    async fn different_decision_after_stored_commit_does_not_sign() {
        let world = world(Outcome::Success, 0).await;
        let mut body = payment_body([0x85; 32], "10000");
        persist_verified_only(&world, &body).await;
        let context = loaded(&world, &body).await.context().clone();
        let before = world.store.stored_commit(&context).await.unwrap();
        let StoredCommit::Verified(before) = before else {
            panic!("verified commit");
        };
        body["decisionEvidence"] = crate::evidence::decision_evidence_value(&other_commit(&body));

        let response = settle(&world, &body, None).await;
        assert_eq!(response["success"], false, "{response}");
        assert_eq!(world.relayer.sign_count(), 0);
        assert!(world.sent.lock().unwrap().is_empty());
        assert_eq!(loaded(&world, &body).await.state(), PaymentState::Committed);
        let StoredCommit::Verified(after) = world.store.stored_commit(&context).await.unwrap()
        else {
            panic!("stored commit replaced");
        };
        assert_eq!(
            after.evidence.body().evidence_id(),
            before.evidence.body().evidence_id()
        );
        assert_eq!(after.decision_digest, before.decision_digest);
        world.store.close().await;
    }

    #[tokio::test]
    async fn broadcast_requires_consumed_commit_and_matching_evidence() {
        let mut world = world(Outcome::Success, 0).await;
        let body = payment_body([0x86; 32], "10000");
        let stopped = settle(&world, &body, Some(StopAfter::Commit)).await;
        assert_eq!(stopped["success"], false, "{stopped}");
        assert_eq!(world.relayer.sign_count(), 1);
        assert!(world.sent.lock().unwrap().is_empty());
        let context = loaded(&world, &body).await.context().clone();
        world
            .store
            .reopen_decision_as_verified(&context)
            .await
            .unwrap();

        let again = settle(&world, &body, None).await;
        assert_eq!(again["success"], false, "{again}");
        assert!(world.sent.lock().unwrap().is_empty());
        assert_eq!(world.relayer.sign_count(), 1);
        reopen(&mut world).await;
        let pass = crate::settle::recover_pass(&recovery_env(&world), NOW).await;
        assert!(matches!(
            pass,
            crate::settle::Pass::Idle | crate::settle::Pass::Inconclusive
        ));
        assert!(world.sent.lock().unwrap().is_empty());
        assert_eq!(world.relayer.sign_count(), 1);
        assert_ne!(loaded(&world, &body).await.state(), PaymentState::Settled);
        world.store.close().await;
    }

    #[tokio::test]
    async fn recovery_refuses_incomplete_legacy_evidence() {
        let mut world = world(Outcome::Success, 0).await;
        let body = payment_body([0xb7; 32], "10000");
        let stopped = settle(&world, &body, Some(StopAfter::Broadcast)).await;
        assert_eq!(stopped["success"], false, "{stopped}");
        let sent = world.sent.lock().unwrap().len();
        assert_eq!(sent, 1);
        reopen(&mut world).await;
        assert_eq!(
            loaded(&world, &body).await.state(),
            PaymentState::SettlementUnknown
        );
        let context = loaded(&world, &body).await.context().clone();
        world
            .store
            .mark_decision_incomplete(&context)
            .await
            .unwrap();

        let pass = crate::settle::recover_pass(&recovery_env(&world), NOW).await;
        assert!(matches!(pass, crate::settle::Pass::Idle));
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.sent.lock().unwrap().len(), 1);
        assert_eq!(
            loaded(&world, &body).await.state(),
            PaymentState::SettlementUnknown
        );
        let retry = settle(&world, &body, None).await;
        assert_eq!(retry["success"], false, "{retry}");
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.sent.lock().unwrap().len(), 1);
        world.store.close().await;
    }

    async fn persist_verified_only(world: &World, body: &Value) {
        let checked = verify::accept_local(body, NOW).unwrap();
        let context = payment_context(&checked).unwrap();
        let action = settlement_action(&checked);
        let evidence = signed_decision(body, DecisionVerdict::Commit);
        let expected = expected_binding(&checked, &context, &action).unwrap();
        let record = assess_decision(&evidence, &expected, &test_oracle()).unwrap();
        world
            .store
            .record_received(context.clone(), action)
            .await
            .unwrap();
        world.store.mark_verified(&context, &action).await.unwrap();
        let commit = Commit::for_oracle(&context, &action, evidence.body().reason().as_str());
        world
            .store
            .persist_verified_commit(
                &context,
                &action,
                &commit,
                &record,
                &evidence,
                &checked.signature,
            )
            .await
            .unwrap();
        assert_eq!(world.relayer.sign_count(), 0);
        assert_eq!(
            world
                .store
                .get(context.network(), context.payer(), context.nonce())
                .await
                .unwrap()
                .state(),
            PaymentState::Committed
        );
    }

    fn other_commit(body: &Value) -> crate::evidence::DclDecisionEvidence {
        let checked = verify::accept_local(body, NOW).unwrap();
        let action = settlement_action(&checked);
        let context = payment_context(&checked).unwrap();
        let decision = crate::evidence::DecisionBody::new(
            crate::evidence::action_id_from_digest(&action).unwrap(),
            action,
            context,
            authorization_identity(&checked),
            DecisionVerdict::Commit,
            crate::evidence::DecisionReason::try_new("other").unwrap(),
            crate::evidence::EvidenceId::new([0xff; 32]),
        )
        .unwrap();
        let digest = decision.decision_digest().unwrap();
        let signature = test_sign(&ORACLE_SECRET, &digest);
        crate::evidence::DclDecisionEvidence::certify(decision, &signature).unwrap()
    }

    #[tokio::test]
    async fn concurrent_processes_broadcast_one_transaction() {
        let world = world(Outcome::Success, 0).await;
        let body = payment_body([0x7a; 32], "10000");
        let other = Store::open(&world.path).await.unwrap();
        let (left, right) = tokio::join!(
            settle_with(&world.store, &world.rpc, &world.relayer, &body),
            settle_with(&other, &world.rpc, &world.relayer, &body)
        );
        let sent = world.sent.lock().unwrap().clone();
        assert!(!sent.is_empty(), "{left} {right}");
        assert!(
            sent.iter().all(|raw| raw == &sent[0]),
            "concurrent processes must broadcast the one stored transaction"
        );
        assert_eq!(world.store.consumption_count().await.unwrap(), 1);
        assert_eq!(world.store.payment_count().await.unwrap(), 1);
        let left_ok = left["success"].as_bool() == Some(true);
        let right_ok = right["success"].as_bool() == Some(true);
        assert!(left_ok || right_ok, "{left} {right}");
        if left_ok && right_ok {
            assert_eq!(left["transaction"], right["transaction"]);
        }
        other.close().await;
        world.store.close().await;
    }

    async fn committed_unsent(nonce: [u8; 32]) -> (World, Value) {
        let world = world(Outcome::Success, 0).await;
        let body = payment_body(nonce, "10000");
        let stopped = settle(&world, &body, Some(StopAfter::Commit)).await;
        assert_eq!(stopped["success"], false, "{stopped}");
        assert_eq!(world.relayer.sign_count(), 1);
        assert!(world.sent.lock().unwrap().is_empty());
        (world, body)
    }

    async fn assert_retry_does_not_send(world: &mut World, body: &Value) {
        let signs = world.relayer.sign_count();
        let again = settle(world, body, None).await;
        assert_eq!(again["success"], false, "{again}");
        assert!(world.sent.lock().unwrap().is_empty());
        assert_eq!(world.relayer.sign_count(), signs);
        reopen(world).await;
        let _ = crate::settle::recover_pass(&recovery_env(world), NOW).await;
        assert!(world.sent.lock().unwrap().is_empty());
        assert_eq!(world.relayer.sign_count(), signs);
        assert_ne!(loaded(world, body).await.state(), PaymentState::Settled);
        world.store.close().await;
    }

    #[tokio::test]
    async fn invalid_authorization_writes_no_payment_row() {
        let world = world(Outcome::Success, 0).await;
        let mut body = payment_body([0xab; 32], "10000");
        let signature = body["paymentPayload"]["payload"]["signature"]
            .as_str()
            .unwrap()
            .to_string();
        let mut corrupted = signature.clone().into_bytes();
        let digit = corrupted.get_mut(2).expect("0x-prefixed signature");
        *digit = if *digit == b'0' { b'1' } else { b'0' };
        let corrupted = String::from_utf8(corrupted).unwrap();
        assert_ne!(corrupted, signature);
        body["paymentPayload"]["payload"]["signature"] = json!(corrupted);
        let response = settle(&world, &body, None).await;
        assert_eq!(response["success"], false);
        assert_eq!(response["errorReason"], INVALID_SIGNATURE);
        assert_eq!(world.store.payment_count().await.unwrap(), 0);
        assert_eq!(world.relayer.sign_count(), 0);
        assert!(world.sent.lock().unwrap().is_empty());
        world.store.close().await;
    }

    #[tokio::test]
    async fn crash_before_broadcast_rebroadcasts_the_stored_transaction() {
        let mut world = world(Outcome::Success, 0).await;
        let body = payment_body([0x11; 32], "10000");
        let stopped = settle(&world, &body, Some(StopAfter::Commit)).await;
        assert_eq!(stopped["success"], false);
        assert_eq!(world.relayer.sign_count(), 1);
        assert!(world.sent.lock().unwrap().is_empty());
        let stored = loaded(&world, &body).await;
        assert_eq!(stored.state(), PaymentState::Settling);
        let raw = world
            .store
            .evidence(stored.context())
            .await
            .unwrap()
            .unwrap()
            .raw_tx;
        world.store.close().await;
        world.store = Store::open(&world.path).await.unwrap();
        assert_eq!(
            loaded(&world, &body).await.state(),
            PaymentState::SettlementUnknown
        );

        let response = settle(&world, &body, None).await;
        assert_eq!(response["success"], true);
        assert_eq!(
            world.relayer.sign_count(),
            1,
            "recovery must not sign again"
        );
        let sent = world.sent.lock().unwrap().clone();
        assert_eq!(sent, vec![raw]);
        assert_eq!(loaded(&world, &body).await.state(), PaymentState::Settled);
        world.store.close().await;
    }

    #[tokio::test]
    async fn crash_after_broadcast_does_not_sign_or_send_a_replacement() {
        let mut world = world(Outcome::Success, 0).await;
        let body = payment_body([0x12; 32], "10000");
        let _ = settle(&world, &body, Some(StopAfter::Broadcast)).await;
        assert_eq!(world.relayer.sign_count(), 1);
        let first = world.sent.lock().unwrap().clone();
        assert_eq!(first.len(), 1);
        world.store.close().await;
        world.store = Store::open(&world.path).await.unwrap();
        assert_eq!(
            loaded(&world, &body).await.state(),
            PaymentState::SettlementUnknown
        );

        let response = settle(&world, &body, None).await;
        assert_eq!(response["success"], true);
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.sent.lock().unwrap().as_slice(), first.as_slice());
        world.store.close().await;
    }

    #[tokio::test]
    async fn conflicting_terms_for_the_same_nonce_are_not_signed() {
        let world = world(Outcome::Success, 0).await;
        let first = payment_body([0x21; 32], "10000");
        assert_eq!(settle(&world, &first, None).await["success"], true);
        let second = payment_body([0x21; 32], "10001");
        let response = settle(&world, &second, None).await;
        assert_eq!(response["success"], false);
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.sent.lock().unwrap().len(), 1);
        assert_eq!(loaded(&world, &first).await.state(), PaymentState::Settled);
        world.store.close().await;
    }

    #[tokio::test]
    async fn concurrent_same_payment_signs_one_transaction() {
        let world = world(Outcome::Success, 0).await;
        let body = payment_body([0x33; 32], "10000");
        let store_b = world.store.clone();
        let rpc_b = world.rpc.clone();
        let relayer_b = world.relayer.clone();
        let (a, b) = tokio::join!(
            settle_with(&world.store, &world.rpc, &world.relayer, &body),
            settle_with(&store_b, &rpc_b, &relayer_b, &body)
        );
        assert_eq!(a["success"], true, "{a}");
        assert_eq!(b["success"], true, "{b}");
        assert_eq!(a["transaction"], b["transaction"]);
        assert!(a["transaction"].as_str().unwrap_or("").starts_with("0x"));
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.sent.lock().unwrap().len(), 1);
        assert_eq!(loaded(&world, &body).await.state(), PaymentState::Settled);
        world.store.close().await;
    }

    #[tokio::test]
    async fn concurrent_settlements_reserve_distinct_relayer_nonces() {
        let world = world(Outcome::Success, 3).await;
        let left = payment_body([0x31; 32], "10000");
        let right = payment_body([0x32; 32], "10000");
        let store_left = world.store.clone();
        let store_right = world.store.clone();
        let rpc_left = world.rpc.clone();
        let rpc_right = world.rpc.clone();
        let relayer_left = world.relayer.clone();
        let relayer_right = world.relayer.clone();
        let (a, b) = tokio::join!(
            settle_with(&store_left, &rpc_left, &relayer_left, &left),
            settle_with(&store_right, &rpc_right, &relayer_right, &right)
        );
        assert_eq!(a["success"], true, "{a}");
        assert_eq!(b["success"], true, "{b}");
        assert_ne!(a["transaction"], b["transaction"]);
        let nonces = world.relayer_nonces().await;
        assert_eq!(nonces, vec![3, 4]);
        assert_eq!(world.relayer.sign_count(), 2);
        let sent = world.sent.lock().unwrap().clone();
        let mut parsed: Vec<u64> = sent
            .iter()
            .map(|raw| parse_signed_tx(raw).unwrap().nonce)
            .collect();
        parsed.sort_unstable();
        assert_eq!(parsed, vec![3, 4]);
        world.store.close().await;
    }

    #[tokio::test]
    async fn mined_revert_uses_the_uncertain_then_failed_path() {
        let world = world(Outcome::Revert, 0).await;
        let body = payment_body([0x41; 32], "10000");
        let response = settle(&world, &body, None).await;
        assert_eq!(response["success"], false);
        assert_eq!(world.relayer.sign_count(), 1);
        let payment = loaded(&world, &body).await;
        assert_eq!(payment.state(), PaymentState::SettleFailed);
        let states = world
            .store
            .event_to_states(payment.context())
            .await
            .unwrap();
        assert!(states.contains(&PaymentState::SettlementUnknown));
        assert_eq!(states.last().copied(), Some(PaymentState::SettleFailed));
        let again = settle(&world, &body, None).await;
        assert_eq!(again["success"], false);
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.sent.lock().unwrap().len(), 1);
        world.store.close().await;
    }

    #[tokio::test]
    async fn rpc_receipt_error_stays_unknown_without_a_new_signature() {
        let world = world(Outcome::ReceiptError, 0).await;
        let body = payment_body([0x51; 32], "10000");
        let response = settle(&world, &body, None).await;
        assert_eq!(response["success"], false);
        assert_eq!(
            loaded(&world, &body).await.state(),
            PaymentState::SettlementUnknown
        );
        let again = settle(&world, &body, None).await;
        assert_eq!(again["success"], false);
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.sent.lock().unwrap().len(), 1);
        assert_eq!(
            loaded(&world, &body).await.state(),
            PaymentState::SettlementUnknown
        );
        world.store.close().await;
    }

    #[tokio::test]
    async fn mismatched_transaction_or_transfer_is_not_settled() {
        for outcome in [
            Outcome::BadSender,
            Outcome::BadTransfer,
            Outcome::NonCanonical,
        ] {
            let world = world(outcome, 0).await;
            let body = payment_body([0x61; 32], "10000");
            let response = settle(&world, &body, None).await;
            assert_eq!(response["success"], false, "{outcome:?}");
            assert_eq!(
                loaded(&world, &body).await.state(),
                PaymentState::SettlementUnknown
            );
            assert_eq!(world.relayer.sign_count(), 1);
            world.store.close().await;
        }
    }

    #[tokio::test]
    async fn mismatched_nonce_calldata_or_unused_authorization_is_not_settled() {
        for outcome in [
            Outcome::BadNonce,
            Outcome::BadCalldata,
            Outcome::AuthorizationUnused,
        ] {
            let world = world(outcome, 0).await;
            let body = payment_body([0x62; 32], "10000");
            let response = settle(&world, &body, None).await;
            assert_eq!(response["success"], false, "{outcome:?} {response}");
            assert_eq!(
                loaded(&world, &body).await.state(),
                PaymentState::SettlementUnknown,
                "{outcome:?}"
            );
            assert_eq!(world.relayer.sign_count(), 1, "{outcome:?}");
            assert_eq!(world.sent.lock().unwrap().len(), 1, "{outcome:?}");
            world.store.close().await;
        }
    }

    #[tokio::test]
    async fn payment_lock_is_released_after_rejection_and_invalid_signature() {
        let world = world(Outcome::Success, 0).await;
        let body = refusal_body([0x91; 32], "10000");
        let rejected = settle(&world, &body, None).await;
        assert_eq!(rejected["success"], false);
        assert_eq!(loaded(&world, &body).await.state(), PaymentState::Rejected);
        let again = tokio::time::timeout(Duration::from_secs(5), settle(&world, &body, None))
            .await
            .expect("payment lock still held after rejection");
        assert_eq!(again["success"], false);
        assert_eq!(world.relayer.sign_count(), 0);

        let mut invalid = payment_body([0x92; 32], "10000");
        let signature = invalid["paymentPayload"]["payload"]["signature"]
            .as_str()
            .unwrap()
            .to_string();
        let mut corrupted = signature.into_bytes();
        let digit = corrupted.get_mut(2).expect("0x-prefixed signature");
        *digit = if *digit == b'0' { b'1' } else { b'0' };
        invalid["paymentPayload"]["payload"]["signature"] =
            json!(String::from_utf8(corrupted).unwrap());
        let early = settle(&world, &invalid, None).await;
        assert_eq!(early["success"], false);
        assert_eq!(early["errorReason"], INVALID_SIGNATURE);
        let followed = tokio::time::timeout(
            Duration::from_secs(5),
            settle(&world, &payment_body([0x92; 32], "10000"), None),
        )
        .await
        .expect("payment lock still held after an early return");
        assert_eq!(followed["success"], true, "{followed}");
        assert_eq!(world.relayer.sign_count(), 1);
        world.store.close().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn lock_wait_consumes_the_validity_budget() {
        let budget = Duration::from_secs(30);
        let world = world(Outcome::Success, 0).await;
        let body = payment_body_window([0x93; 32], "10000", NOW + MIN_VALID_BEFORE_LEAD + 30);
        let guard = world.store.lock_payment(&context_for(&body)).await;
        let store = world.store.clone();
        let rpc = world.rpc.clone();
        let relayer = world.relayer.clone();
        let payload = body.clone();
        tokio::time::pause();
        let task = tokio::spawn(async move {
            settle_body(
                &payload,
                NOW,
                &SettleEnv {
                    rpc: &rpc,
                    store: &store,
                    relayer: &relayer,
                    oracle: test_oracle(),
                    max_fee_per_gas: CEILING,
                    receipt_timeout: budget,
                    stop: None,
                },
            )
            .await
        });
        // The task reaches the payment lock, after the deadline is fixed,
        // before this loop finishes. Time stays paused, so the budget does
        // not depend on how long that takes.
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        tokio::time::advance(budget).await;
        drop(guard);
        let response = task.await.expect("settle task");
        tokio::time::resume();
        assert_eq!(response["success"], false, "{response}");
        assert_eq!(response["transaction"], "");
        assert_eq!(world.relayer.sign_count(), 0);
        assert!(world.sent.lock().unwrap().is_empty());
        assert_eq!(world.store.payment_count().await.unwrap(), 0);

        let other = payment_body_window([0x94; 32], "10000", NOW + MIN_VALID_BEFORE_LEAD + 30);
        let settled = settle_for(&world, &other, budget).await;
        assert_eq!(settled["success"], true, "{settled}");
        assert_eq!(world.relayer.sign_count(), 1);
        world.store.close().await;
    }

    #[tokio::test]
    async fn fee_above_the_ceiling_does_not_enter_settling() {
        let world = world(Outcome::Success, 0).await;
        let body = payment_body([0x71; 32], "10000");
        let env = SettleEnv {
            rpc: &world.rpc,
            store: &world.store,
            relayer: &world.relayer,
            oracle: test_oracle(),
            max_fee_per_gas: 1,
            receipt_timeout: Duration::from_secs(2),
            stop: None,
        };
        let response = settle_body(&body, NOW, &env).await;
        assert_eq!(response["success"], false);
        assert_eq!(world.store.payment_count().await.unwrap(), 0);
        assert_eq!(world.relayer.sign_count(), 0);
        assert!(world.sent.lock().unwrap().is_empty());
        world.store.close().await;
    }

    #[tokio::test]
    async fn insufficient_validity_window_rejects_before_settling() {
        let world = world(Outcome::Success, 0).await;
        let body = payment_body_window([0x81; 32], "10000", NOW + MIN_VALID_BEFORE_LEAD);
        let response = settle_for(&world, &body, Duration::from_secs(20)).await;
        assert_eq!(response["success"], false);
        assert_eq!(world.store.payment_count().await.unwrap(), 0);
        assert_eq!(world.relayer.sign_count(), 0);
        assert!(world.sent.lock().unwrap().is_empty());
        world.store.close().await;
    }

    #[test]
    fn receipt_deadline_is_bounded_by_valid_before() {
        let configured = Duration::from_secs(30);
        let tight = word(NOW + MIN_VALID_BEFORE_LEAD + 2);
        assert_eq!(
            receipt_budget(NOW, &tight, configured).unwrap(),
            Duration::from_secs(2)
        );
        let wide = word(NOW + 30);
        assert_eq!(
            receipt_budget(NOW, &wide, Duration::from_secs(2)).unwrap(),
            Duration::from_secs(2)
        );
        let exact_lead = word(NOW + MIN_VALID_BEFORE_LEAD);
        assert!(receipt_budget(NOW, &exact_lead, configured).is_err());
    }

    #[tokio::test]
    async fn preflight_delay_limits_receipt_polling_to_the_remaining_budget() {
        let delay = Duration::from_millis(1500);
        let budget = Duration::from_secs(8);
        let world = world_delayed(Outcome::WithheldReceipt, 0, delay).await;
        let body = payment_body_window([0x84; 32], "10000", NOW + MIN_VALID_BEFORE_LEAD + 8);
        let response = settle_for(&world, &body, Duration::from_secs(30)).await;
        assert_eq!(response["success"], false, "{response}");
        assert_eq!(
            loaded(&world, &body).await.state(),
            PaymentState::SettlementUnknown
        );
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.sent.lock().unwrap().len(), 1);
        let span = world.receipt_poll_span().expect("receipt poll");
        assert!(span > Duration::from_millis(500), "poll {span:?}");
        assert!(
            span < budget - Duration::from_millis(600),
            "poll restarted the original budget: {span:?}"
        );
        world.store.close().await;
    }

    #[tokio::test]
    async fn receipt_timeout_leaves_payment_unresolved() {
        let world = world(Outcome::WithheldReceipt, 0).await;
        let body = payment_body_window([0x82; 32], "10000", NOW + MIN_VALID_BEFORE_LEAD + 8);
        let started = Instant::now();
        let response = settle_for(&world, &body, Duration::from_secs(30)).await;
        let elapsed = started.elapsed();
        assert!(elapsed < Duration::from_secs(12), "waited {elapsed:?}");
        assert_eq!(response["success"], false);
        assert_eq!(
            loaded(&world, &body).await.state(),
            PaymentState::SettlementUnknown
        );
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.sent.lock().unwrap().len(), 1);
        world.store.close().await;
    }

    #[tokio::test]
    async fn recovery_after_timeout_reuses_the_stored_transaction() {
        let mut world = world(Outcome::WithheldReceipt, 0).await;
        let body = payment_body_window([0x83; 32], "10000", NOW + MIN_VALID_BEFORE_LEAD + 8);
        let response = settle_for(&world, &body, Duration::from_secs(30)).await;
        assert_eq!(response["success"], false);
        assert_eq!(
            loaded(&world, &body).await.state(),
            PaymentState::SettlementUnknown
        );
        let stored = world
            .store
            .evidence(loaded(&world, &body).await.context())
            .await
            .unwrap()
            .unwrap()
            .raw_tx;
        assert_eq!(
            world.sent.lock().unwrap().as_slice(),
            std::slice::from_ref(&stored)
        );
        world.release_receipt.store(true, Ordering::SeqCst);
        world.store.close().await;
        world.store = Store::open(&world.path).await.unwrap();
        assert_eq!(
            loaded(&world, &body).await.state(),
            PaymentState::SettlementUnknown
        );

        let again = settle_for(&world, &body, Duration::from_secs(30)).await;
        assert_eq!(again["success"], true, "{again}");
        assert_eq!(again["transaction"], response["transaction"]);
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.sent.lock().unwrap().as_slice(), &[stored]);
        assert_eq!(loaded(&world, &body).await.state(), PaymentState::Settled);
        world.store.close().await;
    }

    #[tokio::test]
    async fn crash_after_confirmed_receipt_before_final_write_recovers() {
        let mut world = world(Outcome::Success, 0).await;
        let body = payment_body([0xa1; 32], "10000");
        let stopped = settle(&world, &body, Some(StopAfter::Confirmed)).await;
        assert_eq!(stopped["success"], false, "{stopped}");
        assert!(stopped["transaction"]
            .as_str()
            .unwrap_or("")
            .starts_with("0x"));
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.sent.lock().unwrap().len(), 1);
        assert_eq!(loaded(&world, &body).await.state(), PaymentState::Settling);
        let stored = world
            .store
            .evidence(loaded(&world, &body).await.context())
            .await
            .unwrap()
            .unwrap()
            .raw_tx;
        world.store.close().await;
        world.store = Store::open(&world.path).await.unwrap();
        assert_eq!(
            loaded(&world, &body).await.state(),
            PaymentState::SettlementUnknown
        );

        let recovered = settle(&world, &body, None).await;
        assert_eq!(recovered["success"], true, "{recovered}");
        assert_eq!(recovered["transaction"], stopped["transaction"]);
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.sent.lock().unwrap().as_slice(), &[stored]);
        assert_eq!(loaded(&world, &body).await.state(), PaymentState::Settled);
        assert_eq!(world.store.payment_count().await.unwrap(), 1);

        let again = settle(&world, &body, None).await;
        assert_eq!(again["success"], true, "{again}");
        assert_eq!(again["transaction"], recovered["transaction"]);
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.store.payment_count().await.unwrap(), 1);
        world.store.close().await;
    }

    #[tokio::test]
    async fn repeated_recovery_does_not_sign_or_duplicate_the_payment() {
        let mut world = world(Outcome::WithheldReceipt, 0).await;
        let body = payment_body([0xa2; 32], "10000");
        let stopped = settle(&world, &body, Some(StopAfter::Broadcast)).await;
        assert_eq!(stopped["success"], false, "{stopped}");
        assert_eq!(world.relayer.sign_count(), 1);
        let stored = world
            .store
            .evidence(loaded(&world, &body).await.context())
            .await
            .unwrap()
            .unwrap()
            .raw_tx;
        assert_eq!(
            world.sent.lock().unwrap().as_slice(),
            std::slice::from_ref(&stored)
        );
        world.store.close().await;
        world.store = Store::open(&world.path).await.unwrap();
        assert_eq!(
            loaded(&world, &body).await.state(),
            PaymentState::SettlementUnknown
        );

        let pending = settle_for(&world, &body, Duration::ZERO).await;
        assert_eq!(pending["success"], false, "{pending}");
        assert_eq!(
            loaded(&world, &body).await.state(),
            PaymentState::SettlementUnknown
        );
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(
            world.sent.lock().unwrap().as_slice(),
            std::slice::from_ref(&stored)
        );
        assert_eq!(world.store.payment_count().await.unwrap(), 1);
        world.store.close().await;
        world.store = Store::open(&world.path).await.unwrap();

        world.release_receipt.store(true, Ordering::SeqCst);
        let recovered = settle(&world, &body, None).await;
        assert_eq!(recovered["success"], true, "{recovered}");
        assert_eq!(recovered["transaction"], stopped["transaction"]);
        assert_eq!(loaded(&world, &body).await.state(), PaymentState::Settled);
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.sent.lock().unwrap().as_slice(), &[stored]);
        assert_eq!(world.store.payment_count().await.unwrap(), 1);

        let again = settle(&world, &body, None).await;
        assert_eq!(again["success"], true, "{again}");
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.store.payment_count().await.unwrap(), 1);
        world.store.close().await;
    }

    #[tokio::test]
    async fn recovery_rpc_outage_preserves_the_signed_attempt() {
        let mut world = world(Outcome::ReceiptError, 0).await;
        let body = payment_body([0xa3; 32], "10000");
        let stopped = settle(&world, &body, Some(StopAfter::Broadcast)).await;
        assert_eq!(stopped["success"], false, "{stopped}");
        let stored = world
            .store
            .evidence(loaded(&world, &body).await.context())
            .await
            .unwrap()
            .unwrap()
            .raw_tx;
        world.store.close().await;
        world.store = Store::open(&world.path).await.unwrap();

        let again = settle(&world, &body, None).await;
        assert_eq!(again["success"], false, "{again}");
        assert_eq!(
            loaded(&world, &body).await.state(),
            PaymentState::SettlementUnknown
        );
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.sent.lock().unwrap().as_slice(), &[stored]);
        assert_eq!(world.store.payment_count().await.unwrap(), 1);
        world.store.close().await;
    }

    #[tokio::test]
    async fn expired_unmined_attempt_fails_without_a_replacement() {
        let mut world = world(Outcome::Dropped, 0).await;
        let valid_before = NOW + 30;
        let body = payment_body_window([0xa4; 32], "10000", valid_before);
        let stopped = settle(&world, &body, Some(StopAfter::Broadcast)).await;
        assert_eq!(stopped["success"], false, "{stopped}");
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.sent.lock().unwrap().len(), 1);
        let stored = world
            .store
            .evidence(loaded(&world, &body).await.context())
            .await
            .unwrap()
            .unwrap()
            .raw_tx;
        world.store.close().await;
        world.store = Store::open(&world.path).await.unwrap();
        assert_eq!(
            loaded(&world, &body).await.state(),
            PaymentState::SettlementUnknown
        );

        let expired = settle_body(
            &body,
            valid_before,
            &SettleEnv {
                rpc: &world.rpc,
                store: &world.store,
                relayer: &world.relayer,
                oracle: test_oracle(),
                max_fee_per_gas: CEILING,
                receipt_timeout: TEST_RECEIPT_TIMEOUT,
                stop: None,
            },
        )
        .await;
        assert_eq!(expired["success"], false, "{expired}");
        assert_eq!(
            loaded(&world, &body).await.state(),
            PaymentState::SettleFailed
        );
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.sent.lock().unwrap().as_slice(), &[stored]);
        assert_eq!(world.store.payment_count().await.unwrap(), 1);

        let again = settle_body(
            &body,
            valid_before,
            &SettleEnv {
                rpc: &world.rpc,
                store: &world.store,
                relayer: &world.relayer,
                oracle: test_oracle(),
                max_fee_per_gas: CEILING,
                receipt_timeout: TEST_RECEIPT_TIMEOUT,
                stop: None,
            },
        )
        .await;
        assert_eq!(again["success"], false, "{again}");
        assert_eq!(
            loaded(&world, &body).await.state(),
            PaymentState::SettleFailed
        );
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.store.payment_count().await.unwrap(), 1);
        world.store.close().await;
    }

    #[tokio::test]
    async fn worker_recovers_a_confirmed_attempt_without_a_client_request() {
        let mut world = world(Outcome::Success, 0).await;
        let body = payment_body([0xb1; 32], "10000");
        let stopped = settle(&world, &body, Some(StopAfter::Broadcast)).await;
        assert_eq!(stopped["success"], false, "{stopped}");
        let stored = evidence_raw(&world, &body).await;
        reopen(&mut world).await;
        assert_eq!(
            loaded(&world, &body).await.state(),
            PaymentState::SettlementUnknown
        );

        let worker = spawn_worker(&world);
        wait_for_state(&world, &body, PaymentState::Settled).await;
        worker.shutdown().await;

        assert_eq!(loaded(&world, &body).await.state(), PaymentState::Settled);
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.sent.lock().unwrap().as_slice(), &[stored]);
        assert_eq!(world.store.payment_count().await.unwrap(), 1);
        world.store.close().await;
    }

    #[tokio::test]
    async fn worker_rebroadcasts_a_persisted_transaction_that_was_never_sent() {
        let mut world = world(Outcome::Success, 0).await;
        let body = payment_body([0xb2; 32], "10000");
        let stopped = settle(&world, &body, Some(StopAfter::Commit)).await;
        assert_eq!(stopped["success"], false, "{stopped}");
        assert!(world.sent.lock().unwrap().is_empty());
        let stored = evidence_raw(&world, &body).await;
        reopen(&mut world).await;
        assert_eq!(
            loaded(&world, &body).await.state(),
            PaymentState::SettlementUnknown
        );

        let worker = spawn_worker(&world);
        wait_for_state(&world, &body, PaymentState::Settled).await;
        worker.shutdown().await;

        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.sent.lock().unwrap().as_slice(), &[stored]);
        assert_eq!(world.store.payment_count().await.unwrap(), 1);
        world.store.close().await;
    }

    #[tokio::test]
    async fn worker_retries_an_rpc_outage_then_settles_the_same_attempt() {
        let mut world = world(Outcome::Success, 0).await;
        let body = payment_body([0xb3; 32], "10000");
        let _ = settle(&world, &body, Some(StopAfter::Broadcast)).await;
        let stored = evidence_raw(&world, &body).await;
        reopen(&mut world).await;
        world.rpc_errors.store(1, Ordering::SeqCst);

        let worker = spawn_worker(&world);
        wait_for_state(&world, &body, PaymentState::Settled).await;
        worker.shutdown().await;

        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.sent.lock().unwrap().as_slice(), &[stored]);
        assert_eq!(world.store.payment_count().await.unwrap(), 1);
        world.store.close().await;
    }

    #[tokio::test]
    async fn concurrent_workers_finalize_one_attempt() {
        let mut world = world(Outcome::Success, 0).await;
        let body = payment_body([0xb4; 32], "10000");
        let _ = settle(&world, &body, Some(StopAfter::Broadcast)).await;
        let stored = evidence_raw(&world, &body).await;
        reopen(&mut world).await;
        let rpc_a = world.rpc.clone();
        let rpc_b = world.rpc.clone();
        let store_a = world.store.clone();
        let store_b = world.store.clone();
        let relayer_a = world.relayer.clone();
        let relayer_b = world.relayer.clone();
        let env_a = SettleEnv {
            rpc: &rpc_a,
            store: &store_a,
            relayer: &relayer_a,
            oracle: test_oracle(),
            max_fee_per_gas: CEILING,
            receipt_timeout: TEST_RECEIPT_TIMEOUT,
            stop: None,
        };
        let env_b = SettleEnv {
            rpc: &rpc_b,
            store: &store_b,
            relayer: &relayer_b,
            oracle: test_oracle(),
            max_fee_per_gas: CEILING,
            receipt_timeout: TEST_RECEIPT_TIMEOUT,
            stop: None,
        };
        let (left, right) = tokio::join!(
            crate::settle::recover_pass(&env_a, NOW),
            crate::settle::recover_pass(&env_b, NOW),
        );
        assert!(matches!(
            (left, right),
            (
                crate::settle::Pass::Progress | crate::settle::Pass::Idle,
                crate::settle::Pass::Progress | crate::settle::Pass::Idle
            )
        ));
        assert_eq!(loaded(&world, &body).await.state(), PaymentState::Settled);
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.sent.lock().unwrap().as_slice(), &[stored]);
        assert_eq!(world.store.payment_count().await.unwrap(), 1);
        world.store.close().await;
    }

    #[tokio::test]
    async fn worker_shutdown_during_recovery_preserves_the_attempt() {
        let mut world = world(Outcome::WithheldReceipt, 0).await;
        let body = payment_body([0xb5; 32], "10000");
        let _ = settle(&world, &body, Some(StopAfter::Broadcast)).await;
        let stored = evidence_raw(&world, &body).await;
        reopen(&mut world).await;
        let worker = spawn_worker(&world);
        let started = Instant::now();
        loop {
            if !world.receipt_poll.lock().unwrap().is_empty() {
                break;
            }
            if started.elapsed() > Duration::from_secs(2) {
                panic!("worker did not start receipt polling");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let stopping = Instant::now();
        worker.shutdown().await;
        assert!(stopping.elapsed() < Duration::from_secs(2));
        assert_eq!(
            loaded(&world, &body).await.state(),
            PaymentState::SettlementUnknown
        );
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.sent.lock().unwrap().as_slice(), &[stored]);
        assert_eq!(world.store.payment_count().await.unwrap(), 1);
        world.store.close().await;
    }

    #[tokio::test]
    async fn repeated_worker_passes_do_not_add_a_signature_or_payment() {
        let mut world = world(Outcome::Success, 0).await;
        let body = payment_body([0xb6; 32], "10000");
        let _ = settle(&world, &body, Some(StopAfter::Broadcast)).await;
        let stored = evidence_raw(&world, &body).await;
        reopen(&mut world).await;

        let first = crate::settle::recover_pass(&recovery_env(&world), NOW).await;
        assert!(matches!(first, crate::settle::Pass::Progress));
        assert_eq!(loaded(&world, &body).await.state(), PaymentState::Settled);
        let second = crate::settle::recover_pass(&recovery_env(&world), NOW).await;
        assert!(matches!(second, crate::settle::Pass::Idle));
        assert_eq!(world.relayer.sign_count(), 1);
        assert_eq!(world.sent.lock().unwrap().as_slice(), &[stored]);
        assert_eq!(world.store.payment_count().await.unwrap(), 1);
        world.store.close().await;
    }

    fn spawn_worker(world: &World) -> crate::recover::Handle {
        crate::recover::Handle::spawn(
            world.rpc.clone(),
            world.store.clone(),
            world.relayer.clone(),
            test_oracle(),
            CEILING,
            TEST_RECEIPT_TIMEOUT,
            Arc::new(|| Some(NOW)),
        )
    }

    fn recovery_env(world: &World) -> SettleEnv<'_> {
        SettleEnv {
            rpc: &world.rpc,
            store: &world.store,
            relayer: &world.relayer,
            oracle: test_oracle(),
            max_fee_per_gas: CEILING,
            receipt_timeout: TEST_RECEIPT_TIMEOUT,
            stop: None,
        }
    }

    async fn evidence_raw(world: &World, body: &Value) -> Vec<u8> {
        world
            .store
            .evidence(loaded(world, body).await.context())
            .await
            .unwrap()
            .unwrap()
            .raw_tx
    }

    async fn reopen(world: &mut World) {
        world.store.close().await;
        world.store = Store::open(&world.path).await.unwrap();
    }

    async fn wait_for_state(world: &World, body: &Value, wanted: PaymentState) {
        let started = Instant::now();
        loop {
            if loaded(world, body).await.state() == wanted {
                return;
            }
            if started.elapsed() > Duration::from_secs(3) {
                panic!("payment stayed {:?}", loaded(world, body).await.state());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn settle(world: &World, body: &Value, stop: Option<StopAfter>) -> Value {
        drive(
            body,
            NOW,
            &SettleEnv {
                rpc: &world.rpc,
                store: &world.store,
                relayer: &world.relayer,
                oracle: test_oracle(),
                max_fee_per_gas: CEILING,
                receipt_timeout: TEST_RECEIPT_TIMEOUT,
                stop: None,
            },
            stop,
        )
        .await
    }

    async fn settle_for(world: &World, body: &Value, receipt_timeout: Duration) -> Value {
        settle_body(
            body,
            NOW,
            &SettleEnv {
                rpc: &world.rpc,
                store: &world.store,
                relayer: &world.relayer,
                oracle: test_oracle(),
                max_fee_per_gas: CEILING,
                receipt_timeout,
                stop: None,
            },
        )
        .await
    }

    async fn settle_with(store: &Store, rpc: &BaseRpc, relayer: &Relayer, body: &Value) -> Value {
        settle_body(
            body,
            NOW,
            &SettleEnv {
                rpc,
                store,
                relayer,
                oracle: test_oracle(),
                max_fee_per_gas: CEILING,
                receipt_timeout: TEST_RECEIPT_TIMEOUT,
                stop: None,
            },
        )
        .await
    }

    async fn loaded(world: &World, body: &Value) -> crate::machine::Payment {
        let payer = body["paymentPayload"]["payload"]["authorization"]["from"]
            .as_str()
            .unwrap();
        let nonce = body["paymentPayload"]["payload"]["authorization"]["nonce"]
            .as_str()
            .unwrap();
        world.store.get(NETWORK, payer, nonce).await.unwrap()
    }

    impl World {
        fn receipt_poll_span(&self) -> Option<Duration> {
            let times = self.receipt_poll.lock().unwrap();
            Some(times.last()?.saturating_duration_since(*times.first()?))
        }

        async fn relayer_nonces(&self) -> Vec<u64> {
            self.store
                .relayer_nonces(&to_checksum(&self.relayer.address()))
                .await
                .unwrap()
        }
    }

    async fn world(outcome: Outcome, pending: u64) -> World {
        world_delayed(outcome, pending, Duration::ZERO).await
    }

    async fn world_delayed(outcome: Outcome, pending: u64, preflight_delay: Duration) -> World {
        let relayer = Relayer::from_secret([0x24; 32]).unwrap();
        let release_receipt = Arc::new(AtomicBool::new(!matches!(
            outcome,
            Outcome::WithheldReceipt
        )));
        let receipt_poll = Arc::new(Mutex::new(Vec::new()));
        let rpc_errors = Arc::new(AtomicUsize::new(0));
        let (rpc, sent) = mock_rpc(
            outcome,
            pending,
            to_checksum(&relayer.address()),
            release_receipt.clone(),
            preflight_delay,
            receipt_poll.clone(),
            rpc_errors.clone(),
        )
        .await;
        let path = std::env::temp_dir().join(format!(
            "dcl-settle-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_file(&path);
        let store = Store::open(&path).await.unwrap();
        World {
            rpc,
            store,
            path,
            relayer,
            sent,
            release_receipt,
            receipt_poll,
            rpc_errors,
        }
    }

    fn context_for(body: &Value) -> PaymentContext {
        let authorization = &body["paymentPayload"]["payload"]["authorization"];
        PaymentContext::try_new(
            NETWORK,
            authorization["from"].as_str().unwrap(),
            body["paymentRequirements"]["payTo"].as_str().unwrap(),
            body["paymentRequirements"]["asset"].as_str().unwrap(),
            authorization["nonce"].as_str().unwrap(),
        )
        .unwrap()
    }

    fn test_oracle() -> [u8; 20] {
        test_address(&ORACLE_SECRET)
    }

    const ORACLE_SECRET: [u8; 32] = [0x7u8; 32];

    fn payment_body(nonce: [u8; 32], amount: &str) -> Value {
        payment_body_window(nonce, amount, NOW + 30)
    }

    fn refusal_body(nonce: [u8; 32], amount: &str) -> Value {
        let mut body = unsigned_body(nonce, amount, NOW + 30);
        attach_decision(&mut body, DecisionVerdict::NoCommit);
        body
    }

    fn payment_body_window(nonce: [u8; 32], amount: &str, valid_before: u64) -> Value {
        let mut body = unsigned_body(nonce, amount, valid_before);
        attach_decision(&mut body, DecisionVerdict::Commit);
        body
    }

    fn attach_decision(body: &mut Value, verdict: DecisionVerdict) {
        let evidence = signed_decision(body, verdict);
        body["decisionEvidence"] = crate::evidence::decision_evidence_value(&evidence);
    }

    fn signed_decision(
        body: &Value,
        verdict: DecisionVerdict,
    ) -> crate::evidence::DclDecisionEvidence {
        let checked = verify::accept_local(body, NOW).expect("fixture window");
        let action = settlement_action(&checked);
        let context = payment_context(&checked).expect("fixture context");
        let reason = match verdict {
            DecisionVerdict::Commit => "allowed",
            DecisionVerdict::NoCommit => "refused",
        };
        let decision = crate::evidence::DecisionBody::new(
            crate::evidence::action_id_from_digest(&action).unwrap(),
            action,
            context,
            authorization_identity(&checked),
            verdict,
            crate::evidence::DecisionReason::try_new(reason).unwrap(),
            crate::evidence::EvidenceId::new(checked.authorization.nonce),
        )
        .unwrap();
        let digest = decision.decision_digest().unwrap();
        let signature = test_sign(&ORACLE_SECRET, &digest);
        crate::evidence::DclDecisionEvidence::certify(decision, &signature).unwrap()
    }

    fn loaded_payer(body: &Value) -> String {
        body["paymentPayload"]["payload"]["authorization"]["from"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn loaded_nonce(body: &Value) -> String {
        body["paymentPayload"]["payload"]["authorization"]["nonce"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn world_path(world: &World) -> &std::path::Path {
        &world.path
    }

    /// In-process issuer for the Oracle Payment Evidence Contract.
    ///
    /// Amounts above one USDC stay unsigned `NO_COMMIT`. Every smaller amount
    /// is signed here over the facilitator digest with the test Oracle key.
    /// No external checkout or interpreter is consulted.
    fn oracle_issue(payment: &Value) -> Value {
        const MAX_PAYMENT_BASE_UNITS: u128 = 1_000_000;
        const COMMIT_REASON: &str = "payment authorization accepted";
        const CEILING_REASON: &str = "amount exceeds the oracle payment ceiling";
        let amount = payment["paymentRequirements"]["amount"]
            .as_str()
            .expect("payment amount");
        let units: u128 = amount.parse().expect("decimal amount");
        let (verdict, reason) = if units > MAX_PAYMENT_BASE_UNITS {
            (DecisionVerdict::NoCommit, CEILING_REASON)
        } else {
            (DecisionVerdict::Commit, COMMIT_REASON)
        };
        let checked = verify::accept_local(payment, NOW).expect("oracle payment");
        let action = settlement_action(&checked);
        let context = payment_context(&checked).expect("oracle context");
        let decision = crate::evidence::DecisionBody::new(
            crate::evidence::action_id_from_digest(&action).unwrap(),
            action,
            context,
            authorization_identity(&checked),
            verdict,
            crate::evidence::DecisionReason::try_new(reason).unwrap(),
            crate::evidence::EvidenceId::new(checked.authorization.nonce),
        )
        .unwrap();
        let digest = decision.decision_digest().unwrap();
        let mut evidence = crate::evidence::unsigned_decision_evidence_value(&decision);
        if verdict == DecisionVerdict::Commit {
            let signature = test_sign(&ORACLE_SECRET, &digest);
            evidence["signature"] = json!(format!("0x{}", hex_encode(&signature)));
            return json!({
                "verdict": "COMMIT",
                "reason": reason,
                "decisionDigest": format!("0x{}", hex_encode(&digest)),
                "oracleAddress": to_checksum(&test_oracle()),
                "decisionEvidence": evidence,
            });
        }
        json!({
            "verdict": "NO_COMMIT",
            "reason": reason,
            "decisionDigest": format!("0x{}", hex_encode(&digest)),
            "oracleAddress": Value::Null,
            "decisionEvidence": evidence,
        })
    }

    fn unsigned_body(nonce: [u8; 32], amount: &str, valid_before: u64) -> Value {
        let secret = [0x42u8; 32];
        let from = test_address(&secret);
        let to = [0x22u8; 20];
        let value = decimal_word(amount);
        let auth = Authorization {
            from,
            to,
            value,
            valid_after: word(0),
            valid_before: word(valid_before),
            nonce,
        };
        let signature = test_sign(&secret, &signing_digest(&auth));
        let payer = to_checksum(&from);
        let pay_to = to_checksum(&to);
        json!({
            "x402Version": 2,
            "paymentPayload": {
                "x402Version": 2,
                "accepted": terms(&pay_to, amount),
                "payload": {
                    "signature": format!("0x{}", hex_encode(&signature)),
                    "authorization": {
                        "from": payer,
                        "to": pay_to,
                        "value": amount,
                        "validAfter": "0",
                        "validBefore": valid_before.to_string(),
                        "nonce": format!("0x{}", hex_encode(&nonce))
                    }
                }
            },
            "paymentRequirements": terms(&pay_to, amount)
        })
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

    fn word(value: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[24..].copy_from_slice(&value.to_be_bytes());
        out
    }

    fn decimal_word(value: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for byte in value.bytes() {
            let mut carry = u16::from(byte - b'0');
            for slot in out.iter_mut().rev() {
                let next = u16::from(*slot) * 10 + carry;
                *slot = (next & 0xff) as u8;
                carry = next >> 8;
            }
        }
        out
    }

    static NEXT: AtomicU64 = AtomicU64::new(1);

    async fn mock_rpc(
        outcome: Outcome,
        pending: u64,
        relayer: String,
        release_receipt: Arc<AtomicBool>,
        preflight_delay: Duration,
        receipt_poll: Arc<Mutex<Vec<Instant>>>,
        rpc_errors: Arc<AtomicUsize>,
    ) -> (BaseRpc, Arc<Mutex<Vec<Vec<u8>>>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let recorded = sent.clone();
        let app = Router::new().route(
            "/",
            post(move |Json(request): Json<Value>| {
                let recorded = recorded.clone();
                let relayer = relayer.clone();
                let release_receipt = release_receipt.clone();
                let receipt_poll = receipt_poll.clone();
                let rpc_errors = rpc_errors.clone();
                async move {
                    let method = request["method"].as_str().unwrap_or("");
                    if method == "eth_getTransactionReceipt"
                        && rpc_errors
                            .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                                left.checked_sub(1)
                            })
                            .is_ok()
                    {
                        return Json(json!({
                            "jsonrpc": "2.0",
                            "id": 1,
                            "error": { "code": -32000, "message": "unavailable" }
                        }));
                    }
                    if method == "eth_estimateGas" && !preflight_delay.is_zero() {
                        tokio::time::sleep(preflight_delay).await;
                    }
                    if method == "eth_getTransactionReceipt" {
                        receipt_poll.lock().unwrap().push(Instant::now());
                    }
                    let result = match method {
                        "eth_chainId" => json!("0x2105"),
                        "eth_getBalance" => json!("0xde0b6b3a7640000"),
                        "eth_getTransactionCount" => json!(format!("0x{pending:x}")),
                        "eth_estimateGas" => json!("0x186a0"),
                        "eth_maxPriorityFeePerGas" => json!("0x3b9aca00"),
                        "eth_call" => json!(eth_call_result(&request, &recorded, outcome)),
                        "eth_getBlockByNumber" => json!(block_result(&request, outcome)),
                        "eth_sendRawTransaction" => json!(send_raw(&request, &recorded)),
                        "eth_getTransactionByHash" => {
                            transaction_result(&request, &recorded, &relayer, outcome)
                        }
                        "eth_getTransactionReceipt" => {
                            receipt_result(&request, &recorded, outcome, &release_receipt)
                        }
                        _ => {
                            return Json(json!({
                                "jsonrpc": "2.0",
                                "id": 1,
                                "error": { "code": -32601, "message": "unsupported" }
                            }));
                        }
                    };
                    if method == "eth_getTransactionReceipt"
                        && matches!(outcome, Outcome::ReceiptError)
                    {
                        return Json(json!({
                            "jsonrpc": "2.0",
                            "id": 1,
                            "error": { "code": -32000, "message": "timeout" }
                        }));
                    }
                    Json(json!({"jsonrpc": "2.0", "id": 1, "result": result}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let url = format!("http://{address}");
        let timeout = Duration::from_secs(2) + preflight_delay;
        let rpc = BaseRpc::connect_timeout(&url, timeout).unwrap();
        (rpc, sent)
    }

    fn eth_call_result(
        request: &Value,
        sent: &Arc<Mutex<Vec<Vec<u8>>>>,
        outcome: Outcome,
    ) -> Value {
        let data = request["params"][0]["data"].as_str().unwrap_or("");
        let state = format!(
            "0x{}",
            hex_encode(&crate::chain::authorization_state_selector())
        );
        let balance = format!("0x{}", hex_encode(&crate::chain::balance_of_selector()));
        if data.starts_with(&state) {
            let used = !sent.lock().unwrap().is_empty()
                && !matches!(outcome, Outcome::AuthorizationUnused);
            let word = if used {
                format!("0x{}1", "0".repeat(63))
            } else {
                format!("0x{}", "0".repeat(64))
            };
            return json!(word);
        }
        if data.starts_with(&balance) {
            return json!(format!("0x{}2710", "0".repeat(60)));
        }
        json!("0x")
    }

    fn block_result(request: &Value, outcome: Outcome) -> Value {
        let latest = request["params"][0].as_str() == Some("latest");
        let hash = if latest {
            hex_word(0xcd)
        } else if matches!(outcome, Outcome::NonCanonical) {
            hex_word(0x22)
        } else {
            hex_word(0xab)
        };
        json!({
            "hash": hash,
            "baseFeePerGas": "0x3b9aca00"
        })
    }

    fn send_raw(request: &Value, sent: &Arc<Mutex<Vec<Vec<u8>>>>) -> Value {
        let raw = decode_hex(request["params"][0].as_str().unwrap_or("")).unwrap();
        let hash = hash_hex(transaction_hash(&raw));
        sent.lock().unwrap().push(raw);
        json!(hash)
    }

    fn transaction_result(
        request: &Value,
        sent: &Arc<Mutex<Vec<Vec<u8>>>>,
        relayer: &str,
        outcome: Outcome,
    ) -> Value {
        if matches!(outcome, Outcome::Dropped) {
            return Value::Null;
        }
        let Some(raw) = find_raw(request, sent) else {
            return Value::Null;
        };
        let parsed = parse_signed_tx(&raw).unwrap();
        let from = if matches!(outcome, Outcome::BadSender) {
            "0x0000000000000000000000000000000000000002".to_string()
        } else {
            relayer.to_string()
        };
        let nonce = if matches!(outcome, Outcome::BadNonce) {
            parsed.nonce.wrapping_add(1)
        } else {
            parsed.nonce
        };
        let mut input = parsed.data.clone();
        if matches!(outcome, Outcome::BadCalldata) {
            input.push(0);
        }
        json!({
            "hash": hash_hex(transaction_hash(&raw)),
            "from": from,
            "to": to_checksum(&USDC_ADDRESS),
            "nonce": format!("0x{:x}", nonce),
            "value": "0x0",
            "input": format!("0x{}", hex_encode(&input))
        })
    }

    fn receipt_result(
        request: &Value,
        sent: &Arc<Mutex<Vec<Vec<u8>>>>,
        outcome: Outcome,
        release_receipt: &AtomicBool,
    ) -> Value {
        if matches!(outcome, Outcome::Dropped) {
            return Value::Null;
        }
        let Some(raw) = find_raw(request, sent) else {
            return Value::Null;
        };
        if matches!(outcome, Outcome::WithheldReceipt) && !release_receipt.load(Ordering::SeqCst) {
            return Value::Null;
        }
        let parsed = parse_signed_tx(&raw).unwrap();
        let value = if matches!(outcome, Outcome::BadTransfer) {
            word(1)
        } else {
            parsed
                .data
                .get(4 + 64..4 + 96)
                .and_then(|bytes| bytes.try_into().ok())
                .unwrap_or(word(1))
        };
        let from = parsed.data.get(4 + 12..4 + 32).unwrap_or(&[0; 20]);
        let to = parsed.data.get(4 + 32 + 12..4 + 64).unwrap_or(&[0; 20]);
        let hash = if matches!(outcome, Outcome::NonCanonical) {
            hex_word(0x11)
        } else {
            hex_word(0xab)
        };
        json!({
            "transactionHash": hash_hex(transaction_hash(&raw)),
            "status": if matches!(outcome, Outcome::Revert) { "0x0" } else { "0x1" },
            "blockNumber": "0x10",
            "blockHash": hash,
            "logs": [{
                "address": to_checksum(&USDC_ADDRESS),
                "topics": [
                    format!("0x{}", hex_encode(&keccak(b"Transfer(address,address,uint256)"))),
                    format!("0x{}", hex_encode(&pad_topic(from))),
                    format!("0x{}", hex_encode(&pad_topic(to)))
                ],
                "data": format!("0x{}", hex_encode(&value)),
                "logIndex": "0x0"
            }]
        })
    }

    fn find_raw(request: &Value, sent: &Arc<Mutex<Vec<Vec<u8>>>>) -> Option<Vec<u8>> {
        let wanted = request["params"][0].as_str().unwrap_or("");
        sent.lock()
            .unwrap()
            .iter()
            .find(|raw| hash_hex(transaction_hash(raw)) == wanted)
            .cloned()
    }

    fn pad_topic(address: &[u8]) -> [u8; 32] {
        let mut word = [0u8; 32];
        let start = 32 - address.len().min(20);
        word[start..].copy_from_slice(&address[..address.len().min(20)]);
        word
    }

    fn hex_word(byte: u8) -> String {
        format!("0x{}", hex_encode(&[byte; 32]))
    }

    fn decode_hex(value: &str) -> Option<Vec<u8>> {
        let hex = value.strip_prefix("0x").unwrap_or(value);
        if !hex.len().is_multiple_of(2) {
            return None;
        }
        let bytes = hex.as_bytes();
        let mut out = Vec::with_capacity(bytes.len() / 2);
        let mut index = 0;
        while index < bytes.len() {
            out.push((hex_val(bytes[index])? << 4) | hex_val(bytes[index + 1])?);
            index += 2;
        }
        Some(out)
    }

    fn hex_val(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }
}
