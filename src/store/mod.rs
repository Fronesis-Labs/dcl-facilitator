//! SQLite payment store: idempotency, atomic transitions, crash recovery.
//!
//! Opening a database moves any `settling` row to `settlement_unknown`. That
//! state is recoverable and is never treated as a failed or retried settlement.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sqlx::sqlite::{
    SqliteConnectOptions, SqliteConnection, SqliteJournalMode, SqlitePoolOptions, SqliteRow,
};
use sqlx::{Row, SqlitePool};
use tokio::sync::Mutex;

use crate::chain::transaction_hash;
use crate::evidence::{
    authorization_digest_for, payment_key_of, same_consumption, ActionId, AuthorizationIdentity,
    ConsumptionRecord, DclDecisionEvidence, DecisionBody, DecisionReason, EvidenceId, PaymentKey,
    Verdict,
};
use crate::leibniz::{ActionDigest, Commit, Decision, PaymentContext};
use crate::machine::{Payment, PaymentState, TransitionError};

const SCHEMA: &str = include_str!("schema.sql");

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Transition(#[from] TransitionError),
    #[error("idempotency key already used with different payment fields")]
    Conflict,
    #[error("payment not found")]
    NotFound,
    #[error("stored payment row is corrupt")]
    Corrupt,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PutOutcome {
    Created(Payment),
    Existing(Payment),
}

#[derive(Clone)]
pub struct Store {
    inner: Arc<Inner>,
}

struct Inner {
    pool: SqlitePool,
    write: Mutex<()>,
    /// Held across nonce selection and the commit that stores that nonce.
    nonce: Mutex<()>,
    /// One mutex per payment identity. Held from the state read through signing.
    payments: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// Test hook reached after `Relayer::sign` and before `commit_signed`.
    #[cfg(test)]
    sign_gate: Mutex<Option<Arc<SignGate>>>,
}

/// One verified Oracle `COMMIT` and the relayer transaction stored with it.
#[derive(Clone, Copy)]
pub struct SignedCommit<'a> {
    pub context: &'a PaymentContext,
    pub action: &'a ActionDigest,
    pub commit: &'a Commit,
    pub signed: &'a SignedSettlement,
    pub record: &'a ConsumptionRecord,
    pub evidence: &'a DclDecisionEvidence,
    pub claim: &'a SigningClaim,
}

impl Store {
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_secs(5))
            .foreign_keys(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await?;

        let store = Self {
            inner: Arc::new(Inner {
                pool,
                write: Mutex::new(()),
                nonce: Mutex::new(()),
                payments: Mutex::new(HashMap::new()),
                #[cfg(test)]
                sign_gate: Mutex::new(None),
            }),
        };
        store.migrate().await?;
        store.recover_interrupted().await?;
        Ok(store)
    }

    pub async fn close(&self) {
        self.inner.pool.close().await;
    }

    async fn migrate(&self) -> Result<(), StoreError> {
        let mut tx = self.begin_write().await?;
        let result = async {
            let paused = migrate_inner(&mut tx.conn, false).await?;
            if paused {
                return Err(StoreError::Corrupt);
            }
            ensure_signing_claim_columns(&mut tx.conn).await?;
            Ok(())
        }
        .await;
        tx.finish(result).await
    }

    /// Any in-flight `settling` row is uncertain after a process stop.
    /// Does not submit, complete, or fail the settlement.
    async fn recover_interrupted(&self) -> Result<Vec<Payment>, StoreError> {
        let mut tx = self.begin_write().await?;
        let result = recover_interrupted_inner(&mut tx.conn).await;
        tx.finish(result).await
    }

    pub async fn interrupted(&self) -> Result<Vec<Payment>, StoreError> {
        let rows = sqlx::query("SELECT * FROM payments WHERE state = ?")
            .bind(PaymentState::SettlementUnknown.as_str())
            .fetch_all(&self.inner.pool)
            .await?;
        rows.iter().map(payment_from_row).collect()
    }

    pub async fn get(
        &self,
        network: &str,
        payer: &str,
        nonce: &str,
    ) -> Result<Payment, StoreError> {
        let row =
            sqlx::query("SELECT * FROM payments WHERE network = ? AND payer = ? AND nonce = ?")
                .bind(network)
                .bind(payer)
                .bind(nonce)
                .fetch_optional(&self.inner.pool)
                .await?
                .ok_or(StoreError::NotFound)?;
        payment_from_row(&row)
    }

    pub async fn record_received(
        &self,
        context: PaymentContext,
        action: ActionDigest,
    ) -> Result<PutOutcome, StoreError> {
        let mut tx = self.begin_write().await?;
        let result = record_received_inner(&mut tx.conn, context, action).await;
        tx.finish(result).await
    }

    pub async fn mark_verified(
        &self,
        context: &PaymentContext,
        action: &ActionDigest,
    ) -> Result<Payment, StoreError> {
        self.transition(context, action, "verified", |p| p.mark_verified())
            .await
    }

    /// Persist a verified Oracle `COMMIT`, its payer signature, and `Committed`
    /// in one transaction. A later decision cannot replace that row.
    pub async fn persist_verified_commit(
        &self,
        context: &PaymentContext,
        action: &ActionDigest,
        commit: &Commit,
        record: &ConsumptionRecord,
        evidence: &DclDecisionEvidence,
        payer_signature: &[u8; 65],
    ) -> Result<Payment, StoreError> {
        let mut tx = self.begin_write().await?;
        let result = persist_verified_commit_inner(
            &mut tx.conn,
            context,
            action,
            commit,
            record,
            evidence,
            payer_signature,
        )
        .await;
        tx.finish(result).await
    }

    pub async fn begin_settlement(
        &self,
        context: &PaymentContext,
        action: &ActionDigest,
        commit: &Commit,
    ) -> Result<Payment, StoreError> {
        self.transition(context, action, "begin_settlement", |p| {
            p.begin_settlement(commit)
        })
        .await
    }

    pub async fn complete_settlement(
        &self,
        context: &PaymentContext,
        action: &ActionDigest,
    ) -> Result<Payment, StoreError> {
        self.transition(context, action, "complete_settlement", |p| {
            p.complete_settlement()
        })
        .await
    }

    pub async fn resolve_uncertain(
        &self,
        context: &PaymentContext,
        action: &ActionDigest,
        outcome: PaymentState,
    ) -> Result<Payment, StoreError> {
        self.transition(context, action, "resolve_uncertain", |p| {
            p.resolve_uncertain(outcome)
        })
        .await
    }

    /// Serialize settlement of one payment. Hold this before reading its
    /// state and until signing and the receipt outcome have finished.
    /// The key is the payment identity `(network, payer, nonce)`, which is
    /// the row that owns a single `payment_id`.
    pub async fn lock_payment(&self, context: &PaymentContext) -> tokio::sync::OwnedMutexGuard<()> {
        let key = format!(
            "{}\n{}\n{}",
            context.network(),
            context.payer(),
            context.nonce()
        );
        let mutex = {
            let mut payments = self.inner.payments.lock().await;
            payments
                .entry(key)
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        mutex.lock_owned().await
    }

    /// Serialize relayer nonce allocation. Hold this until the signed
    /// transaction and `Settling` row have committed.
    pub async fn lock_nonces(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.inner.nonce.lock().await
    }

    /// Next unused relayer nonce. `pending` is the account's pending transaction count.
    pub async fn next_relayer_nonce(&self, relayer: &str, pending: u64) -> Result<u64, StoreError> {
        let row = sqlx::query(
            "SELECT MAX(relayer_nonce) AS n FROM settlement_evidence WHERE relayer_address = ?",
        )
        .bind(relayer)
        .fetch_one(&self.inner.pool)
        .await?;
        let reserved_next = match row.try_get::<Option<i64>, _>("n")? {
            Some(nonce) => u64::try_from(nonce)
                .map_err(|_| StoreError::Corrupt)?
                .saturating_add(1),
            None => 0,
        };
        Ok(pending.max(reserved_next))
    }

    pub async fn evidence(
        &self,
        context: &PaymentContext,
    ) -> Result<Option<SettlementEvidence>, StoreError> {
        let row = sqlx::query(
            "SELECT e.relayer_address, e.relayer_nonce, e.tx_hash, e.raw_tx, e.calldata,
                    e.receipt_status
             FROM settlement_evidence e
             JOIN payments p ON p.id = e.payment_id
             WHERE p.network = ? AND p.payer = ? AND p.nonce = ?",
        )
        .bind(context.network())
        .bind(context.payer())
        .bind(context.nonce())
        .fetch_optional(&self.inner.pool)
        .await?;
        row.as_ref().map(evidence_from_row).transpose()
    }

    /// Authorization fields stored with the signed transaction.
    /// Recovery rebuilds the receipt checks from this row. It does not sign.
    pub async fn stored_authorization(
        &self,
        context: &PaymentContext,
    ) -> Result<Option<StoredAuthorization>, StoreError> {
        let row = sqlx::query(
            "SELECT p.payer, p.pay_to, p.nonce,
                    e.authorization_value, e.valid_after, e.valid_before, e.signature
             FROM settlement_evidence e
             JOIN payments p ON p.id = e.payment_id
             WHERE p.network = ? AND p.payer = ? AND p.nonce = ?",
        )
        .bind(context.network())
        .bind(context.payer())
        .bind(context.nonce())
        .fetch_optional(&self.inner.pool)
        .await?;
        row.as_ref().map(stored_authorization_from_row).transpose()
    }

    /// Persist the Oracle `COMMIT`, the signed transaction, and `Settling` together.
    ///
    /// The `claim` is the inter-process right to sign, taken before
    /// `Relayer::sign`. A different claim, or none, rolls this transition back.
    /// Callers broadcast only after this returns.
    pub async fn commit_signed(&self, write: SignedCommit<'_>) -> Result<Payment, StoreError> {
        let mut tx = self.begin_write().await?;
        let result = commit_signed_inner(&mut tx.conn, write).await;
        tx.finish(result).await
    }

    /// Take the only right to sign this verified `COMMIT`.
    ///
    /// The update is one `BEGIN IMMEDIATE`. A second process gets
    /// [`StoreError::Conflict`] until the claim expires or is released. Local
    /// signing is expected to finish well inside the lease. A crash leaves the
    /// claim in place until that lease, and then another process may take it.
    /// `commit_signed` accepts only the token stored here.
    pub async fn claim_signing(
        &self,
        context: &PaymentContext,
    ) -> Result<SigningClaim, StoreError> {
        let mut tx = self.begin_write().await?;
        let result = claim_signing_inner(&mut tx.conn, context).await;
        tx.finish(result).await
    }

    /// Drop a claim that did not become a consumed `COMMIT`.
    ///
    /// A claim already cleared or replaced is left untouched.
    pub async fn release_signing_claim(&self, claim: &SigningClaim) -> Result<(), StoreError> {
        let mut tx = self.begin_write().await?;
        let result = release_signing_claim_inner(&mut tx.conn, claim).await;
        tx.finish(result).await
    }

    /// Arm the one-shot pause between signing and `commit_signed`.
    #[cfg(test)]
    pub async fn arm_sign_gate(&self) -> Arc<SignGate> {
        let gate = Arc::new(SignGate {
            entered: std::sync::atomic::AtomicBool::new(false),
            release: std::sync::atomic::AtomicBool::new(false),
        });
        *self.inner.sign_gate.lock().await = Some(gate.clone());
        gate
    }

    #[cfg(test)]
    pub async fn sign_gate(&self) -> Option<Arc<SignGate>> {
        self.inner.sign_gate.lock().await.clone()
    }

    /// Make every current signing lease look expired.
    #[cfg(test)]
    pub async fn expire_signing_claims(&self) -> Result<(), StoreError> {
        let mut tx = self.begin_write().await?;
        let result = sqlx::query("UPDATE decision_consumptions SET signing_claim_until = 0")
            .execute(&mut *tx.conn)
            .await
            .map(|_| ())
            .map_err(StoreError::from);
        tx.finish(result).await
    }

    /// Record Oracle `NO_COMMIT` and reject the payment when the machine allows it.
    ///
    /// The consumption row is kept even when the payment is already past
    /// `Verified`, so a restart still refuses to sign.
    pub async fn refuse(
        &self,
        context: &PaymentContext,
        action: &ActionDigest,
        decision: &Decision,
        record: &ConsumptionRecord,
        evidence: &DclDecisionEvidence,
    ) -> Result<Payment, StoreError> {
        let mut tx = self.begin_write().await?;
        let result = refuse_inner(&mut tx.conn, context, action, decision, record, evidence).await;
        tx.finish(result).await
    }

    /// Oracle decision stored for this payment, including the signed body.
    ///
    /// `Ok(None)` means there is no complete `COMMIT`. Incomplete legacy rows,
    /// `NO_COMMIT`, and absent rows are not returned. Callers must not sign or
    /// broadcast from `Ok(None)`.
    pub async fn stored_decision(
        &self,
        context: &PaymentContext,
    ) -> Result<Option<StoredDecision>, StoreError> {
        Ok(match self.stored_commit(context).await? {
            StoredCommit::Verified(decision) | StoredCommit::Consumed(decision) => Some(decision),
            StoredCommit::Absent | StoredCommit::Incomplete | StoredCommit::NoCommit => None,
        })
    }

    /// Classify the decision row settlement and recovery are allowed to see.
    pub async fn stored_commit(
        &self,
        context: &PaymentContext,
    ) -> Result<StoredCommit, StoreError> {
        let key = match payment_key_of(context) {
            Ok(key) => key,
            Err(_) => return Ok(StoredCommit::Absent),
        };
        let row = sqlx::query(
            "SELECT evidence_id, decision_digest, action_id, action_digest, reason,
                    oracle_signature, body_network, body_payer, body_pay_to, body_asset,
                    body_nonce, chain_id, verifying_contract, auth_payer, auth_recipient,
                    auth_value, auth_valid_after, auth_valid_before, auth_nonce, verdict,
                    raw_tx_hash, state, legacy_incomplete, payer_signature
             FROM decision_consumptions
             WHERE network = ? AND payer = ? AND nonce = ?",
        )
        .bind(key.network())
        .bind(key.payer())
        .bind(key.nonce())
        .fetch_optional(&self.inner.pool)
        .await?;
        match row {
            Some(row) => classify_stored_commit(&row),
            None => Ok(StoredCommit::Absent),
        }
    }

    /// `COMMIT` consumption whose authorization digest matches this payment.
    pub async fn commit_authorizes(
        &self,
        context: &PaymentContext,
        authorization_digest: [u8; 32],
    ) -> Result<bool, StoreError> {
        Ok(self
            .consumed_verdict(context)
            .await?
            .is_some_and(|(verdict, digest)| {
                verdict == Verdict::Commit && digest == authorization_digest
            }))
    }

    pub async fn consumed_verdict(
        &self,
        context: &PaymentContext,
    ) -> Result<Option<(Verdict, [u8; 32])>, StoreError> {
        let key = match payment_key_of(context) {
            Ok(key) => key,
            Err(_) => return Ok(None),
        };
        let row = sqlx::query(
            "SELECT verdict, state, authorization_digest
             FROM decision_consumptions
             WHERE network = ? AND payer = ? AND nonce = ?",
        )
        .bind(key.network())
        .bind(key.payer())
        .bind(key.nonce())
        .fetch_optional(&self.inner.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let state: String = row.try_get("state")?;
        if state != "consumed" && state != "verified" {
            return Err(StoreError::Corrupt);
        }
        let verdict = parse_verdict(&row.try_get::<String, _>("verdict")?)?;
        let digest: [u8; 32] = fixed_array(row.try_get("authorization_digest")?)?;
        Ok(Some((verdict, digest)))
    }

    /// `SettlementUnknown` rows that already have a consumed Oracle `COMMIT`.
    /// Older rows from the local gate are left in place and are not returned.
    pub async fn proven_unknown(&self) -> Result<Vec<Payment>, StoreError> {
        let rows = sqlx::query(
            "SELECT p.* FROM payments p
             INNER JOIN decision_consumptions c
               ON c.network = p.network
              AND c.payer = lower(p.payer)
              AND c.nonce = lower(p.nonce)
             WHERE p.state = ?
               AND c.verdict = 'commit'
               AND c.state = 'consumed'
               AND c.legacy_incomplete = 0
               AND c.raw_tx_hash IS NOT NULL
               AND length(c.payer_signature) = 65",
        )
        .bind(PaymentState::SettlementUnknown.as_str())
        .fetch_all(&self.inner.pool)
        .await?;
        rows.iter().map(payment_from_row).collect()
    }

    /// `Committed` payments whose only decision is a complete verified `COMMIT`
    /// and which have no settlement evidence. Recovery may sign these after
    /// revalidation. Incomplete rows are excluded.
    pub async fn verified_commits_awaiting_signature(&self) -> Result<Vec<Payment>, StoreError> {
        let rows = sqlx::query(
            "SELECT p.* FROM payments p
             INNER JOIN decision_consumptions c
               ON c.network = p.network
              AND c.payer = lower(p.payer)
              AND c.nonce = lower(p.nonce)
             WHERE p.state = 'committed'
               AND c.verdict = 'commit'
               AND c.state = 'verified'
               AND c.legacy_incomplete = 0
               AND c.raw_tx_hash IS NULL
               AND length(c.payer_signature) = 65
               AND NOT EXISTS (
                   SELECT 1 FROM settlement_evidence e WHERE e.payment_id = p.id
               )",
        )
        .fetch_all(&self.inner.pool)
        .await?;
        rows.iter().map(payment_from_row).collect()
    }

    pub async fn conclude(
        &self,
        context: &PaymentContext,
        action: &ActionDigest,
        observation: &ReceiptObservation,
        outcome: PaymentState,
    ) -> Result<Payment, StoreError> {
        let mut tx = self.begin_write().await?;
        let result = conclude_inner(&mut tx.conn, context, action, observation, outcome).await;
        tx.finish(result).await
    }

    /// The signed attempt was never included and `validBefore` has passed.
    /// Does not sign, broadcast, or create another payment row.
    pub async fn expire_unmined(
        &self,
        context: &PaymentContext,
        action: &ActionDigest,
    ) -> Result<Payment, StoreError> {
        let mut tx = self.begin_write().await?;
        let result = expire_unmined_inner(&mut tx.conn, context, action).await;
        tx.finish(result).await
    }

    pub async fn mark_unknown(
        &self,
        context: &PaymentContext,
        action: &ActionDigest,
    ) -> Result<Payment, StoreError> {
        self.transition(context, action, "settlement outcome unknown", |payment| {
            payment.mark_uncertain()
        })
        .await
    }

    #[cfg(test)]
    pub async fn consumption_count(&self) -> Result<i64, StoreError> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM decision_consumptions")
            .fetch_one(&self.inner.pool)
            .await?;
        Ok(row.try_get("n")?)
    }

    #[cfg(test)]
    pub async fn delete_consumptions(&self) -> Result<(), StoreError> {
        let mut tx = self.begin_write().await?;
        sqlx::query("DELETE FROM decision_consumptions")
            .execute(&mut *tx.conn)
            .await?;
        tx.finish(Ok(())).await
    }

    /// Insert a consumption row without moving the payment. Tests use this to
    /// place a `NO_COMMIT` beside a payment that is still `Verified`.
    #[cfg(test)]
    pub async fn plant_consumption(
        &self,
        evidence: &DclDecisionEvidence,
    ) -> Result<(), StoreError> {
        let body = evidence.body();
        let record = ConsumptionRecord::from_parts(
            body.evidence_id(),
            body.authorization().digest(),
            payment_key_of(body.payment_context()).map_err(|_| StoreError::Conflict)?,
            body.verdict(),
            evidence
                .decision_digest()
                .map_err(|_| StoreError::Conflict)?,
        );
        let mut tx = self.begin_write().await?;
        let result = consume_decision(
            &mut tx.conn,
            &record,
            evidence,
            None,
            body.payment_context(),
            body.action_digest(),
        )
        .await
        .map(|_| ());
        tx.finish(result).await
    }

    #[cfg(test)]
    pub async fn overwrite_oracle_signature(&self, signature: &[u8]) -> Result<(), StoreError> {
        self.write_sql(
            sqlx::query("UPDATE decision_consumptions SET oracle_signature = ?").bind(signature),
        )
        .await
    }

    #[cfg(test)]
    pub async fn overwrite_decision_reason(&self, reason: &str) -> Result<(), StoreError> {
        self.write_sql(sqlx::query("UPDATE decision_consumptions SET reason = ?").bind(reason))
            .await
    }

    #[cfg(test)]
    pub async fn overwrite_decision_digest(&self, digest: &[u8]) -> Result<(), StoreError> {
        self.write_sql(
            sqlx::query("UPDATE decision_consumptions SET decision_digest = ?").bind(digest),
        )
        .await
    }

    #[cfg(test)]
    pub async fn overwrite_raw_tx_hash(&self, hash: &[u8]) -> Result<(), StoreError> {
        self.write_sql(sqlx::query("UPDATE decision_consumptions SET raw_tx_hash = ?").bind(hash))
            .await
    }

    #[cfg(test)]
    pub async fn set_payment_state(
        &self,
        context: &PaymentContext,
        state: &str,
    ) -> Result<(), StoreError> {
        self.write_sql(
            sqlx::query(
                "UPDATE payments SET state = ? WHERE network = ? AND payer = ? AND nonce = ?",
            )
            .bind(state)
            .bind(context.network())
            .bind(context.payer())
            .bind(context.nonce()),
        )
        .await
    }

    #[cfg(test)]
    pub async fn mark_decision_incomplete(
        &self,
        context: &PaymentContext,
    ) -> Result<(), StoreError> {
        let key = payment_key_of(context).map_err(|_| StoreError::Conflict)?;
        self.write_sql(
            sqlx::query(
                "UPDATE decision_consumptions SET legacy_incomplete = 1
                 WHERE network = ? AND payer = ? AND nonce = ?",
            )
            .bind(key.network())
            .bind(key.payer())
            .bind(key.nonce()),
        )
        .await
    }

    #[cfg(test)]
    pub async fn reopen_decision_as_verified(
        &self,
        context: &PaymentContext,
    ) -> Result<(), StoreError> {
        let key = payment_key_of(context).map_err(|_| StoreError::Conflict)?;
        self.write_sql(
            sqlx::query(
                "UPDATE decision_consumptions
                 SET state = 'verified', raw_tx_hash = NULL
                 WHERE network = ? AND payer = ? AND nonce = ?",
            )
            .bind(key.network())
            .bind(key.payer())
            .bind(key.nonce()),
        )
        .await
    }

    #[cfg(test)]
    pub async fn clear_oracle_evidence(&self) -> Result<(), StoreError> {
        self.write_sql(sqlx::query(
            "UPDATE decision_consumptions
             SET action_id = NULL, action_digest = NULL, reason = NULL,
                 oracle_signature = NULL, body_network = NULL, body_payer = NULL,
                 body_pay_to = NULL, body_asset = NULL, body_nonce = NULL,
                 chain_id = NULL, verifying_contract = NULL, auth_payer = NULL,
                 auth_recipient = NULL, auth_value = NULL, auth_valid_after = NULL,
                 auth_valid_before = NULL, auth_nonce = NULL, raw_tx_hash = NULL",
        ))
        .await
    }

    #[cfg(test)]
    pub async fn overwrite_payer_signature(&self, signature: &[u8]) -> Result<(), StoreError> {
        self.write_sql(sqlx::query("UPDATE settlement_evidence SET signature = ?").bind(signature))
            .await
    }

    #[cfg(test)]
    pub async fn overwrite_raw_transaction(
        &self,
        raw: &[u8],
        hash: &[u8],
        calldata: &[u8],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin_write().await?;
        let result = async {
            sqlx::query("UPDATE settlement_evidence SET raw_tx = ?, tx_hash = ?, calldata = ?")
                .bind(raw)
                .bind(hash)
                .bind(calldata)
                .execute(&mut *tx.conn)
                .await?;
            sqlx::query("UPDATE decision_consumptions SET raw_tx_hash = ?")
                .bind(hash)
                .execute(&mut *tx.conn)
                .await?;
            Ok(())
        }
        .await;
        tx.finish(result).await
    }

    #[cfg(test)]
    async fn write_sql<'a>(
        &self,
        query: sqlx::query::Query<'a, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'a>>,
    ) -> Result<(), StoreError> {
        let mut tx = self.begin_write().await?;
        let result = query.execute(&mut *tx.conn).await.map(|_| ());
        tx.finish(result.map_err(StoreError::from)).await
    }

    #[cfg(test)]
    pub async fn payment_count(&self) -> Result<i64, StoreError> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM payments")
            .fetch_one(&self.inner.pool)
            .await?;
        Ok(row.try_get("n")?)
    }

    #[cfg(test)]
    pub async fn relayer_nonces(&self, relayer: &str) -> Result<Vec<u64>, StoreError> {
        let rows = sqlx::query(
            "SELECT relayer_nonce FROM settlement_evidence WHERE relayer_address = ? ORDER BY relayer_nonce",
        )
        .bind(relayer)
        .fetch_all(&self.inner.pool)
        .await?;
        rows.iter()
            .map(|row| {
                let nonce: i64 = row.try_get("relayer_nonce")?;
                u64::try_from(nonce).map_err(|_| StoreError::Corrupt)
            })
            .collect()
    }

    pub async fn event_to_states(
        &self,
        context: &PaymentContext,
    ) -> Result<Vec<PaymentState>, StoreError> {
        let rows = sqlx::query(
            "SELECT e.to_state FROM events e
             JOIN payments p ON p.id = e.payment_id
             WHERE p.network = ? AND p.payer = ? AND p.nonce = ?
             ORDER BY e.id ASC",
        )
        .bind(context.network())
        .bind(context.payer())
        .bind(context.nonce())
        .fetch_all(&self.inner.pool)
        .await?;

        rows.iter()
            .map(|row| {
                let label: String = row.try_get("to_state")?;
                PaymentState::parse(&label).ok_or(StoreError::Corrupt)
            })
            .collect()
    }

    async fn transition<F>(
        &self,
        context: &PaymentContext,
        action: &ActionDigest,
        note: &str,
        mutate: F,
    ) -> Result<Payment, StoreError>
    where
        F: FnOnce(&mut Payment) -> Result<(), TransitionError>,
    {
        let mut tx = self.begin_write().await?;
        let result = transition_inner(&mut tx.conn, context, action, note, mutate).await;
        tx.finish(result).await
    }

    async fn begin_write(&self) -> Result<WriteTx<'_>, StoreError> {
        let guard = self.inner.write.lock().await;
        let mut conn = self.inner.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        Ok(WriteTx {
            _guard: guard,
            conn,
        })
    }
}

struct WriteTx<'a> {
    _guard: tokio::sync::MutexGuard<'a, ()>,
    conn: sqlx::pool::PoolConnection<sqlx::Sqlite>,
}

impl WriteTx<'_> {
    async fn finish<T>(mut self, result: Result<T, StoreError>) -> Result<T, StoreError> {
        match result {
            Ok(value) => {
                sqlx::query("COMMIT").execute(&mut *self.conn).await?;
                Ok(value)
            }
            Err(err) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *self.conn).await;
                Err(err)
            }
        }
    }
}

async fn recover_interrupted_inner(
    conn: &mut SqliteConnection,
) -> Result<Vec<Payment>, StoreError> {
    let rows = sqlx::query("SELECT * FROM payments WHERE state = ?")
        .bind(PaymentState::Settling.as_str())
        .fetch_all(&mut *conn)
        .await?;

    let mut recovered = Vec::new();
    for row in rows {
        let mut payment = payment_from_row(&row)?;
        let id: i64 = row.try_get("id")?;
        let from = payment.state();
        payment.mark_uncertain()?;
        persist_transition(conn, id, &payment, from, "process stopped mid-settle").await?;
        recovered.push(payment);
    }
    Ok(recovered)
}

async fn record_received_inner(
    conn: &mut SqliteConnection,
    context: PaymentContext,
    action: ActionDigest,
) -> Result<PutOutcome, StoreError> {
    if let Some(existing) =
        load_by_key(conn, context.network(), context.payer(), context.nonce()).await?
    {
        return if existing.context() == &context && existing.action() == &action {
            Ok(PutOutcome::Existing(existing))
        } else {
            Err(StoreError::Conflict)
        };
    }

    let payment = Payment::received(context.clone(), action);
    let result = sqlx::query(
        "INSERT INTO payments
            (network, payer, pay_to, asset, nonce, action_digest, state)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(context.network())
    .bind(context.payer())
    .bind(context.pay_to())
    .bind(context.asset())
    .bind(context.nonce())
    .bind(action.as_bytes().as_slice())
    .bind(payment.state().as_str())
    .execute(&mut *conn)
    .await;

    match result {
        Ok(done) => {
            append_event(
                conn,
                done.last_insert_rowid(),
                None,
                payment.state(),
                "received",
            )
            .await?;
            Ok(PutOutcome::Created(payment))
        }
        Err(err) if is_unique_violation(&err) => {
            let existing = load_by_key(conn, context.network(), context.payer(), context.nonce())
                .await?
                .ok_or(StoreError::NotFound)?;
            if existing.context() == &context && existing.action() == &action {
                Ok(PutOutcome::Existing(existing))
            } else {
                Err(StoreError::Conflict)
            }
        }
        Err(err) => Err(err.into()),
    }
}

async fn transition_inner<F>(
    conn: &mut SqliteConnection,
    context: &PaymentContext,
    action: &ActionDigest,
    note: &str,
    mutate: F,
) -> Result<Payment, StoreError>
where
    F: FnOnce(&mut Payment) -> Result<(), TransitionError>,
{
    let row = sqlx::query("SELECT * FROM payments WHERE network = ? AND payer = ? AND nonce = ?")
        .bind(context.network())
        .bind(context.payer())
        .bind(context.nonce())
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(StoreError::NotFound)?;

    let mut payment = payment_from_row(&row)?;
    if payment.context() != context || payment.action() != action {
        return Err(StoreError::Conflict);
    }
    let id: i64 = row.try_get("id")?;
    let from = payment.state();
    mutate(&mut payment)?;
    persist_transition(conn, id, &payment, from, note).await?;
    Ok(payment)
}

async fn persist_transition(
    conn: &mut SqliteConnection,
    id: i64,
    payment: &Payment,
    from: PaymentState,
    note: &str,
) -> Result<(), StoreError> {
    let updated = sqlx::query("UPDATE payments SET state = ? WHERE id = ? AND state = ?")
        .bind(payment.state().as_str())
        .bind(id)
        .bind(from.as_str())
        .execute(&mut *conn)
        .await?
        .rows_affected();
    if updated != 1 {
        return Err(TransitionError::DuplicateSettlement.into());
    }
    append_event(conn, id, Some(from), payment.state(), note).await
}

async fn append_event(
    conn: &mut SqliteConnection,
    payment_id: i64,
    from: Option<PaymentState>,
    to: PaymentState,
    note: &str,
) -> Result<(), StoreError> {
    sqlx::query("INSERT INTO events (payment_id, from_state, to_state, note) VALUES (?, ?, ?, ?)")
        .bind(payment_id)
        .bind(from.map(PaymentState::as_str))
        .bind(to.as_str())
        .bind(note)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

async fn load_by_key(
    conn: &mut SqliteConnection,
    network: &str,
    payer: &str,
    nonce: &str,
) -> Result<Option<Payment>, StoreError> {
    let row = sqlx::query("SELECT * FROM payments WHERE network = ? AND payer = ? AND nonce = ?")
        .bind(network)
        .bind(payer)
        .bind(nonce)
        .fetch_optional(&mut *conn)
        .await?;
    row.as_ref().map(payment_from_row).transpose()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedSettlement {
    pub value: [u8; 32],
    pub valid_after: [u8; 32],
    pub valid_before: [u8; 32],
    pub signature: [u8; 65],
    pub calldata: Vec<u8>,
    pub relayer_address: String,
    pub relayer_nonce: u64,
    pub tx_hash: [u8; 32],
    pub raw_tx: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAuthorization {
    pub payer: String,
    pub pay_to: String,
    pub nonce: String,
    pub value: [u8; 32],
    pub valid_after: [u8; 32],
    pub valid_before: [u8; 32],
    pub signature: [u8; 65],
}

/// Oracle decision read back from `decision_consumptions`.
///
/// `decision_digest` is the stored column. Callers recompute it from
/// `evidence` and reject the row when the two differ. Incomplete legacy rows
/// are not represented here.
pub struct StoredDecision {
    pub evidence: DclDecisionEvidence,
    pub decision_digest: [u8; 32],
    pub raw_tx_hash: Option<[u8; 32]>,
    /// `verified` or `consumed`.
    pub state: String,
    pub payer_signature: Option<[u8; 65]>,
}

/// First durable decision for one payment, as settlement and recovery may use it.
pub enum StoredCommit {
    Absent,
    /// `legacy_incomplete = 1`, or a `COMMIT` that cannot be revalidated.
    Incomplete,
    NoCommit,
    Verified(StoredDecision),
    Consumed(StoredDecision),
}

/// Token that proves this process won [`Store::claim_signing`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningClaim {
    token: [u8; 16],
}

/// Pauses the signer after the relayer returns and before `commit_signed`.
#[cfg(test)]
#[derive(Debug)]
pub struct SignGate {
    pub entered: std::sync::atomic::AtomicBool,
    pub release: std::sync::atomic::AtomicBool,
}

/// How long a signing claim blocks other processes. Local signing finishes
/// inside this window. After it, a crashed holder no longer owns the row.
const SIGNING_CLAIM_SECS: i64 = 60;

pub struct SettlementEvidence {
    pub relayer_address: String,
    pub relayer_nonce: u64,
    pub tx_hash: [u8; 32],
    pub raw_tx: Vec<u8>,
    pub calldata: Vec<u8>,
    pub receipt_status: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptObservation {
    pub status: u64,
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub transfer_log_index: Option<u64>,
}

struct DecisionMeta {
    evidence_id: [u8; 32],
    decision_digest: [u8; 32],
    authorization_digest: [u8; 32],
    verdict: Verdict,
    state: String,
    legacy_incomplete: i64,
    payer_signature: Option<Vec<u8>>,
    raw_tx_hash: Option<Vec<u8>>,
}

async fn load_decision_meta(
    conn: &mut SqliteConnection,
    key: &PaymentKey,
) -> Result<Option<DecisionMeta>, StoreError> {
    let row = sqlx::query(
        "SELECT evidence_id, decision_digest, authorization_digest, verdict, state,
                legacy_incomplete, payer_signature, raw_tx_hash
         FROM decision_consumptions
         WHERE network = ? AND payer = ? AND nonce = ?",
    )
    .bind(key.network())
    .bind(key.payer())
    .bind(key.nonce())
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let payer_signature: Option<Vec<u8>> = row.try_get("payer_signature")?;
    let raw_tx_hash: Option<Vec<u8>> = row.try_get("raw_tx_hash")?;
    Ok(Some(DecisionMeta {
        evidence_id: fixed_array(row.try_get("evidence_id")?)?,
        decision_digest: fixed_array(row.try_get("decision_digest")?)?,
        authorization_digest: fixed_array(row.try_get("authorization_digest")?)?,
        verdict: parse_verdict(&row.try_get::<String, _>("verdict")?)?,
        state: row.try_get("state")?,
        legacy_incomplete: row.try_get("legacy_incomplete")?,
        payer_signature,
        raw_tx_hash,
    }))
}

fn same_verified_commit(
    stored: &DecisionMeta,
    record: &ConsumptionRecord,
    payer_signature: &[u8; 65],
) -> bool {
    stored.legacy_incomplete == 0
        && stored.state == "verified"
        && stored.verdict == Verdict::Commit
        && stored.raw_tx_hash.is_none()
        && stored.evidence_id == *record.evidence_id().as_bytes()
        && stored.decision_digest == record.decision_digest()
        && stored.authorization_digest == record.authorization_digest()
        && stored.payer_signature.as_deref() == Some(payer_signature.as_slice())
}

async fn settlement_recorded(
    conn: &mut SqliteConnection,
    context: &PaymentContext,
) -> Result<bool, StoreError> {
    let row = sqlx::query(
        "SELECT 1 AS present
         FROM settlement_evidence AS e
         JOIN payments AS p ON p.id = e.payment_id
         WHERE p.network = ? AND p.payer = ? AND p.nonce = ?",
    )
    .bind(context.network())
    .bind(context.payer())
    .bind(context.nonce())
    .fetch_optional(&mut *conn)
    .await?;
    Ok(row.is_some())
}

async fn persist_verified_commit_inner(
    conn: &mut SqliteConnection,
    context: &PaymentContext,
    action: &ActionDigest,
    commit: &Commit,
    record: &ConsumptionRecord,
    evidence: &DclDecisionEvidence,
    payer_signature: &[u8; 65],
) -> Result<Payment, StoreError> {
    if record.verdict() != Verdict::Commit || !commit.binds(context, action) {
        return Err(StoreError::Conflict);
    }
    let key = payment_key_of(context).map_err(|_| StoreError::Conflict)?;
    if record.payment_key() != &key {
        return Err(StoreError::Conflict);
    }
    if evidence_matches(evidence, record, context, action).is_err() {
        return Err(StoreError::Conflict);
    }
    let payment = load_by_key(conn, context.network(), context.payer(), context.nonce())
        .await?
        .ok_or(StoreError::NotFound)?;
    if payment.context() != context || payment.action() != action {
        return Err(StoreError::Conflict);
    }
    if let Some(stored) = load_decision_meta(conn, &key).await? {
        if !same_verified_commit(&stored, record, payer_signature) {
            return Err(StoreError::Conflict);
        }
        if payment.state() == PaymentState::Committed {
            return Ok(payment);
        }
        if payment.state() != PaymentState::Verified {
            return Err(StoreError::Conflict);
        }
        let decision = Decision::Commit(commit.clone());
        return transition_inner(conn, context, action, decision.reason(), |payment| {
            payment.apply_decision(&decision)
        })
        .await;
    }
    if payment.state() != PaymentState::Verified {
        return Err(StoreError::Conflict);
    }
    insert_verified_commit(conn, &key, record, evidence, payer_signature).await?;
    let decision = Decision::Commit(commit.clone());
    transition_inner(conn, context, action, decision.reason(), |payment| {
        payment.apply_decision(&decision)
    })
    .await
}

async fn insert_verified_commit(
    conn: &mut SqliteConnection,
    key: &PaymentKey,
    record: &ConsumptionRecord,
    evidence: &DclDecisionEvidence,
    payer_signature: &[u8; 65],
) -> Result<(), StoreError> {
    let body = evidence.body();
    let authorization = body.authorization();
    let payment_context = body.payment_context();
    let inserted = sqlx::query(
        "INSERT INTO decision_consumptions (
            evidence_id, decision_digest, network, payer, nonce,
            authorization_digest, verdict, state, legacy_incomplete, payer_signature,
            action_id, action_digest, reason, oracle_signature,
            body_network, body_payer, body_pay_to, body_asset, body_nonce,
            chain_id, verifying_contract, auth_payer, auth_recipient,
            auth_value, auth_valid_after, auth_valid_before, auth_nonce,
            raw_tx_hash
         ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, 'verified', 0, ?,
            ?, ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?, ?, ?,
            ?, ?, ?, ?,
            NULL
         )",
    )
    .bind(record.evidence_id().as_bytes().as_slice())
    .bind(record.decision_digest().as_slice())
    .bind(key.network())
    .bind(key.payer())
    .bind(key.nonce())
    .bind(record.authorization_digest().as_slice())
    .bind(verdict_label(record.verdict()))
    .bind(payer_signature.as_slice())
    .bind(body.action_id().as_str())
    .bind(body.action_digest().as_bytes().as_slice())
    .bind(body.reason().as_str())
    .bind(evidence.signature().as_slice())
    .bind(payment_context.network())
    .bind(payment_context.payer())
    .bind(payment_context.pay_to())
    .bind(payment_context.asset())
    .bind(payment_context.nonce())
    .bind(i64::try_from(authorization.chain_id()).map_err(|_| StoreError::Corrupt)?)
    .bind(authorization.verifying_contract().as_slice())
    .bind(authorization.payer().as_slice())
    .bind(authorization.recipient().as_slice())
    .bind(authorization.value().as_slice())
    .bind(authorization.valid_after().as_slice())
    .bind(authorization.valid_before().as_slice())
    .bind(authorization.nonce().as_slice())
    .execute(&mut *conn)
    .await;
    match inserted {
        Ok(_) => Ok(()),
        Err(err) if is_unique_violation(&err) => Err(StoreError::Conflict),
        Err(err) => Err(err.into()),
    }
}

async fn claim_signing_inner(
    conn: &mut SqliteConnection,
    context: &PaymentContext,
) -> Result<SigningClaim, StoreError> {
    let key = payment_key_of(context).map_err(|_| StoreError::Conflict)?;
    let updated = sqlx::query(
        "UPDATE decision_consumptions
         SET signing_claim = randomblob(16),
             signing_claim_until = CAST(strftime('%s','now') AS INTEGER) + ?
         WHERE network = ? AND payer = ? AND nonce = ?
           AND state = 'verified'
           AND verdict = 'commit'
           AND legacy_incomplete = 0
           AND raw_tx_hash IS NULL
           AND length(payer_signature) = 65
           AND (
                signing_claim IS NULL
                OR signing_claim_until IS NULL
                OR signing_claim_until < CAST(strftime('%s','now') AS INTEGER)
           )",
    )
    .bind(SIGNING_CLAIM_SECS)
    .bind(key.network())
    .bind(key.payer())
    .bind(key.nonce())
    .execute(&mut *conn)
    .await?
    .rows_affected();
    if updated != 1 {
        return Err(StoreError::Conflict);
    }
    let row = sqlx::query(
        "SELECT signing_claim FROM decision_consumptions
         WHERE network = ? AND payer = ? AND nonce = ?",
    )
    .bind(key.network())
    .bind(key.payer())
    .bind(key.nonce())
    .fetch_one(&mut *conn)
    .await?;
    let token: Vec<u8> = row.try_get("signing_claim")?;
    let token: [u8; 16] = token.try_into().map_err(|_| StoreError::Corrupt)?;
    Ok(SigningClaim { token })
}

async fn release_signing_claim_inner(
    conn: &mut SqliteConnection,
    claim: &SigningClaim,
) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE decision_consumptions
         SET signing_claim = NULL, signing_claim_until = NULL
         WHERE signing_claim = ? AND state = 'verified'",
    )
    .bind(claim.token.as_slice())
    .execute(&mut *conn)
    .await?;
    Ok(())
}

async fn promote_verified_commit(
    conn: &mut SqliteConnection,
    key: &PaymentKey,
    write: &SignedCommit<'_>,
    raw_tx_hash: &[u8; 32],
) -> Result<(), StoreError> {
    if evidence_matches(write.evidence, write.record, write.context, write.action).is_err() {
        return Err(StoreError::Conflict);
    }
    let updated = sqlx::query(
        "UPDATE decision_consumptions
         SET state = 'consumed', raw_tx_hash = ?,
             signing_claim = NULL, signing_claim_until = NULL
         WHERE network = ? AND payer = ? AND nonce = ?
           AND state = 'verified'
           AND verdict = 'commit'
           AND legacy_incomplete = 0
           AND raw_tx_hash IS NULL
           AND evidence_id = ?
           AND decision_digest = ?
           AND authorization_digest = ?
           AND payer_signature = ?
           AND oracle_signature = ?
           AND signing_claim = ?",
    )
    .bind(raw_tx_hash.as_slice())
    .bind(key.network())
    .bind(key.payer())
    .bind(key.nonce())
    .bind(write.record.evidence_id().as_bytes().as_slice())
    .bind(write.record.decision_digest().as_slice())
    .bind(write.record.authorization_digest().as_slice())
    .bind(write.signed.signature.as_slice())
    .bind(write.evidence.signature().as_slice())
    .bind(write.claim.token.as_slice())
    .execute(&mut *conn)
    .await?
    .rows_affected();
    if updated != 1 {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

async fn commit_signed_inner(
    conn: &mut SqliteConnection,
    write: SignedCommit<'_>,
) -> Result<Payment, StoreError> {
    let SignedCommit {
        context,
        action,
        commit,
        signed,
        record,
        evidence: _,
        claim: _,
    } = write;
    if record.verdict() != Verdict::Commit || !commit.binds(context, action) {
        return Err(StoreError::Conflict);
    }
    let key = payment_key_of(context).map_err(|_| StoreError::Conflict)?;
    if record.payment_key() != &key {
        return Err(StoreError::Conflict);
    }
    let digest = authorization_digest_for(
        context,
        signed.value,
        signed.valid_after,
        signed.valid_before,
    )
    .map_err(|_| StoreError::Conflict)?;
    if record.authorization_digest() != digest {
        return Err(StoreError::Conflict);
    }
    let raw_tx_hash = transaction_hash(&signed.raw_tx);
    if raw_tx_hash != signed.tx_hash {
        return Err(StoreError::Conflict);
    }
    promote_verified_commit(conn, &key, &write, &raw_tx_hash).await?;
    let row = sqlx::query("SELECT * FROM payments WHERE network = ? AND payer = ? AND nonce = ?")
        .bind(context.network())
        .bind(context.payer())
        .bind(context.nonce())
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(StoreError::NotFound)?;
    let mut payment = payment_from_row(&row)?;
    if payment.context() != context || payment.action() != action {
        return Err(StoreError::Conflict);
    }
    let id: i64 = row.try_get("id")?;
    let from = payment.state();
    payment.begin_settlement(commit)?;
    persist_transition(conn, id, &payment, from, "signed settlement").await?;
    let nonce = i64::try_from(signed.relayer_nonce).map_err(|_| StoreError::Corrupt)?;
    let inserted = sqlx::query(
        "INSERT INTO settlement_evidence (
            payment_id, authorization_value, valid_after, valid_before, signature, calldata,
            relayer_address, relayer_nonce, tx_hash, raw_tx
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(signed.value.as_slice())
    .bind(signed.valid_after.as_slice())
    .bind(signed.valid_before.as_slice())
    .bind(signed.signature.as_slice())
    .bind(signed.calldata.as_slice())
    .bind(&signed.relayer_address)
    .bind(nonce)
    .bind(signed.tx_hash.as_slice())
    .bind(signed.raw_tx.as_slice())
    .execute(&mut *conn)
    .await;
    match inserted {
        Ok(_) => Ok(payment),
        Err(err) if is_unique_violation(&err) => Err(StoreError::Conflict),
        Err(err) => Err(err.into()),
    }
}

async fn refuse_inner(
    conn: &mut SqliteConnection,
    context: &PaymentContext,
    action: &ActionDigest,
    decision: &Decision,
    record: &ConsumptionRecord,
    evidence: &DclDecisionEvidence,
) -> Result<Payment, StoreError> {
    if record.verdict() != Verdict::NoCommit || !decision.binds(context, action) {
        return Err(StoreError::Conflict);
    }
    if !matches!(decision, Decision::NoCommit(_)) {
        return Err(StoreError::Conflict);
    }
    let key = payment_key_of(context).map_err(|_| StoreError::Conflict)?;
    if record.payment_key() != &key {
        return Err(StoreError::Conflict);
    }
    let existing = load_by_key(conn, context.network(), context.payer(), context.nonce()).await?;
    if let Some(payment) = &existing {
        if payment.context() != context || payment.action() != action {
            return Err(StoreError::Conflict);
        }
        if !matches!(
            payment.state(),
            PaymentState::Received
                | PaymentState::Verified
                | PaymentState::Committed
                | PaymentState::Rejected
        ) {
            return Err(StoreError::Conflict);
        }
        if settlement_recorded(conn, context).await? {
            return Err(StoreError::Conflict);
        }
    }
    if let Some(stored) = load_decision_meta(conn, &key).await? {
        if stored.legacy_incomplete != 0 || stored.verdict != Verdict::NoCommit {
            return Err(StoreError::Conflict);
        }
    }
    consume_decision(conn, record, evidence, None, context, action).await?;
    let existing = load_by_key(conn, context.network(), context.payer(), context.nonce()).await?;
    let (id, mut payment) = match existing {
        Some(payment) => {
            if payment.context() != context || payment.action() != action {
                return Err(StoreError::Conflict);
            }
            let row = sqlx::query(
                "SELECT id FROM payments WHERE network = ? AND payer = ? AND nonce = ?",
            )
            .bind(context.network())
            .bind(context.payer())
            .bind(context.nonce())
            .fetch_one(&mut *conn)
            .await?;
            (row.try_get("id")?, payment)
        }
        None => match record_received_inner(conn, context.clone(), *action).await? {
            PutOutcome::Created(payment) | PutOutcome::Existing(payment) => {
                let row = sqlx::query(
                    "SELECT id FROM payments WHERE network = ? AND payer = ? AND nonce = ?",
                )
                .bind(context.network())
                .bind(context.payer())
                .bind(context.nonce())
                .fetch_one(&mut *conn)
                .await?;
                (row.try_get("id")?, payment)
            }
        },
    };
    if payment.state() == PaymentState::Received {
        let from = payment.state();
        payment.mark_verified()?;
        persist_transition(conn, id, &payment, from, "verified").await?;
    }
    if payment.state() == PaymentState::Verified {
        let from = payment.state();
        payment.apply_decision(decision)?;
        persist_transition(conn, id, &payment, from, decision.reason()).await?;
    }
    if payment.state() == PaymentState::Committed {
        let from = payment.state();
        payment.reject_unsettled()?;
        persist_transition(conn, id, &payment, from, decision.reason()).await?;
    }
    Ok(payment)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConsumeEffect {
    Fresh,
    Replay,
}

async fn consume_decision(
    conn: &mut SqliteConnection,
    record: &ConsumptionRecord,
    evidence: &DclDecisionEvidence,
    raw_tx_hash: Option<&[u8; 32]>,
    context: &PaymentContext,
    action: &ActionDigest,
) -> Result<ConsumeEffect, StoreError> {
    if evidence_matches(evidence, record, context, action).is_err() {
        return Err(StoreError::Conflict);
    }
    match (record.verdict(), raw_tx_hash) {
        (Verdict::Commit, Some(_)) | (Verdict::NoCommit, None) => {}
        _ => return Err(StoreError::Conflict),
    }
    if let Some(stored) = load_consumption(conn, record.evidence_id()).await? {
        if same_consumption(&stored, record) {
            return Ok(ConsumeEffect::Replay);
        }
        return Err(StoreError::Conflict);
    }
    let key = record.payment_key();
    let payment = sqlx::query(
        "SELECT evidence_id FROM decision_consumptions WHERE network = ? AND payer = ? AND nonce = ?",
    )
    .bind(key.network())
    .bind(key.payer())
    .bind(key.nonce())
    .fetch_optional(&mut *conn)
    .await?;
    if payment.is_some() {
        return Err(StoreError::Conflict);
    }
    let body = evidence.body();
    let authorization = body.authorization();
    let payment_context = body.payment_context();
    let inserted = sqlx::query(
        "INSERT INTO decision_consumptions (
            evidence_id, decision_digest, network, payer, nonce,
            authorization_digest, verdict, state,
            action_id, action_digest, reason, oracle_signature,
            body_network, body_payer, body_pay_to, body_asset, body_nonce,
            chain_id, verifying_contract, auth_payer, auth_recipient,
            auth_value, auth_valid_after, auth_valid_before, auth_nonce,
            raw_tx_hash
         ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, 'consumed',
            ?, ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?, ?, ?,
            ?, ?, ?, ?,
            ?
         )",
    )
    .bind(record.evidence_id().as_bytes().as_slice())
    .bind(record.decision_digest().as_slice())
    .bind(key.network())
    .bind(key.payer())
    .bind(key.nonce())
    .bind(record.authorization_digest().as_slice())
    .bind(verdict_label(record.verdict()))
    .bind(body.action_id().as_str())
    .bind(body.action_digest().as_bytes().as_slice())
    .bind(body.reason().as_str())
    .bind(evidence.signature().as_slice())
    .bind(payment_context.network())
    .bind(payment_context.payer())
    .bind(payment_context.pay_to())
    .bind(payment_context.asset())
    .bind(payment_context.nonce())
    .bind(i64::try_from(authorization.chain_id()).map_err(|_| StoreError::Corrupt)?)
    .bind(authorization.verifying_contract().as_slice())
    .bind(authorization.payer().as_slice())
    .bind(authorization.recipient().as_slice())
    .bind(authorization.value().as_slice())
    .bind(authorization.valid_after().as_slice())
    .bind(authorization.valid_before().as_slice())
    .bind(authorization.nonce().as_slice())
    .bind(raw_tx_hash.map(|hash| hash.as_slice()))
    .execute(&mut *conn)
    .await;
    match inserted {
        Ok(_) => Ok(ConsumeEffect::Fresh),
        Err(err) if is_unique_violation(&err) => {
            if let Some(stored) = load_consumption(conn, record.evidence_id()).await? {
                if same_consumption(&stored, record) {
                    return Ok(ConsumeEffect::Replay);
                }
                return Err(StoreError::Conflict);
            }
            if sqlx::query(
                "SELECT evidence_id FROM decision_consumptions WHERE network = ? AND payer = ? AND nonce = ?",
            )
            .bind(key.network())
            .bind(key.payer())
            .bind(key.nonce())
            .fetch_optional(&mut *conn)
            .await?
            .is_some()
            {
                return Err(StoreError::Conflict);
            }
            Err(err.into())
        }
        Err(err) => Err(err.into()),
    }
}

async fn load_consumption(
    conn: &mut SqliteConnection,
    evidence_id: EvidenceId,
) -> Result<Option<ConsumptionRecord>, StoreError> {
    let row = sqlx::query(
        "SELECT evidence_id, decision_digest, network, payer, nonce,
                authorization_digest, verdict, state
         FROM decision_consumptions WHERE evidence_id = ?",
    )
    .bind(evidence_id.as_bytes().as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let state: String = row.try_get("state")?;
    if state != "consumed" {
        return Err(StoreError::Corrupt);
    }
    let verdict = parse_verdict(&row.try_get::<String, _>("verdict")?)?;
    Ok(Some(ConsumptionRecord::from_parts(
        EvidenceId::new(fixed_array(row.try_get("evidence_id")?)?),
        fixed_array(row.try_get("authorization_digest")?)?,
        PaymentKey::new(
            row.try_get::<String, _>("network")?,
            row.try_get::<String, _>("payer")?,
            row.try_get::<String, _>("nonce")?,
        ),
        verdict,
        fixed_array(row.try_get("decision_digest")?)?,
    )))
}

fn verdict_label(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Commit => "commit",
        Verdict::NoCommit => "no_commit",
    }
}

fn parse_verdict(label: &str) -> Result<Verdict, StoreError> {
    match label {
        "commit" => Ok(Verdict::Commit),
        "no_commit" => Ok(Verdict::NoCommit),
        _ => Err(StoreError::Corrupt),
    }
}

fn evidence_matches(
    evidence: &DclDecisionEvidence,
    record: &ConsumptionRecord,
    context: &PaymentContext,
    action: &ActionDigest,
) -> Result<(), StoreError> {
    let body = evidence.body();
    if body.verdict() != record.verdict() || body.evidence_id() != record.evidence_id() {
        return Err(StoreError::Conflict);
    }
    if body.action_digest() != action {
        return Err(StoreError::Conflict);
    }
    let digest = evidence
        .decision_digest()
        .map_err(|_| StoreError::Conflict)?;
    if digest != record.decision_digest() {
        return Err(StoreError::Conflict);
    }
    if body.authorization().digest() != record.authorization_digest() {
        return Err(StoreError::Conflict);
    }
    let body_key = payment_key_of(body.payment_context()).map_err(|_| StoreError::Conflict)?;
    let payment_key = payment_key_of(context).map_err(|_| StoreError::Conflict)?;
    if body_key != payment_key || record.payment_key() != &payment_key {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

fn classify_stored_commit(row: &SqliteRow) -> Result<StoredCommit, StoreError> {
    let legacy: i64 = row.try_get("legacy_incomplete")?;
    if legacy != 0 {
        return Ok(StoredCommit::Incomplete);
    }
    let verdict = parse_verdict(&row.try_get::<String, _>("verdict")?)?;
    if verdict == Verdict::NoCommit {
        return Ok(StoredCommit::NoCommit);
    }
    let state: String = row.try_get("state")?;
    if state != "consumed" && state != "verified" {
        return Err(StoreError::Corrupt);
    }
    let Some(evidence) = rebuild_evidence(row, verdict)? else {
        return Ok(StoredCommit::Incomplete);
    };
    let decision_digest = fixed_array(row.try_get("decision_digest")?)?;
    let raw_tx_hash = match row.try_get::<Option<Vec<u8>>, _>("raw_tx_hash")? {
        Some(bytes) => Some(fixed_array(bytes)?),
        None => None,
    };
    let payer_signature = match row.try_get::<Option<Vec<u8>>, _>("payer_signature")? {
        Some(bytes) if bytes.len() == 65 => {
            let mut signature = [0u8; 65];
            signature.copy_from_slice(&bytes);
            Some(signature)
        }
        _ => None,
    };
    let decision = StoredDecision {
        evidence,
        decision_digest,
        raw_tx_hash,
        state: state.clone(),
        payer_signature,
    };
    match (
        state.as_str(),
        decision.raw_tx_hash,
        decision.payer_signature,
    ) {
        ("verified", None, Some(_)) => Ok(StoredCommit::Verified(decision)),
        ("consumed", Some(_), Some(_)) => Ok(StoredCommit::Consumed(decision)),
        _ => Ok(StoredCommit::Incomplete),
    }
}

fn rebuild_evidence(
    row: &SqliteRow,
    verdict: Verdict,
) -> Result<Option<DclDecisionEvidence>, StoreError> {
    let action_id: Option<String> = row.try_get("action_id")?;
    let action_digest: Option<Vec<u8>> = row.try_get("action_digest")?;
    let reason: Option<String> = row.try_get("reason")?;
    let signature: Option<Vec<u8>> = row.try_get("oracle_signature")?;
    let body_network: Option<String> = row.try_get("body_network")?;
    let body_payer: Option<String> = row.try_get("body_payer")?;
    let body_pay_to: Option<String> = row.try_get("body_pay_to")?;
    let body_asset: Option<String> = row.try_get("body_asset")?;
    let body_nonce: Option<String> = row.try_get("body_nonce")?;
    let chain_id: Option<i64> = row.try_get("chain_id")?;
    let verifying_contract: Option<Vec<u8>> = row.try_get("verifying_contract")?;
    let auth_payer: Option<Vec<u8>> = row.try_get("auth_payer")?;
    let auth_recipient: Option<Vec<u8>> = row.try_get("auth_recipient")?;
    let auth_value: Option<Vec<u8>> = row.try_get("auth_value")?;
    let auth_valid_after: Option<Vec<u8>> = row.try_get("auth_valid_after")?;
    let auth_valid_before: Option<Vec<u8>> = row.try_get("auth_valid_before")?;
    let auth_nonce: Option<Vec<u8>> = row.try_get("auth_nonce")?;
    let (
        Some(action_id),
        Some(action_digest),
        Some(reason),
        Some(signature),
        Some(body_network),
        Some(body_payer),
        Some(body_pay_to),
        Some(body_asset),
        Some(body_nonce),
        Some(chain_id),
        Some(verifying_contract),
        Some(auth_payer),
        Some(auth_recipient),
        Some(auth_value),
        Some(auth_valid_after),
        Some(auth_valid_before),
        Some(auth_nonce),
    ) = (
        action_id,
        action_digest,
        reason,
        signature,
        body_network,
        body_payer,
        body_pay_to,
        body_asset,
        body_nonce,
        chain_id,
        verifying_contract,
        auth_payer,
        auth_recipient,
        auth_value,
        auth_valid_after,
        auth_valid_before,
        auth_nonce,
    )
    else {
        return Ok(None);
    };
    let context = match PaymentContext::try_new(
        body_network,
        body_payer,
        body_pay_to,
        body_asset,
        body_nonce,
    ) {
        Ok(context) => context,
        Err(_) => return Ok(None),
    };
    let chain_id = u64::try_from(chain_id).map_err(|_| StoreError::Corrupt)?;
    let body = DecisionBody::new(
        ActionId::try_new(action_id).map_err(|_| StoreError::Corrupt)?,
        ActionDigest::from_slice(&action_digest).ok_or(StoreError::Corrupt)?,
        context,
        AuthorizationIdentity::new(
            chain_id,
            fixed_array(verifying_contract)?,
            fixed_array(auth_payer)?,
            fixed_array(auth_recipient)?,
            fixed_array(auth_value)?,
            fixed_array(auth_valid_after)?,
            fixed_array(auth_valid_before)?,
            fixed_array(auth_nonce)?,
        ),
        verdict,
        DecisionReason::try_new(reason).map_err(|_| StoreError::Corrupt)?,
        EvidenceId::new(fixed_array(row.try_get("evidence_id")?)?),
    )
    .map_err(|_| StoreError::Corrupt)?;
    let evidence =
        DclDecisionEvidence::certify(body, &signature).map_err(|_| StoreError::Corrupt)?;
    Ok(Some(evidence))
}

const DECISION_COLUMNS: &[&str] = &[
    "evidence_id",
    "decision_digest",
    "network",
    "payer",
    "nonce",
    "authorization_digest",
    "verdict",
    "state",
    "action_id",
    "action_digest",
    "reason",
    "oracle_signature",
    "body_network",
    "body_payer",
    "body_pay_to",
    "body_asset",
    "body_nonce",
    "chain_id",
    "verifying_contract",
    "auth_payer",
    "auth_recipient",
    "auth_value",
    "auth_valid_after",
    "auth_valid_before",
    "auth_nonce",
    "raw_tx_hash",
];

const EVIDENCE_PRESENT: &str = "
    action_id IS NOT NULL
    AND action_digest IS NOT NULL AND length(action_digest) = 32
    AND reason IS NOT NULL
    AND oracle_signature IS NOT NULL AND length(oracle_signature) = 65
    AND body_network IS NOT NULL
    AND body_payer IS NOT NULL
    AND body_pay_to IS NOT NULL
    AND body_asset IS NOT NULL
    AND body_nonce IS NOT NULL
    AND chain_id IS NOT NULL
    AND verifying_contract IS NOT NULL AND length(verifying_contract) = 20
    AND auth_payer IS NOT NULL AND length(auth_payer) = 20
    AND auth_recipient IS NOT NULL AND length(auth_recipient) = 20
    AND auth_value IS NOT NULL AND length(auth_value) = 32
    AND auth_valid_after IS NOT NULL AND length(auth_valid_after) = 32
    AND auth_valid_before IS NOT NULL AND length(auth_valid_before) = 32
    AND auth_nonce IS NOT NULL AND length(auth_nonce) = 32
    AND length(evidence_id) = 32
    AND length(decision_digest) = 32
    AND length(authorization_digest) = 32
";

const NEW_DECISION_TABLE: &str = "
CREATE TABLE decision_consumptions_new (
    evidence_id BLOB PRIMARY KEY CHECK (length(evidence_id) = 32),
    decision_digest BLOB NOT NULL CHECK (length(decision_digest) = 32),
    network TEXT NOT NULL,
    payer TEXT NOT NULL,
    nonce TEXT NOT NULL,
    authorization_digest BLOB NOT NULL CHECK (length(authorization_digest) = 32),
    verdict TEXT NOT NULL CHECK (verdict IN ('commit', 'no_commit')),
    state TEXT NOT NULL CHECK (state IN ('verified', 'consumed')),
    legacy_incomplete INTEGER NOT NULL DEFAULT 0 CHECK (legacy_incomplete IN (0, 1)),
    payer_signature BLOB,
    action_id TEXT,
    action_digest BLOB,
    reason TEXT,
    oracle_signature BLOB,
    body_network TEXT,
    body_payer TEXT,
    body_pay_to TEXT,
    body_asset TEXT,
    body_nonce TEXT,
    chain_id INTEGER,
    verifying_contract BLOB,
    auth_payer BLOB,
    auth_recipient BLOB,
    auth_value BLOB,
    auth_valid_after BLOB,
    auth_valid_before BLOB,
    auth_nonce BLOB,
    raw_tx_hash BLOB,
    UNIQUE (network, payer, nonce)
)";

/// Apply schema and, when the decision table is still the pre-`legacy_incomplete`
/// shape, rebuild it. The caller holds `BEGIN IMMEDIATE`.
///
/// `stop_before_repair` returns after the table swap and before payment repair.
/// The caller rolls that transaction back. Production passes `false`.
async fn migrate_inner(
    conn: &mut SqliteConnection,
    stop_before_repair: bool,
) -> Result<bool, StoreError> {
    apply_schema(conn).await?;
    let definition = sqlx::query(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'decision_consumptions'",
    )
    .fetch_optional(&mut *conn)
    .await?;
    let Some(definition) = definition else {
        return Err(StoreError::Corrupt);
    };
    let sql: Option<String> = definition.try_get("sql")?;
    if sql.is_some_and(|sql| sql.contains("legacy_incomplete")) {
        return Ok(false);
    }

    ensure_decision_columns(conn).await?;
    let names = sqlx::query("SELECT name FROM pragma_table_info('decision_consumptions')")
        .fetch_all(&mut *conn)
        .await?;
    for name in &names {
        let name: String = name.try_get("name")?;
        if !DECISION_COLUMNS.contains(&name.as_str()) {
            return Err(StoreError::Corrupt);
        }
    }

    sqlx::query(NEW_DECISION_TABLE).execute(&mut *conn).await?;
    sqlx::query(
        "INSERT INTO decision_consumptions_new (
            evidence_id, decision_digest, network, payer, nonce, authorization_digest,
            verdict, state, legacy_incomplete, payer_signature,
            action_id, action_digest, reason, oracle_signature,
            body_network, body_payer, body_pay_to, body_asset, body_nonce,
            chain_id, verifying_contract, auth_payer, auth_recipient,
            auth_value, auth_valid_after, auth_valid_before, auth_nonce,
            raw_tx_hash
        )
        SELECT
            evidence_id, decision_digest, network, payer, nonce, authorization_digest,
            verdict, state, 1, NULL,
            action_id, action_digest, reason, oracle_signature,
            body_network, body_payer, body_pay_to, body_asset, body_nonce,
            chain_id, verifying_contract, auth_payer, auth_recipient,
            auth_value, auth_valid_after, auth_valid_before, auth_nonce,
            raw_tx_hash
        FROM decision_consumptions",
    )
    .execute(&mut *conn)
    .await?;

    let mark_refusal = format!(
        "UPDATE decision_consumptions_new
         SET legacy_incomplete = 0
         WHERE verdict = 'no_commit'
           AND state = 'consumed'
           AND raw_tx_hash IS NULL
           AND {EVIDENCE_PRESENT}"
    );
    sqlx::query(&mark_refusal).execute(&mut *conn).await?;

    let mark_commit = format!(
        "UPDATE decision_consumptions_new
         SET legacy_incomplete = 0,
             payer_signature = (
                 SELECT e.signature
                 FROM payments AS p
                 JOIN settlement_evidence AS e
                   ON e.payment_id = p.id
                  AND e.tx_hash = decision_consumptions_new.raw_tx_hash
                 WHERE p.network = decision_consumptions_new.network
                   AND lower(p.payer) = decision_consumptions_new.payer
                   AND lower(p.nonce) = decision_consumptions_new.nonce
             )
         WHERE verdict = 'commit'
           AND state = 'consumed'
           AND raw_tx_hash IS NOT NULL
           AND length(raw_tx_hash) = 32
           AND {EVIDENCE_PRESENT}
           AND (
               SELECT COUNT(*)
               FROM payments AS p
               JOIN settlement_evidence AS e
                 ON e.payment_id = p.id
                AND e.tx_hash = decision_consumptions_new.raw_tx_hash
               WHERE p.network = decision_consumptions_new.network
                 AND lower(p.payer) = decision_consumptions_new.payer
                 AND lower(p.nonce) = decision_consumptions_new.nonce
           ) = 1
           AND length((
               SELECT e.signature
               FROM payments AS p
               JOIN settlement_evidence AS e
                 ON e.payment_id = p.id
                AND e.tx_hash = decision_consumptions_new.raw_tx_hash
               WHERE p.network = decision_consumptions_new.network
                 AND lower(p.payer) = decision_consumptions_new.payer
                 AND lower(p.nonce) = decision_consumptions_new.nonce
           )) = 65"
    );
    sqlx::query(&mark_commit).execute(&mut *conn).await?;

    let before = count_rows(conn, "decision_consumptions").await?;
    let after = count_rows(conn, "decision_consumptions_new").await?;
    if before != after {
        return Err(StoreError::Corrupt);
    }

    sqlx::query("DROP TABLE decision_consumptions")
        .execute(&mut *conn)
        .await?;
    sqlx::query("ALTER TABLE decision_consumptions_new RENAME TO decision_consumptions")
        .execute(&mut *conn)
        .await?;
    if stop_before_repair {
        return Ok(true);
    }

    sqlx::query("CREATE TABLE decision_migration_repair_ids (id INTEGER PRIMARY KEY)")
        .execute(&mut *conn)
        .await?;
    sqlx::query(
        "INSERT INTO decision_migration_repair_ids (id)
         SELECT p.id
         FROM payments AS p
         WHERE p.state = 'committed'
           AND NOT EXISTS (
               SELECT 1 FROM settlement_evidence AS e WHERE e.payment_id = p.id
           )
           AND EXISTS (
               SELECT 1 FROM decision_consumptions AS d
               WHERE d.network = p.network
                 AND d.payer = lower(p.payer)
                 AND d.nonce = lower(p.nonce)
                 AND d.verdict = 'no_commit'
                 AND d.state = 'consumed'
                 AND d.legacy_incomplete = 0
           )",
    )
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "UPDATE payments
         SET state = 'rejected'
         WHERE id IN (SELECT id FROM decision_migration_repair_ids)",
    )
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "INSERT INTO events (payment_id, from_state, to_state, note)
         SELECT id, 'committed', 'rejected', 'no_commit'
         FROM decision_migration_repair_ids",
    )
    .execute(&mut *conn)
    .await?;
    sqlx::query("DROP TABLE decision_migration_repair_ids")
        .execute(&mut *conn)
        .await?;
    Ok(false)
}

async fn apply_schema(conn: &mut SqliteConnection) -> Result<(), StoreError> {
    for statement in SCHEMA.split(';') {
        let statement = statement.trim();
        if statement.is_empty() {
            continue;
        }
        sqlx::query(statement).execute(&mut *conn).await?;
    }
    Ok(())
}

async fn count_rows(conn: &mut SqliteConnection, table: &str) -> Result<i64, StoreError> {
    let sql = format!("SELECT COUNT(*) AS n FROM {table}");
    let row = sqlx::query(&sql).fetch_one(&mut *conn).await?;
    Ok(row.try_get("n")?)
}

async fn ensure_signing_claim_columns(conn: &mut SqliteConnection) -> Result<(), StoreError> {
    const COLUMNS: &[(&str, &str)] = &[
        (
            "signing_claim",
            "ALTER TABLE decision_consumptions ADD COLUMN signing_claim BLOB",
        ),
        (
            "signing_claim_until",
            "ALTER TABLE decision_consumptions ADD COLUMN signing_claim_until INTEGER",
        ),
    ];
    for (name, statement) in COLUMNS {
        let row = sqlx::query(
            "SELECT 1 AS present FROM pragma_table_info('decision_consumptions') WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(&mut *conn)
        .await?;
        if row.is_none() {
            sqlx::query(statement).execute(&mut *conn).await?;
        }
    }
    Ok(())
}

async fn ensure_decision_columns(conn: &mut SqliteConnection) -> Result<(), StoreError> {
    const COLUMNS: &[(&str, &str)] = &[
        (
            "action_id",
            "ALTER TABLE decision_consumptions ADD COLUMN action_id TEXT",
        ),
        (
            "action_digest",
            "ALTER TABLE decision_consumptions ADD COLUMN action_digest BLOB",
        ),
        (
            "reason",
            "ALTER TABLE decision_consumptions ADD COLUMN reason TEXT",
        ),
        (
            "oracle_signature",
            "ALTER TABLE decision_consumptions ADD COLUMN oracle_signature BLOB",
        ),
        (
            "body_network",
            "ALTER TABLE decision_consumptions ADD COLUMN body_network TEXT",
        ),
        (
            "body_payer",
            "ALTER TABLE decision_consumptions ADD COLUMN body_payer TEXT",
        ),
        (
            "body_pay_to",
            "ALTER TABLE decision_consumptions ADD COLUMN body_pay_to TEXT",
        ),
        (
            "body_asset",
            "ALTER TABLE decision_consumptions ADD COLUMN body_asset TEXT",
        ),
        (
            "body_nonce",
            "ALTER TABLE decision_consumptions ADD COLUMN body_nonce TEXT",
        ),
        (
            "chain_id",
            "ALTER TABLE decision_consumptions ADD COLUMN chain_id INTEGER",
        ),
        (
            "verifying_contract",
            "ALTER TABLE decision_consumptions ADD COLUMN verifying_contract BLOB",
        ),
        (
            "auth_payer",
            "ALTER TABLE decision_consumptions ADD COLUMN auth_payer BLOB",
        ),
        (
            "auth_recipient",
            "ALTER TABLE decision_consumptions ADD COLUMN auth_recipient BLOB",
        ),
        (
            "auth_value",
            "ALTER TABLE decision_consumptions ADD COLUMN auth_value BLOB",
        ),
        (
            "auth_valid_after",
            "ALTER TABLE decision_consumptions ADD COLUMN auth_valid_after BLOB",
        ),
        (
            "auth_valid_before",
            "ALTER TABLE decision_consumptions ADD COLUMN auth_valid_before BLOB",
        ),
        (
            "auth_nonce",
            "ALTER TABLE decision_consumptions ADD COLUMN auth_nonce BLOB",
        ),
        (
            "raw_tx_hash",
            "ALTER TABLE decision_consumptions ADD COLUMN raw_tx_hash BLOB",
        ),
    ];
    for (name, statement) in COLUMNS {
        let row = sqlx::query(
            "SELECT 1 AS present FROM pragma_table_info('decision_consumptions') WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(&mut *conn)
        .await?;
        if row.is_none() {
            sqlx::query(statement).execute(&mut *conn).await?;
        }
    }
    Ok(())
}

async fn conclude_inner(
    conn: &mut SqliteConnection,
    context: &PaymentContext,
    action: &ActionDigest,
    observation: &ReceiptObservation,
    outcome: PaymentState,
) -> Result<Payment, StoreError> {
    if !matches!(outcome, PaymentState::Settled | PaymentState::SettleFailed) {
        return Err(TransitionError::Illegal(outcome).into());
    }
    let row = sqlx::query("SELECT * FROM payments WHERE network = ? AND payer = ? AND nonce = ?")
        .bind(context.network())
        .bind(context.payer())
        .bind(context.nonce())
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(StoreError::NotFound)?;
    let mut payment = payment_from_row(&row)?;
    if payment.context() != context || payment.action() != action {
        return Err(StoreError::Conflict);
    }
    let id: i64 = row.try_get("id")?;
    let status = i64::try_from(observation.status).map_err(|_| StoreError::Corrupt)?;
    let block_number = i64::try_from(observation.block_number).map_err(|_| StoreError::Corrupt)?;
    let log_index = observation
        .transfer_log_index
        .map(i64::try_from)
        .transpose()
        .map_err(|_| StoreError::Corrupt)?;
    let updated = sqlx::query(
        "UPDATE settlement_evidence
         SET receipt_status = ?, block_number = ?, block_hash = ?, transfer_log_index = ?
         WHERE payment_id = ?",
    )
    .bind(status)
    .bind(block_number)
    .bind(observation.block_hash.as_slice())
    .bind(log_index)
    .bind(id)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    if updated != 1 {
        return Err(StoreError::Corrupt);
    }
    match (payment.state(), outcome) {
        (PaymentState::Settling, PaymentState::Settled) => {
            let from = payment.state();
            payment.complete_settlement()?;
            persist_transition(conn, id, &payment, from, "receipt confirmed").await?;
        }
        (PaymentState::SettlementUnknown, PaymentState::Settled) => {
            let from = payment.state();
            payment.resolve_uncertain(PaymentState::Settled)?;
            persist_transition(conn, id, &payment, from, "receipt confirmed").await?;
        }
        (PaymentState::Settling, PaymentState::SettleFailed) => {
            let from = payment.state();
            payment.mark_uncertain()?;
            persist_transition(conn, id, &payment, from, "mined revert").await?;
            let from = payment.state();
            payment.resolve_uncertain(PaymentState::SettleFailed)?;
            persist_transition(conn, id, &payment, from, "mined revert").await?;
        }
        (PaymentState::SettlementUnknown, PaymentState::SettleFailed) => {
            let from = payment.state();
            payment.resolve_uncertain(PaymentState::SettleFailed)?;
            persist_transition(conn, id, &payment, from, "mined revert").await?;
        }
        (PaymentState::Settled, PaymentState::Settled)
        | (PaymentState::SettleFailed, PaymentState::SettleFailed) => {}
        (state, _) => return Err(TransitionError::Illegal(state).into()),
    }
    Ok(payment)
}

async fn expire_unmined_inner(
    conn: &mut SqliteConnection,
    context: &PaymentContext,
    action: &ActionDigest,
) -> Result<Payment, StoreError> {
    let row = sqlx::query("SELECT * FROM payments WHERE network = ? AND payer = ? AND nonce = ?")
        .bind(context.network())
        .bind(context.payer())
        .bind(context.nonce())
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(StoreError::NotFound)?;
    let mut payment = payment_from_row(&row)?;
    if payment.context() != context || payment.action() != action {
        return Err(StoreError::Conflict);
    }
    let id: i64 = row.try_get("id")?;
    if payment.state() == PaymentState::SettleFailed {
        return Ok(payment);
    }
    if payment.state() == PaymentState::Settling {
        let from = payment.state();
        payment.mark_uncertain()?;
        persist_transition(conn, id, &payment, from, "unmined authorization expired").await?;
    }
    if payment.state() != PaymentState::SettlementUnknown {
        return Err(TransitionError::Illegal(payment.state()).into());
    }
    let from = payment.state();
    payment.resolve_uncertain(PaymentState::SettleFailed)?;
    persist_transition(conn, id, &payment, from, "unmined authorization expired").await?;
    Ok(payment)
}

fn stored_authorization_from_row(row: &SqliteRow) -> Result<StoredAuthorization, StoreError> {
    let signature: Vec<u8> = row.try_get("signature")?;
    Ok(StoredAuthorization {
        payer: row.try_get("payer")?,
        pay_to: row.try_get("pay_to")?,
        nonce: row.try_get("nonce")?,
        value: fixed_array(row.try_get("authorization_value")?)?,
        valid_after: fixed_array(row.try_get("valid_after")?)?,
        valid_before: fixed_array(row.try_get("valid_before")?)?,
        signature: fixed_array(signature)?,
    })
}

fn fixed_array<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], StoreError> {
    bytes.try_into().map_err(|_| StoreError::Corrupt)
}

fn evidence_from_row(row: &SqliteRow) -> Result<SettlementEvidence, StoreError> {
    let nonce: i64 = row.try_get("relayer_nonce")?;
    let hash: Vec<u8> = row.try_get("tx_hash")?;
    let hash: [u8; 32] = hash
        .as_slice()
        .try_into()
        .map_err(|_| StoreError::Corrupt)?;
    let status: Option<i64> = row.try_get("receipt_status")?;
    Ok(SettlementEvidence {
        relayer_address: row.try_get("relayer_address")?,
        relayer_nonce: u64::try_from(nonce).map_err(|_| StoreError::Corrupt)?,
        tx_hash: hash,
        raw_tx: row.try_get("raw_tx")?,
        calldata: row.try_get("calldata")?,
        receipt_status: status,
    })
}

fn payment_from_row(row: &SqliteRow) -> Result<Payment, StoreError> {
    let context = PaymentContext::try_new(
        row.try_get::<String, _>("network")?,
        row.try_get::<String, _>("payer")?,
        row.try_get::<String, _>("pay_to")?,
        row.try_get::<String, _>("asset")?,
        row.try_get::<String, _>("nonce")?,
    )
    .map_err(|_| StoreError::Corrupt)?;
    let digest: Vec<u8> = row.try_get("action_digest")?;
    let action = ActionDigest::from_slice(&digest).ok_or(StoreError::Corrupt)?;
    let state_raw: String = row.try_get("state")?;
    let state = PaymentState::parse(&state_raw).ok_or(StoreError::Corrupt)?;
    Ok(Payment::restore(state, context, action))
}

fn is_unique_violation(err: &sqlx::Error) -> bool {
    err.as_database_error()
        .map(|d| d.is_unique_violation())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leibniz::{LeibnizGate, PolicyGate};
    use sqlx::sqlite::{
        SqliteConnectOptions, SqliteConnection, SqliteJournalMode, SqlitePoolOptions,
    };
    use sqlx::{Row, SqlitePool};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn temp_path() -> std::path::PathBuf {
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("dcl-fac-m2-{}-{}.db", std::process::id(), n))
    }

    fn ctx(nonce: &str) -> PaymentContext {
        PaymentContext::try_new("base", "payer", "payto", "usdc", nonce).unwrap()
    }

    fn canonical_ctx() -> PaymentContext {
        PaymentContext::try_new(
            "eip155:8453",
            "0x1111111111111111111111111111111111111111",
            "0x2222222222222222222222222222222222222222",
            "0x3333333333333333333333333333333333333333",
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap()
    }

    fn digest(tag: u8) -> ActionDigest {
        let mut bytes = [0u8; 32];
        bytes[0] = tag;
        ActionDigest::new(bytes)
    }

    fn commit_for(context: &PaymentContext, action: &ActionDigest) -> Decision {
        LeibnizGate.decide(context, action)
    }

    async fn open() -> (Store, std::path::PathBuf) {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        (Store::open(&path).await.unwrap(), path)
    }

    fn addressed(tag: u8) -> PaymentContext {
        let mut nonce = [0u8; 32];
        nonce[31] = tag;
        let mut hex = String::from("0x");
        for byte in nonce {
            hex.push_str(&format!("{byte:02x}"));
        }
        PaymentContext::try_new(
            "eip155:8453",
            "0x1111111111111111111111111111111111111111",
            "0x2222222222222222222222222222222222222222",
            "0x3333333333333333333333333333333333333333",
            hex,
        )
        .unwrap()
    }

    fn verified_commit(
        context: &PaymentContext,
        action: &ActionDigest,
        evidence_byte: u8,
        verdict: crate::evidence::Verdict,
    ) -> (
        Decision,
        ConsumptionRecord,
        crate::evidence::DclDecisionEvidence,
        [u8; 65],
    ) {
        use crate::evidence::{
            action_id_from_digest, AuthorizationIdentity, DclDecisionEvidence, DecisionBody,
            DecisionReason, EvidenceId,
        };
        let hex = context.nonce().trim_start_matches("0x");
        let mut parsed = [0u8; 32];
        for (index, byte) in parsed.iter_mut().enumerate() {
            let high = u8::from_str_radix(&hex[index * 2..index * 2 + 1], 16).unwrap();
            let low = u8::from_str_radix(&hex[index * 2 + 1..index * 2 + 2], 16).unwrap();
            *byte = (high << 4) | low;
        }
        let authorization = AuthorizationIdentity::new(
            8453, [0x33; 20], [0x11; 20], [0x22; 20], [0; 32], [0; 32], [1; 32], parsed,
        );
        let body = DecisionBody::new(
            action_id_from_digest(action).unwrap(),
            *action,
            context.clone(),
            authorization,
            verdict,
            DecisionReason::try_new("allowed").unwrap(),
            EvidenceId::new([evidence_byte; 32]),
        )
        .unwrap();
        let decision_digest = body.decision_digest().unwrap();
        let mut signature = [0x11; 65];
        signature[64] = evidence_byte;
        let evidence = DclDecisionEvidence::certify(body, &signature).unwrap();
        let record = ConsumptionRecord::from_parts(
            EvidenceId::new([evidence_byte; 32]),
            authorization.digest(),
            payment_key_of(context).unwrap(),
            verdict,
            decision_digest,
        );
        let payer_signature = [0x42; 65];
        let decision = match verdict {
            crate::evidence::Verdict::Commit => {
                Decision::Commit(Commit::for_oracle(context, action, "allowed"))
            }
            crate::evidence::Verdict::NoCommit => Decision::NoCommit(
                crate::leibniz::NoCommit::for_oracle(context, action, "allowed"),
            ),
        };
        (decision, record, evidence, payer_signature)
    }

    async fn committed(store: &Store, context: &PaymentContext, action: &ActionDigest) -> Decision {
        store
            .record_received(context.clone(), *action)
            .await
            .unwrap();
        store.mark_verified(context, action).await.unwrap();
        let (decision, record, evidence, signature) =
            verified_commit(context, action, 0x4, crate::evidence::Verdict::Commit);
        let commit = decision.as_commit().unwrap();
        store
            .persist_verified_commit(context, action, commit, &record, &evidence, &signature)
            .await
            .unwrap();
        decision
    }

    fn oracle_evidence(
        context: &PaymentContext,
        action: &ActionDigest,
        signed: &SignedSettlement,
        authorization_digest: [u8; 32],
    ) -> (ConsumptionRecord, crate::evidence::DclDecisionEvidence) {
        use crate::evidence::{
            action_id_from_digest, AuthorizationIdentity, DclDecisionEvidence, DecisionBody,
            DecisionReason, EvidenceId, Verdict,
        };
        let authorization = AuthorizationIdentity::new(
            8453,
            [0x33; 20],
            [0x11; 20],
            [0x22; 20],
            signed.value,
            signed.valid_after,
            signed.valid_before,
            [0xaa; 32],
        );
        assert_eq!(authorization.digest(), authorization_digest);
        let body = DecisionBody::new(
            action_id_from_digest(action).unwrap(),
            *action,
            context.clone(),
            authorization,
            Verdict::Commit,
            DecisionReason::try_new("allowed").unwrap(),
            EvidenceId::new([4; 32]),
        )
        .unwrap();
        let decision_digest = body.decision_digest().unwrap();
        let evidence = DclDecisionEvidence::certify(body, &[0x11; 65]).unwrap();
        let record = ConsumptionRecord::from_parts(
            EvidenceId::new([4; 32]),
            authorization_digest,
            payment_key_of(context).unwrap(),
            Verdict::Commit,
            decision_digest,
        );
        (record, evidence)
    }

    #[tokio::test]
    async fn persists_across_reopen() {
        let (store, path) = open().await;
        let context = addressed(1);
        let action = digest(1);
        let decision = committed(&store, &context, &action).await;
        store.close().await;

        let store = Store::open(&path).await.unwrap();
        let loaded = store
            .get(context.network(), context.payer(), context.nonce())
            .await
            .unwrap();
        assert_eq!(loaded.state(), PaymentState::Committed);
        assert_eq!(loaded.context(), &context);
        assert_eq!(loaded.action(), &action);
        let commit = decision.as_commit().unwrap();
        store
            .begin_settlement(&context, &action, commit)
            .await
            .unwrap();
        store.close().await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn duplicate_idempotency_key() {
        let (store, path) = open().await;
        let context = ctx("dup");
        let action = digest(1);
        let first = store
            .record_received(context.clone(), action)
            .await
            .unwrap();
        assert!(matches!(first, PutOutcome::Created(_)));

        let replay = store
            .record_received(context.clone(), action)
            .await
            .unwrap();
        assert!(matches!(replay, PutOutcome::Existing(_)));

        let other = PaymentContext::try_new("base", "payer", "other", "usdc", "dup").unwrap();
        let err = store.record_received(other, action).await.unwrap_err();
        assert!(matches!(err, StoreError::Conflict));
        store.close().await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn concurrent_same_key_does_not_duplicate() {
        let (store, path) = open().await;
        let context = addressed(7);
        let action = digest(7);
        let a = store.clone();
        let b = store.clone();
        let ctx_a = context.clone();
        let ctx_b = context.clone();

        let (left, right) = tokio::join!(
            a.record_received(ctx_a, action),
            b.record_received(ctx_b, action)
        );
        left.unwrap();
        right.unwrap();

        let row = sqlx::query("SELECT COUNT(*) AS n FROM payments")
            .fetch_one(&store.inner.pool)
            .await
            .unwrap();
        let n: i64 = row.try_get("n").unwrap();
        assert_eq!(n, 1);

        store.mark_verified(&context, &action).await.unwrap();
        let (decision, record, evidence, signature) =
            verified_commit(&context, &action, 0x7, crate::evidence::Verdict::Commit);
        let commit = decision.as_commit().unwrap();
        store
            .persist_verified_commit(&context, &action, commit, &record, &evidence, &signature)
            .await
            .unwrap();
        let commit = commit.clone();
        let s1 = store.clone();
        let s2 = store.clone();
        let c1 = context.clone();
        let c2 = context.clone();
        let commit2 = commit.clone();

        let (settle_a, settle_b) = tokio::join!(
            s1.begin_settlement(&c1, &action, &commit),
            s2.begin_settlement(&c2, &action, &commit2)
        );
        let outcomes = [settle_a.is_ok(), settle_b.is_ok()];
        assert_eq!(outcomes.iter().filter(|ok| **ok).count(), 1);
        assert!(settle_a.is_err() || settle_b.is_err());
        let loaded = store
            .get(context.network(), context.payer(), context.nonce())
            .await
            .unwrap();
        assert_eq!(loaded.state(), PaymentState::Settling);
        store.close().await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn settlement_requires_bound_commit() {
        let (store, path) = open().await;
        let context = ctx("gate");
        let action = digest(1);
        store
            .record_received(context.clone(), action)
            .await
            .unwrap();
        store.mark_verified(&context, &action).await.unwrap();
        let commit = commit_for(&context, &action).as_commit().unwrap().clone();
        let err = store
            .begin_settlement(&context, &action, &commit)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            StoreError::Transition(TransitionError::CommitRequired)
        ));
        store.close().await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn commit_cannot_be_reused_after_completion() {
        let (store, path) = open().await;
        let context = addressed(2);
        let action = digest(1);
        let decision = committed(&store, &context, &action).await;
        let commit = decision.as_commit().unwrap();
        store
            .begin_settlement(&context, &action, commit)
            .await
            .unwrap();
        store.complete_settlement(&context, &action).await.unwrap();
        let err = store
            .begin_settlement(&context, &action, commit)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            StoreError::Transition(TransitionError::DuplicateSettlement)
        ));
        store.close().await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn interrupted_settlement_is_uncertain_and_not_retried() {
        let (store, path) = open().await;
        let context = addressed(3);
        let action = digest(3);
        let decision = committed(&store, &context, &action).await;
        let commit = decision.as_commit().unwrap().clone();
        store
            .begin_settlement(&context, &action, &commit)
            .await
            .unwrap();
        store.close().await;

        let store = Store::open(&path).await.unwrap();
        let loaded = store
            .get(context.network(), context.payer(), context.nonce())
            .await
            .unwrap();
        assert_eq!(loaded.state(), PaymentState::SettlementUnknown);
        let interrupted = store.interrupted().await.unwrap();
        assert_eq!(interrupted.len(), 1);

        let err = store
            .begin_settlement(&context, &action, &commit)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            StoreError::Transition(TransitionError::DuplicateSettlement)
        ));

        let states = store.event_to_states(&context).await.unwrap();
        let settling = states
            .iter()
            .filter(|s| **s == PaymentState::Settling)
            .count();
        assert_eq!(settling, 1, "recovery must not start another settlement");
        assert_eq!(
            states.last().copied(),
            Some(PaymentState::SettlementUnknown)
        );

        let resolved = store
            .resolve_uncertain(&context, &action, PaymentState::Settled)
            .await
            .unwrap();
        assert_eq!(resolved.state(), PaymentState::Settled);
        store.close().await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn conclude_is_idempotent_for_the_same_terminal_state() {
        let (store, path) = open().await;
        let context = canonical_ctx();
        let action = digest(4);
        store
            .record_received(context.clone(), action)
            .await
            .unwrap();
        store.mark_verified(&context, &action).await.unwrap();
        let signed = SignedSettlement {
            value: [0; 32],
            valid_after: [0; 32],
            valid_before: [1; 32],
            signature: [0x42; 65],
            calldata: vec![1, 2, 3],
            relayer_address: "0xrelayer".to_string(),
            relayer_nonce: 1,
            tx_hash: transaction_hash(&[4, 5, 6]),
            raw_tx: vec![4, 5, 6],
        };
        let digest = crate::evidence::authorization_digest_for(
            &context,
            signed.value,
            signed.valid_after,
            signed.valid_before,
        )
        .unwrap();
        let (record, evidence) = oracle_evidence(&context, &action, &signed, digest);
        let commit = Commit::for_oracle(&context, &action, "allowed");
        store
            .persist_verified_commit(
                &context,
                &action,
                &commit,
                &record,
                &evidence,
                &signed.signature,
            )
            .await
            .unwrap();
        let claim = store.claim_signing(&context).await.unwrap();
        store
            .commit_signed(SignedCommit {
                context: &context,
                action: &action,
                commit: &commit,
                signed: &signed,
                record: &record,
                evidence: &evidence,
                claim: &claim,
            })
            .await
            .unwrap();
        let observation = ReceiptObservation {
            status: 1,
            block_number: 3,
            block_hash: [7; 32],
            transfer_log_index: Some(0),
        };
        store
            .conclude(&context, &action, &observation, PaymentState::Settled)
            .await
            .unwrap();
        store
            .conclude(&context, &action, &observation, PaymentState::Settled)
            .await
            .unwrap();
        let loaded = store
            .get(context.network(), context.payer(), context.nonce())
            .await
            .unwrap();
        assert_eq!(loaded.state(), PaymentState::Settled);
        let settled = store
            .event_to_states(&context)
            .await
            .unwrap()
            .into_iter()
            .filter(|state| *state == PaymentState::Settled)
            .count();
        assert_eq!(settled, 1);
        let err = store
            .conclude(&context, &action, &observation, PaymentState::SettleFailed)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            StoreError::Transition(TransitionError::Illegal(PaymentState::Settled))
        ));
        assert_eq!(
            store
                .get(context.network(), context.payer(), context.nonce())
                .await
                .unwrap()
                .state(),
            PaymentState::Settled
        );
        store.close().await;
        let _ = std::fs::remove_file(&path);
    }

    const LEGACY_CORE: &str = "
CREATE TABLE payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    network TEXT NOT NULL,
    payer TEXT NOT NULL,
    pay_to TEXT NOT NULL,
    asset TEXT NOT NULL,
    nonce TEXT NOT NULL,
    action_digest BLOB NOT NULL CHECK (length(action_digest) = 32),
    state TEXT NOT NULL CHECK (state IN (
        'received', 'verified', 'committed', 'settling', 'settled',
        'rejected', 'settle_failed', 'settlement_unknown'
    )),
    UNIQUE (network, payer, nonce)
);
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    payment_id INTEGER NOT NULL REFERENCES payments(id),
    from_state TEXT,
    to_state TEXT NOT NULL,
    note TEXT,
    at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX events_payment_id ON events (payment_id);
CREATE TABLE decision_consumptions (
    evidence_id BLOB PRIMARY KEY CHECK (length(evidence_id) = 32),
    decision_digest BLOB NOT NULL CHECK (length(decision_digest) = 32),
    network TEXT NOT NULL,
    payer TEXT NOT NULL,
    nonce TEXT NOT NULL,
    authorization_digest BLOB NOT NULL CHECK (length(authorization_digest) = 32),
    verdict TEXT NOT NULL CHECK (verdict IN ('commit', 'no_commit')),
    state TEXT NOT NULL CHECK (state = 'consumed'),
    action_id TEXT,
    action_digest BLOB CHECK (action_digest IS NULL OR length(action_digest) = 32),
    reason TEXT,
    oracle_signature BLOB CHECK (oracle_signature IS NULL OR length(oracle_signature) = 65),
    body_network TEXT,
    body_payer TEXT,
    body_pay_to TEXT,
    body_asset TEXT,
    body_nonce TEXT,
    chain_id INTEGER,
    verifying_contract BLOB CHECK (verifying_contract IS NULL OR length(verifying_contract) = 20),
    auth_payer BLOB CHECK (auth_payer IS NULL OR length(auth_payer) = 20),
    auth_recipient BLOB CHECK (auth_recipient IS NULL OR length(auth_recipient) = 20),
    auth_value BLOB CHECK (auth_value IS NULL OR length(auth_value) = 32),
    auth_valid_after BLOB CHECK (auth_valid_after IS NULL OR length(auth_valid_after) = 32),
    auth_valid_before BLOB CHECK (auth_valid_before IS NULL OR length(auth_valid_before) = 32),
    auth_nonce BLOB CHECK (auth_nonce IS NULL OR length(auth_nonce) = 32),
    raw_tx_hash BLOB CHECK (raw_tx_hash IS NULL OR length(raw_tx_hash) = 32),
    UNIQUE (network, payer, nonce)
);
";

    const LEGACY_SETTLEMENT: &str = "
CREATE TABLE settlement_evidence (
    payment_id INTEGER PRIMARY KEY REFERENCES payments(id),
    authorization_value BLOB NOT NULL CHECK (length(authorization_value) = 32),
    valid_after BLOB NOT NULL CHECK (length(valid_after) = 32),
    valid_before BLOB NOT NULL CHECK (length(valid_before) = 32),
    signature BLOB NOT NULL CHECK (length(signature) = 65),
    calldata BLOB NOT NULL,
    relayer_address TEXT NOT NULL,
    relayer_nonce INTEGER NOT NULL,
    tx_hash BLOB NOT NULL CHECK (length(tx_hash) = 32),
    raw_tx BLOB NOT NULL,
    receipt_status INTEGER,
    block_number INTEGER,
    block_hash BLOB,
    transfer_log_index INTEGER,
    UNIQUE (relayer_address, relayer_nonce),
    UNIQUE (tx_hash)
);
";

    const LOOSE_SETTLEMENT: &str = "
CREATE TABLE settlement_evidence (
    payment_id INTEGER PRIMARY KEY REFERENCES payments(id),
    authorization_value BLOB NOT NULL,
    valid_after BLOB NOT NULL,
    valid_before BLOB NOT NULL,
    signature BLOB NOT NULL,
    calldata BLOB NOT NULL,
    relayer_address TEXT NOT NULL,
    relayer_nonce INTEGER NOT NULL,
    tx_hash BLOB NOT NULL,
    raw_tx BLOB NOT NULL
);
";

    fn remove_db(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let text = path.to_string_lossy();
        let _ = std::fs::remove_file(format!("{text}-wal"));
        let _ = std::fs::remove_file(format!("{text}-shm"));
    }

    async fn raw_pool(path: &std::path::Path) -> SqlitePool {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_secs(5))
            .foreign_keys(true);
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .unwrap()
    }

    async fn exec_script(conn: &mut SqliteConnection, script: &str) {
        for statement in script.split(';') {
            let statement = statement.trim();
            if statement.is_empty() {
                continue;
            }
            sqlx::query(statement).execute(&mut *conn).await.unwrap();
        }
    }

    async fn legacy_pool(script: &str) -> (std::path::PathBuf, SqlitePool) {
        let path = temp_path();
        remove_db(&path);
        let pool = raw_pool(&path).await;
        let mut conn = pool.acquire().await.unwrap();
        exec_script(&mut conn, script).await;
        drop(conn);
        (path, pool)
    }

    fn fill(byte: u8, len: usize) -> Vec<u8> {
        vec![byte; len]
    }

    fn nonce_upper() -> String {
        format!("0x{}", "AB".repeat(32))
    }

    fn nonce_lower() -> String {
        format!("0x{}", "ab".repeat(32))
    }

    async fn insert_payment(
        conn: &mut SqliteConnection,
        payer: &str,
        nonce: &str,
        state: &str,
    ) -> i64 {
        let done = sqlx::query(
            "INSERT INTO payments
                (network, payer, pay_to, asset, nonce, action_digest, state)
             VALUES ('eip155:8453', ?, '0x2222222222222222222222222222222222222222',
                     '0x3333333333333333333333333333333333333333', ?, ?, ?)",
        )
        .bind(payer)
        .bind(nonce)
        .bind(fill(9, 32).as_slice())
        .bind(state)
        .execute(&mut *conn)
        .await
        .unwrap();
        done.last_insert_rowid()
    }

    async fn insert_event(conn: &mut SqliteConnection, payment_id: i64) {
        sqlx::query(
            "INSERT INTO events (payment_id, from_state, to_state, note)
             VALUES (?, 'verified', 'committed', 'allowed')",
        )
        .bind(payment_id)
        .execute(&mut *conn)
        .await
        .unwrap();
    }

    async fn insert_decision(
        conn: &mut SqliteConnection,
        evidence: u8,
        payer: &str,
        nonce: &str,
        verdict: &str,
        complete: bool,
        raw_tx_hash: Option<&[u8]>,
    ) {
        let oracle = complete.then(|| fill(0x51, 65));
        let action_digest = complete.then(|| fill(0x41, 32));
        let contract = complete.then(|| fill(0x61, 20));
        let auth_payer = complete.then(|| fill(0x71, 20));
        let auth_recipient = complete.then(|| fill(0x81, 20));
        let auth_value = complete.then(|| fill(0x91, 32));
        let auth_after = complete.then(|| fill(0xA1, 32));
        let auth_before = complete.then(|| fill(0xB1, 32));
        let auth_nonce = complete.then(|| fill(0xC1, 32));
        let action_id: Option<&str> = complete.then_some("settle");
        let reason: Option<&str> = complete.then_some("recorded");
        let network: Option<&str> = complete.then_some("eip155:8453");
        sqlx::query(
            "INSERT INTO decision_consumptions (
                evidence_id, decision_digest, network, payer, nonce, authorization_digest,
                verdict, state, action_id, action_digest, reason, oracle_signature,
                body_network, body_payer, body_pay_to, body_asset, body_nonce,
                chain_id, verifying_contract, auth_payer, auth_recipient,
                auth_value, auth_valid_after, auth_valid_before, auth_nonce, raw_tx_hash
            ) VALUES (
                ?, ?, 'eip155:8453', ?, ?, ?, ?, 'consumed',
                ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?, ?
            )",
        )
        .bind(fill(evidence, 32).as_slice())
        .bind(fill(0x22, 32).as_slice())
        .bind(payer)
        .bind(nonce)
        .bind(fill(0x33, 32).as_slice())
        .bind(verdict)
        .bind(action_id)
        .bind(action_digest.as_deref())
        .bind(reason)
        .bind(oracle.as_deref())
        .bind(network)
        .bind(complete.then_some(payer))
        .bind(complete.then_some("0x2222222222222222222222222222222222222222"))
        .bind(complete.then_some("0x3333333333333333333333333333333333333333"))
        .bind(complete.then_some(nonce))
        .bind(complete.then_some(8453_i64))
        .bind(contract.as_deref())
        .bind(auth_payer.as_deref())
        .bind(auth_recipient.as_deref())
        .bind(auth_value.as_deref())
        .bind(auth_after.as_deref())
        .bind(auth_before.as_deref())
        .bind(auth_nonce.as_deref())
        .bind(raw_tx_hash)
        .execute(&mut *conn)
        .await
        .unwrap();
    }

    async fn insert_settlement(
        conn: &mut SqliteConnection,
        payment_id: i64,
        signature: &[u8],
        tx_hash: &[u8],
        relayer_nonce: i64,
    ) {
        sqlx::query(
            "INSERT INTO settlement_evidence (
                payment_id, authorization_value, valid_after, valid_before, signature, calldata,
                relayer_address, relayer_nonce, tx_hash, raw_tx
            ) VALUES (?, ?, ?, ?, ?, ?, '0xrelayer', ?, ?, ?)",
        )
        .bind(payment_id)
        .bind(fill(0x01, 32).as_slice())
        .bind(fill(0x02, 32).as_slice())
        .bind(fill(0x03, 32).as_slice())
        .bind(signature)
        .bind(fill(0xAB, 8).as_slice())
        .bind(relayer_nonce)
        .bind(tx_hash)
        .bind(fill(0xCD, 8).as_slice())
        .execute(&mut *conn)
        .await
        .unwrap();
    }

    async fn event_rows(pool: &SqlitePool) -> Vec<(Option<String>, String, String)> {
        let rows = sqlx::query("SELECT from_state, to_state, note FROM events ORDER BY id")
            .fetch_all(pool)
            .await
            .unwrap();
        rows.iter()
            .map(|row| (row.get("from_state"), row.get("to_state"), row.get("note")))
            .collect()
    }

    #[tokio::test]
    async fn committed_no_commit_without_evidence_repairs_to_rejected() {
        let (path, pool) = legacy_pool(&format!("{LEGACY_CORE}{LEGACY_SETTLEMENT}")).await;
        let mut conn = pool.acquire().await.unwrap();
        let payment = insert_payment(
            &mut conn,
            "0x00000000000000000000000000000000000000Aa",
            &nonce_upper(),
            "committed",
        )
        .await;
        insert_event(&mut conn, payment).await;
        insert_decision(
            &mut conn,
            0x10,
            "0x00000000000000000000000000000000000000aa",
            &nonce_lower(),
            "no_commit",
            true,
            None,
        )
        .await;
        drop(conn);
        pool.close().await;

        let store = Store::open(&path).await.unwrap();
        let state: String = sqlx::query("SELECT state FROM payments WHERE id = ?")
            .bind(payment)
            .fetch_one(&store.inner.pool)
            .await
            .unwrap()
            .get("state");
        assert_eq!(state, "rejected");
        let flags =
            sqlx::query("SELECT legacy_incomplete, payer_signature FROM decision_consumptions")
                .fetch_one(&store.inner.pool)
                .await
                .unwrap();
        let incomplete: i64 = flags.get("legacy_incomplete");
        let signature: Option<Vec<u8>> = flags.get("payer_signature");
        assert_eq!(incomplete, 0);
        assert!(signature.is_none());
        assert_eq!(
            event_rows(&store.inner.pool).await,
            vec![
                (
                    Some("verified".to_string()),
                    "committed".to_string(),
                    "allowed".to_string()
                ),
                (
                    Some("committed".to_string()),
                    "rejected".to_string(),
                    "no_commit".to_string()
                ),
            ]
        );
        store.close().await;

        let store = Store::open(&path).await.unwrap();
        assert_eq!(event_rows(&store.inner.pool).await.len(), 2);
        let state: String = sqlx::query("SELECT state FROM payments WHERE id = ?")
            .bind(payment)
            .fetch_one(&store.inner.pool)
            .await
            .unwrap()
            .get("state");
        assert_eq!(state, "rejected");
        store.close().await;
        remove_db(&path);
    }

    #[tokio::test]
    async fn ambiguous_settlement_signature_stays_incomplete() {
        let (path, pool) = legacy_pool(&format!("{LEGACY_CORE}{LOOSE_SETTLEMENT}")).await;
        let mut conn = pool.acquire().await.unwrap();
        let hash = fill(0x33, 32);
        let left = insert_payment(
            &mut conn,
            "0x00000000000000000000000000000000000000Aa",
            &nonce_upper(),
            "committed",
        )
        .await;
        let right = insert_payment(
            &mut conn,
            "0x00000000000000000000000000000000000000aA",
            &nonce_upper(),
            "verified",
        )
        .await;
        insert_event(&mut conn, left).await;
        insert_settlement(&mut conn, left, &fill(0x11, 65), &hash, 1).await;
        insert_settlement(&mut conn, right, &fill(0x22, 65), &hash, 2).await;
        insert_decision(
            &mut conn,
            0x20,
            "0x00000000000000000000000000000000000000aa",
            &nonce_lower(),
            "commit",
            true,
            Some(&hash),
        )
        .await;
        drop(conn);
        pool.close().await;

        let store = Store::open(&path).await.unwrap();
        let row = sqlx::query(
            "SELECT legacy_incomplete, payer_signature, oracle_signature, raw_tx_hash
             FROM decision_consumptions",
        )
        .fetch_one(&store.inner.pool)
        .await
        .unwrap();
        let incomplete: i64 = row.get("legacy_incomplete");
        let signature: Option<Vec<u8>> = row.get("payer_signature");
        let oracle: Vec<u8> = row.get("oracle_signature");
        let stored_hash: Vec<u8> = row.get("raw_tx_hash");
        assert_eq!(incomplete, 1);
        assert!(signature.is_none());
        assert_eq!(oracle, fill(0x51, 65));
        assert_eq!(stored_hash, hash);
        let states: Vec<String> = sqlx::query("SELECT state FROM payments ORDER BY id")
            .fetch_all(&store.inner.pool)
            .await
            .unwrap()
            .iter()
            .map(|row| row.get("state"))
            .collect();
        assert_eq!(
            states,
            vec!["committed".to_string(), "verified".to_string()]
        );
        assert_eq!(event_rows(&store.inner.pool).await.len(), 1);
        let decisions: i64 = sqlx::query("SELECT COUNT(*) AS n FROM decision_consumptions")
            .fetch_one(&store.inner.pool)
            .await
            .unwrap()
            .get("n");
        assert_eq!(decisions, 1);
        store.close().await;
        remove_db(&path);
    }

    #[tokio::test]
    async fn rebuild_rolls_back_before_repair() {
        let (path, pool) = legacy_pool(&format!("{LEGACY_CORE}{LEGACY_SETTLEMENT}")).await;
        let mut conn = pool.acquire().await.unwrap();
        let payment = insert_payment(
            &mut conn,
            "0x00000000000000000000000000000000000000Aa",
            &nonce_upper(),
            "committed",
        )
        .await;
        insert_event(&mut conn, payment).await;
        insert_decision(
            &mut conn,
            0x30,
            "0x00000000000000000000000000000000000000aa",
            &nonce_lower(),
            "no_commit",
            true,
            None,
        )
        .await;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *conn)
            .await
            .unwrap();
        let paused = super::migrate_inner(&mut conn, true).await.unwrap();
        assert!(paused);
        sqlx::query("ROLLBACK").execute(&mut *conn).await.unwrap();

        let column: i64 = sqlx::query(
            "SELECT COUNT(*) AS n FROM pragma_table_info('decision_consumptions')
             WHERE name = 'legacy_incomplete'",
        )
        .fetch_one(&mut *conn)
        .await
        .unwrap()
        .get("n");
        assert_eq!(column, 0);
        let swapped: i64 = sqlx::query(
            "SELECT COUNT(*) AS n FROM sqlite_master
             WHERE name IN ('decision_consumptions_new', 'decision_migration_repair_ids')",
        )
        .fetch_one(&mut *conn)
        .await
        .unwrap()
        .get("n");
        assert_eq!(swapped, 0);
        let state: String = sqlx::query("SELECT state FROM payments WHERE id = ?")
            .bind(payment)
            .fetch_one(&mut *conn)
            .await
            .unwrap()
            .get("state");
        assert_eq!(state, "committed");
        let events: i64 = sqlx::query("SELECT COUNT(*) AS n FROM events")
            .fetch_one(&mut *conn)
            .await
            .unwrap()
            .get("n");
        assert_eq!(events, 1);
        let decisions: i64 = sqlx::query("SELECT COUNT(*) AS n FROM decision_consumptions")
            .fetch_one(&mut *conn)
            .await
            .unwrap()
            .get("n");
        assert_eq!(decisions, 1);
        drop(conn);
        pool.close().await;
        remove_db(&path);
    }

    #[tokio::test]
    async fn concurrent_open_migrates_once() {
        let (path, pool) = legacy_pool(&format!("{LEGACY_CORE}{LEGACY_SETTLEMENT}")).await;
        let mut conn = pool.acquire().await.unwrap();
        let payment = insert_payment(
            &mut conn,
            "0x00000000000000000000000000000000000000Aa",
            &nonce_upper(),
            "committed",
        )
        .await;
        insert_event(&mut conn, payment).await;
        insert_decision(
            &mut conn,
            0x40,
            "0x00000000000000000000000000000000000000aa",
            &nonce_lower(),
            "no_commit",
            true,
            None,
        )
        .await;
        drop(conn);
        pool.close().await;

        let (left, right) = tokio::join!(Store::open(&path), Store::open(&path));
        let left = left.unwrap();
        let right = right.unwrap();
        let events = event_rows(&left.inner.pool).await;
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].0.as_deref(), Some("committed"));
        assert_eq!(events[1].1, "rejected");
        assert_eq!(events[1].2, "no_commit");
        let decisions: i64 = sqlx::query("SELECT COUNT(*) AS n FROM decision_consumptions")
            .fetch_one(&left.inner.pool)
            .await
            .unwrap()
            .get("n");
        assert_eq!(decisions, 1);
        let state: String = sqlx::query("SELECT state FROM payments WHERE id = ?")
            .bind(payment)
            .fetch_one(&left.inner.pool)
            .await
            .unwrap()
            .get("state");
        assert_eq!(state, "rejected");
        left.close().await;
        right.close().await;
        remove_db(&path);
    }

    #[tokio::test]
    async fn rebuild_preserves_events_and_incomplete_decisions() {
        let (path, pool) = legacy_pool(&format!("{LEGACY_CORE}{LEGACY_SETTLEMENT}")).await;
        let mut conn = pool.acquire().await.unwrap();
        let incomplete_payment = insert_payment(
            &mut conn,
            "0x00000000000000000000000000000000000000Aa",
            &nonce_upper(),
            "committed",
        )
        .await;
        insert_event(&mut conn, incomplete_payment).await;
        insert_decision(
            &mut conn,
            0x50,
            "0x00000000000000000000000000000000000000aa",
            &nonce_lower(),
            "no_commit",
            false,
            None,
        )
        .await;
        let copied = fill(0x44, 65);
        let hash = fill(0x55, 32);
        let settled = insert_payment(
            &mut conn,
            "0x00000000000000000000000000000000000000Bb",
            &format!("0x{}", "CD".repeat(32)),
            "committed",
        )
        .await;
        insert_event(&mut conn, settled).await;
        insert_settlement(&mut conn, settled, &copied, &hash, 7).await;
        insert_decision(
            &mut conn,
            0x60,
            "0x00000000000000000000000000000000000000bb",
            &format!("0x{}", "cd".repeat(32)),
            "commit",
            true,
            Some(&hash),
        )
        .await;
        drop(conn);
        pool.close().await;

        let store = Store::open(&path).await.unwrap();
        let rows = sqlx::query(
            "SELECT evidence_id, legacy_incomplete, payer_signature, oracle_signature
             FROM decision_consumptions
             ORDER BY evidence_id",
        )
        .fetch_all(&store.inner.pool)
        .await
        .unwrap();
        assert_eq!(rows.len(), 2);
        let incomplete_flag: i64 = rows[0].get("legacy_incomplete");
        let incomplete_signature: Option<Vec<u8>> = rows[0].get("payer_signature");
        let incomplete_oracle: Option<Vec<u8>> = rows[0].get("oracle_signature");
        assert_eq!(rows[0].get::<Vec<u8>, _>("evidence_id"), fill(0x50, 32));
        assert_eq!(incomplete_flag, 1);
        assert!(incomplete_signature.is_none());
        assert!(incomplete_oracle.is_none());
        let copied_flag: i64 = rows[1].get("legacy_incomplete");
        let copied_signature: Option<Vec<u8>> = rows[1].get("payer_signature");
        assert_eq!(rows[1].get::<Vec<u8>, _>("evidence_id"), fill(0x60, 32));
        assert_eq!(copied_flag, 0);
        assert_eq!(copied_signature.as_deref(), Some(copied.as_slice()));
        let state: String = sqlx::query("SELECT state FROM payments WHERE id = ?")
            .bind(incomplete_payment)
            .fetch_one(&store.inner.pool)
            .await
            .unwrap()
            .get("state");
        assert_eq!(state, "committed");
        let events = event_rows(&store.inner.pool).await;
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|event| event.1 == "committed"));
        store.close().await;
        remove_db(&path);
    }

    #[tokio::test]
    async fn signing_claim_is_exclusive_until_release_or_expiry() {
        let (store, path) = open().await;
        let context = addressed(21);
        let action = digest(8);
        store
            .record_received(context.clone(), action)
            .await
            .unwrap();
        store.mark_verified(&context, &action).await.unwrap();
        let (decision, record, evidence, signature) =
            verified_commit(&context, &action, 0x21, crate::evidence::Verdict::Commit);
        let commit = decision.as_commit().unwrap();
        store
            .persist_verified_commit(&context, &action, commit, &record, &evidence, &signature)
            .await
            .unwrap();
        let other = Store::open(&path).await.unwrap();
        let (left, right) =
            tokio::join!(store.claim_signing(&context), other.claim_signing(&context),);
        let claim = match (left, right) {
            (Ok(claim), Err(StoreError::Conflict)) | (Err(StoreError::Conflict), Ok(claim)) => {
                claim
            }
            (Ok(_), Ok(_)) => panic!("two processes claimed the same commit"),
            _ => panic!("claim failed for an unclaimed commit"),
        };
        assert!(matches!(
            store.claim_signing(&context).await.unwrap_err(),
            StoreError::Conflict
        ));
        store.release_signing_claim(&claim).await.unwrap();
        let released = other.claim_signing(&context).await.unwrap();
        assert_ne!(released.token, claim.token);

        sqlx::query("UPDATE decision_consumptions SET signing_claim_until = 0")
            .execute(&store.inner.pool)
            .await
            .unwrap();
        let renewed = store.claim_signing(&context).await.unwrap();
        assert_ne!(renewed.token, released.token);
        let signed = SignedSettlement {
            value: [0; 32],
            valid_after: [0; 32],
            valid_before: [1; 32],
            signature,
            calldata: vec![1],
            relayer_address: "0xrelayer".to_string(),
            relayer_nonce: 4,
            tx_hash: transaction_hash(&[1, 2, 3]),
            raw_tx: vec![1, 2, 3],
        };
        let err = store
            .commit_signed(SignedCommit {
                context: &context,
                action: &action,
                commit,
                signed: &signed,
                record: &record,
                evidence: &evidence,
                claim: &released,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::Conflict));
        store
            .commit_signed(SignedCommit {
                context: &context,
                action: &action,
                commit,
                signed: &signed,
                record: &record,
                evidence: &evidence,
                claim: &renewed,
            })
            .await
            .unwrap();
        assert!(matches!(
            store.stored_commit(&context).await.unwrap(),
            StoredCommit::Consumed(_)
        ));
        other.close().await;
        store.close().await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn commit_then_no_commit_keeps_the_stored_commit() {
        let (store, path) = open().await;
        let context = addressed(11);
        let action = digest(1);
        store
            .record_received(context.clone(), action)
            .await
            .unwrap();
        store.mark_verified(&context, &action).await.unwrap();
        let (decision, record, evidence, signature) =
            verified_commit(&context, &action, 0x11, crate::evidence::Verdict::Commit);
        let commit = decision.as_commit().unwrap();
        store
            .persist_verified_commit(&context, &action, commit, &record, &evidence, &signature)
            .await
            .unwrap();
        let again = store
            .persist_verified_commit(&context, &action, commit, &record, &evidence, &signature)
            .await
            .unwrap();
        assert_eq!(again.state(), PaymentState::Committed);

        let (refusal, refusal_record, refusal_evidence, _) =
            verified_commit(&context, &action, 0x12, crate::evidence::Verdict::NoCommit);
        let err = store
            .refuse(
                &context,
                &action,
                &refusal,
                &refusal_record,
                &refusal_evidence,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::Conflict));
        assert_eq!(
            store
                .get(context.network(), context.payer(), context.nonce())
                .await
                .unwrap()
                .state(),
            PaymentState::Committed
        );
        let row = sqlx::query(
            "SELECT verdict, state, legacy_incomplete, payer_signature
             FROM decision_consumptions",
        )
        .fetch_one(&store.inner.pool)
        .await
        .unwrap();
        assert_eq!(row.get::<String, _>("verdict"), "commit");
        assert_eq!(row.get::<String, _>("state"), "verified");
        assert_eq!(row.get::<i64, _>("legacy_incomplete"), 0);
        assert_eq!(row.get::<Vec<u8>, _>("payer_signature"), signature.to_vec());
        let count: i64 = sqlx::query("SELECT COUNT(*) AS n FROM decision_consumptions")
            .fetch_one(&store.inner.pool)
            .await
            .unwrap()
            .get("n");
        assert_eq!(count, 1);

        let other = addressed(12);
        let action_b = digest(2);
        store
            .record_received(other.clone(), action_b)
            .await
            .unwrap();
        store.mark_verified(&other, &action_b).await.unwrap();
        let (first, first_record, first_evidence, first_signature) =
            verified_commit(&other, &action_b, 0x21, crate::evidence::Verdict::Commit);
        let (second, second_record, second_evidence, second_signature) =
            verified_commit(&other, &action_b, 0x22, crate::evidence::Verdict::Commit);
        let left = store.clone();
        let right = store.clone();
        let (left_result, right_result) = tokio::join!(
            left.persist_verified_commit(
                &other,
                &action_b,
                first.as_commit().unwrap(),
                &first_record,
                &first_evidence,
                &first_signature
            ),
            right.persist_verified_commit(
                &other,
                &action_b,
                second.as_commit().unwrap(),
                &second_record,
                &second_evidence,
                &second_signature
            ),
        );
        assert_eq!(
            [left_result.is_ok(), right_result.is_ok()]
                .into_iter()
                .filter(|ok| *ok)
                .count(),
            1
        );
        let raced: i64 =
            sqlx::query("SELECT COUNT(*) AS n FROM decision_consumptions WHERE nonce = ?")
                .bind(payment_key_of(&other).unwrap().nonce())
                .fetch_one(&store.inner.pool)
                .await
                .unwrap()
                .get("n");
        assert_eq!(raced, 1);
        assert_eq!(
            store
                .get(other.network(), other.payer(), other.nonce())
                .await
                .unwrap()
                .state(),
            PaymentState::Committed
        );
        store.close().await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn no_commit_then_commit_stays_rejected() {
        let (store, path) = open().await;
        let context = addressed(13);
        let action = digest(3);
        store
            .record_received(context.clone(), action)
            .await
            .unwrap();
        store.mark_verified(&context, &action).await.unwrap();
        let (refusal, refusal_record, refusal_evidence, _) =
            verified_commit(&context, &action, 0x31, crate::evidence::Verdict::NoCommit);
        let rejected = store
            .refuse(
                &context,
                &action,
                &refusal,
                &refusal_record,
                &refusal_evidence,
            )
            .await
            .unwrap();
        assert_eq!(rejected.state(), PaymentState::Rejected);
        let (decision, record, evidence, signature) =
            verified_commit(&context, &action, 0x32, crate::evidence::Verdict::Commit);
        let err = store
            .persist_verified_commit(
                &context,
                &action,
                decision.as_commit().unwrap(),
                &record,
                &evidence,
                &signature,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::Conflict));
        assert_eq!(
            store
                .get(context.network(), context.payer(), context.nonce())
                .await
                .unwrap()
                .state(),
            PaymentState::Rejected
        );
        let verdict: String = sqlx::query("SELECT verdict FROM decision_consumptions")
            .fetch_one(&store.inner.pool)
            .await
            .unwrap()
            .get("verdict");
        assert_eq!(verdict, "no_commit");
        store.close().await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn committed_without_decision_is_not_signed() {
        let (store, path) = open().await;
        let context = addressed(14);
        let action = digest(4);
        store
            .record_received(context.clone(), action)
            .await
            .unwrap();
        store.mark_verified(&context, &action).await.unwrap();
        sqlx::query("UPDATE payments SET state = 'committed' WHERE nonce = ?")
            .bind(context.nonce())
            .execute(&store.inner.pool)
            .await
            .unwrap();
        let (decision, record, evidence, signature) =
            verified_commit(&context, &action, 0x41, crate::evidence::Verdict::Commit);
        let err = store
            .persist_verified_commit(
                &context,
                &action,
                decision.as_commit().unwrap(),
                &record,
                &evidence,
                &signature,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::Conflict));
        let signed = SignedSettlement {
            value: [0; 32],
            valid_after: [0; 32],
            valid_before: [1; 32],
            signature,
            calldata: vec![1],
            relayer_address: "0xrelayer".to_string(),
            relayer_nonce: 1,
            tx_hash: transaction_hash(&[9, 9, 9]),
            raw_tx: vec![9, 9, 9],
        };
        let err = store
            .commit_signed(SignedCommit {
                context: &context,
                action: &action,
                commit: decision.as_commit().unwrap(),
                signed: &signed,
                record: &record,
                evidence: &evidence,
                claim: &SigningClaim { token: [9; 16] },
            })
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::Conflict));
        assert_eq!(
            store
                .get(context.network(), context.payer(), context.nonce())
                .await
                .unwrap()
                .state(),
            PaymentState::Committed
        );
        let decisions: i64 = sqlx::query("SELECT COUNT(*) AS n FROM decision_consumptions")
            .fetch_one(&store.inner.pool)
            .await
            .unwrap()
            .get("n");
        assert_eq!(decisions, 0);
        let evidence_rows: i64 = sqlx::query("SELECT COUNT(*) AS n FROM settlement_evidence")
            .fetch_one(&store.inner.pool)
            .await
            .unwrap()
            .get("n");
        assert_eq!(evidence_rows, 0);
        store.close().await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn complete_no_commit_rejects_only_an_unsettled_commit() {
        let (store, path) = open().await;
        let context = addressed(15);
        let action = digest(5);
        store
            .record_received(context.clone(), action)
            .await
            .unwrap();
        store.mark_verified(&context, &action).await.unwrap();
        sqlx::query("UPDATE payments SET state = 'committed' WHERE nonce = ?")
            .bind(context.nonce())
            .execute(&store.inner.pool)
            .await
            .unwrap();
        let (refusal, record, evidence, _) =
            verified_commit(&context, &action, 0x51, crate::evidence::Verdict::NoCommit);
        let rejected = store
            .refuse(&context, &action, &refusal, &record, &evidence)
            .await
            .unwrap();
        assert_eq!(rejected.state(), PaymentState::Rejected);

        let settled = addressed(16);
        let action_b = digest(6);
        store
            .record_received(settled.clone(), action_b)
            .await
            .unwrap();
        store.mark_verified(&settled, &action_b).await.unwrap();
        let (decision, commit_record, commit_evidence, signature) =
            verified_commit(&settled, &action_b, 0x61, crate::evidence::Verdict::Commit);
        let commit = decision.as_commit().unwrap();
        store
            .persist_verified_commit(
                &settled,
                &action_b,
                commit,
                &commit_record,
                &commit_evidence,
                &signature,
            )
            .await
            .unwrap();
        let signed = SignedSettlement {
            value: [0; 32],
            valid_after: [0; 32],
            valid_before: [1; 32],
            signature,
            calldata: vec![1],
            relayer_address: "0xrelayer".to_string(),
            relayer_nonce: 2,
            tx_hash: transaction_hash(&[8, 8, 8]),
            raw_tx: vec![8, 8, 8],
        };
        let claim = store.claim_signing(&settled).await.unwrap();
        store
            .commit_signed(SignedCommit {
                context: &settled,
                action: &action_b,
                commit,
                signed: &signed,
                record: &commit_record,
                evidence: &commit_evidence,
                claim: &claim,
            })
            .await
            .unwrap();
        let (later, later_record, later_evidence, _) = verified_commit(
            &settled,
            &action_b,
            0x62,
            crate::evidence::Verdict::NoCommit,
        );
        let err = store
            .refuse(&settled, &action_b, &later, &later_record, &later_evidence)
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::Conflict));
        assert_eq!(
            store
                .get(settled.network(), settled.payer(), settled.nonce())
                .await
                .unwrap()
                .state(),
            PaymentState::Settling
        );

        let incomplete = addressed(17);
        let action_c = digest(7);
        store
            .record_received(incomplete.clone(), action_c)
            .await
            .unwrap();
        store.mark_verified(&incomplete, &action_c).await.unwrap();
        let key = payment_key_of(&incomplete).unwrap();
        sqlx::query(
            "INSERT INTO decision_consumptions (
                evidence_id, decision_digest, network, payer, nonce,
                authorization_digest, verdict, state, legacy_incomplete
             ) VALUES (?, ?, ?, ?, ?, ?, 'commit', 'consumed', 1)",
        )
        .bind([0x70u8; 32].as_slice())
        .bind([0x71u8; 32].as_slice())
        .bind(key.network())
        .bind(key.payer())
        .bind(key.nonce())
        .bind([0x72u8; 32].as_slice())
        .execute(&store.inner.pool)
        .await
        .unwrap();
        let before = sqlx::query(
            "SELECT verdict, state, legacy_incomplete, payer_signature FROM decision_consumptions WHERE nonce = ?",
        )
        .bind(key.nonce())
        .fetch_one(&store.inner.pool)
        .await
        .unwrap();
        let (other, other_record, other_evidence, other_signature) = verified_commit(
            &incomplete,
            &action_c,
            0x73,
            crate::evidence::Verdict::Commit,
        );
        let err = store
            .persist_verified_commit(
                &incomplete,
                &action_c,
                other.as_commit().unwrap(),
                &other_record,
                &other_evidence,
                &other_signature,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::Conflict));
        let (refusal, refusal_record, refusal_evidence, _) = verified_commit(
            &incomplete,
            &action_c,
            0x74,
            crate::evidence::Verdict::NoCommit,
        );
        let err = store
            .refuse(
                &incomplete,
                &action_c,
                &refusal,
                &refusal_record,
                &refusal_evidence,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::Conflict));
        let after = sqlx::query(
            "SELECT verdict, state, legacy_incomplete, payer_signature FROM decision_consumptions WHERE nonce = ?",
        )
        .bind(key.nonce())
        .fetch_one(&store.inner.pool)
        .await
        .unwrap();
        assert_eq!(
            after.get::<String, _>("verdict"),
            before.get::<String, _>("verdict")
        );
        assert_eq!(
            after.get::<String, _>("state"),
            before.get::<String, _>("state")
        );
        assert_eq!(
            after.get::<i64, _>("legacy_incomplete"),
            before.get::<i64, _>("legacy_incomplete")
        );
        assert!(after
            .try_get::<Option<Vec<u8>>, _>("payer_signature")
            .unwrap()
            .is_none());
        assert_eq!(
            store
                .get(incomplete.network(), incomplete.payer(), incomplete.nonce())
                .await
                .unwrap()
                .state(),
            PaymentState::Verified
        );
        store.close().await;
        let _ = std::fs::remove_file(&path);
    }
}
