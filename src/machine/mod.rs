//! Payment state machine.
//!
//! Settlement is reachable only from `Committed`, and `Committed` is reachable
//! only by applying an explicit [`Commit`] bound to this payment's context
//! and action digest.

use crate::leibniz::{ActionDigest, Commit, Decision, PaymentContext};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentState {
    Received,
    Verified,
    Committed,
    Settling,
    Settled,
    Rejected,
    SettleFailed,
    SettlementUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransitionError {
    #[error("decision is not bound to this payment and action")]
    UnboundDecision,
    #[error("explicit commit required before settlement")]
    CommitRequired,
    #[error("settlement already started or finished; will not submit another transaction")]
    DuplicateSettlement,
    #[error("illegal transition from {0:?}")]
    Illegal(PaymentState),
}

impl PaymentState {
    pub fn as_str(self) -> &'static str {
        match self {
            PaymentState::Received => "received",
            PaymentState::Verified => "verified",
            PaymentState::Committed => "committed",
            PaymentState::Settling => "settling",
            PaymentState::Settled => "settled",
            PaymentState::Rejected => "rejected",
            PaymentState::SettleFailed => "settle_failed",
            PaymentState::SettlementUnknown => "settlement_unknown",
        }
    }

    pub fn parse(label: &str) -> Option<Self> {
        match label {
            "received" => Some(PaymentState::Received),
            "verified" => Some(PaymentState::Verified),
            "committed" => Some(PaymentState::Committed),
            "settling" => Some(PaymentState::Settling),
            "settled" => Some(PaymentState::Settled),
            "rejected" => Some(PaymentState::Rejected),
            "settle_failed" => Some(PaymentState::SettleFailed),
            "settlement_unknown" => Some(PaymentState::SettlementUnknown),
            _ => None,
        }
    }
}

/// One payment after a successful verify, waiting on the Leibniz gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payment {
    state: PaymentState,
    context: PaymentContext,
    action: ActionDigest,
}

impl Payment {
    pub fn received(context: PaymentContext, action: ActionDigest) -> Self {
        Self {
            state: PaymentState::Received,
            context,
            action,
        }
    }

    pub fn verified(context: PaymentContext, action: ActionDigest) -> Self {
        Self {
            state: PaymentState::Verified,
            context,
            action,
        }
    }

    pub(crate) fn restore(
        state: PaymentState,
        context: PaymentContext,
        action: ActionDigest,
    ) -> Self {
        Self {
            state,
            context,
            action,
        }
    }

    pub fn state(&self) -> PaymentState {
        self.state
    }

    pub fn context(&self) -> &PaymentContext {
        &self.context
    }

    pub fn action(&self) -> &ActionDigest {
        &self.action
    }

    pub fn mark_verified(&mut self) -> Result<(), TransitionError> {
        if self.state != PaymentState::Received {
            return Err(TransitionError::Illegal(self.state));
        }
        self.state = PaymentState::Verified;
        Ok(())
    }

    /// Apply a gate decision. Wrong binding is a hard error and does not
    /// move the state (fail-closed).
    pub fn apply_decision(&mut self, decision: &Decision) -> Result<(), TransitionError> {
        if self.state != PaymentState::Verified {
            return Err(TransitionError::Illegal(self.state));
        }
        if !decision.binds(&self.context, &self.action) {
            return Err(TransitionError::UnboundDecision);
        }
        match decision {
            Decision::Commit(_) => {
                self.state = PaymentState::Committed;
                Ok(())
            }
            Decision::NoCommit(_) => {
                self.state = PaymentState::Rejected;
                Ok(())
            }
        }
    }

    /// Enter `Settling` only with an explicit `Commit` for this payment.
    /// The caller persists the signed transaction in the same database
    /// transaction, then broadcasts that stored transaction.
    pub fn begin_settlement(&mut self, commit: &Commit) -> Result<(), TransitionError> {
        match self.state {
            PaymentState::Settling
            | PaymentState::Settled
            | PaymentState::SettleFailed
            | PaymentState::SettlementUnknown => {
                return Err(TransitionError::DuplicateSettlement);
            }
            PaymentState::Committed => {}
            _ => return Err(TransitionError::CommitRequired),
        }
        if !commit.binds(&self.context, &self.action) {
            return Err(TransitionError::UnboundDecision);
        }
        self.state = PaymentState::Settling;
        Ok(())
    }

    /// A durable `NO_COMMIT` arrived before any raw transaction was stored.
    pub fn reject_unsettled(&mut self) -> Result<(), TransitionError> {
        if self.state != PaymentState::Committed {
            return Err(TransitionError::Illegal(self.state));
        }
        self.state = PaymentState::Rejected;
        Ok(())
    }

    /// Local completion after a known in-process settle attempt. Not a resubmit.
    pub fn complete_settlement(&mut self) -> Result<(), TransitionError> {
        if self.state != PaymentState::Settling {
            return Err(TransitionError::Illegal(self.state));
        }
        self.state = PaymentState::Settled;
        Ok(())
    }

    /// Crash while `Settling`: status is uncertain, not a failure, not a retry.
    pub fn mark_uncertain(&mut self) -> Result<(), TransitionError> {
        if self.state != PaymentState::Settling {
            return Err(TransitionError::Illegal(self.state));
        }
        self.state = PaymentState::SettlementUnknown;
        Ok(())
    }

    /// Operator/chain confirmation of an uncertain payment. Does not submit a tx.
    pub fn resolve_uncertain(&mut self, outcome: PaymentState) -> Result<(), TransitionError> {
        if self.state != PaymentState::SettlementUnknown {
            return Err(TransitionError::Illegal(self.state));
        }
        match outcome {
            PaymentState::Settled | PaymentState::SettleFailed => {
                self.state = outcome;
                Ok(())
            }
            _ => Err(TransitionError::Illegal(self.state)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leibniz::{ActionDigest, Decision, LeibnizGate, PaymentContext, PolicyGate};

    fn ctx(nonce: &str) -> PaymentContext {
        PaymentContext::try_new("base", "payer", "payto", "usdc", nonce).unwrap()
    }

    fn digest(tag: u8) -> ActionDigest {
        let mut bytes = [0u8; 32];
        bytes[0] = tag;
        ActionDigest::new(bytes)
    }

    fn commit_for(context: &PaymentContext, action: &ActionDigest) -> Decision {
        LeibnizGate.decide(context, action)
    }

    #[test]
    fn settlement_requires_explicit_commit() {
        let context = ctx("1");
        let action = digest(1);
        let mut payment = Payment::verified(context.clone(), action);

        assert_eq!(
            payment.begin_settlement(
                commit_for(&context, &action)
                    .as_commit()
                    .expect("fixture commit")
            ),
            Err(TransitionError::CommitRequired)
        );
        assert_eq!(payment.state(), PaymentState::Verified);
    }

    #[test]
    fn matching_commit_allows_settlement() {
        let context = ctx("1");
        let action = digest(1);
        let mut payment = Payment::verified(context.clone(), action);
        let decision = commit_for(&context, &action);

        payment.apply_decision(&decision).unwrap();
        assert_eq!(payment.state(), PaymentState::Committed);

        let commit = decision.as_commit().expect("Commit");
        payment.begin_settlement(commit).unwrap();
        assert_eq!(payment.state(), PaymentState::Settling);
    }

    #[test]
    fn commit_cannot_be_reused_on_another_payment_or_action() {
        let a = ctx("1");
        let b = ctx("2");
        let action_a = digest(1);
        let action_b = digest(2);
        let stolen = commit_for(&a, &action_a);

        let mut other_payment = Payment::verified(b.clone(), action_a);
        assert_eq!(
            other_payment.apply_decision(&stolen),
            Err(TransitionError::UnboundDecision)
        );
        assert_eq!(other_payment.state(), PaymentState::Verified);

        let mut other_action = Payment::verified(a.clone(), action_b);
        assert_eq!(
            other_action.apply_decision(&stolen),
            Err(TransitionError::UnboundDecision)
        );
        assert_eq!(other_action.state(), PaymentState::Verified);
    }

    #[test]
    fn foreign_commit_cannot_settle_a_committed_payment() {
        let a = ctx("1");
        let b = ctx("2");
        let action = digest(1);
        let mut payment = Payment::verified(a.clone(), action);
        let own = commit_for(&a, &action);
        payment.apply_decision(&own).unwrap();

        let foreign = commit_for(&b, &action);
        let foreign_commit = foreign.as_commit().expect("Commit");
        assert_eq!(
            payment.begin_settlement(foreign_commit),
            Err(TransitionError::UnboundDecision)
        );
        assert_eq!(payment.state(), PaymentState::Committed);
    }

    #[test]
    fn no_commit_rejects_and_blocks_settlement() {
        let context = ctx("1");
        let action = ActionDigest::new([0u8; 32]);
        let mut payment = Payment::verified(context.clone(), action);
        let decision = LeibnizGate.decide(&context, &action);

        assert!(matches!(decision, Decision::NoCommit(_)));
        payment.apply_decision(&decision).unwrap();
        assert_eq!(payment.state(), PaymentState::Rejected);

        let allowed = commit_for(&ctx("1"), &digest(1));
        let commit = allowed.as_commit().expect("unrelated Commit");
        assert_eq!(
            payment.begin_settlement(commit),
            Err(TransitionError::CommitRequired)
        );
        assert_eq!(payment.state(), PaymentState::Rejected);
    }

    #[test]
    fn invalid_transitions_are_rejected() {
        let context = ctx("1");
        let action = digest(1);
        let mut payment = Payment::received(context.clone(), action);
        assert_eq!(
            payment.apply_decision(&commit_for(&context, &action)),
            Err(TransitionError::Illegal(PaymentState::Received))
        );

        payment.mark_verified().unwrap();
        assert_eq!(
            payment.mark_verified(),
            Err(TransitionError::Illegal(PaymentState::Verified))
        );
        assert_eq!(
            payment.complete_settlement(),
            Err(TransitionError::Illegal(PaymentState::Verified))
        );
    }

    #[test]
    fn completed_payment_cannot_settle_again() {
        let context = ctx("1");
        let action = digest(1);
        let mut payment = Payment::verified(context.clone(), action);
        let decision = commit_for(&context, &action);
        payment.apply_decision(&decision).unwrap();
        let commit = decision.as_commit().expect("Commit");
        payment.begin_settlement(commit).unwrap();
        payment.complete_settlement().unwrap();

        assert_eq!(
            payment.begin_settlement(commit),
            Err(TransitionError::DuplicateSettlement)
        );
        assert_eq!(payment.state(), PaymentState::Settled);
        assert_eq!(
            payment.reject_unsettled(),
            Err(TransitionError::Illegal(PaymentState::Settled))
        );
    }

    #[test]
    fn committed_payment_without_a_settlement_can_be_rejected() {
        let context = ctx("1");
        let action = digest(1);
        let mut payment = Payment::verified(context.clone(), action);
        let decision = commit_for(&context, &action);
        payment.apply_decision(&decision).unwrap();
        assert_eq!(payment.state(), PaymentState::Committed);

        payment.reject_unsettled().unwrap();
        assert_eq!(payment.state(), PaymentState::Rejected);
        assert_eq!(
            payment.reject_unsettled(),
            Err(TransitionError::Illegal(PaymentState::Rejected))
        );
    }
}
