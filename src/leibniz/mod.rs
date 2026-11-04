//! Leibniz layer: payment binding types (journal hash-chain is still M5).
//!
//! Live settlement does not consult [`LeibnizGate`]. A `Commit` that authorizes
//! a USDC transaction is minted only after a verified Oracle `COMMIT`.
//! Anything other than that explicit token, bound to the same payment context
//! and action digest, must be treated as a refusal to settle.

/// Validated payment identity presented to the gate after `/verify` succeeds.
///
/// Construction is the validation step: empty fields are rejected, so `decide`
/// only sees a well-formed context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentContext {
    network: String,
    payer: String,
    pay_to: String,
    asset: String,
    nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidPaymentContext;

impl PaymentContext {
    pub fn try_new(
        network: impl Into<String>,
        payer: impl Into<String>,
        pay_to: impl Into<String>,
        asset: impl Into<String>,
        nonce: impl Into<String>,
    ) -> Result<Self, InvalidPaymentContext> {
        let ctx = Self {
            network: network.into(),
            payer: payer.into(),
            pay_to: pay_to.into(),
            asset: asset.into(),
            nonce: nonce.into(),
        };
        if ctx.network.is_empty()
            || ctx.payer.is_empty()
            || ctx.pay_to.is_empty()
            || ctx.asset.is_empty()
            || ctx.nonce.is_empty()
        {
            return Err(InvalidPaymentContext);
        }
        Ok(ctx)
    }

    pub fn network(&self) -> &str {
        &self.network
    }

    pub fn payer(&self) -> &str {
        &self.payer
    }

    pub fn pay_to(&self) -> &str {
        &self.pay_to
    }

    pub fn asset(&self) -> &str {
        &self.asset
    }

    pub fn nonce(&self) -> &str {
        &self.nonce
    }
}

/// Digest of the action this payment is meant to unlock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionDigest([u8; 32]);

impl ActionDigest {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(Self)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn is_unspecified(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

/// Ties a gate outcome to one payment context and one action.
///
/// Equality of the stored copies is the binding: a `Commit` from payment A
/// cannot be applied to payment B or to a different action.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Binding {
    context: PaymentContext,
    action: ActionDigest,
}

impl Binding {
    fn of(context: &PaymentContext, action: &ActionDigest) -> Self {
        Self {
            context: context.clone(),
            action: *action,
        }
    }

    fn binds(&self, context: &PaymentContext, action: &ActionDigest) -> bool {
        &self.context == context && &self.action == action
    }
}

/// Explicit allow-to-settle token.
///
/// Live settlement mints this only from a verified Oracle `COMMIT`.
/// [`PolicyGate::decide`] still mints one for in-memory tests of the state
/// machine. That test token must not be used to sign or broadcast USDC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    reason: String,
    binding: Binding,
}

impl Commit {
    /// Settlement right after Oracle `COMMIT`. The state machine still checks
    /// that this token is bound to the payment being settled.
    pub(crate) fn for_oracle(
        context: &PaymentContext,
        action: &ActionDigest,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            reason: reason.into(),
            binding: Binding::of(context, action),
        }
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub fn binds(&self, context: &PaymentContext, action: &ActionDigest) -> bool {
        self.binding.binds(context, action)
    }
}

/// Explicit refusal. Still bound so a `NoCommit` for one payment cannot be
/// applied to another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoCommit {
    reason: String,
    binding: Binding,
}

impl NoCommit {
    pub(crate) fn for_oracle(
        context: &PaymentContext,
        action: &ActionDigest,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            reason: reason.into(),
            binding: Binding::of(context, action),
        }
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub fn binds(&self, context: &PaymentContext, action: &ActionDigest) -> bool {
        self.binding.binds(context, action)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Commit(Commit),
    NoCommit(NoCommit),
}

impl Decision {
    pub fn reason(&self) -> &str {
        match self {
            Decision::Commit(c) => c.reason(),
            Decision::NoCommit(n) => n.reason(),
        }
    }

    pub fn binds(&self, context: &PaymentContext, action: &ActionDigest) -> bool {
        match self {
            Decision::Commit(c) => c.binds(context, action),
            Decision::NoCommit(n) => n.binds(context, action),
        }
    }

    pub fn as_commit(&self) -> Option<&Commit> {
        match self {
            Decision::Commit(c) => Some(c),
            Decision::NoCommit(_) => None,
        }
    }
}

/// In-process DCL stand-in. Fail-closed: an unspecified action is a refusal.
#[derive(Debug, Default, Clone, Copy)]
pub struct LeibnizGate;

/// Decides whether one verified payment may settle for one action digest.
pub trait PolicyGate {
    fn decide(&self, context: &PaymentContext, action: &ActionDigest) -> Decision;
}

impl PolicyGate for LeibnizGate {
    fn decide(&self, context: &PaymentContext, action: &ActionDigest) -> Decision {
        let binding = Binding::of(context, action);
        if action.is_unspecified() {
            return Decision::NoCommit(NoCommit {
                reason: "action digest is unspecified".to_string(),
                binding,
            });
        }
        Decision::Commit(Commit {
            reason: "local dcl policy allowed".to_string(),
            binding,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(nonce: &str) -> PaymentContext {
        PaymentContext::try_new("base", "payer", "payto", "usdc", nonce).unwrap()
    }

    fn digest(tag: u8) -> ActionDigest {
        let mut bytes = [0u8; 32];
        bytes[0] = tag;
        ActionDigest::new(bytes)
    }

    #[test]
    fn rejects_empty_payment_fields() {
        assert!(PaymentContext::try_new("", "p", "t", "a", "n").is_err());
        assert!(PaymentContext::try_new("n", "", "t", "a", "1").is_err());
    }

    #[test]
    fn commit_is_bound_to_exact_context_and_action() {
        let gate = LeibnizGate;
        let a = ctx("1");
        let action = digest(1);
        let decision = gate.decide(&a, &action);

        match &decision {
            Decision::Commit(commit) => {
                assert_eq!(commit.reason(), "local dcl policy allowed");
                assert!(commit.binds(&a, &action));
                assert!(!commit.binds(&ctx("2"), &action));
                assert!(!commit.binds(&a, &digest(2)));
            }
            Decision::NoCommit(_) => panic!("expected Commit"),
        }
    }

    #[test]
    fn unspecified_action_is_no_commit() {
        let gate = LeibnizGate;
        let a = ctx("1");
        let action = ActionDigest::new([0u8; 32]);
        let decision = gate.decide(&a, &action);

        match decision {
            Decision::NoCommit(n) => {
                assert!(n.reason().contains("unspecified"));
                assert!(n.binds(&a, &action));
                assert!(!n.binds(&ctx("2"), &action));
            }
            Decision::Commit(_) => panic!("expected NoCommit"),
        }
    }

    #[test]
    fn policy_gate_dispatch_binds_commit_and_rejects_zero_digest() {
        let gate = LeibnizGate;
        let context = ctx("1");
        let action = digest(1);
        let committed = PolicyGate::decide(&gate, &context, &action);

        assert!(matches!(committed, Decision::Commit(_)));
        assert_eq!(committed.reason(), "local dcl policy allowed");
        assert!(committed.binds(&context, &action));
        assert!(!committed.binds(&ctx("2"), &action));
        assert!(!committed.binds(&context, &digest(2)));

        let zero = ActionDigest::new([0u8; 32]);
        assert!(zero.is_unspecified());
        let rejected = PolicyGate::decide(&gate, &context, &zero);
        assert!(matches!(rejected, Decision::NoCommit(_)));
        assert_eq!(rejected.reason(), "action digest is unspecified");
        assert!(rejected.binds(&context, &zero));
        assert!(!rejected.binds(&ctx("2"), &zero));
        assert!(!rejected.binds(&context, &action));
    }
}
