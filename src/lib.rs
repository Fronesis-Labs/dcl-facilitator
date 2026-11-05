//! DCL x402 facilitator with a policy gate (Leibniz layer).
//!
//! `POST /verify` checks an x402 v2 EIP-3009 authorization locally and does
//! not write payment state. `POST /settle` signs with the local relayer only
//! after a verified Oracle `COMMIT` bound to that authorization. A missing
//! or invalid decision does not fall back to the local policy gate. Recovery
//! rechecks the stored signature and the stored raw transaction before it
//! broadcasts. It does not execute DCL.
//! Payment rows live in SQLite with uniqueness on `(network, payer, nonce)`.

pub mod api;
pub mod chain;
pub mod config;
pub mod error;
pub mod evidence;
pub mod leibniz;
pub mod machine;
pub mod prepare;
pub mod recover;
pub mod settle;
pub mod store;
pub mod verify;
