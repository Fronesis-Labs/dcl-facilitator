//! Base mainnet USDC access: read-only verification and relayer settlement.

mod eip3009;
mod rpc;
mod tx;

pub use eip3009::{
    authorization_state_selector, balance_of_selector, keccak, recover_signer, signing_digest,
    to_checksum, transfer_with_authorization_calldata, transfer_with_authorization_selector,
    Authorization, ChainError, BASE_CHAIN_ID, EIP712_NAME, EIP712_VERSION, NETWORK, USDC_ADDRESS,
};
pub use rpc::{BaseRpc, RpcBlock, RpcReceipt, RpcTransaction};
pub use tx::{
    parse_signed_tx, recover_sender, transaction_hash, ParsedTx, Relayer, SignedTx, UnsignedTx,
};

#[cfg(test)]
pub(crate) use eip3009::{test_address, test_sign};
