//! EIP-3009 `TransferWithAuthorization` digest and signature recovery.
//!
//! Domain and type hash follow Circle `stablecoin-evm` `EIP712.sol` and
//! `EIP3009.sol`. The token binding is Circle USDC on Base mainnet
//! (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`), EIP-712 name `USD Coin`,
//! version `2`, chain id 8453 (`eip155:8453`).

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};

/// CAIP-2 identifier for Base mainnet. x402 v2 section 11.1.
pub const NETWORK: &str = "eip155:8453";

/// EIP-155 chain id referenced by [`NETWORK`].
pub const BASE_CHAIN_ID: u64 = 8453;

/// Circle USDC proxy on Base mainnet.
pub const USDC_ADDRESS: [u8; 20] = [
    0x83, 0x35, 0x89, 0xfc, 0xd6, 0xed, 0xb6, 0xe0, 0x8f, 0x4c, 0x7c, 0x32, 0xd4, 0xf7, 0x1b, 0x54,
    0xbd, 0xa0, 0x29, 0x13,
];

/// EIP-712 domain `name` for Base USDC. Must match the token, not the symbol.
pub const EIP712_NAME: &str = "USD Coin";

/// EIP-712 domain `version` passed to Circle `makeDomainSeparator`.
pub const EIP712_VERSION: &str = "2";

/// `keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")`.
/// Published as `TRANSFER_WITH_AUTHORIZATION_TYPEHASH` in Circle `EIP3009.sol`.
const TRANSFER_WITH_AUTHORIZATION_TYPEHASH: [u8; 32] = [
    0x7c, 0x7c, 0x6c, 0xdb, 0x67, 0xa1, 0x87, 0x43, 0xf4, 0x9e, 0xc6, 0xfa, 0x9b, 0x35, 0xf5, 0x0d,
    0x52, 0xed, 0x05, 0xcb, 0xed, 0x4c, 0xc5, 0x92, 0xe1, 0x3b, 0x44, 0x50, 0x1c, 0x1a, 0x22, 0x67,
];

/// `keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")`.
/// Hard-coded in Circle `EIP712.makeDomainSeparator`.
const EIP712_DOMAIN_TYPEHASH: [u8; 32] = [
    0x8b, 0x73, 0xc3, 0xc6, 0x9b, 0xb8, 0xfe, 0x3d, 0x51, 0x2e, 0xcc, 0x4c, 0xf7, 0x59, 0xcc, 0x79,
    0x23, 0x9f, 0x7b, 0x17, 0x9b, 0x0f, 0xfa, 0xca, 0xa9, 0xa7, 0x5d, 0x52, 0x2b, 0x39, 0x40, 0x0f,
];

/// secp256k1n/2. Signatures with `s` above this are malleable (EIP-2).
const HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

const AUTHORIZATION_STATE_SIG: &str = "authorizationState(address,bytes32)";
const BALANCE_OF_SIG: &str = "balanceOf(address)";
/// Circle `transferWithAuthorization` bytes overload. The x402 payload carries
/// one 65-byte signature, which this ABI accepts directly.
const TRANSFER_WITH_AUTHORIZATION_SIG: &str =
    "transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,bytes)";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Authorization {
    pub from: [u8; 20],
    pub to: [u8; 20],
    pub value: [u8; 32],
    pub valid_after: [u8; 32],
    pub valid_before: [u8; 32],
    pub nonce: [u8; 32],
}

#[derive(Debug)]
pub enum ChainError {
    Signature,
    Rpc,
    /// `eth_call` reached the node and the contract reverted.
    Reverted,
}

pub fn keccak(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    digest
}

pub fn authorization_state_selector() -> [u8; 4] {
    selector(AUTHORIZATION_STATE_SIG)
}

fn selector(signature: &str) -> [u8; 4] {
    let digest = keccak(signature.as_bytes());
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&digest[..4]);
    selector
}

pub fn balance_of_selector() -> [u8; 4] {
    selector(BALANCE_OF_SIG)
}

pub fn transfer_with_authorization_selector() -> [u8; 4] {
    selector(TRANSFER_WITH_AUTHORIZATION_SIG)
}

/// ABI encoding of `balanceOf(address)`.
pub fn balance_of_calldata(account: [u8; 20]) -> Vec<u8> {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&balance_of_selector());
    data.extend_from_slice(&word_address(account));
    data
}

/// ABI encoding of `transferWithAuthorization(..., bytes signature)`.
/// This is an `eth_call` payload only; nothing here is signed or broadcast.
pub fn transfer_with_authorization_calldata(auth: &Authorization, signature: &[u8; 65]) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 8 * 32 + 32);
    data.extend_from_slice(&transfer_with_authorization_selector());
    data.extend_from_slice(&word_address(auth.from));
    data.extend_from_slice(&word_address(auth.to));
    data.extend_from_slice(&auth.value);
    data.extend_from_slice(&auth.valid_after);
    data.extend_from_slice(&auth.valid_before);
    data.extend_from_slice(&auth.nonce);
    // Head offset of the dynamic `bytes` tail, in bytes from the start of the arguments.
    let mut offset = [0u8; 32];
    offset[31] = (7 * 32) as u8;
    data.extend_from_slice(&offset);
    let mut length = [0u8; 32];
    length[31] = signature.len() as u8;
    data.extend_from_slice(&length);
    data.extend_from_slice(signature);
    data.resize(data.len() + (32 - (signature.len() % 32)), 0);
    data
}

/// ABI encoding of `authorizationState(address,bytes32)`.
pub fn authorization_state_calldata(authorizer: [u8; 20], nonce: [u8; 32]) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 32 + 32);
    data.extend_from_slice(&authorization_state_selector());
    data.extend_from_slice(&word_address(authorizer));
    data.extend_from_slice(&nonce);
    data
}

pub fn signing_digest(auth: &Authorization) -> [u8; 32] {
    let struct_hash = keccak(&concat_words(&[
        TRANSFER_WITH_AUTHORIZATION_TYPEHASH,
        word_address(auth.from),
        word_address(auth.to),
        auth.value,
        auth.valid_after,
        auth.valid_before,
        auth.nonce,
    ]));
    let mut message = Vec::with_capacity(2 + 32 + 32);
    message.extend_from_slice(&[0x19, 0x01]);
    message.extend_from_slice(&domain_separator());
    message.extend_from_slice(&struct_hash);
    keccak(&message)
}

pub fn domain_separator() -> [u8; 32] {
    let mut chain = [0u8; 32];
    chain[24..].copy_from_slice(&BASE_CHAIN_ID.to_be_bytes());
    keccak(&concat_words(&[
        EIP712_DOMAIN_TYPEHASH,
        keccak(EIP712_NAME.as_bytes()),
        keccak(EIP712_VERSION.as_bytes()),
        chain,
        word_address(USDC_ADDRESS),
    ]))
}

/// Recover the signer of a 65-byte `r || s || v` signature.
/// `v` may be 0/1 or 27/28. High-`s` signatures are rejected.
pub fn recover_signer(digest: &[u8; 32], signature: &[u8; 65]) -> Result<[u8; 20], ChainError> {
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&signature[..32]);
    s.copy_from_slice(&signature[32..64]);
    if r == [0u8; 32] || s == [0u8; 32] || s > HALF_N {
        return Err(ChainError::Signature);
    }
    let v = match signature[64] {
        0 | 27 => 0,
        1 | 28 => 1,
        _ => return Err(ChainError::Signature),
    };
    let sig = Signature::from_slice(&signature[..64]).map_err(|_| ChainError::Signature)?;
    let recid = RecoveryId::try_from(v).map_err(|_| ChainError::Signature)?;
    let key = VerifyingKey::recover_from_prehash(digest, &sig, recid)
        .map_err(|_| ChainError::Signature)?;
    let point = key.to_encoded_point(false);
    let encoded = point.as_bytes();
    if encoded.len() != 65 {
        return Err(ChainError::Signature);
    }
    let hash = keccak(&encoded[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    Ok(address)
}

pub fn to_checksum(address: &[u8; 20]) -> String {
    let hex = hex_encode(address);
    let hash = keccak(hex.as_bytes());
    let mut out = String::from("0x");
    for (i, byte) in hex.bytes().enumerate() {
        let nibble = if i % 2 == 0 {
            hash[i / 2] >> 4
        } else {
            hash[i / 2] & 0x0f
        };
        if nibble >= 8 {
            out.push((byte as char).to_ascii_uppercase());
        } else {
            out.push(byte as char);
        }
    }
    out
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
pub(crate) fn test_address(secret: &[u8; 32]) -> [u8; 20] {
    use k256::ecdsa::SigningKey;
    let bytes = k256::FieldBytes::from(*secret);
    let key = SigningKey::from_bytes(&bytes).expect("test key");
    let point = key.verifying_key().to_encoded_point(false);
    let hash = keccak(&point.as_bytes()[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    address
}

#[cfg(test)]
pub(crate) fn test_sign(secret: &[u8; 32], digest: &[u8; 32]) -> [u8; 65] {
    use k256::ecdsa::SigningKey;
    let bytes = k256::FieldBytes::from(*secret);
    let key = SigningKey::from_bytes(&bytes).expect("test key");
    let (sig, recid) = key.sign_prehash_recoverable(digest).expect("sign");
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&sig.to_bytes());
    out[64] = recid.to_byte() + 27;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typehashes_match_circle_source_strings() {
        let transfer = keccak(
            b"TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)",
        );
        assert_eq!(transfer, TRANSFER_WITH_AUTHORIZATION_TYPEHASH);
        let domain = keccak(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        );
        assert_eq!(domain, EIP712_DOMAIN_TYPEHASH);
    }

    #[test]
    fn authorization_state_selector_matches_canonical_abi() {
        assert_eq!(authorization_state_selector(), [0xe9, 0x4a, 0x01, 0x02]);
        assert_eq!(balance_of_selector(), [0x70, 0xa0, 0x82, 0x31]);
    }

    #[test]
    fn transfer_calldata_is_the_bytes_overload() {
        let auth = Authorization {
            from: [0x11; 20],
            to: [0x22; 20],
            value: [0; 32],
            valid_after: [0; 32],
            valid_before: [0; 32],
            nonce: [0xab; 32],
        };
        let signature = [0x7u8; 65];
        let data = transfer_with_authorization_calldata(&auth, &signature);
        assert_eq!(&data[..4], &transfer_with_authorization_selector());
        assert_eq!(data[4 + 6 * 32 + 31], 224);
        assert_eq!(data[4 + 7 * 32 + 31], 65);
        assert_eq!(&data[4 + 8 * 32..4 + 8 * 32 + 65], &signature);
    }

    #[test]
    fn checksum_matches_eip55_vector() {
        let raw = hex_decode("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").unwrap();
        let mut address = [0u8; 20];
        address.copy_from_slice(&raw);
        assert_eq!(
            to_checksum(&address),
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        );
    }

    #[test]
    fn usdc_constant_is_the_circle_base_address() {
        assert_eq!(
            to_checksum(&USDC_ADDRESS).to_ascii_lowercase(),
            "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
        );
    }

    #[test]
    fn recovered_signer_matches_the_test_key() {
        let secret = [0x42u8; 32];
        let auth = sample_auth(test_address(&secret));
        let digest = signing_digest(&auth);
        let signature = test_sign(&secret, &digest);
        let recovered = recover_signer(&digest, &signature).unwrap();
        assert_eq!(recovered, auth.from);
    }

    #[test]
    fn high_s_signature_is_rejected() {
        let secret = [0x42u8; 32];
        let auth = sample_auth(test_address(&secret));
        let digest = signing_digest(&auth);
        let mut signature = test_sign(&secret, &digest);
        for (a, b) in signature[32..64].iter_mut().zip(HALF_N) {
            *a = b;
        }
        signature[63] = signature[63].saturating_add(1);
        assert!(recover_signer(&digest, &signature).is_err());
    }

    fn sample_auth(from: [u8; 20]) -> Authorization {
        Authorization {
            from,
            to: [0x11u8; 20],
            value: {
                let mut v = [0u8; 32];
                v[31] = 1;
                v
            },
            valid_after: [0u8; 32],
            valid_before: {
                let mut v = [0u8; 32];
                v[28..].copy_from_slice(&4_102_444_800u32.to_be_bytes());
                v
            },
            nonce: [0xabu8; 32],
        }
    }

    fn hex_decode(s: &str) -> Option<Vec<u8>> {
        if s.len() % 2 != 0 {
            return None;
        }
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
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
}
