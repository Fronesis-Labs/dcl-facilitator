//! EIP-1559 transaction for a Base USDC `transferWithAuthorization` call.
//!
//! The relayer key signs this envelope and pays gas. The EIP-3009 signature
//! stays inside the calldata. A signature produced here is discarded unless
//! the caller stores the exact raw bytes before broadcasting them.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use k256::ecdsa::SigningKey;

use super::eip3009::{
    keccak, recover_signer, to_checksum, ChainError, BASE_CHAIN_ID, USDC_ADDRESS,
};

#[derive(Clone)]
pub struct Relayer {
    inner: Arc<RelayerInner>,
}

struct RelayerInner {
    secret: [u8; 32],
    address: [u8; 20],
    signs: AtomicU64,
}

impl std::fmt::Debug for Relayer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Relayer")
            .field("address", &to_checksum(&self.inner.address))
            .finish()
    }
}

impl Relayer {
    pub fn from_secret(secret: [u8; 32]) -> Result<Self, ChainError> {
        let address = address_of(&secret)?;
        Ok(Self {
            inner: Arc::new(RelayerInner {
                secret,
                address,
                signs: AtomicU64::new(0),
            }),
        })
    }

    /// Load a hex-encoded 32-byte key. The file bytes are cleared after parsing.
    pub fn from_file(path: &Path) -> Result<Self, ChainError> {
        let mut bytes = std::fs::read(path).map_err(|_| ChainError::Signature)?;
        let parsed = parse_key_file(&bytes);
        bytes.fill(0);
        Self::from_secret(parsed?)
    }

    pub fn address(&self) -> [u8; 20] {
        self.inner.address
    }

    pub fn sign_count(&self) -> u64 {
        self.inner.signs.load(Ordering::SeqCst)
    }

    pub fn sign(&self, tx: &UnsignedTx) -> Result<SignedTx, ChainError> {
        self.inner.signs.fetch_add(1, Ordering::SeqCst);
        if tx.chain_id != BASE_CHAIN_ID || tx.value != 0 || tx.to != USDC_ADDRESS {
            return Err(ChainError::Signature);
        }
        let unsigned = unsigned_list(tx);
        let hash = signing_hash(&unsigned);
        let bytes = k256::FieldBytes::from(self.inner.secret);
        let key = SigningKey::from_bytes(&bytes).map_err(|_| ChainError::Signature)?;
        let (signature, recid) = key
            .sign_prehash_recoverable(&hash)
            .map_err(|_| ChainError::Signature)?;
        let compact = signature.to_bytes();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&compact[..32]);
        s.copy_from_slice(&compact[32..]);
        let y_parity = recid.to_byte();
        let mut check = [0u8; 65];
        check[..32].copy_from_slice(&r);
        check[32..64].copy_from_slice(&s);
        check[64] = y_parity;
        if recover_signer(&hash, &check)? != self.inner.address {
            return Err(ChainError::Signature);
        }
        let mut items = unsigned;
        items.push(rlp_uint(u128::from(y_parity)));
        items.push(rlp_uint_be(&r));
        items.push(rlp_uint_be(&s));
        let mut raw = vec![0x02];
        raw.extend(rlp_list(&items));
        let hash = transaction_hash(&raw);
        Ok(SignedTx { raw, hash })
    }
}

pub struct UnsignedTx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee: u128,
    pub max_fee: u128,
    pub gas_limit: u64,
    pub to: [u8; 20],
    pub value: u128,
    pub data: Vec<u8>,
}

pub struct SignedTx {
    pub raw: Vec<u8>,
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee: u128,
    pub max_fee: u128,
    pub gas_limit: u64,
    pub to: [u8; 20],
    pub value: u128,
    pub data: Vec<u8>,
}

pub fn transaction_hash(raw: &[u8]) -> [u8; 32] {
    keccak(raw)
}

pub fn parse_signed_tx(raw: &[u8]) -> Result<ParsedTx, ChainError> {
    let (items, y_parity, r, s) = split_signed(raw)?;
    let _ = (y_parity, r, s);
    Ok(ParsedTx {
        chain_id: u64_from(&items[0])?,
        nonce: u64_from(&items[1])?,
        max_priority_fee: u128_from(&items[2])?,
        max_fee: u128_from(&items[3])?,
        gas_limit: u64_from(&items[4])?,
        to: address_from(&items[5])?,
        value: u128_from(&items[6])?,
        data: items[7].clone(),
    })
}

pub fn recover_sender(raw: &[u8]) -> Result<[u8; 20], ChainError> {
    let (items, y_parity, r, s) = split_signed(raw)?;
    let unsigned = vec![
        rlp_uint(u128::from(u64_from(&items[0])?)),
        rlp_uint(u128::from(u64_from(&items[1])?)),
        rlp_uint(u128_from(&items[2])?),
        rlp_uint(u128_from(&items[3])?),
        rlp_uint(u128::from(u64_from(&items[4])?)),
        rlp_bytes(&items[5]),
        rlp_uint(u128_from(&items[6])?),
        rlp_bytes(&items[7]),
        rlp_list(&[]),
    ];
    let hash = signing_hash(&unsigned);
    let mut signature = [0u8; 65];
    signature[..32].copy_from_slice(&r);
    signature[32..64].copy_from_slice(&s);
    signature[64] = y_parity;
    recover_signer(&hash, &signature)
}

type SplitSigned = (Vec<Vec<u8>>, u8, [u8; 32], [u8; 32]);

fn split_signed(raw: &[u8]) -> Result<SplitSigned, ChainError> {
    if raw.first() != Some(&0x02) {
        return Err(ChainError::Signature);
    }
    let (item, used) = read_item(&raw[1..])?;
    if used != raw.len() - 1 {
        return Err(ChainError::Signature);
    }
    let list = match item {
        Rlp::List(items) if items.len() == 12 => items,
        _ => return Err(ChainError::Signature),
    };
    let mut bytes = Vec::with_capacity(12);
    for (index, item) in list.into_iter().enumerate() {
        match item {
            Rlp::Bytes(value) if index != 8 => bytes.push(value),
            Rlp::List(items) if index == 8 && items.is_empty() => bytes.push(Vec::new()),
            _ => return Err(ChainError::Signature),
        }
    }
    let y_parity = match bytes[9].as_slice() {
        [] => 0,
        [0x01] => 1,
        _ => return Err(ChainError::Signature),
    };
    let r = pad32(&bytes[10])?;
    let s = pad32(&bytes[11])?;
    Ok((bytes, y_parity, r, s))
}

fn unsigned_list(tx: &UnsignedTx) -> Vec<Vec<u8>> {
    vec![
        rlp_uint(u128::from(tx.chain_id)),
        rlp_uint(u128::from(tx.nonce)),
        rlp_uint(tx.max_priority_fee),
        rlp_uint(tx.max_fee),
        rlp_uint(u128::from(tx.gas_limit)),
        rlp_bytes(&tx.to),
        rlp_uint(tx.value),
        rlp_bytes(&tx.data),
        rlp_list(&[]),
    ]
}

fn signing_hash(unsigned: &[Vec<u8>]) -> [u8; 32] {
    let mut preimage = vec![0x02];
    preimage.extend(rlp_list(unsigned));
    keccak(&preimage)
}

fn address_of(secret: &[u8; 32]) -> Result<[u8; 20], ChainError> {
    let bytes = k256::FieldBytes::from(*secret);
    let key = SigningKey::from_bytes(&bytes).map_err(|_| ChainError::Signature)?;
    let point = key.verifying_key().to_encoded_point(false);
    let encoded = point.as_bytes();
    if encoded.len() != 65 {
        return Err(ChainError::Signature);
    }
    let hash = keccak(&encoded[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    Ok(address)
}

fn parse_key_file(bytes: &[u8]) -> Result<[u8; 32], ChainError> {
    if bytes.len() > 80 {
        return Err(ChainError::Signature);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ChainError::Signature)?;
    let trimmed = text.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if hex.len() != 64 {
        return Err(ChainError::Signature);
    }
    let decoded = decode_hex(hex).ok_or(ChainError::Signature)?;
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&decoded);
    Ok(secret)
}

fn rlp_bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 0x80 {
        return vec![data[0]];
    }
    let mut out = prefix(0x80, data.len());
    out.extend_from_slice(data);
    out
}

fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = Vec::new();
    for item in items {
        payload.extend_from_slice(item);
    }
    let mut out = prefix(0xc0, payload.len());
    out.extend(payload);
    out
}

fn rlp_uint(value: u128) -> Vec<u8> {
    if value == 0 {
        return rlp_bytes(&[]);
    }
    rlp_bytes(trim_be(&value.to_be_bytes()))
}

fn rlp_uint_be(bytes: &[u8]) -> Vec<u8> {
    rlp_bytes(trim_be(bytes))
}

fn prefix(offset: u8, len: usize) -> Vec<u8> {
    if len <= 55 {
        return vec![offset + u8::try_from(len).unwrap_or(55)];
    }
    let wide = len.to_be_bytes();
    let size = trim_be(&wide);
    let mut out = Vec::with_capacity(1 + size.len());
    out.push(offset + 55 + u8::try_from(size.len()).unwrap_or(1));
    out.extend_from_slice(size);
    out
}

fn trim_be(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    &bytes[start..]
}

enum Rlp {
    Bytes(Vec<u8>),
    List(Vec<Rlp>),
}

fn read_item(input: &[u8]) -> Result<(Rlp, usize), ChainError> {
    if input.is_empty() {
        return Err(ChainError::Signature);
    }
    let prefix = input[0];
    if prefix <= 0x7f {
        return Ok((Rlp::Bytes(vec![prefix]), 1));
    }
    if prefix <= 0xb7 {
        let len = (prefix - 0x80) as usize;
        let end = 1 + len;
        if input.len() < end {
            return Err(ChainError::Signature);
        }
        return Ok((Rlp::Bytes(input[1..end].to_vec()), end));
    }
    if prefix <= 0xbf {
        let len_of_len = (prefix - 0xb7) as usize;
        return read_sized(input, len_of_len, false);
    }
    if prefix <= 0xf7 {
        let len = (prefix - 0xc0) as usize;
        let end = 1 + len;
        if input.len() < end {
            return Err(ChainError::Signature);
        }
        return Ok((Rlp::List(read_sequence(&input[1..end])?), end));
    }
    let len_of_len = (prefix - 0xf7) as usize;
    read_sized(input, len_of_len, true)
}

fn read_sized(input: &[u8], len_of_len: usize, list: bool) -> Result<(Rlp, usize), ChainError> {
    if len_of_len == 0 || input.len() < 1 + len_of_len {
        return Err(ChainError::Signature);
    }
    let mut wide = [0u8; 8];
    if len_of_len > 8 {
        return Err(ChainError::Signature);
    }
    wide[8 - len_of_len..].copy_from_slice(&input[1..1 + len_of_len]);
    let len = usize::try_from(u64::from_be_bytes(wide)).map_err(|_| ChainError::Signature)?;
    let start = 1 + len_of_len;
    let end = start + len;
    if input.len() < end {
        return Err(ChainError::Signature);
    }
    if list {
        Ok((Rlp::List(read_sequence(&input[start..end])?), end))
    } else {
        Ok((Rlp::Bytes(input[start..end].to_vec()), end))
    }
}

fn read_sequence(mut input: &[u8]) -> Result<Vec<Rlp>, ChainError> {
    let mut items = Vec::new();
    while !input.is_empty() {
        let (item, used) = read_item(input)?;
        items.push(item);
        input = &input[used..];
    }
    Ok(items)
}

fn u64_from(bytes: &[u8]) -> Result<u64, ChainError> {
    if bytes.len() > 8 || bytes.first() == Some(&0) {
        return Err(ChainError::Signature);
    }
    let mut wide = [0u8; 8];
    wide[8 - bytes.len()..].copy_from_slice(bytes);
    Ok(u64::from_be_bytes(wide))
}

fn u128_from(bytes: &[u8]) -> Result<u128, ChainError> {
    if bytes.len() > 16 || bytes.first() == Some(&0) {
        return Err(ChainError::Signature);
    }
    let mut wide = [0u8; 16];
    wide[16 - bytes.len()..].copy_from_slice(bytes);
    Ok(u128::from_be_bytes(wide))
}

fn address_from(bytes: &[u8]) -> Result<[u8; 20], ChainError> {
    let mut address = [0u8; 20];
    if bytes.len() != 20 {
        return Err(ChainError::Signature);
    }
    address.copy_from_slice(bytes);
    Ok(address)
}

fn pad32(bytes: &[u8]) -> Result<[u8; 32], ChainError> {
    if bytes.is_empty() || bytes.len() > 32 || bytes[0] == 0 {
        return Err(ChainError::Signature);
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(out)
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let bytes = value.as_bytes();
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
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_transaction_recovers_the_relayer_and_is_deterministic() {
        let relayer = Relayer::from_secret([0x24; 32]).unwrap();
        let first = sample(1, 20);
        let signed = relayer.sign(&first).unwrap();
        let again = relayer.sign(&first).unwrap();
        assert_eq!(signed.raw, again.raw);
        assert_eq!(transaction_hash(&signed.raw), signed.hash);
        assert_eq!(recover_sender(&signed.raw).unwrap(), relayer.address());
        let parsed = parse_signed_tx(&signed.raw).unwrap();
        assert_eq!(parsed.nonce, 1);
        assert_eq!(parsed.to, USDC_ADDRESS);
        assert_eq!(parsed.value, 0);
        assert_eq!(parsed.data, first.data);
        assert_eq!(parsed.max_fee, 20);

        let repriced = relayer.sign(&sample(1, 21)).unwrap();
        assert_ne!(repriced.hash, signed.hash);
        assert_eq!(relayer.sign_count(), 3);
        let debug = format!("{relayer:?}");
        assert!(!debug.contains("242424"));
    }

    #[test]
    fn key_file_is_one_hex_scalar() {
        let path = std::env::temp_dir().join(format!("dcl-key-{}-only", std::process::id()));
        std::fs::write(
            &path,
            "0x2424242424242424242424242424242424242424242424242424242424242424\n",
        )
        .unwrap();
        let loaded = Relayer::from_file(&path).unwrap();
        assert_eq!(
            loaded.address(),
            Relayer::from_secret([0x24; 32]).unwrap().address()
        );
        let _ = std::fs::remove_file(&path);
        assert!(Relayer::from_file(Path::new("relative.key")).is_err());
    }

    fn sample(nonce: u64, max_fee: u128) -> UnsignedTx {
        UnsignedTx {
            chain_id: BASE_CHAIN_ID,
            nonce,
            max_priority_fee: 1,
            max_fee,
            gas_limit: 100_000,
            to: USDC_ADDRESS,
            value: 0,
            data: vec![0x12, 0x34, 0x56, 0x78, 0x00],
        }
    }
}
