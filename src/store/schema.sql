CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    network TEXT NOT NULL,
    payer TEXT NOT NULL,
    pay_to TEXT NOT NULL,
    asset TEXT NOT NULL,
    nonce TEXT NOT NULL,
    action_digest BLOB NOT NULL CHECK (length(action_digest) = 32),
    state TEXT NOT NULL CHECK (state IN (
        'received',
        'verified',
        'committed',
        'settling',
        'settled',
        'rejected',
        'settle_failed',
        'settlement_unknown'
    )),
    UNIQUE (network, payer, nonce)
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    payment_id INTEGER NOT NULL REFERENCES payments(id),
    from_state TEXT,
    to_state TEXT NOT NULL,
    note TEXT,
    at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS events_payment_id ON events (payment_id);

CREATE TABLE IF NOT EXISTS settlement_evidence (
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

-- One Oracle decision. `verified` is a durable COMMIT with no raw transaction.
-- `consumed` is final: a COMMIT carries `raw_tx_hash`, and `no_commit` does not.
-- `legacy_incomplete` marks a copied row whose evidence is missing, malformed,
-- or whose payer signature did not match exactly one settlement row.
-- Body columns added by older builds have no length checks, so a legacy blob
-- of any length still copies. Absence of a row is not permission to broadcast.
CREATE TABLE IF NOT EXISTS decision_consumptions (
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
    signing_claim BLOB,
    signing_claim_until INTEGER,
    UNIQUE (network, payer, nonce)
);
