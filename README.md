# dcl-facilitator

x402 v2 facilitator for Base mainnet USDC. An Oracle `COMMIT` is the only
permission to settle. The local policy gate is not on that path.

**Status:** `POST /verify` and `POST /settle` accept exact EIP-3009 payments on
Base mainnet (`eip155:8453`, chain id `8453`). The asset is Circle USDC
`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`, EIP-712 name `USD Coin`, version
`2`. That domain is fixed in the binary. It is not taken from the request.

`/verify` is read-only. It checks the payload, recovers the payer signature,
and asks Base for `authorizationState`, `balanceOf`, and a
`transferWithAuthorization` simulation. It does not write a payment row.

`/settle` signs one relayer transaction only after `assess_decision` accepts an
Oracle `COMMIT` bound to that authorization. That decision is stored first as
`verified`. Signing then consumes it in the same SQLite transaction that
stores the raw transaction. Broadcast uses those exact bytes. A missing or
invalid decision does not fall back to `LeibnizGate`. Recovery rechecks the
stored Oracle signature and the stored raw transaction before sending, and
does not rebroadcast a settlement that has no stored Oracle `COMMIT`. A repeat
of the same payment returns the stored transaction instead of signing another
one. `GET /supported` still returns `{ "kinds": [] }`.

Settlement needs `BASE_RPC_URL`, `DATABASE_PATH`, an absolute
`SETTLER_KEY_FILE` outside this repository, `SETTLER_MAX_FEE_PER_GAS`, and
`ORACLE_ADDRESS`. Without the settler key and the Oracle address, the process
can verify and cannot sign or broadcast.

The append-only hash-chained journal is not implemented. `LeibnizGate` is not
consulted during settlement.

## Payment flow

1. Parse the x402 v2 body. The network, asset, and EIP-712 domain must match
   the constants above. `accepted` and `paymentRequirements` must be the same
   terms.
2. Look up `(network, payer, nonce)` in SQLite.
3. `/verify` simulates the transfer and reads `authorizationState`.
4. `/settle` requires `decisionEvidence`. The facilitator rebuilds the
   expected binding from the payment and checks the Oracle signature over
   `decisionDigest`.
5. A verified `COMMIT` is stored with decision state `verified` in the same
   SQLite transaction that moves the payment to `Committed`. `NO_COMMIT` is
   stored as a refusal and is not a permission to sign.
6. One signing claim owns the relayer signature. Consuming that `COMMIT`,
   storing the raw transaction, and moving the payment to `Settling` happen in
   one SQLite transaction. The stored raw transaction is the only transaction
   that may be broadcast, including after a restart.
7. A successful response requires a receipt with status `1`, a canonical block,
   the USDC `Transfer` log, and `authorizationState` showing the nonce used.

## Oracle Payment Evidence Contract

The Oracle must reproduce this serialization. It must not sign a
`decisionDigest`, verdict, or evidence object supplied by the caller. It
receives the authorization, checks it, evaluates its own policy, builds the
canonical object, computes the digest, and signs only its own `COMMIT`.

`dcl-facilitator evidence` prints the unsigned object and digest for one
payment body. It does not sign and it does not open a database, an RPC
connection, or a relayer key.

```
dcl-facilitator evidence --reason <text> --verdict COMMIT --now <unix> --body payment.json
```

`decisionDigest` is `keccak256` of the concatenation of eight 32-byte words.
It is not a hash of the JSON text, so key order does not enter it. Words 4
and 8 are copied as raw bytes. The other words are hashes:

1. `keccak256("DCL_DECISION_EVIDENCE_V1")`
2. `keccak256` of the verdict string, `COMMIT` or `NO_COMMIT`
3. `keccak256` of `actionId` as UTF-8
4. `actionDigest`, the 32 bytes themselves
5. the authorization-identity digest
6. `keccak256` of the canonical payment context
7. `keccak256` of the reason as UTF-8
8. `evidenceId`, the 32 bytes themselves

`actionId` is lowercase hex, with no `0x` prefix, of
`keccak256` of the raw concatenation `DCL_ACTION_ID_V1` followed by the 32-byte
`actionDigest`. The result is 64 hex characters.

`actionDigest` is `keccak256` of this raw concatenation. There are no
separators and no length prefixes, and none of these fields are hex text or
ABI-padded words:

1. the UTF-8 bytes of `eip155:8453`
2. the USDC address, 20 bytes
3. the payer, 20 bytes
4. the recipient, 20 bytes
5. `value`, 32-byte big-endian
6. `validAfter`, 32-byte big-endian
7. `validBefore`, 32-byte big-endian
8. the nonce, 32 bytes
9. the payer signature, 65 bytes `r || s || v`

The authorization-identity digest is `keccak256` of these words:
`keccak256("DCL_AUTHORIZATION_IDENTITY_V1")`, chain id `8453`, the USDC
address, payer, recipient, value, `validAfter`, `validBefore`, and nonce.
Addresses in those words are 20 bytes left-padded to 32. Integer fields are
32-byte big-endian words. The payer signature is not part of this identity.

The canonical payment context is length-prefixed UTF-8. Each field is a
big-endian `u32` length followed by the bytes of `network`, payer, `payTo`,
asset, and nonce, in that order. `network` is the literal `eip155:8453`.
Addresses are lowercase `0x` plus 40 hex characters. The nonce is lowercase
`0x` plus 64 hex characters. Checksummed addresses may appear in the JSON
object. The digest uses the lowercase form.

`POST /settle` reads `decisionEvidence` as one object. Every field below is
required. An absent field, an empty string, and `null` are rejected. The
facilitator does not fill in a default.

| field | canonical form |
|---|---|
| `actionId` | 64 lowercase hex characters, no `0x` prefix |
| `actionDigest`, `evidenceId` | `0x` plus 64 hex characters |
| `verdict` | `COMMIT` or `NO_COMMIT` |
| `reason` | UTF-8, 1 to 1024 bytes |
| `signature` | `0x` plus 130 hex characters, `r \|\| s \|\| v` |
| `context.network` | `eip155:8453` |
| `context.payer`, `context.payTo`, `context.asset` | `0x` plus 40 hex characters |
| `context.nonce` | `0x` plus 64 hex characters |
| `authorization.chainId` | JSON number `8453` |
| `authorization.verifyingContract`, `authorization.payer`, `authorization.recipient` | `0x` plus 40 hex characters |
| `authorization.value`, `authorization.validAfter`, `authorization.validBefore`, `authorization.nonce` | `0x` plus 64 hex characters |

`evidenceId` is chosen by the Oracle. It is not derived by `/settle`. The
offline `evidence` command uses the authorization nonce when `--evidence-id`
is omitted. That default is only for the unsigned printout.

The Oracle signature is recoverable secp256k1 over the raw 32-byte digest, not
over a hex string and not over an EIP-191 prefix. The encoding is `r || s || v`.
`v` may be `0`, `1`, `27`, or `28`. `0` and `27` are the same recovery id, and
`1` and `28` are the other. The signature emitted by the reference signer uses
`v = recovery id + 27` and a low `s`. A zero `r` or `s`, a high `s`, or any
other `v` is rejected. The recovered address must equal `ORACLE_ADDRESS`.

Changing the amount, payer, recipient, nonce, validity window, payer
signature, `actionDigest`, `actionId`, `evidenceId`, reason, or verdict
produces a different digest. A signed `NO_COMMIT` is not permission to settle.
The same signed `COMMIT` does not create a second relayer signature or a
second transaction. `oracle_commit_is_accepted_once` covers acceptance,
tampering, `NO_COMMIT`, replay, and two parallel settlement calls. That test
signs with the in-process test key over the same digest. It does not broadcast
to Base.

## Layout

| path | role |
|---|---|
| `src/api` | `/health`, `/supported`, `/verify`, `/settle` |
| `src/config.rs` | environment, loopback by default |
| `src/verify.rs` | read-only x402 v2 checks |
| `src/chain` | EIP-3009 digest, Base RPC, relayer transaction |
| `src/evidence.rs` | `decisionEvidence`, `decisionDigest`, signature recovery |
| `src/prepare.rs` | offline unsigned evidence |
| `src/settle.rs` | settlement after a verified `COMMIT` |
| `src/recover.rs` | restart from the stored raw transaction |
| `src/store` | SQLite idempotency, consumption, signing claims |
| `src/machine` | payment states |
| `src/leibniz` | payment-binding types; the journal is not live |

## Dev

```
cargo test --offline
cargo clippy --all-targets -- -D warnings
cargo fmt --all
```

```
dcl-facilitator evidence --reason "payment authorization accepted" --verdict COMMIT --now 1700000000 --body payment.json
```

Settlement is configured with `HOST`, `PORT`, `BASE_RPC_URL`, `DATABASE_PATH`,
`SETTLER_KEY_FILE`, `SETTLER_MAX_FEE_PER_GAS`, and `ORACLE_ADDRESS`. The names
are listed in `.env.example`. A verify-only process sets `BASE_RPC_URL` and
leaves the settler key unset.

## Local files

These stay out of Git: `.env` and every `.env.*` file except `.env.example`,
SQLite databases, `target/`, and key material (`*.pem`, `*.key`, `*.p12`,
`*.pfx`, `*.keystore`, `keystore.json`, `wallet.json`). The relayer key and
any RPC credential belong outside this repository. `ORACLE_ADDRESS` is a
public address. The Oracle signing key is not a facilitator setting.

## Notes

- The default bind address is `127.0.0.1`. Do not expose the port without
  authentication in front of it.
- Request bodies are not logged. They contain signed authorizations.
- `Cargo.lock` is committed.
- `deploy/` is a verify-only unit and environment for one host. It sets a
  public Base RPC URL and does not set a settler key.
