# dcl-facilitator

x402 facilitator with a DCL policy gate (the "Leibniz layer").

**Status:** local x402 v2 `POST /verify` and `POST /settle` for Base mainnet
USDC (EIP-3009, `eip155:8453`). Verify is read-only. Settle signs one relayer
transaction only after a verified Oracle `COMMIT`, stores that decision with
the raw transaction, and only then broadcasts those exact bytes. It does not
fall back to the local policy gate and it does not execute DCL. Recovery
rechecks the stored Oracle signature and the raw transaction before sending,
and does not rebroadcast a settlement that has no stored Oracle `COMMIT`.
`GET /supported`
still advertises nothing. Settlement needs `BASE_RPC_URL`, `DATABASE_PATH`, an
absolute `SETTLER_KEY_FILE` outside this repository, `SETTLER_MAX_FEE_PER_GAS`,
and `ORACLE_ADDRESS`.

## Target pipeline

1. Parse and static checks (allowlist of network / asset / payTo, EIP-712
   domain from config, never from the request)
2. Idempotency lookup by `(network, payer, nonce)`
3. `verify` (simulation, `authorizationState`)
4. Oracle `COMMIT` bound to this authorization, consumed in SQLite
5. `settle` only after an explicit `Commit`
6. Confirm via receipt and `authorizationState`, write the journal, respond

Invariant: a paid action is never committed without a confirmed settlement,
and every state transition is recorded in an append-only, hash-chained journal.

## Layout

| path | role | milestone |
|---|---|---|
| `src/api` | HTTP routes | M1 (stubs) |
| `src/config.rs` | env config, loopback by default | M1 |
| `src/machine` | payment state machine | M2 |
| `src/store` | SQLite store, idempotency, recovery | M2 |
| `src/chain` | EVM verify / settle / receipts | M3-M4 |
| `src/leibniz` | policy gate + journal | M5 |

## Dev

    cargo test
    cargo clippy --all-targets -- -D warnings
    cargo fmt --all
    HOST=127.0.0.1 PORT=8080 BASE_RPC_URL=http://127.0.0.1:8545 DATABASE_PATH=facilitator.db SETTLER_KEY_FILE=C:\keys\relayer.hex SETTLER_MAX_FEE_PER_GAS=1000000000 cargo run

## Notes

- Binds to `127.0.0.1` by default. Do not expose it to the internet without
  authentication in front of it.
- Never log request bodies: they contain signed authorizations.
- `Cargo.lock` is committed. The pins on `tokio` and `hyper-util` exist only
  because the lockfile was first generated with an old toolchain; run
  `cargo update` with a current Rust and commit the result.
- If code from `second-state/x402-facilitator` (Apache-2.0) is copied later,
  keep the license headers and add a `NOTICE` file.
