# Architecture

`railgun-go` is organized as a protocol engine. Packages should remain usable without a CLI or UI.

## Package Map

| Package | Role |
| --- | --- |
| `pkg/crypto` | Railgun-compatible hashing, keys, token data, note encryption, memo helpers, and primitive formatting. |
| `pkg/proof` | Proof input formatting, public signals, artifact loading, Groth16 verification, witness parsing, and prover interfaces. |
| `pkg/transaction` | Shield/transact/unshield requests, calldata, bound params, signatures, RelayAdapt helpers, and EIP-1559 sending primitives. |
| `pkg/events` | V2/V3 log parsing, JSON-RPC adapters, checkpoint stores, and block-range scanners. |
| `pkg/wallet` | Wallet state, TXO import, balances, transaction history, POI status, local rescans, keystores, and rollback. |
| `pkg/quicksync` | Historical event bootstrap sources. |
| `pkg/sdk` | Stable runtime facade that assembles stores, providers, network config, sync strategy, proof config, and private execution. |

## Dependency Direction

Lower packages should not depend on `pkg/sdk`. Application orchestration belongs above the SDK, not inside proof, wallet, event, or transaction primitives.

Preferred flow:

```text
app
  -> pkg/sdk
      -> pkg/wallet
      -> pkg/events
      -> pkg/quicksync
      -> pkg/transaction
      -> pkg/proof
      -> pkg/crypto
```

## Runtime Model

`Runtime` owns one wallet session. It holds:

- an `Engine` with wallet state, chain config, active TXID versions, and provider;
- proof artifact config and an optional proof backend;
- optional wallet secret material for private execution;
- a sync strategy.

SDK-created runtimes capture active TXID versions when the engine is created. This avoids cross-runtime contamination through global chain V3 state.

## Persistence Layout

`StoreSet` bundles the seven persistence backends a wallet session needs. `NewMemoryStores()` returns purely in-memory backends; `NewFileStores(dir)` lays the same backends out as files inside `dir` (created with mode `0700`):

| Store | File / dir under `dir` | Contents |
| --- | --- | --- |
| `State` | `wallet-state.json` | Decrypted TXOs, balances, scan progress per Merkle tree. |
| `Checkpoints` | `checkpoints.json` | Per-TXID-version scan cursors keyed by `keyPrefix`. |
| `TXIDStore` | `txids.json` | Indexed Railgun TXIDs the wallet has seen. |
| `TXIDMerkleTree` | `txid-merkle-tree.json` | TXID Merkle tree nodes for V3 sync. |
| `UTXOMerkleTree` | `utxo-merkle-tree.pebble/` | Pebble key/value store for the UTXO Merkle tree — the largest store by far on a fully-synced wallet. |
| `SpentPOIEvents` | `spent-poi-events.json` | Locally observed spent-POI events awaiting submission. |
| `Details` | `wallet-details.json` | Wallet identity, indexed address, and metadata. |

Memory stores are for tests and ephemeral sessions; every restart starts from scratch. File stores survive restarts: re-creating the runtime against the same `dir` resumes sync from the persisted checkpoints.

The seven backends are consistent with each other after every successful `Sync` chunk; treat `dir` as one logical unit when backing up, restoring, or moving wallets. Stop the process before copying, since the Pebble store keeps an exclusive lock on `utxo-merkle-tree.pebble/` while open. One `dir` belongs to one wallet — host multiple wallets in sibling directories (`.railgun-go/wallet-1`, `.railgun-go/wallet-2`, ...).

## Proof Model

Default tests do not require rapidsnark. Native proving is opt-in:

- `ProofBackend` can be injected for tests or custom proving infrastructure;
- otherwise unshield flows use the rapidsnark-backed prover when built with the `rapidsnark` tag;
- witness generation requires the `witnesscalc` tag.

Keep artifact loading, witness generation, proof execution, and local verification independently testable.
