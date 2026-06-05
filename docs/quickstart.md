# Quickstart

This guide shows the smallest engine-only flow: create a runtime, inspect
provider capabilities, sync wallet state, and read balances. It does not start
or depend on any CLI or GUI.

## 1. Install

Clone the repository and run the default checks:

```bash
go test ./pkg/...
```

Default tests do not need rapidsnark. Native proving and unshield workflows
need a `prover` binary; see [rapidsnark Setup](rapidsnark-setup.md).

## 2. Configure a Network

The engine is chain-agnostic. Drop-in mainnet configs for BSC, Ethereum, and
Polygon ship under [`examples/networks/`](../examples/networks/) — they include
the upstream Railgun contract addresses, deployment blocks, and POI launch
blocks, so you only need to override `rpcEndpoint` for your provider:

```go
config, err := sdk.LoadNetworkConfig("examples/networks/bsc.json")
if err != nil {
    return err
}
config.RPCEndpoint = "https://your-provider/bsc" // optional override
```

`NetworkConfig` is a plain Go struct (`pkg/sdk.NetworkConfig`) — build it in
code, ship it as JSON, or roll your own loader. To target a chain that isn't
bundled, copy one of the example files and replace `chain.id`, the contract
addresses, `defaultStartBlock`, and the POI launch block. Schema fields are
documented in [docs/architecture.md](architecture.md#persistence-layout) (for
where they're persisted) and inline on the `NetworkConfig` struct.

## 3. Create a Read-Only Runtime

Use memory stores for tests and short-lived sessions:

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/bf30075/railgun-go/pkg/sdk"
)

func main() {
    ctx := context.Background()
    config, err := sdk.LoadNetworkConfig("examples/networks/bsc.json")
    if err != nil {
        log.Fatal(err)
    }

    runtime, err := sdk.NewMemoryRuntimeFromMnemonic(
        sdk.RuntimeOptions{Network: config},
        "test test test test test test test test test test test junk",
        0,
    )
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(runtime.WalletAddress())
    fmt.Printf("%+v\n", runtime.ProviderCapabilities())

    if _, err := runtime.Sync(ctx, "wallet"); err != nil {
        log.Fatal(err)
    }

    balances, err := runtime.Balances(ctx, nil)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("%+v\n", balances)
}
```

Use file stores when wallet state and checkpoints should survive process
restarts:

```go
runtime, err := sdk.NewFileRuntimeFromMnemonic(
    ".railgun-go/wallet-1",
    sdk.RuntimeOptions{Network: config},
    mnemonic,
    0,
)
```

## 4. Sync Loop and Progress

`Sync(ctx, keyPrefix)` is incremental. `keyPrefix` is the namespace used for
this wallet's scan checkpoints; pick one string and reuse it on every call so
the runtime resumes from the last successful block instead of re-scanning.
`"wallet"` is fine for a single-wallet process.

A single `Sync` call scans up to the latest finalized block at the time it is
invoked. For continuous sync, run it in a loop:

```go
for {
    if _, err := runtime.Sync(ctx, "wallet"); err != nil {
        log.Printf("sync error: %v", err)
    }
    cursor, _ := runtime.SyncCursor(ctx, "wallet")
    log.Printf("synced=%d next=%d per-version=%+v",
        cursor.SyncedBlock, cursor.NextBlock, cursor.Versions)

    select {
    case <-ctx.Done():
        return
    case <-time.After(15 * time.Second):
    }
}
```

`SyncCursor.SyncedBlock` is the overall low-water mark; use `Versions` for
per-TXID-version progress display. Checkpoints advance only after each chunk
succeeds, so a failed call never rolls back earlier progress.

### Faster Initial Sync on BNB Chain

Scanning V2 history over RPC is slow. Opt into the GraphQL bootstrap by
setting `SyncStrategy` on `RuntimeOptions`:

```go
runtime, err := sdk.NewFileRuntimeFromMnemonic(
    ".railgun-go/wallet-1",
    sdk.RuntimeOptions{
        Network:      config,
        SyncStrategy: sdk.BSCV2QuickSyncStrategy{},
    },
    mnemonic,
    0,
)
```

The strategy bootstraps V2 accumulated events from the Railgun GraphQL
endpoint, then falls back to RPC for the tail. Cancel by removing the field
or setting it to `sdk.RPCSyncStrategy{}`.

## 5. Private Execution

Shield and unshield workflows need a runtime created with wallet secret
material. Do not hard-code real mnemonics or private keys in source code,
tests, logs, or issue reports.

```go
runtime, err := sdk.NewFileRuntimeFromKeystore(
    ".railgun-go/wallet-1",
    ".railgun-go/wallet-1.vault.json",
    password,
    sdk.RuntimeOptions{
        Network: config,
        Proof: &sdk.ProofConfig{
            RapidsnarkProverBinary: "/absolute/path/to/prover",
            ArtifactCacheDir:       ".railgun-go/artifacts",
        },
    },
)
```

Before exposing private execution in an application, check
`runtime.ProviderCapabilities()` and fail closed when the provider cannot send
EIP-1559 transactions, read receipts, or make contract calls.

### Shield ERC20

```go
result, err := runtime.ShieldERC20(ctx, sdk.ShieldERC20Request{
    RecipientRailgunAddress: runtime.WalletAddress(),
    TokenAddress:            "0x55d398326f99059ff775485246999027b3197955", // USDT on BSC
    Amount:                  new(big.Int).SetUint64(1_000_000),           // 1.0 (6 decimals)
    Decimals:                6,
    PollInterval:            2 * time.Second,
    MaxNonceRetries:         5,
    Progress: func(p sdk.TransactionProgress) {
        log.Printf("%s: %s", p.Stage, p.Message)
    },
})
if err != nil {
    return err
}
// result.Approval is nil when existing allowance was already sufficient.
// result.Shield carries the on-chain shield transaction and receipt.
```

`ShieldERC20` checks public balance and allowance, sends an approval when
needed, re-verifies allowance, then submits the shield transaction through the
Railgun smart wallet. A reverted receipt fails the call.

### Unshield ERC20 (V2)

```go
tokenData, err := railcrypto.TokenDataERC20("0x55d398326f99059ff775485246999027b3197955")
if err != nil {
    return err
}

result, err := runtime.UnshieldERC20V2(ctx, sdk.UnshieldERC20V2Request{
    RecipientAddress: "0xRecipientEVMAddress",
    TokenData:        tokenData,
    Amount:           new(big.Int).SetUint64(500_000), // half a unit
    PollInterval:     2 * time.Second,
    MaxNonceRetries:  5,
    // Per-request override: when set, takes precedence over RuntimeOptions.Proof.
    // Useful for isolating artifact caches per job (e.g. one cache dir per call).
    Proof:            sdk.ProofConfig{RapidsnarkProverBinary: "/absolute/path/to/prover"},
    ArtifactCacheDir: ".railgun-go/jobs/<job-id>/artifacts",
    Progress: func(p sdk.TransactionProgress) {
        log.Printf("%s: %s", p.Stage, p.Message)
    },
})
if err != nil {
    return err
}
// result.SpendUTXOs lists the private notes consumed.
// result.Transaction holds the broadcast transaction and receipt.
```

When `Amount` is `nil` the runtime spends the full available token balance.
Spend selection only uses TXOs that POI buckets mark spendable; if stored
TXOs are missing note randomness or Merkle proofs, the call stops and the
wallet should be resynced.

For the base token (BNB) shield/unshield variants, use `ShieldBaseToken` and
`UnshieldBaseTokenV2` with the same shape.

`Progress` and `MaxNonceRetries` are supported on every shield/unshield
request type. `Progress` reports coarse stages (e.g. `approving`, `proving`,
`broadcasting`, `confirmed`) — wire it to whatever surface your app needs
(logs, TUI, SSE). `MaxNonceRetries` caps nonce reuse retries when the mempool
returns "nonce already used"; `5` is a sensible default.

## 6. Verification Loop

Run the core checks before handing off a change:

```bash
make check
go vet ./pkg/...
```

Use native proving checks only when the prover and matching artifacts are
available:

```bash
go test -tags witnesscalc ./pkg/proof/witness
go test -tags "rapidsnark witnesscalc" ./...
```
